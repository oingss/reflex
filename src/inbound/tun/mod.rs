//! TUN 虚拟网卡入站

pub mod gvisor;
mod netstack;
pub mod platform;
mod native_tun;
mod interface_monitor;

#[cfg(target_os = "android")]
pub mod packages_android;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, oneshot, Mutex},
};
use tracing::{debug, error, info, warn};
#[cfg(not(target_os = "windows"))]
use tun::AbstractDevice as _;

use crate::{
    config::inbound::TunInboundConfig,
    inbound::{
        dns::{DnsQuery, DnsQuerySource, DnsQueryTx},
        InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession,
    },
};

// ── 常量 ──────────────────────────────────────────────────────────────────────

pub(crate) const DEFAULT_UDP_TIMEOUT_SECS: u64 = 300;
pub(crate) const IPPROTO_TCP: u8 = 6;
pub(crate) const IPPROTO_UDP: u8 = 17;
pub(crate) const IPPROTO_ICMP: u8 = 1;
pub(crate) const IPPROTO_ICMPV6: u8 = 58;
pub(crate) const IPV4_VERSION: u8 = 4;
pub(crate) const IPV6_VERSION: u8 = 6;

/// NAT 端口范围（与 sing-tun stack_system_nat.go 保持一致：10000-65535）
const NAT_PORT_START: u16 = 10000;
const NAT_PORT_END: u16 = 65535;

/// 默认 loopback 地址（参照 sing-tun TunOptions.Inet4LoopbackAddress 默认值）。
/// 当配置中未指定 `loopback_address` 时使用。
const DEFAULT_INET4_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const DEFAULT_INET6_LOOPBACK: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

/// TUN 接口可见性轮询参数（参考 clash-rs TunRunner 的 TUN_VISIBILITY_MAX_ATTEMPTS）。
const TUN_VISIBILITY_MAX_ATTEMPTS: u32 = 40;
const TUN_VISIBILITY_POLL_INTERVAL_MS: u64 = 50;

/// 等待 TUN 接口在网络接口列表中可见（参考 clash-rs: runner.rs TUN_VISIBILITY_MAX_ATTEMPTS）。
/// 新创建的 TUN 设备可能不会立即被系统网络子系统识别，需轮询等待。
/// 在所有平台（Linux/macOS/Windows）上调用。
async fn wait_for_tun_visibility(if_name: &str) {
    for attempt in 0..TUN_VISIBILITY_MAX_ATTEMPTS {
        // 尝试通过 tun_name() 获取设备名验证（tun 0.8 保证 tun_name() 返回真实名）
        if is_tun_interface_visible(if_name) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(TUN_VISIBILITY_POLL_INTERVAL_MS)).await;
    }
    warn!(
        interface = %if_name,
        "tun: interface not visible after {}ms, proceeding anyway",
        TUN_VISIBILITY_MAX_ATTEMPTS as u64 * TUN_VISIBILITY_POLL_INTERVAL_MS
    );
}

/// 检查 TUN 接口是否在网络接口列表中可见。
/// 使用平台原生方式查询接口列表。
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn is_tun_interface_visible(if_name: &str) -> bool {
    // 通过 /sys/class/net 检查接口是否存在（Linux/macOS）
    // macOS 下 /sys/class/net 不存在，使用 if_nametoindex
    #[cfg(target_os = "linux")]
    {
        let path = std::path::Path::new("/sys/class/net").join(if_name);
        if path.exists() {
            return true;
        }
    }
    #[cfg(target_os = "macos")]
    {
        // macOS 上使用 if_nametoindex 检查接口是否存在
        let name_c = std::ffi::CString::new(if_name).ok();
        if let Some(ref name) = name_c {
            unsafe {
                let idx = libc::if_nametoindex(name.as_ptr());
                if idx != 0 {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn is_tun_interface_visible(if_name: &str) -> bool {
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            &format!("(Get-NetAdapter -Name '{if_name}' -ErrorAction SilentlyContinue).ifIndex")])
        .output();
    if let Ok(out) = out {
        if !String::from_utf8_lossy(&out.stdout).trim().is_empty() {
            return true;
        }
    }
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn is_tun_interface_visible(_if_name: &str) -> bool {
    true
}

/// 判断 IPv4 地址是否为全局单播地址（参照 sing-tun processIPv4 中的 destination 检查）。
/// 排除：0.0.0.0/8（本网络）、255.255.255.255（广播）、224.0.0.0/4（组播）。
/// 注意：sing-tun 使用 `netip.Addr.IsGlobalUnicast()`，其语义等同此处实现。
fn is_global_unicast_v4(addr: Ipv4Addr) -> bool {
    if addr.is_unspecified() || addr.is_broadcast() {
        return false;
    }
    let octets = addr.octets();
    // 仅排除组播 224.0.0.0/4（Go IsGlobalUnicast 语义）。
    // 保留 240.0.0.0/4（除 255.255.255.255 广播外），与 sing-tun 对齐。
    if octets[0] >= 224 && octets[0] < 240 {
        return false;
    }
    true
}

/// 判断 IPv6 地址是否为全局单播地址（参照 sing-tun processIPv6 中的 destination 检查）。
/// 排除：`::`（未指定）、`::1`（loopback）、`fe80::/10`（link-local）、`ff00::/8`（组播）。
fn is_global_unicast_v6(addr: Ipv6Addr) -> bool {
    if addr.is_unspecified() || addr.is_loopback() {
        return false;
    }
    let seg0 = addr.segments()[0];
    // link-local fe80::/10
    if (seg0 & 0xffc0) == 0xfe80 {
        return false;
    }
    // multicast ff00::/8
    if (seg0 & 0xff00) == 0xff00 {
        return false;
    }
    true
}

// ── 本地子网收集与过滤 ───────────────────────────────────────────────────────
//
// 当 TUN 启用 auto_route 后，所有流量（包括访问本机 LAN/Docker 子网的流量）
// 都可能被 TUN 劫持。若放任这些流量进入代理路径，会形成死循环：
//   1. 主机应用发 UDP 到 LAN（如 172.19.0.3:137）
//   2. TUN 劫持 → reflex 转发 → direct outbound 再次发送
//   3. 出站包又被 TUN 劫持 → 回到步骤 2，端口递增爆炸
//
// 解决方案：TUN 启动时枚举所有非 TUN、非 loopback 网卡的子网，在
// process_ipv4/process_ipv6 入口处直接丢弃 src 或 dst 落在这些子网内的包。
// 这与 sing-tun `exclude_route_address` + 内核 `auto_detect_interface` 组合
// 等价，但更鲁棒——不依赖 ip rule 的 `suppress_prefixlength` 是否生效。

/// 收集本机所有非 TUN、非 loopback 网卡的 IPv4 子网（network, prefix_len）。
///
/// `exclude_if` 为 TUN 设备名，其子网不会被收集（TUN 子网流量应正常处理）。
/// 返回值用于在 process_ipv4 中过滤 LAN 流量。
#[cfg(target_os = "linux")]
pub(crate) fn collect_local_subnets_v4(exclude_if: Option<&str>) -> Vec<(Ipv4Addr, u8)> {
    use crate::outbound::common::interface_finder::linux::list_interfaces;

    let mut subnets = Vec::new();
    for iface in list_interfaces() {
        // 跳过 TUN 设备自身
        if let Some(name) = exclude_if {
            if iface.name == name {
                continue;
            }
        }
        for (ip, pl) in iface.addrs {
            if let IpAddr::V4(v4) = ip {
                let pl = pl.min(32);
                let mask = if pl == 0 { 0u32 } else { !((1u32 << (32 - pl)) - 1) };
                let net = Ipv4Addr::from(u32::from(v4) & mask);
                subnets.push((net, pl));
            }
        }
    }
    subnets
}

/// IPv6 版本。
#[cfg(target_os = "linux")]
pub(crate) fn collect_local_subnets_v6(exclude_if: Option<&str>) -> Vec<(Ipv6Addr, u8)> {
    use crate::outbound::common::interface_finder::linux::list_interfaces;

    let mut subnets = Vec::new();
    for iface in list_interfaces() {
        if let Some(name) = exclude_if {
            if iface.name == name {
                continue;
            }
        }
        for (ip, pl) in iface.addrs {
            if let IpAddr::V6(v6) = ip {
                let pl = pl.min(128);
                let mask = if pl == 0 { 0u128 } else { !((1u128 << (128 - pl)) - 1) };
                let net = Ipv6Addr::from(u128::from(v6) & mask);
                subnets.push((net, pl));
            }
        }
    }
    subnets
}

/// 非 Linux 平台暂不支持本地子网枚举，返回空（不过滤）。
#[cfg(not(target_os = "linux"))]
pub(crate) fn collect_local_subnets_v4(_exclude_if: Option<&str>) -> Vec<(Ipv4Addr, u8)> {
    Vec::new()
}
#[cfg(not(target_os = "linux"))]
pub(crate) fn collect_local_subnets_v6(_exclude_if: Option<&str>) -> Vec<(Ipv6Addr, u8)> {
    Vec::new()
}

/// 判断 IPv4 地址是否落在任一本地子网内。
pub(crate) fn ip_in_local_subnets_v4(
    addr: Ipv4Addr,
    subnets: &[(Ipv4Addr, u8)],
) -> bool {
    subnets.iter().any(|(net, pl)| {
        let pl = (*pl).min(32);
        if pl == 0 {
            return true;
        }
        let mask = !((1u32 << (32 - pl)) - 1);
        (u32::from(addr) & mask) == (u32::from(*net) & mask)
    })
}

/// 判断 IPv6 地址是否落在任一本地子网内。
pub(crate) fn ip_in_local_subnets_v6(
    addr: Ipv6Addr,
    subnets: &[(Ipv6Addr, u8)],
) -> bool {
    subnets.iter().any(|(net, pl)| {
        let pl = (*pl).min(128);
        if pl == 0 {
            return true;
        }
        let mask = !((1u128 << (128 - pl)) - 1);
        (u128::from(addr) & mask) == (u128::from(*net) & mask)
    })
}

/// 计算 IPv4 子网的广播地址（参照 sing-tun BroadcastAddr）。
fn broadcast_addr_v4(network: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let mask = if prefix_len == 0 {
        0u32
    } else {
        !((1u32 << (32 - prefix_len.min(32))) - 1)
    };
    let net = u32::from(network) & mask;
    let bcast = net | !mask;
    Ipv4Addr::from(bcast)
}

/// 判断 IPv4 地址是否在 TUN 子网内（用于 acceptLoop 目标重写）。
/// 参照 sing-tun acceptLoop L332-346：若原始目标落在 TUN 前缀内，
/// 改写为 127.0.0.1，使应用能通过 TUN 地址访问本地回环服务。
fn addr_in_prefix_v4(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = !((1u32 << (32 - prefix_len.min(32))) - 1);
    (u32::from(addr) & mask) == (u32::from(network) & mask)
}

fn addr_in_prefix_v6(addr: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let bits = prefix_len.min(128) as usize;
    let a = u128::from(addr);
    let n = u128::from(network);
    let mask = if bits == 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - bits)) - 1)
    };
    (a & mask) == (n & mask)
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

pub(crate) fn prefix_len_to_mask_v4(len: u8) -> Ipv4Addr {
    if len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = !((1u32 << (32 - len.min(32))) - 1);
    Ipv4Addr::from(mask)
}

fn parse_addr_prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: IpAddr = ip_str.parse().ok()?;
    let prefix_len: u8 = len_str.parse().ok()?;
    let max_len = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_len {
        return None;
    }
    Some((ip, prefix_len))
}

/// 解析纯 IP 地址（不带前缀长度，用于 `loopback_address` 配置项）。
fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse().ok()
}

/// 解析 `"start:end"` 形式的 UID 范围（参照 sing-tun parseRange）。
/// 返回 (start, end) 闭区间。出错返回 None。
#[allow(dead_code)]
fn parse_uid_range(s: &str) -> Option<(u32, u32)> {
    let (start_str, end_str) = s.split_once(':')?;
    let start: u32 = start_str.trim().parse().ok()?;
    let end: u32 = end_str.trim().parse().ok()?;
    if start > end {
        return None;
    }
    Some((start, end))
}

/// 把 `include_uid` + `include_uid_range` 合并为已排序、去重的 `(lo, hi)` 范围列表。
/// 单个 UID 视为 `(uid, uid)` 区间。
#[allow(dead_code)]
fn merge_uid_list_and_ranges(uids: &[u32], ranges: &[String]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = uids.iter().map(|&u| (u, u)).collect();
    for r in ranges {
        if let Some((lo, hi)) = parse_uid_range(r) {
            out.push((lo, hi));
        } else {
            warn!(range = %r, "tun: invalid include/exclude uid_range (expected 'start:end')");
        }
    }
    out.sort_unstable();
    out.dedup();
    merge_ranges(out)
}

/// 合并相邻或重叠的范围（参照 sing-tun 内部 ranges.Merge）。
#[allow(dead_code)]
fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return ranges;
    }
    ranges.sort_unstable();
    let mut merged = vec![ranges[0]];
    for (a, b) in ranges.into_iter().skip(1) {
        let last = merged.last_mut().unwrap();
        if a <= last.1.saturating_add(1) {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    merged
}

/// 从 base 中减去 sub 的所有范围（参照 sing-tun subtract_ranges）。
#[allow(dead_code)]
fn subtract_ranges(base: &[(u32, u32)], sub: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut result: Vec<(u32, u32)> = base.to_vec();
    for &(lo, hi) in sub {
        let mut next = Vec::with_capacity(result.len() + 1);
        for (a, b) in result.into_iter() {
            if hi < a || lo > b {
                next.push((a, b));
            } else {
                if a < lo {
                    next.push((a, lo - 1));
                }
                if b > hi {
                    next.push((hi + 1, b));
                }
            }
        }
        result = next;
    }
    result
}

/// 计算 ranges 相对 [lo, hi] 的补集（参照 sing-tun complement_ranges）。
#[allow(dead_code)]
fn complement_ranges(ranges: &[(u32, u32)], lo: u32, hi: u32) -> Vec<(u32, u32)> {
    let mut result = Vec::new();
    let mut cur = lo;
    for &(a, b) in ranges {
        if cur < a {
            result.push((cur, a - 1));
        }
        cur = b.saturating_add(1);
    }
    if cur <= hi {
        result.push((cur, hi));
    }
    result
}

// ── TCP NAT 表（参照 sing-tun stack_system_nat.go）────────────────────────────
//
// 关键修复（对比旧实现）：
// 1. **addr_map key 用 (src, dst) 5-tuple**：旧实现用 src 作为 key，
//    同一 src 连接不同 dst 时会复用同一 nat_port，导致 port_map 中
//    destination 被覆盖，回包反查到错误目标。sing-tun 用 (source, destination)
//    作为 key，同一 src 不同 dst 分配不同 port。
// 2. **双检锁**：sing-tun Lookup 在写锁内再次检查 addrMap，避免并发请求
//    为同一 (src, dst) 分配多个端口。旧实现没有双检锁，会产生 stale entry。
// 3. **线性探测端口分配**：对齐 sing-tun allocatePortLocked，从 portIndex
//    开始找下一个空闲端口；端口池满时驱逐最旧条目。
// 4. **锁顺序统一**：所有路径遵循 addr_map → port_map，避免死锁。
// 5. **per-entry last_active**：每条会话的 last_active 用独立 Mutex 保护，
//    更新时间戳只需锁单个 entry，不阻塞其他会话的查找/插入。
// 6. **throttled update**：sing-tun 仅当距上次更新 >1s 时才刷新 last_active。

struct TcpNatEntry {
    source: SocketAddr,
    destination: SocketAddr,
    /// std::sync::Mutex（非 tokio）—— 持锁期间无 .await，仅读写 Instant
    last_active: std::sync::Mutex<Instant>,
}

pub(crate) struct TcpNat {
    /// 端口分配游标。用 AtomicU16 替代 Mutex<u16>，无锁推进。
    port_index: std::sync::atomic::AtomicU16,
    /// (src, dst) → nat_port（5-tuple key，对齐 sing-tun tcpNatKey）
    addr_map: tokio::sync::RwLock<HashMap<(SocketAddr, SocketAddr), u16>>,
    /// nat_port → session（Arc 便于在读锁释放后仍持有 entry 引用）
    port_map: tokio::sync::RwLock<HashMap<u16, Arc<TcpNatEntry>>>,
}

impl TcpNat {
    pub(crate) fn new() -> Self {
        Self {
            port_index: std::sync::atomic::AtomicU16::new(NAT_PORT_START),
            addr_map: tokio::sync::RwLock::new(HashMap::new()),
            port_map: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// 为 (src, dst) 分配 NAT 端口。
    /// - 已有映射直接返回（throttled 更新 last_active）。
    /// - 无可用端口时：驱逐 last_active 最旧的条目后复用其端口。
    ///
    /// 锁顺序：addr_map → port_map（与 sing-tun 一致，避免死锁）。
    async fn lookup_or_insert(&self, src: SocketAddr, dst: SocketAddr) -> u16 {
        let key = (src, dst);

        // 快速路径：读锁查 addr_map
        if let Some(&port) = self.addr_map.read().await.get(&key) {
            // throttled 更新 last_active（仅当 >1s 未更新）
            if let Some(entry) = self.port_map.read().await.get(&port) {
                let now = Instant::now();
                if let Ok(mut la) = entry.last_active.lock() {
                    if now.duration_since(*la) > Duration::from_secs(1) {
                        *la = now;
                    }
                }
            }
            return port;
        }

        // 慢速路径：addr_map 写锁 + 双检锁（对齐 sing-tun Lookup L111-L114）
        let mut addr_map = self.addr_map.write().await;
        if let Some(&port) = addr_map.get(&key) {
            // 并发请求已插入，用已有的
            return port;
        }

        // 分配新端口：port_map 写锁 + 线性探测（对齐 sing-tun allocatePortLocked）
        let mut port_map = self.port_map.write().await;
        let port = self.allocate_port_locked(&mut port_map, &mut addr_map);

        let entry = Arc::new(TcpNatEntry {
            source: src,
            destination: dst,
            last_active: std::sync::Mutex::new(Instant::now()),
        });
        port_map.insert(port, entry);
        addr_map.insert(key, port);
        port
    }

    /// 线性探测分配端口（对齐 sing-tun allocatePortLocked L131-L144）。
    /// 端口池满时驱逐 last_active 最旧的条目。
    /// 调用者必须持有 port_map 和 addr_map 的写锁。
    fn allocate_port_locked(
        &self,
        port_map: &mut HashMap<u16, Arc<TcpNatEntry>>,
        addr_map: &mut HashMap<(SocketAddr, SocketAddr), u16>,
    ) -> u16 {
        use std::sync::atomic::Ordering;
        let total = (NAT_PORT_END as u32) - (NAT_PORT_START as u32) + 1;
        for _ in 0..total {
            let p = self.port_index.fetch_add(1, Ordering::Relaxed);
            // 回绕到合法范围（fetch_add 在 u16 边界会 wrap，需检测 p 是否仍落在
            // NAT 端口区间内；不在则把游标重置到起点后继续）
            let p = if !(NAT_PORT_START..=NAT_PORT_END).contains(&p) {
                self.port_index
                    .store(NAT_PORT_START.wrapping_add(1), Ordering::Relaxed);
                NAT_PORT_START
            } else {
                p
            };
            if !port_map.contains_key(&p) {
                return p;
            }
        }
        // 端口池满：驱逐 last_active 最旧的条目
        let evict_port = port_map
            .iter()
            .min_by_key(|(_, e)| {
                e.last_active
                    .lock()
                    .map(|t| *t)
                    .unwrap_or_else(|_| Instant::now())
            })
            .map(|(&p, _)| p)
            .unwrap_or(NAT_PORT_START);
        if let Some(old) = port_map.remove(&evict_port) {
            addr_map.remove(&(old.source, old.destination));
        }
        evict_port
    }

    /// 根据 NAT 端口反查原始 (src, dst)，同时 throttled 更新 last_active。
    /// 只取 port_map 读锁，允许并发反查。
    async fn lookup_back(&self, nat_port: u16) -> Option<(SocketAddr, SocketAddr)> {
        let entry = {
            let port_map = self.port_map.read().await;
            port_map.get(&nat_port).cloned()?
        };
        // throttled 更新：仅当距上次更新 >1s 时刷新
        let now = Instant::now();
        if let Ok(mut la) = entry.last_active.lock() {
            if now.duration_since(*la) > Duration::from_secs(1) {
                *la = now;
            }
        }
        Some((entry.source, entry.destination))
    }

    /// GC：删除超时会话。
    /// 锁顺序：addr_map → port_map（与 lookup_or_insert 一致，避免死锁）。
    async fn gc(&self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<(u16, (SocketAddr, SocketAddr))> = {
            let port_map = self.port_map.read().await;
            port_map
                .iter()
                .filter(|(_, e)| {
                    e.last_active
                        .lock()
                        .map(|t| now.duration_since(*t) > timeout)
                        .unwrap_or(false)
                })
                .map(|(&p, e)| (p, (e.source, e.destination)))
                .collect()
        };
        if expired.is_empty() {
            return;
        }
        let mut addr_map = self.addr_map.write().await;
        let mut port_map = self.port_map.write().await;
        for (port, key) in expired {
            port_map.remove(&port);
            addr_map.remove(&key);
        }
    }
}

// ── 统一 TUN 写回辅助 ─────────────────────────────────────────────────────────

/// 写回 TUN 设备。
/// `raw_ip` 是原始 IP 包（不含 PI 头）。
/// tun 0.8 起所有平台包均不含 PI 头，直接写入即可。
pub(crate) async fn tun_write(
    writer: &Mutex<impl AsyncWriteExt + Unpin + Send>,
    raw_ip: &[u8],
    _is_ipv6: bool,
) {
    let mut guard = writer.lock().await;
    let _ = guard.write_all(raw_ip).await;
}

// ── TunInbound ────────────────────────────────────────────────────────────────

pub struct TunInbound {
    config: TunInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    /// TUN 层 DNS 劫持：直接拦截端口 53 的 UDP 流量，通过 DNS 解析器处理
    /// （参考 clash-rs datagram.rs:97-168），避免经过代理路径。
    dns_tx: Option<DnsQueryTx>,
    /// 是否启用 TUN 层 DNS 劫持（从 route.hijack_dns 同步）
    dns_hijack: bool,
}

impl TunInbound {
    pub fn new(
        config: TunInboundConfig,
        tcp_tx: mpsc::Sender<InboundTcpStream>,
        udp_tx: mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self {
            config,
            tcp_tx,
            udp_tx,
            dns_tx: None,
            dns_hijack: false,
        }
    }

    /// 设置 DNS 劫持参数（在 run() 之前调用）。
    /// `dns_tx` 为向 DNS 解析器发送查询的通道。
    pub fn with_dns_hijack(mut self, dns_tx: DnsQueryTx, enabled: bool) -> Self {
        self.dns_tx = if enabled { Some(dns_tx) } else { None };
        self.dns_hijack = enabled;
        self
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let cfg = Arc::new(self.config);
        let tag = Arc::new(cfg.tag.clone());
        let udp_timeout = Duration::from_secs(if cfg.udp_timeout == 0 {
            DEFAULT_UDP_TIMEOUT_SECS
        } else {
            cfg.udp_timeout
        });

        // ── 解析 TUN 地址 ────────────────────────────────────────────────────
        // 与 sing-tun NewSystem 对齐：区分 server_addr（listener 绑定地址，
        // 即 TUN 配置的地址本身，如 198.18.0.1）和 client_addr（用于 NAT 重写源地址，
        // 即 server_addr.Next()，如 198.18.0.2）。
        // 这样 listener 的 acceptLoop 端口和 NAT 端口在内核路由层面不会冲突，
        // 且回包匹配条件 `src == client_addr && sport == tcp_port` 不会误触发。
        let mut inet4_server_addr: Option<Ipv4Addr> = None;
        let mut inet4_client_addr: Option<Ipv4Addr> = None;
        let mut inet6_server_addr: Option<Ipv6Addr> = None;
        let mut inet6_client_addr: Option<Ipv6Addr> = None;
        // 收集所有前缀，用于 acceptLoop 目标重写（参照 sing-tun inet4Prefixes）
        let mut inet4_prefixes: Vec<(Ipv4Addr, u8)> = Vec::new();
        let mut inet6_prefixes: Vec<(Ipv6Addr, u8)> = Vec::new();

        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), pl)) => {
                    if inet4_server_addr.is_none() {
                        inet4_server_addr = Some(ip);
                        inet4_client_addr = Some(Ipv4Addr::from(u32::from(ip).wrapping_add(1)));
                    }
                    inet4_prefixes.push((ip, pl));
                }
                Some((IpAddr::V6(ip), pl)) => {
                    if inet6_server_addr.is_none() {
                        inet6_server_addr = Some(ip);
                        inet6_client_addr = Some(Ipv6Addr::from(u128::from(ip).wrapping_add(1)));
                    }
                    inet6_prefixes.push((ip, pl));
                }
                None => warn!(addr = %addr_str, "tun: invalid address prefix"),
            }
        }

        if inet4_server_addr.is_none() && inet6_server_addr.is_none() {
            anyhow::bail!("tun: at least one address must be configured");
        }

        // ── 解析 loopback 地址（参照 sing-tun Inet4LoopbackAddress）─────────
        // 默认 127.0.0.1 / ::1；配置中可覆盖。
        let mut inet4_loopback: Ipv4Addr = DEFAULT_INET4_LOOPBACK;
        let mut inet6_loopback: Ipv6Addr = DEFAULT_INET6_LOOPBACK;
        for s in &cfg.loopback_address {
            match parse_ip(s) {
                Some(IpAddr::V4(a)) => inet4_loopback = a,
                Some(IpAddr::V6(a)) => inet6_loopback = a,
                None => warn!(addr = %s, "tun: invalid loopback_address"),
            }
        }

        // ── 计算 IPv4 广播地址（参照 sing-tun BroadcastAddr）─────────────────
        // 用于 processIPv4 中过滤广播包。
        let inet4_broadcast = inet4_prefixes
            .first()
            .map(|(net, pl)| broadcast_addr_v4(*net, *pl));

        // 注：route_address / route_exclude_address 在各平台 platform::setup 中
        // 自行解析（因为路由规则按平台方式下发）。这里不预先解析。

        // ── 创建 TUN 设备 ────────────────────────────────────────────────────
        let (dev, if_name) = {
            let mut tun_cfg = tun::Configuration::default();
            tun_cfg.mtu(cfg.mtu as u16);
            tun_cfg.up();

            // 接口名：tun_name() 是 tun 0.8 的新 API（name() 已废弃）
            if let Some(ref name) = cfg.interface_name {
                tun_cfg.tun_name(name);
            }

            if let Some(ip) = inet4_server_addr {
                if let Some((_, prefix_len)) = cfg
                    .address
                    .iter()
                    .find_map(|s| parse_addr_prefix(s).filter(|(a, _)| a.is_ipv4()))
                {
                    tun_cfg
                        .address(ip)
                        .netmask(prefix_len_to_mask_v4(prefix_len));
                }
            }

            // ── 平台特有配置 ─────────────────────────────────────────────────
            // tun 0.8（合并自 tun2）的 API：platform() → platform_config()

            #[cfg(target_os = "linux")]
            tun_cfg.platform_config(|p| {
                // tun 0.8 起所有平台包都**不含** PI 头（packet_information 已废弃）
                // ensure_root_privileges：自动处理 /dev/net/tun 权限
                p.ensure_root_privileges(true);
            });

            #[cfg(target_os = "windows")]
            {
                // device_guid：为 wintun 适配器指定固定 GUID，避免每次启动创建新适配器
                // 用接口名做种子生成确定性 UUID（与 clash-rs 策略一致）
                let guid_seed = cfg.interface_name.as_deref().unwrap_or("tun0").as_bytes();
                // 简单 hash → u128（不依赖 uuid crate）
                let mut guid: u128 = 0xdeadbeef_cafebabe_12345678_9abcdef0;
                for (i, &b) in guid_seed.iter().enumerate() {
                    guid ^= (b as u128).wrapping_shl((i % 16) as u32 * 8);
                    guid = guid.wrapping_mul(0x6c62272e07bb0142_u128);
                }
                tun_cfg.platform_config(|p| {
                    p.device_guid(guid);
                });
            }

            let dev = tun::create_as_async(&tun_cfg)
                .map_err(|e| anyhow::anyhow!("failed to create TUN device: {e}"))?;

            // 获取实际接口名。
            // tun 0.8 在 Linux/macOS 下 dev.tun_name() 返回内核分配的真实名称；
            // Windows 下 wintun 适配器名由 device_guid 决定，以 PowerShell 查询为准。
            #[cfg(not(target_os = "windows"))]
            let if_name = {
                match dev.tun_name() {
                    Ok(name) if !name.is_empty() => name,
                    _ => cfg
                        .interface_name
                        .clone()
                        .unwrap_or_else(|| "tun0".to_string()),
                }
            };

            #[cfg(target_os = "windows")]
            let if_name = {
                // wintun 适配器创建后名称由 guid 决定，需要通过 PowerShell 查询实际名称
                // 等待最多 3s 让适配器在系统中注册
                let expected = cfg.interface_name.as_deref().unwrap_or("tun0");
                platform::resolve_actual_interface_name(expected)
            };

            (dev, if_name)
        };

        info!(
            tag = %tag,
            interface = %if_name,
            mtu = cfg.mtu,
            "tun inbound started"
        );

        // ── 等待 TUN 接口可见（参考 clash-rs: TUN_VISIBILITY_MAX_ATTEMPTS）───
        // 新创建的 TUN 设备可能不会立即被系统网络子系统识别。
        // 轮询等待最多 TUN_VISIBILITY_MAX_ATTEMPTS 次。
        wait_for_tun_visibility(&if_name).await;

        // ── auto_route ───────────────────────────────────────────────────────
        let mut tun_state = crate::inbound::tun::platform::SetupState::default();
        if cfg.auto_route {
            match platform::setup(&cfg, &if_name).await {
                Ok(state) => {
                    tun_state = state;
                    info!(interface = %if_name, "tun: auto_route configured");
                }
                Err(e) => {
                    warn!(err = %e, "tun: auto_route setup failed (requires elevated privileges)")
                }
            }
        }

        // ── 收集本地子网（用于过滤 LAN/Docker 流量，避免死循环）──────────────
        // auto_route 会把所有流量（包括访问本机 LAN/Docker 子网的流量）劫持到 TUN。
        // 若放任这些流量进入代理路径，会形成死循环（详见 collect_local_subnets_v4 注释）。
        // 这里枚举所有非 TUN、非 loopback 网卡的子网，传给 process_ipv4/v6 过滤。
        let local_subnets_v4 = collect_local_subnets_v4(Some(&if_name));
        let local_subnets_v6 = collect_local_subnets_v6(Some(&if_name));
        if !local_subnets_v4.is_empty() || !local_subnets_v6.is_empty() {
            info!(
                v4_count = local_subnets_v4.len(),
                v6_count = local_subnets_v6.len(),
                v4_sample = ?local_subnets_v4.iter().take(3).collect::<Vec<_>>(),
                "tun: collected local subnets for LAN traffic filtering"
            );
        }

        // ── 协议栈分发：system / gvisor / mixed ──────────────────────────────
        // system 栈：继续走下方的 TCP NAT + UDP session 逻辑（reflex 原有实现）。
        // gvisor / mixed 栈：交给 gvisor 模块（基于 smoltcp 用户态协议栈）。
        //
        // 配置中 `stack` 字段（config/inbound.rs:377）默认 "system"，
        // 支持 "gvisor" / "mixed"（后者 TCP 走 system NAT，UDP 走 gvisor）。
        if matches!(cfg.stack.as_str(), "gvisor" | "mixed") {
            info!(
                tag = %tag,
                stack = %cfg.stack,
                interface = %if_name,
                "tun: switching to {} stack (smoltcp userspace)",
                cfg.stack
            );
            // Windows：gvisor 路径无需 bind TCP listener 到 TUN 地址，
            // 跳过 wait_for_tun_address。
            let (reader, writer) = tokio::io::split(dev);
            let writer = Arc::new(Mutex::new(writer));
            let tag_clone = tag.clone();
            let tcp_tx = self.tcp_tx.clone();
            let udp_tx = self.udp_tx.clone();
            let mtu = cfg.mtu as usize;

            let dns_tx_ref = self.dns_tx.clone();
            let dns_hijack = self.dns_hijack;

            if cfg.stack == "gvisor" {
                return gvisor::run_gvisor(
                    reader, writer, mtu, tag_clone, tcp_tx, udp_tx,
                    local_subnets_v4, local_subnets_v6,
                    dns_tx_ref, dns_hijack,
                )
                .await;
            } else {
                // mixed：TCP 走 system NAT，UDP 走 gvisor。
                return gvisor::run_mixed(
                    reader,
                    writer,
                    mtu,
                    tag_clone,
                    tcp_tx,
                    udp_tx,
                    inet4_server_addr,
                    inet4_client_addr,
                    inet6_server_addr,
                    inet6_client_addr,
                    inet4_prefixes,
                    inet6_prefixes,
                    inet4_loopback,
                    inet6_loopback,
                    cfg.tcp_mss,
                    local_subnets_v4,
                    local_subnets_v6,
                    dns_tx_ref, dns_hijack,
                )
                .await;
            }
        }

        // ── Windows：等待 TUN 地址真正生效后再 bind ────────────────────────
        // wintun 适配器创建并由 netsh 配置 IP 后，Windows 需要额外时间
        // 将地址注册到网卡。直接 bind 会因地址不可用而失败。
        // 轮询策略参照 sing-tun retryableListenError（WSAEADDRNOTAVAIL 重试）。
        #[cfg(target_os = "windows")]
        if cfg.auto_route {
            if let Some(addr) = inet4_server_addr {
                platform::wait_for_tun_address(addr).await;
            }
        }

        // ── 在 TUN 地址上建 TCP Listener（参照 sing-tun start()）────────────
        // 绑定到 server_addr（与 sing-tun start() L132 一致），失败时重试 3 次
        // （对应 sing-tun 的 retryableListenError 逻辑）。
        let tcp_listener_v4: Option<Arc<TcpListener>> = if let Some(addr) = inet4_server_addr {
            let mut result = None;
            for attempt in 0..3u32 {
                match TcpListener::bind(SocketAddrV4::new(addr, 0)).await {
                    Ok(l) => {
                        info!(tag = %tag, addr = %l.local_addr().unwrap(), "tun: TCP v4 listener ready");
                        result = Some(Arc::new(l));
                        break;
                    }
                    Err(e) if attempt < 2 => {
                        warn!(err = %e, attempt, "tun: TCP v4 bind failed, retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(e) => {
                        warn!(err = %e, "tun: failed to bind TCP v4 listener");
                    }
                }
            }
            result
        } else {
            None
        };

        let tcp_listener_v6: Option<Arc<TcpListener>> = if let Some(addr) = inet6_server_addr {
            let mut result = None;
            for attempt in 0..3u32 {
                match TcpListener::bind(SocketAddrV6::new(addr, 0, 0, 0)).await {
                    Ok(l) => {
                        info!(tag = %tag, addr = %l.local_addr().unwrap(), "tun: TCP v6 listener ready");
                        result = Some(Arc::new(l));
                        break;
                    }
                    Err(e) if attempt < 2 => {
                        warn!(err = %e, attempt, "tun: TCP v6 bind failed, retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    Err(e) => {
                        warn!(err = %e, "tun: failed to bind TCP v6 listener");
                    }
                }
            }
            result
        } else {
            None
        };

        let tcp_port_v4 = tcp_listener_v4
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);
        let tcp_port_v6 = tcp_listener_v6
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port())
            .unwrap_or(0);

        // ── TCP NAT 表 ───────────────────────────────────────────────────────
        let tcp_nat = Arc::new(TcpNat::new());

        // ── TCP accept loop ──────────────────────────────────────────────────
        // 传入 TUN 前缀，用于 acceptLoop 目标重写（参照 sing-tun acceptLoop L332-346）。
        // loopback 地址使用配置值（默认 127.0.0.1 / ::1）。
        if let Some(listener) = tcp_listener_v4.clone() {
            let nat = tcp_nat.clone();
            let tx = self.tcp_tx.clone();
            let tag2 = tag.clone();
            let prefixes = Arc::new(
                inet4_prefixes
                    .iter()
                    .map(|(ip, pl)| (IpAddr::V4(*ip), *pl))
                    .collect::<Vec<_>>(),
            );
            tokio::spawn(async move {
                accept_loop(
                    listener,
                    nat,
                    tx,
                    tag2,
                    prefixes,
                    false,
                    (inet4_loopback, inet6_loopback),
                )
                .await;
            });
        }
        if let Some(listener) = tcp_listener_v6.clone() {
            let nat = tcp_nat.clone();
            let tx = self.tcp_tx.clone();
            let tag2 = tag.clone();
            let prefixes = Arc::new(
                inet6_prefixes
                    .iter()
                    .map(|(ip, pl)| (IpAddr::V6(*ip), *pl))
                    .collect::<Vec<_>>(),
            );
            tokio::spawn(async move {
                accept_loop(
                    listener,
                    nat,
                    tx,
                    tag2,
                    prefixes,
                    true,
                    (inet4_loopback, inet6_loopback),
                )
                .await;
            });
        }

        // ── UDP 会话表 ───────────────────────────────────────────────────────
        let udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // ── 拆分 TUN 读写半部 ────────────────────────────────────────────────
        let (mut reader, writer) = tokio::io::split(dev);
        let writer = Arc::new(Mutex::new(writer));

        // ── 定时 GC（参照 sing-tun loopCheckTimeout）────────────────────────
        {
            let nat = tcp_nat.clone();
            let sessions = udp_sessions.clone();
            let timeout = udp_timeout;
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(timeout / 2);
                loop {
                    ticker.tick().await;
                    nat.gc(timeout).await;
                    sessions
                        .lock()
                        .await
                        .retain(|_, v| v.last_seen.elapsed() < timeout);
                }
            });
        }

        let mut pkt_buf = vec![0u8; cfg.mtu as usize + 64];

        loop {
            let n = match reader.read(&mut pkt_buf).await {
                Ok(0) => {
                    info!(tag = %tag, "tun device closed");
                    break;
                }
                Ok(n) => n,
                Err(e) => {
                    error!(err = %e, "tun read error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            // tun 0.8：所有平台包均不含 PI 头（packet_information 已废弃）
            let pkt_slice = &pkt_buf[..n];

            if pkt_slice.is_empty() {
                continue;
            }

            match pkt_slice[0] >> 4 {
                IPV4_VERSION => {
                    process_ipv4(
                        pkt_slice,
                        inet4_server_addr,
                        inet4_client_addr,
                        inet4_broadcast,
                        inet4_loopback,
                        tcp_port_v4,
                        cfg.tcp_mss,
                        &tag,
                        &self.udp_tx,
                        writer.clone(),
                        tcp_nat.clone(),
                        udp_sessions.clone(),
                        udp_timeout,
                        &local_subnets_v4,
                        &self.dns_tx,
                        self.dns_hijack,
                    )
                    .await;
                }
                IPV6_VERSION => {
                    process_ipv6(
                        pkt_slice,
                        inet6_server_addr,
                        inet6_client_addr,
                        inet6_loopback,
                        tcp_port_v6,
                        cfg.tcp_mss,
                        &tag,
                        &self.udp_tx,
                        writer.clone(),
                        tcp_nat.clone(),
                        udp_sessions.clone(),
                        udp_timeout,
                        &local_subnets_v6,
                        &self.dns_tx,
                        self.dns_hijack,
                    )
                    .await;
                }
                v => {
                    debug!(version = v, "tun: unknown IP version, dropping");
                }
            }
        }

        if cfg.auto_route {
            if let Err(e) = platform::teardown(&cfg, &if_name, &tun_state).await {
                warn!(err = %e, "tun: auto_route teardown failed");
            }
        }

        Ok(())
    }
}

// ── TCP accept loop ───────────────────────────────────────────────────────────

/// TCP accept 循环。
/// `prefixes` 为 TUN 地址前缀列表，`is_v6` 标记地址族，`loopback` 为本族回环地址。
/// 参照 sing-tun acceptLoop：若原始目标落在 TUN 前缀内，
/// 改写为配置的 loopback 地址（默认 127.0.0.1 / ::1），
/// 使应用能通过 TUN 地址访问本地回环服务。
pub(crate) async fn accept_loop(
    listener: Arc<TcpListener>,
    tcp_nat: Arc<TcpNat>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
    prefixes: Arc<Vec<(IpAddr, u8)>>,
    is_v6: bool,
    loopback: (Ipv4Addr, Ipv6Addr),
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!(err = %e, "tun: TCP accept error");
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };
        let nat_port = peer.port();
        let result = tcp_nat.lookup_back(nat_port).await;
        match result {
            Some((_src, mut dst)) => {
                // 目标重写：若 dst IP 落在 TUN 子网内，改写为 loopback。
                // 这样应用连接 TUN 地址（如 198.18.0.1:53）时，
                // 代理会连接 127.0.0.1:53 而非 TUN 地址本身。
                let need_rewrite = if is_v6 {
                    if let SocketAddr::V6(a) = dst {
                        prefixes.iter().any(|(net, pl)| match net {
                            IpAddr::V6(n) => addr_in_prefix_v6(*a.ip(), *n, *pl),
                            _ => false,
                        })
                    } else {
                        false
                    }
                } else if let SocketAddr::V4(a) = dst {
                    prefixes.iter().any(|(net, pl)| match net {
                        IpAddr::V4(n) => addr_in_prefix_v4(*a.ip(), *n, *pl),
                        _ => false,
                    })
                } else {
                    false
                };
                if need_rewrite {
                    dst = if is_v6 {
                        SocketAddr::V6(SocketAddrV6::new(loopback.1, dst.port(), 0, 0))
                    } else {
                        SocketAddr::V4(SocketAddrV4::new(loopback.0, dst.port()))
                    };
                }
                let inbound = InboundTcpStream {
                    stream: SniffedStream::new(stream),
                    target: Target::Socket(dst),
                    inbound_tag: (*tag).clone(),
                    sniffed_protocol: None,
                    sniffed_domain: None,
                };
                if tcp_tx.send(inbound).await.is_err() {
                    debug!("tun: tcp_tx closed");
                    break;
                }
            }
            None => {
                debug!(nat_port, "tun: unknown NAT port, dropping TCP connection");
            }
        }
    }
}

// ── UDP 会话条目 ──────────────────────────────────────────────────────────────

struct UdpEntry {
    reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
    last_seen: Instant,
}

// ── IPv4 包处理 ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_ipv4(
    raw: &[u8],
    inet4_server_addr: Option<Ipv4Addr>,
    inet4_client_addr: Option<Ipv4Addr>,
    inet4_broadcast: Option<Ipv4Addr>,
    inet4_loopback: Ipv4Addr,
    tcp_port: u16,
    tcp_mss: Option<u16>,
    tag: &Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    udp_timeout: Duration,
    local_subnets_v4: &[(Ipv4Addr, u8)],
    dns_tx: &Option<DnsQueryTx>,
    dns_hijack: bool,
) {
    if raw.len() < 20 {
        return;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    if raw.len() < ihl || ihl < 20 {
        return;
    }
    let flags_frag = u16::from_be_bytes([raw[6], raw[7]]);
    let more_fragments = (flags_frag & 0x2000) != 0;
    let frag_offset = flags_frag & 0x1fff;

    let src_ip = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
    let dst_ip = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
    let payload = &raw[ihl..];

    // ── 本地子网流量过滤 ───────────────────────────────────────────────
    // 若 src 或 dst 落在任一本地（非 TUN）网卡子网内，直接丢弃。
    // 这避免了 auto_route 劫持 LAN/Docker 流量后形成的死循环：
    // 主机发 UDP 到 LAN → TUN 劫持 → reflex 转发 → 出站包又被 TUN 劫持 → ...
    if !local_subnets_v4.is_empty()
        && (ip_in_local_subnets_v4(src_ip, local_subnets_v4)
            || ip_in_local_subnets_v4(dst_ip, local_subnets_v4))
    {
        return;
    }

    match raw[9] {
        IPPROTO_TCP => {
            if more_fragments || frag_offset != 0 {
                debug!("tun: ipv4 tcp fragment dropped");
                return;
            }
            handle_tcp_v4(
                raw,
                payload,
                src_ip,
                dst_ip,
                inet4_server_addr,
                inet4_client_addr,
                inet4_loopback,
                tcp_port,
                tcp_mss,
                writer,
                tcp_nat,
            )
            .await;
        }
        IPPROTO_UDP => {
            if more_fragments || frag_offset != 0 {
                debug!("tun: ipv4 udp fragment dropped");
                return;
            }
            // 过滤非全局单播目标（参照 sing-tun processIPv4UDP L582-584）。
            if !is_global_unicast_v4(dst_ip) {
                return;
            }
            if let Some((src, dst, data)) = parse_udp_v4(payload, src_ip, dst_ip) {
                dispatch_udp(
                    src,
                    dst,
                    data,
                    tag.clone(),
                    udp_tx,
                    writer,
                    udp_sessions,
                    udp_timeout,
                    dns_tx,
                    dns_hijack,
                )
                .await;
            }
        }
        IPPROTO_ICMP => {
            // 与 sing-tun processIPv4 一致：广播地址 / 非全局单播目标直接返回。
            if Some(dst_ip) == inet4_broadcast || !is_global_unicast_v4(dst_ip) {
                return;
            }
            handle_icmpv4(raw, ihl, src_ip, dst_ip, inet4_server_addr, writer).await;
        }
        _ => {}
    }
}

// ── IPv6 包处理 ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_ipv6(
    raw: &[u8],
    inet6_server_addr: Option<Ipv6Addr>,
    inet6_client_addr: Option<Ipv6Addr>,
    inet6_loopback: Ipv6Addr,
    tcp_port: u16,
    tcp_mss: Option<u16>,
    tag: &Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    udp_timeout: Duration,
    local_subnets_v6: &[(Ipv6Addr, u8)],
    dns_tx: &Option<DnsQueryTx>,
    dns_hijack: bool,
) {
    if raw.len() < 40 {
        return;
    }
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap_or([0u8; 16]));
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));
    let payload = &raw[40..];

    // ── 本地子网流量过滤（与 process_ipv4 同理）───────────────────────
    if !local_subnets_v6.is_empty()
        && (ip_in_local_subnets_v6(src_ip, local_subnets_v6)
            || ip_in_local_subnets_v6(dst_ip, local_subnets_v6))
    {
        return;
    }

    match raw[6] {
        IPPROTO_TCP => {
            handle_tcp_v6(
                raw,
                payload,
                src_ip,
                dst_ip,
                inet6_server_addr,
                inet6_client_addr,
                inet6_loopback,
                tcp_port,
                tcp_mss,
                writer,
                tcp_nat,
            )
            .await;
        }
        IPPROTO_UDP => {
            // 过滤非全局单播目标（参照 sing-tun processIPv6UDP L592-594）。
            if !is_global_unicast_v6(dst_ip) {
                return;
            }
            if let Some((src, dst, data)) = parse_udp_v6(payload, src_ip, dst_ip) {
                dispatch_udp(
                    src,
                    dst,
                    data,
                    tag.clone(),
                    udp_tx,
                    writer,
                    udp_sessions,
                    udp_timeout,
                    dns_tx,
                    dns_hijack,
                )
                .await;
            }
        }
        IPPROTO_ICMPV6 => {
            // 与 sing-tun processIPv6 一致：非全局单播目标直接返回。
            if !is_global_unicast_v6(dst_ip) {
                return;
            }
            handle_icmpv6(raw, src_ip, dst_ip, inet6_server_addr, writer).await;
        }
        _ => {}
    }
}

// ── TCP System Stack NAT（参照 sing-tun processIPv4TCP/processIPv6TCP）────────

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tcp_v4(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    inet4_server_addr: Option<Ipv4Addr>,
    inet4_client_addr: Option<Ipv4Addr>,
    inet4_loopback: Ipv4Addr,
    tcp_port: u16,
    tcp_mss: Option<u16>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
) {
    let (server_addr, client_addr) = match (inet4_server_addr, inet4_client_addr) {
        (Some(a), Some(n)) => (a, n),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);
    let ihl = ((raw[0] & 0x0f) as usize) * 4;

    // 来自 Listener 的回包（参照 sing-tun processIPv4TCP L390：src == server_addr && srcPort == tcpPort）。
    // 注意此处 inet4_addr 为 server_addr（listener 绑定地址），与旧实现一致。
    if src_ip == server_addr && src_port == tcp_port {
        let nat_dst_port = dst_port;
        let result = tcp_nat.lookup_back(nat_dst_port).await;
        if let Some((orig_src, orig_dst)) = result {
            let mut pkt = raw.to_vec();
            let (new_src_ip, new_src_port) = match orig_dst {
                SocketAddr::V4(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            let (new_dst_ip, new_dst_port) = match orig_src {
                SocketAddr::V4(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            pkt[12..16].copy_from_slice(&new_src_ip);
            pkt[16..20].copy_from_slice(&new_dst_ip);
            pkt[ihl..ihl + 2].copy_from_slice(&new_src_port.to_be_bytes());
            pkt[ihl + 2..ihl + 4].copy_from_slice(&new_dst_port.to_be_bytes());
            // 回包方向也 clamp MSS（SYN-ACK 也需处理，参照 sing-tun rewriteForward 不区分方向）
            if let Some(max_mss) = tcp_mss {
                clamp_tcp_mss(&mut pkt, ihl, max_mss);
            }
            recompute_tcp_checksum_v4(&mut pkt, ihl);
            recompute_ipv4_checksum(&mut pkt);
            tun_write(&writer, &pkt, false).await;
        }
        return;
    }

    // 过滤非全局单播目标（参照 sing-tun processIPv4TCP L388：destination.Addr().IsGlobalUnicast()）
    if !is_global_unicast_v4(dst_ip) {
        return;
    }

    // loopback 重写（参照 sing-tun processIPv4TCP L400-408）
    if dst_ip == inet4_loopback {
        let mut pkt = raw.to_vec();
        // 把目标改为源 IP，源改为 loopback（与 sing-tun 一致，使本地回环服务可见）
        pkt[12..16].copy_from_slice(&inet4_loopback.octets()); // src = loopback
        pkt[16..20].copy_from_slice(&src_ip.octets()); // dst = 原 src
                                                       // loopback 重写路径也 clamp MSS（SYN 包仍需处理）
        if let Some(max_mss) = tcp_mss {
            clamp_tcp_mss(&mut pkt, ihl, max_mss);
        }
        recompute_tcp_checksum_v4(&mut pkt, ihl);
        recompute_ipv4_checksum(&mut pkt);
        tun_write(&writer, &pkt, false).await;
        return;
    }

    let src = SocketAddr::V4(SocketAddrV4::new(src_ip, src_port));
    let dst = SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port));

    let nat_port = tcp_nat.lookup_or_insert(src, dst).await;

    let mut pkt = raw.to_vec();
    // 与 sing-tun processIPv4TCP L418-421 对齐：
    //   src = client_addr（server_addr.Next()），dst = server_addr
    pkt[12..16].copy_from_slice(&client_addr.octets());
    pkt[16..20].copy_from_slice(&server_addr.octets());
    pkt[ihl..ihl + 2].copy_from_slice(&nat_port.to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&tcp_port.to_be_bytes());
    // 转发方向 clamp MSS（参照 sing-tun rewriteForward：isTCPSyn 时调用 clampTCPMSS）
    if let Some(max_mss) = tcp_mss {
        clamp_tcp_mss(&mut pkt, ihl, max_mss);
    }
    recompute_tcp_checksum_v4(&mut pkt, ihl);
    recompute_ipv4_checksum(&mut pkt);
    tun_write(&writer, &pkt, false).await;

    debug!(src = %src, dst = %dst, nat_port, "tun: tcp v4 NAT");
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_tcp_v6(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    inet6_server_addr: Option<Ipv6Addr>,
    inet6_client_addr: Option<Ipv6Addr>,
    inet6_loopback: Ipv6Addr,
    tcp_port: u16,
    tcp_mss: Option<u16>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
) {
    let (server_addr, client_addr) = match (inet6_server_addr, inet6_client_addr) {
        (Some(a), Some(n)) => (a, n),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);

    // 来自 Listener 的回包（参照 sing-tun processIPv6TCP L485）
    if src_ip == server_addr && src_port == tcp_port {
        let result = tcp_nat.lookup_back(dst_port).await;
        if let Some((orig_src, orig_dst)) = result {
            let mut pkt = raw.to_vec();
            let (new_src_ip, new_src_port) = match orig_dst {
                SocketAddr::V6(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            let (new_dst_ip, new_dst_port) = match orig_src {
                SocketAddr::V6(a) => (a.ip().octets(), a.port()),
                _ => return,
            };
            pkt[8..24].copy_from_slice(&new_src_ip);
            pkt[24..40].copy_from_slice(&new_dst_ip);
            pkt[40..42].copy_from_slice(&new_src_port.to_be_bytes());
            pkt[42..44].copy_from_slice(&new_dst_port.to_be_bytes());
            // 回包方向也 clamp MSS（SYN-ACK 也需处理）
            if let Some(max_mss) = tcp_mss {
                clamp_tcp_mss(&mut pkt, 40, max_mss);
            }
            recompute_tcp_checksum_v6(&mut pkt);
            tun_write(&writer, &pkt, true).await;
        }
        return;
    }

    // 过滤非全局单播目标（参照 sing-tun processIPv6TCP L483）
    if !is_global_unicast_v6(dst_ip) {
        return;
    }

    // loopback 重写（参照 sing-tun processIPv6TCP L495-503）
    if dst_ip == inet6_loopback {
        let mut pkt = raw.to_vec();
        pkt[8..24].copy_from_slice(&inet6_loopback.octets()); // src = loopback
        pkt[24..40].copy_from_slice(&src_ip.octets()); // dst = 原 src
                                                       // loopback 重写路径也 clamp MSS（SYN 包仍需处理）
        if let Some(max_mss) = tcp_mss {
            clamp_tcp_mss(&mut pkt, 40, max_mss);
        }
        recompute_tcp_checksum_v6(&mut pkt);
        tun_write(&writer, &pkt, true).await;
        return;
    }

    let src = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
    let dst = SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0));
    let nat_port = tcp_nat.lookup_or_insert(src, dst).await;

    let mut pkt = raw.to_vec();
    // 与 sing-tun processIPv6TCP L513-516 对齐：
    //   src = client_addr，dst = server_addr
    pkt[8..24].copy_from_slice(&client_addr.octets());
    pkt[24..40].copy_from_slice(&server_addr.octets());
    pkt[40..42].copy_from_slice(&nat_port.to_be_bytes());
    pkt[42..44].copy_from_slice(&tcp_port.to_be_bytes());
    // 转发方向 clamp MSS（参照 sing-tun rewriteForward：isTCPSyn 时调用 clampTCPMSS）
    if let Some(max_mss) = tcp_mss {
        clamp_tcp_mss(&mut pkt, 40, max_mss);
    }
    recompute_tcp_checksum_v6(&mut pkt);
    tun_write(&writer, &pkt, true).await;
}

// ── ICMPv4 回环 ───────────────────────────────────────────────────────────────

pub(crate) async fn handle_icmpv4(
    raw: &[u8],
    ihl: usize,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    _inet4_server_addr: Option<Ipv4Addr>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
) {
    let payload = &raw[ihl..];
    if payload.len() < 8 {
        return;
    }
    // 与 sing-tun processIPv4ICMP L643 一致：只响应 Echo Request 且 Code==0
    if payload[0] != 8 || payload[1] != 0 {
        return;
    }

    let mut pkt = raw.to_vec();
    pkt[12..16].copy_from_slice(&dst_ip.octets());
    pkt[16..20].copy_from_slice(&src_ip.octets());
    pkt[ihl] = 0; // Echo Reply
    pkt[ihl + 2] = 0;
    pkt[ihl + 3] = 0;
    let cksum = internet_checksum(&pkt[ihl..]);
    pkt[ihl + 2] = (cksum >> 8) as u8;
    pkt[ihl + 3] = (cksum & 0xff) as u8;
    recompute_ipv4_checksum(&mut pkt);
    tun_write(&writer, &pkt, false).await;
}

// ── ICMPv6 回环 ───────────────────────────────────────────────────────────────

pub(crate) async fn handle_icmpv6(
    raw: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    _inet6_server_addr: Option<Ipv6Addr>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
) {
    if raw.len() < 48 {
        return;
    }
    // 与 sing-tun processIPv6ICMP L695 一致：只响应 Echo Request 且 Code==0
    if raw[40] != 128 || raw[41] != 0 {
        return;
    }

    let mut pkt = raw.to_vec();
    pkt[8..24].copy_from_slice(&dst_ip.octets());
    pkt[24..40].copy_from_slice(&src_ip.octets());
    pkt[40] = 129; // Echo Reply
    recompute_icmpv6_checksum(&mut pkt);
    tun_write(&writer, &pkt, true).await;
}

// ── UDP 分发 ──────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn dispatch_udp(
    src: SocketAddr,
    dst: SocketAddr,
    data: Bytes,
    tag: Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    _udp_timeout: Duration,
    dns_tx: &Option<DnsQueryTx>,
    dns_hijack: bool,
) {
    // TUN 层 DNS 劫持：参考 clash-rs datagram.rs:97-168，
    // 在端口 53 且 hijack_dns 启用时直接通过 DNS 解析器响应，
    // 不创建 UDP session / 不经过代理路径。
    if dns_hijack && dst.port() == 53 {
        let (reply_tx, reply_rx) = oneshot::channel();
        let query = DnsQuery {
            message: data,
            from: src,
            inbound_tag: (*tag).clone(),
            source: DnsQuerySource::Hijacked,
            reply_tx,
        };
        if let Some(ref tx) = dns_tx {
            if tx.send(query).await.is_err() {
                debug!("tun: dns_tx closed, skip DNS hijack");
                return;
            }
            match reply_rx.await {
                Ok(response) => {
                    if let Some(pkt) = build_udp_reply_packet(dst, src, &response) {
                        let is_v6 = matches!(dst, SocketAddr::V6(_));
                        tun_write(&writer, &pkt, is_v6).await;
                    }
                }
                Err(_) => {
                    debug!("tun: DNS reply rx dropped");
                }
            }
        }
        return;
    }

    let key = (src, dst);
    let mut sessions = udp_sessions.lock().await;

    let entry = sessions.entry(key).or_insert_with(|| {
        debug!(src = %src, dst = %dst, "tun: new UDP session");
        let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
        let w = writer.clone();
        tokio::spawn(async move {
            while let Some((payload, _client_src, server_src)) = reply_rx.recv().await {
                // 回包：IP 源 = 远端服务器（server_src / spoofed_src），
                // IP 目标 = 原始客户端（src）。出站发送的元组为
                // (data, client_src, spoofed_src)，此前误把 client_src 当作
                // 回包源地址，导致 src=dst=client，回包被 OS 丢弃。
                if let Some(pkt) = build_udp_reply_packet(server_src, src, &payload) {
                    let is_v6 = matches!(server_src, SocketAddr::V6(_));
                    tun_write(&w, &pkt, is_v6).await;
                }
            }
        });
        UdpEntry {
            reply_tx,
            last_seen: Instant::now(),
        }
    });
    entry.last_seen = Instant::now();
    let session = UdpSession {
        reply_tx: entry.reply_tx.clone(),
    };
    drop(sessions);

    let packet = InboundUdpPacket {
        data,
        src,
        target: Target::Socket(dst),
        inbound_tag: (*tag).clone(),
        session,
        sniffed_protocol: None,
        sniffed_domain: None,
        origin_destination: None,
        upstream_rx: None,
        lifetime_guards: vec![],
    };
    if udp_tx.send(packet).await.is_err() {
        debug!("tun: udp_tx closed");
    }
}

// ── 解析函数 ──────────────────────────────────────────────────────────────────

pub(crate) fn parse_udp_v4(
    udp: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
) -> Option<(SocketAddr, SocketAddr, Bytes)> {
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload_len = length.saturating_sub(8).min(udp.len().saturating_sub(8));
    let data = Bytes::copy_from_slice(&udp[8..8 + payload_len]);
    Some((
        SocketAddr::V4(SocketAddrV4::new(src_ip, src_port)),
        SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port)),
        data,
    ))
}

pub(crate) fn parse_udp_v6(
    udp: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
) -> Option<(SocketAddr, SocketAddr, Bytes)> {
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload_len = length.saturating_sub(8).min(udp.len().saturating_sub(8));
    let data = Bytes::copy_from_slice(&udp[8..8 + payload_len]);
    Some((
        SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0)),
        SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0)),
        data,
    ))
}

// ── UDP 回包封装（纯 IP 包，不含 PI 头）──────────────────────────────────────

pub(crate) fn build_udp_reply_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => build_udp_reply_v4(s, d, payload),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => build_udp_reply_v6(s, d, payload),
        _ => None,
    }
}

fn build_udp_reply_v4(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = (8 + payload.len()) as u16;
    let total_len = 20u16 + udp_len;

    // 纯 IP 包，不含 PI 头
    let mut pkt = Vec::with_capacity(total_len as usize);

    // IP header
    pkt.extend_from_slice(&[
        0x45,
        0x00,
        (total_len >> 8) as u8,
        (total_len & 0xff) as u8,
        0x00,
        0x00,
        0x40,
        0x00, // id=0, DF
        64,
        IPPROTO_UDP,
        0x00,
        0x00, // TTL, proto, checksum=0
    ]);
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());

    // IP checksum（针对前 20 字节）
    let cksum = internet_checksum(&pkt[..20]);
    pkt[10] = (cksum >> 8) as u8;
    pkt[11] = (cksum & 0xff) as u8;

    // UDP header
    let udp_start = pkt.len();
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(payload);

    // UDP checksum（含 IPv4 伪头部）
    let cksum = udp_checksum_v4(&src.ip().octets(), &dst.ip().octets(), &pkt[udp_start..]);
    pkt[udp_start + 6] = (cksum >> 8) as u8;
    pkt[udp_start + 7] = (cksum & 0xff) as u8;

    Some(pkt)
}

fn build_udp_reply_v6(src: SocketAddrV6, dst: SocketAddrV6, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = (8 + payload.len()) as u16;

    // 纯 IPv6 包，不含 PI 头
    let mut pkt = Vec::with_capacity(40 + udp_len as usize);

    // IPv6 fixed header (40 bytes)
    pkt.push(0x60);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // flow label
    pkt.extend_from_slice(&udp_len.to_be_bytes()); // PayloadLength
    pkt.push(IPPROTO_UDP);
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src.ip().octets());
    pkt.extend_from_slice(&dst.ip().octets());

    // UDP header + payload
    let udp_start = pkt.len();
    pkt.extend_from_slice(&src.port().to_be_bytes());
    pkt.extend_from_slice(&dst.port().to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    pkt.extend_from_slice(payload);

    // UDP checksum（含 IPv6 伪头部）
    let cksum = udp_checksum_v6(&src.ip().octets(), &dst.ip().octets(), &pkt[udp_start..]);
    pkt[udp_start + 6] = (cksum >> 8) as u8;
    pkt[udp_start + 7] = (cksum & 0xff) as u8;

    Some(pkt)
}

// ── Checksum 计算 ─────────────────────────────────────────────────────────────

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IPv4 包 checksum（不含 PI 头，直接操作原始 IP 包）
fn recompute_ipv4_checksum(pkt: &mut [u8]) {
    if pkt.len() < 20 {
        return;
    }
    pkt[10] = 0;
    pkt[11] = 0;
    let cksum = internet_checksum(&pkt[..20]);
    pkt[10] = (cksum >> 8) as u8;
    pkt[11] = (cksum & 0xff) as u8;
}

/// IPv4 TCP checksum（`pkt` 为原始 IP 包，`ihl` 为 IP 头长度）
fn recompute_tcp_checksum_v4(pkt: &mut [u8], ihl: usize) {
    if pkt.len() < ihl + 18 {
        return;
    }
    let src_ip: [u8; 4] = pkt[12..16].try_into().unwrap_or([0u8; 4]);
    let dst_ip: [u8; 4] = pkt[16..20].try_into().unwrap_or([0u8; 4]);
    let tcp_off = ihl;
    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let cksum = checksum_with_pseudo_v4(&src_ip, &dst_ip, IPPROTO_TCP, &pkt[tcp_off..]);
    pkt[tcp_off + 16] = (cksum >> 8) as u8;
    pkt[tcp_off + 17] = (cksum & 0xff) as u8;
}

/// IPv6 TCP checksum（`pkt` 为原始 IPv6 包）
fn recompute_tcp_checksum_v6(pkt: &mut [u8]) {
    if pkt.len() < 40 + 18 {
        return;
    }
    let src_ip: [u8; 16] = pkt[8..24].try_into().unwrap_or([0u8; 16]);
    let dst_ip: [u8; 16] = pkt[24..40].try_into().unwrap_or([0u8; 16]);
    let tcp_off = 40;
    pkt[tcp_off + 16] = 0;
    pkt[tcp_off + 17] = 0;
    let cksum = checksum_with_pseudo_v6(&src_ip, &dst_ip, IPPROTO_TCP, &pkt[tcp_off..]);
    pkt[tcp_off + 16] = (cksum >> 8) as u8;
    pkt[tcp_off + 17] = (cksum & 0xff) as u8;
}

/// TCP 选项常量（参照 sing-tun gtcpip/header/tcp.go）。
const TCP_OPT_EOL: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_MSS_LEN: u8 = 4;
/// TCP 最小头长度（字节）。
const TCP_MIN_HEADER_LEN: usize = 20;
/// SYN 标志位（TCP flags 第 13 字节）。
const TCP_FLAG_SYN: u8 = 0x02;

/// 修改 TCP SYN 包的 MSS option，将其限制在 `max_mss` 以内。
///
/// 参照 sing-tun `clampTCPMSS`（flow_rewrite.go L227-L280）：
/// - 仅遍历 TCP options 区域（data offset 之后），不动 payload
/// - 找到 MSS option（type=2, len=4）后，若原值 > max_mss 则改写为 max_mss
/// - 遇到 EOL 或非法 option 长度时停止
/// - 调用方需在改写后调用 `recompute_tcp_checksum_v4` / `_v6` 修正校验和
///
/// `tcp_off` 是 TCP 头在 `pkt` 中的起始偏移；`pkt` 为可写的原始 IP 包。
/// 返回 true 表示已改写 MSS（需要重算 checksum），false 表示未改写。
fn clamp_tcp_mss(pkt: &mut [u8], tcp_off: usize, max_mss: u16) -> bool {
    // 至少需要 TCP 头 + 4 字节 option 才可能有 MSS
    if pkt.len() < tcp_off + TCP_MIN_HEADER_LEN + 4 {
        return false;
    }
    // data offset 字段（高 4 位）以 4 字节为单位
    let data_offset = (pkt[tcp_off + 12] >> 4) as usize * 4;
    if data_offset < TCP_MIN_HEADER_LEN || tcp_off + data_offset > pkt.len() {
        return false;
    }

    // 仅 SYN / SYN-ACK 包需要 clamp（参照 sing-tun rewriteForward 仅在 isTCPSyn 时调用）
    if pkt[tcp_off + 13] & TCP_FLAG_SYN == 0 {
        return false;
    }

    let options = &mut pkt[tcp_off + TCP_MIN_HEADER_LEN..tcp_off + data_offset];
    let mut i = 0;
    while i < options.len() {
        match options[i] {
            TCP_OPT_EOL => return false,
            TCP_OPT_NOP => {
                i += 1;
                continue;
            }
            TCP_OPT_MSS => {
                // MSS option 格式：[kind=2][len=4][mss_hi][mss_lo]
                if i + 4 > options.len() || options[i + 1] != TCP_OPT_MSS_LEN {
                    return false;
                }
                let current = u16::from_be_bytes([options[i + 2], options[i + 3]]);
                if current <= max_mss {
                    return false;
                }
                options[i + 2] = (max_mss >> 8) as u8;
                options[i + 3] = (max_mss & 0xff) as u8;
                return true;
            }
            _ => {
                // 其他 option：用 length 字段跳过；length < 2 视为非法（参照 sing-tun）
                if i + 2 > options.len() {
                    return false;
                }
                let opt_len = options[i + 1] as usize;
                if opt_len < 2 || i + opt_len > options.len() {
                    return false;
                }
                i += opt_len;
            }
        }
    }
    false
}

/// ICMPv6 checksum（含 IPv6 伪头部）
fn recompute_icmpv6_checksum(pkt: &mut [u8]) {
    if pkt.len() < 40 + 8 {
        return;
    }
    let src_ip: [u8; 16] = pkt[8..24].try_into().unwrap_or([0u8; 16]);
    let dst_ip: [u8; 16] = pkt[24..40].try_into().unwrap_or([0u8; 16]);
    let icmp_off = 40;
    pkt[icmp_off + 2] = 0;
    pkt[icmp_off + 3] = 0;
    let cksum = checksum_with_pseudo_v6(&src_ip, &dst_ip, IPPROTO_ICMPV6, &pkt[icmp_off..]);
    pkt[icmp_off + 2] = (cksum >> 8) as u8;
    pkt[icmp_off + 3] = (cksum & 0xff) as u8;
}

fn udp_checksum_v4(src: &[u8; 4], dst: &[u8; 4], udp: &[u8]) -> u16 {
    checksum_with_pseudo_v4(src, dst, IPPROTO_UDP, udp)
}

fn udp_checksum_v6(src: &[u8; 16], dst: &[u8; 16], udp: &[u8]) -> u16 {
    checksum_with_pseudo_v6(src, dst, IPPROTO_UDP, udp)
}

fn checksum_with_pseudo_v4(src: &[u8; 4], dst: &[u8; 4], proto: u8, data: &[u8]) -> u16 {
    let len = data.len() as u16;
    let pseudo = [
        src[0],
        src[1],
        src[2],
        src[3],
        dst[0],
        dst[1],
        dst[2],
        dst[3],
        0,
        proto,
        (len >> 8) as u8,
        (len & 0xff) as u8,
    ];
    let mut sum: u32 = 0;
    for chunk in pseudo.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_with_pseudo_v6(src: &[u8; 16], dst: &[u8; 16], proto: u8, data: &[u8]) -> u16 {
    let len = data.len() as u32;
    let mut sum: u32 = 0;
    for chunk in src.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    for chunk in dst.chunks_exact(2) {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += proto as u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ── Linux 路由实现 ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
// platform 模块已移至 `mod platform`（src/inbound/tun/platform/）
// 包含 Linux(rtnetlink)/macOS(AF_ROUTE)/Windows(WFP) 原生实现。

// platform 模块已移至 `mod platform`（src/inbound/tun/platform/）
// macOS 实现见 platform/macos.rs（AF_ROUTE + route 命令 fallback）

// platform 模块已移至 `mod platform`（src/inbound/tun/platform/）
// Windows 实现见 platform/windows.rs（WFP + winipcfg + netsh fallback）

// platform 模块已移至 `mod platform`（src/inbound/tun/platform/）
// 其他平台见 platform/stub.rs（空操作 + warn）

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_parse_addr_prefix() {
        let (ip, len) = parse_addr_prefix("198.18.0.1/16").unwrap();
        assert_eq!(ip, "198.18.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(len, 16);
    }

    #[test]
    fn test_parse_addr_prefix_ipv6() {
        let (ip, len) = parse_addr_prefix("fd00::1/126").unwrap();
        assert!(ip.is_ipv6());
        assert_eq!(len, 126);
    }

    #[test]
    fn test_parse_addr_prefix_invalid() {
        assert!(parse_addr_prefix("198.18.0.1").is_none());
        assert!(parse_addr_prefix("198.18.0.1/33").is_none());
    }

    #[test]
    fn test_internet_checksum_nonzero() {
        let hdr = [
            0x45u8, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10,
            0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        assert_ne!(internet_checksum(&hdr), 0);
    }

    #[tokio::test]
    async fn test_tcp_nat_alloc_and_lookup() {
        let nat = TcpNat::new();
        let src: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let dst: SocketAddr = "8.8.8.8:80".parse().unwrap();
        let port = nat.lookup_or_insert(src, dst).await;
        assert!((NAT_PORT_START..=NAT_PORT_END).contains(&port));
        // 同一 src 应得到同一 port
        assert_eq!(nat.lookup_or_insert(src, dst).await, port);
        let (got_src, got_dst) = nat.lookup_back(port).await.unwrap();
        assert_eq!(got_src, src);
        assert_eq!(got_dst, dst);
    }

    #[tokio::test]
    async fn test_tcp_nat_gc() {
        let nat = TcpNat::new();
        let src: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let dst: SocketAddr = "9.9.9.9:443".parse().unwrap();
        nat.lookup_or_insert(src, dst).await;
        nat.gc(Duration::from_secs(0)).await;
        assert!(nat.port_map.read().await.is_empty());
        assert!(nat.addr_map.read().await.is_empty());
    }

    #[tokio::test]
    async fn test_tcp_nat_eviction_correctness() {
        let nat = TcpNat::new();
        // 填满端口池
        for i in 0..(NAT_PORT_END - NAT_PORT_START + 1) {
            let src: SocketAddr = format!("10.0.{}.{}:1000", i / 256, i % 256)
                .parse()
                .unwrap();
            let dst: SocketAddr = "8.8.8.8:80".parse().unwrap();
            nat.lookup_or_insert(src, dst).await;
        }
        // 再分配一个新的，应触发 LRU 驱逐而不是覆盖随机条目
        let new_src: SocketAddr = "192.168.99.1:9999".parse().unwrap();
        let new_dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let port = nat.lookup_or_insert(new_src, new_dst).await;
        // 分配的端口应在合法范围内
        assert!((NAT_PORT_START..=NAT_PORT_END).contains(&port));
        // 新条目应可以反查
        assert!(nat.lookup_back(port).await.is_some());
    }

    #[test]
    fn test_addr_in_prefix_v4() {
        assert!(addr_in_prefix_v4(
            "198.18.0.5".parse().unwrap(),
            "198.18.0.0".parse().unwrap(),
            16
        ));
        assert!(!addr_in_prefix_v4(
            "10.0.0.1".parse().unwrap(),
            "198.18.0.0".parse().unwrap(),
            16
        ));
        assert!(addr_in_prefix_v4(
            "10.0.0.1".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            0
        ));
    }

    #[test]
    fn test_addr_in_prefix_v6() {
        // /120: fd00::0 — fd00::FF (256 地址)
        assert!(addr_in_prefix_v6(
            "fd00::5".parse().unwrap(),
            "fd00::".parse().unwrap(),
            120
        ));
        assert!(!addr_in_prefix_v6(
            "fd01::1".parse().unwrap(),
            "fd00::".parse().unwrap(),
            120
        ));
        // /126: 仅 4 地址 (0-3)
        assert!(addr_in_prefix_v6(
            "fd00::3".parse().unwrap(),
            "fd00::".parse().unwrap(),
            126
        ));
        assert!(!addr_in_prefix_v6(
            "fd00::4".parse().unwrap(),
            "fd00::".parse().unwrap(),
            126
        ));
    }

    #[test]
    fn test_build_udp_reply_v4_no_pi() {
        let src: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let dst: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let payload = b"hello world";
        let pkt = build_udp_reply_packet(src, dst, payload).unwrap();
        // 返回的是纯 IP 包（不含 PI 头）：IPv4(20) + UDP(8) + payload
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        // IP version = 4
        assert_eq!(pkt[0] >> 4, 4);
    }

    #[test]
    fn test_build_udp_reply_v6_no_pi() {
        let src: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let dst: SocketAddr = "[fe80::1]:12345".parse().unwrap();
        let payload = b"test";
        let pkt = build_udp_reply_packet(src, dst, payload).unwrap();
        // 返回的是纯 IPv6 包（不含 PI 头）：IPv6(40) + UDP(8) + payload
        assert_eq!(pkt.len(), 40 + 8 + payload.len());
        // IP version = 6
        assert_eq!(pkt[0] >> 4, 6);
    }

    #[test]
    fn test_udp_checksum_v4_nonzero() {
        let src = [8u8, 8, 8, 8];
        let dst = [192u8, 168, 1, 1];
        let udp = [
            0x00, 0x35, 0x30, 0x39, 0x00, 0x0c, 0x00, 0x00, b'h', b'i', b'!', b'!',
        ]; // port 53→12345, len=12
        let cksum = udp_checksum_v4(&src, &dst, &udp);
        assert_ne!(cksum, 0);
    }

    /// 构造一个带 MSS option 的 TCP SYN IPv4 包用于 clamp 测试。
    /// 包结构：IPv4 header (20B, IHL=5) + TCP header (24B, data offset=6, 含 4B MSS option)
    fn build_syn_v4_with_mss(mss: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 20 + 24];
        // IPv4 header
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[9] = IPPROTO_TCP; // protocol = TCP
                              // src/dst 可任意（不参与 clamp 逻辑）
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // TCP header
        let tcp_off = 20;
        pkt[tcp_off..tcp_off + 2].copy_from_slice(&0x1234u16.to_be_bytes()); // src port
        pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&0x0050u16.to_be_bytes()); // dst port
        pkt[tcp_off + 12] = 0x60; // data offset = 6 (24 bytes), reserved = 0
        pkt[tcp_off + 13] = TCP_FLAG_SYN; // SYN
                                          // TCP options: MSS option (kind=2, len=4, mss_hi, mss_lo)
        pkt[tcp_off + 20] = TCP_OPT_MSS;
        pkt[tcp_off + 21] = TCP_OPT_MSS_LEN;
        pkt[tcp_off + 22..tcp_off + 24].copy_from_slice(&mss.to_be_bytes());
        pkt
    }

    #[test]
    fn test_clamp_tcp_mss_v4_rewrites_when_exceeds() {
        let mut pkt = build_syn_v4_with_mss(1460);
        // max_mss = 1400，原值 1460 > 1400，应改写为 1400
        let changed = clamp_tcp_mss(&mut pkt, 20, 1400);
        assert!(changed);
        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss, 1400);
    }

    #[test]
    fn test_clamp_tcp_mss_v4_no_rewrite_when_within() {
        let mut pkt = build_syn_v4_with_mss(1200);
        // max_mss = 1400，原值 1200 <= 1400，不应改写
        let changed = clamp_tcp_mss(&mut pkt, 20, 1400);
        assert!(!changed);
        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss, 1200);
    }

    #[test]
    fn test_clamp_tcp_mss_v4_skips_non_syn() {
        let mut pkt = build_syn_v4_with_mss(1460);
        // 把 SYN flag 改为 ACK (0x10)，不应改写
        pkt[20 + 13] = 0x10;
        let changed = clamp_tcp_mss(&mut pkt, 20, 1400);
        assert!(!changed);
        let mss = u16::from_be_bytes([pkt[20 + 22], pkt[20 + 23]]);
        assert_eq!(mss, 1460);
    }

    #[test]
    fn test_clamp_tcp_mss_v4_skips_when_no_mss_option() {
        // 构造一个只有 NOP+NOP 的 SYN 包（不含 MSS option）
        let mut pkt = vec![0u8; 20 + 24];
        pkt[0] = 0x45;
        pkt[9] = IPPROTO_TCP;
        let tcp_off = 20;
        pkt[tcp_off + 12] = 0x60; // data offset = 6
        pkt[tcp_off + 13] = TCP_FLAG_SYN;
        pkt[tcp_off + 20] = TCP_OPT_NOP;
        pkt[tcp_off + 21] = TCP_OPT_NOP;
        pkt[tcp_off + 22] = TCP_OPT_NOP;
        pkt[tcp_off + 23] = TCP_OPT_NOP;
        let changed = clamp_tcp_mss(&mut pkt, 20, 1400);
        assert!(!changed);
    }

    #[test]
    fn test_clamp_tcp_mss_v6_rewrites_when_exceeds() {
        // IPv6 包：40B IPv6 header + 24B TCP header (含 MSS option)
        let mut pkt = vec![0u8; 40 + 24];
        pkt[0] = 0x60; // IPv6 version
        pkt[6] = IPPROTO_TCP; // next header = TCP
        let tcp_off = 40;
        pkt[tcp_off + 12] = 0x60; // data offset = 6
        pkt[tcp_off + 13] = TCP_FLAG_SYN;
        pkt[tcp_off + 20] = TCP_OPT_MSS;
        pkt[tcp_off + 21] = TCP_OPT_MSS_LEN;
        pkt[tcp_off + 22..tcp_off + 24].copy_from_slice(&1500u16.to_be_bytes());
        let changed = clamp_tcp_mss(&mut pkt, 40, 1280);
        assert!(changed);
        let mss = u16::from_be_bytes([pkt[tcp_off + 22], pkt[tcp_off + 23]]);
        assert_eq!(mss, 1280);
    }
}
