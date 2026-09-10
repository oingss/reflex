pub mod gso;
pub mod gvisor;
pub mod icmp_forwarder;
mod interface_monitor;
mod ip_defrag;
mod native_tun;
mod netstack;
pub mod platform;

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
    app::outbound_mgr::OutboundManager,
    config::inbound::TunInboundConfig,
    inbound::{
        dns::{DnsQuery, DnsQuerySource, DnsQueryTx},
        InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession,
    },
    router::Router,
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
    for _attempt in 0..TUN_VISIBILITY_MAX_ATTEMPTS {
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
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("(Get-NetAdapter -Name '{if_name}' -ErrorAction SilentlyContinue).ifIndex"),
        ])
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

// ── 本地子网流量说明 ─────────────────────────────────────────────────────────
//
// 当 TUN 启用 auto_route 后，所有流量（包括访问本机 LAN/Docker 子网的流量）
// 都可能被 TUN 劫持。B5 修复后各栈统一不再在用户态按"本地子网"丢包
// （旧实现在此收集本地子网并丢弃 src/dst 命中的包，导致 LAN/NAS/打印机
// 不可达）：LAN 连通性由路由规则保证（fwmark 规则带 suppress_prefixlength 0，
// main 表中更精确的本地子网路由优先，LAN 流量根本不进 TUN；端口 53 的
// DNS 例外，被有意劫持）。到达 TUN 的 LAN 包按正常路径处理
// （DNS 劫持 / NAT / 转发），与 sing-tun 语义一致。

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

/// 检查 `ip + 1` 是否仍在前缀 `(ip, prefix_len)` 内（对齐 sing-tun HasNextAddress）。
/// 用于 system stack 校验 client_addr（= server_addr.Next()）的可达性。
/// 返回 false 的典型场景：
/// - `/32`：ip+1 不在 /32 内
/// - `x.x.x.255/24`：ip+1 = x.x.(x+1).0 不在 /24 内
/// - `255.255.255.255/any`：ip+1 溢出为 0.0.0.0
fn has_next_addr_v4(ip: Ipv4Addr, prefix_len: u8) -> bool {
    let cur = u32::from(ip);
    // 防溢出：255.255.255.255 + 1 = 0（wrap），无下一地址
    if cur == u32::MAX {
        return false;
    }
    let next = cur + 1;
    if prefix_len == 0 {
        return true;
    }
    let pl = prefix_len.min(32) as u32;
    let mask = !((1u32 << (32 - pl)) - 1);
    (cur & mask) == (next & mask)
}

/// IPv6 版本（对齐 sing-tun HasNextAddress）。
fn has_next_addr_v6(ip: Ipv6Addr, prefix_len: u8) -> bool {
    let cur = u128::from(ip);
    if cur == u128::MAX {
        return false;
    }
    let next = cur + 1;
    if prefix_len == 0 {
        return true;
    }
    let pl = prefix_len.min(128) as u128;
    let mask = !((1u128 << (128 - pl)) - 1);
    (cur & mask) == (next & mask)
}

/// 判断 IPv4 地址是否在指定前缀内。
#[allow(dead_code)]
fn addr_in_prefix_v4(addr: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    let mask = !((1u32 << (32 - prefix_len.min(32))) - 1);
    (u32::from(addr) & mask) == (u32::from(network) & mask)
}

#[allow(dead_code)]
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
    /// - 端口池耗尽时返回 `None`，丢弃新连接（对齐 sing-tun allocatePortLocked
    ///   返回 (0, false) 后 Lookup 返回 0，processIPv4TCP 报错并丢包）。
    ///   **不驱逐**已有条目——驱逐活跃连接的 NAT 端口会导致：
    ///   1) 被驱逐连接的回包 lookup_back 返回 None → 连接挂死
    ///   2) 被驱逐端口被新连接复用 → 旧连接回包被误送到新客户端 → 数据错乱
    ///
    /// 锁顺序：addr_map → port_map（与 sing-tun 一致，避免死锁）。
    async fn lookup_or_insert(&self, src: SocketAddr, dst: SocketAddr) -> Option<u16> {
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
            return Some(port);
        }

        // 慢速路径：addr_map 写锁 + 双检锁（对齐 sing-tun Lookup L111-L114）
        let mut addr_map = self.addr_map.write().await;
        if let Some(&port) = addr_map.get(&key) {
            // 并发请求已插入，用已有的
            return Some(port);
        }

        // 分配新端口：port_map 写锁 + 线性探测（对齐 sing-tun allocatePortLocked）
        let mut port_map = self.port_map.write().await;
        let port = self.allocate_port_locked(&port_map)?;

        let entry = Arc::new(TcpNatEntry {
            source: src,
            destination: dst,
            last_active: std::sync::Mutex::new(Instant::now()),
        });
        port_map.insert(port, entry);
        addr_map.insert(key, port);
        Some(port)
    }

    /// 线性探测分配端口（对齐 sing-tun allocatePortLocked L131-L144）。
    /// 端口池满时返回 `None`（不驱逐，对齐 sing-tun 返回 (0, false)）。
    /// 调用者必须持有 port_map 的写锁。
    fn allocate_port_locked(&self, port_map: &HashMap<u16, Arc<TcpNatEntry>>) -> Option<u16> {
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
                return Some(p);
            }
        }
        // 端口池满：不驱逐，返回 None（对齐 sing-tun 行为）
        None
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
            // R6：读锁收集与写锁删除之间存在窗口，期间 lookup_or_insert /
            // lookup_back 可能已刷新该条目的 last_active。删除前在写锁内
            // 二次确认，避免误删活跃连接（误删后回包 lookup_back 失败，
            // 客户端连接静默挂死）。
            if let Some(e) = port_map.get(&port) {
                let still_expired = e
                    .last_active
                    .lock()
                    .map(|t| now.duration_since(*t) > timeout)
                    .unwrap_or(false);
                if !still_expired {
                    continue;
                }
            }
            port_map.remove(&port);
            addr_map.remove(&key);
        }
    }

    /// 清空全部 NAT 会话（对齐 sing-tun ResetNetwork：网络切换时调用）。
    /// 锁顺序：addr_map → port_map（与 lookup_or_insert 一致）。
    pub(crate) async fn clear(&self) {
        self.addr_map.write().await.clear();
        self.port_map.write().await.clear();
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

// ── MTU 闭环（F3 补齐，对齐 sing-tun flow_mtu.go）───────────────────────────
//
// 旧实现把超过 TUN MTU 的回包直接写入 TUN，被内核静默丢弃（大包 UDP / DF
// 流量静默失败，无 PMTU 通知）。对齐 sing-tun forwardToPort 的 MTU 处理：
// - IPv4 非 DF：用户态分片（fragmentIPv4Packet）
// - IPv4 DF：回 ICMPv4 Destination Unreachable / Fragmentation Needed
// - IPv6：回 ICMPv6 Packet Too Big

/// MTU 闭环写出：包不超过 MTU 时直接写；超限时按协议分片或回 ICMP 错误。
pub(crate) async fn tun_write_mtu(
    writer: &Mutex<impl AsyncWriteExt + Unpin + Send>,
    pkt: Vec<u8>,
    mtu: usize,
    is_ipv6: bool,
) {
    if mtu == 0 || pkt.len() <= mtu {
        tun_write(writer, &pkt, is_ipv6).await;
        return;
    }
    if !is_ipv6 {
        // DF 标志（bit 14 of flags/frag 字段，0x4000）
        let df = pkt.len() >= 8 && (u16::from_be_bytes([pkt[6], pkt[7]]) & 0x4000) != 0;
        if !df {
            match fragment_ipv4_packet(&pkt, mtu) {
                Some(fragments) => {
                    for frag in fragments {
                        tun_write(writer, &frag, false).await;
                    }
                    return;
                }
                None => {
                    // 分片失败（头部异常 / MTU 过小）：退回 FragNeeded 通告
                }
            }
        }
        if let Some(reply) = build_fragmentation_needed(&pkt, mtu) {
            tun_write(writer, &reply, false).await;
        }
    } else if let Some(reply) = build_packet_too_big(&pkt, mtu) {
        tun_write(writer, &reply, true).await;
    }
}

/// IPv4 最小 MTU（RFC 791：每个主机必须能转发 68 字节数据报）。
const IPV4_MINIMUM_MTU: usize = 68;
/// IPv6 最小 MTU（RFC 8200：1280 字节）。
const IPV6_MINIMUM_MTU: usize = 1280;
/// 合成 ICMP 错误包的 TTL（对齐 sing-tun synthesizedTTL）。
const SYNTHESIZED_TTL: u8 = 64;

/// TCP 校验和（IPv4 伪头部）。
fn tcp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(12 + tcp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(IPPROTO_TCP);
    buf.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp);
    !internet_checksum(&buf)
}

/// TCP 校验和（IPv6 伪头部）。
fn tcp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, tcp: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + tcp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0]);
    buf.push(IPPROTO_TCP);
    buf.extend_from_slice(tcp);
    !internet_checksum(&buf)
}

/// 构造 TCP RST 回包（T3，对齐 sing-tun PrepareConnection 失败 → RST）。
///
/// 用于响应客户端 SYN 但 NAT/监听器无法建立连接的场景：RST|ACK、
/// seq=0、ack=client_seq+1（Linux 对拒绝连接的标准回法），让客户端
/// 立即感知拒绝而不是等到重传超时。`src/sport` 为服务端（原 SYN 的
/// 目标），`dst/dport` 为客户端（原 SYN 的源）。
fn build_tcp_rst_v4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    client_seq: u32,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = SYNTHESIZED_TTL;
    pkt[9] = IPPROTO_TCP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    // TCP 头（20 字节）： sport, dport, seq=0, ack=client_seq+1,
    // data offset=5, flags=RST|ACK, window=0
    pkt[20..22].copy_from_slice(&sport.to_be_bytes());
    pkt[22..24].copy_from_slice(&dport.to_be_bytes());
    pkt[28..32].copy_from_slice(&client_seq.wrapping_add(1).to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x14;
    let csum = tcp_checksum_v4(src, dst, &pkt[20..40]);
    pkt[36..38].copy_from_slice(&csum.to_be_bytes());
    let csum = !internet_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = (csum & 0xff) as u8;
    pkt
}

/// IPv6 版本。
fn build_tcp_rst_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    client_seq: u32,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 60];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&20u16.to_be_bytes()); // payload_len = TCP 头
    pkt[6] = IPPROTO_TCP;
    pkt[7] = SYNTHESIZED_TTL; // hop limit
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..42].copy_from_slice(&sport.to_be_bytes());
    pkt[42..44].copy_from_slice(&dport.to_be_bytes());
    pkt[48..52].copy_from_slice(&client_seq.wrapping_add(1).to_be_bytes());
    pkt[52] = 0x50;
    pkt[53] = 0x14;
    let csum = tcp_checksum_v6(src, dst, &pkt[40..60]);
    pkt[56..58].copy_from_slice(&csum.to_be_bytes());
    pkt
}

/// IPv4 用户态分片（对齐 sing-tun fragmentIPv4Packet）。
///
/// 按每片 payload 8 字节对齐切分；保留原包 flags（除 MF 按分片需要重设）与
/// fragment offset 基准。返回 None 表示无法分片（头部异常 / MTU 过小）。
fn fragment_ipv4_packet(pkt: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl >= pkt.len() {
        return None;
    }
    let payload = &pkt[ihl..];
    // 分片 payload 必须 8 字节对齐（offset 以 8 字节为单位）
    let max_frag_payload = (mtu.saturating_sub(ihl)) & !7;
    if max_frag_payload == 0 {
        return None;
    }
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    let base_offset = flags_frag & 0x1fff;
    let original_more = (flags_frag & 0x2000) != 0;
    let base_flags = flags_frag & !0x2000; // 清 MF

    let mut fragments = Vec::with_capacity(payload.len().div_ceil(max_frag_payload));
    let mut start = 0usize;
    while start < payload.len() {
        let end = (start + max_frag_payload).min(payload.len());
        let mut frag = Vec::with_capacity(ihl + end - start);
        frag.extend_from_slice(&pkt[..ihl]);
        frag.extend_from_slice(&payload[start..end]);
        let mut flags = base_flags;
        if original_more || end < payload.len() {
            flags |= 0x2000; // MF
        }
        let new_offset = base_offset + (start as u16 / 8);
        let flags_frag = flags & !0x1fff | (new_offset & 0x1fff);
        frag[6..8].copy_from_slice(&flags_frag.to_be_bytes());
        let total_len = frag.len() as u16;
        frag[2..4].copy_from_slice(&total_len.to_be_bytes());
        // IP 校验和
        frag[10..12].copy_from_slice(&[0, 0]);
        let csum = !internet_checksum(&frag[..ihl]);
        frag[10] = (csum >> 8) as u8;
        frag[11] = (csum & 0xff) as u8;
        fragments.push(frag);
        start = end;
    }
    Some(fragments)
}

/// 构造 ICMPv4 Destination Unreachable / Fragmentation Needed 错误包
/// （对齐 sing-tun buildFragmentationNeeded）。
///
/// `orig` 为超 MTU 的原始包；错误包 src = 原包 dst、dst = 原包 src，
/// 内嵌原包头部（最多 576 - 20 - 8 字节）。
fn build_fragmentation_needed(orig: &[u8], mtu: usize) -> Option<Vec<u8>> {
    if orig.len() < 20 {
        return None;
    }
    let ihl = ((orig[0] & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None;
    }
    let advertised = mtu.clamp(IPV4_MINIMUM_MTU, 0xffff);
    let original_len = orig.len();
    // ICMPv4 错误至少内嵌 8 字节传输层头
    let min_payload = ihl + 8;
    if original_len < min_payload {
        return None;
    }
    // 最小可处理数据报 576：IP(20) + ICMP(8) + payload
    let max_payload = 576 - 20 - 8;
    let payload_len = original_len.min(max_payload);
    let size = 20 + 8 + payload_len;

    let mut pkt = vec![0u8; size];
    // IPv4 头
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&[0x00, 0x00]); // flags/frag
    pkt[8] = SYNTHESIZED_TTL;
    pkt[9] = IPPROTO_ICMP;
    pkt[12..16].copy_from_slice(&orig[16..20]); // src = 原 dst
    pkt[16..20].copy_from_slice(&orig[12..16]); // dst = 原 src
    let csum = !internet_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = (csum & 0xff) as u8;
    // ICMP 头：type=3 (DstUnreachable), code=4 (Fragmentation Needed)
    pkt[20] = 3;
    pkt[21] = 4;
    // NEXT-HOP MTU（bytes 6..8 of ICMP header；bytes 4..6 保留为 0）
    pkt[26..28].copy_from_slice(&(advertised as u16).to_be_bytes());
    // 内嵌原始包
    pkt[28..28 + payload_len].copy_from_slice(&orig[..payload_len]);
    // ICMP 校验和
    let csum = !internet_checksum(&pkt[20..]);
    pkt[22] = (csum >> 8) as u8;
    pkt[23] = (csum & 0xff) as u8;
    Some(pkt)
}

/// 构造 ICMPv6 Packet Too Big 错误包（对齐 sing-tun buildPacketTooBig）。
///
/// `orig` 为超 MTU 的原始 IPv6 包；错误包 src = 原包 dst、dst = 原包 src。
fn build_packet_too_big(orig: &[u8], mtu: usize) -> Option<Vec<u8>> {
    if orig.len() < 40 {
        return None;
    }
    let advertised = mtu.max(IPV6_MINIMUM_MTU);
    let original_len = orig.len();
    // 最小 IPv6 MTU 1280：固定头(40) + ICMP(8) + payload
    let max_payload = IPV6_MINIMUM_MTU - 40 - 8;
    let payload_len = original_len.min(max_payload);
    let size = 40 + 8 + payload_len;

    let mut pkt = vec![0u8; size];
    // IPv6 固定头
    pkt[0] = 0x60;
    let payload_len_field = (8 + payload_len) as u16;
    pkt[4..6].copy_from_slice(&payload_len_field.to_be_bytes());
    pkt[6] = IPPROTO_ICMPV6;
    pkt[7] = SYNTHESIZED_TTL;
    pkt[8..24].copy_from_slice(&orig[24..40]); // src = 原 dst
    pkt[24..40].copy_from_slice(&orig[8..24]); // dst = 原 src
                                               // ICMPv6 头：type=2 (Packet Too Big), code=0
    pkt[40] = 2;
    pkt[41] = 0;
    pkt[44..48].copy_from_slice(&(advertised as u32).to_be_bytes());
    // 内嵌原始包
    pkt[48..48 + payload_len].copy_from_slice(&orig[..payload_len]);
    // ICMPv6 校验和（含伪头部）
    let src: [u8; 16] = pkt[8..24].try_into().ok()?;
    let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
    let csum = checksum_with_pseudo_v6(&src, &dst, IPPROTO_ICMPV6, &pkt[40..]);
    pkt[42] = (csum >> 8) as u8;
    pkt[43] = (csum & 0xff) as u8;
    Some(pkt)
}

/// 构造 ICMPv4 Destination Unreachable / Port Unreachable（type 3 / code 3）。
///
/// `orig` 为原始 IP+UDP 头部（至少 28 字节）；错误包 src = 原 dst、
/// dst = 原 src，内嵌原包头（对齐 sing-tun 的 ICMP 错误包语义）。
fn build_icmpv4_port_unreachable(orig: &[u8]) -> Option<Vec<u8>> {
    if orig.len() < 28 {
        return None;
    }
    let ihl = ((orig[0] & 0x0f) as usize) * 4;
    if ihl < 20 || orig.len() < ihl + 8 {
        return None;
    }
    let payload_len = orig.len().min(576 - 20 - 8);
    let size = 20 + 8 + payload_len;

    let mut pkt = vec![0u8; size];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    pkt[6..8].copy_from_slice(&[0x00, 0x00]);
    pkt[8] = SYNTHESIZED_TTL;
    pkt[9] = IPPROTO_ICMP;
    pkt[12..16].copy_from_slice(&orig[16..20]); // src = 原 dst
    pkt[16..20].copy_from_slice(&orig[12..16]); // dst = 原 src
    let csum = !internet_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = (csum & 0xff) as u8;
    // ICMP：type=3 (DstUnreachable), code=3 (Port Unreachable)，unused=0
    pkt[20] = 3;
    pkt[21] = 3;
    pkt[28..28 + payload_len].copy_from_slice(&orig[..payload_len]);
    let csum = !internet_checksum(&pkt[20..]);
    pkt[22] = (csum >> 8) as u8;
    pkt[23] = (csum & 0xff) as u8;
    Some(pkt)
}

/// 构造 ICMPv6 Destination Unreachable / Port Unreachable（type 1 / code 4）。
fn build_icmpv6_port_unreachable(orig: &[u8]) -> Option<Vec<u8>> {
    if orig.len() < 48 {
        return None;
    }
    let payload_len = orig.len().min(IPV6_MINIMUM_MTU - 40 - 8);
    let size = 40 + 8 + payload_len;

    let mut pkt = vec![0u8; size];
    pkt[0] = 0x60;
    let payload_len_field = (8 + payload_len) as u16;
    pkt[4..6].copy_from_slice(&payload_len_field.to_be_bytes());
    pkt[6] = IPPROTO_ICMPV6;
    pkt[7] = SYNTHESIZED_TTL;
    pkt[8..24].copy_from_slice(&orig[24..40]); // src = 原 dst
    pkt[24..40].copy_from_slice(&orig[8..24]); // dst = 原 src
    // ICMPv6：type=1 (DstUnreachable), code=4 (Port Unreachable)，unused=0
    pkt[40] = 1;
    pkt[41] = 4;
    pkt[48..48 + payload_len].copy_from_slice(&orig[..payload_len]);
    let src: [u8; 16] = pkt[8..24].try_into().ok()?;
    let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
    let csum = checksum_with_pseudo_v6(&src, &dst, IPPROTO_ICMPV6, &pkt[40..]);
    pkt[42] = (csum >> 8) as u8;
    pkt[43] = (csum & 0xff) as u8;
    Some(pkt)
}

/// 默认路由变化监控任务（对齐 sing-tun monitor.go 的 default-route 检测）。
///
/// 每 3s 查询一次 v4/v6 默认网关；检测到默认路由消失、恢复或网关变化时：
/// - 清空 TCP NAT / UDP 会话表（若有，对齐 ResetNetwork 语义）；
/// - auto_route 时重建路由（platform::update_routes，旧实现是死代码）。
///
/// 局限：Windows 上 TUN 自身的 metric=0 默认路由会被视为默认网关，
/// 物理网关变化可能不触发；但默认路由消失（如 Wi-Fi 断开）仍可检测。
fn spawn_default_route_watcher(
    cfg: Arc<TunInboundConfig>,
    if_name: String,
    nat: Option<Arc<TcpNat>>,
    udp_sessions: Option<Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>>,
) {
    tokio::spawn(async move {
        let mut last = platform::current_default_gateways().await;
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let now = platform::current_default_gateways().await;
            if now == last {
                continue;
            }
            info!(prev = ?last, now = ?now, "tun: default route changed");
            last = now;
            if let Some(nat) = &nat {
                nat.clear().await;
            }
            if let Some(sessions) = &udp_sessions {
                sessions.lock().await.clear();
            }
            if cfg.auto_route && cfg.file_descriptor.is_none() {
                match tokio::task::spawn_blocking({
                    let cfg = cfg.clone();
                    let if_name = if_name.clone();
                    move || platform::update_routes(&cfg, &if_name)
                })
                .await
                {
                    Ok(Ok(())) => info!("tun: routes refreshed after default-route change"),
                    Ok(Err(e)) => warn!(err = %e, "tun: route refresh failed"),
                    Err(e) => warn!(err = %e, "tun: route refresh task panicked"),
                }
            }
        }
    });
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
    /// 路由器：注入后启用 TUN 入站 ICMP 路由策略
    /// （对齐 sing-box 1.13.0 `network:"icmp"` 规则匹配）。
    /// None 时 ICMP 转发器退化为始终转发的旧行为。
    router: Option<Arc<Router>>,
    /// 出站管理器：用于判断 `route` 动作指向的出站是否支持 ICMP
    /// （仅 direct 支持，对齐 sing-box outbound.Network() 含 NetworkICMP）。
    outbound_mgr: Option<Arc<OutboundManager>>,
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
            router: None,
            outbound_mgr: None,
        }
    }

    /// 设置 DNS 劫持参数（在 run() 之前调用）。
    /// `dns_tx` 为向 DNS 解析器发送查询的通道。
    pub fn with_dns_hijack(mut self, dns_tx: DnsQueryTx, enabled: bool) -> Self {
        self.dns_tx = if enabled { Some(dns_tx) } else { None };
        self.dns_hijack = enabled;
        self
    }

    /// 注入路由器与出站管理器，启用 TUN 入站 ICMP 路由策略
    /// （对齐 sing-box 1.13.0 `network:"icmp"` 规则匹配）。
    /// 在 run() 之前调用；未注入时 ICMP 转发器退化为始终转发的旧行为。
    pub fn with_router(
        mut self,
        router: Arc<Router>,
        outbound_mgr: Arc<OutboundManager>,
    ) -> Self {
        self.router = Some(router);
        self.outbound_mgr = Some(outbound_mgr);
        self
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let cfg = Arc::new(self.config);
        let tag = Arc::new(cfg.tag.clone());
        // 提前捕获路由器/出站管理器：注入后 ICMP 转发器走 `network:"icmp"`
        // 路由策略；None 时退化为始终转发的旧行为（system/gvisor/mixed 三栈统一）。
        let router = self.router;
        let outbound_mgr = self.outbound_mgr;
        let udp_timeout = Duration::from_secs(if cfg.udp_timeout == 0 {
            DEFAULT_UDP_TIMEOUT_SECS
        } else {
            cfg.udp_timeout
        });

        // ── 动态推导 TCP MSS（对齐 sing-tun mtuToMSS）──────────────────────────
        // 未显式配置 `tcp_mss` 时，按 TUN MTU 推导：MSS = MTU - 60（保守值，
        // 兼容 v4/v6）。显式配置优先。该值贯穿 system/mixed/gvisor 三种栈。
        let effective_mss = compute_effective_mss(cfg.tcp_mss, cfg.mtu);
        if let Some(mss) = effective_mss {
            debug!(tag = %tag, mtu = cfg.mtu, mss, "tun: effective TCP MSS");
        }

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
                        // 对齐 sing-tun NewSystem L87-93：校验 ip+1 仍在前缀内，
                        // 否则 system stack 的 NAT client_addr 不可达（如 /32 或
                        // x.x.x.255/24 时 ip+1 落到前缀外，内核无对应路由）。
                        if !has_next_addr_v4(ip, pl) {
                            anyhow::bail!(
                                "tun: need one more IPv4 address in first prefix for system stack \
                                 (address {} with prefix /{} has no valid next address in-prefix)",
                                ip,
                                pl
                            );
                        }
                        inet4_server_addr = Some(ip);
                        inet4_client_addr = Some(Ipv4Addr::from(u32::from(ip).wrapping_add(1)));
                    }
                    inet4_prefixes.push((ip, pl));
                }
                Some((IpAddr::V6(ip), pl)) => {
                    if inet6_server_addr.is_none() {
                        // 对齐 sing-tun NewSystem L94-100：校验 ip+1 仍在前缀内。
                        if !has_next_addr_v6(ip, pl) {
                            anyhow::bail!(
                                "tun: need one more IPv6 address in first prefix for system stack \
                                 (address {} with prefix /{} has no valid next address in-prefix)",
                                ip,
                                pl
                            );
                        }
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

        // ── 解析 loopback 地址（参照 sing-tun Inet4LoopbackAddress []netip.Addr）─
        // sing-tun 支持多个 loopback 地址列表，dispatchIPv4 用 slices.Contains 检查。
        // 默认 [127.0.0.1] / [::1]；配置中可追加或覆盖。
        let mut inet4_loopback: Vec<Ipv4Addr> = Vec::new();
        let mut inet6_loopback: Vec<Ipv6Addr> = Vec::new();
        for s in &cfg.loopback_address {
            match parse_ip(s) {
                Some(IpAddr::V4(a)) => {
                    if !inet4_loopback.contains(&a) {
                        inet4_loopback.push(a);
                    }
                }
                Some(IpAddr::V6(a)) => {
                    if !inet6_loopback.contains(&a) {
                        inet6_loopback.push(a);
                    }
                }
                None => warn!(addr = %s, "tun: invalid loopback_address"),
            }
        }
        if inet4_loopback.is_empty() {
            inet4_loopback.push(DEFAULT_INET4_LOOPBACK);
        }
        if inet6_loopback.is_empty() {
            inet6_loopback.push(DEFAULT_INET6_LOOPBACK);
        }

        // ── 计算 IPv4 广播地址（参照 sing-tun BroadcastAddr）─────────────────
        // 用于 processIPv4 中过滤广播包。
        let inet4_broadcast = inet4_prefixes
            .first()
            .map(|(net, pl)| broadcast_addr_v4(*net, *pl));

        // 注：route_address / route_exclude_address 在各平台 platform::setup 中
        // 自行解析（因为路由规则按平台方式下发）。这里不预先解析。

        // ── TUN 设备来源抽象（external fd 模式，对齐 sing-box file_descriptor）──
        // 统一包装 tun crate 设备与外部 fd，供 NativeTun::with_gso 使用。
        enum TunDevice {
            Crate(tun::AsyncDevice),
            /// 外部传入的 fd（Unix；如 Android VpnService.establish() 返回值）
            #[cfg(unix)]
            Fd(tokio::net::UnixStream),
        }

        impl tokio::io::AsyncRead for TunDevice {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                match &mut *self {
                    TunDevice::Crate(d) => std::pin::Pin::new(d).poll_read(cx, buf),
                    #[cfg(unix)]
                    TunDevice::Fd(s) => std::pin::Pin::new(s).poll_read(cx, buf),
                }
            }
        }

        impl tokio::io::AsyncWrite for TunDevice {
            fn poll_write(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                match &mut *self {
                    TunDevice::Crate(d) => std::pin::Pin::new(d).poll_write(cx, buf),
                    #[cfg(unix)]
                    TunDevice::Fd(s) => std::pin::Pin::new(s).poll_write(cx, buf),
                }
            }

            fn poll_flush(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                match &mut *self {
                    TunDevice::Crate(d) => std::pin::Pin::new(d).poll_flush(cx),
                    #[cfg(unix)]
                    TunDevice::Fd(s) => std::pin::Pin::new(s).poll_flush(cx),
                }
            }

            fn poll_shutdown(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                match &mut *self {
                    TunDevice::Crate(d) => std::pin::Pin::new(d).poll_shutdown(cx),
                    #[cfg(unix)]
                    TunDevice::Fd(s) => std::pin::Pin::new(s).poll_shutdown(cx),
                }
            }
        }

        /// 从外部 fd 构造 TUN 设备（对齐 sing-box file_descriptor）。
        /// **接管 fd 所有权**；置为非阻塞后交由 tokio 事件循环驱动。
        #[cfg(unix)]
        fn tun_device_from_fd(fd: i32) -> std::io::Result<tokio::net::UnixStream> {
            use std::os::unix::io::FromRawFd;
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
            tokio::net::UnixStream::from_std(stream)
        }

        // ── 创建 TUN 设备 ────────────────────────────────────────────────────
        let (dev, if_name) = match cfg.file_descriptor {
            #[cfg(unix)]
            Some(fd) => {
                info!(
                    fd,
                    "tun: external file_descriptor mode (device/address/route setup managed by caller)"
                );
                let stream = tun_device_from_fd(fd)
                    .map_err(|e| anyhow::anyhow!("tun: invalid file descriptor {fd}: {e}"))?;
                let if_name = cfg
                    .interface_name
                    .clone()
                    .unwrap_or_else(|| "tun".to_string());
                (TunDevice::Fd(stream), if_name)
            }
            #[cfg(not(unix))]
            Some(fd) => {
                let _ = fd;
                anyhow::bail!("tun: file_descriptor is only supported on Unix platforms");
            }
            None => {
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
                // 启用 IFF_VNET_HDR 以支持 GSO/GRO 卸载（对齐 sing-tun enableGSO）。
                // 启用后每个读写的数据包前会带 10 字节 virtio_net_hdr。
                p.vnet_hdr(true);
            });

            #[cfg(target_os = "windows")]
            {
                // device_guid：为 wintun 适配器指定固定 GUID，避免每次启动创建新适配器
                // 用接口名做种子生成确定性 UUID（与 clash-rs 策略一致）
                let guid_seed = cfg.interface_name.as_deref().unwrap_or("wintun").as_bytes();
                // 简单 hash → u128（不依赖 uuid crate）
                let mut guid: u128 = 0xdeadbeef_cafebabe_12345678_9abcdef0;
                for (i, &b) in guid_seed.iter().enumerate() {
                    guid ^= (b as u128).wrapping_shl((i % 16) as u32 * 8);
                    guid = guid.wrapping_mul(0x6c62272e07bb0142_u128);
                }
                // 释放内嵌的 wintun.dll 到临时目录（对齐 sing-tun ensureWintunDLL），
                // 让 tun crate 从该路径加载，无需用户单独分发 wintun.dll。
                let wintun_path = platform::windows::extract_embedded_wintun();
                tun_cfg.platform_config(|p| {
                    p.device_guid(guid);
                    p.wintun_file(&wintun_path);
                });
                // ring 容量 8MB（对齐 sing-tun tun_windows.go StartSession(0x800000)）。
                // tun crate 默认用 64MB 上限，每个适配器多占 56MB 内核内存。
                tun_cfg.ring_capacity(0x800_000);
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
                // 注意：tun crate 0.8 在 Windows 上创建适配器时，缺省接口名是 "wintun"
                // （tun-0.8.x/src/platform/windows/device.rs: tun_name.unwrap_or("wintun")），
                // 必须与之一致，否则用 "tun0" 查询不到接口，后续 netsh/Win32 配置全部落空
                // （对齐 sing-tun：CreateAdapter(options.Name, ...) 直接用 options.Name）。
                let expected = cfg.interface_name.as_deref().unwrap_or("wintun");
                platform::resolve_actual_interface_name(expected)
            };

            (TunDevice::Crate(dev), if_name)
            }
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
        // external fd 模式下接口由调用方创建，跳过。
        if cfg.file_descriptor.is_none() {
            wait_for_tun_visibility(&if_name).await;
        }

        // ── auto_route ───────────────────────────────────────────────────────
        let mut tun_state = crate::inbound::tun::platform::SetupState::default();
        if cfg.auto_route && cfg.file_descriptor.is_some() {
            warn!(
                "tun: file_descriptor mode ignores auto_route (routes managed by the fd provider)"
            );
        }
        if cfg.auto_route && cfg.file_descriptor.is_none() {
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

        // ── TUN 卸载探测 + NativeTun 包装（B1/B10 修复）─────────────────────
        // 必须在协议栈分发（system/gvisor/mixed）之前完成：
        // Linux IFF_VNET_HDR 下内核在每个读写包前附带 10 字节 virtio_net_hdr
        // （与 TUNSETOFFLOAD 是否成功无关），所有协议栈的读写都必须统一经
        // NativeTun 处理，否则读写路径头错位导致数据损坏（旧实现 gvisor/mixed
        // 栈直接 tokio::io::split 裸读写，Linux 上 100% 损坏）。
        let mtu_usize = cfg.mtu as usize;
        #[cfg(target_os = "linux")]
        let (vnet_hdr, gro_flags) = if cfg.file_descriptor.is_some() {
            // 外部 fd（如 Android VpnService.establish()）不带 virtio_net_hdr，
            // 也不应被 TUNSETOFFLOAD 触碰。
            (false, gso::GroDisablementFlags::default())
        } else {
            let TunDevice::Crate(dev) = &dev else {
                unreachable!("fd mode handled above");
            };
            use std::os::fd::AsRawFd;
            let off = platform::linux::setup_tun_offload(dev.as_raw_fd());
            let mut gro = gso::GroDisablementFlags::default();
            if !off.tcp_gso {
                gro.disable_tcp();
            }
            if !off.udp_gso {
                gro.disable_udp();
            }
            (off.vnet_hdr, gro)
        };
        #[cfg(not(target_os = "linux"))]
        let (vnet_hdr, gro_flags) = (false, gso::GroDisablementFlags::default());

        let native = native_tun::NativeTun::with_gso(dev, mtu_usize, vnet_hdr, gro_flags);
        if vnet_hdr {
            info!(
                tag = %tag,
                tcp_gso = gro_flags.can_tcp(),
                udp_gso = gro_flags.can_udp(),
                "tun: virtio_net_hdr active (Linux), GSO/GRO offload state"
            );
        }
        let (reader, native_writer) = native.split();

        // ── probeTCPGRO 探针（B10 修复，对齐 sing-tun NativeTun.Start）─────
        // 部分内核 TUNSETOFFLOAD 成功但无法处理合并后的 GSO 写入；写入两个
        // 可合并的 TCP 探针段（userspace GRO 合并为 GSO 包）自检，失败则
        // 禁用 TCP+UDP GRO（内核拒绝写入（设备未 up）也走此降级路径）。
        #[cfg(target_os = "linux")]
        if vnet_hdr && gro_flags.can_tcp() {
            if let Err(e) = native_writer.probe_tcp_gro(inet4_server_addr).await {
                warn!(err = %e, "tun: GRO probe failed, TCP & UDP GRO disabled");
            }
        }
        let writer = native_writer.handle();

        // ── 协议栈分发：system / gvisor / mixed ──────────────────────────────
        // system 栈：继续走下方的 TCP NAT + UDP session 逻辑（reflex 原有实现）。
        // gvisor / mixed 栈：交给 gvisor 模块（基于 smoltcp 用户态协议栈）。
        //
        // 配置中 `stack` 字段（config/inbound.rs:377）默认 "system"，
        // 支持 "gvisor" / "mixed"（后者 TCP 走 system NAT，UDP 走 gvisor）。
        // B1 修复：gvisor/mixed 栈读写统一走 NativeTun（reader/writer），
        // virtio_net_hdr 由 LinuxTunReader/LinuxTunWriter 统一剥除/前置。
        // gvisor/mixed 栈的默认路由变化监控（会话表在栈内部，仅重建路由）
        if matches!(cfg.stack.as_str(), "gvisor" | "mixed") {
            spawn_default_route_watcher(cfg.clone(), if_name.clone(), None, None);
        }

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
            let tag_clone = tag.clone();
            let tcp_tx = self.tcp_tx.clone();
            let udp_tx = self.udp_tx.clone();
            let mtu = cfg.mtu as usize;

            let dns_tx_ref = self.dns_tx.clone();
            let dns_hijack = self.dns_hijack;
            // ICMP 路由策略注入（对齐 system 栈）：gvisor/mixed 栈的 ICMP
            // 转发器同样需要 router/outbound_mgr 来匹配 `network:"icmp"` 规则。
            let router_for_gvisor = router.clone();
            let outbound_mgr_for_gvisor = outbound_mgr.clone();

            // B6 修复（对齐 system 栈 B5 与 sing-tun 语义）：gvisor/mixed 栈
            // 不再在用户态丢弃本地子网流量。旧实现与 system 栈行为不一致：
            // 同样的 auto_route 配置下，system 栈放行 LAN 流量（由路由规则
            // suppress_prefixlength 保证 LAN 不入 TUN），gvisor/mixed 却把
            // LAN 包全部丢弃，导致这两种栈下 LAN/NAS/Docker 完全不可达。
            // 优雅关闭：信号到达时立即退出协议栈循环，走下方的 teardown
            // 路径（否则任务被 abort，路由/WFP/DNS 清理全部跳过）。
            let mut shutdown_rx = crate::app::shutdown::subscribe();
            let stack_result = tokio::select! {
                _ = crate::app::shutdown::wait_shutdown(&mut shutdown_rx) => {
                    info!(tag = %tag, "tun: shutdown signal received (gvisor/mixed stack)");
                    Ok(())
                }
                r = async {
                    if cfg.stack == "gvisor" {
                        gvisor::run_gvisor(
                            reader,
                            writer,
                            mtu,
                            tag_clone,
                            tcp_tx,
                            udp_tx,
                            udp_timeout,
                            dns_tx_ref,
                            dns_hijack,
                            router_for_gvisor,
                            outbound_mgr_for_gvisor,
                        )
                        .await
                    } else {
                        // mixed：TCP 走 system NAT，UDP 走 gvisor。
                        gvisor::run_mixed(
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
                            &inet4_loopback,
                            &inet6_loopback,
                            effective_mss,
                            udp_timeout,
                            dns_tx_ref,
                            dns_hijack,
                            inet4_prefixes.clone(),
                            inet6_prefixes.clone(),
                            router_for_gvisor,
                            outbound_mgr_for_gvisor,
                        )
                        .await
                    }
                } => r,
            };

            // ── gvisor/mixed 栈退出收尾（修复：旧实现在此提前 return，
            // 跳过了 platform::teardown，导致 auto_route 安装的 ip rule/
            // 路由/WFP 过滤器/DNS 配置全部泄漏到进程退出后）。对齐
            // sing-tun：协议栈选择与路由生命周期解耦，关闭路径无条件
            // 清理（tun.go Close → routeAddress/unsetDNS 等）。
            if cfg.auto_route {
                if let Err(e) = platform::teardown(&cfg, &if_name, &tun_state).await {
                    warn!(err = %e, "tun: auto_route teardown failed");
                }
            }

            return stack_result;
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

        // ── TCP DNS 劫持监听器（对齐 sing-tun DNSMode=hijack 的 TCP 路径）────
        // 当 dns_hijack 启用时，绑定一个独立 TCP 监听器接收被 NAT 重定向的
        // port 53 连接，按 DNS-over-TCP 帧格式解析后交给 dns_tx。
        let dns_tcp_listener_v4: Option<Arc<TcpListener>> = if self.dns_hijack {
            if let Some(addr) = inet4_server_addr {
                TcpListener::bind(SocketAddrV4::new(addr, 0))
                    .await
                    .ok()
                    .map(Arc::new)
            } else {
                None
            }
        } else {
            None
        };
        let dns_tcp_listener_v6: Option<Arc<TcpListener>> = if self.dns_hijack {
            if let Some(addr) = inet6_server_addr {
                TcpListener::bind(SocketAddrV6::new(addr, 0, 0, 0))
                    .await
                    .ok()
                    .map(Arc::new)
            } else {
                None
            }
        } else {
            None
        };
        let dns_tcp_port_v4 = dns_tcp_listener_v4
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port());
        let dns_tcp_port_v6 = dns_tcp_listener_v6
            .as_ref()
            .and_then(|l| l.local_addr().ok())
            .map(|a| a.port());
        if dns_tcp_port_v4.is_some() || dns_tcp_port_v6.is_some() {
            info!(
                tag = %tag,
                v4_port = ?dns_tcp_port_v4,
                v6_port = ?dns_tcp_port_v6,
                "tun: TCP DNS hijack listener ready"
            );
        }

        // ── TCP NAT 表 ───────────────────────────────────────────────────────
        let tcp_nat = Arc::new(TcpNat::new());

        // 启动 TCP DNS 劫持 accept loop
        if let Some(listener) = dns_tcp_listener_v4.clone() {
            let nat = tcp_nat.clone();
            let tx = self.dns_tx.clone();
            let tag2 = tag.clone();
            tokio::spawn(async move {
                tcp_dns_accept_loop(listener, nat, tx, tag2).await;
            });
        }
        if let Some(listener) = dns_tcp_listener_v6.clone() {
            let nat = tcp_nat.clone();
            let tx = self.dns_tx.clone();
            let tag2 = tag.clone();
            tokio::spawn(async move {
                tcp_dns_accept_loop(listener, nat, tx, tag2).await;
            });
        }

// ── TCP accept loop ──────────────────────────────────────────────────
// 对齐 sing-tun acceptLoop（stack_system.go:331-346）：TUN 前缀内目标
// 改写为 loopback 后再交付出站处理（R2 修复）。
if let Some(listener) = tcp_listener_v4.clone() {
    let nat = tcp_nat.clone();
    let tx = self.tcp_tx.clone();
    let tag2 = tag.clone();
    let p4 = inet4_prefixes.clone();
    let p6 = inet6_prefixes.clone();
    tokio::spawn(async move {
        accept_loop(listener, nat, tx, tag2, p4, p6).await;
    });
}
if let Some(listener) = tcp_listener_v6.clone() {
    let nat = tcp_nat.clone();
    let tx = self.tcp_tx.clone();
    let tag2 = tag.clone();
    let p4 = inet4_prefixes.clone();
    let p6 = inet6_prefixes.clone();
    tokio::spawn(async move {
        accept_loop(listener, nat, tx, tag2, p4, p6).await;
    });
}

        // ── UDP 会话表 ───────────────────────────────────────────────────────
        let udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // ── 网络切换时重置 NAT（对齐 sing-tun ResetNetwork）────────────────
        // interface_monitor（B8：netlink 事件驱动 + 轮询兜底）监听接口/地址/路由
        // 变更。事件到达时清空 TCP NAT 与 UDP 会话表，避免切换网络后旧 5-tuple
        // 映射把回包导到错误客户端（对齐 sing-box Inbound.InterfaceUpdated →
        // tunStack.ResetNetwork() 的语义）。旧实现里 interface_monitor 从未被
        // 注册（死代码），NAT 只能靠 300s 超时 GC 自愈，期间回包错乱。
        // 仅 system 栈接线（gvisor/mixed 栈的 UDP NAT 在 smoltcp 内，无法从
        // 外部清空；gvisor 的 TCP 仍走 system NAT，mixed 不接以保持简单）。
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let nat_monitor_id = {
            let nat = tcp_nat.clone();
            let sessions = udp_sessions.clone();
            Some(
                interface_monitor::register(move |_ev: &interface_monitor::InterfaceEvent| {
                    let nat = nat.clone();
                    let sessions = sessions.clone();
                    tokio::spawn(async move {
                        nat.clear().await;
                        sessions.lock().await.clear();
                    });
                })
                .await,
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        #[allow(unused_variables)]
        let nat_monitor_id: Option<usize> = None;

        // ── 默认路由变化监控（对齐 sing-tun monitor 的 default-route 检测）──
        // 检测默认路由消失/恢复/网关变化：清空 NAT 与 UDP 会话表，
        // auto_route 时重建路由。Windows/macOS 无 netlink 监控，此任务
        // 是网络切换感知的唯一来源；Linux/Android 与 netlink 监控互补
        // （netlink 任意事件即清表，本任务额外负责路由重建）。
        spawn_default_route_watcher(
            cfg.clone(),
            if_name.clone(),
            Some(tcp_nat.clone()),
            Some(udp_sessions.clone()),
        );

        // ── TUN 读写半部 ────────────────────────────────────────────────────
        // B1/B10 修复：NativeTun 已在协议栈分发之前创建（gvisor/mixed 分支
        // 会提前 return 并取走 reader/writer）。此处 system 栈直接复用：
        // Linux 下读写统一经 NativeTun 处理 virtio_net_hdr（批量读 +
        // GSO 拆分；写方向由 LinuxTunWriter::poll_write 前置 hdr）。
        let (mut reader, writer) = (reader, writer);

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

        // ── ICMP 转发器（system 栈：raw socket ping 转发）──────────────────
        // 对齐 sing-tun stack_system.go ICMP forwarding：到达 TUN 的 ICMP Echo Request
        // 均为外部目的地（ping TUN 自身地址由内核直接响应，不会进入 TUN fd），
        // 通过 raw/ping socket 转发到上游并回注 reply。
        #[cfg(unix)]
        let icmp_forwarder = {
            use crate::inbound::tun::icmp_forwarder::IcmpForwarder;
            let fwd = IcmpForwarder::new(writer.clone());
            // 注入路由器/出站管理器：启用 `network:"icmp"` 规则匹配
            // （reject/block/非直连出站丢弃等）。未注入时退化为始终转发。
            let fwd = if let (Some(router), Some(outbound_mgr)) =
                (router.as_ref(), outbound_mgr.as_ref())
            {
                fwd.with_router(router.clone(), outbound_mgr.clone(), tag.clone())
            } else {
                fwd
            };
            Some(fwd)
        };

        // ── 批量读取循环（对齐 sing-tun Linux 批量 I/O）────────────────────────
        // 使用 NativeTunReader::read_batch 一次读取多个包，降低 syscall 次数。
        // 非 Linux 平台 / GSO 未启用时退化为单包读取。
        const BATCH_SIZE: usize = 64;
        let mut batch_bufs: Vec<Vec<u8>> = (0..BATCH_SIZE)
            .map(|_| Vec::with_capacity(mtu_usize + 64))
            .collect();

        // IPv4 分片重组器（对齐 sing-tun IPv4 reassembly：system 栈此前
        // 直接丢弃分片，导致依赖分片的 DNS/TCP/UDP 大包黑洞）。
        let mut defragmenter = ip_defrag::IpDefragmenter::new();

        // 优雅关闭：批量读循环上 select 关闭信号，信号到达时 break →
        // 执行下方 platform::teardown（删除路由/恢复 DNS/关 WFP）。
        let mut shutdown_rx = crate::app::shutdown::subscribe();

        loop {
            let sizes = tokio::select! {
                _ = crate::app::shutdown::wait_shutdown(&mut shutdown_rx) => {
                    info!(tag = %tag, "tun: shutdown signal received, tearing down auto_route");
                    break;
                }
                r = reader.read_batch(&mut batch_bufs) => match r {
                    Ok(sizes) if sizes.is_empty() => {
                        info!(tag = %tag, "tun device closed");
                        break;
                    }
                    Ok(sizes) => sizes,
                    Err(e) => {
                        error!(err = %e, "tun read error");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                }
            };

            for (idx, &len) in sizes.iter().enumerate() {
                if len == 0 {
                    continue;
                }
                // tun 0.8：所有平台包均不含 PI 头（packet_information 已废弃）
                let pkt_slice = &batch_bufs[idx][..len];
                if pkt_slice.is_empty() {
                    continue;
                }

                // ICMP Echo Request → IcmpForwarder（unix 平台 raw socket 转发）
                // 处理成功则跳过后续 process_ipv4/v6（避免重复本地回环响应）
                #[cfg(unix)]
                {
                    if let Some(ref fwdr) = icmp_forwarder {
                        if fwdr.handle_packet(pkt_slice).await {
                            continue;
                        }
                    }
                }

                // IPv4 分片重组：非首片/含 MF 的包喂入重组器，完成后按
                // 普通包进入 NAT/dispatch（TCP/UDP/ICMP 统一覆盖）。
                if pkt_slice.len() >= 20 && pkt_slice[0] >> 4 == IPV4_VERSION {
                    let ff = u16::from_be_bytes([pkt_slice[6], pkt_slice[7]]);
                    if ff & 0x3fff != 0 {
                        if let Some(full) = defragmenter.feed(pkt_slice, Instant::now()) {
                            process_ipv4(
                                &full,
                                inet4_server_addr,
                                inet4_client_addr,
                                inet4_broadcast,
                                &inet4_loopback,
                                tcp_port_v4,
                                dns_tcp_port_v4,
                                effective_mss,
                                &tag,
                                &self.udp_tx,
                                writer.clone(),
                                tcp_nat.clone(),
                                udp_sessions.clone(),
                                udp_timeout,
                                mtu_usize,
                                &self.dns_tx,
                                self.dns_hijack,
                            )
                            .await;
                        }
                        continue;
                    }
                }

                match pkt_slice[0] >> 4 {
                    IPV4_VERSION => {
                        process_ipv4(
                            pkt_slice,
                            inet4_server_addr,
                            inet4_client_addr,
                            inet4_broadcast,
                            &inet4_loopback,
                            tcp_port_v4,
                            dns_tcp_port_v4,
                            effective_mss,
                            &tag,
                            &self.udp_tx,
                            writer.clone(),
                            tcp_nat.clone(),
                            udp_sessions.clone(),
                            udp_timeout,
                            mtu_usize,
                            &self.dns_tx,
                            self.dns_hijack,
                        )
                        .await;
                    }
                    IPV6_VERSION => {
                        // T2：IPv6 分片重组（对齐 sing-tun gvisor 栈的
                        // reassembly；旧实现直接丢弃分片，IPv6 大包黑洞）。
                        // 完成后按普通包走 process_ipv6（TCP/UDP/ICMP 统一）。
                        if pkt_slice.len() >= 48 && ip_defrag::ipv6_is_fragment(pkt_slice) {
                            if let Some(full) =
                                defragmenter.feed_ipv6(pkt_slice, Instant::now())
                            {
                                process_ipv6(
                                    &full,
                                    inet6_server_addr,
                                    inet6_client_addr,
                                    &inet6_loopback,
                                    tcp_port_v6,
                                    dns_tcp_port_v6,
                                    effective_mss,
                                    &tag,
                                    &self.udp_tx,
                                    writer.clone(),
                                    tcp_nat.clone(),
                                    udp_sessions.clone(),
                                    udp_timeout,
                                    mtu_usize,
                                    &self.dns_tx,
                                    self.dns_hijack,
                                )
                                .await;
                            }
                            continue;
                        }
                        process_ipv6(
                            pkt_slice,
                            inet6_server_addr,
                            inet6_client_addr,
                            &inet6_loopback,
                            tcp_port_v6,
                            dns_tcp_port_v6,
                            effective_mss,
                            &tag,
                            &self.udp_tx,
                            writer.clone(),
                            tcp_nat.clone(),
                            udp_sessions.clone(),
                            udp_timeout,
                            mtu_usize,
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
        }

        if cfg.auto_route {
            if let Err(e) = platform::teardown(&cfg, &if_name, &tun_state).await {
                warn!(err = %e, "tun: auto_route teardown failed");
            }
        }

        // 注销网络变更回调（TUN 退出后不再清 NAT）
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(id) = nat_monitor_id {
            interface_monitor::unregister(id).await;
        }

        Ok(())
    }
}

// ── TCP accept loop ───────────────────────────────────────────────────────────

/// TCP accept 循环。
///
/// 对齐 sing-tun acceptLoop（stack_system.go:320-349）：用 NAT 会话中存储的
/// 原始目标交付出站处理，且**目标落在 TUN 前缀（inet4Prefixes/inet6Prefixes）
/// 内时改写为 loopback**（v4→127.0.0.1，v6→::1），使应用访问 TUN 子网内
/// 地址能到达本机服务，而不是交给出站代理去连不可路由的 TUN 地址。
///
/// loopback（127.0.0.1 / ::1）目标的处理已在 `handle_tcp_v4/v6` 的包处理
/// 路径中通过 reflect 机制完成（参照 sing-tun processIPv4TCP L458-467），
/// 这些包不会经过 NAT 到达 acceptLoop。
pub(crate) async fn accept_loop(
    listener: Arc<TcpListener>,
    tcp_nat: Arc<TcpNat>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
    inet4_prefixes: Vec<(Ipv4Addr, u8)>,
    inet6_prefixes: Vec<(Ipv6Addr, u8)>,
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
        match tcp_nat.lookup_back(nat_port).await {
            Some((_src, mut dst)) => {
                // 对齐 sing-tun acceptLoop L331-346：TUN 前缀内目标改写为 loopback
                match dst {
                    SocketAddr::V4(v4) => {
                        if inet4_prefixes
                            .iter()
                            .any(|(net, pl)| addr_in_prefix_v4(*v4.ip(), *net, *pl))
                        {
                            dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v4.port());
                        }
                    }
                    SocketAddr::V6(v6) => {
                        if inet6_prefixes
                            .iter()
                            .any(|(net, pl)| addr_in_prefix_v6(*v6.ip(), *net, *pl))
                        {
                            dst = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), v6.port());
                        }
                    }
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

// ── TCP DNS 劫持 accept loop（对齐 sing-tun DNSMode=hijack 的 TCP 路径）───────
//
// 当 `dns_hijack` 启用时，目标端口为 53 的 TCP 连接通过 NAT 重定向到本监听器。
// DNS-over-TCP 帧格式：[2 字节大端长度][DNS 报文]。本循环读取每一帧，经 dns_tx
// 解析后把响应按相同格式写回。与 UDP 劫持不同，TCP 是流式，需独立监听器。

pub(crate) async fn tcp_dns_accept_loop(
    listener: Arc<TcpListener>,
    tcp_nat: Arc<TcpNat>,
    dns_tx: Option<DnsQueryTx>,
    tag: Arc<String>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!(err = %e, "tun: TCP DNS accept error");
                tokio::time::sleep(Duration::from_millis(5)).await;
                continue;
            }
        };
        let nat_port = peer.port();
        let orig = tcp_nat.lookup_back(nat_port).await;
        let (src, _dst) = match orig {
            Some((s, d)) => (s, d),
            None => {
                debug!(nat_port, "tun: TCP DNS unknown NAT port, dropping");
                continue;
            }
        };
        let dns_tx_clone = dns_tx.clone();
        let tag_clone = tag.clone();
        tokio::spawn(handle_dns_tcp_stream(stream, src, dns_tx_clone, tag_clone));
    }
}

/// 处理一条 DNS-over-TCP 连接（对齐 sing-tun DNSMode=hijack 的 TCP 路径）。
///
/// 循环读取 `[2 字节大端长度][DNS 报文]` 帧，经 `dns_tx` 解析后把响应按相同
/// 格式写回。由 system/mixed 栈的 `tcp_dns_accept_loop` 与 gvisor 栈的 TCP
/// dispatch 共用（F6：gvisor 栈此前 TCP DNS 劫持完全缺失，port 53 连接被
/// 当作普通代理连接送入代理路径）。
pub(crate) async fn handle_dns_tcp_stream<S>(
    mut stream: S,
    src: SocketAddr,
    dns_tx: Option<DnsQueryTx>,
    tag: Arc<String>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    // DNS-over-TCP 允许多个查询复用同一连接，循环读取直到对端关闭。
    loop {
        // 读取 2 字节长度前缀
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break; // 对端关闭或出错
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65535 {
            debug!(msg_len, "tun: TCP DNS invalid message length");
            break;
        }
        let mut msg = vec![0u8; msg_len];
        if stream.read_exact(&mut msg).await.is_err() {
            break;
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let query = DnsQuery {
            message: Bytes::from(msg),
            from: src,
            inbound_tag: (*tag).clone(),
            source: DnsQuerySource::Hijacked,
            reply_tx,
        };
        let tx = match dns_tx.as_ref() {
            Some(t) => t,
            None => break,
        };
        if tx.send(query).await.is_err() {
            debug!("tun: TCP DNS dns_tx closed");
            break;
        }
        match reply_rx.await {
            Ok(response) => {
                let resp_len = response.len() as u16;
                if stream.write_all(&resp_len.to_be_bytes()).await.is_err() {
                    break;
                }
                if stream.write_all(&response).await.is_err() {
                    break;
                }
                let _ = stream.flush().await;
            }
            Err(_) => {
                debug!("tun: TCP DNS reply dropped");
                break;
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
    inet4_loopback: &[Ipv4Addr],
    tcp_port: u16,
    dns_tcp_port: Option<u16>,
    tcp_mss: Option<u16>,
    tag: &Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    udp_timeout: Duration,
    mtu: usize,
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

    // ── TUN 子网广播过滤（对齐 sing-tun BroadcastAddr 语义）───────────────
    // 主机在 TUN 子网内的广播（如 198.18.255.255:137 NetBIOS、mDNS）会被
    // auto_route 送进 TUN；这类包没有转发意义（TUN 是点对点虚拟网），
    // 旧实现只在 ICMP 分支检查广播地址，UDP/TCP 广播会进入代理路径
    // （典型噪音：`src=<tun地址>:137 dst=198.18.255.255:137` 反复刷日志）。
    // 这里对 TCP/UDP/ICMP 统一丢弃发往 TUN 子网广播地址的包。
    if Some(dst_ip) == inet4_broadcast {
        return;
    }

    // ── 本地子网流量：放行进入正常处理（B5 修复）───────────────────────
    // 旧实现在此处直接丢弃 src/dst 落在本地网卡子网内的包，导致同网段
    // NAS/打印机/路由器管理页不可达，且劫持到 TUN 的 LAN DNS 查询也被丢。
    // 对齐 sing-tun 语义：LAN 连通性由路由规则保证（fwmark 规则带
    // suppress_prefixlength 0，使 main 表中更精确的本地子网路由优先生效，
    // LAN 流量根本不会进入 TUN；仅 DNS（端口 53）例外，被有意劫持）。
    // 到达 TUN 的 LAN 包按正常路径处理（DNS 劫持 / NAT / 转发）。

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
                dns_tcp_port,
                tcp_mss,
                writer,
                tcp_nat,
                dns_hijack,
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
                // 捕获原始 IP+UDP 头部模板（含 IP options），用于回包保留
                // ToS/DSCP、IP ID、flags(DF)、TTL 等字段（对齐 sing-tun
                // systemUDPPacketWriter4 的 headerCopy）。
                let hdr_end = (ihl + 8).min(raw.len());
                dispatch_udp(
                    src,
                    dst,
                    data,
                    tag.clone(),
                    udp_tx,
                    writer,
                    udp_sessions,
                    udp_timeout,
                    mtu,
                    dns_tx,
                    dns_hijack,
                    &raw[..hdr_end],
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
    inet6_loopback: &[Ipv6Addr],
    tcp_port: u16,
    dns_tcp_port: Option<u16>,
    tcp_mss: Option<u16>,
    tag: &Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    udp_timeout: Duration,
    mtu: usize,
    dns_tx: &Option<DnsQueryTx>,
    dns_hijack: bool,
) {
    if raw.len() < 40 {
        return;
    }
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap_or([0u8; 16]));
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));

    // ── IPv6 扩展头遍历（B3 修复，对齐 sing-tun skipIPv6ExtensionHeaders）──
    // 旧实现直接以固定头 next_header（raw[6]）分派协议，不遍历
    // hop-by-hop / routing / destination-options 扩展头，带扩展头的
    // TCP/UDP 包被误判或把扩展头当传输头解析。
    let (protocol, payload, is_fragment, transport_present) =
        skip_ipv6_extension_headers(raw[6], &raw[40..]);
    if is_fragment || !transport_present {
        // 分片包（fragment header）无法做 NAT/端口解析，与 sing-tun 语义
        // 一致按 fragment 流处理：system 栈不支持分片重组，直接丢弃。
        debug!(
            fragment = is_fragment,
            "tun: ipv6 extension header packet dropped (fragment/unsupported)"
        );
        return;
    }

    // ── 本地子网流量：放行进入正常处理（B5 修复，与 process_ipv4 同理）──

    match protocol {
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
                dns_tcp_port,
                tcp_mss,
                writer,
                tcp_nat,
                dns_hijack,
            )
            .await;
        }
        IPPROTO_UDP => {
            // 过滤非全局单播目标（参照 sing-tun processIPv6UDP L592-594）。
            if !is_global_unicast_v6(dst_ip) {
                return;
            }
            if let Some((src, dst, data)) = parse_udp_v6(payload, src_ip, dst_ip) {
                // 捕获原始 IPv6+UDP 头部模板，用于回包保留 traffic class、
                // flow label、hop limit 等字段（对齐 sing-tun
                // systemUDPPacketWriter6 的 headerCopy）。带扩展头时模板
                // 覆盖固定头 + 全部扩展头 + UDP 头。
                let hdr_len = raw.len() - payload.len() + 8;
                let hdr_end = hdr_len.min(raw.len());
                dispatch_udp(
                    src,
                    dst,
                    data,
                    tag.clone(),
                    udp_tx,
                    writer,
                    udp_sessions,
                    udp_timeout,
                    mtu,
                    dns_tx,
                    dns_hijack,
                    &raw[..hdr_end],
                )
                .await;
            }
        }
        IPPROTO_ICMPV6 => {
            // 与 sing-tun processIPv6 一致：非全局单播目标直接返回。
            if !is_global_unicast_v6(dst_ip) {
                return;
            }
            // handle_icmpv6 的回包构造假定 ICMPv6 头紧随固定头（offset 40）；
            // 带扩展头的 ICMPv6（实践中不存在于 Echo Request）直接丢弃。
            if payload.len() == raw.len() - 40 {
                handle_icmpv6(raw, src_ip, dst_ip, inet6_server_addr, writer).await;
            }
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
    inet4_loopback: &[Ipv4Addr],
    tcp_port: u16,
    dns_tcp_port: Option<u16>,
    tcp_mss: Option<u16>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    dns_hijack: bool,
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

    // DNS 劫持：目标端口 53 且启用 dns_hijack 时，NAT 重定向到 DNS TCP 监听器。
    // 与 sing-tun DNSMode=hijack 一致：在包层把 port 53 流量导向本地 DNS 处理。
    // B2 修复：NAT 改写使用 effective_tcp_port（旧实现计算后未使用，仍写死
    // tcp_port，导致 port 53 的 TCP 连接被 NAT 到通用 listener 当作普通代理
    // 连接，DNS TCP 劫持完全失效、dns_tcp_listener 成为死代码）。
    let effective_tcp_port: u16 = if dns_hijack && dst_port == 53 {
        match dns_tcp_port {
            Some(p) => p,
            None => tcp_port, // 未配置 DNS 监听器则回退到通用 listener
        }
    } else {
        tcp_port
    };

    // 来自 Listener 的回包（参照 sing-tun processIPv4TCP L390：src == server_addr && srcPort == tcpPort）。
    // 注意此处 inet4_addr 为 server_addr（listener 绑定地址），与旧实现一致。
    // 同时兼容 DNS 劫持监听器的回包（srcPort == dns_tcp_port）。
    if src_ip == server_addr && (src_port == tcp_port || dns_tcp_port == Some(src_port)) {
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

    // loopback 重写（参照 sing-tun processIPv4TCP L458-467）
    // 遍历 loopback 地址列表（slices.Contains 语义），匹配则 reflect。
    if let Some(&lb) = inet4_loopback.iter().find(|&&lb| lb == dst_ip) {
        let mut pkt = raw.to_vec();
        // 把目标改为源 IP，源改为匹配的 loopback 地址（与 sing-tun 一致）
        pkt[12..16].copy_from_slice(&lb.octets()); // src = loopback
        pkt[16..20].copy_from_slice(&src_ip.octets()); // dst = 原 src
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

let nat_port = match tcp_nat.lookup_or_insert(src, dst).await {
Some(p) => p,
None => {
// 端口池耗尽：回 RST 并丢弃新连接（对齐 sing-tun
// processIPv4TCP L470-472；sing-tun 在 PrepareConnection
// 失败时同样回 RST，客户端立即感知拒绝而非等到超时）
warn!("tun: tcp v4 NAT port space exhausted, sending RST");
if tcp_payload.len() >= 8 {
let client_seq = u32::from_be_bytes([
tcp_payload[4],
tcp_payload[5],
tcp_payload[6],
tcp_payload[7],
]);
let rst = build_tcp_rst_v4(dst_ip, src_ip, dst_port, src_port, client_seq);
tun_write(&writer, &rst, false).await;
}
return;
}
};

    let mut pkt = raw.to_vec();
    // 与 sing-tun processIPv4TCP L418-421 对齐：
    //   src = client_addr（server_addr.Next()），dst = server_addr
    // B2 修复：目标端口使用 effective_tcp_port（DNS 劫持时指向 DNS 监听器）。
    pkt[12..16].copy_from_slice(&client_addr.octets());
    pkt[16..20].copy_from_slice(&server_addr.octets());
    pkt[ihl..ihl + 2].copy_from_slice(&nat_port.to_be_bytes());
    pkt[ihl + 2..ihl + 4].copy_from_slice(&effective_tcp_port.to_be_bytes());
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
    inet6_loopback: &[Ipv6Addr],
    tcp_port: u16,
    dns_tcp_port: Option<u16>,
    tcp_mss: Option<u16>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    dns_hijack: bool,
) {
    let (server_addr, client_addr) = match (inet6_server_addr, inet6_client_addr) {
        (Some(a), Some(n)) => (a, n),
        _ => return,
    };
    if tcp_payload.len() < 20 {
        return;
    }
    // TCP 头在原始包中的偏移：raw.len() - tcp_payload.len()。
    // 无扩展头时为 40；带 hop-by-hop/routing/dst-options 扩展头时 > 40
    // （B3 修复：旧实现写死 40，扩展头包的 NAT 端口改写会覆盖扩展头，
    // 回包/转发方向全部损坏）。IPv4 侧 IHL 本身覆盖 options，无需此推导。
    let tcp_off = raw.len().saturating_sub(tcp_payload.len());
    if tcp_off < 40 || tcp_off + 20 > raw.len() {
        return;
    }
    let src_port = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]);
    let dst_port = u16::from_be_bytes([tcp_payload[2], tcp_payload[3]]);

    // DNS 劫持：目标端口 53 且启用 dns_hijack 时，NAT 重定向到 DNS TCP 监听器。
    // 与 sing-tun DNSMode=hijack 一致：在包层把 port 53 流量导向本地 DNS 处理。
    // B2 修复：NAT 改写使用 effective_tcp_port（与 handle_tcp_v4 同理）。
    let effective_tcp_port: u16 = if dns_hijack && dst_port == 53 {
        match dns_tcp_port {
            Some(p) => p,
            None => tcp_port, // 未配置 DNS 监听器则回退到通用 listener
        }
    } else {
        tcp_port
    };

    // 来自 Listener 的回包（参照 sing-tun processIPv6TCP L485）。
    // 同时兼容 DNS 劫持监听器的回包（srcPort == dns_tcp_port）。
    if src_ip == server_addr && (src_port == tcp_port || dns_tcp_port == Some(src_port)) {
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
            pkt[tcp_off..tcp_off + 2].copy_from_slice(&new_src_port.to_be_bytes());
            pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&new_dst_port.to_be_bytes());
            // 回包方向也 clamp MSS（SYN-ACK 也需处理）
            if let Some(max_mss) = tcp_mss {
                clamp_tcp_mss(&mut pkt, tcp_off, max_mss);
            }
            recompute_tcp_checksum_v6(&mut pkt, tcp_off);
            tun_write(&writer, &pkt, true).await;
        }
        return;
    }

    // 过滤非全局单播目标（参照 sing-tun processIPv6TCP L483）
    if !is_global_unicast_v6(dst_ip) {
        return;
    }

    // loopback 重写（参照 sing-tun processIPv6TCP L495-503）
    // 遍历 loopback 地址列表（slices.Contains 语义），匹配则 reflect。
    if let Some(&lb) = inet6_loopback.iter().find(|&&lb| lb == dst_ip) {
        let mut pkt = raw.to_vec();
        pkt[8..24].copy_from_slice(&lb.octets()); // src = loopback
        pkt[24..40].copy_from_slice(&src_ip.octets()); // dst = 原 src
        if let Some(max_mss) = tcp_mss {
            clamp_tcp_mss(&mut pkt, tcp_off, max_mss);
        }
        recompute_tcp_checksum_v6(&mut pkt, tcp_off);
        tun_write(&writer, &pkt, true).await;
        return;
    }

    let src = SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0));
    let dst = SocketAddr::V6(SocketAddrV6::new(dst_ip, dst_port, 0, 0));
let nat_port = match tcp_nat.lookup_or_insert(src, dst).await {
Some(p) => p,
None => {
// 端口池耗尽：回 RST 并丢弃新连接（对齐 sing-tun
// processIPv6TCP L507-509 + PrepareConnection 失败 → RST）
warn!("tun: tcp v6 NAT port space exhausted, sending RST");
if tcp_payload.len() >= 8 {
let client_seq = u32::from_be_bytes([
tcp_payload[4],
tcp_payload[5],
tcp_payload[6],
tcp_payload[7],
]);
let rst = build_tcp_rst_v6(dst_ip, src_ip, dst_port, src_port, client_seq);
tun_write(&writer, &rst, true).await;
}
return;
}
};

    let mut pkt = raw.to_vec();
    // 与 sing-tun processIPv6TCP L513-516 对齐：
    //   src = client_addr，dst = server_addr
    // B2 修复：目标端口使用 effective_tcp_port（DNS 劫持时指向 DNS 监听器）。
    pkt[8..24].copy_from_slice(&client_addr.octets());
    pkt[24..40].copy_from_slice(&server_addr.octets());
    pkt[tcp_off..tcp_off + 2].copy_from_slice(&nat_port.to_be_bytes());
    pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&effective_tcp_port.to_be_bytes());
    // 转发方向 clamp MSS（参照 sing-tun rewriteForward：isTCPSyn 时调用 clampTCPMSS）
    if let Some(max_mss) = tcp_mss {
        clamp_tcp_mss(&mut pkt, tcp_off, max_mss);
    }
    recompute_tcp_checksum_v6(&mut pkt, tcp_off);
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
    udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpEntry>>>,
    udp_timeout: Duration,
    mtu: usize,
    dns_tx: &Option<DnsQueryTx>,
    dns_hijack: bool,
    ip_udp_header: &[u8],
) {
    // TUN 层 DNS 劫持：参考 clash-rs datagram.rs:97-168，
    // 在端口 53 且 hijack_dns 启用时直接通过 DNS 解析器响应，
    // 不创建 UDP session / 不经过代理路径。
    // dns_tx 不可用（解析器未挂载）时回退到正常 UDP 会话路径，
    // 避免 hijack 开启但解析器缺失时端口 53 流量被静默丢弃。
    if dns_hijack && dst.port() == 53 {
        if let Some(ref tx) = dns_tx {
            let (reply_tx, reply_rx) = oneshot::channel();
            let query = DnsQuery {
                // clone：send 失败/无 dns_tx 时回退到下方正常 UDP 会话路径，
                // `data` 仍需保留（DNS 查询包很小，clone 代价可忽略）。
                message: data.clone(),
                from: src,
                inbound_tag: (*tag).clone(),
                source: DnsQuerySource::Hijacked,
                reply_tx,
            };
            if tx.send(query).await.is_err() {
                debug!("tun: dns_tx closed, fall back to normal UDP path");
            } else {
                match reply_rx.await {
                    Ok(response) => {
                        if let Some(pkt) = build_udp_reply_packet(dst, src, &response) {
                            let is_v6 = matches!(dst, SocketAddr::V6(_));
                            // F3：DNS 响应可超过 TUN MTU，按 MTU 闭环写出
                            //（IPv4 非分片 DF → ICMP FragNeeded；可分片 → 用户态分片；
                            // IPv6 → ICMPv6 Packet Too Big）。
                            tun_write_mtu(&writer, pkt, mtu, is_v6).await;
                        }
                    }
                    Err(_) => {
                        debug!("tun: DNS reply rx dropped");
                    }
                }
                return;
            }
        }
    }

    let key = src;
    let mut sessions = udp_sessions.lock().await;

    let entry = sessions.entry(key).or_insert_with(|| {
        debug!(src = %src, dst = %dst, "tun: new UDP session");
        let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
        let w = writer.clone();
        // 捕获原始请求 IP+UDP 头部模板（对齐 sing-tun systemUDPPacketWriter4/6
        // 的 headerCopy）。回包时复用该模板，保留 ToS/DSCP、IP ID、flags(DF)、
        // TTL、IP options 等字段，仅改写 src/dst/长度/校验和。
        let hdr_template = ip_udp_header.to_vec();
        // F3：TUN MTU 用于回包超限时的用户态分片 / ICMP 通告。
        let reply_mtu = mtu;
        tokio::spawn(async move {
            // R5：空闲超时自退。旧实现 task 依赖所有 reply_tx 被 drop 才退出，
            // handler 长期持有 session 时 task 滞留泄漏。空闲 udp_timeout
            // （与 GC 阈值一致）后自行退出；每次收到回包请求会重置计时。
            loop {
                match tokio::time::timeout(udp_timeout, reply_rx.recv()).await {
                    Ok(Some((payload, _client_src, server_src))) => {
                        // 回包：IP 源 = 远端服务器（server_src / spoofed_src），
                        // IP 目标 = 原始客户端（src）。出站发送的元组为
                        // (data, client_src, spoofed_src)，此前误把 client_src 当作
                        // 回包源地址，导致 src=dst=client，回包被 OS 丢弃。
                        // 优先使用头部模板构建回包（保留原始 ToS/TTL/ID/flags/options），
                        // 模板无效时回退到从零构造。
                        let pkt = build_udp_reply_packet_with_template(
                            &hdr_template,
                            server_src,
                            src,
                            &payload,
                        )
                        .or_else(|| build_udp_reply_packet(server_src, src, &payload));
                        if let Some(pkt) = pkt {
                            let is_v6 = matches!(server_src, SocketAddr::V6(_));
                            // F3：超过 TUN MTU 的回包按 MTU 闭环写出（分片/ICMP 通告），
                            // 旧实现直接写超大包被内核静默丢弃（大包 UDP 静默失败）。
                            tun_write_mtu(&w, pkt, reply_mtu, is_v6).await;
                        }
                    }
                    // 所有 reply_tx 已 drop：session 已结束
                    Ok(None) => break,
                    // 空闲超时：与 GC 阈值一致，避免 task 滞留
                    Err(_elapsed) => break,
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
        // 对齐 sing-tun：UDP 转发不可用时回 ICMP Port Unreachable，
        // 让应用立即收到 ECONNREFUSED 而不是等待超时。
        let is_v6 = matches!(src, SocketAddr::V6(_));
        let err_pkt = if is_v6 {
            build_icmpv6_port_unreachable(ip_udp_header)
        } else {
            build_icmpv4_port_unreachable(ip_udp_header)
        };
        if let Some(err_pkt) = err_pkt {
            tun_write(&writer, &err_pkt, is_v6).await;
        }
    }
}

// ── 解析函数 ──────────────────────────────────────────────────────────────────

/// IPv6 扩展头常量（对齐内核 IPPROTO_*）
pub(crate) const IPPROTO_HOPOPTS: u8 = 0; // hop-by-hop options
pub(crate) const IPPROTO_ROUTING: u8 = 43; // routing header
pub(crate) const IPPROTO_FRAGMENT: u8 = 44; // fragment header
pub(crate) const IPPROTO_DSTOPTS: u8 = 60; // destination options

/// 遍历 IPv6 扩展头（B3 修复，对齐 sing-tun flow_parse.go skipIPv6ExtensionHeaders）。
///
/// 从固定头 next_header（`protocol`）开始，跳过 hop-by-hop / routing /
/// destination-options 扩展头，返回：
/// - 最终传输层协议号
/// - 传输层 payload（跳过全部扩展头后的切片）
/// - `is_fragment`：是否遇到 fragment 扩展头（分片包）
/// - `transport_present`：是否成功定位到可解析的传输层（false 表示
///   扩展头长度越界 / 链路异常）
///
/// 遇到 fragment header 时立即返回（fragment = true），此时无法安全定位
/// 传输层头（首片之外的分片不含传输层头）。
pub(crate) fn skip_ipv6_extension_headers(
    mut protocol: u8,
    mut payload: &[u8],
) -> (u8, &[u8], bool, bool) {
    loop {
        match protocol {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                if payload.len() < 2 {
                    // 扩展头长度字段越界，无法继续遍历
                    return (protocol, payload, false, false);
                }
                // 扩展头长度 = (payload[1] + 1) * 8 字节
                let ext_len = (payload[1] as usize + 1) * 8;
                if payload.len() < ext_len {
                    return (protocol, payload, false, false);
                }
                protocol = payload[0]; // Next Header 字段
                payload = &payload[ext_len..];
            }
            IPPROTO_FRAGMENT => {
                // 分片头：无法安全定位传输层（非首片不含传输层头）
                return (protocol, payload, true, false);
            }
            _ => {
                // TCP / UDP / ICMPv6 / ESP 等非扩展头协议：遍历结束
                return (protocol, payload, false, true);
            }
        }
    }
}

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

pub(crate) fn build_udp_reply_packet(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
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

// ── UDP 回包封装（基于原始请求 IP+UDP 头部模板）─────────────────────────────
//
// 对齐 sing-tun systemUDPPacketWriter4/6 的 headerCopy 机制：
// 在 UDP 会话建立时捕获原始请求的 IP+UDP 头部（含 IP options），构建回包时
// 复用该模板，仅改写 src/dst 地址与端口、长度与校验和。这样保留了请求包的
// ToS/DSCP、IP ID、flags(DF)、TTL、IP options 等字段，避免回包因这些字段
// 与 OS 期望不符而被丢弃或触发异常行为。
//
// `template` 为原始请求的 IP 头 + UDP 头（IPv4: IHL*4 + 8；IPv6: 40 + 8）。
// 返回 None 时调用方应回退到 build_udp_reply_packet（从零构造）。

fn build_udp_reply_packet_with_template(
    template: &[u8],
    reply_src: SocketAddr,
    reply_dst: SocketAddr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if template.is_empty() {
        return None;
    }
    match (reply_src, reply_dst, template[0] >> 4) {
        (SocketAddr::V4(s), SocketAddr::V4(d), 4) => {
            build_udp_reply_v4_with_template(template, s, d, payload)
        }
        (SocketAddr::V6(s), SocketAddr::V6(d), 6) => {
            build_udp_reply_v6_with_template(template, s, d, payload)
        }
        _ => None,
    }
}

/// 基于 IPv4 请求头部模板构建回包（对齐 sing-tun systemUDPPacketWriter4.WritePacket）。
///
/// 步骤：
/// 1. 复制模板（IP 头含 options + UDP 头），追加新 payload
/// 2. 设置 TotalLength = ihl + 8 + payload.len()
/// 3. 交换 src/dst IP：dst = 原始 src，src = reply_src（服务器）
/// 4. 交换 UDP 端口：dst_port = 原始 src_port，src_port = reply_src.port
/// 5. 设置 UDP Length = 8 + payload.len()
/// 6. 重算 UDP 校验和（含 IPv4 伪头部，使用新 src/dst）
/// 7. 重算 IP 校验和（覆盖 IHL*4 字节，含 options）
fn build_udp_reply_v4_with_template(
    template: &[u8],
    reply_src: SocketAddrV4,
    reply_dst: SocketAddrV4,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if template.len() < 28 {
        return None; // 至少 20(IP) + 8(UDP)
    }
    let ihl = ((template[0] & 0x0f) as usize) * 4;
    if ihl < 20 || template.len() < ihl + 8 {
        return None;
    }
    let udp_len = (8 + payload.len()) as u16;
    let total_len = (ihl as u16) + udp_len;

    let mut pkt = Vec::with_capacity(ihl + 8 + payload.len());
    pkt.extend_from_slice(&template[..ihl + 8]);
    pkt.extend_from_slice(payload);

    // TotalLength（字节 2-3）
    pkt[2] = (total_len >> 8) as u8;
    pkt[3] = (total_len & 0xff) as u8;
    // 交换 IP src/dst：dst = 原始 src（字节 12-15），src = 服务器（reply_src）
    let orig_src_ip: [u8; 4] = pkt[12..16].try_into().ok()?;
    pkt[16..20].copy_from_slice(&orig_src_ip); // dst = 原始 src
    pkt[12..16].copy_from_slice(&reply_src.ip().octets()); // src = 服务器
                                                           // 交换 UDP 端口：dst_port = 原始 src_port，src_port = 服务器端口
    let udp_off = ihl;
    let orig_src_port = u16::from_be_bytes([pkt[udp_off], pkt[udp_off + 1]]);
    pkt[udp_off + 2] = (orig_src_port >> 8) as u8;
    pkt[udp_off + 3] = (orig_src_port & 0xff) as u8; // dst_port = 原始 src_port
    pkt[udp_off] = (reply_src.port() >> 8) as u8;
    pkt[udp_off + 1] = (reply_src.port() & 0xff) as u8; // src_port = 服务器端口
                                                        // UDP Length
    pkt[udp_off + 4] = (udp_len >> 8) as u8;
    pkt[udp_off + 5] = (udp_len & 0xff) as u8;

    // 重算 UDP 校验和（含 IPv4 伪头部，使用新 src/dst）
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let new_src_ip: [u8; 4] = pkt[12..16].try_into().ok()?;
    let new_dst_ip: [u8; 4] = pkt[16..20].try_into().ok()?;
    let cksum = udp_checksum_v4(&new_src_ip, &new_dst_ip, &pkt[udp_off..]);
    pkt[udp_off + 6] = (cksum >> 8) as u8;
    pkt[udp_off + 7] = (cksum & 0xff) as u8;

    // 重算 IP 校验和（覆盖 IHL*4 字节，含 options）
    pkt[10] = 0;
    pkt[11] = 0;
    let ip_cksum = internet_checksum(&pkt[..ihl]);
    pkt[10] = (ip_cksum >> 8) as u8;
    pkt[11] = (ip_cksum & 0xff) as u8;

    // reply_dst 仅用于校验地址族一致（已在调用处保证），此处不再写入
    let _ = reply_dst;
    Some(pkt)
}

/// 基于 IPv6 请求头部模板构建回包（对齐 sing-tun systemUDPPacketWriter6.WritePacket）。
///
/// 步骤：
/// 1. 复制模板（40 字节固定头 + 8 字节 UDP 头），追加新 payload
/// 2. 设置 PayloadLength = 8 + payload.len()
/// 3. 交换 src/dst IP：dst = 原始 src，src = reply_src（服务器）
/// 4. 交换 UDP 端口：dst_port = 原始 src_port，src_port = reply_src.port
/// 5. 设置 UDP Length = 8 + payload.len()
/// 6. 重算 UDP 校验和（含 IPv6 伪头部，使用新 src/dst）
///    IPv6 无 IP 头校验和。
fn build_udp_reply_v6_with_template(
    template: &[u8],
    reply_src: SocketAddrV6,
    reply_dst: SocketAddrV6,
    payload: &[u8],
) -> Option<Vec<u8>> {
    if template.len() < 48 {
        return None; // 至少 40(IPv6) + 8(UDP)
    }
    let udp_len = (8 + payload.len()) as u16;

    let mut pkt = Vec::with_capacity(48 + payload.len());
    pkt.extend_from_slice(&template[..48]);
    pkt.extend_from_slice(payload);

    // PayloadLength（字节 4-5）
    pkt[4] = (udp_len >> 8) as u8;
    pkt[5] = (udp_len & 0xff) as u8;
    // 交换 IP src/dst：dst = 原始 src（字节 8-23），src = 服务器
    let mut orig_src_ip = [0u8; 16];
    orig_src_ip.copy_from_slice(&pkt[8..24]);
    pkt[24..40].copy_from_slice(&orig_src_ip); // dst = 原始 src
    pkt[8..24].copy_from_slice(&reply_src.ip().octets()); // src = 服务器
                                                          // 交换 UDP 端口：dst_port = 原始 src_port，src_port = 服务器端口
    let udp_off = 40usize;
    let orig_src_port = u16::from_be_bytes([pkt[udp_off], pkt[udp_off + 1]]);
    pkt[udp_off + 2] = (orig_src_port >> 8) as u8;
    pkt[udp_off + 3] = (orig_src_port & 0xff) as u8; // dst_port = 原始 src_port
    pkt[udp_off] = (reply_src.port() >> 8) as u8;
    pkt[udp_off + 1] = (reply_src.port() & 0xff) as u8; // src_port = 服务器端口
                                                        // UDP Length
    pkt[udp_off + 4] = (udp_len >> 8) as u8;
    pkt[udp_off + 5] = (udp_len & 0xff) as u8;

    // 重算 UDP 校验和（含 IPv6 伪头部，使用新 src/dst）
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;
    let new_src_ip: [u8; 16] = pkt[8..24].try_into().ok()?;
    let new_dst_ip: [u8; 16] = pkt[24..40].try_into().ok()?;
    let cksum = udp_checksum_v6(&new_src_ip, &new_dst_ip, &pkt[udp_off..]);
    pkt[udp_off + 6] = (cksum >> 8) as u8;
    pkt[udp_off + 7] = (cksum & 0xff) as u8;

    let _ = reply_dst;
    Some(pkt)
}

// ── Checksum 计算 ─────────────────────────────────────────────────────────────

pub(crate) fn internet_checksum(data: &[u8]) -> u16 {
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

/// IPv4 包 checksum（不含 PI 头，直接操作原始 IP 包）。
/// 对齐 sing-tun `ipHdr.SetChecksum(^ipHdr.CalculateChecksum())`：
/// checksum 覆盖**整个 IP 头**（IHL × 4 字节），含 IP options。
/// 旧实现固定取前 20 字节，IHL > 5（带 options）时 checksum 错误，
/// 导致对端协议栈丢弃带 IP options 的包。
pub(crate) fn recompute_ipv4_checksum(pkt: &mut [u8]) {
    if pkt.len() < 20 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }
    pkt[10] = 0;
    pkt[11] = 0;
    let cksum = internet_checksum(&pkt[..ihl]);
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

/// IPv6 TCP checksum（`pkt` 为原始 IPv6 包，`tcp_off` 为 TCP 头偏移）。
/// 无扩展头时为 40；带扩展头时由调用方按 `raw.len() - tcp_payload.len()` 传入，
/// 否则伪头部校验和会作用到错误区间（B3 修复）。
fn recompute_tcp_checksum_v6(pkt: &mut [u8], tcp_off: usize) {
    if pkt.len() < tcp_off + 18 || tcp_off < 40 {
        return;
    }
    let src_ip: [u8; 16] = pkt[8..24].try_into().unwrap_or([0u8; 16]);
    let dst_ip: [u8; 16] = pkt[24..40].try_into().unwrap_or([0u8; 16]);
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

/// 根据配置的 `tcp_mss` 和 TUN MTU 计算有效的 MSS 值。
///
/// 对齐 sing-tun `mtuToMSS`：当 `cfg_mss` 未显式配置时，从 MTU 动态推导：
/// - IPv4: MSS = MTU - 20 (IP头) - 20 (TCP头) = MTU - 40
/// - IPv6: MSS = MTU - 40 (IP头) - 20 (TCP头) = MTU - 60
///
/// 显式配置的 `cfg_mss` 优先（覆盖动态计算）。
/// 同一个值同时用于 v4/v6（v6 的 MSS 会被 clamp 到更小，确保不碎片）。
pub(crate) fn compute_effective_mss(cfg_mss: Option<u16>, mtu: u32) -> Option<u16> {
    if let Some(mss) = cfg_mss {
        return Some(mss);
    }
    // 动态推导：使用 IPv6 公式 (MTU-60) 作为保守值，同时适用 v4/v6。
    // v4 连接的 MSS 会被限制到 MTU-60（比理论最大 MTU-40 小 20 字节），
    // 但确保 v6 连接不碎片。对齐 sing-tun 默认行为。
    if mtu > 60 {
        Some((mtu - 60) as u16)
    } else if mtu > 40 {
        Some((mtu - 40) as u16)
    } else {
        None
    }
}

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
pub(crate) fn recompute_icmpv6_checksum(pkt: &mut [u8]) {
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

pub(crate) fn checksum_with_pseudo_v4(src: &[u8; 4], dst: &[u8; 4], proto: u8, data: &[u8]) -> u16 {
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
    for chunk in pseudo.as_chunks::<2>().0 {
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

pub(crate) fn checksum_with_pseudo_v6(
    src: &[u8; 16],
    dst: &[u8; 16],
    proto: u8,
    data: &[u8],
) -> u16 {
    let len = data.len() as u32;
    let mut sum: u32 = 0;
    for chunk in src.as_chunks::<2>().0 {
        sum += ((chunk[0] as u32) << 8) | (chunk[1] as u32);
    }
    for chunk in dst.as_chunks::<2>().0 {
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

// ── 平台原生实现 ──────────────────────────────────────────────────────────────
// platform 模块（src/inbound/tun/platform/）已拆分为各平台子模块：
//   Linux:   rtnetlink 路由 + nftables TPROXY
//   macOS:   AF_ROUTE + route 命令 fallback + utun 高级选项
//   Windows: WFP 端口 53 阻断 + winipcfg + netsh fallback
//   其他:    stub（空操作 + warn）

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
        let port = nat.lookup_or_insert(src, dst).await.unwrap();
        assert!((NAT_PORT_START..=NAT_PORT_END).contains(&port));
        // 同一 src 应得到同一 port
        assert_eq!(nat.lookup_or_insert(src, dst).await, Some(port));
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
    async fn test_tcp_nat_port_exhaustion_returns_none() {
        // 对齐 sing-tun：端口池耗尽时返回 None（不驱逐），保护已有连接。
        let nat = TcpNat::new();
        // 填满端口池（每个 (src, dst) 5-tuple 分配一个端口）
        for i in 0..(NAT_PORT_END - NAT_PORT_START + 1) {
            let src: SocketAddr = format!("10.0.{}.{}:1000", i / 256, i % 256)
                .parse()
                .unwrap();
            let dst: SocketAddr = "8.8.8.8:80".parse().unwrap();
            nat.lookup_or_insert(src, dst).await;
        }
        // 再分配一个新的，应返回 None（端口池耗尽，不驱逐）
        let new_src: SocketAddr = "192.168.99.1:9999".parse().unwrap();
        let new_dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
        assert_eq!(nat.lookup_or_insert(new_src, new_dst).await, None);
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
    fn test_has_next_addr_v4() {
        // 正常 /16：198.18.0.1 → 198.18.0.2 在前缀内
        assert!(has_next_addr_v4("198.18.0.1".parse().unwrap(), 16));
        // /32：ip+1 不在 /32 内
        assert!(!has_next_addr_v4("198.18.0.1".parse().unwrap(), 32));
        // x.x.x.255/24：ip+1 = x.x.(x+1).0 不在 /24 内
        assert!(!has_next_addr_v4("198.18.0.255".parse().unwrap(), 24));
        // /30：198.18.0.1 → .2 在前缀内（.0-.3）
        assert!(has_next_addr_v4("198.18.0.1".parse().unwrap(), 30));
        // /30：198.18.0.2 → .3 在前缀内
        assert!(has_next_addr_v4("198.18.0.2".parse().unwrap(), 30));
        // /30：198.18.0.3 → .4 不在 /30 内
        assert!(!has_next_addr_v4("198.18.0.3".parse().unwrap(), 30));
        // 255.255.255.255 → 溢出
        assert!(!has_next_addr_v4("255.255.255.255".parse().unwrap(), 0));
        // /0：任何非溢出地址都有下一地址
        assert!(has_next_addr_v4("1.2.3.4".parse().unwrap(), 0));
    }

    #[test]
    fn test_has_next_addr_v6() {
        // 正常 /126：fd00::1 → fd00::2 在前缀内
        assert!(has_next_addr_v6("fd00::1".parse().unwrap(), 126));
        // /128：ip+1 不在 /128 内
        assert!(!has_next_addr_v6("fd00::1".parse().unwrap(), 128));
        // /126：fd00::3 → fd00::4 不在 /126 内（.0-.3）
        assert!(!has_next_addr_v6("fd00::3".parse().unwrap(), 126));
        // 全 1 溢出
        let all_ones = Ipv6Addr::from(u128::MAX);
        assert!(!has_next_addr_v6(all_ones, 0));
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

    /// 构造一个原始 IPv4 UDP 请求包的 IP+UDP 头部模板（28 字节，IHL=5）。
    /// 客户端 192.168.1.100:12345 → 服务器 8.8.8.8:53
    fn build_v4_request_template(tos: u8, ip_id: u16, ttl: u8) -> Vec<u8> {
        let mut hdr = vec![0u8; 28];
        hdr[0] = 0x45; // version=4, IHL=5
        hdr[1] = tos;
        // total_length (bytes 2-3) — 请求时的值，回包会重算
        hdr[2..4].copy_from_slice(&100u16.to_be_bytes());
        hdr[4..6].copy_from_slice(&ip_id.to_be_bytes());
        hdr[6] = 0x40; // flags: DF
        hdr[7] = 0x00; // frag offset
        hdr[8] = ttl;
        hdr[9] = IPPROTO_UDP;
        // checksum (bytes 10-11) — 请求时的值，回包会重算
        // src = client
        hdr[12..16].copy_from_slice(&[192, 168, 1, 100]);
        // dst = server
        hdr[16..20].copy_from_slice(&[8, 8, 8, 8]);
        // UDP header
        hdr[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port (client)
        hdr[22..24].copy_from_slice(&53u16.to_be_bytes()); // dst port (server)
        hdr[24..26].copy_from_slice(&92u16.to_be_bytes()); // UDP length
        hdr[26..28].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        hdr
    }

    #[test]
    fn test_build_udp_reply_v4_with_template_preserves_fields() {
        let template = build_v4_request_template(0x28, 0x1234, 55);
        let reply_src: SocketAddr = "8.8.8.8:53".parse().unwrap(); // server
        let reply_dst: SocketAddr = "192.168.1.100:12345".parse().unwrap(); // client
        let payload = b"reply-data";
        let pkt =
            build_udp_reply_packet_with_template(&template, reply_src, reply_dst, payload).unwrap();

        // 长度 = 20(IP) + 8(UDP) + payload
        assert_eq!(pkt.len(), 20 + 8 + payload.len());
        // 保留 ToS
        assert_eq!(pkt[1], 0x28);
        // 保留 IP ID
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x1234);
        // 保留 flags(DF)
        assert_eq!(pkt[6] & 0xe0, 0x40);
        // 保留 TTL
        assert_eq!(pkt[8], 55);
        // 交换 IP src/dst：src=server(8.8.8.8), dst=client(192.168.1.100)
        assert_eq!(&pkt[12..16], &[8, 8, 8, 8]);
        assert_eq!(&pkt[16..20], &[192, 168, 1, 100]);
        // 交换 UDP 端口：src=53(server), dst=12345(client)
        assert_eq!(u16::from_be_bytes([pkt[20], pkt[21]]), 53);
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 12345);
        // TotalLength = 20 + 8 + payload
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        assert_eq!(total, 20 + 8 + payload.len());
        // UDP Length = 8 + payload
        let udp_len = u16::from_be_bytes([pkt[24], pkt[25]]) as usize;
        assert_eq!(udp_len, 8 + payload.len());
        // IP checksum 校验：对含 checksum 字段的完整头计算应得 0
        assert_eq!(internet_checksum(&pkt[..20]), 0, "IP checksum invalid");
        // UDP checksum 校验（含伪头部）
        let src_ip: [u8; 4] = pkt[12..16].try_into().unwrap();
        let dst_ip: [u8; 4] = pkt[16..20].try_into().unwrap();
        let udp_cksum = u16::from_be_bytes([pkt[26], pkt[27]]);
        let mut udp_hdr = pkt[20..].to_vec();
        udp_hdr[6] = 0;
        udp_hdr[7] = 0;
        let recomputed = udp_checksum_v4(&src_ip, &dst_ip, &udp_hdr);
        assert_eq!(udp_cksum, recomputed, "UDP checksum mismatch");
    }

    #[test]
    fn test_build_udp_reply_v4_with_template_ip_options() {
        // IHL=6（24 字节 IP 头，含 4 字节 options），验证 IP checksum 覆盖 options
        let mut hdr = vec![0u8; 24 + 8]; // 24 IP + 8 UDP
        hdr[0] = 0x46; // version=4, IHL=6
        hdr[1] = 0x10; // ToS
        hdr[4..6].copy_from_slice(&0xBEEFu16.to_be_bytes()); // IP ID
        hdr[8] = 48; // TTL
        hdr[9] = IPPROTO_UDP;
        hdr[12..16].copy_from_slice(&[10, 0, 0, 2]); // src = client
        hdr[16..20].copy_from_slice(&[1, 1, 1, 1]); // dst = server
        hdr[20..24].copy_from_slice(&[0x01, 0x01, 0x01, 0x00]); // NOP, NOP, NOP, EOL (options)
        hdr[24..26].copy_from_slice(&54321u16.to_be_bytes()); // src port (client)
        hdr[26..28].copy_from_slice(&80u16.to_be_bytes()); // dst port (server)

        let reply_src: SocketAddr = "1.1.1.1:80".parse().unwrap();
        let reply_dst: SocketAddr = "10.0.0.2:54321".parse().unwrap();
        let payload = b"ok";
        let pkt =
            build_udp_reply_packet_with_template(&hdr, reply_src, reply_dst, payload).unwrap();

        // 长度 = 24(IP含options) + 8(UDP) + payload
        assert_eq!(pkt.len(), 24 + 8 + payload.len());
        // IHL 保留为 6
        assert_eq!(pkt[0], 0x46);
        // IP options 保留
        assert_eq!(&pkt[20..24], &[0x01, 0x01, 0x01, 0x00]);
        // ToS / TTL 保留
        assert_eq!(pkt[1], 0x10);
        assert_eq!(pkt[8], 48);
        // IP checksum 覆盖 24 字节（含 options）：对含 checksum 字段的完整头计算应得 0
        assert_eq!(
            internet_checksum(&pkt[..24]),
            0,
            "IP checksum must cover options"
        );
    }

    #[test]
    fn test_build_udp_reply_v6_with_template_preserves_fields() {
        // IPv6 模板：40(IPv6) + 8(UDP) = 48 字节
        let mut hdr = vec![0u8; 48];
        hdr[0] = 0x60; // version=6
                       // traffic class + flow label (bytes 1-3): TC=0x28, FL=0x12345
        hdr[1] = 0x28;
        hdr[2..4].copy_from_slice(&[0x12, 0x34]); // flow label low bits (with TC nibble)
        hdr[6] = IPPROTO_UDP; // next header
        hdr[7] = 37; // hop limit
                     // src = client [fc00::100]
        hdr[8..24].copy_from_slice(&[0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        // dst = server [fc00::dead]
        hdr[24..40].copy_from_slice(&[0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad]);
        // UDP header
        hdr[40..42].copy_from_slice(&24680u16.to_be_bytes()); // src port (client)
        hdr[42..44].copy_from_slice(&443u16.to_be_bytes()); // dst port (server)

        let reply_src: SocketAddr = "[fc00::dead]:443".parse().unwrap();
        let reply_dst: SocketAddr = "[fc00::100]:24680".parse().unwrap();
        let payload = b"v6reply";
        let pkt =
            build_udp_reply_packet_with_template(&hdr, reply_src, reply_dst, payload).unwrap();

        // 长度 = 40(IPv6) + 8(UDP) + payload
        assert_eq!(pkt.len(), 40 + 8 + payload.len());
        // 保留 traffic class（高 4 位 of byte 1）
        assert_eq!(pkt[1] & 0xf0, 0x20);
        // 保留 hop limit
        assert_eq!(pkt[7], 37);
        // 交换 src/dst
        assert_eq!(
            &pkt[8..24],
            &[0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad]
        );
        assert_eq!(
            &pkt[24..40],
            &[0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        );
        // 交换端口
        assert_eq!(u16::from_be_bytes([pkt[40], pkt[41]]), 443);
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 24680);
        // PayloadLength = 8 + payload
        let plen = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
        assert_eq!(plen, 8 + payload.len());
        // UDP checksum 校验
        let src_ip: [u8; 16] = pkt[8..24].try_into().unwrap();
        let dst_ip: [u8; 16] = pkt[24..40].try_into().unwrap();
        let udp_cksum = u16::from_be_bytes([pkt[46], pkt[47]]);
        let mut udp_hdr = pkt[40..].to_vec();
        udp_hdr[6] = 0;
        udp_hdr[7] = 0;
        let recomputed = udp_checksum_v6(&src_ip, &dst_ip, &udp_hdr);
        assert_eq!(udp_cksum, recomputed, "IPv6 UDP checksum mismatch");
    }

    #[test]
    fn test_build_udp_reply_packet_with_template_fallback() {
        // 空模板应返回 None（调用方回退到从零构造）
        let r = build_udp_reply_packet_with_template(
            &[],
            "8.8.8.8:53".parse().unwrap(),
            "1.2.3.4:5".parse().unwrap(),
            b"x",
        );
        assert!(r.is_none());
        // 过短模板应返回 None
        let r = build_udp_reply_packet_with_template(
            &[0x45, 0x00],
            "8.8.8.8:53".parse().unwrap(),
            "1.2.3.4:5".parse().unwrap(),
            b"x",
        );
        assert!(r.is_none());
        // 地址族不匹配应返回 None（v4 地址 + v6 模板）
        let mut hdr = vec![0u8; 48];
        hdr[0] = 0x60;
        let r = build_udp_reply_packet_with_template(
            &hdr,
            "8.8.8.8:53".parse().unwrap(),
            "1.2.3.4:5".parse().unwrap(),
            b"x",
        );
        assert!(r.is_none());
    }

    #[test]
    fn test_compute_effective_mss_explicit_config_wins() {
        // 显式配置优先，忽略 MTU
        assert_eq!(compute_effective_mss(Some(1200), 9000), Some(1200));
        assert_eq!(compute_effective_mss(Some(1460), 1500), Some(1460));
    }

    #[test]
    fn test_compute_effective_mss_derived_from_mtu_default() {
        // 未配置 cfg_mss：默认 MTU=9000 → 9000-60=8940
        assert_eq!(compute_effective_mss(None, 9000), Some(8940));
        // 标准以太网 MTU=1500 → 1500-60=1440（保守值，兼容 v6）
        assert_eq!(compute_effective_mss(None, 1500), Some(1440));
        // IPv6 最小 MTU=1280 → 1280-60=1220
        assert_eq!(compute_effective_mss(None, 1280), Some(1220));
    }

    #[test]
    fn test_compute_effective_mss_small_mtu_uses_v4_formula() {
        // MTU <= 60 但 > 40：退化用 v4 公式 (MTU-40)
        assert_eq!(compute_effective_mss(None, 50), Some(10));
        assert_eq!(compute_effective_mss(None, 41), Some(1));
    }

    #[test]
    fn test_compute_effective_mss_too_small_returns_none() {
        // MTU <= 40：无法承载 TCP，返回 None（不 clamp）
        assert_eq!(compute_effective_mss(None, 40), None);
        assert_eq!(compute_effective_mss(None, 0), None);
    }
}
