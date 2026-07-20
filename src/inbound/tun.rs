//! TUN 虚拟网卡入站。
//!
//! ## 架构（System Stack NAT，参照 sing-tun `stack_system.go`）
//!
//! ### TCP 处理
//! 1. 启动时在 TUN 自身地址（`inet4_addr`，如 198.18.0.1）上绑定一个长期 TcpListener（端口随机）。
//! 2. 收到 TCP 出站包：改写头部，src→inet4_next:nat_port，dst→inet4_addr:listener_port，
//!    写回 TUN；内核 TCP 栈向 Listener 发起连接。
//! 3. Listener accept 后，按 NAT 表（nat_port → 原始 dst）还原真实目标。
//! 4. 来自 Listener 的回包（src 为 TUN 地址）：反向还原 src/dst 后写回 TUN。
//!
//! ### UDP 处理
//! UDP 会话表维持 (src, dst) → reply_tx 映射；回包直接封装 IP/UDP 头写回 TUN。
//! checksum 使用完整伪头部计算（含 IPv4/IPv6 伪头）。
//!
//! ### ICMP 处理
//! ICMPv4/v6 Echo Request 在 TUN 内部回环（src↔dst 互换，类型改为 Reply）。
//!
//! ### 写回路径统一
//! 所有"写回 TUN"操作统一通过 `tun_write`：
//! - 构建函数只返回原始 IP 包
//! - tun 0.8 所有平台均不含 PI 头，`tun_write` 直接写入
//!
//! ### TCP NAT 端口耗尽策略（参照 sing-tun）
//! 端口循环分配；耗尽时驱逐 last_active 最旧的条目，不覆盖随机条目。
//!
//! ### Linux auto_route
//! 使用 iproute2 策略路由；所有已添加规则优先级记录在 `used_priorities` 中，
//! teardown 时精确清理，不依赖固定偏移量。
//!
//! ### Windows auto_route
//! 使用 `netsh` + 实际接口名（通过 PowerShell 验证后再执行）。
//!
//! 修复了三个问题：
//! 1. **TCP Listener 绑定时序**：`platform::setup()` 配置 IP 地址后，Windows 需要数百毫秒
//!    才能将地址绑定到网卡。旧代码直接 bind 导致必然失败。
//!    修复：setup 之后、bind 之前轮询等待地址真正可用（最多 6s）。
//! 2. **接口名验证**：wintun 适配器创建后实际名称以 PowerShell 查询为准，
//!    配置的 `interface_name` 不一定与内核看到的相同。
//!    修复：setup() 先用 PowerShell 验证实际接口名，再执行 netsh。
//! 3. **strict_route 自身豁免**：旧代码用 `netsh advfirewall` 阻断所有 UDP/53 出站，
//!    包括 reflex 进程自身，导致代理的 DNS 查询也被拦截。
//!    修复：添加 `program=<exe_path>` 例外，只拦截其他进程的 UDP/53。
//!
//! ## 依赖
//! `tun = { version = "0.8", features = ["async"] }`
//!
//! **tun 0.8 = tun2 合并版**：tun2 的作者（@ssrlive）已成为 tun crate 共同维护者，
//! tun2 停止独立维护，代码全部并回 tun crate（0.7+）。相对 0.6 的关键变化：
//!   - `platform(...)` → `platform_config(...)`
//!   - Linux 新增 `p.ensure_root_privileges(true)`
//!   - Windows 新增 `p.device_guid(u128)` 固定适配器 GUID
//!   - Windows 底层从 `wintun 0.3`（需手动提供 DLL）换成 `wintun-bindings 0.7`
//!     （**静态链接 DLL，无需用户手动拷贝**）
//!   - `create_as_async` / `Configuration` 接口不变，直接升级即可

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
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, warn};
#[cfg(not(target_os = "windows"))]
use tun::AbstractDevice as _;

use crate::{
    config::inbound::TunInboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession},
};

// ── 常量 ──────────────────────────────────────────────────────────────────────

const DEFAULT_UDP_TIMEOUT_SECS: u64 = 300;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
const IPV4_VERSION: u8 = 4;
const IPV6_VERSION: u8 = 6;

/// NAT 端口范围（与 sing-tun 保持一致）
const NAT_PORT_START: u16 = 10000;
const NAT_PORT_END: u16 = 60000;

/// 默认 loopback 地址（参照 sing-tun TunOptions.Inet4LoopbackAddress 默认值）。
/// 当配置中未指定 `loopback_address` 时使用。
const DEFAULT_INET4_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const DEFAULT_INET6_LOOPBACK: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);

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
// 关键优化（对比旧实现）：
// 1. **锁分离**：addr_map 和 port_map 各有独立 RwLock。
//    旧实现用单个 RwLock<TcpNat> 包裹两表，lookup_back 取写锁，
//    每条 TCP accept 都串行化。现在 lookup_back 只取 port_map 的**读锁**，
//    允许并发反查。
// 2. **per-entry last_active**：每条会话的 last_active 用独立 Mutex 保护，
//    更新时间戳只需锁单个 entry，不阻塞其他会话的查找/插入。
// 3. **throttled update**：sing-tun 仅当距上次更新 >1s 时才刷新 last_active，
//    避免高频小流量连接在每包都争抢 entry 锁。此处采用同样策略。

struct TcpNatEntry {
    source: SocketAddr,
    destination: SocketAddr,
    /// std::sync::Mutex（非 tokio）—— 持锁期间无 .await，仅读写 Instant
    last_active: std::sync::Mutex<Instant>,
}

struct TcpNat {
    /// 端口分配游标，用 Mutex 保护（分配时不持有 map 的锁）
    port_index: std::sync::Mutex<u16>,
    /// (src_addr, src_port) → nat_port
    addr_map: tokio::sync::RwLock<HashMap<SocketAddr, u16>>,
    /// nat_port → session（Arc 便于在读锁释放后仍持有 entry 引用）
    port_map: tokio::sync::RwLock<HashMap<u16, Arc<TcpNatEntry>>>,
}

impl TcpNat {
    fn new() -> Self {
        Self {
            port_index: std::sync::Mutex::new(NAT_PORT_START),
            addr_map: tokio::sync::RwLock::new(HashMap::new()),
            port_map: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// 为 (src, dst) 分配 NAT 端口。
    /// - 已有映射直接返回（throttled 更新 last_active）。
    /// - 无可用端口时：驱逐 last_active 最旧的条目后复用其端口。
    async fn lookup_or_insert(&self, src: SocketAddr, dst: SocketAddr) -> u16 {
        // 快速路径：读锁查 addr_map
        if let Some(&port) = self.addr_map.read().await.get(&src) {
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

        // 慢速路径：分配新端口
        // 1. 在 port_index Mutex 下取下一个候选端口
        let port = {
            let mut idx = self.port_index.lock().unwrap();
            let p = *idx;
            *idx = if *idx >= NAT_PORT_END {
                NAT_PORT_START
            } else {
                *idx + 1
            };
            p
        };

        // 2. 写锁两表插入
        {
            let mut port_map = self.port_map.write().await;
            // 端口已被占用（循环碰撞）→ 驱逐最旧条目
            if port_map.contains_key(&port) {
                let evict_port = port_map
                    .iter()
                    .min_by_key(|(_, e)| {
                        e.last_active
                            .lock()
                            .map(|t| *t)
                            .unwrap_or_else(|_| Instant::now())
                    })
                    .map(|(&p, _)| p)
                    .unwrap_or(port);
                if let Some(old) = port_map.remove(&evict_port) {
                    drop(port_map);
                    self.addr_map.write().await.remove(&old.source);
                    // 重新获取写锁插入
                    self.port_map.write().await.insert(
                        evict_port,
                        Arc::new(TcpNatEntry {
                            source: src,
                            destination: dst,
                            last_active: std::sync::Mutex::new(Instant::now()),
                        }),
                    );
                    self.addr_map.write().await.insert(src, evict_port);
                    return evict_port;
                }
            }
            port_map.insert(
                port,
                Arc::new(TcpNatEntry {
                    source: src,
                    destination: dst,
                    last_active: std::sync::Mutex::new(Instant::now()),
                }),
            );
        }
        self.addr_map.write().await.insert(src, port);
        port
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
    async fn gc(&self, timeout: Duration) {
        let now = Instant::now();
        let expired: Vec<(u16, SocketAddr)> = {
            let port_map = self.port_map.read().await;
            port_map
                .iter()
                .filter(|(_, e)| {
                    e.last_active
                        .lock()
                        .map(|t| now.duration_since(*t) > timeout)
                        .unwrap_or(false)
                })
                .map(|(&p, e)| (p, e.source))
                .collect()
        };
        if expired.is_empty() {
            return;
        }
        let mut port_map = self.port_map.write().await;
        let mut addr_map = self.addr_map.write().await;
        for (port, src) in expired {
            port_map.remove(&port);
            addr_map.remove(&src);
        }
    }
}

// ── 统一 TUN 写回辅助 ─────────────────────────────────────────────────────────

/// 写回 TUN 设备。
/// `raw_ip` 是原始 IP 包（不含 PI 头）。
/// tun 0.8 起所有平台包均不含 PI 头，直接写入即可。
async fn tun_write(
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
        }
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

        // ── auto_route ───────────────────────────────────────────────────────
        if cfg.auto_route {
            match platform::setup(&cfg, &if_name) {
                Ok(()) => info!(interface = %if_name, "tun: auto_route configured"),
                Err(e) => {
                    warn!(err = %e, "tun: auto_route setup failed (requires elevated privileges)")
                }
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
                accept_loop(listener, nat, tx, tag2, prefixes, false, (inet4_loopback, inet6_loopback)).await;
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
                accept_loop(listener, nat, tx, tag2, prefixes, true, (inet4_loopback, inet6_loopback)).await;
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
                        &tag,
                        &self.udp_tx,
                        writer.clone(),
                        tcp_nat.clone(),
                        udp_sessions.clone(),
                        udp_timeout,
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
                        &tag,
                        &self.udp_tx,
                        writer.clone(),
                        tcp_nat.clone(),
                        udp_sessions.clone(),
                        udp_timeout,
                    )
                    .await;
                }
                v => {
                    debug!(version = v, "tun: unknown IP version, dropping");
                }
            }
        }

        if cfg.auto_route {
            if let Err(e) = platform::teardown(&cfg, &if_name) {
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
async fn accept_loop(
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
    tag: &Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    udp_timeout: Duration,
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
    tag: &Arc<String>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    writer: Arc<Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
    tcp_nat: Arc<TcpNat>,
    udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpEntry>>>,
    udp_timeout: Duration,
) {
    if raw.len() < 40 {
        return;
    }
    let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap_or([0u8; 16]));
    let dst_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));
    let payload = &raw[40..];

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
async fn handle_tcp_v4(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    inet4_server_addr: Option<Ipv4Addr>,
    inet4_client_addr: Option<Ipv4Addr>,
    inet4_loopback: Ipv4Addr,
    tcp_port: u16,
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
    recompute_tcp_checksum_v4(&mut pkt, ihl);
    recompute_ipv4_checksum(&mut pkt);
    tun_write(&writer, &pkt, false).await;

    debug!(src = %src, dst = %dst, nat_port, "tun: tcp v4 NAT");
}

#[allow(clippy::too_many_arguments)]
async fn handle_tcp_v6(
    raw: &[u8],
    tcp_payload: &[u8],
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    inet6_server_addr: Option<Ipv6Addr>,
    inet6_client_addr: Option<Ipv6Addr>,
    inet6_loopback: Ipv6Addr,
    tcp_port: u16,
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
    recompute_tcp_checksum_v6(&mut pkt);
    tun_write(&writer, &pkt, true).await;
}

// ── ICMPv4 回环 ───────────────────────────────────────────────────────────────

async fn handle_icmpv4(
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

async fn handle_icmpv6(
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
) {
    let key = (src, dst);
    let mut sessions = udp_sessions.lock().await;

    let entry = sessions.entry(key).or_insert_with(|| {
        debug!(src = %src, dst = %dst, "tun: new UDP session");
        let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
        let w = writer.clone();
        tokio::spawn(async move {
            while let Some((payload, orig_src, _spoofed_src)) = reply_rx.recv().await {
                // 统一调用 build_udp_reply_packet（返回原始 IP 包，不含 PI）
                if let Some(pkt) = build_udp_reply_packet(orig_src, src, &payload) {
                    let is_v6 = matches!(orig_src, SocketAddr::V6(_));
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

fn parse_udp_v4(
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

fn parse_udp_v6(
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

fn build_udp_reply_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
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
mod platform {
    use super::{parse_addr_prefix, TunInboundConfig};
    use std::net::IpAddr;
    use std::process::Command;
    use tracing::{info, warn};

    // ── UID 范围计算 ─────────────────────────────────────────────────────────
    // 直接复用上层模块的范围运算函数，避免重复实现导致行为不一致。

    /// 合并 `include_uid`/`exclude_uid` + `include_uid_range`/`exclude_uid_range`，
    /// 输出最终的 excluded 范围（参照 sing-tun buildExcludedRanges）。
    fn build_excluded_uid_ranges_full(cfg: &TunInboundConfig) -> Vec<(u32, u32)> {
        let include = super::merge_uid_list_and_ranges(&cfg.include_uid, &cfg.include_uid_range);
        let exclude = super::merge_uid_list_and_ranges(&cfg.exclude_uid, &cfg.exclude_uid_range);
        if include.is_empty() && exclude.is_empty() {
            return vec![];
        }
        const UID_MAX: u32 = u32::MAX - 1;
        if !include.is_empty() {
            super::merge_ranges(super::complement_ranges(
                &super::subtract_ranges(&include, &exclude),
                0,
                UID_MAX,
            ))
        } else {
            super::merge_ranges(exclude)
        }
    }

    // ── iproute2 封装 ────────────────────────────────────────────────────────

    /// 执行 `ip [args...]`，忽略错误（由调用者通过 used_priorities 追踪）
    fn ip(args: &[&str]) {
        Command::new("ip").args(args).output().ok();
    }

    fn ip6(args: &[&str]) {
        Command::new("ip").arg("-6").args(args).output().ok();
    }

    /// 执行并检查返回值
    fn ip_check(args: &[&str]) -> bool {
        Command::new("ip")
            .args(args)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    // ── 地址解析 ────────────────────────────────────────────────────────────

    struct AddrInfo {
        inet4: Vec<(std::net::Ipv4Addr, u8)>,
        inet6: Vec<(std::net::Ipv6Addr, u8)>,
    }

    fn parse_addresses(cfg: &TunInboundConfig) -> AddrInfo {
        let mut inet4 = vec![];
        let mut inet6 = vec![];
        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), pl)) => inet4.push((ip, pl)),
                Some((IpAddr::V6(ip), pl)) => inet6.push((ip, pl)),
                None => warn!(addr = %addr_str, "tun: invalid address prefix"),
            }
        }
        AddrInfo { inet4, inet6 }
    }

    fn v4_network(ip: std::net::Ipv4Addr, pl: u8) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from(ip) & !((1u32 << (32 - pl.min(32))) - 1))
    }

    fn v6_network(ip: std::net::Ipv6Addr, pl: u8) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(u128::from(ip) & !((1u128 << (128 - pl.min(128))) - 1))
    }

    /// 判断 prefix `outer` 是否完全包含 prefix `inner`（用于 route_exclude_address 过滤）。
    fn prefix_contains_v4(outer: (std::net::Ipv4Addr, u8), inner: (std::net::Ipv4Addr, u8)) -> bool {
        let (o_net, o_pl) = outer;
        let (i_net, i_pl) = inner;
        if o_pl > i_pl {
            return false;
        }
        let mask = !((1u32 << (32 - o_pl.min(32))) - 1);
        (u32::from(o_net) & mask) == (u32::from(i_net) & mask)
    }

    fn prefix_contains_v6(
        outer: (std::net::Ipv6Addr, u8),
        inner: (std::net::Ipv6Addr, u8),
    ) -> bool {
        let (o_net, o_pl) = outer;
        let (i_net, i_pl) = inner;
        if o_pl > i_pl {
            return false;
        }
        let mask = !((1u128 << (128 - o_pl.min(128))) - 1);
        (u128::from(o_net) & mask) == (u128::from(i_net) & mask)
    }

    /// setup 返回所有已添加的规则优先级列表，供 teardown 精确清理。
    pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let table = cfg.iproute2_table_index.to_string();
        let prio_base = cfg.iproute2_rule_index;
        // nop 锚点：优先级固定为 prio_base + 100，远离业务规则，避免冲突
        let nop_prio = prio_base + 100;
        let nop = nop_prio.to_string();

        let addrs = parse_addresses(cfg);
        let has_v4 = !addrs.inet4.is_empty();
        let has_v6 = !addrs.inet6.is_empty();

        // 确保设备 up
        ip(&["link", "set", if_name, "up"]);

        // ── 路由表：默认路由 / route_address ──────────────────────────────
        // 与 sing-tun routes() 对齐：默认**不创建网关**（sing-tun 注释
        // "Do not create gateway on linux by default"），通过 `suppress_prefixlength 0`
        // 让规则匹配默认路由。
        // 但若用户指定了 `route_address`，则只为这些 CIDR 添加路由。
        // `route_exclude_address` 通过不添加对应路由实现排除（与 sing-tun netipx IPSet 等价）。
        let route_v4: Vec<(std::net::Ipv4Addr, u8)> = if !cfg.route_address.is_empty() {
            cfg.route_address
                .iter()
                .filter_map(|s| match super::parse_addr_prefix(s) {
                    Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
                    _ => None,
                })
                .collect()
        } else {
            // 默认劫持 0.0.0.0/0
            vec![(std::net::Ipv4Addr::UNSPECIFIED, 0)]
        };
        let route_v6: Vec<(std::net::Ipv6Addr, u8)> = if !cfg.route_address.is_empty() {
            cfg.route_address
                .iter()
                .filter_map(|s| match super::parse_addr_prefix(s) {
                    Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
                    _ => None,
                })
                .collect()
        } else {
            vec![(std::net::Ipv6Addr::UNSPECIFIED, 0)]
        };
        // 应用 route_exclude_address 过滤
        let excluded_v4: Vec<(std::net::Ipv4Addr, u8)> = cfg
            .route_exclude_address
            .iter()
            .filter_map(|s| match super::parse_addr_prefix(s) {
                Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect();
        let excluded_v6: Vec<(std::net::Ipv6Addr, u8)> = cfg
            .route_exclude_address
            .iter()
            .filter_map(|s| match super::parse_addr_prefix(s) {
                Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect();
        let route_v4: Vec<(std::net::Ipv4Addr, u8)> = route_v4
            .into_iter()
            .filter(|r| !excluded_v4.iter().any(|e| prefix_contains_v4(*e, *r)))
            .collect();
        let route_v6: Vec<(std::net::Ipv6Addr, u8)> = route_v6
            .into_iter()
            .filter(|r| !excluded_v6.iter().any(|e| prefix_contains_v6(*e, *r)))
            .collect();

        if has_v4 {
            for (net_ip, pl) in &route_v4 {
                let cidr = format!("{net_ip}/{pl}");
                ip(&["route", "add", &cidr, "dev", if_name, "table", &table]);
            }
        }
        if has_v6 {
            for (net_ip, pl) in &route_v6 {
                let cidr = format!("{net_ip}/{pl}");
                ip6(&["route", "add", &cidr, "dev", if_name, "table", &table]);
            }
        }

        // ── 策略规则（按优先级顺序添加，与 sing-tun rules() 顺序对齐）─────
        // 使用独立的 p4/p6 计数器，每条规则占一个优先级槽位
        let mut p4 = prio_base;
        let mut p6 = prio_base;

        // 1. UID 排除（goto nop）—— 合并 include_uid(_range) 与 exclude_uid(_range)
        let excluded_uids = build_excluded_uid_ranges_full(cfg);
        for (lo, hi) in &excluded_uids {
            let uid_range = format!("{lo}-{hi}");
            if has_v4 {
                ip(&[
                    "rule",
                    "add",
                    "priority",
                    &p4.to_string(),
                    "uidrange",
                    &uid_range,
                    "goto",
                    &nop,
                ]);
                p4 += 1;
            }
            if has_v6 {
                ip6(&[
                    "rule",
                    "add",
                    "priority",
                    &p6.to_string(),
                    "uidrange",
                    &uid_range,
                    "goto",
                    &nop,
                ]);
                p6 += 1;
            }
        }

        // 2. 接口过滤
        if !cfg.include_interface.is_empty() {
            // 白名单：不在列表中的接口 goto nop，在列表中的跳过后续规则继续
            for iface in &cfg.include_interface {
                if has_v4 {
                    ip(&[
                        "rule",
                        "add",
                        "priority",
                        &p4.to_string(),
                        "iif",
                        iface,
                        "lookup",
                        &table,
                    ]);
                    p4 += 1;
                }
                if has_v6 {
                    ip6(&[
                        "rule",
                        "add",
                        "priority",
                        &p6.to_string(),
                        "iif",
                        iface,
                        "lookup",
                        &table,
                    ]);
                    p6 += 1;
                }
            }
            // 不匹配的接口 → nop
            if has_v4 {
                ip(&["rule", "add", "priority", &p4.to_string(), "goto", &nop]);
                p4 += 1;
            }
            if has_v6 {
                ip6(&["rule", "add", "priority", &p6.to_string(), "goto", &nop]);
                p6 += 1;
            }
        } else if !cfg.exclude_interface.is_empty() {
            // 黑名单：列表中的接口 goto nop
            for iface in &cfg.exclude_interface {
                if has_v4 {
                    ip(&[
                        "rule",
                        "add",
                        "priority",
                        &p4.to_string(),
                        "iif",
                        iface,
                        "goto",
                        &nop,
                    ]);
                    p4 += 1;
                }
                if has_v6 {
                    ip6(&[
                        "rule",
                        "add",
                        "priority",
                        &p6.to_string(),
                        "iif",
                        iface,
                        "goto",
                        &nop,
                    ]);
                    p6 += 1;
                }
            }
        }

        // 3. strict_route：为缺失地址族添加 unreachable 规则
        if cfg.strict_route {
            if !has_v4 {
                ip(&[
                    "rule",
                    "add",
                    "priority",
                    &p4.to_string(),
                    "type",
                    "unreachable",
                ]);
                p4 += 1;
            }
            if !has_v6 {
                ip6(&[
                    "rule",
                    "add",
                    "priority",
                    &p6.to_string(),
                    "type",
                    "unreachable",
                ]);
                p6 += 1;
            }
        }

        // 4. TUN 子网直接走 TUN 路由表
        for (ip_addr, prefix_len) in &addrs.inet4 {
            let net = v4_network(*ip_addr, *prefix_len);
            let dst = format!("{net}/{prefix_len}");
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "to",
                &dst,
                "lookup",
                &table,
            ]);
            p4 += 1;
        }
        for (ip_addr, prefix_len) in &addrs.inet6 {
            let net = v6_network(*ip_addr, *prefix_len);
            let dst = format!("{net}/{prefix_len}");
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "to",
                &dst,
                "lookup",
                &table,
            ]);
            p6 += 1;
        }

        // 5. suppress_prefixlength 0（与 sing-tun L811-816 对齐：无 iif 过滤）
        //    过滤默认路由，防止递归。sing-tun 这里**不带** `not iif lo`，
        //    让所有源（包括 lo）的默认路由都走 TUN 表。
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "lookup",
                &table,
                "suppress_prefixlength",
                "0",
            ]);
            p4 += 1;
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "lookup",
                &table,
                "suppress_prefixlength",
                "0",
            ]);
            p6 += 1;
        }

        // 6. DNS 劫持：not dport 53 → main 表 suppress_prefixlength 0
        //    （与 sing-tun L828-847 对齐）
        //    让非 53 端口的流量走 main 表的默认路由（即物理网卡），
        //    而 53 端口（DNS）继续走 TUN 表（被 TUN 劫持到本地 DNS）。
        //    注意：sing-tun 用 Invert=true 表示"非 dport 53"。
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "not",
                "dport",
                "53",
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
            ]);
            p4 += 1;
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "not",
                "dport",
                "53",
                "lookup",
                "main",
                "suppress_prefixlength",
                "0",
            ]);
            p6 += 1;
        }

        // 7. TUN 自身出站流量 → goto nop（避免环回）
        //    （与 sing-tun L849-855 对齐，放在 suppress_prefixlength 之后）
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "iif",
                if_name,
                "goto",
                &nop,
            ]);
            p4 += 1;
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "iif",
                if_name,
                "goto",
                &nop,
            ]);
            p6 += 1;
        }

        // 8. 非 loopback 出站 → TUN 表
        //    （与 sing-tun L857-864 对齐）
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "not",
                "iif",
                "lo",
                "lookup",
                &table,
            ]);
            // 注意：sing-tun 在 IPv4 这里**不**递增 priority（L883 注释 `// priority++`）
            // 但 reflex 的每条规则占一个槽位，所以仍递增以避免规则覆盖。
            p4 += 1;
            // iif lo src 0.0.0.0/32 → TUN 表（与 sing-tun L866-872 对齐）
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "iif",
                "lo",
                "from",
                "0.0.0.0/32",
                "lookup",
                &table,
            ]);
            p4 += 1;
            // iif lo src <tun_prefix> → TUN 表（与 sing-tun L874-882 对齐）
            for (ip_addr, prefix_len) in &addrs.inet4 {
                let net = v4_network(*ip_addr, *prefix_len);
                let src = format!("{net}/{prefix_len}");
                ip(&[
                    "rule",
                    "add",
                    "priority",
                    &p4.to_string(),
                    "iif",
                    "lo",
                    "from",
                    &src,
                    "lookup",
                    &table,
                ]);
                p4 += 1;
            }
        }
        if has_v6 {
            // IPv6：iif tun goto nop（sing-tun L885-890）
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "iif",
                if_name,
                "goto",
                &nop,
            ]);
            p6 += 1;
            // iif lo src ::/1 goto nop（sing-tun L892-898）
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "iif",
                "lo",
                "from",
                "::/1",
                "goto",
                &nop,
            ]);
            // iif lo src 8000::/1 goto nop（sing-tun L900-906）
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "iif",
                "lo",
                "from",
                "8000::/1",
                "goto",
                &nop,
            ]);
            p6 += 1;
            // iif lo src <tun_prefix> → TUN 表（sing-tun L910-917）
            for (ip_addr, prefix_len) in &addrs.inet6 {
                let net = v6_network(*ip_addr, *prefix_len);
                let src = format!("{net}/{prefix_len}");
                ip6(&[
                    "rule",
                    "add",
                    "priority",
                    &p6.to_string(),
                    "iif",
                    "lo",
                    "from",
                    &src,
                    "lookup",
                    &table,
                ]);
                p6 += 1;
            }
            // 最终 fallback：lookup table（sing-tun L921-925）
            ip6(&["rule", "add", "priority", &p6.to_string(), "lookup", &table]);
            p6 += 1;
        }

        // 9. nop 锚点（必须在所有业务规则之后）
        if has_v4 {
            ip(&["rule", "add", "priority", &nop]);
        }
        if has_v6 {
            ip6(&["rule", "add", "priority", &nop]);
        }

        // 将实际使用的优先级范围记录到文件，供 teardown 精确清理
        // 格式：p4_max p6_max nop_prio
        let state = format!("{} {} {}", p4, p6, nop_prio);
        let _ = std::fs::write(
            format!("/tmp/reflex-tun-{}.state", cfg.iproute2_table_index),
            state,
        );

        info!(interface = %if_name, table = %table, p4_used = p4 - prio_base, p6_used = p6 - prio_base, "tun: auto_route configured (Linux)");
        let _ = ip_check; // suppress unused warning
        Ok(())
    }

    pub fn teardown(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let table = cfg.iproute2_table_index.to_string();
        let prio_base = cfg.iproute2_rule_index;

        // 读取 setup 时记录的状态
        let state_file = format!("/tmp/reflex-tun-{}.state", cfg.iproute2_table_index);
        let (p4_max, p6_max, nop_prio) = if let Ok(s) = std::fs::read_to_string(&state_file) {
            let parts: Vec<u32> = s
                .split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect();
            if parts.len() == 3 {
                (parts[0], parts[1], parts[2])
            } else {
                // fallback：清理 prio_base 到 prio_base+120
                (prio_base + 120, prio_base + 120, prio_base + 100)
            }
        } else {
            (prio_base + 120, prio_base + 120, prio_base + 100)
        };
        let _ = std::fs::remove_file(&state_file);

        // 清除路由表
        ip(&["route", "flush", "table", &table]);
        ip6(&["route", "flush", "table", &table]);

        // 精确清理 IPv4 规则（从 prio_base 到 p4_max，加上 nop_prio）
        for prio in prio_base..=p4_max.max(nop_prio) {
            let ps = prio.to_string();
            for _ in 0..3 {
                ip(&["rule", "del", "priority", &ps]);
            }
        }

        // 精确清理 IPv6 规则
        for prio in prio_base..=p6_max.max(nop_prio) {
            let ps = prio.to_string();
            for _ in 0..3 {
                ip6(&["rule", "del", "priority", &ps]);
            }
        }

        info!(interface = %if_name, "tun: auto_route cleaned up (Linux)");
        Ok(())
    }
}

// ── macOS 实现 ────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::{parse_addr_prefix, TunInboundConfig};
    use std::net::IpAddr;
    use std::process::Command;
    use tracing::{info, warn};

    const IPV4_SUB_RANGES: &[&str] = &[
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ];
    const IPV6_SUB_RANGES: &[&str] = &[
        "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1",
    ];

    pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        if cfg.strict_route {
            warn!("tun: strict_route not supported on macOS");
        }
        if !cfg.include_interface.is_empty() || !cfg.exclude_interface.is_empty() {
            warn!("tun: include/exclude_interface not supported on macOS");
        }
        if !cfg.include_uid.is_empty() || !cfg.exclude_uid.is_empty() {
            warn!("tun: include/exclude_uid not supported on macOS");
        }

        let mut has_v4 = false;
        let mut has_v6 = false;
        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), _)) => {
                    Command::new("ifconfig")
                        .args([if_name, &ip.to_string(), &ip.to_string()])
                        .output()
                        .ok();
                    has_v4 = true;
                }
                Some((IpAddr::V6(ip), prefix_len)) => {
                    Command::new("ifconfig")
                        .args([
                            if_name,
                            "inet6",
                            &format!("{}/{}", ip, prefix_len),
                            "prefixlen",
                            &prefix_len.to_string(),
                            "alias",
                        ])
                        .output()
                        .ok();
                    has_v6 = true;
                }
                None => warn!(addr = %addr_str, "tun: invalid address prefix"),
            }
        }
        Command::new("ifconfig").args([if_name, "up"]).output().ok();

        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("route")
                    .args(["add", "-net", cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("route")
                    .args(["add", "-inet6", cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
        }
        Command::new("dscacheutil")
            .args(["-flushcache"])
            .output()
            .ok();
        info!(interface = %if_name, "tun: auto_route configured (macOS)");
        Ok(())
    }

    pub fn teardown(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let has_v4 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv4())
                .unwrap_or(false)
        });
        let has_v6 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv6())
                .unwrap_or(false)
        });

        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("route")
                    .args(["delete", "-net", cidr])
                    .output()
                    .ok();
            }
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("route")
                    .args(["delete", "-inet6", cidr])
                    .output()
                    .ok();
            }
        }
        Command::new("dscacheutil")
            .args(["-flushcache"])
            .output()
            .ok();
        info!(interface = %if_name, "tun: auto_route cleaned up (macOS)");
        Ok(())
    }
}

// ── Windows 实现 ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
mod platform {
    use super::{parse_addr_prefix, prefix_len_to_mask_v4, TunInboundConfig};
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
    use std::process::Command;
    use tokio::net::TcpListener;
    use tracing::{info, warn};

    // IPv4/IPv6 非默认路由段（与 sing-tun / clash-rs 一致）
    const IPV4_SUB_RANGES: &[&str] = &[
        "1.0.0.0/8",
        "2.0.0.0/7",
        "4.0.0.0/6",
        "8.0.0.0/5",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ];
    const IPV6_SUB_RANGES: &[&str] = &[
        "100::/8", "200::/7", "400::/6", "800::/5", "1000::/4", "2000::/3", "4000::/2", "8000::/1",
    ];

    // ── 接口名解析 ────────────────────────────────────────────────────────────

    /// 通过 PowerShell 查询适配器的真实名称。
    /// wintun 适配器由 device_guid 唯一标识，名称可能与配置值不同。
    /// 返回 PowerShell 查询到的实际名称；若查询失败则返回 expected 原值。
    pub fn resolve_actual_interface_name(expected: &str) -> String {
        // 先用期望名直接尝试（最常见情况，避免每次都启动 PowerShell）
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).Name",
                    expected
                ),
            ])
            .output();
        if let Ok(out) = out {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
        // 查不到则返回原值，后续 netsh 会输出具体错误
        warn!(expected = %expected, "tun: could not verify interface name via PowerShell, using configured name");
        expected.to_string()
    }

    /// 等待 Windows TUN 接口在系统中可见（wintun 创建后有延迟）。
    /// 返回实际可见的接口名（与 resolve_actual_interface_name 一致）。
    fn wait_for_interface(if_name: &str) {
        for _ in 0..30 {
            let out = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    &format!(
                        "(Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue).ifIndex",
                        if_name
                    ),
                ])
                .output()
                .ok();
            if let Some(out) = out {
                let s = String::from_utf8_lossy(&out.stdout);
                if s.trim().parse::<u32>().is_ok() {
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        warn!(interface = %if_name, "tun: interface not visible after 3s");
    }

    // ── 等待地址生效（修复 TCP Listener 绑定时序）────────────────────────────

    /// 等待 TUN 接口的 IPv4 地址真正可绑定。
    ///
    /// Windows 在 netsh 配置 IP 后仍需数百毫秒才将地址加入网卡。
    /// 参照 sing-tun 的 retryableListenError（WSAEADDRNOTAVAIL）重试策略。
    /// 最多等待 6 秒（30 × 200ms），超时后继续（bind 可能仍会失败，
    /// 届时上层有 3 次重试兜底）。
    pub async fn wait_for_tun_address(addr: Ipv4Addr) {
        for _ in 0u32..30 {
            match TcpListener::bind(SocketAddrV4::new(addr, 0)).await {
                Ok(_) => return, // 地址已可用，立即返回
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
            }
        }
        warn!(addr = %addr, "tun: address not ready after 6s, proceeding anyway");
    }

    // ── 获取当前进程可执行文件路径（用于防火墙规则自身豁免）────────────────

    fn current_exe_path() -> Option<String> {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
    }

    // ── setup / teardown ─────────────────────────────────────────────────────

    pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        if !cfg.include_interface.is_empty() || !cfg.exclude_interface.is_empty() {
            warn!("tun: include/exclude_interface not supported on Windows");
        }
        if !cfg.include_uid.is_empty() || !cfg.exclude_uid.is_empty() {
            warn!("tun: include/exclude_uid not supported on Windows");
        }

        // 等待适配器在系统中注册（wintun 创建后有短暂延迟）
        wait_for_interface(if_name);

        let mut has_v4 = false;
        let mut has_v6 = false;

        for addr_str in &cfg.address {
            match parse_addr_prefix(addr_str) {
                Some((IpAddr::V4(ip), prefix_len)) => {
                    let mask = prefix_len_to_mask_v4(prefix_len);
                    // 使用 netsh 配置 IP 地址（tun crate 在 Windows 上的 address() 无效）
                    let ok = Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "set",
                            "address",
                            "name",
                            if_name,
                            "static",
                            &ip.to_string(),
                            &mask.to_string(),
                        ])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    if !ok {
                        warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv4 address via netsh");
                    } else {
                        info!(interface = %if_name, ip = %ip, mask = %mask, "tun: IPv4 address configured");
                    }
                    has_v4 = true;
                }
                Some((IpAddr::V6(ip), prefix_len)) => {
                    let ok = Command::new("netsh")
                        .args([
                            "interface",
                            "ipv6",
                            "add",
                            "address",
                            if_name,
                            &format!("{}/{}", ip, prefix_len),
                        ])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    if !ok {
                        warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv6 address via netsh");
                    } else {
                        info!(interface = %if_name, ip = %ip, "tun: IPv6 address configured");
                    }
                    has_v6 = true;
                }
                None => warn!(addr = %addr_str, "tun: invalid address prefix"),
            }
        }

        // 添加路由（metric=1 优先于主路由表）
        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        cidr,
                        if_name,
                        "metric=1",
                    ])
                    .output()
                    .ok();
            }
            info!(interface = %if_name, "tun: IPv4 routes added");
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "add",
                        "route",
                        cidr,
                        if_name,
                        "metric=1",
                    ])
                    .output()
                    .ok();
            }
            info!(interface = %if_name, "tun: IPv6 routes added");
        }

        // strict_route：通过 Windows 防火墙实现。
        //
        // 与 sing-tun tun_windows.go Start() L183-362 对齐：
        //   1. 阻断所有非 reflex 进程对 53 端口（TCP+UDP）的出站连接（防 DNS 泄漏）。
        //      sing-tun 用 WFP FWPM_FILTER 阻断 53 端口；reflex 用 netsh advfirewall 等价实现。
        //   2. 若没有配置 IPv6 地址，阻断所有 IPv6 出站连接（防 IPv6 流量绕过 TUN）。
        //      sing-tun 用 WFP block filter 阻断 IPv6；reflex 用 netsh 等价实现。
        //
        // netsh advfirewall 的优先级由添加顺序决定（先匹配先执行），
        // 因此先添加 allow 规则（reflex 自身豁免），再添加 block 规则。
        if cfg.strict_route {
            // 清理旧规则
            for name in [
                "reflex-tun-strict-allow-udp",
                "reflex-tun-strict-allow-tcp",
                "reflex-tun-strict-block-udp",
                "reflex-tun-strict-block-tcp",
                "reflex-tun-strict-block-v6",
                // 兼容旧命名
                "reflex-tun-strict-allow",
                "reflex-tun-strict-block",
            ] {
                Command::new("netsh")
                    .args(["advfirewall", "firewall", "delete", "rule", &format!("name={name}")])
                    .output()
                    .ok();
            }

            // 规则1：允许 reflex 自身的 53 端口出站（UDP + TCP）
            if let Some(exe) = current_exe_path() {
                for proto in ["UDP", "TCP"] {
                    let ok = Command::new("netsh")
                        .args([
                            "advfirewall",
                            "firewall",
                            "add",
                            "rule",
                            &format!("name=reflex-tun-strict-allow-{}", proto.to_lowercase()),
                            &format!("protocol={proto}"),
                            "dir=out",
                            "remoteport=53",
                            "action=allow",
                            &format!("program={}", exe),
                        ])
                        .output()
                        .map(|o| o.status.success())
                        .unwrap_or(false);
                    if ok {
                        info!(exe = %exe, proto, "tun: strict_route self-allow rule added");
                    } else {
                        warn!(exe = %exe, proto, "tun: failed to add strict_route self-allow rule");
                    }
                }
            } else {
                warn!("tun: could not get current exe path, strict_route self-allow skipped");
            }

            // 规则2：阻断其他所有进程对 53 端口（UDP + TCP）的出站
            for proto in ["UDP", "TCP"] {
                Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        &format!("name=reflex-tun-strict-block-{}", proto.to_lowercase()),
                        &format!("protocol={proto}"),
                        "dir=out",
                        "remoteport=53",
                        "action=block",
                    ])
                    .output()
                    .ok();
            }
            info!("tun: strict_route DNS block rules added (Windows, UDP+TCP), reflex self exempted");

            // 规则3：若没有 IPv6 地址，阻断所有 IPv6 出站（与 sing-tun L270-282 对齐）。
            // sing-tun 通过 WFP FWPM_LAYER_ALE_AUTH_CONNECT_V6 block filter 实现；
            // reflex 用 netsh 阻断 IPv6 出站等价实现。
            if !has_v6 {
                Command::new("netsh")
                    .args([
                        "advfirewall",
                        "firewall",
                        "add",
                        "rule",
                        "name=reflex-tun-strict-block-v6",
                        "dir=out",
                        "action=block",
                        "remoteip=::/0",
                    ])
                    .output()
                    .ok();
                info!("tun: strict_route IPv6 block rule added (no IPv6 address configured)");
            }
        }

        // 刷新 DNS 缓存
        Command::new("ipconfig").args(["/flushdns"]).output().ok();
        info!(interface = %if_name, "tun: auto_route configured (Windows)");
        Ok(())
    }

    pub fn teardown(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        let has_v4 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv4())
                .unwrap_or(false)
        });
        let has_v6 = cfg.address.iter().any(|a| {
            parse_addr_prefix(a)
                .map(|(ip, _)| ip.is_ipv6())
                .unwrap_or(false)
        });

        if has_v4 {
            for &cidr in IPV4_SUB_RANGES {
                Command::new("netsh")
                    .args(["interface", "ipv4", "delete", "route", cidr, if_name])
                    .output()
                    .ok();
            }
        }
        if has_v6 {
            for &cidr in IPV6_SUB_RANGES {
                Command::new("netsh")
                    .args(["interface", "ipv6", "delete", "route", cidr, if_name])
                    .output()
                    .ok();
            }
        }
        if cfg.strict_route {
            for name in [
                "reflex-tun-strict-allow-udp",
                "reflex-tun-strict-allow-tcp",
                "reflex-tun-strict-block-udp",
                "reflex-tun-strict-block-tcp",
                "reflex-tun-strict-block-v6",
                // 兼容旧命名
                "reflex-tun-strict-allow",
                "reflex-tun-strict-block",
            ] {
                Command::new("netsh")
                    .args(["advfirewall", "firewall", "delete", "rule", &format!("name={name}")])
                    .output()
                    .ok();
            }
        }
        Command::new("ipconfig").args(["/flushdns"]).output().ok();
        info!(interface = %if_name, "tun: auto_route cleaned up (Windows)");
        Ok(())
    }
}

// ── 其他平台存根 ──────────────────────────────────────────────────────────────

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::TunInboundConfig;
    use tracing::warn;
    pub fn setup(_cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
        warn!(interface = %if_name, "tun: auto_route not supported on this platform");
        Ok(())
    }
    pub fn teardown(_cfg: &TunInboundConfig, _if_name: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

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
        assert!(port >= NAT_PORT_START && port <= NAT_PORT_END);
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
        assert!(port >= NAT_PORT_START && port <= NAT_PORT_END);
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
}
