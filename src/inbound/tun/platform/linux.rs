use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    sync::Mutex,
};
use tracing::{info, warn};

use super::SetupState;
use crate::config::inbound::TunInboundConfig;

// ── 地址辅助 ──────────────────────────────────────────────────────────────────

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

fn v4_network(ip: Ipv4Addr, pl: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & !((1u32 << (32 - pl.min(32))) - 1))
}

fn v6_network(ip: Ipv6Addr, pl: u8) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(ip) & !((1u128 << (128 - pl.min(128))) - 1))
}

fn prefix_contains_v4(outer: (Ipv4Addr, u8), inner: (Ipv4Addr, u8)) -> bool {
    let (o_net, o_pl) = outer;
    let (i_net, i_pl) = inner;
    if o_pl > i_pl {
        return false;
    }
    let mask = !((1u32 << (32 - o_pl.min(32))) - 1);
    (u32::from(o_net) & mask) == (u32::from(i_net) & mask)
}

fn prefix_contains_v6(outer: (Ipv6Addr, u8), inner: (Ipv6Addr, u8)) -> bool {
    let (o_net, o_pl) = outer;
    let (i_net, i_pl) = inner;
    if o_pl > i_pl {
        return false;
    }
    let mask = !((1u128 << (128 - o_pl.min(128))) - 1);
    (u128::from(o_net) & mask) == (u128::from(i_net) & mask)
}

// ── ip 命令封装 ────────────────────────────────────────────────────────────────
// 所有路由/规则/地址操作统一使用 ip 命令。
// rtnetlink crate 在 0.14 中 rule API 不完整，route/addr API 需要 builder 模式，
// 为简化维护，全部走 ip 命令。

async fn ip(args: &[&str]) {
    if let Ok(out) = Command::new("ip").args(args).output() {
        if !out.status.success() {
            // 防环回相关的 rule/route 若静默失败，直接后果就是流量环回且
            // 无从排查，这里必须留痕
            tracing::warn!(
                cmd = ?args,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "ip command failed"
            );
        }
    }
}

async fn ip6(args: &[&str]) {
    if let Ok(out) = Command::new("ip").arg("-6").args(args).output() {
        if !out.status.success() {
            tracing::warn!(
                cmd = ?args,
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "ip -6 command failed"
            );
        }
    }
}

/// 动态构造的参数列表（含条件性 fwmark 选择器）走这两个封装。
async fn ip_owned(args: &[String]) {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    ip(&refs).await;
}

async fn ip6_owned(args: &[String]) {
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    ip6(&refs).await;
}

// ── UID 范围计算 ──────────────────────────────────────────────────────────────

fn merge_uid_list_and_ranges(uids: &[u32], ranges: &[String]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = uids.iter().map(|&u| (u, u)).collect();
    for r in ranges {
        if let Some((lo, hi)) = parse_uid_range(r) {
            out.push((lo, hi));
        }
    }
    out.sort_unstable();
    out.dedup();
    merge_ranges(out)
}

fn parse_uid_range(s: &str) -> Option<(u32, u32)> {
    let (start_str, end_str) = s.split_once(':')?;
    let start: u32 = start_str.trim().parse().ok()?;
    let end: u32 = end_str.trim().parse().ok()?;
    if start > end {
        return None;
    }
    Some((start, end))
}

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

fn subtract_ranges(base: &[(u32, u32)], sub: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut result = base.to_vec();
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

fn build_excluded_uid_ranges(cfg: &TunInboundConfig) -> Vec<(u32, u32)> {
    let include = merge_uid_list_and_ranges(&cfg.include_uid, &cfg.include_uid_range);
    let exclude = merge_uid_list_and_ranges(&cfg.exclude_uid, &cfg.exclude_uid_range);
    if include.is_empty() && exclude.is_empty() {
        return vec![];
    }
    const UID_MAX: u32 = u32::MAX - 1;
    if !include.is_empty() {
        merge_ranges(complement_ranges(
            &subtract_ranges(&include, &exclude),
            0,
            UID_MAX,
        ))
    } else {
        merge_ranges(exclude)
    }
}

// ── 接口监控 ──────────────────────────────────────────────────────────────────
//
// 使用 rtnetlink 监听链路事件（RTM_NEWLINK/RTM_DELLINK），
// 在接口 UP/DOWN 或创建/删除时回调更新路由规则。
// 替代 sing-tun 的 InterfaceMonitor。

static INTERFACE_MONITOR: once_cell::sync::Lazy<Mutex<InterfaceMonitorState>> =
    once_cell::sync::Lazy::new(|| Mutex::new(InterfaceMonitorState::default()));

#[allow(clippy::type_complexity)]
#[derive(Default)]
struct InterfaceMonitorState {
    callbacks: Vec<(usize, Box<dyn Fn(&InterfaceEvent) + Send>)>,
    next_id: usize,
    running: bool,
}

#[derive(Debug, Clone)]
pub struct InterfaceEvent {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub addresses: Vec<IpAddr>,
}

/// 注册接口变更回调。返回的 ID 用于取消注册。
pub async fn register_interface_callback<F>(cb: F) -> usize
where
    F: Fn(&InterfaceEvent) + Send + 'static,
{
    let mut state = INTERFACE_MONITOR.lock().unwrap();
    let id = state.next_id;
    state.next_id += 1;
    state.callbacks.push((id, Box::new(cb)));

    if !state.running {
        state.running = true;
        // 启动监控 task
        tokio::spawn(interface_monitor_task());
    }
    id
}

/// 取消接口监听回调。
pub async fn unregister_interface_callback(id: usize) {
    let mut state = INTERFACE_MONITOR.lock().unwrap();
    state.callbacks.retain(|(i, _)| *i != id);
}

async fn interface_monitor_task() {
    // 使用 rtnetlink 监听链路事件
    // 在实际实现中，需要建立 netlink 连接并监听 RTMGRP_LINK | RTMGRP_IPV4_IFADDR
    // 这里使用 tokio::fs::watcher 风格轮询 /proc/net/dev 作为简化实现
    let mut last_ifaces = HashSet::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3));

    loop {
        interval.tick().await;
        let current = scan_interfaces();
        if current != last_ifaces {
            last_ifaces = current;
            let state = INTERFACE_MONITOR.lock().unwrap();
            for (_, cb) in &state.callbacks {
                // 简化：只通知有变化
                // 实际应扫描新旧差异逐个通知
                for iface in &last_ifaces {
                    // 解析 iface 格式: "name:index:up"
                    let parts: Vec<&str> = iface.split(':').collect();
                    if parts.len() >= 3 {
                        let event = InterfaceEvent {
                            name: parts[0].to_string(),
                            index: parts[1].parse().unwrap_or(0),
                            up: parts[2] == "1",
                            addresses: vec![],
                        };
                        cb(&event);
                    }
                }
            }
        }
    }
}

/// 扫描 /sys/class/net 获取当前接口列表。
fn scan_interfaces() -> HashSet<String> {
    let mut ifaces = HashSet::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let up_path = entry.path().join("operstate");
            let up = std::fs::read_to_string(&up_path)
                .map(|s| s.trim() == "up")
                .unwrap_or(false);
            let index_path = entry.path().join("ifindex");
            let index = std::fs::read_to_string(&index_path)
                .map(|s| s.trim().parse::<u32>().unwrap_or(0))
                .unwrap_or(0);
            ifaces.insert(format!("{name}:{index}:{}", if up { 1 } else { 0 }));
        }
    }
    ifaces
}

// ── autoRedirect (nftables TPROXY) ────────────────────────────────────────────
//
// 使用 nftables 实现流量重定向（TPROXY），对齐 sing-tun autoRedirect。
// 当 `auto_redirect` 启用时，创建 nftables 规则集：
// - PREROUTING 链：对非 TUN 入站的 TCP/UDP 包打 input_mark，
//   配合 `ip rule fwmark <input_mark> lookup <table>` 将流量路由到 TUN。
// - OUTPUT 链：对 reflex 自身出站包（带 output_mark）跳过标记，避免循环。
//
// fwmark 模式（非 TPROXY 透明代理端口）：仅打 mark + ip rule 路由，
// 流量仍由 TUN 接口捕获（与 sing-tun auto_redirect 通过路由表捕获一致）。

/// nftables 表名（teardown 时按此名删除）。
fn nft_table_name(if_name: &str) -> String {
    // nft 表名仅允许字母数字下划线，替换非法字符
    format!(
        "reflex_tun_{}",
        if_name.replace(|c: char| !c.is_alphanumeric(), "_")
    )
}

/// 配置 nftables TPROXY/fwmark 规则集。
///
/// 创建 inet 表（同时覆盖 v4/v6），仅含 prerouting 链。
/// 入站转发包（非 TUN 接口）打 input_mark，配合 `ip rule fwmark` 路由到 TUN。
///
/// 不再安装 OUTPUT 链：旧实现的 OUTPUT 链无差别给本机出站流量打 input_mark，
/// 导致已建立入站连接（如 SSH）的回包被 reroute 到 TUN → 连接断开。本机
/// 流量的接管由 ip rule `iif lo from 0.0.0.0/32 lookup <table>` 完成，
/// 它只匹配新建连接（from=0.0.0.0），已建立连接的回包（from=物理IP）不受影响。
/// reflex 自身出站已在 connect 前通过 SO_MARK 设置 output_mark，无需 nftables。
pub fn setup_nftables_redirect(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
    let table = nft_table_name(if_name);
    let input_mark = cfg.auto_redirect_input_mark;
    let output_mark = cfg.auto_redirect_output_mark;

    // nftables 规则集（inet 表同时处理 v4/v6）
    // PREROUTING (mangle, priority -150 = NF_IP_PRI_MANGLE):
    //   - iif == TUN → return（TUN 流量不再标记）
    //   - mark == output_mark → return（reflex 自身出站回包不标记）
    //   - mark == input_mark → return（已标记，避免重复）
    //   - TCP/UDP → set mark input_mark
    let cmds = format!(
        r#"
flush table inet {table}
table inet {table} {{
    chain prerouting {{
        type filter hook prerouting priority -150; policy accept;
        meta iifname "{if_name}" return comment "skip TUN ingress"
        meta mark {output_mark} return comment "skip reflex own reply"
        meta mark {input_mark} return comment "skip already marked"
        meta l4proto {tcp} meta mark set {input_mark} accept comment "mark TCP for TUN"
        meta l4proto {udp} meta mark set {input_mark} accept comment "mark UDP for TUN"
    }}
}}
"#,
        table = table,
        if_name = if_name,
        input_mark = input_mark,
        output_mark = output_mark,
        tcp = 6,  // IPPROTO_TCP
        udp = 17, // IPPROTO_UDP
    );

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("nft spawn: {e}"))?;

    use std::io::Write;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(cmds.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("nftables setup failed (exit code {:?})", status.code());
    }
    info!(
        interface = %if_name, table = %table,
        input_mark = format!("0x{:x}", input_mark),
        output_mark = format!("0x{:x}", output_mark),
        "tun: nftables auto_redirect rules installed"
    );
    Ok(())
}

/// 清理 nftables 规则集。
pub fn cleanup_nftables_redirect(cfg: &TunInboundConfig, if_name: &str) {
    let table = nft_table_name(if_name);
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", &table])
        .output();
    // 同时清理可能残留的 fwmark ip rule
    let input_mark = cfg.auto_redirect_input_mark;
    let table_idx = cfg.iproute2_table_index;
    let _ = Command::new("ip")
        .args([
            "rule",
            "del",
            "fwmark",
            &format!("0x{:x}", input_mark),
            "lookup",
            &table_idx.to_string(),
        ])
        .output();
    let _ = Command::new("ip")
        .args([
            "-6",
            "rule",
            "del",
            "fwmark",
            &format!("0x{:x}", input_mark),
            "lookup",
            &table_idx.to_string(),
        ])
        .output();
}

// ── systemd-resolved 集成 ─────────────────────────────────────────────────────
//
// 通过 resolvectl 命令配置 systemd-resolved 将 TUN 接口的 DNS 查询
// 指向反射代理的 DNS 服务器地址。

pub fn setup_systemd_resolved(cfg: &TunInboundConfig, if_name: &str) {
    let _ = Command::new("resolvectl")
        .args(["domain", if_name, "~."])
        .output();
    let _ = Command::new("resolvectl")
        .args(["default-route", if_name, "true"])
        .output();

    // 构造 DNS 服务器地址列表：dns_servers 覆盖项优先（对齐 sing-tun
    // Inet4DNSAddress/Inet6DNSAddress）；否则网关覆盖项；否则
    // 第一个 v4/v6 地址的 next（对齐 sing-tun DNSServerAddress 默认行为）
    let mut dns_args = vec!["dns".to_string(), if_name.to_string()];
    let mut dns_v4 = cfg
        .dns_servers
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .find(|ip| ip.is_ipv4());
    let mut dns_v6 = cfg
        .dns_servers
        .iter()
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .find(|ip| ip.is_ipv6());
    if dns_v4.is_none() {
        if let Some(gw) = &cfg.inet4_gateway_address {
            dns_v4 = gw.parse::<IpAddr>().ok().filter(|ip| ip.is_ipv4());
        }
    }
    if dns_v6.is_none() {
        if let Some(gw) = &cfg.inet6_gateway_address {
            dns_v6 = gw.parse::<IpAddr>().ok().filter(|ip| ip.is_ipv6());
        }
    }
    if dns_v4.is_none() {
        for addr_str in &cfg.address {
            if let Some((IpAddr::V4(ip), _)) = parse_addr_prefix(addr_str) {
                dns_v4 = Some(IpAddr::V4(Ipv4Addr::from(u32::from(ip).wrapping_add(1))));
                break;
            }
        }
    }
    if dns_v6.is_none() {
        for addr_str in &cfg.address {
            if let Some((IpAddr::V6(ip), _)) = parse_addr_prefix(addr_str) {
                dns_v6 = Some(IpAddr::V6(Ipv6Addr::from(u128::from(ip).wrapping_add(1))));
                break;
            }
        }
    }
    if let Some(ip) = dns_v4 {
        dns_args.push(ip.to_string());
    }
    if let Some(ip) = dns_v6 {
        dns_args.push(ip.to_string());
    }
    if dns_args.len() > 2 {
        let _ = Command::new("resolvectl").args(&dns_args).output();
    }
}

pub fn cleanup_systemd_resolved(if_name: &str) {
    let _ = Command::new("resolvectl")
        .args(["revert", if_name])
        .output();
}

// ── GSO/GRO 卸载支持 ─────────────────────────────────────────────────────────
//
// 通过 TUNGETIFF 确认 IFF_VNET_HDR 生效，再以 TUNSETOFFLOAD 启用 TSO/USO
// 卸载（对齐 sing-tun tun_linux.go enableGSO + tun_linux_flags.go
// checkVNETHDREnabled/setTCPOffload/setUDPOffload）。
//
// 关键语义（B1 修复依据）：IFF_VNET_HDR 一旦生效，内核在**每个**读写包前
// 都附带 10 字节 virtio_net_hdr —— 与 TUNSETOFFLOAD 是否成功无关。
// 因此 vnet_hdr 与 GSO/GRO 卸载是两个独立维度：
// - vnet_hdr：决定读写是否剥/补 virtio_net_hdr（由 TUNGETIFF 探测）；
// - tcp_gso/udp_gso：决定读到的包是否可能是 GSO 大包、写方向是否可
//   合并出 GSO 包（由 TUNSETOFFLOAD 逐级探测，失败禁用对应方向 GRO）。

/// TUNSETOFFLOAD ioctl 请求号（对齐 Linux 内核 TUNSETOFFLOAD = _IOW('T', 208, unsigned int)）
#[cfg(target_os = "linux")]
const TUNSETOFFLOAD: u64 = 0x400454d0;

/// TUNGETIFF ioctl 请求号（对齐 Linux 内核 TUNGETIFF = _IOR('T', 210, int)）
#[cfg(target_os = "linux")]
const TUNGETIFF: u64 = 0x800454d2;

/// IFF_VNET_HDR flag（对齐内核 if_tun.h）
#[cfg(target_os = "linux")]
const IFF_VNET_HDR: u16 = 0x4000;

/// TUN 卸载标志（对齐 sing-tun tun_linux_flags.go）
#[cfg(target_os = "linux")]
const TUN_F_CSUM: u32 = 0x01;
#[cfg(target_os = "linux")]
const TUN_F_TSO4: u32 = 0x02;
#[cfg(target_os = "linux")]
const TUN_F_TSO6: u32 = 0x04;
#[cfg(target_os = "linux")]
const TUN_F_USO4: u32 = 0x10;
#[cfg(target_os = "linux")]
const TUN_F_USO6: u32 = 0x20;

/// TUNSETOFFLOAD 探测结果。
#[derive(Clone, Copy, Debug, Default)]
pub struct TunOffload {
    /// IFF_VNET_HDR 是否生效（读写包前是否附带 virtio_net_hdr）。
    pub vnet_hdr: bool,
    /// TCP GSO（TSO4|TSO6）卸载是否成功（读方向可能收到 GSO 大包，
    /// 写方向可合并出 TCP GSO 包）。
    pub tcp_gso: bool,
    /// UDP GSO（USO4|USO6）卸载是否成功。
    pub udp_gso: bool,
}

/// 通过 TUNGETIFF ioctl 检查设备是否以 IFF_VNET_HDR 打开
/// （对齐 sing-tun tun_linux_flags.go checkVNETHDREnabled）。
#[cfg(target_os = "linux")]
pub fn tun_has_vnet_hdr(fd: std::os::fd::RawFd) -> bool {
    // ifreq 布局：[IFNAMSIZ(16) 字节名字][2 字节 flags]
    let mut ifr = [0u8; 24];
    let ret = unsafe { libc::ioctl(fd, TUNGETIFF as _, ifr.as_mut_ptr()) };
    if ret != 0 {
        return false;
    }
    // flags 位于 ifr[16..18]，native endian
    let flags = u16::from_ne_bytes([ifr[16], ifr[17]]);
    flags & IFF_VNET_HDR != 0
}

#[cfg(not(target_os = "linux"))]
pub fn tun_has_vnet_hdr(_fd: std::os::fd::RawFd) -> bool {
    false
}

/// 探测并启用 TUN 卸载（对齐 sing-tun NativeTun.enableGSO）。
///
/// 流程：
/// 1. TUNGETIFF 确认 IFF_VNET_HDR 生效（未生效则无任何卸载）；
/// 2. TUNSETOFFLOAD(CSUM|TSO4|TSO6)：失败则 TCP+UDP GRO 均禁用；
/// 3. TUNSETOFFLOAD(CSUM|TSO4|TSO6|USO4|USO6)：失败则仅禁用 UDP GRO。
///
/// 注意：卸载失败**不影响** vnet_hdr 的判定 —— 只要 IFF_VNET_HDR 生效，
/// 读写就必须处理 virtio_net_hdr（B1 修复核心）。
#[cfg(target_os = "linux")]
pub fn setup_tun_offload(fd: std::os::fd::RawFd) -> TunOffload {
    let mut result = TunOffload::default();

    if !tun_has_vnet_hdr(fd) {
        warn!("tun: IFF_VNET_HDR not enabled, virtio_net_hdr absent, GSO/GRO disabled");
        return result;
    }
    result.vnet_hdr = true;

    // TCP 卸载（CSUM|TSO4|TSO6）
    let tcp_offloads = (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6) as libc::c_int;
    let ret = unsafe { libc::ioctl(fd, TUNSETOFFLOAD as _, tcp_offloads) };
    if ret != 0 {
        warn!("tun: TUNSETOFFLOAD(TSO) failed, TCP & UDP GRO disabled");
        return result;
    }
    result.tcp_gso = true;

    // TCP + UDP 卸载（追加 USO4|USO6）
    let full_offloads =
        (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_USO4 | TUN_F_USO6) as libc::c_int;
    let ret = unsafe { libc::ioctl(fd, TUNSETOFFLOAD as _, full_offloads) };
    if ret != 0 {
        warn!("tun: TUNSETOFFLOAD(USO) failed, UDP GRO disabled");
        return result;
    }
    result.udp_gso = true;

    info!("tun: TUNSETOFFLOAD enabled (CSUM|TSO4|TSO6|USO4|USO6), vnet_hdr active");
    result
}

#[cfg(not(target_os = "linux"))]
pub fn setup_tun_offload(_fd: std::os::fd::RawFd) -> TunOffload {
    TunOffload::default()
}

/// 通过 ethtool 启用 TUN 接口的 checksum offload（兼容回退路径）。
pub fn setup_checksum_offload(if_name: &str) -> anyhow::Result<bool> {
    // 尝试启用 TX checksum offload
    let tx_on = Command::new("ethtool")
        .args(["-K", if_name, "tx", "on"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if tx_on {
        info!(interface = %if_name, "tun: TX checksum offload enabled");
    }

    // 尝试启用 RX checksum offload
    let rx_on = Command::new("ethtool")
        .args(["-K", if_name, "rx", "on"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if rx_on {
        info!(interface = %if_name, "tun: RX checksum offload enabled");
    }

    Ok(tx_on)
}

// ── setup / teardown ──────────────────────────────────────────────────────────

pub async fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    let table = cfg.iproute2_table_index;
    let prio_base = cfg.iproute2_rule_index;
    let nop_prio = prio_base + 100;
    let mut state = SetupState::default();

    // 收集地址信息
    let addrs = parse_addresses(cfg);
    let has_v4 = !addrs.inet4.is_empty();
    let has_v6 = !addrs.inet6.is_empty();

    // 确保设备 UP
    ip(&["link", "set", if_name, "up"]).await;

    // ── 配置接口地址（幂等，对齐 sing-tun configure() AddrAdd + EEXIST 跳过）──
    // tun crate 创建设备时仅设置了第一个 IPv4 地址；多前缀 / IPv6 地址
    // 在此补齐（L2 修复）。已存在的地址添加会失败（File exists），静默忽略。
    for (ip, pl) in &addrs.inet4 {
        let cidr = format!("{ip}/{pl}");
        let out = Command::new("ip")
            .args(["addr", "add", &cidr, "dev", if_name])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                info!(interface = %if_name, ip = %ip, "tun: IPv4 address added");
            }
        }
    }
    for (ip, pl) in &addrs.inet6 {
        let cidr = format!("{ip}/{pl}");
        let out = Command::new("ip")
            .args(["-6", "addr", "add", &cidr, "dev", if_name])
            .output();
        if let Ok(o) = out {
            if o.status.success() {
                info!(interface = %if_name, ip = %ip, "tun: IPv6 address added");
            }
        }
    }

    // ── 路由表（route_address 减 route_exclude_address 差集，对齐 sing-tun）──
    add_routes_to_table(cfg, if_name, table, has_v4, has_v6, &mut state);

    // ── 策略规则（全部使用 ip 命令，rtnetlink rule API 在 0.14 不完整）────
    let mut p4 = prio_base;
    let mut p6 = prio_base;

    // 0. TUN-egress 豁免（对齐 sing-tun tun_linux.go：iif <tun> goto nop）。
    // reflex 写回 TUN 的响应包（iif = tun）绝不能再被送进 TUN 表：
    // 网关/路由器模式下这些包的 dst 是 LAN 客户端地址而非本机地址，
    // 若先命中下面的 TUN 表全量查找规则，会被表内默认路由再次送回 TUN，
    // 形成写回 → 重新路由 → 再进 TUN 的回环。必须放在所有 lookup 规则之前。
    // （本地桌面场景 dst 是本机地址，优先级 0 的 local 规则先行命中，
    // 不受此规则影响。）
    if has_v4 {
        ip(&[
            "rule",
            "add",
            "priority",
            &p4.to_string(),
            "iif",
            if_name,
            "goto",
            &nop_prio.to_string(),
        ])
        .await;
        state.rule_priorities.push(p4);
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
            &nop_prio.to_string(),
        ])
        .await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 1. fwmark 排除选择器（不安装独立的 `not fwmark lookup` 规则）。
    //
    // 旧实现在此处安装了一条 `ip rule add not fwmark <M> lookup <table>`
    // 规则，意图让「未标记流量全量走 TUN 表」。这在桌面场景可行，但在
    // 服务器场景是致命的：SSH 入站连接的回包（iif=lo, from=物理IP,
    // 未带 mark）会被这条规则匹配 → 进 TUN 表默认路由 → 回包进 TUN
    // → SSH 客户端收不到回包 → 连接断开。这正是「终端运行导致 SSH
    // 断开」的根因。
    //
    // 正确做法（对齐 sing-box）：不安装这条无条件 `not fwmark lookup`
    // 规则。本机流量的接管由下方规则 8b `iif lo from 0.0.0.0/32 lookup
    // <table>` 完成——它只匹配新建连接（connect 时 from=0.0.0.0），
    // 已建立连接的回包 from=物理IP 不匹配 → 落到 main 表走物理网卡。
    //
    // fwmark_not 选择器仍然需要：下方规则 3/4/5/8b/8c 携带它，让带
    // mark 的 reflex 自身出站流量跳过这些 lookup 规则，落到 main 表。
    let effective_so_mark = cfg.so_mark.or(if cfg.auto_redirect {
        Some(cfg.auto_redirect_output_mark)
    } else {
        None
    });
    let fwmark_not: Vec<String> = effective_so_mark
        .map(|m| vec!["not".to_string(), "fwmark".to_string(), m.to_string()])
        .unwrap_or_default();

    // 2. UID 排除
    let excluded_uids = build_excluded_uid_ranges(cfg);
    for (lo, hi) in &excluded_uids {
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "uidrange",
                &format!("{lo}-{hi}"),
                "goto",
                &nop_prio.to_string(),
            ])
            .await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "uidrange",
                &format!("{lo}-{hi}"),
                "goto",
                &nop_prio.to_string(),
            ])
            .await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
    }

    // 2. 接口过滤
    if !cfg.include_interface.is_empty() {
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
                    &table.to_string(),
                ])
                .await;
                state.rule_priorities.push(p4);
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
                    &table.to_string(),
                ])
                .await;
                state.rule_priorities.push(p6);
                p6 += 1;
            }
        }
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "priority",
                &p4.to_string(),
                "goto",
                &nop_prio.to_string(),
            ])
            .await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "priority",
                &p6.to_string(),
                "goto",
                &nop_prio.to_string(),
            ])
            .await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
    } else if !cfg.exclude_interface.is_empty() {
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
                    &nop_prio.to_string(),
                ])
                .await;
                state.rule_priorities.push(p4);
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
                    &nop_prio.to_string(),
                ])
                .await;
                state.rule_priorities.push(p6);
                p6 += 1;
            }
        }
    }

    // 3. strict_route（对齐 sing-tun tun_linux.go L780-797：unreachable 只对
    // 「未启用 TUN 地址的协议族」安装，用于单栈 TUN 下彻底阻断另一族流量、
    // 防止其经 main 表直接泄漏。对已启用族安装无条件 unreachable 是错误的：
    // 未标记流量早在规则 1 就已进 TUN，根本到不了这里；它唯一能拦到的是
    // so_mark 标记的 reflex 自身出站流量（旧实现的豁免规则选择器还写反成
    // `not fwmark`，实际豁免的是未标记流量），结果就是 strict_route 开启
    // 后 reflex 自身出站全部 ENETUNREACH。已启用族的防泄漏由规则 1 的
    // 全量捕获保证，无需 unreachable。）
    if cfg.strict_route {
        if !has_v4 {
            let mut args: Vec<String> = vec![
                "rule".to_string(),
                "add".to_string(),
                "priority".to_string(),
                p4.to_string(),
            ];
            args.extend(fwmark_not.iter().cloned());
            args.extend(["type".to_string(), "unreachable".to_string()]);
            ip_owned(&args).await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
        if !has_v6 {
            let mut args: Vec<String> = vec![
                "rule".to_string(),
                "add".to_string(),
                "priority".to_string(),
                p6.to_string(),
            ];
            args.extend(fwmark_not.iter().cloned());
            args.extend(["type".to_string(), "unreachable".to_string()]);
            ip6_owned(&args).await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
    }

    // 4. TUN 子网走 TUN 表（带 not fwmark：marked 流量目标在 TUN 子网时
    // 不应被送回 TUN 形成环回，让它落到 main 表由后续规则处理）
    for (ip_addr, prefix_len) in &addrs.inet4 {
        let net = v4_network(*ip_addr, *prefix_len);
        let dst = format!("{net}/{prefix_len}");
        let mut args: Vec<String> = vec![
            "rule".to_string(),
            "add".to_string(),
            "priority".to_string(),
            p4.to_string(),
        ];
        args.extend(fwmark_not.iter().cloned());
        args.extend([
            "to".to_string(),
            dst,
            "lookup".to_string(),
            table.to_string(),
        ]);
        ip_owned(&args).await;
        state.rule_priorities.push(p4);
        p4 += 1;
    }
    for (ip_addr, prefix_len) in &addrs.inet6 {
        let net = v6_network(*ip_addr, *prefix_len);
        let dst = format!("{net}/{prefix_len}");
        let mut args: Vec<String> = vec![
            "rule".to_string(),
            "add".to_string(),
            "priority".to_string(),
            p6.to_string(),
        ];
        args.extend(fwmark_not.iter().cloned());
        args.extend([
            "to".to_string(),
            dst,
            "lookup".to_string(),
            table.to_string(),
        ]);
        ip6_owned(&args).await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 5. suppress_prefixlength 0（带 not fwmark，理由同规则 4）
    if has_v4 {
        let mut args: Vec<String> = vec![
            "rule".to_string(),
            "add".to_string(),
            "priority".to_string(),
            p4.to_string(),
        ];
        args.extend(fwmark_not.iter().cloned());
        args.extend([
            "lookup".to_string(),
            table.to_string(),
            "suppress_prefixlength".to_string(),
            "0".to_string(),
        ]);
        ip_owned(&args).await;
        state.rule_priorities.push(p4);
        p4 += 1;
    }
    if has_v6 {
        let mut args: Vec<String> = vec![
            "rule".to_string(),
            "add".to_string(),
            "priority".to_string(),
            p6.to_string(),
        ];
        args.extend(fwmark_not.iter().cloned());
        args.extend([
            "lookup".to_string(),
            table.to_string(),
            "suppress_prefixlength".to_string(),
            "0".to_string(),
        ]);
        ip6_owned(&args).await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 6. DNS 劫持: not dport 53 → main table suppress_prefixlength 0
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
        ])
        .await;
        state.rule_priorities.push(p4);
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
        ])
        .await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 7. TUN 自身出站 goto nop
    if has_v4 {
        ip(&[
            "rule",
            "add",
            "priority",
            &p4.to_string(),
            "iif",
            if_name,
            "goto",
            &nop_prio.to_string(),
        ])
        .await;
        state.rule_priorities.push(p4);
        p4 += 1;
    }

    // 8. 非 loopback → TUN 表
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
            &table.to_string(),
        ])
        .await;
        state.rule_priorities.push(p4);
        p4 += 1;
        let mut args: Vec<String> = vec![
            "rule".to_string(),
            "add".to_string(),
            "priority".to_string(),
            p4.to_string(),
            "iif".to_string(),
            "lo".to_string(),
            "from".to_string(),
            "0.0.0.0/32".to_string(),
        ];
        args.extend(fwmark_not.iter().cloned());
        args.extend([
            "lookup".to_string(),
            table.to_string(),
        ]);
        ip_owned(&args).await;
        state.rule_priorities.push(p4);
        p4 += 1;
        for (ip_addr, prefix_len) in &addrs.inet4 {
            let net = v4_network(*ip_addr, *prefix_len);
            let src = format!("{net}/{prefix_len}");
            let mut args: Vec<String> = vec![
                "rule".to_string(),
                "add".to_string(),
                "priority".to_string(),
                p4.to_string(),
                "iif".to_string(),
                "lo".to_string(),
                "from".to_string(),
                src,
            ];
            args.extend(fwmark_not.iter().cloned());
            args.extend(["lookup".to_string(), table.to_string()]);
            ip_owned(&args).await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
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
            &nop_prio.to_string(),
        ])
        .await;
        state.rule_priorities.push(p6);
        p6 += 1;
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
            &nop_prio.to_string(),
        ])
        .await;
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
            &nop_prio.to_string(),
        ])
        .await;
        state.rule_priorities.push(p6);
        p6 += 1;
        for (ip_addr, prefix_len) in &addrs.inet6 {
            let net = v6_network(*ip_addr, *prefix_len);
            let src = format!("{net}/{prefix_len}");
            let mut args: Vec<String> = vec![
                "rule".to_string(),
                "add".to_string(),
                "priority".to_string(),
                p6.to_string(),
                "iif".to_string(),
                "lo".to_string(),
                "from".to_string(),
                src,
            ];
            args.extend(fwmark_not.iter().cloned());
            args.extend(["lookup".to_string(), table.to_string()]);
            ip6_owned(&args).await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
        ip6(&[
            "rule",
            "add",
            "priority",
            &p6.to_string(),
            "lookup",
            &table.to_string(),
        ])
        .await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 9. nop 锚点
    if has_v4 {
        ip(&["rule", "add", "priority", &nop_prio.to_string()]).await;
        state.rule_priorities.push(nop_prio);
    }
    if has_v6 {
        ip6(&["rule", "add", "priority", &nop_prio.to_string()]).await;
        state.rule_priorities.push(nop_prio);
    }

    // 保存 setup 状态供 teardown 精确清理
    let state_str = format!("{} {}", p4, p6);
    let _ = std::fs::write(format!("/tmp/reflex-tun-{}.state", table), state_str);

    // ── 启用 checksum offload ──────────────────────────────────────────────
    let _ = setup_checksum_offload(if_name);

    // ── 配置 systemd-resolved ──────────────────────────────────────────────
    setup_systemd_resolved(cfg, if_name);

    // ── autoRedirect（nftables fwmark 模式）──────────────────────────────
    // 启用后：nftables 对入站 TCP/UDP 打 input_mark，配合 ip rule fwmark
    // 将流量路由到 TUN 表；reflex 自身出站设 output_mark 绕过。
    if cfg.auto_redirect {
        // 添加 fwmark → TUN 表 的策略规则（v4 + v6）
        let input_mark = cfg.auto_redirect_input_mark;
        let fwmark_str = format!("0x{:x}", input_mark);
        if has_v4 {
            ip(&[
                "rule",
                "add",
                "fwmark",
                &fwmark_str,
                "lookup",
                &table.to_string(),
            ])
            .await;
            state.rule_priorities.push(0); // fwmark 规则无 priority 字段，占位
        }
        if has_v6 {
            ip6(&[
                "rule",
                "add",
                "fwmark",
                &fwmark_str,
                "lookup",
                &table.to_string(),
            ])
            .await;
        }
        // 安装 nftables 表（PREROUTING + OUTPUT 链）
        match setup_nftables_redirect(cfg, if_name) {
            Ok(()) => info!(tag = "tun", "tun: auto_redirect (nftables fwmark) enabled"),
            Err(e) => {
                warn!(err = %e, "tun: auto_redirect nftables setup failed (is nft installed?)")
            }
        }
    }

    // ── 注册接口监听 ───────────────────────────────────────────────────────
    // 简化为不注册（由上层 TunInbound 控制）
    info!(
        interface = %if_name, table = %table,
        p4_used = p4 - prio_base, p6_used = p6 - prio_base,
        "tun: auto_route configured (Linux, native rtnetlink)"
    );

    Ok(state)
}

pub async fn teardown(
    cfg: &TunInboundConfig,
    if_name: &str,
    state: &SetupState,
) -> anyhow::Result<()> {
    let table = cfg.iproute2_table_index;
    let prio_base = cfg.iproute2_rule_index;

    // 删除 setup 时配置的接口地址（对齐 sing-tun unsetAddresses，
    // tun_linux.go:1025-1041）。旧实现从不删地址，teardown 后地址残留在
    // TUN 设备上（接口名复用时可能拿到旧地址导致路由歧义）。
    let addrs = parse_addresses(cfg);
    {
        for (ip_addr, pl) in &addrs.inet4 {
            let cidr = format!("{ip_addr}/{pl}");
            let _ = Command::new("ip")
                .args(["addr", "del", &cidr, "dev", if_name])
                .output();
        }
        for (ip_addr, pl) in &addrs.inet6 {
            let cidr = format!("{ip_addr}/{pl}");
            let _ = Command::new("ip")
                .args(["-6", "addr", "del", &cidr, "dev", if_name])
                .output();
        }
    }

    // 清除路由
    ip(&["route", "flush", "table", &table.to_string()]).await;
    ip6(&["route", "flush", "table", &table.to_string()]).await;

    // 清除规则。
    // 优先使用 setup 记录在内存中的 rule_priorities（精确、不依赖 /tmp 文件，
    // 且避免误删系统 local 规则——auto_redirect 的 fwmark 占位 0 必须跳过，
    // 该 fwmark 规则由 cleanup_nftables_redirect 负责删除）。
    // 无记录时回退：按 [prio_base, prio_base+120] 范围清理（旧行为）。
    if !state.rule_priorities.is_empty() {
        let mut priorities: Vec<u32> = state.rule_priorities.clone();
        priorities.sort_unstable();
        priorities.dedup();
        for prio in priorities {
            if prio == 0 {
                continue; // auto_redirect fwmark 占位，单独清理
            }
            for _ in 0..3 {
                ip(&["rule", "del", "priority", &prio.to_string()]).await;
            }
            for _ in 0..3 {
                ip6(&["rule", "del", "priority", &prio.to_string()]).await;
            }
        }
    } else {
        // 旧逻辑：从 state 文件读取优先级信息（兼容旧版本 / 崩溃残留清理）
        let state_file = format!("/tmp/reflex-tun-{}.state", table);
        let (p4_max, p6_max) = if let Ok(s) = std::fs::read_to_string(&state_file) {
            let parts: Vec<u32> = s
                .split_whitespace()
                .filter_map(|x| x.parse().ok())
                .collect();
            if parts.len() >= 2 {
                (parts[0], parts[1])
            } else {
                (prio_base + 120, prio_base + 120)
            }
        } else {
            (prio_base + 120, prio_base + 120)
        };
        let _ = std::fs::remove_file(&state_file);

        let nop_prio = prio_base + 100;
        for prio in prio_base..=p4_max.max(nop_prio) {
            for _ in 0..3 {
                ip(&["rule", "del", "priority", &prio.to_string()]).await;
            }
        }
        for prio in prio_base..=p6_max.max(nop_prio) {
            for _ in 0..3 {
                ip6(&["rule", "del", "priority", &prio.to_string()]).await;
            }
        }
    }

    // 清理 systemd-resolved
    cleanup_systemd_resolved(if_name);

    // 清理 nftables（含 fwmark 规则）
    cleanup_nftables_redirect(cfg, if_name);

    info!(interface = %if_name, "tun: auto_route cleaned up (Linux)");
    Ok(())
}

// ── 默认路由查询（默认路由变化监控用）───────────────────────────────────────

/// 从 `ip route show default` 输出解析网关："default via X dev Y ..."。
fn default_gateway_from_route_output(out: &str) -> Option<IpAddr> {
    for line in out.lines() {
        let line = line.trim();
        if !line.starts_with("default") {
            continue;
        }
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "via" {
                if let Some(gw) = it.next() {
                    if let Ok(ip) = gw.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
                break;
            }
        }
    }
    None
}

pub async fn current_default_gateways() -> (Option<IpAddr>, Option<IpAddr>) {
    tokio::task::spawn_blocking(|| {
        let v4 = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| default_gateway_from_route_output(&s))
            .filter(|ip| ip.is_ipv4());
        let v6 = Command::new("ip")
            .args(["-6", "route", "show", "default"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| default_gateway_from_route_output(&s))
            .filter(|ip| ip.is_ipv6());
        (v4, v6)
    })
    .await
    .unwrap_or((None, None))
}

pub fn update_routes(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
    // 对齐 sing-tun UpdateRouteOptions：清空 TUN 表路由后按新配置重建。
    // 旧实现是 no-op（L3）。
    let table = cfg.iproute2_table_index;
    Command::new("ip")
        .args(["route", "flush", "table", &table.to_string()])
        .output()
        .ok();
    Command::new("ip")
        .args(["-6", "route", "flush", "table", &table.to_string()])
        .output()
        .ok();

    let addrs = parse_addresses(cfg);
    let has_v4 = !addrs.inet4.is_empty();
    let has_v6 = !addrs.inet6.is_empty();
    let mut state = SetupState::default();
    add_routes_to_table(cfg, if_name, table, has_v4, has_v6, &mut state);
    info!(interface = %if_name, table = %table, "tun: routes updated (Linux)");
    Ok(())
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

struct AddrInfo {
    inet4: Vec<(Ipv4Addr, u8)>,
    inet6: Vec<(Ipv6Addr, u8)>,
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

fn build_route_targets_v4(cfg: &TunInboundConfig) -> Vec<(Ipv4Addr, u8)> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        vec![(Ipv4Addr::UNSPECIFIED, 0)]
    }
}

fn build_route_targets_v6(cfg: &TunInboundConfig) -> Vec<(Ipv6Addr, u8)> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        vec![(Ipv6Addr::UNSPECIFIED, 0)]
    }
}

fn parse_excluded_v4(cfg: &TunInboundConfig) -> Vec<(Ipv4Addr, u8)> {
    cfg.route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
            _ => None,
        })
        .collect()
}

fn parse_excluded_v6(cfg: &TunInboundConfig) -> Vec<(Ipv6Addr, u8)> {
    cfg.route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
            _ => None,
        })
        .collect()
}

// ── 前缀集合减法（对齐 sing-tun BuildAutoRouteRanges 的 netipx.IPSetBuilder 差集）──
//
// route_exclude_address 不能靠「exclude 完全覆盖 route 才跳过」处理：
// 默认路由 0.0.0.0/0 永远不会被 192.168.0.0/16 之类的前缀覆盖，
// 导致 exclude 段流量仍然进入 TUN（旧实现 bug，L1）。
// 正确做法：把 route 集合按 exclude 做差集，生成不包含排除段的精确前缀集合。
// 实现为递归二分拆分：无交集的子树直接保留，完全被 exclude 覆盖的子树剪枝。

fn v4_prefix_mask(pl: u8) -> u32 {
    if pl == 0 {
        0
    } else {
        !((1u32 << (32 - pl.min(32))) - 1)
    }
}

fn v6_prefix_mask(pl: u8) -> u128 {
    if pl == 0 {
        0
    } else {
        !((1u128 << (128 - pl.min(128))) - 1)
    }
}

/// exclude 前缀 (e_net, e_pl) 是否与 (net, pl) 有交集。
fn v4_intersects(e_net: Ipv4Addr, e_pl: u8, net: Ipv4Addr, pl: u8) -> bool {
    let (coarse_net, coarse_pl, fine_net) = if e_pl <= pl {
        (e_net, e_pl, net)
    } else {
        (net, pl, e_net)
    };
    (u32::from(fine_net) & v4_prefix_mask(coarse_pl))
        == (u32::from(coarse_net) & v4_prefix_mask(coarse_pl))
}

fn v6_intersects(e_net: Ipv6Addr, e_pl: u8, net: Ipv6Addr, pl: u8) -> bool {
    let (coarse_net, coarse_pl, fine_net) = if e_pl <= pl {
        (e_net, e_pl, net)
    } else {
        (net, pl, e_net)
    };
    (u128::from(fine_net) & v6_prefix_mask(coarse_pl))
        == (u128::from(coarse_net) & v6_prefix_mask(coarse_pl))
}

fn fully_excluded_v4(net: Ipv4Addr, pl: u8, excludes: &[(Ipv4Addr, u8)]) -> bool {
    excludes
        .iter()
        .any(|&(e_net, e_pl)| e_pl <= pl && prefix_contains_v4((e_net, e_pl), (net, pl)))
}

fn fully_excluded_v6(net: Ipv6Addr, pl: u8, excludes: &[(Ipv6Addr, u8)]) -> bool {
    excludes
        .iter()
        .any(|&(e_net, e_pl)| e_pl <= pl && prefix_contains_v6((e_net, e_pl), (net, pl)))
}

fn split_subtract_v4(
    net: Ipv4Addr,
    pl: u8,
    excludes: &[(Ipv4Addr, u8)],
    out: &mut Vec<(Ipv4Addr, u8)>,
) {
    if fully_excluded_v4(net, pl, excludes) {
        return; // 完全被 exclude 覆盖，剪枝
    }
    if pl >= 32 {
        out.push((net, pl));
        return;
    }
    // 与任何 exclude 都无交集 → 直接保留整棵子树
    if !excludes
        .iter()
        .any(|&(e_net, e_pl)| v4_intersects(e_net, e_pl, net, pl))
    {
        out.push((net, pl));
        return;
    }
    // 有交集 → 二分拆分继续
    let child_pl = pl + 1;
    let left = net;
    let right = v4_network(
        Ipv4Addr::from(u32::from(net) | (1u32 << (32 - child_pl))),
        child_pl,
    );
    split_subtract_v4(left, child_pl, excludes, out);
    split_subtract_v4(right, child_pl, excludes, out);
}

fn split_subtract_v6(
    net: Ipv6Addr,
    pl: u8,
    excludes: &[(Ipv6Addr, u8)],
    out: &mut Vec<(Ipv6Addr, u8)>,
) {
    if fully_excluded_v6(net, pl, excludes) {
        return;
    }
    if pl >= 128 {
        out.push((net, pl));
        return;
    }
    if !excludes
        .iter()
        .any(|&(e_net, e_pl)| v6_intersects(e_net, e_pl, net, pl))
    {
        out.push((net, pl));
        return;
    }
    let child_pl = pl + 1;
    let left = net;
    let right = v6_network(
        Ipv6Addr::from(u128::from(net) | (1u128 << (128 - child_pl))),
        child_pl,
    );
    split_subtract_v6(left, child_pl, excludes, out);
    split_subtract_v6(right, child_pl, excludes, out);
}

/// route_address 减去 route_exclude_address 后的最终 v4 路由集合
/// （对齐 sing-tun BuildAutoRouteRanges 的 IPSet 差集语义）。
fn final_route_v4(cfg: &TunInboundConfig) -> Vec<(Ipv4Addr, u8)> {
    let routes = build_route_targets_v4(cfg);
    let excludes = parse_excluded_v4(cfg);
    if excludes.is_empty() {
        return routes;
    }
    let mut out = Vec::new();
    for (net, pl) in &routes {
        split_subtract_v4(*net, *pl, &excludes, &mut out);
    }
    out
}

fn final_route_v6(cfg: &TunInboundConfig) -> Vec<(Ipv6Addr, u8)> {
    let routes = build_route_targets_v6(cfg);
    let excludes = parse_excluded_v6(cfg);
    if excludes.is_empty() {
        return routes;
    }
    let mut out = Vec::new();
    for (net, pl) in &routes {
        split_subtract_v6(*net, *pl, &excludes, &mut out);
    }
    out
}

/// 把最终路由集合添加到 TUN 表（setup 与 update_routes 共用）。
/// 返回添加的路由列表（写入 state）。
fn add_routes_to_table(
    cfg: &TunInboundConfig,
    if_name: &str,
    table: u32,
    has_v4: bool,
    has_v6: bool,
    state: &mut SetupState,
) {
    if has_v4 {
        for (net_ip, pl) in final_route_v4(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            Command::new("ip")
                .args([
                    "route",
                    "add",
                    &cidr,
                    "dev",
                    if_name,
                    "table",
                    &table.to_string(),
                ])
                .output()
                .ok();
            state.routes_v4.push(cidr);
        }
    }
    if has_v6 {
        for (net_ip, pl) in final_route_v6(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            Command::new("ip")
                .args([
                    "-6",
                    "route",
                    "add",
                    &cidr,
                    "dev",
                    if_name,
                    "table",
                    &table.to_string(),
                ])
                .output()
                .ok();
            state.routes_v6.push(cidr);
        }
    }
}
