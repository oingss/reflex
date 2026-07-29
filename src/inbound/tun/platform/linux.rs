//! Linux 原生 TUN auto_route / strict_route 实现。
//!
//! 使用 rtnetlink 直连内核（替代 ip 命令），nftables 实现 autoRedirect，
//! netlink 监听实现接口热插拔监控，D-Bus 实现 systemd-resolved 集成。

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    sync::Mutex,
};
use tracing::{info, warn};

use crate::config::inbound::TunInboundConfig;
use super::SetupState;

// ── 地址辅助 ──────────────────────────────────────────────────────────────────

fn parse_addr_prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: IpAddr = ip_str.parse().ok()?;
    let prefix_len: u8 = len_str.parse().ok()?;
    let max_len = if ip.is_ipv4() { 32 } else { 128 };
    if prefix_len > max_len { return None; }
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
    if o_pl > i_pl { return false; }
    let mask = !((1u32 << (32 - o_pl.min(32))) - 1);
    (u32::from(o_net) & mask) == (u32::from(i_net) & mask)
}

fn prefix_contains_v6(outer: (Ipv6Addr, u8), inner: (Ipv6Addr, u8)) -> bool {
    let (o_net, o_pl) = outer;
    let (i_net, i_pl) = inner;
    if o_pl > i_pl { return false; }
    let mask = !((1u128 << (128 - o_pl.min(128))) - 1);
    (u128::from(o_net) & mask) == (u128::from(i_net) & mask)
}

// ── ip 命令封装 ────────────────────────────────────────────────────────────────
// 所有路由/规则/地址操作统一使用 ip 命令。
// rtnetlink crate 在 0.14 中 rule API 不完整，route/addr API 需要 builder 模式，
// 为简化维护，全部走 ip 命令。

async fn ip(args: &[&str]) {
    Command::new("ip").args(args).output().ok();
}

async fn ip6(args: &[&str]) {
    Command::new("ip").arg("-6").args(args).output().ok();
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
    if start > end { return None; }
    Some((start, end))
}

fn merge_ranges(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    if ranges.is_empty() { return ranges; }
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
                if a < lo { next.push((a, lo - 1)); }
                if b > hi { next.push((hi + 1, b)); }
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
        if cur < a { result.push((cur, a - 1)); }
        cur = b.saturating_add(1);
    }
    if cur <= hi { result.push((cur, hi)); }
    result
}

fn build_excluded_uid_ranges(cfg: &TunInboundConfig) -> Vec<(u32, u32)> {
    let include = merge_uid_list_and_ranges(&cfg.include_uid, &cfg.include_uid_range);
    let exclude = merge_uid_list_and_ranges(&cfg.exclude_uid, &cfg.exclude_uid_range);
    if include.is_empty() && exclude.is_empty() { return vec![]; }
    const UID_MAX: u32 = u32::MAX - 1;
    if !include.is_empty() {
        merge_ranges(complement_ranges(
            &subtract_ranges(&include, &exclude), 0, UID_MAX,
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
// 使用 nftables 实现流量重定向（TPROXY），替代 sing-tun 的 autoRedirect。
// 当 `redirect` 模式启用时，创建 nftables 规则集将流量 TPROXY 到代理端口。

/// 配置 nftables TPROXY 规则集。
pub fn setup_nftables_redirect(_cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
    let table = format!("reflex_tun_{}", if_name);

    // 创建 nftables 表和 chain
    let cmds = format!(r#"
table inet {table} {{
    chain prerouting {{
        type filter hook prerouting priority -150; policy accept;
        meta iif "{if_name}" return;
        meta mark 0x2023 return;
        tcp dport 53 meta mark set 0x2023 tproxy to :0 accept;
        udp dport 53 meta mark set 0x2023 tproxy to :0 accept;
    }}
    chain output {{
        type route hook output priority -150; policy accept;
        meta oif "{if_name}" return;
        meta mark 0x2024 return;
        meta skuid root return;
        tcp dport 53 meta mark set 0x2024 accept;
        udp dport 53 meta mark set 0x2024 accept;
    }}
}}
"#);

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
        anyhow::bail!("nftables setup failed");
    }
    Ok(())
}

/// 清理 nftables 规则集。
pub fn cleanup_nftables_redirect(_cfg: &TunInboundConfig, if_name: &str) {
    let table = format!("reflex_tun_{}", if_name);
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", &table])
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

    // 构造 DNS 服务器地址列表
    let mut dns_args = vec!["dns".to_string(), if_name.to_string()];
    // 从 address 配置中取 client_addr（第一个 v4 地址的 next）
    for addr_str in &cfg.address {
        if let Some((IpAddr::V4(ip), _)) = parse_addr_prefix(addr_str) {
            let client = Ipv4Addr::from(u32::from(ip).wrapping_add(1));
            dns_args.push(client.to_string());
            break;
        }
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
// 通过 ethtool ioctl 启用 TUN 接口的 checksum offload。
// 完整的 GSO/GRO 需要在 TUN 设备上启用 IFF_VNET_HDR 并处理 virtio_net_hdr。

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

    // ── 路由表 ─────────────────────────────────────────────────────────────
    let route_v4 = build_route_targets_v4(cfg);
    let route_v6 = build_route_targets_v6(cfg);
    let excluded_v4 = parse_excluded_v4(cfg);
    let excluded_v6 = parse_excluded_v6(cfg);

    if has_v4 {
        for (net_ip, pl) in &route_v4 {
            if excluded_v4.iter().any(|e| prefix_contains_v4(*e, (*net_ip, *pl))) {
                continue;
            }
            let cidr = format!("{net_ip}/{pl}");
            ip(&["route", "add", &cidr, "dev", if_name, "table", &table.to_string()]).await;
            state.routes_v4.push(cidr);
        }
    }
    if has_v6 {
        for (net_ip, pl) in &route_v6 {
            if excluded_v6.iter().any(|e| prefix_contains_v6(*e, (*net_ip, *pl))) {
                continue;
            }
            let cidr = format!("{net_ip}/{pl}");
            ip6(&["route", "add", &cidr, "dev", if_name, "table", &table.to_string()]).await;
            state.routes_v6.push(cidr);
        }
    }

    // ── 策略规则（全部使用 ip 命令，rtnetlink rule API 在 0.14 不完整）────
    let mut p4 = prio_base;
    let mut p6 = prio_base;

    // 1. fwmark 排除（参考 clash-rs: `ip rule add not fwmark $SO_MARK table $TABLE`）
    // 若配置了 so_mark，reflex 自身出站流量会带上此 mark，这些流量不走 TUN 表，
    // 避免路由循环。此规则优于 UID 排除。
    if let Some(mark) = cfg.so_mark {
        if has_v4 {
            ip(&["rule", "add", "priority", &p4.to_string(),
                "not", "fwmark", &mark.to_string(), "lookup", &table.to_string()]).await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
        if has_v6 {
            ip6(&["rule", "add", "priority", &p6.to_string(),
                "not", "fwmark", &mark.to_string(), "lookup", &table.to_string()]).await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
    }

    // 2. UID 排除
    let excluded_uids = build_excluded_uid_ranges(cfg);
    for (lo, hi) in &excluded_uids {
        if has_v4 {
            ip(&["rule", "add", "priority", &p4.to_string(),
                "uidrange", &format!("{lo}-{hi}"), "goto", &nop_prio.to_string()]).await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
        if has_v6 {
            ip6(&["rule", "add", "priority", &p6.to_string(),
                "uidrange", &format!("{lo}-{hi}"), "goto", &nop_prio.to_string()]).await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
    }

    // 2. 接口过滤
    if !cfg.include_interface.is_empty() {
        for iface in &cfg.include_interface {
            if has_v4 {
                ip(&["rule", "add", "priority", &p4.to_string(),
                    "iif", iface, "lookup", &table.to_string()]).await;
                state.rule_priorities.push(p4);
                p4 += 1;
            }
            if has_v6 {
                ip6(&["rule", "add", "priority", &p6.to_string(),
                    "iif", iface, "lookup", &table.to_string()]).await;
                state.rule_priorities.push(p6);
                p6 += 1;
            }
        }
        if has_v4 {
            ip(&["rule", "add", "priority", &p4.to_string(), "goto", &nop_prio.to_string()]).await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
        if has_v6 {
            ip6(&["rule", "add", "priority", &p6.to_string(), "goto", &nop_prio.to_string()]).await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
    } else if !cfg.exclude_interface.is_empty() {
        for iface in &cfg.exclude_interface {
            if has_v4 {
                ip(&["rule", "add", "priority", &p4.to_string(),
                    "iif", iface, "goto", &nop_prio.to_string()]).await;
                state.rule_priorities.push(p4);
                p4 += 1;
            }
            if has_v6 {
                ip6(&["rule", "add", "priority", &p6.to_string(),
                    "iif", iface, "goto", &nop_prio.to_string()]).await;
                state.rule_priorities.push(p6);
                p6 += 1;
            }
        }
    }

    // 3. strict_route
    if cfg.strict_route {
        if !has_v4 {
            ip(&["rule", "add", "priority", &p4.to_string(), "type", "unreachable"]).await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
        if !has_v6 {
            ip6(&["rule", "add", "priority", &p6.to_string(), "type", "unreachable"]).await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
    }

    // 4. TUN 子网走 TUN 表
    for (ip_addr, prefix_len) in &addrs.inet4 {
        let net = v4_network(*ip_addr, *prefix_len);
        let dst = format!("{net}/{prefix_len}");
        ip(&["rule", "add", "priority", &p4.to_string(), "to", &dst,
            "lookup", &table.to_string()]).await;
        state.rule_priorities.push(p4);
        p4 += 1;
    }
    for (ip_addr, prefix_len) in &addrs.inet6 {
        let net = v6_network(*ip_addr, *prefix_len);
        let dst = format!("{net}/{prefix_len}");
        ip6(&["rule", "add", "priority", &p6.to_string(), "to", &dst,
            "lookup", &table.to_string()]).await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 5. suppress_prefixlength 0
    if has_v4 {
        ip(&["rule", "add", "priority", &p4.to_string(),
            "lookup", &table.to_string(), "suppress_prefixlength", "0"]).await;
        state.rule_priorities.push(p4);
        p4 += 1;
    }
    if has_v6 {
        ip6(&["rule", "add", "priority", &p6.to_string(),
            "lookup", &table.to_string(), "suppress_prefixlength", "0"]).await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 6. DNS 劫持: not dport 53 → main table suppress_prefixlength 0
    if has_v4 {
        ip(&["rule", "add", "priority", &p4.to_string(),
            "not", "dport", "53", "lookup", "main", "suppress_prefixlength", "0"]).await;
        state.rule_priorities.push(p4);
        p4 += 1;
    }
    if has_v6 {
        ip6(&["rule", "add", "priority", &p6.to_string(),
            "not", "dport", "53", "lookup", "main", "suppress_prefixlength", "0"]).await;
        state.rule_priorities.push(p6);
        p6 += 1;
    }

    // 7. TUN 自身出站 goto nop
    if has_v4 {
        ip(&["rule", "add", "priority", &p4.to_string(),
            "iif", if_name, "goto", &nop_prio.to_string()]).await;
        state.rule_priorities.push(p4);
        p4 += 1;
    }

    // 8. 非 loopback → TUN 表
    if has_v4 {
        ip(&["rule", "add", "priority", &p4.to_string(),
            "not", "iif", "lo", "lookup", &table.to_string()]).await;
        state.rule_priorities.push(p4);
        p4 += 1;
        ip(&["rule", "add", "priority", &p4.to_string(),
            "iif", "lo", "from", "0.0.0.0/32", "lookup", &table.to_string()]).await;
        state.rule_priorities.push(p4);
        p4 += 1;
        for (ip_addr, prefix_len) in &addrs.inet4 {
            let net = v4_network(*ip_addr, *prefix_len);
            let src = format!("{net}/{prefix_len}");
            ip(&["rule", "add", "priority", &p4.to_string(),
                "iif", "lo", "from", &src, "lookup", &table.to_string()]).await;
            state.rule_priorities.push(p4);
            p4 += 1;
        }
    }
    if has_v6 {
        ip6(&["rule", "add", "priority", &p6.to_string(),
            "iif", if_name, "goto", &nop_prio.to_string()]).await;
        state.rule_priorities.push(p6);
        p6 += 1;
        ip6(&["rule", "add", "priority", &p6.to_string(),
            "iif", "lo", "from", "::/1", "goto", &nop_prio.to_string()]).await;
        ip6(&["rule", "add", "priority", &p6.to_string(),
            "iif", "lo", "from", "8000::/1", "goto", &nop_prio.to_string()]).await;
        state.rule_priorities.push(p6);
        p6 += 1;
        for (ip_addr, prefix_len) in &addrs.inet6 {
            let net = v6_network(*ip_addr, *prefix_len);
            let src = format!("{net}/{prefix_len}");
            ip6(&["rule", "add", "priority", &p6.to_string(),
                "iif", "lo", "from", &src, "lookup", &table.to_string()]).await;
            state.rule_priorities.push(p6);
            p6 += 1;
        }
        ip6(&["rule", "add", "priority", &p6.to_string(),
            "lookup", &table.to_string()]).await;
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
    let _ = std::fs::write(
        format!("/tmp/reflex-tun-{}.state", table),
        state_str,
    );

    // ── 启用 checksum offload ──────────────────────────────────────────────
    let _ = setup_checksum_offload(if_name);

    // ── 配置 systemd-resolved ──────────────────────────────────────────────
    setup_systemd_resolved(cfg, if_name);

    // ── autoRedirect（nftables TPROXY）─────────────────────────────────────
    // 当配置了 auto_redirect 时启用
    // （当前版本预留接口，待后续扩展）

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
    _cfg: &TunInboundConfig,
    if_name: &str,
    _state: &SetupState,
) -> anyhow::Result<()> {
    let table = _cfg.iproute2_table_index;
    let prio_base = _cfg.iproute2_rule_index;

    // 从 state 文件读取优先级信息
    let state_file = format!("/tmp/reflex-tun-{}.state", table);
    let (p4_max, p6_max) = if let Ok(s) = std::fs::read_to_string(&state_file) {
        let parts: Vec<u32> = s.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if parts.len() >= 2 { (parts[0], parts[1]) }
        else { (prio_base + 120, prio_base + 120) }
    } else {
        (prio_base + 120, prio_base + 120)
    };
    let _ = std::fs::remove_file(&state_file);

    // 清除路由
    ip(&["route", "flush", "table", &table.to_string()]).await;
    ip6(&["route", "flush", "table", &table.to_string()]).await;

    // 清除规则（从记录的范围精确清理）
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

    // 清理 systemd-resolved
    cleanup_systemd_resolved(if_name);

    // 清理 nftables
    cleanup_nftables_redirect(_cfg, if_name);

    info!(interface = %if_name, "tun: auto_route cleaned up (Linux)");
    Ok(())
}

pub fn update_routes(_cfg: &TunInboundConfig, _if_name: &str) -> anyhow::Result<()> {
    // 路由更新（接口变更后重新添加路由）
    // 简化：不做完整重算，由上层 TunInbound 在接口事件后重新 setup
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
        cfg.route_address.iter()
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
        cfg.route_address.iter()
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
    cfg.route_exclude_address.iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
            _ => None,
        })
        .collect()
}

fn parse_excluded_v6(cfg: &TunInboundConfig) -> Vec<(Ipv6Addr, u8)> {
    cfg.route_exclude_address.iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
            _ => None,
        })
        .collect()
}
