use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
};
use tracing::{info, warn};

use super::super::packages_android::PackageManager;
use super::SetupState;
use crate::config::inbound::TunInboundConfig;

const ANDROID_USER_RANGE: u32 = 100000;
const PROTECTED_FROM_VPN_MARK: u32 = 0x20000;

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
    let seg = ip.segments();
    let mut out = [0u16; 8];
    let mut remaining = pl.min(128);
    for (i, s) in seg.iter().enumerate() {
        if remaining == 0 {
            break;
        }
        if remaining >= 16 {
            out[i] = *s;
            remaining -= 16;
        } else {
            let mask = !((1u16 << (16 - remaining)) - 1);
            out[i] = s & mask;
            remaining = 0;
        }
    }
    Ipv6Addr::from(out)
}

// ── Netlink 禁止检测 ──────────────────────────────────────────────────────────
// Android 11+ 不允许非系统应用打开 netlink 套接字。

fn check_netlink_banned() -> bool {
    let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_ROUTE) };
    if sock < 0 {
        return true;
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    let ret = unsafe {
        libc::bind(
            sock,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&addr) as libc::socklen_t,
        )
    };
    unsafe {
        libc::close(sock);
    }
    ret < 0
}

// ── 路由计算 ──────────────────────────────────────────────────────────────────

// Android 不使用独立路由表，所有路由直接添加到 main 表。因此**绝不能添加
// `0.0.0.0/0 dev tun` 默认路由**——它会覆盖系统物理默认路由，导致：
//   1. reflex 自身出站（fwmark 0x20000 → lookup main）命中 TUN 默认路由 → 环回；
//   2. SSH/ADB 入站连接的回包查询路由时命中 TUN → 回包进 TUN → 连接断开。
// 对齐 sing-box route_android.go + sing-tun darwin BuildAutoRouteRanges：
// 用子网分段（8 条 /1~/8）覆盖整个单播空间，保留物理默认路由 0.0.0.0/0，
// reflex 自身出站和已建立连接的回包走物理默认路由，转发流量命中更具体的
// TUN 子段路由进 TUN。
const IPV4_SUB_RANGES: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(1, 0, 0, 0), 8),
    (Ipv4Addr::new(2, 0, 0, 0), 7),
    (Ipv4Addr::new(4, 0, 0, 0), 6),
    (Ipv4Addr::new(8, 0, 0, 0), 5),
    (Ipv4Addr::new(16, 0, 0, 0), 4),
    (Ipv4Addr::new(32, 0, 0, 0), 3),
    (Ipv4Addr::new(64, 0, 0, 0), 2),
    (Ipv4Addr::new(128, 0, 0, 0), 1),
];
const IPV6_SUB_RANGES: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x100, 0, 0, 0, 0, 0, 0, 0), 8),
    (Ipv6Addr::new(0x200, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0x400, 0, 0, 0, 0, 0, 0, 0), 6),
    (Ipv6Addr::new(0x800, 0, 0, 0, 0, 0, 0, 0), 5),
    (Ipv6Addr::new(0x1000, 0, 0, 0, 0, 0, 0, 0), 4),
    (Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3),
    (Ipv6Addr::new(0x4000, 0, 0, 0, 0, 0, 0, 0), 2),
    (Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

fn route_v4(cfg: &TunInboundConfig) -> Vec<(Ipv4Addr, u8)> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        // 默认路由不能用 0.0.0.0/0（会覆盖物理默认路由导致环回），
        // 用子网分段覆盖整个 IPv4 单播空间，保留 0.0.0.0/0 给物理网卡。
        IPV4_SUB_RANGES.to_vec()
    }
}

fn route_v6(cfg: &TunInboundConfig) -> Vec<(Ipv6Addr, u8)> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        // 同 route_v4，IPv6 用子网分段覆盖整个单播空间。
        IPV6_SUB_RANGES.to_vec()
    }
}

// ── UID / Android 用户 / 包名 → 排除范围 ─────────────────────────────────────

/// 构建 Android UID 排除范围集。
/// 处理 include_android_user、include_package、exclude_package 以及
/// 原有的 include_uid/exclude_uid/include_uid_range/exclude_uid_range。
async fn build_android_uid_exclusions(
    cfg: &TunInboundConfig,
    pkg_mgr: &PackageManager,
) -> Vec<(u32, u32)> {
    let mut excluded: Vec<(u32, u32)> = vec![];

    // 1. 处理 include_android_user：所包含用户之外的 UID 范围均应排除。
    //    Android 多用户机制：每个用户对应一个 UID 空间 [user_id * 100000, (user_id+1)*100000 - 1]
    //    - user 0：主用户（UIDs 0-99999）
    //    - user 10：工作配置（UIDs 1000000-1099999）
    //    - user 999：受限用户
    //    配置中可指定 user id（如 [0, 10]），仅这些用户的流量进入 TUN。
    let mut include_users: Vec<u32> = cfg
        .include_android_user
        .iter()
        .filter_map(|&u| {
            if u < 0 {
                warn!(
                    user_id = u,
                    "tun: ignoring negative include_android_user id"
                );
                None
            } else {
                Some(u as u32)
            }
        })
        .collect();
    if include_users.is_empty() {
        // 自动发现 /data/user/ 中的用户目录（包含主用户 0、工作配置 10 等）
        if let Ok(entries) = std::fs::read_dir("/data/user") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(uid) = name.parse::<u32>() {
                        include_users.push(uid);
                    }
                }
            }
        }
        if include_users.is_empty() {
            include_users.push(0); // 默认 owner 用户
        }
    }
    // 包含用户的 UID 空间为 [uid * 100000, (uid+1) * 100000 - 1]
    let mut include_ranges: Vec<(u32, u32)> = include_users
        .iter()
        .map(|&u| (u * ANDROID_USER_RANGE, (u + 1) * ANDROID_USER_RANGE - 1))
        .collect();
    include_ranges.sort_unstable();
    // 取补集作为排除范围
    let user_end = 999999; // 最大 Android UID
    excluded.extend(complement_ranges(&include_ranges, 0, user_end));

    // 2. 处理 include_package / exclude_package
    let include_uids: Vec<u32> = pkg_mgr.resolve_packages(&cfg.include_package).await;
    let exclude_uids: Vec<u32> = pkg_mgr.resolve_packages(&cfg.exclude_package).await;

    // 将 include_package 的 UID 从排除列表中移除
    for uid in &include_uids {
        excluded.retain(|(lo, hi)| !(*lo <= *uid && *uid <= *hi));
    }
    // 将 exclude_package 的 UID 加入排除列表
    for uid in &exclude_uids {
        excluded.push((*uid, *uid));
    }

    // 3. 合并原有的 include_uid / exclude_uid / include_uid_range / exclude_uid_range
    let inc_uids = merge_uid_list_and_ranges(&cfg.include_uid, &cfg.include_uid_range);
    let exc_uids = merge_uid_list_and_ranges(&cfg.exclude_uid, &cfg.exclude_uid_range);
    // include_uid 范围需要从排除集中移除
    for (lo, hi) in &inc_uids {
        excluded.retain(|(e_lo, e_hi)| !(*lo <= *e_lo && *hi >= *e_hi));
    }
    for uid in &exc_uids {
        excluded.push(*uid);
    }

    merge_ranges(excluded)
}

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
    for &(a, b) in &ranges[1..] {
        let last = merged.last_mut().unwrap();
        if a <= last.1.saturating_add(1) {
            last.1 = last.1.max(b);
        } else {
            merged.push((a, b));
        }
    }
    merged
}

fn complement_ranges(ranges: &[(u32, u32)], start: u32, end: u32) -> Vec<(u32, u32)> {
    if ranges.is_empty() {
        return vec![(start, end)];
    }
    let mut result = Vec::new();
    let mut cur = start;
    for &(lo, hi) in ranges {
        if cur < lo {
            result.push((cur, lo - 1));
        }
        cur = hi.saturating_add(1);
        if cur > end {
            break;
        }
    }
    if cur <= end {
        result.push((cur, end));
    }
    result
}

// ── 接口名解析（Android 需要查找 utun 接口）───────────────────────────────────

pub fn resolve_tun_interface(expected: &str) -> String {
    let path = format!("/dev/tun");
    if std::path::Path::new(&path).exists() {
        // Android TUN 设备始终为 /dev/tun，但接口名需通过 ifconfig 确认。
        let out = Command::new("ip")
            .args(["link", "show", expected])
            .output()
            .ok();
        if let Some(out) = out {
            if out.status.success() {
                return expected.to_string();
            }
        }
        // 尝试查找第一个 utun 接口
        let out = Command::new("ip")
            .args(["link", "show", "type", "tun"])
            .output()
            .ok();
        if let Some(out) = out {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if let Some(name) = line.trim().strip_suffix(':') {
                    let name = name.trim();
                    if name.starts_with("tun") || name.starts_with("utun") {
                        return name.to_string();
                    }
                }
            }
        }
    }
    expected.to_string()
}

// ── setup / teardown ──────────────────────────────────────────────────────────

pub async fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    // 检测 netlink 是否被禁止
    if check_netlink_banned() {
        warn!("tun: netlink socket banned on this Android device, some features limited");
    }

    let mut state = SetupState::default();
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

    // 启动包管理器
    let pkg_mgr = {
        let mut pm = PackageManager::new();
        let _ = pm.start().await;
        pm
    };

    // 构建 UID 排除
    let excluded_uids = build_android_uid_exclusions(cfg, &pkg_mgr).await;

    // 确保设备 UP
    Command::new("ip")
        .args(["link", "set", if_name, "up"])
        .output()
        .ok();

    // ── 路由表：TUN 子网走 TUN 接口 ────────────────────────────────────────
    // Android 不使用独立路由表 + 策略规则，而是通过 ip route add 直接添加。
    if has_v4 {
        for (net_ip, pl) in &route_v4(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            Command::new("ip")
                .args(["route", "add", &cidr, "dev", if_name])
                .output()
                .ok();
            state.routes_v4.push(cidr);
        }
    }
    if has_v6 {
        for (net_ip, pl) in &route_v6(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            Command::new("ip")
                .args(["-6", "route", "add", &cidr, "dev", if_name])
                .output()
                .ok();
            state.routes_v6.push(cidr);
        }
    }

    // ── 策略规则（简化：Android 不支持 suppress_prefixlength 和 dport 53）─
    let prio_base = cfg.iproute2_rule_index;
    let nop_prio = prio_base + 100;

    // UID 排除
    for (lo, hi) in &excluded_uids {
        let prio_str = prio_base.to_string();
        let nop_str = nop_prio.to_string();
        let uid_range = format!("{lo}-{hi}");
        for family in rule_families(has_v4, has_v6) {
            add_family_rule(
                family,
                &["priority", &prio_str, "uidrange", &uid_range, "goto", &nop_str],
                prio_base,
                &mut state,
            );
        }
    }

    // 接口过滤
    if !cfg.include_interface.is_empty() {
        for iface in &cfg.include_interface {
            let prio_str = prio_base.to_string();
            for family in rule_families(has_v4, has_v6) {
                add_family_rule(
                    family,
                    &["priority", &prio_str, "iif", iface, "lookup", "main"],
                    prio_base,
                    &mut state,
                );
            }
        }
    } else if !cfg.exclude_interface.is_empty() {
        for iface in &cfg.exclude_interface {
            let prio_str = prio_base.to_string();
            let nop_str = nop_prio.to_string();
            for family in rule_families(has_v4, has_v6) {
                add_family_rule(
                    family,
                    &["priority", &prio_str, "iif", iface, "goto", &nop_str],
                    prio_base,
                    &mut state,
                );
            }
        }
    }

    // ── Android VPN 0x20000 mark 旁路规则 ──────────────────────────────────
    // Android 的 VpnService.protect(socket) 会给 socket 打上 fwmark 0x20000
    // （PROTECTED_FROM_VPN_MARK），使其绕过 TUN/VPN。被保护的应用（如系统
    // 应用、被 VPN allowlist 的应用）调用 protect() 后流量需走 main 表。
    //
    // 对齐 sing-box route_android.go：
    // - 始终添加规则（不依赖 VPN 当前是否启用，因为应用随时可能调用 protect()）
    // - fwmark 以 `0x` 前缀的十六进制传递给 ip 命令（否则会被当作十进制解析）
    // - override_android_vpn=true 时附加 suppress_prefixlength 0：
    //     仍允许 TUN 的更具体路由覆盖 main 表的默认路由，
    //     即"接管"被保护应用的流量（仅当 TUN 有比默认更具体的路由时）
    // - v4/v6 双栈均添加
    let vpn_active = check_android_vpn_active();
    if vpn_active {
        info!("tun: Android system VPN detected, adding fwmark 0x20000 bypass rules");
    } else {
        info!("tun: adding fwmark 0x20000 bypass rules (for VpnService.protect() callers)");
    }
    let fwmark = format!("0x{PROTECTED_FROM_VPN_MARK:x}");
    for family in [None, Some("-6")] {
        let family_enabled = match family {
            None => has_v4,
            Some(_) => has_v6,
        };
        if !family_enabled {
            continue;
        }
        let mut rule = Command::new("ip");
        if let Some(arg) = family {
            rule.arg(arg);
        }
        rule.args([
            "rule",
            "add",
            "priority",
            &prio_base.to_string(),
            "fwmark",
            &fwmark,
            "lookup",
            "main",
        ]);
        if cfg.override_android_vpn {
            // suppress_prefixlength 0：抑制默认路由（prefixlen 0），
            // 仅当 main 表中有比 0 更具体的路由时才使用 main 表。
            // 这允许 TUN 接管被保护应用的流量（除非它们的目标有更具体的物理路由）。
            rule.arg("suppress_prefixlength").arg("0");
        }
        // 重复添加会失败（File exists），用 .ok() 忽略
        rule.output().ok();
        state.rule_priorities.push(prio_base);
    }

    // TUN 自身出站 → goto nop
    {
        let prio_str = prio_base.to_string();
        let nop_str = nop_prio.to_string();
        for family in rule_families(has_v4, has_v6) {
            add_family_rule(
                family,
                &["priority", &prio_str, "iif", if_name, "goto", &nop_str],
                prio_base,
                &mut state,
            );
        }
    }

    // 非 lo 出站 → lookup main
    {
        let prio_str = prio_base.to_string();
        for family in rule_families(has_v4, has_v6) {
            add_family_rule(
                family,
                &["priority", &prio_str, "not", "iif", "lo", "lookup", "main"],
                prio_base,
                &mut state,
            );
        }
    }

    // lo src <tun_prefix> → lookup main
    for addr_str in &cfg.address {
        if let Some((ip, pl)) = parse_addr_prefix(addr_str) {
            let prio_str = prio_base.to_string();
            match ip {
                IpAddr::V4(ip) => {
                    let net = v4_network(ip, pl);
                    for family in rule_families(has_v4, false) {
                        add_family_rule(
                            family,
                            &[
                                "priority",
                                &prio_str,
                                "iif",
                                "lo",
                                "from",
                                &format!("{net}/{pl}"),
                                "lookup",
                                "main",
                            ],
                            prio_base,
                            &mut state,
                        );
                    }
                }
                IpAddr::V6(ip) => {
                    let net = v6_network(ip, pl);
                    for family in rule_families(false, has_v6) {
                        add_family_rule(
                            family,
                            &[
                                "priority",
                                &prio_str,
                                "iif",
                                "lo",
                                "from",
                                &format!("{net}/{pl}"),
                                "lookup",
                                "main",
                            ],
                            prio_base,
                            &mut state,
                        );
                    }
                }
            }
        }
    }

    // nop 锚点
    {
        let nop_str = nop_prio.to_string();
        for family in rule_families(has_v4, has_v6) {
            add_family_rule(family, &["priority", &nop_str], nop_prio, &mut state);
        }
    }

    info!(interface = %if_name, "tun: auto_route configured (Android)");
    Ok(state)
}

pub async fn teardown(
    cfg: &TunInboundConfig,
    if_name: &str,
    state: &SetupState,
) -> anyhow::Result<()> {
    // 清理路由
    for cidr in &state.routes_v4 {
        Command::new("ip")
            .args(["route", "del", cidr])
            .output()
            .ok();
    }
    for cidr in &state.routes_v6 {
        Command::new("ip")
            .args(["-6", "route", "del", cidr])
            .output()
            .ok();
    }

    // 清理规则（v4/v6 两个地址族都要删除，setup 时对双栈均添加了规则）
    for prio in &state.rule_priorities {
        let prio_str = prio.to_string();
        for _ in 0..3 {
            Command::new("ip")
                .args(["rule", "del", "priority", &prio_str])
                .output()
                .ok();
            Command::new("ip")
                .args(["-6", "rule", "del", "priority", &prio_str])
                .output()
                .ok();
        }
    }
    let nop_prio = cfg.iproute2_rule_index + 100;
    let nop_str = nop_prio.to_string();
    for _ in 0..3 {
        Command::new("ip")
            .args(["rule", "del", "priority", &nop_str])
            .output()
            .ok();
        Command::new("ip")
            .args(["-6", "rule", "del", "priority", &nop_str])
            .output()
            .ok();
    }

    info!(interface = %if_name, "tun: auto_route cleaned up (Android)");
    Ok(())
}

// ── 默认路由查询（默认路由变化监控用；toybox ip route show default）─────────

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

pub fn update_routes(_cfg: &TunInboundConfig, _if_name: &str) -> anyhow::Result<()> {
    Ok(())
}

/// 根据双栈启用情况返回需要添加策略规则的地址族参数。
/// `None` 对应 `ip`（IPv4），`Some("-6")` 对应 `ip -6`（IPv6）。
///
/// 修复：此前所有策略规则仅覆盖 IPv4（`if has_v4`），IPv6 流量完全没有
/// 策略规则保护。对齐 sing-tun/sing-box 在 Android 上对双栈均添加规则的
/// 行为（route_android.go / tun_android.go）。
fn rule_families(has_v4: bool, has_v6: bool) -> Vec<Option<&'static str>> {
    let mut families = Vec::with_capacity(2);
    if has_v4 {
        families.push(None);
    }
    if has_v6 {
        families.push(Some("-6"));
    }
    families
}

/// 在指定地址族上执行 `ip [-6] rule add <args>`，并记录优先级供 teardown 清理。
fn add_family_rule(family: Option<&str>, args: &[&str], prio: u32, state: &mut SetupState) {
    let mut cmd = Command::new("ip");
    if let Some(f) = family {
        cmd.arg(f);
    }
    cmd.args(["rule", "add"]);
    cmd.args(args);
    // 重复添加会失败（File exists），忽略错误
    cmd.output().ok();
    state.rule_priorities.push(prio);
}

// ── Android VPN 检测 ──────────────────────────────────────────────────────────
// 通过读取 netlink 规则中 0x20000 mark 判断系统 VPN 是否启用。
// Android VpnService 启用时会自动添加 `fwmark 0x20000 lookup <table>` 规则。

fn check_android_vpn_active() -> bool {
    let out = Command::new("ip").args(["rule", "show"]).output().ok();
    let stdout = match out {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return false,
    };
    // `ip rule show` 输出中 fwmark 以 `0x20000` 形式显示（iproute2 默认十六进制）
    // 兼容两种格式：`fwmark 0x20000` 和 `fwmark 20000`（某些旧版本）
    let hex_mark = format!("0x{PROTECTED_FROM_VPN_MARK:x}");
    let dec_mark = format!("{}", PROTECTED_FROM_VPN_MARK);
    stdout.lines().any(|line| {
        line.contains("fwmark") && (line.contains(&hex_mark) || line.contains(&dec_mark))
    })
}
