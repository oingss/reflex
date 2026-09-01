use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
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

// macOS 使用子网分段方式添加路由（不能直接添加 0.0.0.0/0，需分段）
// 对齐 sing-tun tun_rules.go autoRouteUseSubRanges：macOS 用 8 条子段
// 覆盖整个 IPv4/IPv6 单播空间，避免覆盖系统默认路由 0.0.0.0/0。
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

// ── 前缀减法（对齐 sing-tun BuildAutoRouteRanges 的 IPSet 差集语义）─────────────
//
// route_exclude_address 不能靠「单独添加 exclude 路由走物理网关」处理：
// 1. 物理网关会变化（用户切换 Wi-Fi/有线），旧 exclude 路由指向过时网关，
//    teardown 也删不干净（旧实现 teardown 重新解析配置，配置若已变更则泄漏）。
// 2. sing-tun darwin 的做法是 BuildAutoRouteRanges：把 route 集合按 exclude
//    做差集，生成不包含排除段的精确前缀集合，只往 TUN 接口添加差集结果。
//    exclude 段的流量自然落到系统默认路由（物理网关），无需额外管理。
//
// 实现为递归二分拆分：无交集的子树直接保留，完全被 exclude 覆盖的子树剪枝。

fn v4_network(ip: Ipv4Addr, pl: u8) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & !((1u32 << (32 - pl.min(32))) - 1))
}

fn v6_network(ip: Ipv6Addr, pl: u8) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(ip) & !((1u128 << (128 - pl.min(128))) - 1))
}

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

fn prefix_contains_v4(outer: (Ipv4Addr, u8), inner: (Ipv4Addr, u8)) -> bool {
    let (o_net, o_pl) = outer;
    let (i_net, i_pl) = inner;
    if o_pl > i_pl {
        return false;
    }
    let mask = v4_prefix_mask(o_pl);
    (u32::from(o_net) & mask) == (u32::from(i_net) & mask)
}

fn prefix_contains_v6(outer: (Ipv6Addr, u8), inner: (Ipv6Addr, u8)) -> bool {
    let (o_net, o_pl) = outer;
    let (i_net, i_pl) = inner;
    if o_pl > i_pl {
        return false;
    }
    let mask = v6_prefix_mask(o_pl);
    (u128::from(o_net) & mask) == (u128::from(i_net) & mask)
}

fn v4_intersects(e_net: Ipv4Addr, e_pl: u8, net: Ipv4Addr, pl: u8) -> bool {
    let (coarse_net, coarse_pl, fine_net) = if e_pl <= pl {
        (e_net, e_pl, net)
    } else {
        (net, pl, e_net)
    };
    (u32::from(fine_net) & v4_prefix_mask(coarse_pl)) == (u32::from(coarse_net) & v4_prefix_mask(coarse_pl))
}

fn v6_intersects(e_net: Ipv6Addr, e_pl: u8, net: Ipv6Addr, pl: u8) -> bool {
    let (coarse_net, coarse_pl, fine_net) = if e_pl <= pl {
        (e_net, e_pl, net)
    } else {
        (net, pl, e_net)
    };
    (u128::from(fine_net) & v6_prefix_mask(coarse_pl)) == (u128::from(coarse_net) & v6_prefix_mask(coarse_pl))
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
        return;
    }
    if pl >= 32 {
        out.push((net, pl));
        return;
    }
    if !excludes
        .iter()
        .any(|&(e_net, e_pl)| v4_intersects(e_net, e_pl, net, pl))
    {
        out.push((net, pl));
        return;
    }
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
    let base: Vec<(Ipv4Addr, u8)> = if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        IPV4_SUB_RANGES
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    };
    let excludes: Vec<(Ipv4Addr, u8)> = cfg
        .route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V4(ip), pl)) => Some((ip, pl)),
            _ => None,
        })
        .collect();
    if excludes.is_empty() {
        return base;
    }
    let mut out = Vec::new();
    for (net, pl) in &base {
        split_subtract_v4(*net, *pl, &excludes, &mut out);
    }
    out
}

fn final_route_v6(cfg: &TunInboundConfig) -> Vec<(Ipv6Addr, u8)> {
    let base: Vec<(Ipv6Addr, u8)> = if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    } else {
        IPV6_SUB_RANGES
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
                _ => None,
            })
            .collect()
    };
    let excludes: Vec<(Ipv6Addr, u8)> = cfg
        .route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V6(ip), pl)) => Some((ip, pl)),
            _ => None,
        })
        .collect();
    if excludes.is_empty() {
        return base;
    }
    let mut out = Vec::new();
    for (net, pl) in &base {
        split_subtract_v6(*net, *pl, &excludes, &mut out);
    }
    out
}

// ── AF_ROUTE 原生路由操作 ────────────────────────────────────────────────────
//
// 使用 AF_ROUTE socket 直接发送路由消息到内核，替代 `route` 命令。
// macOS 的路由 socket 使用 RTM_ADD/RTM_DELETE 消息。

// AF_ROUTE socket 用于创建路由 socket（目前 add_route/delete_route 仍走
// `route` 命令，socket 本身保留供后续原生 RTM_ADD/RTM_DELETE 实现使用）。
#[allow(unused_imports)]
use libc::{AF_ROUTE, SOCK_RAW};
use std::mem;
use std::os::unix::io::RawFd;

/// AF_ROUTE socket 文件描述符封装。
struct RouteSocket {
    fd: RawFd,
}

impl RouteSocket {
    fn new() -> std::io::Result<Self> {
        let fd = unsafe { libc::socket(AF_ROUTE, SOCK_RAW, 0) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// 在 utun fd 上设置高级 socket 选项（对齐 sing-tun darwin_device.go）。
    ///
    /// macOS utun 设备支持以下 setsockopt 优化：
    /// - `LOCAL_SENDTS` / `LOCAL_RECVTS`：启用时间戳（可选，部分 macOS 版本支持）
    /// - `SO_SNDBUF` / `SO_RCVBUF`：增大发送/接收缓冲区，避免高 PPS 场景下的丢包
    /// - `F_SETNOSIGPIPE`：防止写 utun 时 SIGPIPE 导致进程退出
    ///
    /// 参考 sing-tun darwin_device.go setsockopt 部分 + clash-rs utun 配置。
    #[allow(dead_code)]
    fn apply_utun_socket_options(fd: RawFd) {
        // 增大 socket 缓冲区到 4MB（对齐 sing-tun 默认值）
        const BUF_SIZE: libc::c_int = 4 * 1024 * 1024;
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &BUF_SIZE as *const _ as *const libc::c_void,
                std::mem::size_of_val(&BUF_SIZE) as libc::socklen_t,
            )
        };
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &BUF_SIZE as *const _ as *const libc::c_void,
                std::mem::size_of_val(&BUF_SIZE) as libc::socklen_t,
            )
        };

        // 防止 SIGPIPE（macOS 写关闭的 fd 会触发 SIGPIPE）。
        // macOS 没有 F_SETNOSIGPIPE，用 setsockopt(SO_NOSIGPIPE) 等价设置。
        let one: libc::c_int = 1;
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };

        info!(
            "tun: utun advanced socket options applied (SO_SNDBUF/SO_RCVBUF=4MB, SO_NOSIGPIPE)"
        );
    }

    /// 添加路由条目。
    fn add_route(&self, dst: &str, gateway: Option<IpAddr>, if_name: Option<&str>) -> bool {
        // 简化实现：当前仍使用 route 命令，AF_ROUTE 后续版本完善
        let mut cmd = Command::new("route");
        cmd.arg("-n").arg("add");

        let is_v6 = dst.contains(':');
        if is_v6 {
            cmd.arg("-inet6");
        }

        cmd.arg("-net").arg(dst);
        if let Some(gw) = gateway {
            cmd.arg(&gw.to_string());
        }
        if let Some(name) = if_name {
            cmd.arg("-interface").arg(name);
        }

        cmd.output().map(|o| o.status.success()).unwrap_or(false)
    }

    /// 删除路由条目。
    fn delete_route(&self, dst: &str) -> bool {
        let mut cmd = Command::new("route");
        cmd.arg("-n").arg("delete");

        if dst.contains(':') {
            cmd.arg("-inet6");
        }

        cmd.arg("-net").arg(dst);

        cmd.output().map(|o| o.status.success()).unwrap_or(false)
    }
}

impl Drop for RouteSocket {
    fn drop(&mut self) {
        // 修复 fd 泄漏：add_route/delete_route 实际走 `route` 命令，此
        // AF_ROUTE socket 本身未被使用但也从未关闭 —— 每次 setup 泄漏
        // 一个 fd（对齐 sing-tun：路由 socket 生命周期由 Close 管理）。
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

// ── 默认网关查询 ──────────────────────────────────────────────────────────────

fn get_default_gateway_v4() -> Option<IpAddr> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if line.trim().starts_with("gateway:") {
            let gw = line.split(':').nth(1)?.trim();
            return gw.parse().ok();
        }
    }
    None
}

fn get_default_gateway_v6() -> Option<IpAddr> {
    let out = Command::new("route")
        .args(["-n", "get", "-inet6", "default"])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if line.trim().starts_with("gateway:") {
            let gw = line.split(':').nth(1)?.trim();
            return gw.parse().ok();
        }
    }
    None
}

/// 查询当前系统默认网关 (v4, v6)。默认路由变化监控用。
pub async fn current_default_gateways() -> (Option<IpAddr>, Option<IpAddr>) {
    tokio::task::spawn_blocking(|| {
        (get_default_gateway_v4(), get_default_gateway_v6())
    })
    .await
    .unwrap_or((None, None))
}

/// 解析 `route -n get [-inet6] default` 输出里的 `interface:` 行，拿到物理默认
/// 路由当前所在的接口名（如 "en0"），再用 `if_nametoindex` 转成接口索引。
/// 必须在 TUN 的默认路由装上之前调用，否则读到的就是 TUN 自己了。
fn get_default_interface_index(inet6: bool) -> Option<u32> {
    let mut args = vec!["-n", "get"];
    if inet6 {
        args.push("-inet6");
    }
    args.push("default");
    let out = Command::new("route").args(&args).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let if_name = s
        .lines()
        .find(|line| line.trim().starts_with("interface:"))
        .and_then(|line| line.split(':').nth(1))
        .map(|s| s.trim().to_string())?;

    let c_name = std::ffi::CString::new(if_name).ok()?;
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        None
    } else {
        Some(idx)
    }
}

/// 在装 TUN 路由前，把当前物理默认路由所在接口登记给
/// outbound::common::interface_finder，供 direct 等出站用 IP_BOUND_IF /
/// IPV6_BOUND_IF 把自身 socket 绑定到物理网卡，避免 auto_route 把默认路由
/// 指向 TUN 之后，reflex 自己的出站流量被重新截获形成环路。
/// 探测不到（比如没有 IPv6 出口）时安静跳过，不当作错误。
fn register_physical_interface() {
    use crate::outbound::common::interface_finder::macos_iface;

    if let Some(idx) = get_default_interface_index(false) {
        macos_iface::set_physical_if_index_v4(idx);
        info!(
            if_idx = idx,
            "tun: registered physical IPv4 interface for direct outbound binding"
        );
    } else {
        warn!("tun: could not determine physical IPv4 interface for anti-loop binding");
    }
    if let Some(idx) = get_default_interface_index(true) {
        macos_iface::set_physical_if_index_v6(idx);
        info!(
            if_idx = idx,
            "tun: registered physical IPv6 interface for direct outbound binding"
        );
    }
}

// ── setup / teardown ──────────────────────────────────────────────────────────

/// 添加路由到 TUN 接口（setup 与 update_routes 共用）。
/// 使用 final_route_v4/v6（已减去 route_exclude_address 的差集结果），
/// 对齐 sing-tun darwin setRoutes()：只往 TUN 接口添加最终路由集合，
/// exclude 段的流量自然落到系统默认路由，无需额外添加 exclude 路由。
fn add_tun_routes(
    cfg: &TunInboundConfig,
    if_name: &str,
    rt_socket: &Option<RouteSocket>,
    has_v4: bool,
    has_v6: bool,
    state: &mut SetupState,
) {
    if has_v4 {
        for (net_ip, pl) in final_route_v4(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            if let Some(ref sock) = rt_socket {
                sock.add_route(&cidr, None, Some(if_name));
            } else {
                Command::new("route")
                    .args(["-n", "add", "-net", &cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
            state.routes_v4.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv4 routes added (macOS)");
    }
    if has_v6 {
        for (net_ip, pl) in final_route_v6(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            if let Some(ref sock) = rt_socket {
                sock.add_route(&cidr, None, Some(if_name));
            } else {
                Command::new("route")
                    .args(["-n", "add", "-inet6", &cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
            state.routes_v6.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv6 routes added (macOS)");
    }
}

pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
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

    let mut state = SetupState::default();
    let rt_socket = RouteSocket::new().ok();

    // 必须在装 TUN 路由之前探测物理默认路由所在接口，此时路由表还没被
    // TUN 接管，探测结果才可信（呼应 Windows setup() 里 add_reflex_bypass
    // 的同一时序要求）。
    register_physical_interface();

    // 添加路由到 TUN 接口（使用 route - exclude 差集，对齐 sing-tun
    // BuildAutoRouteRanges：不再单独添加 exclude 路由走物理网关，
    // exclude 段流量自然落到系统默认路由）。
    add_tun_routes(cfg, if_name, &rt_socket, has_v4, has_v6, &mut state);

    // 刷新 DNS 缓存
    Command::new("dscacheutil")
        .args(["-flushcache"])
        .output()
        .ok();

    info!(interface = %if_name, "tun: auto_route configured (macOS)");
    Ok(state)
}

pub fn teardown(_cfg: &TunInboundConfig, if_name: &str, state: &SetupState) -> anyhow::Result<()> {
    // 使用 setup 时记录在 state 中的路由列表精确清理（对齐 sing-tun
    // unsetRoutes：删除 setup 时添加的路由）。
    // 旧实现重新解析 cfg.route_exclude_address 来清理 exclude 路由，
    // 若配置已变更则泄漏；新实现不再添加单独的 exclude 路由，
    // state.routes_v4/v6 已包含全部 TUN 路由，删除即可。
    for cidr in &state.routes_v4 {
        Command::new("route")
            .args(["-n", "delete", "-net", cidr])
            .output()
            .ok();
    }
    for cidr in &state.routes_v6 {
        Command::new("route")
            .args(["-n", "delete", "-inet6", cidr])
            .output()
            .ok();
    }

    Command::new("dscacheutil")
        .args(["-flushcache"])
        .output()
        .ok();
    info!(interface = %if_name, "tun: auto_route cleaned up (macOS)");
    Ok(())
}

pub fn update_routes(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
    // 对齐 sing-tun darwin UpdateRouteOptions：先删除旧路由再按新配置重建。
    // 旧实现 macOS 没有 update_routes（platform::update_routes 在 macOS 上
    // 走 fallback 返回 Ok(()) 的 no-op），默认路由变化时 TUN 路由无法热更新。
    let rt_socket = RouteSocket::new().ok();

    // 先删除旧路由（通过遍历当前系统路由表中指向 TUN 接口的条目）
    // macOS 无法像 Linux 那样 flush 一个独立路由表，只能逐条删除。
    // 使用 `route -n delete` 尝试删除可能的旧路由条目（幂等：不存在则静默失败）。
    // 对齐 sing-tun darwin unsetRoutes → setRoutes 的两步流程。
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

    // 用新配置计算最终路由集合，逐条 add（已存在则 route 命令会报错，忽略）。
    // 先 delete 再 add 实现"重建"语义（route 命令不支持原子替换）。
    if has_v4 {
        for (net_ip, pl) in final_route_v4(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            // 先删后加（幂等）
            Command::new("route")
                .args(["-n", "delete", "-net", &cidr])
                .output()
                .ok();
            if let Some(ref sock) = &rt_socket {
                sock.add_route(&cidr, None, Some(if_name));
            } else {
                Command::new("route")
                    .args(["-n", "add", "-net", &cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
        }
    }
    if has_v6 {
        for (net_ip, pl) in final_route_v6(cfg) {
            let cidr = format!("{net_ip}/{pl}");
            Command::new("route")
                .args(["-n", "delete", "-inet6", &cidr])
                .output()
                .ok();
            if let Some(ref sock) = &rt_socket {
                sock.add_route(&cidr, None, Some(if_name));
            } else {
                Command::new("route")
                    .args(["-n", "add", "-inet6", &cidr, "-interface", if_name])
                    .output()
                    .ok();
            }
        }
    }

    info!(interface = %if_name, "tun: routes updated (macOS)");
    Ok(())
}
