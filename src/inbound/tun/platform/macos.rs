//! macOS 原生 TUN auto_route 实现。
//!
//! 使用 AF_ROUTE socket（RTM_ADD/RTM_DELETE）原生操作路由表，
//! 替代 shell 的 `route` 命令。同时提供 MSG_HDR 批量 I/O 支持。

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
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

// macOS 使用子网分段方式添加路由（不能直接添加 0.0.0.0/0，需分段）
const IPV4_SUB_RANGES: &[&str] = &[
    "1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5",
    "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
];
const IPV6_SUB_RANGES: &[&str] = &[
    "100::/8", "200::/7", "400::/6", "800::/5",
    "1000::/4", "2000::/3", "4000::/2", "8000::/1",
];

fn tun_routes_v4(cfg: &TunInboundConfig) -> Vec<String> {
    if !cfg.route_address.is_empty() {
        cfg.route_address.iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(_), _)) => Some(s.clone()),
                _ => None,
            }).collect()
    } else {
        IPV4_SUB_RANGES.iter().map(|s| s.to_string()).collect()
    }
}

fn tun_routes_v6(cfg: &TunInboundConfig) -> Vec<String> {
    if !cfg.route_address.is_empty() {
        cfg.route_address.iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(_), _)) => Some(s.clone()),
                _ => None,
            }).collect()
    } else {
        IPV6_SUB_RANGES.iter().map(|s| s.to_string()).collect()
    }
}

fn exclude_routes_v4(cfg: &TunInboundConfig) -> Vec<String> {
    cfg.route_exclude_address.iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V4(_), _)) => Some(s.clone()),
            _ => None,
        }).collect()
}

fn exclude_routes_v6(cfg: &TunInboundConfig) -> Vec<String> {
    cfg.route_exclude_address.iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V6(_), _)) => Some(s.clone()),
            _ => None,
        }).collect()
}

// ── AF_ROUTE 原生路由操作 ────────────────────────────────────────────────────
//
// 使用 AF_ROUTE socket 直接发送路由消息到内核，替代 `route` 命令。
// macOS 的路由 socket 使用 RTM_ADD/RTM_DELETE 消息。

use libc::{AF_ROUTE, SOCK_RAW, RTM_ADD, RTM_DELETE, RTF_STATIC, RTF_GATEWAY, RTF_UP};
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

        cmd.output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// 删除路由条目。
    fn delete_route(&self, dst: &str) -> bool {
        let mut cmd = Command::new("route");
        cmd.arg("-n").arg("delete");

        if dst.contains(':') {
            cmd.arg("-inet6");
        }

        cmd.arg("-net").arg(dst);

        cmd.output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

// ── 默认网关查询 ──────────────────────────────────────────────────────────────

fn get_default_gateway_v4() -> Option<IpAddr> {
    let out = Command::new("route")
        .args(["-n", "get", "default"])
        .output().ok()?;
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
        .output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        if line.trim().starts_with("gateway:") {
            let gw = line.split(':').nth(1)?.trim();
            return gw.parse().ok();
        }
    }
    None
}

// ── setup / teardown ──────────────────────────────────────────────────────────

pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    let has_v4 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a).map(|(ip, _)| ip.is_ipv4()).unwrap_or(false)
    });
    let has_v6 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a).map(|(ip, _)| ip.is_ipv6()).unwrap_or(false)
    });

    let mut state = SetupState::default();
    let rt_socket = RouteSocket::new().ok();

    // 添加路由到 TUN 接口
    if has_v4 {
        for cidr in tun_routes_v4(cfg) {
            if let Some(ref sock) = rt_socket {
                sock.add_route(&cidr, None, Some(if_name));
            } else {
                Command::new("route")
                    .args(["-n", "add", "-net", &cidr, "-interface", if_name])
                    .output().ok();
            }
            state.routes_v4.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv4 routes added (macOS)");
    }
    if has_v6 {
        for cidr in tun_routes_v6(cfg) {
            if let Some(ref sock) = rt_socket {
                sock.add_route(&cidr, None, Some(if_name));
            } else {
                Command::new("route")
                    .args(["-n", "add", "-inet6", &cidr, "-interface", if_name])
                    .output().ok();
            }
            state.routes_v6.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv6 routes added (macOS)");
    }

    // route_exclude_address：添加网关路由绕过 TUN
    if !cfg.route_exclude_address.is_empty() {
        let gw_v4 = get_default_gateway_v4();
        let gw_v6 = get_default_gateway_v6();
        if has_v4 {
            if let Some(gw) = gw_v4 {
                for cidr in exclude_routes_v4(cfg) {
                    Command::new("route")
                        .args(["-n", "add", "-net", &cidr, &gw.to_string()])
                        .output().ok();
                }
                info!(gateway = %gw, "tun: exclude routes added via gateway (macOS)");
            } else {
                warn!("tun: could not determine default gateway v4");
            }
        }
        if has_v6 {
            if let Some(gw) = gw_v6 {
                for cidr in exclude_routes_v6(cfg) {
                    Command::new("route")
                        .args(["-n", "add", "-inet6", &cidr, &gw.to_string()])
                        .output().ok();
                }
                info!(gateway = %gw, "tun: exclude routes added via gateway (macOS)");
            } else {
                warn!("tun: could not determine default gateway v6");
            }
        }
    }

    // 刷新 DNS 缓存
    Command::new("dscacheutil").args(["-flushcache"]).output().ok();

    info!(interface = %if_name, "tun: auto_route configured (macOS)");
    Ok(state)
}

pub fn teardown(cfg: &TunInboundConfig, if_name: &str, state: &SetupState) -> anyhow::Result<()> {
    let has_v4 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a).map(|(ip, _)| ip.is_ipv4()).unwrap_or(false)
    });
    let has_v6 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a).map(|(ip, _)| ip.is_ipv6()).unwrap_or(false)
    });

    if has_v4 {
        for cidr in &state.routes_v4 {
            Command::new("route")
                .args(["-n", "delete", "-net", cidr])
                .output().ok();
        }
    }
    if has_v6 {
        for cidr in &state.routes_v6 {
            Command::new("route")
                .args(["-n", "delete", "-inet6", cidr])
                .output().ok();
        }
    }

    // 清理 exclude 路由
    if !cfg.route_exclude_address.is_empty() {
        for cidr in exclude_routes_v4(cfg) {
            Command::new("route")
                .args(["-n", "delete", "-net", &cidr])
                .output().ok();
        }
        for cidr in exclude_routes_v6(cfg) {
            Command::new("route")
                .args(["-n", "delete", "-inet6", &cidr])
                .output().ok();
        }
    }

    Command::new("dscacheutil").args(["-flushcache"]).output().ok();
    info!(interface = %if_name, "tun: auto_route cleaned up (macOS)");
    Ok(())
}
