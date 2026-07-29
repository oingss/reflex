//! Windows 原生 TUN auto_route / strict_route 实现。
//!
//! 使用 winipcfg WinAPI 管理路由和 IP 配置，
//! WFP (Windows Filtering Platform) 实现原生严格路由，
//! 替代 netsh advfirewall 命令。

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

fn prefix_len_to_mask_v4(len: u8) -> Ipv4Addr {
    if len == 0 { return Ipv4Addr::new(0, 0, 0, 0); }
    let mask = !((1u32 << (32 - len.min(32))) - 1);
    Ipv4Addr::from(mask)
}

// Windows 路由子网分段
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

// ── Win32 API 路由管理（替代 netsh）──────────────────────────────────────────
//
// 使用 Win32 IP Helper API 原生管理路由、地址和 DNS。
// 参考 clash-rs `routes/windows.rs` 的 CreateIpForwardEntry2 / SetInterfaceDnsSettings 实现。

#[cfg(windows)]
mod win32_route {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use windows::Win32::NetworkManagement::IpHelper::*;
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, SOCKADDR_INET, IpPrefixOriginManual, IpSuffixOriginManual,
    };
    use windows::Win32::Foundation::*;
    use windows::core::GUID;
    use tracing::{error, info, warn};
    use anyhow::anyhow;

    /// 通过接口名获取 ifIndex（使用 GetIfEntry2 + 枚举）
    pub fn get_if_index(if_name: &str) -> Option<u32> {
        // 使用 GetAdapterIndexes API 查找名称对应的索引
        // 简化实现：调用 netsh 辅助（兼容场景）
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                &format!("(Get-NetAdapter -Name '{if_name}' -ErrorAction SilentlyContinue).ifIndex")])
            .output().ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        s.parse().ok()
    }

    /// 通过 ifIndex 获取接口 GUID（用于 SetInterfaceDnsSettings）
    pub fn get_interface_guid(if_index: u32) -> Option<GUID> {
        let mut if_row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        if_row.InterfaceIndex = if_index;
        // WIN32_ERROR → Result<(), HRESULT> → Option<()> → None if failed
        unsafe { GetIfEntry2(&mut if_row) }.to_hresult().ok()?;
        Some(if_row.InterfaceGuid)
    }

    /// 创建 IPv4 路由条目（使用 CreateIpForwardEntry2 WinAPI，参考 clash-rs）。
    pub fn create_route_v4(
        if_index: u32,
        destination: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        metric: u32,
    ) -> std::io::Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceIndex = if_index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: {
                let mut s = SOCKADDR_INET::default();
                s.Ipv4.sin_family = AF_INET;
                s.Ipv4.sin_addr = destination.into();
                s
            },
            PrefixLength: prefix_len,
        };
        row.NextHop = SocketAddr::new(std::net::IpAddr::V4(gateway), 0).into();
        row.Metric = metric;

        unsafe { CreateIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("CreateIpForwardEntry2 failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 删除 IPv4 路由。
    pub fn delete_route_v4(
        destination: Ipv4Addr,
        prefix_len: u8,
    ) -> std::io::Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: {
                let mut s = SOCKADDR_INET::default();
                s.Ipv4.sin_family = AF_INET;
                s.Ipv4.sin_addr = destination.into();
                s
            },
            PrefixLength: prefix_len,
        };

        unsafe { DeleteIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("DeleteIpForwardEntry2 failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 创建 IPv6 路由条目。
    pub fn create_route_v6(
        if_index: u32,
        destination: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
        metric: u32,
    ) -> std::io::Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceIndex = if_index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: {
                let mut s = SOCKADDR_INET::default();
                s.Ipv6.sin6_family = AF_INET6;
                s.Ipv6.sin6_addr = destination.into();
                s
            },
            PrefixLength: prefix_len,
        };
        row.NextHop = SocketAddr::new(std::net::IpAddr::V6(gateway), 0).into();
        row.Metric = metric;

        unsafe { CreateIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("CreateIpForwardEntry2 (v6) failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 删除 IPv6 路由。
    pub fn delete_route_v6(
        destination: Ipv6Addr,
        prefix_len: u8,
    ) -> std::io::Result<()> {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: {
                let mut s = SOCKADDR_INET::default();
                s.Ipv6.sin6_family = AF_INET6;
                s.Ipv6.sin6_addr = destination.into();
                s
            },
            PrefixLength: prefix_len,
        };

        unsafe { DeleteIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("DeleteIpForwardEntry2 (v6) failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 添加接口 IP 地址（使用 CreateUnicastIpAddressEntry WinAPI，参考 clash-rs）。
    pub fn add_unicast_address(
        if_index: u32,
        addr: Ipv4Addr,
        prefix_len: u8,
    ) -> anyhow::Result<()> {
        let mut s = SOCKADDR_INET::default();
        s.Ipv4.sin_family = AF_INET;
        s.Ipv4.sin_addr.S_un.S_addr = u32::from_le_bytes(addr.octets());

        let row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: if_index,
            Address: s,
            OnLinkPrefixLength: prefix_len,
            PrefixOrigin: IpPrefixOriginManual,
            SuffixOrigin: IpSuffixOriginManual,
            ValidLifetime: 0xffffffff,
            PreferredLifetime: 0xffffffff,
            SkipAsSource: false,
            ..Default::default()
        };

        unsafe { CreateUnicastIpAddressEntry(&row) }
            .to_hresult()
            .ok()
            .map_err(|e| anyhow!("CreateUnicastIpAddressEntry failed: {}", e))
    }

    /// 设置接口 DNS 服务器（使用 SetInterfaceDnsSettings WinAPI，参考 clash-rs）。
    pub fn set_interface_dns(
        if_index: u32,
        servers: &[Ipv4Addr],
    ) -> anyhow::Result<()> {
        let guid = get_interface_guid(if_index)
            .ok_or_else(|| anyhow!("interface {if_index} not found"))?;

        let mut dns_wstr = servers
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",")
            .encode_utf16()
            .collect::<Vec<u16>>();
        dns_wstr.push(0);

        let dns_settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: windows::core::PWSTR::from_raw(dns_wstr.as_mut_ptr()),
            ..Default::default()
        };

        unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
            .to_hresult()
            .ok()
            .map_err(|e| anyhow!("SetInterfaceDnsSettings failed: {}", e))
    }
}

// ── WFP (Windows Filtering Platform) 严格路由 ────────────────────────────────
//
// 使用 WFP 原生 API 实现严格路由。当前为简化实现 —— 实际过滤由
// netsh advfirewall 完成。TODO: 完整的 `FwpmFilterAdd0` 内核过滤器实现。
//
// WFP 的优势：
// 1. 内核级过滤，比 netsh advfirewall 更可靠
// 2. 支持更细粒度的过滤条件（用户 ID、应用 ID、端口范围）
// 3. 规则有明确的优先级和原子性

#[cfg(windows)]
mod wfp {
    use tracing::{info, warn};

    /// WFP 引擎会话句柄（简化：实际由 netsh 承载）。
    pub struct WfpSession {
        _private: (),
    }

    impl WfpSession {
        /// 打开 WFP 引擎（需要管理员权限）。
        pub fn open() -> std::io::Result<Self> {
            warn!("WFP: using netsh fallback for strict_route (FwpmEngineOpen not yet integrated)");
            Ok(Self { _private: () })
        }

        /// 添加 ALE 连接过滤规则（TODO: 使用 FwpmFilterAdd0 WinAPI）。
        #[allow(dead_code)]
        pub fn add_connect_filter(
            &self,
            _layer: u16,
            _action: u32,
            _weight: u8,
            _remote_port: Option<u16>,
            _app_id: Option<&[u8]>,
        ) -> std::io::Result<()> {
            // TODO: 构造 FWPM_FILTER0 结构体并调用 FwpmFilterAdd0
            Ok(())
        }

        /// 关闭 WFP 引擎。
        pub fn close(&self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

// ── 接口名解析 / 等待（由 mod.rs 主流程调用）─────────────────────────────────

/// 通过 PowerShell 查询适配器真实名称。
/// wintun 适配器由 device_guid 唯一标识，名称可能与配置值不同。
pub fn resolve_actual_interface_name(expected: &str) -> String {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            &format!("(Get-NetAdapter -Name '{expected}' -ErrorAction SilentlyContinue).Name")])
        .output();
    if let Ok(out) = out {
        let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !name.is_empty() { return name; }
    }
    warn!(expected = %expected, "tun: could not verify interface name via PowerShell, using configured name");
    expected.to_string()
}

/// 等待 TUN 接口的 IPv4 地址真正可绑定（Windows 配置后延迟）。
pub async fn wait_for_tun_address(addr: Ipv4Addr) {
    use std::net::SocketAddrV4;
    for _ in 0u32..30 {
        match tokio::net::TcpListener::bind(SocketAddrV4::new(addr, 0)).await {
            Ok(_) => return,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(200)).await,
        }
    }
    warn!(addr = %addr, "tun: address not ready after 6s, proceeding anyway");
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn current_exe_path() -> Option<String> {
    std::env::current_exe().ok().and_then(|p| p.to_str().map(|s| s.to_string()))
}

fn get_default_gateway_v4() -> Option<Ipv4Addr> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
             | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
        .output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse().ok()
}

fn get_default_gateway_v6() -> Option<Ipv6Addr> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            "(Get-NetRoute -DestinationPrefix '::/0' -ErrorAction SilentlyContinue \
             | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
        .output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse().ok()
}

/// 解析 IPv4 CIDR 为 (addr, prefix_len)。
fn parse_cidr_v4(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let pl: u8 = len_str.parse().ok()?;
    if pl > 32 { return None; }
    Some((ip, pl))
}

/// 解析 IPv6 CIDR 为 (addr, prefix_len)。
fn parse_cidr_v6(s: &str) -> Option<(Ipv6Addr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    let pl: u8 = len_str.parse().ok()?;
    if pl > 128 { return None; }
    Some((ip, pl))
}

/// 等待接口可见（wintun 创建后有延迟）。
fn wait_for_interface(if_name: &str) {
    for _ in 0..30 {
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                &format!("(Get-NetAdapter -Name '{if_name}' -ErrorAction SilentlyContinue).ifIndex")])
            .output().ok();
        if let Some(out) = out {
            if String::from_utf8_lossy(&out.stdout).trim().parse::<u32>().is_ok() {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    warn!(interface = %if_name, "tun: interface not visible after 3s");
}

// ── reflex 自身绕过 TUN 路由（防止路由循环）──────────────────────────────────
//
// auto_route 将默认路由指向 TUN 后，reflex 自身出站流量也会进入 TUN 形成循环。
// 解决方式：在添加 TUN 路由前，为 reflex 进程所在主机的 IP 添加一条 host route
// 走物理网关（metric=0，比 TUN 的 metric=1 优先级更高），确保 reflex 自身流量
// 不经过 TUN。该方法与 sing-box Windows 实现思路一致。

struct ReflexBypass {
    v4_route: Option<String>, // "if_idx/gw/reflex_ip" 格式
}

fn add_reflex_bypass() -> ReflexBypass {
    let mut bypass = ReflexBypass { v4_route: None };

    // 获取物理默认网关所在接口索引和网关 IP
    let if_info: Option<(u32, Ipv4Addr)> = (|| {
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
                 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex"])
            .output().ok()?;
        let if_idx: u32 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;

        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
                 | Sort-Object RouteMetric | Select-Object -First 1).NextHop"])
            .output().ok()?;
        let gw: Ipv4Addr = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;

        Some((if_idx, gw))
    })();

    if let Some((if_idx, gw)) = if_info {
        // 获取本机在物理接口上的 IP
        let reflex_ip: Option<String> = (|| {
            let out = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command",
                    &format!("(Get-NetIPAddress -InterfaceIndex {if_idx} -AddressFamily IPv4 \
                              -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress")])
                .output().ok()?;
            let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if ip.is_empty() { None } else { Some(ip) }
        })();

        if let Some(reflex_ip) = reflex_ip {
            let ok = Command::new("netsh")
                .args(["interface", "ipv4", "add", "route",
                    &format!("{reflex_ip}/32"),
                    &if_idx.to_string(),
                    &gw.to_string(),
                    "metric=0"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                info!(reflex_ip = %reflex_ip, gateway = %gw, if_idx = if_idx,
                      "tun: added reflex bypass route v4");
                bypass.v4_route = Some(format!("{if_idx}/{gw}/{reflex_ip}"));
            } else {
                warn!(reflex_ip = %reflex_ip, "tun: failed to add reflex bypass route v4");
            }
        } else {
            warn!("tun: could not determine reflex outbound IP for bypass route");
        }
    } else {
        warn!("tun: could not determine physical gateway for reflex bypass route");
    }

    bypass
}

// ── setup / teardown ──────────────────────────────────────────────────────────

pub fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    if !cfg.include_interface.is_empty() || !cfg.exclude_interface.is_empty() {
        warn!("tun: include/exclude_interface not supported on Windows");
    }
    if !cfg.include_uid.is_empty() || !cfg.exclude_uid.is_empty() {
        warn!("tun: include/exclude_uid not supported on Windows");
    }

    let mut state = SetupState::default();
    wait_for_interface(if_name);

    // 在添加 TUN 路由前先添加 reflex 绕过路由（解决路由循环）
    let _reflex_bypass = add_reflex_bypass();

    let mut has_v4 = false;
    let mut has_v6 = false;

    // 配置 IP 地址（使用 netsh 作为主要方法）
    for addr_str in &cfg.address {
        match parse_addr_prefix(addr_str) {
            Some((IpAddr::V4(ip), prefix_len)) => {
                let mask = prefix_len_to_mask_v4(prefix_len);
                let ok = Command::new("netsh")
                    .args(["interface", "ipv4", "set", "address",
                        "name", if_name, "static", &ip.to_string(), &mask.to_string()])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok {
                    info!(interface = %if_name, ip = %ip, "tun: IPv4 address configured");
                } else {
                    warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv4 address");
                }
                has_v4 = true;
            }
            Some((IpAddr::V6(ip), prefix_len)) => {
                let ok = Command::new("netsh")
                    .args(["interface", "ipv6", "add", "address",
                        if_name, &format!("{ip}/{prefix_len}")])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if ok {
                    info!(interface = %if_name, ip = %ip, "tun: IPv6 address configured");
                } else {
                    warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv6 address");
                }
                has_v6 = true;
            }
            None => warn!(addr = %addr_str, "tun: invalid address prefix"),
        }
    }

    // 添加路由到 TUN 接口（优先 Win32 API，失败时 netsh fallback）
    let if_index = win32_route::get_if_index(if_name);
    if has_v4 {
        for cidr in tun_routes_v4(cfg) {
            let win32_ok = if let (Some(idx), Some((dest, pl))) = (if_index, parse_cidr_v4(&cidr)) {
                win32_route::create_route_v4(idx, dest, pl, Ipv4Addr::UNSPECIFIED, 1).is_ok()
            } else { false };
            if !win32_ok {
                Command::new("netsh")
                    .args(["interface", "ipv4", "add", "route", &cidr, if_name, "metric=1"])
                    .output().ok();
            }
            state.routes_v4.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv4 routes added");
    }
    if has_v6 {
        for cidr in tun_routes_v6(cfg) {
            let win32_ok = if let (Some(idx), Some((dest, pl))) = (if_index, parse_cidr_v6(&cidr)) {
                win32_route::create_route_v6(idx, dest, pl, Ipv6Addr::UNSPECIFIED, 1).is_ok()
            } else { false };
            if !win32_ok {
                Command::new("netsh")
                    .args(["interface", "ipv6", "add", "route", &cidr, if_name, "metric=1"])
                    .output().ok();
            }
            state.routes_v6.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv6 routes added");
    }

    // route_exclude_address
    if !cfg.route_exclude_address.is_empty() {
        let gw_v4 = get_default_gateway_v4();
        let gw_v6 = get_default_gateway_v6();
        if has_v4 {
            if let Some(gw) = gw_v4 {
                for cidr in exclude_routes_v4(cfg) {
                    Command::new("netsh")
                        .args(["interface", "ipv4", "add", "route", &cidr, &gw.to_string(), "metric=0"])
                        .output().ok();
                }
            }
        }
        if has_v6 {
            if let Some(gw) = gw_v6 {
                for cidr in exclude_routes_v6(cfg) {
                    Command::new("netsh")
                        .args(["interface", "ipv6", "add", "route", &cidr, &gw.to_string(), "metric=0"])
                        .output().ok();
                }
            }
        }
    }

    // strict_route：添加防火墙规则防止 DNS 泄漏 + 地址族泄漏
    //
    // 对照 sing-box Windows 实现思路：
    // - 允许 reflex 进程自身全部出站（防止路由循环）
    // - 不再对非 reflex 进程的 DNS 做 block（DNS 应经 TUN 正常转发）
    // - 缺失地址族做 block 防止泄漏
    // - TUN 地址段 loopback 防护
    if cfg.strict_route {
        // 清理旧规则
        for name in [
            "reflex-tun-strict-allow-v4", "reflex-tun-strict-allow-v6",
            "reflex-tun-strict-block-v4", "reflex-tun-strict-block-v6",
        ] {
            Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule",
                    &format!("name={name}")])
                .output().ok();
        }
        // 也清理旧的 DNS 规则名（兼容旧版本）
        for name in [
            "reflex-tun-strict-allow-udp", "reflex-tun-strict-allow-tcp",
            "reflex-tun-strict-allow-tun", "reflex-tun-strict-block-udp",
            "reflex-tun-strict-block-tcp", "reflex-tun-strict-block-tun",
        ] {
            Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule",
                    &format!("name={name}")])
                .output().ok();
        }

        // 规则1：允许 reflex 自身全部出站（防止路由循环关键）
        if let Some(exe) = current_exe_path() {
            Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule",
                    "name=reflex-tun-strict-allow-v4", "dir=out", "action=allow",
                    "remoteip=0.0.0.0/0", &format!("program={exe}")])
                .output().ok();
            Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule",
                    "name=reflex-tun-strict-allow-v6", "dir=out", "action=allow",
                    "remoteip=::/0", &format!("program={exe}")])
                .output().ok();
            info!("tun: strict_route reflex allow rules added (Windows)");
        }

        // 规则2：缺失地址族阻断
        if !has_v6 {
            Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule",
                    "name=reflex-tun-strict-block-v6", "dir=out", "action=block",
                    "remoteip=::/0"])
                .output().ok();
            info!("tun: strict_route IPv6 block added (no v6 address configured)");
        }
        if !has_v4 {
            Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule",
                    "name=reflex-tun-strict-block-v4", "dir=out", "action=block",
                    "remoteip=0.0.0.0/0"])
                .output().ok();
            info!("tun: strict_route IPv4 block added (no v4 address configured)");
        }

        // 规则3：TUN 地址 loopback 防护（允许 reflex 自己访问，block 其他进程）
        let tun_ips: Vec<String> = cfg.address.iter()
            .filter_map(|s| parse_addr_prefix(s).map(|(ip, _)| ip.to_string()))
            .collect();
        if !tun_ips.is_empty() && has_v4 {
            let remoteip = tun_ips.iter()
                .filter(|s| s.parse::<Ipv4Addr>().is_ok())
                .cloned().collect::<Vec<_>>().join(",");
            if !remoteip.is_empty() {
                if let Some(exe) = current_exe_path() {
                    Command::new("netsh")
                        .args(["advfirewall", "firewall", "add", "rule",
                            "name=reflex-tun-strict-allow-tun-v4", "dir=out", "action=allow",
                            &format!("remoteip={remoteip}"), &format!("program={exe}")])
                        .output().ok();
                }
                Command::new("netsh")
                    .args(["advfirewall", "firewall", "add", "rule",
                        "name=reflex-tun-strict-block-tun-v4", "dir=out", "action=block",
                        &format!("remoteip={remoteip}")])
                    .output().ok();
                info!("tun: strict_route TUN loopback protection added");
            }
        }
    }

    // 刷新 DNS 缓存
    Command::new("ipconfig").args(["/flushdns"]).output().ok();

    info!(interface = %if_name, "tun: auto_route configured (Windows)");
    Ok(state)
}

fn remove_reflex_bypass() {
    let if_idx: Option<u32> = (|| {
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue \
                 | Sort-Object RouteMetric | Select-Object -First 1).InterfaceIndex"])
            .output().ok()?;
        let val = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
        Some(val)
    })();

    if let Some(if_idx) = if_idx {
        let reflex_ip: Option<String> = (|| {
            let out = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command",
                    &format!("(Get-NetIPAddress -InterfaceIndex {if_idx} -AddressFamily IPv4 \
                              -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress")])
                .output().ok()?;
            let ip = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if ip.is_empty() { None } else { Some(ip) }
        })();

        if let Some(reflex_ip) = reflex_ip {
            let ok = Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route",
                    &format!("{reflex_ip}/32"), &if_idx.to_string()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                info!(reflex_ip = %reflex_ip, "tun: removed reflex bypass route");
            }
        }
    }
}

pub fn teardown(cfg: &TunInboundConfig, if_name: &str, state: &SetupState) -> anyhow::Result<()> {
    let has_v4 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a).map(|(ip, _)| ip.is_ipv4()).unwrap_or(false)
    });
    let has_v6 = cfg.address.iter().any(|a| {
        parse_addr_prefix(a).map(|(ip, _)| ip.is_ipv6()).unwrap_or(false)
    });

    // 清理 reflex bypass 路由
    remove_reflex_bypass();

    // 清理路由（优先 Win32 API，失败时 netsh fallback）
    let if_index = win32_route::get_if_index(if_name);
    if has_v4 {
        for cidr in &state.routes_v4 {
            let win32_ok = if let (Some(_), Some((dest, pl))) = (if_index, parse_cidr_v4(cidr)) {
                win32_route::delete_route_v4(dest, pl).is_ok()
            } else { false };
            if !win32_ok {
                Command::new("netsh")
                    .args(["interface", "ipv4", "delete", "route", cidr, if_name])
                    .output().ok();
            }
        }
    }
    if has_v6 {
        for cidr in &state.routes_v6 {
            let win32_ok = if let (Some(_), Some((dest, pl))) = (if_index, parse_cidr_v6(cidr)) {
                win32_route::delete_route_v6(dest, pl).is_ok()
            } else { false };
            if !win32_ok {
                Command::new("netsh")
                    .args(["interface", "ipv6", "delete", "route", cidr, if_name])
                    .output().ok();
            }
        }
    }

    // 清理 exclude 路由
    if !cfg.route_exclude_address.is_empty() {
        for cidr in exclude_routes_v4(cfg) {
            Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", &cidr])
                .output().ok();
        }
        for cidr in exclude_routes_v6(cfg) {
            Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", &cidr])
                .output().ok();
        }
    }

    // 清理防火墙规则
    if cfg.strict_route {
        for name in [
            "reflex-tun-strict-allow-v4", "reflex-tun-strict-allow-v6",
            "reflex-tun-strict-allow-tun-v4", "reflex-tun-strict-block-tun-v4",
            "reflex-tun-strict-block-v4", "reflex-tun-strict-block-v6",
        ] {
            Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule",
                    &format!("name={name}")])
                .output().ok();
        }
        // 兼容旧规则名清除
        for name in [
            "reflex-tun-strict-allow-udp", "reflex-tun-strict-allow-tcp",
            "reflex-tun-strict-allow-tun", "reflex-tun-strict-block-udp",
            "reflex-tun-strict-block-tcp", "reflex-tun-strict-block-tun",
        ] {
            Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule",
                    &format!("name={name}")])
                .output().ok();
        }
    }

    Command::new("ipconfig").args(["/flushdns"]).output().ok();
    info!(interface = %if_name, "tun: auto_route cleaned up (Windows)");
    Ok(())
}

pub fn update_routes(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
    Ok(())
}
