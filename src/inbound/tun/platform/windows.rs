use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    process::Command,
};
use tracing::{info, warn};

use super::SetupState;
use crate::config::inbound::TunInboundConfig;

// Windows 平台：接口 LUID 类型（setup/teardown 路由辅助函数使用）
#[cfg(windows)]
use ::windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
#[cfg(windows)]
use ::windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

#[cfg(target_arch = "x86_64")]
const EMBEDDED_WINTUN: &[u8] = include_bytes!("../assets/wintun-x86_64.dll");
#[cfg(target_arch = "x86")]
const EMBEDDED_WINTUN: &[u8] = include_bytes!("../assets/wintun-x86.dll");

pub fn extract_embedded_wintun() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push("reflex-wintun.dll");

    // 已存在且大小一致 → 复用，避免占用时写入失败
    let need_write = match std::fs::metadata(&path) {
        Ok(meta) => meta.len() as usize != EMBEDDED_WINTUN.len(),
        Err(_) => true,
    };

    if need_write {
        // 先写到 .tmp 再原子 rename，避免半写文件被其他实例加载
        let mut tmp = path.clone();
        tmp.set_extension("dll.tmp");
        match std::fs::write(&tmp, EMBEDDED_WINTUN) {
            Ok(()) => {
                if let Err(e) = std::fs::rename(&tmp, &path) {
                    // rename 失败（跨卷 / DLL 被锁）→ 尝试直接覆盖目标
                    warn!(err = %e, "tun: rename wintun.dll.tmp failed, trying direct write");
                    let _ = std::fs::write(&path, EMBEDDED_WINTUN);
                    let _ = std::fs::remove_file(&tmp);
                }
            }
            Err(e) => {
                warn!(err = %e, path = %path.display(), "tun: failed to extract embedded wintun.dll");
            }
        }
    }

    if path.exists() {
        info!(path = %path.display(), size = EMBEDDED_WINTUN.len(), "tun: embedded wintun.dll ready");
    }
    path
}

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

fn prefix_len_to_mask_v4(len: u8) -> Ipv4Addr {
    if len == 0 {
        return Ipv4Addr::new(0, 0, 0, 0);
    }
    let mask = !((1u32 << (32 - len.min(32))) - 1);
    Ipv4Addr::from(mask)
}

// Windows 路由子网：对齐 sing-tun BuildAutoRouteRanges（非 darwin 分支）。
// 未配置 route_address 时直接劫持默认路由 0.0.0.0/0 + ::/0（TUN 接口 metric=0
// 保证优先级高于物理默认路由），而非旧实现的 8 条分段子网（漏 0.0.0.0/8）。

fn tun_routes_v4(cfg: &TunInboundConfig) -> Vec<String> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V4(_), _)) => Some(s.clone()),
                _ => None,
            })
            .collect()
    } else {
        vec!["0.0.0.0/0".to_string()]
    }
}

fn tun_routes_v6(cfg: &TunInboundConfig) -> Vec<String> {
    if !cfg.route_address.is_empty() {
        cfg.route_address
            .iter()
            .filter_map(|s| match parse_addr_prefix(s) {
                Some((IpAddr::V6(_), _)) => Some(s.clone()),
                _ => None,
            })
            .collect()
    } else {
        vec!["::/0".to_string()]
    }
}

fn exclude_routes_v4(cfg: &TunInboundConfig) -> Vec<String> {
    cfg.route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V4(_), _)) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

fn exclude_routes_v6(cfg: &TunInboundConfig) -> Vec<String> {
    cfg.route_exclude_address
        .iter()
        .filter_map(|s| match parse_addr_prefix(s) {
            Some((IpAddr::V6(_), _)) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

// ── Win32 API 路由管理（替代 netsh）──────────────────────────────────────────
//
// 使用 Win32 IP Helper API 原生管理路由、地址和 DNS。
// 参考 clash-rs `routes/windows.rs` 的 CreateIpForwardEntry2 / SetInterfaceDnsSettings 实现。

#[cfg(windows)]
mod win32_route {
    use ::windows::core::{GUID, PCWSTR};
    use ::windows::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;
    use ::windows::Win32::NetworkManagement::IpHelper::*;
    use ::windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use ::windows::Win32::Networking::WinSock::{
        IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, RouterDiscoveryDisabled,
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET,
    };
    use anyhow::anyhow;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use tracing::{debug, error};

    fn encode_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 通过接口名获取 LUID（ConvertInterfaceNameToLuidW，对齐 sing-tun winipcfg.LUID）。
    /// 相比 PowerShell 查询：更快、无进程启动开销、无引号注入问题。
    pub fn get_interface_luid(if_name: &str) -> Option<NET_LUID_LH> {
        let name_w = encode_wide(if_name);
        let mut luid = NET_LUID_LH::default();
        let r = unsafe { ConvertInterfaceNameToLuidW(PCWSTR(name_w.as_ptr()), &mut luid) };
        if r.0 != 0 {
            // wintun 接口的 InterfaceAlias 可能与 FriendlyName 不一致，
            // 这是常态而非错误（err=123），调用方有 ifIndex 反查 LUID 兜底，
            // 这里降为 debug 避免每次启动刷告警。
            debug!(
                if_name,
                err = r.0,
                "tun: ConvertInterfaceNameToLuidW failed (alias differs from FriendlyName)"
            );
            return None;
        }
        Some(luid)
    }

    /// 通过 ifIndex 反查 LUID（ConvertInterfaceIndexToLuid）。
    /// 当名字解析（ConvertInterfaceNameToLuidW）因 wintun 接口 alias 与
    /// FriendlyName 不一致而失败（err=123，见 setup 中的 fallback）时使用。
    pub fn luid_from_index(if_index: u32) -> Option<NET_LUID_LH> {
        let mut luid = NET_LUID_LH::default();
        if unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) }.0 == 0 {
            Some(luid)
        } else {
            None
        }
    }

    /// 通过接口名获取 ifIndex（Win32 优先，PowerShell 兜底）。
    pub fn get_if_index(if_name: &str) -> Option<u32> {
        if let Some(luid) = get_interface_luid(if_name) {
            let mut index = 0u32;
            if unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) }.0 == 0 {
                return Some(index);
            }
        }
        // fallback：PowerShell（兼容 FriendlyName 与 alias 不一致的场景）
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-NetAdapter -Name '{if_name}' -ErrorAction SilentlyContinue).ifIndex"
                ),
            ])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        s.parse().ok()
    }

    /// 通过 ifIndex 获取接口 GUID（用于 SetInterfaceDnsSettings）
    pub fn get_interface_guid(if_index: u32) -> Option<GUID> {
        let mut if_row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        if_row.InterfaceIndex = if_index;
        unsafe { GetIfEntry2(&mut if_row) }.to_hresult().ok().ok()?;
        Some(if_row.InterfaceGuid)
    }

    /// 构建 MIB_IPFORWARD_ROW2（对齐 sing-tun addRouteList：
    /// 以 LUID 为主键、NextHop=网关、metric 显式、生命周期 0xffffffff）。
    fn build_route_row(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: SocketAddr,
        prefix_len: u8,
        gateway: SocketAddr,
        metric: u32,
    ) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        if let Some(l) = luid {
            row.InterfaceLuid = l;
        }
        if let Some(i) = if_index {
            row.InterfaceIndex = i;
        }
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: destination.into(),
            PrefixLength: prefix_len,
        };
        row.NextHop = gateway.into();
        row.Metric = metric;
        row.ValidLifetime = 0xffffffff;
        row.PreferredLifetime = 0xffffffff;
        row
    }

    fn sockaddr_v4(ip: Ipv4Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(ip), 0)
    }
    fn sockaddr_v6(ip: Ipv6Addr) -> SocketAddr {
        SocketAddr::new(IpAddr::V6(ip), 0)
    }

    /// 创建 IPv4 路由条目（CreateIpForwardEntry2，对齐 sing-tun addRouteList）。
    pub fn create_route_v4(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
        metric: u32,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v4(destination),
            prefix_len,
            sockaddr_v4(gateway),
            metric,
        );
        unsafe { CreateIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("CreateIpForwardEntry2 failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 删除 IPv4 路由。
    /// 注意：DeleteIpForwardEntry2 的 key 包含 NextHop，必须与创建时一致，
    /// 因此需要传入 gateway（对齐 sing-tun DeleteRoute 语义）。
    pub fn delete_route_v4(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv4Addr,
        prefix_len: u8,
        gateway: Ipv4Addr,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v4(destination),
            prefix_len,
            sockaddr_v4(gateway),
            0,
        );
        unsafe { DeleteIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("DeleteIpForwardEntry2 failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 创建 IPv6 路由条目。
    pub fn create_route_v6(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
        metric: u32,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v6(destination),
            prefix_len,
            sockaddr_v6(gateway),
            metric,
        );
        unsafe { CreateIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("CreateIpForwardEntry2 (v6) failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 删除 IPv6 路由。
    /// 注意：DeleteIpForwardEntry2 的 key 包含 NextHop，必须与创建时一致，
    /// 因此需要传入 gateway（对齐 sing-tun DeleteRoute 语义）。
    pub fn delete_route_v6(
        luid: Option<NET_LUID_LH>,
        if_index: Option<u32>,
        destination: Ipv6Addr,
        prefix_len: u8,
        gateway: Ipv6Addr,
    ) -> std::io::Result<()> {
        let row = build_route_row(
            luid,
            if_index,
            sockaddr_v6(destination),
            prefix_len,
            sockaddr_v6(gateway),
            0,
        );
        unsafe { DeleteIpForwardEntry2(&row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("DeleteIpForwardEntry2 (v6) failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 删除接口上的全部路由（对齐 sing-tun FlushRoutes，用于 UpdateRouteOptions）。
    pub fn flush_routes(luid: NET_LUID_LH) -> std::io::Result<()> {
        unsafe {
            let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
            let r = GetIpForwardTable2(AF_UNSPEC, &mut table);
            if r.0 != 0 {
                return Err(std::io::Error::other(format!(
                    "GetIpForwardTable2 failed: Win32 error {}",
                    r.0
                )));
            }
            if table.is_null() {
                return Ok(());
            }
            let count = (*table).NumEntries as usize;
            let entries = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            let mut last_err: Option<u32> = None;
            for row in entries {
                if row.InterfaceLuid.Value == luid.Value {
                    let r2 = DeleteIpForwardEntry2(row);
                    if r2.0 != 0 && last_err.is_none() {
                        last_err = Some(r2.0);
                    }
                }
            }
            FreeMibTable(table as *const core::ffi::c_void);
            match last_err {
                Some(e) => Err(std::io::Error::other(format!(
                    "DeleteIpForwardEntry2 failed: Win32 error {e}"
                ))),
                None => Ok(()),
            }
        }
    }

    /// 添加接口单播地址（v4，对齐 sing-tun AddIPAddress：DadState=Preferred，
    /// Valid/PreferredLifetime=0xffffffff，SkipAsSource=false）。
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
            DadState: IpDadStatePreferred,
            ValidLifetime: 0xffffffff,
            PreferredLifetime: 0xffffffff,
            SkipAsSource: false.into(),
            ..Default::default()
        };

        let r = unsafe { CreateUnicastIpAddressEntry(&row) };
        // tun crate 创建适配器时已按配置设置过 v4 地址，这里重复添加会返回
        // ERROR_OBJECT_ALREADY_EXISTS(5010)——视为成功（地址已就位），
        // 避免 Windows 日志里刷"failed to set IPv4 address"告警。
        if r.0 == 0 || r.0 == ERROR_OBJECT_ALREADY_EXISTS.0 {
            Ok(())
        } else {
            Err(anyhow!(
                "CreateUnicastIpAddressEntry failed: Win32 error {}",
                r.0
            ))
        }
    }

    /// 添加接口单播地址（v6）。OnLinkPrefixLength 承载前缀长度。
    pub fn add_unicast_address_v6(
        if_index: u32,
        addr: Ipv6Addr,
        prefix_len: u8,
    ) -> anyhow::Result<()> {
        let mut s = SOCKADDR_INET::default();
        s.Ipv6.sin6_family = AF_INET6;
        s.Ipv6.sin6_addr = addr.into();

        let row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: if_index,
            Address: s,
            OnLinkPrefixLength: prefix_len,
            PrefixOrigin: IpPrefixOriginManual,
            SuffixOrigin: IpSuffixOriginManual,
            DadState: IpDadStatePreferred,
            ValidLifetime: 0xffffffff,
            PreferredLifetime: 0xffffffff,
            SkipAsSource: false.into(),
            ..Default::default()
        };

        let r = unsafe { CreateUnicastIpAddressEntry(&row) };
        if r.0 == 0 || r.0 == ERROR_OBJECT_ALREADY_EXISTS.0 {
            Ok(())
        } else {
            Err(anyhow!(
                "CreateUnicastIpAddressEntry (v6) failed: Win32 error {}",
                r.0
            ))
        }
    }

    /// 删除接口上全部单播地址（对齐 sing-tun FlushIPAddresses）。
    /// 解决 netsh `ipv6 add address` 重启累积堆叠问题（B4）。
    pub fn flush_unicast_addresses(luid: NET_LUID_LH) -> std::io::Result<()> {
        unsafe {
            let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
            let r = GetUnicastIpAddressTable(AF_UNSPEC, &mut table);
            if r.0 != 0 {
                return Err(std::io::Error::other(format!(
                    "GetUnicastIpAddressTable failed: Win32 error {}",
                    r.0
                )));
            }
            if table.is_null() {
                return Ok(());
            }
            let count = (*table).NumEntries as usize;
            let entries = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            let mut last_err: Option<u32> = None;
            for row in entries {
                if row.InterfaceLuid.Value == luid.Value {
                    let r2 = DeleteUnicastIpAddressEntry(row);
                    if r2.0 != 0 && last_err.is_none() {
                        last_err = Some(r2.0);
                    }
                }
            }
            FreeMibTable(table as *const core::ffi::c_void);
            match last_err {
                Some(e) => Err(std::io::Error::other(format!(
                    "DeleteUnicastIpAddressEntry failed: Win32 error {e}"
                ))),
                None => Ok(()),
            }
        }
    }

    /// 设置接口参数（对齐 sing-tun configure() 中的 IPInterface 设置）：
    /// - 路由器发现关闭（RouterDiscoveryDisabled）
    /// - 禁用重复地址检测（DadTransmits=0，地址即时可用）
    /// - 关闭无状态/有状态自动配置
    /// - NlMtu 对齐配置
    /// - AutoRoute 时 UseAutomaticMetric=false + Metric=0（保证 TUN 路由优先级）
    /// - IPv4 额外开启 ForwardingEnabled（sing-tun 仅 v4 开启）
    pub fn configure_interface(
        luid: NET_LUID_LH,
        family: ADDRESS_FAMILY,
        mtu: u32,
        auto_route: bool,
        set_forwarding: bool,
    ) -> std::io::Result<()> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid = luid;
        let r = unsafe { GetIpInterfaceEntry(&mut row) };
        if r.0 != 0 {
            return Err(std::io::Error::other(format!(
                "GetIpInterfaceEntry failed: Win32 error {}",
                r.0
            )));
        }
        if set_forwarding {
            row.ForwardingEnabled = true.into();
        }
        row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
        row.DadTransmits = 0;
        row.ManagedAddressConfigurationSupported = false.into();
        row.OtherStatefulConfigurationSupported = false.into();
        row.NlMtu = mtu;
        if auto_route {
            row.UseAutomaticMetric = false.into();
            row.Metric = 0;
        }
        unsafe { SetIpInterfaceEntry(&mut row) }
            .to_hresult()
            .ok()
            .inspect_err(|e| error!("SetIpInterfaceEntry failed: {}", e))
            .map_err(|e| std::io::Error::other(e.message()))
    }

    /// 设置接口 DNS 服务器（SetInterfaceDnsSettings WinAPI，参考 clash-rs）。
    /// `servers` 为空时清空接口 DNS（对齐 sing-tun SetDNS(family, nil, nil)）。
    pub fn set_interface_dns(if_index: u32, servers: &[IpAddr]) -> anyhow::Result<()> {
        let guid = get_interface_guid(if_index)
            .ok_or_else(|| anyhow!("interface {if_index} not found"))?;

        let dns_str = servers
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>()
            .join(",");
        let mut dns_wstr: Vec<u16> = dns_str.encode_utf16().chain(std::iter::once(0)).collect();

        let dns_settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: ::windows::core::PWSTR::from_raw(dns_wstr.as_mut_ptr()),
            ..Default::default()
        };

        unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
            .to_hresult()
            .ok()
            .map_err(|e| anyhow!("SetInterfaceDnsSettings failed: {}", e))
    }

    /// 禁用接口 DNS 动态注册（对齐 sing-tun DisableDNSRegistration）。
    pub fn disable_dns_registration(if_index: u32) -> anyhow::Result<()> {
        let guid = get_interface_guid(if_index)
            .ok_or_else(|| anyhow!("interface {if_index} not found"))?;

        let dns_settings = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_REGISTRATION_ENABLED as u64,
            RegistrationEnabled: 0,
            ..Default::default()
        };

        unsafe { SetInterfaceDnsSettings(guid, &dns_settings) }
            .to_hresult()
            .ok()
            .map_err(|e| anyhow!("SetInterfaceDnsSettings (registration) failed: {}", e))
    }

    /// SOCKADDR_INET → IpAddr（读取路由表 NextHop / Prefix、单播地址表 Address 用）。
    /// `sin_family` 与 `sin6_family` 共享同一偏移，先读 Ipv4.sin_family 判别族，
    /// 再按族读取对应联合体字段——访问 union 字段需 unsafe。
    fn sockaddr_inet_to_ip(addr: &SOCKADDR_INET) -> Option<IpAddr> {
        unsafe {
            let fam = addr.Ipv4.sin_family;
            if fam == AF_INET {
                let s_addr = addr.Ipv4.sin_addr.S_un.S_addr;
                // S_addr 以网络字节序存储；to_ne_bytes 在 Windows(LE) 上得到 [octets...]
                Some(IpAddr::V4(Ipv4Addr::from(s_addr.to_ne_bytes())))
            } else if fam == AF_INET6 {
                // IN6_ADDR 为 repr(C)、恰好 16 字节；按指针读 16 字节，避免依赖
                // windows-rs 各版本 IN6_ADDR 内部联合体字段命名（u.Byte / Byte）。
                let bytes: [u8; 16] =
                    std::ptr::read(&addr.Ipv6.sin6_addr as *const _ as *const [u8; 16]);
                Some(IpAddr::V6(Ipv6Addr::from(bytes)))
            } else {
                None
            }
        }
    }

    /// 查询默认路由所在的物理接口（GetIpForwardTable2，替代 Get-NetRoute PowerShell）。
    /// 返回 (if_index, gateway_ip)。`tun_if_index` 用于排除 TUN 自身接口——上次
    /// 异常退出未清理时可能残留 metric=0 的 TUN 默认路由，若不排除会被误选为
    /// "物理网卡"，所有出站 socket 被 IP_UNICAST_IF 钉回 TUN 形成死环。
    /// 按 Metric 升序取最低（对齐 `Get-NetRoute | Sort RouteMetric | Select -First 1`）。
    pub fn find_default_route(
        family: ADDRESS_FAMILY,
        tun_if_index: Option<u32>,
    ) -> Option<(u32, IpAddr)> {
        unsafe {
            let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
            if GetIpForwardTable2(family, &mut table).0 != 0 || table.is_null() {
                return None;
            }
            let count = (*table).NumEntries as usize;
            let entries = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            let mut best: Option<&MIB_IPFORWARD_ROW2> = None;
            for row in entries {
                // 默认路由：PrefixLength==0 且目的地址为未指定
                if row.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                let is_unspec = sockaddr_inet_to_ip(&row.DestinationPrefix.Prefix)
                    .map(|p| match p {
                        IpAddr::V4(v) => v.is_unspecified(),
                        IpAddr::V6(v) => v.is_unspecified(),
                    })
                    .unwrap_or(false);
                if !is_unspec {
                    continue;
                }
                // 排除 TUN 自身接口（防止残留路由导致死环）
                if tun_if_index == Some(row.InterfaceIndex) {
                    continue;
                }
                match best {
                    None => best = Some(row),
                    Some(b) if row.Metric < b.Metric => best = Some(row),
                    _ => {}
                }
            }
            let result = best.and_then(|row| {
                let gw = sockaddr_inet_to_ip(&row.NextHop)?;
                Some((row.InterfaceIndex, gw))
            });
            FreeMibTable(table as *const core::ffi::c_void);
            result
        }
    }

    /// 查询接口上的首选源 IP（GetUnicastIpAddressTable，替代 Get-NetIPAddress PowerShell）。
    /// 取 DadState==Preferred、SkipAsSource==false 的首个地址；IPv6 自动跳过
    /// link-local（fe80::/10），对齐旧 PowerShell 实现的过滤语义。
    pub fn find_source_ip(family: ADDRESS_FAMILY, if_index: u32) -> Option<IpAddr> {
        unsafe {
            let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
            if GetUnicastIpAddressTable(family, &mut table).0 != 0 || table.is_null() {
                return None;
            }
            let count = (*table).NumEntries as usize;
            let entries = std::slice::from_raw_parts((*table).Table.as_ptr(), count);
            let mut found = None;
            for row in entries {
                if row.InterfaceIndex != if_index {
                    continue;
                }
                if row.DadState != IpDadStatePreferred {
                    continue;
                }
                // SkipAsSource=true 的地址 Windows 不允许 bind 作源 IP
                if row.SkipAsSource.as_bool() {
                    continue;
                }
                let ip = sockaddr_inet_to_ip(&row.Address)?;
                if let IpAddr::V6(v6) = ip {
                    if v6.is_unicast_link_local() {
                        continue;
                    }
                }
                found = Some(ip);
                break;
            }
            FreeMibTable(table as *const core::ffi::c_void);
            found
        }
    }
}

// ── WFP (Windows Filtering Platform) 严格路由 ────────────────────────────────
//
// 使用 WFP 原生 API（FwpmEngineOpen0 / FwpmSubLayerAdd0 / FwpmFilterAdd0）实现
// 内核级流量过滤，严格对齐 sing-tun tun_windows.go Start() 的 strict_route：
//
//  1. 打开引擎（FWPM_SESSION_FLAG_DYNAMIC，会话结束自动清理全部过滤器）
//  2. 创建自定义 sublayer（weight = MaxUint16），保证规则优先于系统防火墙
//  3. permit 自身进程（ALE_APP_ID 匹配，weight 13，CLEAR_ACTION_RIGHT）
//     → 防止 block :53 把 reflex 自己的 DNS 出站一起拦掉（代理 DNS 死锁）
//  4. 缺失地址族 block（weight 12）—— 仅 IPv6（对齐 sing-tun：v4 block
//     被注释掉，因为 block 全部 IPv4 在「TUN 仅 IPv6」场景下会切断系统网络）
//  5. permit TUN 接口（LOCAL_INTERFACE_INDEX 匹配，weight 11）
//     → TUN 接口流量不受 block :53 影响（DNS hijack 在 IP 层处理）
//  6. block :53（weight 10，v4+v6）→ 强制其他进程 DNS 走 TUN，防泄漏
//
// 修复说明：旧实现直接 zeroed FWPM_FILTER0 且不设 subLayerKey，
// FwpmFilterAdd0 会因 sublayer 无效而失败（规则静默失效），
// 且缺少自身进程 / TUN 接口 permit（B2，P0）。

#[cfg(windows)]
mod wfp {
    use ::windows::core::{GUID, PCWSTR};
    use ::windows::Win32::Foundation::HANDLE;
    use ::windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use ::windows::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
    use tracing::{info, warn};

    // FWPM_CONDITION_LOCAL_INTERFACE_INDEX：windows 0.58 crate 未导出，
    // GUID 取自 fwpmu.h（与 sing-tun internal/winsys/constants.go 一致）。
    const FWPM_CONDITION_LOCAL_INTERFACE_INDEX: GUID =
        GUID::from_u128(0x667fd755_d695_434a_8af5_d3835a1259bc);

    // 权重对齐 sing-tun：permit 自身进程 > block 缺失地址族 > permit TUN > block DNS
    const WEIGHT_PERMIT_APP: u8 = 13;
    const WEIGHT_BLOCK_FAMILY: u8 = 12;
    const WEIGHT_PERMIT_TUN: u8 = 11;
    const WEIGHT_BLOCK_DNS: u8 = 10;

    fn encode_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// WFP 引擎会话封装。drop 时自动关闭引擎并清理过滤器（FWPM_SESSION_FLAG_DYNAMIC）。
    pub struct WfpSession {
        engine_handle: HANDLE,
        sub_layer_key: GUID,
    }

    impl WfpSession {
        /// 打开 WFP 引擎（需要管理员权限）并创建自定义 sublayer。
        pub fn open() -> std::io::Result<Self> {
            let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
            // FWPM_SESSION_FLAG_DYNAMIC: 会话结束时自动删除所有添加的过滤器
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let mut handle = HANDLE::default();
            let result = unsafe {
                FwpmEngineOpen0(
                    None,
                    RPC_C_AUTHN_DEFAULT as u32, // windows crate 0.58: RPC_C_AUTHN_DEFAULT 是 i32(-1)
                    None,
                    Some(&session),
                    &mut handle,
                )
            };
            if result != 0 {
                return Err(std::io::Error::other(format!(
                    "FwpmEngineOpen0 failed: Win32 error {result}"
                )));
            }

            // 创建自定义 sublayer（sing-tun：Weight = MaxUint16），
            // 让本会话的规则优先于系统防火墙规则。
            let sub_layer_key =
                GUID::new().map_err(|e| std::io::Error::other(format!("CoCreateGuid: {e}")))?;
            let name_w = encode_wide("reflex auto-route rules");
            let desc_w = encode_wide("reflex tun auto-route rules (strict_route)");
            let mut sub_layer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sub_layer.subLayerKey = sub_layer_key;
            sub_layer.displayData = FWPM_DISPLAY_DATA0 {
                name: ::windows::core::PWSTR::from_raw(name_w.as_ptr() as *mut u16),
                description: ::windows::core::PWSTR::from_raw(desc_w.as_ptr() as *mut u16),
            };
            // windows crate 0.58 中 FWPM_SUBLAYER0.weight 直接是 u16（不是
            // FWPM_VALUE 联合），对齐 sing-tun 的 Weight = MaxUint16。
            sub_layer.weight = u16::MAX;
            let result = unsafe { FwpmSubLayerAdd0(handle, &sub_layer, None) };
            if result != 0 {
                let _ = unsafe { FwpmEngineClose0(handle) };
                return Err(std::io::Error::other(format!(
                    "FwpmSubLayerAdd0 failed: Win32 error {result}"
                )));
            }
            info!("tun: WFP engine opened, sublayer created");
            Ok(Self {
                engine_handle: handle,
                sub_layer_key,
            })
        }

        /// 添加过滤器（统一挂到本会话 sublayer）。
        fn add_filter(
            &self,
            layer: GUID,
            weight: u8,
            action_type: FWP_ACTION_TYPE,
            display_name: &str,
            conditions: &mut [FWPM_FILTER_CONDITION0],
            flags: FWPM_FILTER_FLAGS,
        ) -> std::io::Result<()> {
            let name_w = encode_wide(display_name);
            let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            filter.layerKey = layer;
            // ⚠️ subLayerKey 必须指向已添加的 sublayer，否则 FwpmFilterAdd0 失败
            filter.subLayerKey = self.sub_layer_key;
            filter.action.r#type = action_type;
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = weight;
            filter.flags = flags;
            filter.displayData = FWPM_DISPLAY_DATA0 {
                name: ::windows::core::PWSTR::from_raw(name_w.as_ptr() as *mut u16),
                description: ::windows::core::PWSTR::from_raw(name_w.as_ptr() as *mut u16),
            };
            filter.filterCondition = conditions.as_mut_ptr();
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterKey =
                GUID::new().map_err(|e| std::io::Error::other(format!("CoCreateGuid: {e}")))?;

            let mut filter_id: u64 = 0;
            let result =
                unsafe { FwpmFilterAdd0(self.engine_handle, &filter, None, Some(&mut filter_id)) };
            if result != 0 {
                return Err(std::io::Error::other(format!(
                    "FwpmFilterAdd0 ({display_name}) failed: Win32 error {result}"
                )));
            }
            Ok(())
        }

        /// permit 当前进程（ALE_APP_ID 匹配，CLEAR_ACTION_RIGHT），v4 + v6。
        /// 防止后续 block 规则拦截 reflex 自身出站（对齐 sing-tun permitFilter4/6）。
        pub fn protect_process(&self, exe_path: &str) -> std::io::Result<()> {
            let exe_w = encode_wide(exe_path);
            let mut appid: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
            let result = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(exe_w.as_ptr()), &mut appid) };
            if result != 0 || appid.is_null() {
                return Err(std::io::Error::other(format!(
                    "FwpmGetAppIdFromFileName0 failed: Win32 error {result}"
                )));
            }

            let appid_ref = unsafe { &*appid };
            let mut cond_v4 = self.make_app_id_condition(appid_ref);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                WEIGHT_PERMIT_APP,
                FWP_ACTION_PERMIT,
                "reflex protect ipv4",
                std::slice::from_mut(&mut cond_v4),
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            )?;
            let mut cond_v6 = self.make_app_id_condition(appid_ref);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                WEIGHT_PERMIT_APP,
                FWP_ACTION_PERMIT,
                "reflex protect ipv6",
                std::slice::from_mut(&mut cond_v6),
                FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            )?;

            // 释放 FwpmGetAppIdFromFileName0 分配的内存
            unsafe {
                FwpmFreeMemory0(
                    &mut appid as *mut *mut FWP_BYTE_BLOB as *mut *mut core::ffi::c_void,
                );
            }
            Ok(())
        }

        /// block 缺失地址族（对齐 sing-tun blockFilter：weight 12）。
        pub fn block_family(&self, layer: GUID, name: &str) -> std::io::Result<()> {
            self.add_filter(
                layer,
                WEIGHT_BLOCK_FAMILY,
                FWP_ACTION_BLOCK,
                name,
                &mut [],
                FWPM_FILTER_FLAGS(0),
            )
        }

        /// permit 从 TUN 接口发起的连接（LOCAL_INTERFACE_INDEX 匹配，对齐 sing-tun
        /// tunFilter4/6：weight 11，让 TUN 接口流量不受 block :53 影响）。
        #[allow(clippy::field_reassign_with_default)] // FWP 联合体字段无法用结构体字面量初始化
        pub fn permit_tun_interface(
            &self,
            layer: GUID,
            if_index: u32,
            name: &str,
        ) -> std::io::Result<()> {
            let mut cond = FWPM_FILTER_CONDITION0::default();
            // windows crate 0.58 未导出 FWPM_CONDITION_LOCAL_INTERFACE_INDEX，
            // 按其值内联定义（对齐 sing-tun internal/winsys/constants.go:113-118）。
            // 修复：旧实现用 FWPM_CONDITION_ARRIVAL_INTERFACE_INDEX，该字段仅
            // 用于接收/accept 路径，在 ALE_AUTH_CONNECT 层不匹配出站接口，
            // 导致 permit 过滤器静默失效。
            cond.fieldKey = FWPM_CONDITION_LOCAL_INTERFACE_INDEX;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue.r#type = FWP_UINT32;
            cond.conditionValue.Anonymous.uint32 = if_index;
            self.add_filter(
                layer,
                WEIGHT_PERMIT_TUN,
                FWP_ACTION_PERMIT,
                name,
                std::slice::from_mut(&mut cond),
                FWPM_FILTER_FLAGS(0),
            )
        }

        /// block 出站 port 53（v4 + v6，对齐 sing-tun blockDNSFilter4/6：weight 10，
        /// 不带 protocol 条件；reflex 无 DNSMode 概念，恒启用防泄漏）。
        pub fn block_dns(&self) -> std::io::Result<()> {
            let mut cond_v4 = self.make_uint16_condition(FWPM_CONDITION_IP_REMOTE_PORT, 53);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                WEIGHT_BLOCK_DNS,
                FWP_ACTION_BLOCK,
                "reflex block ipv4 dns",
                std::slice::from_mut(&mut cond_v4),
                FWPM_FILTER_FLAGS(0),
            )?;
            let mut cond_v6 = self.make_uint16_condition(FWPM_CONDITION_IP_REMOTE_PORT, 53);
            self.add_filter(
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                WEIGHT_BLOCK_DNS,
                FWP_ACTION_BLOCK,
                "reflex block ipv6 dns",
                std::slice::from_mut(&mut cond_v6),
                FWPM_FILTER_FLAGS(0),
            )
        }

        #[allow(clippy::field_reassign_with_default)] // FWP 联合体字段无法用结构体字面量初始化
        fn make_app_id_condition(&self, appid: &FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
            let mut cond = FWPM_FILTER_CONDITION0::default();
            cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
            // windows crate 0.58: byteBlob 字段是 *mut FWP_BYTE_BLOB（不是值类型）
            cond.conditionValue.Anonymous.byteBlob =
                appid as *const FWP_BYTE_BLOB as *mut FWP_BYTE_BLOB;
            cond
        }

        #[allow(clippy::field_reassign_with_default)] // FWP 联合体字段无法用结构体字面量初始化
        fn make_uint16_condition(&self, key: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
            let mut cond = FWPM_FILTER_CONDITION0::default();
            cond.fieldKey = key;
            cond.matchType = FWP_MATCH_EQUAL;
            cond.conditionValue.r#type = FWP_UINT16;
            cond.conditionValue.Anonymous.uint16 = value;
            cond
        }
    }

    impl Drop for WfpSession {
        fn drop(&mut self) {
            if !self.engine_handle.is_invalid() {
                let _ = unsafe { FwpmEngineClose0(self.engine_handle) };
                info!("tun: WFP engine closed (filters auto-removed via DYNAMIC flag)");
            }
        }
    }

    /// 创建完整 strict_route WFP 会话（对齐 sing-tun tun_windows.go Start()）。
    /// 返回堆指针（以 usize 存储），teardown 时调用 `drop_wfp_session` 释放。
    /// 失败返回 0（调用方应忽略并降级）。
    pub fn create_strict_session(
        exe_path: Option<String>,
        if_index: Option<u32>,
        has_v4: bool,
        has_v6: bool,
    ) -> usize {
        let session = match WfpSession::open() {
            Ok(s) => s,
            Err(e) => {
                warn!("tun: WFP session open failed (strict_route disabled): {e}");
                return 0;
            }
        };

        // 1. permit 自身进程（关键：防止 block :53 拦截 reflex 自己的 DNS）
        if let Some(exe) = exe_path {
            if let Err(e) = session.protect_process(&exe) {
                warn!("tun: WFP protect_process failed: {e}");
            }
        } else {
            warn!("tun: cannot determine current exe for WFP process permit");
        }

        // 2. 缺失地址族 block
        //
        // 对齐 sing-tun tun_windows.go Start()：IPv4 block 过滤器被注释掉
        // （`/*if len(t.options.Inet4Address) == 0 { ... }*/`），只 block IPv6。
        // 原因：Windows 上绝大多数系统依赖 IPv4 通信，当 TUN 仅配置 IPv6 地址时
        // block 全部 IPv4 流量会导致系统网络完全不可用（甚至连 DNS 都解析不了）。
        // IPv6 相反：block IPv6 仅阻止 IPv6 泄漏，系统可回退 IPv4，安全得多。
        //
        // 旧实现同时 block v4+v6，在「TUN 仅 IPv6」场景下会把机器从 IPv4
        // 互联网切断，属于过激行为。
        //
        // Note: 仅保留 IPv6 block（与 sing-tun 完全对齐）。
        // #[cfg(not(feature = "strict_route_block_v4"))]
        // if !has_v4 {
        //     session.block_family(FWPM_LAYER_ALE_AUTH_CONNECT_V4, "reflex block ipv4")?;
        // }
        if !has_v6 {
            if let Err(e) =
                session.block_family(FWPM_LAYER_ALE_AUTH_CONNECT_V6, "reflex block ipv6")
            {
                warn!("tun: WFP block_family v6 failed: {e}");
            }
        }

        // 3. permit TUN 接口
        if let Some(idx) = if_index {
            if has_v4 {
                if let Err(e) = session.permit_tun_interface(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    idx,
                    "reflex allow ipv4",
                ) {
                    warn!("tun: WFP permit_tun_interface v4 failed: {e}");
                }
            }
            if has_v6 {
                if let Err(e) = session.permit_tun_interface(
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    idx,
                    "reflex allow ipv6",
                ) {
                    warn!("tun: WFP permit_tun_interface v6 failed: {e}");
                }
            }
        }

        // 4. block :53（防 DNS 泄漏）
        if let Err(e) = session.block_dns() {
            warn!("tun: WFP block_dns failed: {e}");
        }

        let boxed = Box::new(session);
        Box::into_raw(boxed) as usize
    }

    /// 释放由 `create_strict_session` 创建的 WFP 会话。
    /// 安全性：ptr 必须由 `create_strict_session` 返回，且只能释放一次。
    pub unsafe fn drop_wfp_session(ptr: usize) {
        if ptr != 0 {
            let _ = Box::from_raw(ptr as *mut WfpSession);
        }
    }
}

// ── 接口名解析 / 等待（由 mod.rs 主流程调用）─────────────────────────────────

/// 通过 PowerShell 查询适配器真实名称。
/// wintun 适配器由 device_guid 唯一标识，名称可能与配置值不同。
/// 适配器创建后网络子系统枚举存在延迟，重试最多 1s（对齐 wait_for_interface 的
/// 轮询思路；B1 修复后 expected 与 tun crate 实际名一致，重试为兜底）。
pub fn resolve_actual_interface_name(expected: &str) -> String {
    for _ in 0..10 {
        let out = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("(Get-NetAdapter -Name '{expected}' -ErrorAction SilentlyContinue).Name"),
            ])
            .output();
        if let Ok(out) = out {
            let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !name.is_empty() {
                return name;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
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
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
}

/// F4：自身 exe 的入站 TCP 放行规则名（对齐 sing-tun fixWindowsFirewall）。
const INBOUND_TCP_RULE_NAME: &str = "reflex-tun-allow-inbound-tcp";
/// 自身 exe 的入站 UDP 放行规则名。Windows 防火墙默认入站策略是 BLOCK，
/// 虽然 outbound UDP 后会话内入站响应能放行（stateful），但某些场景下
///（如 hysteria2/QUIC 服务器响应包端口/IP 变化、新建立的 5-tuple）
/// 仍可能被拦截导致 QUIC connect 永远卡住。对齐 sing-tun
/// fixWindowsFirewall 的 TCP+UDP 双规则。
const INBOUND_UDP_RULE_NAME: &str = "reflex-tun-allow-inbound-udp";

/// 为自身 exe 添加入站 TCP ALLOW 防火墙规则（对齐 sing-tun
/// stack_system_windows.go fixWindowsFirewall）：system/mixed 栈在 TUN 地址上
/// 监听 TCP，Windows 防火墙默认入站策略会拦截发往该监听器的连接，导致
/// TUN 下 TCP 流量全部握手超时。规则限定 program=<自身 exe> + protocol=tcp，
/// 收敛暴露面。失败仅告警（非提权环境/组策略限制时不应阻断启动）。
fn add_inbound_tcp_firewall_rule() {
    // 先删除同名旧规则，避免堆叠残留
    remove_inbound_tcp_firewall_rule();
    let Some(exe) = current_exe_path() else {
        warn!("tun: cannot resolve current exe path, skip inbound TCP firewall rule");
        return;
    };
    let out = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={INBOUND_TCP_RULE_NAME}"),
            "dir=in",
            "action=allow",
            &format!("program={exe}"),
            "protocol=tcp",
            "enable=yes",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            info!(exe = %exe, "tun: inbound TCP firewall rule added (fixWindowsFirewall)");
        }
        Ok(o) => {
            warn!(
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "tun: failed to add inbound TCP firewall rule (TCP through TUN may be blocked by Windows Firewall)"
            );
        }
        Err(e) => {
            warn!(err = %e, "tun: failed to run netsh for inbound TCP firewall rule");
        }
    }
}

/// 删除自身 exe 的入站 TCP 放行规则（幂等）。
fn remove_inbound_tcp_firewall_rule() {
    Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={INBOUND_TCP_RULE_NAME}"),
        ])
        .output()
        .ok();
}

/// 为自身 exe 添加入站 UDP ALLOW 防火墙规则。Windows 防火墙默认入站
/// 策略是 BLOCK，部分场景下 QUIC/hysteria2 服务端响应包或 DNS UDP 响应
/// 会被拦截，导致 QUIC connect 永远卡住、DNS UDP 查询全超时。规则限定
/// program=<自身 exe> + protocol=udp，收敛暴露面（对齐 sing-tun
/// fixWindowsFirewall 的 TCP+UDP 双放行）。
fn add_inbound_udp_firewall_rule() {
    remove_inbound_udp_firewall_rule();
    let Some(exe) = current_exe_path() else {
        warn!("tun: cannot resolve current exe path, skip inbound UDP firewall rule");
        return;
    };
    let out = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={INBOUND_UDP_RULE_NAME}"),
            "dir=in",
            "action=allow",
            &format!("program={exe}"),
            "protocol=udp",
            "enable=yes",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            info!(exe = %exe, "tun: inbound UDP firewall rule added");
        }
        Ok(o) => {
            warn!(
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "tun: failed to add inbound UDP firewall rule (QUIC/DNS UDP responses may be blocked by Windows Firewall)"
            );
        }
        Err(e) => {
            warn!(err = %e, "tun: failed to run netsh for inbound UDP firewall rule");
        }
    }
}

/// 删除自身 exe 的入站 UDP 放行规则（幂等）。
fn remove_inbound_udp_firewall_rule() {
    Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={INBOUND_UDP_RULE_NAME}"),
        ])
        .output()
        .ok();
}

/// 物理默认网关 IPv4（GetIpForwardTable2 原生查询，替代 Get-NetRoute PowerShell）。
/// 不排除 TUN 接口——用于 exclude 路由与默认路由变化监控；调用方需注意若 TUN
/// 已添加 metric=0 默认路由，本函数会返回 TUN 网关（与旧 PowerShell 行为一致）。
fn get_default_gateway_v4() -> Option<Ipv4Addr> {
    win32_route::find_default_route(AF_INET, None)
        .and_then(|(_, gw)| match gw {
            IpAddr::V4(v) => Some(v),
            _ => None,
        })
}

/// 物理默认网关 IPv6（GetIpForwardTable2 原生查询，替代 Get-NetRoute PowerShell）。
fn get_default_gateway_v6() -> Option<Ipv6Addr> {
    win32_route::find_default_route(AF_INET6, None)
        .and_then(|(_, gw)| match gw {
            IpAddr::V6(v) => Some(v),
            _ => None,
        })
}

/// 查询当前系统默认网关 (v4, v6)。默认路由变化监控用。
pub async fn current_default_gateways() -> (Option<IpAddr>, Option<IpAddr>) {
    tokio::task::spawn_blocking(|| {
        (
            get_default_gateway_v4().map(IpAddr::V4),
            get_default_gateway_v6().map(IpAddr::V6),
        )
    })
    .await
    .unwrap_or((None, None))
}

/// 解析 IPv4 CIDR 为 (addr, prefix_len)。
fn parse_cidr_v4(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let pl: u8 = len_str.parse().ok()?;
    if pl > 32 {
        return None;
    }
    Some((ip, pl))
}

/// 解析 IPv6 CIDR 为 (addr, prefix_len)。
fn parse_cidr_v6(s: &str) -> Option<(Ipv6Addr, u8)> {
    let (ip_str, len_str) = s.split_once('/')?;
    let ip: Ipv6Addr = ip_str.parse().ok()?;
    let pl: u8 = len_str.parse().ok()?;
    if pl > 128 {
        return None;
    }
    Some((ip, pl))
}

/// 等待 wintun 接口可见（创建后存在短暂延迟）。
/// 用原生 get_if_index（ConvertInterfaceNameToLuidW → ConvertInterfaceLuidToIndex）
/// 轮询，替代旧实现每轮 sh 一次 PowerShell Get-NetAdapter（冷启动 200ms+/次）。
fn wait_for_interface(if_name: &str) {
    for _ in 0..30 {
        if win32_route::get_if_index(if_name).is_some() {
            return;
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

struct ReflexBypassRoute {
    #[allow(dead_code)]
    if_idx: u32,
    #[allow(dead_code)]
    gateway: IpAddr,
    #[allow(dead_code)]
    src_ip: IpAddr,
}

struct ReflexBypass {
    #[allow(dead_code)]
    v4: Option<ReflexBypassRoute>,
    #[allow(dead_code)]
    v6: Option<ReflexBypassRoute>,
}

/// 添加 IPv4 bypass host route：把 reflex 主机源 IP 经物理网关走 host route，
/// metric=0 优先于 TUN 默认路由，防止 reflex 自身出站环回 TUN。
/// CreateIpForwardEntry2 优先，netsh fallback（对齐 add_auto_routes 风格）。
fn add_bypass_route_v4(if_idx: u32, src: Ipv4Addr, gw: Ipv4Addr) -> bool {
    // 幂等：先删后加（上次异常退出残留 / 删除失败时避免"已存在"失败）
    let _ = win32_route::delete_route_v4(None, Some(if_idx), src, 32, gw);
    if win32_route::create_route_v4(None, Some(if_idx), src, 32, gw, 0).is_ok() {
        return true;
    }
    let _ = Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "delete",
            "route",
            &format!("{src}/32"),
            &if_idx.to_string(),
        ])
        .output();
    Command::new("netsh")
        .args([
            "interface",
            "ipv4",
            "add",
            "route",
            &format!("{src}/32"),
            &if_idx.to_string(),
            &gw.to_string(),
            "metric=0",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 添加 IPv6 bypass host route（同 v4 语义，补 IPv6 环回防护缺口）。
fn add_bypass_route_v6(if_idx: u32, src: Ipv6Addr, gw: Ipv6Addr) -> bool {
    let _ = win32_route::delete_route_v6(None, Some(if_idx), src, 128, gw);
    if win32_route::create_route_v6(None, Some(if_idx), src, 128, gw, 0).is_ok() {
        return true;
    }
    let _ = Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "delete",
            "route",
            &format!("{src}/128"),
            &if_idx.to_string(),
        ])
        .output();
    Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "add",
            "route",
            &format!("{src}/128"),
            &if_idx.to_string(),
            &gw.to_string(),
            "metric=0",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// auto_route 将默认路由指向 TUN 后，reflex 自身出站流量也会进入 TUN 形成循环。
/// 解决：在添加 TUN 路由前，为主机源 IP 添加 host route 走物理网关（metric=0，
/// 比 TUN 默认路由优先），并登记物理接口 ifIndex + 源 IP 给 interface_finder
/// 供 IP_UNICAST_IF / bind 源 IP 双保险（对齐 sing-tun Windows 思路）。
///
/// 探测全部走原生 GetIpForwardTable2 / GetUnicastIpAddressTable（替代旧实现的
/// 4 次 PowerShell sh，消除冷启动延迟与 locale 解析问题）；bypass 路由统一走
/// CreateIpForwardEntry2（与 add_auto_routes 一致），并补 IPv6 bypass（旧实现
/// 只给 IPv4 加 bypass 路由，IPv6 仅登记 ifIndex，Win11 23H2 仍可能环回）。
fn add_reflex_bypass(if_name: &str) -> ReflexBypass {
    let tun_if_index = win32_route::get_if_index(if_name);

    // ── IPv4 ──
    // 探测物理默认路由所在接口 + 网关（排除 TUN 自身，防残留路由导致死环）
    let v4 = win32_route::find_default_route(AF_INET, tun_if_index)
        .and_then(|(if_idx, gw)| match gw {
            IpAddr::V4(g) => Some((if_idx, g)),
            _ => None,
        })
        .and_then(|(if_idx, gw)| {
            // 探测物理接口首选源 IP
            let src = win32_route::find_source_ip(AF_INET, if_idx)
                .and_then(|ip| match ip {
                    IpAddr::V4(v) => Some(v),
                    _ => None,
                })?;
            Some((if_idx, gw, src))
        });

    let v4 = if let Some((if_idx, gw, src)) = v4 {
        // 登记给 outbound interface_finder：IP_UNICAST_IF + 源 IP bind 双保险，
        // 避免仅设 IP_UNICAST_IF 在 Win11 23H2 等版本不能可靠钉住 TCP connect。
        crate::outbound::common::interface_finder::windows_iface::set_physical_if_index_v4(if_idx);
        crate::outbound::common::interface_finder::windows_iface::set_physical_src_ip_v4(src);
        info!(if_idx, gateway = %gw, src_ip = %src,
              "tun: registered physical IPv4 interface + source IP");

        if add_bypass_route_v4(if_idx, src, gw) {
            info!(src_ip = %src, gateway = %gw, if_idx,
                  "tun: added reflex bypass route v4");
            Some(ReflexBypassRoute {
                if_idx,
                gateway: IpAddr::V4(gw),
                src_ip: IpAddr::V4(src),
            })
        } else {
            warn!(src_ip = %src, gateway = %gw, if_idx,
                  "tun: failed to add reflex bypass route v4");
            None
        }
    } else {
        warn!("tun: could not determine physical IPv4 gateway/source for bypass route");
        None
    };

    // ── IPv6（与 IPv4 独立；很多机器无 IPv6 出口，探测不到属正常，安静跳过）──
    let v6 = win32_route::find_default_route(AF_INET6, tun_if_index)
        .and_then(|(if_idx, gw)| match gw {
            IpAddr::V6(g) => Some((if_idx, g)),
            _ => None,
        })
        .and_then(|(if_idx, gw)| {
            let src = win32_route::find_source_ip(AF_INET6, if_idx)
                .and_then(|ip| match ip {
                    IpAddr::V6(v) => Some(v),
                    _ => None,
                })?;
            Some((if_idx, gw, src))
        });

    let v6 = if let Some((if_idx, gw, src)) = v6 {
        crate::outbound::common::interface_finder::windows_iface::set_physical_if_index_v6(if_idx);
        crate::outbound::common::interface_finder::windows_iface::set_physical_src_ip_v6(src);
        info!(if_idx, gateway = %gw, src_ip = %src,
              "tun: registered physical IPv6 interface + source IP");

        if add_bypass_route_v6(if_idx, src, gw) {
            info!(src_ip = %src, gateway = %gw, if_idx,
                  "tun: added reflex bypass route v6");
            Some(ReflexBypassRoute {
                if_idx,
                gateway: IpAddr::V6(gw),
                src_ip: IpAddr::V6(src),
            })
        } else {
            warn!(src_ip = %src, gateway = %gw, if_idx,
                  "tun: failed to add reflex bypass route v6");
            None
        }
    } else {
        info!("tun: no physical IPv6 gateway/source (skipping IPv6 bypass route)");
        None
    };

    ReflexBypass { v4, v6 }
}

// ── setup / teardown ──────────────────────────────────────────────────────────

/// 计算 IPv4 地址的下一个地址（对齐 sing-tun HasNextAddress）。
fn next_v4(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let v = u32::from(ip);
    if v == u32::MAX {
        None
    } else {
        Some(Ipv4Addr::from(v + 1))
    }
}

/// TUN 服务端地址（网关/DNS）：第一个 v4 地址的下一个。
/// 对齐 sing-tun Inet4GatewayAddr / Inet4DNSAddress 的 Windows 默认行为。
/// `inet4_gateway_address` 覆盖项优先（对齐 sing-tun Inet4GatewayAddr）。
fn server_addr_v4(cfg: &TunInboundConfig) -> Option<Ipv4Addr> {
    if let Some(gw) = &cfg.inet4_gateway_address {
        if let Ok(ip) = gw.parse::<Ipv4Addr>() {
            return Some(ip);
        }
        warn!(value = %gw, "tun: invalid inet4_gateway_address, falling back to auto");
    }
    cfg.address.iter().find_map(|s| match parse_addr_prefix(s) {
        Some((IpAddr::V4(ip), _)) => next_v4(ip),
        _ => None,
    })
}

fn server_addr_v6(cfg: &TunInboundConfig) -> Option<Ipv6Addr> {
    if let Some(gw) = &cfg.inet6_gateway_address {
        if let Ok(ip) = gw.parse::<Ipv6Addr>() {
            return Some(ip);
        }
        warn!(value = %gw, "tun: invalid inet6_gateway_address, falling back to auto");
    }
    cfg.address.iter().find_map(|s| match parse_addr_prefix(s) {
        // std 的 Ipv6Addr 无加法方法，用 u128 运算（与 mod.rs has_next_addr_v6 一致）
        Some((IpAddr::V6(ip), _)) => Some(Ipv6Addr::from(u128::from(ip).wrapping_add(1))),
        _ => None,
    })
}

/// 按地址族用 netsh 设置接口 DNS（`netsh interface ipv4|ipv6 set/add dnsservers`）。
/// 返回是否全部成功。
fn set_dns_servers_family_netsh(if_name: &str, family: &str, addrs: &[IpAddr]) -> bool {
    debug_assert!(!addrs.is_empty());
    let mut ok = Command::new("netsh")
        .args([
            "interface",
            family,
            "set",
            "dnsservers",
            &format!("name={if_name}"),
            "source=static",
            &format!("address={}", addrs[0]),
            "validate=no",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    for a in &addrs[1..] {
        let added = Command::new("netsh")
            .args([
                "interface",
                family,
                "add",
                "dnsservers",
                &format!("name={if_name}"),
                &format!("address={a}"),
                "validate=no",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        ok = ok && added;
    }
    ok
}

/// 按地址族用 PowerShell 设置接口 DNS（Set-DnsClientServerAddress 兜底）。
fn set_dns_servers_family_ps(idx: u32, family: &str, addrs: &[IpAddr]) -> bool {
    let list = addrs
        .iter()
        .map(|a| format!("'{a}'"))
        .collect::<Vec<_>>()
        .join(",");
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Set-DnsClientServerAddress -InterfaceIndex {idx} \
                 -AddressFamily {family} -ServerAddresses @({list}) -ErrorAction Stop"
            ),
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 把 auto_route 路由添加到 TUN 接口（Win32 优先，netsh fallback）。
/// 对齐 sing-tun addRouteList：NextHop=网关（server addr），metric=0。
fn add_auto_routes(
    cfg: &TunInboundConfig,
    if_name: &str,
    luid: Option<NET_LUID_LH>,
    if_index: Option<u32>,
    has_v4: bool,
    has_v6: bool,
    state: &mut SetupState,
) {
    let gw_v4 = server_addr_v4(cfg).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let gw_v6 = server_addr_v6(cfg).unwrap_or(Ipv6Addr::UNSPECIFIED);
    if has_v4 {
        for cidr in tun_routes_v4(cfg) {
            let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                (luid, if_index, parse_cidr_v4(&cidr))
            {
                win32_route::create_route_v4(Some(l), Some(i), dest, pl, gw_v4, 0).is_ok()
            } else {
                false
            };
            if !win32_ok {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "add",
                        "route",
                        &cidr,
                        if_name,
                        "metric=0",
                    ])
                    .output()
                    .ok();
            }
            state.routes_v4.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv4 routes added (metric=0)");
    }
    if has_v6 {
        for cidr in tun_routes_v6(cfg) {
            let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                (luid, if_index, parse_cidr_v6(&cidr))
            {
                win32_route::create_route_v6(Some(l), Some(i), dest, pl, gw_v6, 0).is_ok()
            } else {
                false
            };
            if !win32_ok {
                Command::new("netsh")
                    .args([
                        "interface",
                        "ipv6",
                        "add",
                        "route",
                        &cidr,
                        if_name,
                        "metric=0",
                    ])
                    .output()
                    .ok();
            }
            state.routes_v6.push(cidr);
        }
        info!(interface = %if_name, "tun: IPv6 routes added (metric=0)");
    }
}

/// 把 route_exclude_address 路由添加到物理网关（Win32 优先，netsh fallback）。
/// 修复 B3：旧实现 netsh 参数错位（网关被放在接口名位置），命令恒失败；
/// teardown 也因缺 interface 参数删不干净。现在统一走 CreateIpForwardEntry2，
/// fallback netsh 也修正为 `prefix interface nexthop metric` 顺序。
fn add_exclude_routes(
    cfg: &TunInboundConfig,
    if_name: &str,
    luid: Option<NET_LUID_LH>,
    if_index: Option<u32>,
    has_v4: bool,
    has_v6: bool,
    state: &mut SetupState,
) {
    if cfg.route_exclude_address.is_empty() {
        return;
    }
    let gw_phys_v4 = get_default_gateway_v4();
    let gw_phys_v6 = get_default_gateway_v6();
    if has_v4 {
        if let Some(gw) = gw_phys_v4 {
            for cidr in exclude_routes_v4(cfg) {
                let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                    (luid, if_index, parse_cidr_v4(&cidr))
                {
                    win32_route::create_route_v4(Some(l), Some(i), dest, pl, gw, 0).is_ok()
                } else {
                    false
                };
                if !win32_ok {
                    // 参数顺序：prefix interface nexthop metric（B3 修复）
                    Command::new("netsh")
                        .args([
                            "interface",
                            "ipv4",
                            "add",
                            "route",
                            &cidr,
                            if_name,
                            &gw.to_string(),
                            "metric=0",
                        ])
                        .output()
                        .ok();
                }
                // 记录 "cidr|gateway"：DeleteIpForwardEntry2 的 key 含 NextHop，
                // teardown 必须用创建时的同一网关；若 teardown 时重新查询默认
                // 网关（默认路由可能已切换），删除会静默失败导致路由泄漏。
                state.exclude_routes_v4.push(format!("{cidr}|{gw}"));
            }
        } else {
            warn!("tun: no IPv4 default gateway, exclude routes skipped");
        }
    }
    if has_v6 {
        if let Some(gw) = gw_phys_v6 {
            for cidr in exclude_routes_v6(cfg) {
                let win32_ok = if let (Some(l), Some(i), Some((dest, pl))) =
                    (luid, if_index, parse_cidr_v6(&cidr))
                {
                    win32_route::create_route_v6(Some(l), Some(i), dest, pl, gw, 0).is_ok()
                } else {
                    false
                };
                if !win32_ok {
                    Command::new("netsh")
                        .args([
                            "interface",
                            "ipv6",
                            "add",
                            "route",
                            &cidr,
                            if_name,
                            &gw.to_string(),
                            "metric=0",
                        ])
                        .output()
                        .ok();
                }
                state.exclude_routes_v6.push(format!("{cidr}|{gw}"));
            }
        } else {
            warn!("tun: no IPv6 default gateway, exclude routes skipped");
        }
    }
}

/// 旧版本遗留的 netsh advfirewall strict 规则名（新实现全部走 WFP，清理残留）。
const LEGACY_STRICT_RULE_NAMES: &[&str] = &[
    "reflex-tun-strict-allow-v4",
    "reflex-tun-strict-allow-v6",
    "reflex-tun-strict-allow-tun-v4",
    "reflex-tun-strict-block-tun-v4",
    "reflex-tun-strict-block-v4",
    "reflex-tun-strict-block-v6",
    "reflex-tun-strict-allow-udp",
    "reflex-tun-strict-allow-tcp",
    "reflex-tun-strict-allow-tun",
    "reflex-tun-strict-block-udp",
    "reflex-tun-strict-block-tcp",
    "reflex-tun-strict-block-tun",
];

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
    let _reflex_bypass = add_reflex_bypass(if_name);

    // F4 修复（对齐 sing-tun stack_system_windows.go fixWindowsFirewall）：
    // system/mixed 栈会在 TUN 地址上监听 TCP，客户端连接到达该监听器时属于
    // 入站连接，Windows 防火墙（公用/专用配置文件的默认入站策略为 Block）
    // 会拦截 SYN，导致 TUN 的 TCP 流量全部握手超时。sing-tun 专门为自身
    // exe 添加了入站 TCP ALLOW 规则；reflex 此前缺失该逻辑，gvisor 栈
    // 无 OS 监听器不需要。
    if cfg.stack != "gvisor" {
        add_inbound_tcp_firewall_rule();
    }
    // UDP 入站放行规则与 TUN 栈类型无关：QUIC/hysteria2 与 DNS UDP 上游的
    // 响应包都从物理网卡进入 reflex 自身 socket，Windows 防火墙默认入站
    // BLOCK 会拦截这些响应导致 QUIC connect / DNS UDP 永久超时
    // （观测现象：日志中只有 "starting QUIC connect" 后再无任何后续）。
    // 与 TCP 规则不同，gvisor 栈同样需要此规则，因为这是物理网卡层面的入站。
    add_inbound_udp_firewall_rule();

    // 解析配置地址
    let mut v4_addrs: Vec<(Ipv4Addr, u8)> = Vec::new();
    let mut v6_addrs: Vec<(Ipv6Addr, u8)> = Vec::new();
    for addr_str in &cfg.address {
        match parse_addr_prefix(addr_str) {
            Some((IpAddr::V4(ip), pl)) => v4_addrs.push((ip, pl)),
            Some((IpAddr::V6(ip), pl)) => v6_addrs.push((ip, pl)),
            None => warn!(addr = %addr_str, "tun: invalid address prefix"),
        }
    }
    let has_v4 = !v4_addrs.is_empty();
    let has_v6 = !v6_addrs.is_empty();

    // 接口索引 + LUID（Win32，替代 PowerShell 查询）
    let if_index = win32_route::get_if_index(if_name);
    // wintun 接口的 InterfaceAlias 可能与 FriendlyName 不一致，
    // ConvertInterfaceNameToLuidW 会返回 err=123；此时用 ifIndex 反查 LUID
    // 兜底，保证 flush_unicast_addresses / 路由等 LUID 路径可用。
    let if_luid = win32_route::get_interface_luid(if_name)
        .or_else(|| if_index.and_then(win32_route::luid_from_index));
    if if_index.is_none() || if_luid.is_none() {
        warn!(interface = %if_name, "tun: interface not resolvable via Win32 API (netsh fallback)");
    }

    // ── 1. 配置 IP 地址：先 flush 再 add（对齐 sing-tun SetIPAddressesForFamily）──
    // 修复 B4：旧实现 netsh `ipv6 add address` 累积堆叠，重启后 IPv6 地址成倍残留。
    if let Some(luid) = if_luid {
        if let Err(e) = win32_route::flush_unicast_addresses(luid) {
            warn!(err = %e, "tun: flush unicast addresses failed (continuing)");
        }
    }
    for (ip, pl) in &v4_addrs {
        if let Some(idx) = if_index {
            if win32_route::add_unicast_address(idx, *ip, *pl).is_ok() {
                info!(interface = %if_name, ip = %ip, "tun: IPv4 address configured (Win32)");
                continue;
            }
        }
        // netsh fallback
        let mask = prefix_len_to_mask_v4(*pl);
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
        if ok {
            info!(interface = %if_name, ip = %ip, "tun: IPv4 address configured (netsh)");
        } else {
            warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv4 address");
        }
    }
    for (ip, pl) in &v6_addrs {
        if let Some(idx) = if_index {
            if win32_route::add_unicast_address_v6(idx, *ip, *pl).is_ok() {
                info!(interface = %if_name, ip = %ip, "tun: IPv6 address configured (Win32)");
                continue;
            }
        }
        let ok = Command::new("netsh")
            .args([
                "interface",
                "ipv6",
                "add",
                "address",
                if_name,
                &format!("{ip}/{pl}"),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            info!(interface = %if_name, ip = %ip, "tun: IPv6 address configured (netsh)");
        } else {
            warn!(interface = %if_name, ip = %ip, "tun: failed to set IPv6 address");
        }
    }

    // ── 2. 接口参数（对齐 sing-tun configure()：DAD 关闭 / 路由器发现关闭 /
    //        无状态配置关闭 / NlMtu=MTU / AutoRoute 时 Metric=0；IPv4 开转发）──
    if let Some(luid) = if_luid {
        if has_v4 {
            if let Err(e) = win32_route::configure_interface(luid, AF_INET, cfg.mtu, true, true) {
                warn!(err = %e, "tun: configure IPv4 interface failed");
            }
        }
        if has_v6 {
            if let Err(e) = win32_route::configure_interface(luid, AF_INET6, cfg.mtu, true, false) {
                warn!(err = %e, "tun: configure IPv6 interface failed");
            }
        }
    }

    // ── 3. 接口 DNS（对齐 sing-tun configure()：DNS = server addr；禁 DNS 注册）──
    // 修复 M1：旧实现从不设置 TUN 接口 DNS，auto_route 后系统 DNS 查询进 TUN 无应答。
    // dns_servers 覆盖项优先（按族分别下发，对齐 sing-tun Inet4DNSAddress/
    // Inet6DNSAddress）；未配置时沿用 TUN server addr。
    if let Some(idx) = if_index {
        let mut dns_v4: Vec<IpAddr> = Vec::new();
        let mut dns_v6: Vec<IpAddr> = Vec::new();
        if !cfg.dns_servers.is_empty() {
            for s in &cfg.dns_servers {
                match s.parse::<IpAddr>() {
                    Ok(IpAddr::V4(ip)) => dns_v4.push(IpAddr::V4(ip)),
                    Ok(IpAddr::V6(ip)) => dns_v6.push(IpAddr::V6(ip)),
                    Err(_) => warn!(value = %s, "tun: invalid dns_servers entry, ignored"),
                }
            }
        }
        if dns_v4.is_empty() && dns_v6.is_empty() {
            if has_v4 {
                if let Some(ip) = server_addr_v4(cfg) {
                    dns_v4.push(IpAddr::V4(ip));
                }
            }
            if has_v6 {
                if let Some(ip) = server_addr_v6(cfg) {
                    dns_v6.push(IpAddr::V6(ip));
                }
            }
        }
        if !dns_v4.is_empty() || !dns_v6.is_empty() {
            // Win32 SetInterfaceDnsSettings 不区分地址族，混合列表一次下发
            let all_dns: Vec<IpAddr> = dns_v4.iter().chain(dns_v6.iter()).cloned().collect();
            if let Err(e) = win32_route::set_interface_dns(idx, &all_dns) {
                // Win32 SetInterfaceDnsSettings 对 wintun 接口偶发 E_INVALIDARG
                // （0x80070057，接口 GUID/版本不匹配），按族用 netsh 下发、
                // PowerShell Set-DnsClientServerAddress 兜底（clash-rs 同款做法）。
                warn!(err = %e, "tun: set interface DNS via Win32 failed, trying netsh/PowerShell");
                let mut ok = true;
                if !dns_v4.is_empty()
                    && !(set_dns_servers_family_netsh(if_name, "ipv4", &dns_v4)
                        || set_dns_servers_family_ps(idx, "IPv4", &dns_v4))
                {
                    ok = false;
                }
                if !dns_v6.is_empty()
                    && !(set_dns_servers_family_netsh(if_name, "ipv6", &dns_v6)
                        || set_dns_servers_family_ps(idx, "IPv6", &dns_v6))
                {
                    ok = false;
                }
                if !ok {
                    warn!(
                        interface = %if_name,
                        "tun: failed to set interface DNS (Win32 + netsh + PowerShell)"
                    );
                }
            }
        }
        if let Err(e) = win32_route::disable_dns_registration(idx) {
            warn!(err = %e, "tun: disable DNS registration failed");
        }
    }

    // ── 4. auto_route 路由（metric=0，NextHop=网关，对齐 sing-tun addRouteList）──
    add_auto_routes(cfg, if_name, if_luid, if_index, has_v4, has_v6, &mut state);

    // ── 5. route_exclude_address（NextHop=物理网关 metric=0；B3 修复）────────
    add_exclude_routes(cfg, if_name, if_luid, if_index, has_v4, has_v6, &mut state);

    // ── 6. strict_route：完整 WFP 会话（对齐 sing-tun Start()）───────────────
    // 修复 B2：旧实现 WFP 过滤器缺 subLayerKey 导致添加失败且无自身进程/TUN permit。
    if cfg.strict_route {
        // 清理旧版本遗留的 netsh advfirewall 规则（新实现全部走 WFP）
        for name in LEGACY_STRICT_RULE_NAMES {
            Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={name}"),
                ])
                .output()
                .ok();
        }
        state.wfp_session =
            wfp::create_strict_session(current_exe_path(), if_index, has_v4, has_v6);
    }

    // 刷新 DNS 缓存
    Command::new("ipconfig").args(["/flushdns"]).output().ok();

    info!(interface = %if_name, "tun: auto_route configured (Windows)");
    Ok(state)
}

/// 删除 reflex bypass host route（v4 + v6）。原生探测 + DeleteIpForwardEntry2，
/// netsh fallback。与 add_reflex_bypass 对称——网络未变化时删除的是同一条路由；
/// 网络变化则探测到新的 (if_idx, gw, src)，旧路由残留（与旧 PS 实现行为一致）。
fn remove_reflex_bypass(if_name: &str) {
    let tun_if_index = win32_route::get_if_index(if_name);

    // ── IPv4 ──
    let v4 = win32_route::find_default_route(AF_INET, tun_if_index)
        .and_then(|(if_idx, gw)| match gw {
            IpAddr::V4(g) => Some((if_idx, g)),
            _ => None,
        })
        .and_then(|(if_idx, gw)| {
            let src = win32_route::find_source_ip(AF_INET, if_idx)
                .and_then(|ip| match ip {
                    IpAddr::V4(v) => Some(v),
                    _ => None,
                })?;
            Some((if_idx, gw, src))
        });

    if let Some((if_idx, gw, src)) = v4 {
        if win32_route::delete_route_v4(None, Some(if_idx), src, 32, gw).is_err() {
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    &format!("{src}/32"),
                    &if_idx.to_string(),
                ])
                .output();
        }
        info!(reflex_ip = %src, "tun: removed reflex bypass route v4");
    }

    // ── IPv6 ──
    let v6 = win32_route::find_default_route(AF_INET6, tun_if_index)
        .and_then(|(if_idx, gw)| match gw {
            IpAddr::V6(g) => Some((if_idx, g)),
            _ => None,
        })
        .and_then(|(if_idx, gw)| {
            let src = win32_route::find_source_ip(AF_INET6, if_idx)
                .and_then(|ip| match ip {
                    IpAddr::V6(v) => Some(v),
                    _ => None,
                })?;
            Some((if_idx, gw, src))
        });

    if let Some((if_idx, gw, src)) = v6 {
        if win32_route::delete_route_v6(None, Some(if_idx), src, 128, gw).is_err() {
            let _ = Command::new("netsh")
                .args([
                    "interface",
                    "ipv6",
                    "delete",
                    "route",
                    &format!("{src}/128"),
                    &if_idx.to_string(),
                ])
                .output();
        }
        info!(reflex_ip = %src, "tun: removed reflex bypass route v6");
    }
}

pub fn teardown(cfg: &TunInboundConfig, if_name: &str, state: &SetupState) -> anyhow::Result<()> {
    info!(interface = %if_name, routes_v4 = state.routes_v4.len(), routes_v6 = state.routes_v6.len(), exclude_v4 = state.exclude_routes_v4.len(), exclude_v6 = state.exclude_routes_v6.len(), "tun: teardown starting (Windows)");
    let if_index = win32_route::get_if_index(if_name);
    let if_luid = win32_route::get_interface_luid(if_name);

    // 清理 reflex bypass 路由
    remove_reflex_bypass(if_name);

    // 清理 auto_route 路由（DeleteIpForwardEntry2 的 key 含 NextHop，
    // 必须与创建时一致：auto 路由 NextHop=server addr，exclude 路由 NextHop=物理网关）
    let gw_v4 = server_addr_v4(cfg).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let gw_v6 = server_addr_v6(cfg).unwrap_or(Ipv6Addr::UNSPECIFIED);
    for cidr in &state.routes_v4 {
        let win32_ok = if let (Some(l), Some((dest, pl))) = (if_luid, parse_cidr_v4(cidr)) {
            win32_route::delete_route_v4(Some(l), if_index, dest, pl, gw_v4).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }
    for cidr in &state.routes_v6 {
        let win32_ok = if let (Some(l), Some((dest, pl))) = (if_luid, parse_cidr_v6(cidr)) {
            win32_route::delete_route_v6(Some(l), if_index, dest, pl, gw_v6).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }

    // 清理 exclude 路由（修复 B3：旧实现删除命令缺 interface 参数，永远删不掉）。
    // 修复：NextHop 使用 setup 时记录的网关（"cidr|gw" 格式）；仅旧格式/无
    // 记录时才回退到重新查询当前默认网关（默认网关切换时旧查询会失败）。
    let gw_phys_v4_fallback = get_default_gateway_v4();
    let gw_phys_v6_fallback = get_default_gateway_v6();
    for entry in &state.exclude_routes_v4 {
        let (cidr, recorded_gw) = match entry.split_once('|') {
            Some((c, g)) => (c, g.parse::<Ipv4Addr>().ok()),
            None => (entry.as_str(), None),
        };
        let gw = recorded_gw.or(gw_phys_v4_fallback);
        let win32_ok = if let (Some(l), Some(gw), Some((dest, pl))) =
            (if_luid, gw, parse_cidr_v4(cidr))
        {
            win32_route::delete_route_v4(Some(l), if_index, dest, pl, gw).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }
    for entry in &state.exclude_routes_v6 {
        let (cidr, recorded_gw) = match entry.split_once('|') {
            Some((c, g)) => (c, g.parse::<Ipv6Addr>().ok()),
            None => (entry.as_str(), None),
        };
        let gw = recorded_gw.or(gw_phys_v6_fallback);
        let win32_ok = if let (Some(l), Some(gw), Some((dest, pl))) =
            (if_luid, gw, parse_cidr_v6(cidr))
        {
            win32_route::delete_route_v6(Some(l), if_index, dest, pl, gw).is_ok()
        } else {
            false
        };
        if !win32_ok {
            Command::new("netsh")
                .args(["interface", "ipv6", "delete", "route", cidr, if_name])
                .output()
                .ok();
        }
    }

    // 清理防火墙规则
    if cfg.strict_route {
        // 释放 WFP 会话（会话 drop 时通过 DYNAMIC 标志自动移除所有过滤器）
        if state.wfp_session != 0 {
            unsafe { wfp::drop_wfp_session(state.wfp_session) };
        }
        // 兼容旧版本 netsh 规则名清除
        for name in LEGACY_STRICT_RULE_NAMES {
            Command::new("netsh")
                .args([
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    &format!("name={name}"),
                ])
                .output()
                .ok();
        }
    }
    // F4：移除自身 exe 的入站 TCP 放行规则（幂等；即使 setup 阶段未添加，
    // 无害删除）。无论栈类型都尝试清理，避免非 auto_route 退出时残留。
    remove_inbound_tcp_firewall_rule();
    // 同步移除 UDP 放行规则（与 setup 中 add_inbound_udp_firewall_rule 对应）。
    remove_inbound_udp_firewall_rule();

    Command::new("ipconfig").args(["/flushdns"]).output().ok();
    info!(interface = %if_name, "tun: auto_route cleaned up (Windows)");
    Ok(())
}

pub fn update_routes(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
    // 修复 M3：旧实现是 no-op，路由无法热更新。
    // 对齐 sing-tun UpdateRouteOptions：flush 本接口全部路由后按新配置重建。
    let Some(luid) = win32_route::get_interface_luid(if_name) else {
        warn!(interface = %if_name, "tun: update_routes: interface not resolvable");
        return Ok(());
    };
    if let Err(e) = win32_route::flush_routes(luid) {
        warn!(err = %e, "tun: update_routes: flush routes failed (continuing)");
    }
    let if_index = win32_route::get_if_index(if_name);
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
    add_auto_routes(
        cfg,
        if_name,
        Some(luid),
        if_index,
        has_v4,
        has_v6,
        &mut state,
    );
    add_exclude_routes(
        cfg,
        if_name,
        Some(luid),
        if_index,
        has_v4,
        has_v6,
        &mut state,
    );
    Command::new("ipconfig").args(["/flushdns"]).output().ok();
    info!(interface = %if_name, "tun: routes updated (Windows)");
    Ok(())
}
