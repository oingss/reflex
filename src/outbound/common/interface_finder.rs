#[cfg(target_os = "linux")]
pub mod linux {
    use std::net::{IpAddr, Ipv4Addr};

    /// 一张网卡的摘要信息。
    #[derive(Debug, Clone)]
    pub struct Interface {
        pub name: String,
        /// 该网卡绑定的所有地址及前缀长度（prefix_len）
        pub addrs: Vec<(IpAddr, u8)>,
    }

    /// 读取所有本地网卡信息（通过 getifaddrs）。
    pub fn list_interfaces() -> Vec<Interface> {
        let mut result: Vec<Interface> = Vec::new();

        // 用 /proc/net/if_inet6 和 /proc/net/fib_trie 太繁琐；
        // 直接调用 getifaddrs(3) 最简洁，libc crate 已经有封装。
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                return result;
            }
            let mut ifa = ifap;
            while !ifa.is_null() {
                let ifa_ref = &*ifa;
                ifa = ifa_ref.ifa_next;

                if ifa_ref.ifa_addr.is_null() {
                    continue;
                }
                // 只关心 UP 的网卡
                if ifa_ref.ifa_flags & libc::IFF_UP as u32 == 0 {
                    continue;
                }

                let family = (*ifa_ref.ifa_addr).sa_family as i32;
                let (ip, prefix_len) = match family {
                    libc::AF_INET => {
                        let sa = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in);
                        let ip = IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)));
                        let prefix_len = if !ifa_ref.ifa_netmask.is_null() {
                            let nm = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in);
                            u32::from_be(nm.sin_addr.s_addr).count_ones() as u8
                        } else {
                            32
                        };
                        (ip, prefix_len)
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa_ref.ifa_addr as *const libc::sockaddr_in6);
                        let ip = IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr));
                        let prefix_len = if !ifa_ref.ifa_netmask.is_null() {
                            let nm = &*(ifa_ref.ifa_netmask as *const libc::sockaddr_in6);
                            nm.sin6_addr
                                .s6_addr
                                .iter()
                                .map(|b| b.count_ones() as u8)
                                .sum()
                        } else {
                            128
                        };
                        (ip, prefix_len)
                    }
                    _ => continue,
                };

                let name = std::ffi::CStr::from_ptr(ifa_ref.ifa_name)
                    .to_string_lossy()
                    .into_owned();

                // 跳过 loopback
                if ifa_ref.ifa_flags & libc::IFF_LOOPBACK as u32 != 0 {
                    continue;
                }

                if let Some(entry) = result.iter_mut().find(|i| i.name == name) {
                    entry.addrs.push((ip, prefix_len));
                } else {
                    result.push(Interface {
                        name,
                        addrs: vec![(ip, prefix_len)],
                    });
                }
            }
            libc::freeifaddrs(ifap);
        }
        result
    }

    /// 判断 `target` 是否属于 `iface` 的某个子网。
    fn addr_in_interface(iface: &Interface, target: IpAddr) -> bool {
        for (iface_ip, prefix_len) in &iface.addrs {
            if ip_in_subnet(*iface_ip, *prefix_len, target) {
                return true;
            }
        }
        false
    }

    /// 判断 `target` 是否属于以 `base` / `prefix_len` 描述的子网。
    fn ip_in_subnet(base: IpAddr, prefix_len: u8, target: IpAddr) -> bool {
        match (base, target) {
            (IpAddr::V4(b), IpAddr::V4(t)) => {
                if prefix_len == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(prefix_len as u32);
                let b32 = u32::from(b);
                let t32 = u32::from(t);
                (b32 >> shift) == (t32 >> shift)
            }
            (IpAddr::V6(b), IpAddr::V6(t)) => {
                if prefix_len == 0 {
                    return true;
                }
                let b128 = u128::from(b);
                let t128 = u128::from(t);
                let shift = 128u32.saturating_sub(prefix_len as u32);
                (b128 >> shift) == (t128 >> shift)
            }
            _ => false,
        }
    }

    /// 查找目标 IP 所属的网卡名称。
    /// 若目标 IP 恰好是某张网卡自身的地址，则跳过（避免 loopback 式连接）。
    pub fn find_interface_by_addr(target: IpAddr, interfaces: &[Interface]) -> Option<&Interface> {
        for iface in interfaces {
            // 目标 IP 不能是这张网卡自身的地址（避免自连）
            let is_self = iface.addrs.iter().any(|(ip, _)| *ip == target);
            if is_self {
                continue;
            }
            if addr_in_interface(iface, target) {
                return Some(iface);
            }
        }
        None
    }

    /// 从 `/proc/net/route` 读取默认路由（Destination=0, Mask=0）对应的网卡名。
    ///
    /// 文件格式（制表符分隔）：
    /// ```text
    /// Iface  Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    /// eth0   00000000    0101A8C0 0003  0      0   100    00000000 0   0      0
    /// ```
    /// Destination 和 Mask 均为小端十六进制，0x00000000 表示 0.0.0.0。
    pub fn default_route_interface() -> Option<String> {
        let content = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 8 {
                continue;
            }
            let dest = u32::from_str_radix(fields[1], 16).ok()?;
            let mask = u32::from_str_radix(fields[7], 16).ok()?;
            // 默认路由：Destination=0 且 Mask=0
            if dest == 0 && mask == 0 {
                return Some(fields[0].to_string());
            }
        }
        None
    }

    /// 对 socket fd 设置 `SO_BINDTODEVICE`，将 socket 绑定到指定网卡。
    ///
    /// # Safety
    /// `fd` 必须是有效的 socket 文件描述符。
    pub fn bind_to_interface(
        fd: std::os::unix::io::RawFd,
        iface_name: &str,
    ) -> std::io::Result<()> {
        let name = std::ffi::CString::new(iface_name)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SO_BINDTODEVICE 需要 CAP_NET_RAW 或 root；在 OpenWrt 上 sing-box/clash 也是这样做的
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr() as *const libc::c_void,
                name.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// 根据目标 IP 自动选择出口网卡并绑定 socket。
    ///
    /// 两步逻辑（与 sing-box AutoDetectInterfaceFunc 一致）：
    ///   1. 目标 IP 属于某张本地网卡的子网 → 绑定该网卡
    ///   2. 否则 → 绑定默认路由网卡
    ///
    /// 任何步骤失败都静默跳过（不影响连接，只是可能走错网卡）。
    pub fn auto_bind_interface(fd: std::os::unix::io::RawFd, target: IpAddr) {
        let interfaces = list_interfaces();

        // 步骤 1：目标 IP 是否属于某张本地网卡的子网
        if let Some(iface) = find_interface_by_addr(target, &interfaces) {
            let _ = bind_to_interface(fd, &iface.name.clone());
            return;
        }

        // 步骤 2：使用默认路由网卡
        if let Some(iface_name) = default_route_interface() {
            let _ = bind_to_interface(fd, &iface_name);
        }
    }
}

// ── 公开 API（跨平台）────────────────────────────────────────────────────────

/// 根据目标地址自动选择出口网卡并绑定 socket（仅 Linux 生效）。
///
/// `fd` 是已创建但尚未 connect 的 socket 文件描述符。
/// 非 Linux 平台为空操作，编译不产生任何代码。
#[cfg(unix)]
#[allow(unused_variables)]
pub fn auto_bind_interface_for_target(fd: std::os::unix::io::RawFd, target: std::net::IpAddr) {
    #[cfg(target_os = "linux")]
    linux::auto_bind_interface(fd, target);
}

/// 将 socket 绑定到指定网卡名称（仅 Linux 生效）。
///
/// 非 Linux 平台为空操作。
#[cfg(unix)]
#[allow(unused_variables)]
pub fn bind_to_interface(fd: std::os::unix::io::RawFd, iface_name: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    return linux::bind_to_interface(fd, iface_name);
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

// ── Windows：IP_UNICAST_IF / IPV6_UNICAST_IF 防环回 ────────────────────────
//
// 背景：Linux 用 SO_MARK + `ip rule not fwmark` 把 reflex 自身出站流量排除出
// TUN 的策略路由表；Windows 没有 SO_MARK 这个概念，auto_route 生效后
// （TUN 的默认路由 metric 比物理网卡更优）reflex 自身未绑定网卡的 direct
// 出站 socket 会被系统路由表重新导向 TUN，TUN 又把它当成"新连接"交回
// dispatcher → direct 出站再次发送，形成无限循环（连接数暴涨、CPU/内存
// 迅速耗尽，且往往需要手动重置网络才能恢复）。
//
// 对应方案：与 sing-box / sing-tun Windows 实现一致，用
// `setsockopt(IPPROTO_IP, IP_UNICAST_IF, <ifIndex>)`（IPv6 对应
// `IPPROTO_IPV6, IPV6_UNICAST_IF`）把 socket 强制绑定到 auto_route 生效前
// 探测到的物理网卡，无论系统路由表怎么变，这个 socket 的流量都只从物理网卡
// 发出，不会再被 TUN 截获。
//
// 物理网卡 ifIndex 由 `inbound::tun::platform::windows::setup()` 在添加 TUN
// 路由之前探测并写入这里（此时路由表还没被 TUN 接管，探测结果可信）。
#[cfg(target_os = "windows")]
pub mod windows_iface {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::RwLock;

    /// 0 表示"尚未探测到 / 不适用"，有效 ifIndex 从 1 开始。
    static PHYSICAL_IF_INDEX_V4: AtomicU32 = AtomicU32::new(0);
    static PHYSICAL_IF_INDEX_V6: AtomicU32 = AtomicU32::new(0);

    /// 物理网卡的源 IPv4 / IPv6 地址（auto_route 生效前探测到）。
    /// 关键：仅设 `IP_UNICAST_IF` 在部分 Windows 版本（含 Windows 11 23H2）
    /// 上不能可靠地把 TCP connect / UDP sendto 钉在物理网卡上 —— 路由表
    /// 仍按 destination 选路，TUN 默认路由会优先匹配，导致首包被 TUN 截获
    /// 形成 src=172.31.0.1（TUN 自身 IP）的环回。
    /// 显式 `bind(socket, <phys_src_ip>:0)` 把源 IP 钉到物理网卡，Windows
    /// 会按"源 IP 所属接口"匹配出站路由，从而绕开 TUN（对齐 clash-rs
    /// socket_helpers.rs 的 `socket.bind(&src.into())` + sing-box dialer 的
    /// Dialer.Control 显式 LocalAddr）。RwLock<Option<>> 以便 TUN setup
    /// 在不同阶段更新（IPv4 先于 IPv6 探测到）。
    static PHYSICAL_SRC_IP_V4: RwLock<Option<Ipv4Addr>> = RwLock::new(None);
    static PHYSICAL_SRC_IP_V6: RwLock<Option<Ipv6Addr>> = RwLock::new(None);

    /// 由 TUN 的 Windows setup() 在装 TUN 路由前调用，登记探测到的物理出口网卡。
    pub fn set_physical_if_index_v4(idx: u32) {
        PHYSICAL_IF_INDEX_V4.store(idx, Ordering::Relaxed);
    }

    pub fn set_physical_if_index_v6(idx: u32) {
        PHYSICAL_IF_INDEX_V6.store(idx, Ordering::Relaxed);
    }

    pub fn physical_if_index_v4() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V4.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    pub fn physical_if_index_v6() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V6.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    /// 登记物理网卡的源 IPv4 地址（auto_route 生效前由 TUN setup 探测）。
    /// 配合 `bind_to_physical_src_ip_*`：仅靠 IP_UNICAST_IF 在部分 Windows
    /// 版本不能保证 TCP connect 不走 TUN，必须显式 bind 到物理源 IP。
    pub fn set_physical_src_ip_v4(ip: Ipv4Addr) {
        *PHYSICAL_SRC_IP_V4.write().unwrap() = Some(ip);
    }

    pub fn set_physical_src_ip_v6(ip: Ipv6Addr) {
        *PHYSICAL_SRC_IP_V6.write().unwrap() = Some(ip);
    }

    pub fn physical_src_ip_v4() -> Option<Ipv4Addr> {
        *PHYSICAL_SRC_IP_V4.read().unwrap()
    }

    pub fn physical_src_ip_v6() -> Option<Ipv6Addr> {
        *PHYSICAL_SRC_IP_V6.read().unwrap()
    }

    /// 选定 `target` 对应的物理源 IP：v4 目标返回 v4 源，v6 目标返回 v6 源
    ///（dual-stack 时优先 v6；v6 源缺失时回退 v4 用于 v4-mapped 场景）。
    pub fn physical_src_ip_for(target: IpAddr) -> Option<IpAddr> {
        match target {
            IpAddr::V4(_) => physical_src_ip_v4().map(IpAddr::V4),
            IpAddr::V6(_) => physical_src_ip_v6()
                .map(IpAddr::V6)
                .or_else(|| physical_src_ip_v4().map(IpAddr::V4)),
        }
    }

    /// 把已创建（尚未 connect/send）的 socket 绑定到探测到的物理网卡。
    /// 没有探测到物理网卡（未触发 auto_route 防环回逻辑）时为空操作。
    ///
    /// 对齐 clash-rs `must_bind_socket_on_interface`（proxy/utils/platform/win.rs）：
    ///   - IPv4 `IP_UNICAST_IF` 用网络字节序 `to_be_bytes()`（微软文档 + clash-rs
    ///     生产验证，旧实现误改主机字节序导致 ifIndex 解析错误、流量丢弃）
    ///   - IPv6 `IPV6_UNICAST_IF` 用主机字节序 `to_ne_bytes()`
    ///   - UDP socket 额外绑定 `IP_MULTICAST_IF` / `IPV6_MULTICAST_IF`
    ///   - dual-stack IPv6 socket 回退绑定 IPv4 接口
    ///   - 跳过 loopback 目标（绑定接口会阻止访问 localhost）
    pub fn bind_socket_to_physical_interface(raw_socket: std::os::windows::io::RawSocket, target: IpAddr) {
        // 跳过 loopback：绑定物理接口会导致无法访问 localhost（对齐 clash-rs
        // socket_helpers：`!endpoint.ip().is_loopback()` 才绑定）
        if target.is_loopback() {
            return;
        }

        use ::windows::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_IP, IPPROTO_IPV6, IP_UNICAST_IF, IPV6_UNICAST_IF,
            IP_MULTICAST_IF, IPV6_MULTICAST_IF, SOCKET,
        };

        let sock = SOCKET(raw_socket as usize);
        match target {
            IpAddr::V4(_) => {
                if let Some(idx) = physical_if_index_v4() {
                    // IP_UNICAST_IF：网络字节序（big-endian）。
                    // 对齐 clash-rs win.rs L34: `idx.to_be_bytes()` + 微软文档
                    // "a 4-byte IPv4 address in network byte order"。
                    let bytes = idx.to_be_bytes();
                    unsafe {
                        let rc = setsockopt(sock, IPPROTO_IP.0, IP_UNICAST_IF, Some(&bytes));
                        if rc != 0 {
                            tracing::warn!(
                                err = rc, idx,
                                "windows_iface: IP_UNICAST_IF setsockopt failed"
                            );
                        }
                        // UDP 组播也需要绑定到物理接口（对齐 clash-rs win.rs L66-70）。
                        // 对 TCP socket 设置会返回错误但无害（TCP 不支持组播）。
                        let _ = setsockopt(
                            sock, IPPROTO_IP.0, IP_MULTICAST_IF, Some(&bytes),
                        );
                    }
                } else {
                    tracing::debug!(
                        "windows_iface: physical IPv4 interface not registered yet, skip binding"
                    );
                }
            }
            IpAddr::V6(_) => {
                if let Some(idx) = physical_if_index_v6() {
                    // IPV6_UNICAST_IF：主机字节序（对齐 clash-rs win.rs L46 + 微软
                    // 文档 "4-byte interface index in host byte order"）。
                    let bytes = idx.to_ne_bytes();
                    unsafe {
                        let rc = setsockopt(sock, IPPROTO_IPV6.0, IPV6_UNICAST_IF, Some(&bytes));
                        if rc != 0 {
                            tracing::warn!(
                                err = rc, idx,
                                "windows_iface: IPV6_UNICAST_IF setsockopt failed"
                            );
                        }
                        let _ = setsockopt(
                            sock, IPPROTO_IPV6.0, IPV6_MULTICAST_IF, Some(&bytes),
                        );
                    }
                }
                // dual-stack 回退：IPv6 socket 也尝试绑定 IPv4 接口（对齐 clash-rs
                // win.rs L93-100）。dual-stack socket 上 IPv4 流量仍走 IPv4 路由，
                // 必须同时绑定 IPv4 接口，否则 IPv4 出站会环回进 TUN。
                if let Some(idx) = physical_if_index_v4() {
                    let bytes = idx.to_be_bytes();
                    unsafe {
                        let _ = setsockopt(sock, IPPROTO_IP.0, IP_UNICAST_IF, Some(&bytes));
                    }
                }
            }
        }
    }

    /// 枚举系统 DNS 服务器（优先物理网卡；用于 Windows 上替代
    /// /etc/resolv.conf —— Windows 没有标准 resolv.conf，旧实现回退到
    /// 127.0.0.1:53，而本机根本没人在 53 上监听，导致 DNS local 上游全部
    /// 超时、TUN auto_route 下网络瘫痪）。
    ///
    /// 过滤：仅取 UP 状态、非 loopback 的适配器；已登记物理网卡时优先只取
    /// 物理网卡的 DNS（TUN 网卡上的 DNS 是 reflex 自己设的劫持地址，必须
    /// 排除）；丢弃 0.0.0.0/:: 与本机自身地址。
    pub fn system_dns_servers() -> Vec<IpAddr> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST,
            IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

        let mut out: Vec<IpAddr> = Vec::new();
        let phys_v4 = physical_if_index_v4();
        let phys_v6 = physical_if_index_v6();
        let mut size: u32 = 16 * 1024;
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
        loop {
            let mut buf = vec![0u8; size as usize];
            let adapters = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let rc = unsafe {
                GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(adapters), &mut size)
            };
            // windows 0.58：返回 u32；ERROR_BUFFER_OVERFLOW = 122
            if rc == 122 {
                size = size.saturating_mul(2);
                continue;
            }
            if rc != 0 {
                return out;
            }
            let mut p = adapters;
            while !p.is_null() {
                let a = unsafe { &*p };
                p = a.Next;
                // IfOperStatusUp = 1；IF_TYPE_SOFTWARE_LOOPBACK = 24
                if a.OperStatus.0 != 1 || a.IfType == 24 {
                    continue;
                }
                // 优先物理网卡：已登记物理网卡时，跳过其它适配器
                //（TUN 适配器上的 DNS 是 reflex 自己设的劫持地址）
                // windows 0.58：IfIndex 在 Anonymous1 联合体里
                let idx = unsafe { a.Anonymous1.Anonymous.IfIndex };
                if (phys_v4.is_some() || phys_v6.is_some())
                    && Some(idx) != phys_v4
                    && Some(idx) != phys_v6
                {
                    continue;
                }
                let mut dsa = a.FirstDnsServerAddress;
                while !dsa.is_null() {
                    let d = unsafe { &*dsa };
                    dsa = d.Next;
                    let sa = d.Address.lpSockaddr;
                    if sa.is_null() {
                        continue;
                    }
                    let ip = unsafe {
                        match (*sa).sa_family.0 {
                            2 => {
                                let sa4 = *(sa as *const SOCKADDR_IN);
                                Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                                    sa4.sin_addr.S_un.S_addr,
                                ))))
                            }
                            23 => {
                                let sa6 = *(sa as *const SOCKADDR_IN6);
                                Some(IpAddr::V6(std::net::Ipv6Addr::from(sa6.sin6_addr.u.Byte)))
                            }
                            _ => None,
                        }
                    };
                    if let Some(ip) = ip {
                        // 排除未指定地址与本机自身地址（后者是 TUN 劫持地址）
                        if ip.is_unspecified() || super::local_ranges::is_own_address(ip) {
                            continue;
                        }
                        if !out.contains(&ip) {
                            out.push(ip);
                        }
                    }
                }
            }
            break;
        }
        out
    }
}

// ── macOS：IP_BOUND_IF / IPV6_BOUND_IF 防环回 ──────────────────────────────
//
// 跟 Windows 的处境一样：macOS 没有 SO_MARK，`auto_route` 在 macOS 上是靠
// `route add -interface <tun>` 把默认路由整个指向 TUN 网卡实现的（见
// `inbound/tun/platform/macos.rs`），却完全没有对 reflex 自身出站流量做任何
// 排除处理——之前这里唯一能用的是 `route_exclude_address`，但那是要用户手
// 动一条条列出目标 IP 的白名单，不是通用机制。direct 出站本身在 macOS 上
// 也只是个空函数（旧版 `apply_interface_bind` 对非 Linux 的 unix 平台整体
// 空操作），所以 macOS 上以前跟改之前的 Windows 一样，direct 及所有协议出站
// 都可能被 TUN 接管的默认路由重新截获，形成环路。
//
// 对应方案：BSD/Darwin 提供了 `IP_BOUND_IF`（IPv6 对应 `IPV6_BOUND_IF`）这个
// socket 选项，功能与 Linux 的 SO_BINDTODEVICE 等价——把 socket 绑定到指定
// 接口索引，无视路由表。物理网卡的接口索引由
// `inbound::tun::platform::macos::setup()` 在添加 TUN 路由之前探测并写入。
#[cfg(target_os = "macos")]
pub mod macos_iface {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 0 表示"尚未探测到 / 不适用"，有效 ifIndex 从 1 开始。
    static PHYSICAL_IF_INDEX_V4: AtomicU32 = AtomicU32::new(0);
    static PHYSICAL_IF_INDEX_V6: AtomicU32 = AtomicU32::new(0);

    /// 由 TUN 的 macOS setup() 在装 TUN 路由前调用，登记探测到的物理出口网卡。
    pub fn set_physical_if_index_v4(idx: u32) {
        PHYSICAL_IF_INDEX_V4.store(idx, Ordering::Relaxed);
    }

    pub fn set_physical_if_index_v6(idx: u32) {
        PHYSICAL_IF_INDEX_V6.store(idx, Ordering::Relaxed);
    }

    pub fn physical_if_index_v4() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V4.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    pub fn physical_if_index_v6() -> Option<u32> {
        match PHYSICAL_IF_INDEX_V6.load(Ordering::Relaxed) {
            0 => None,
            idx => Some(idx),
        }
    }

    /// 把已创建（尚未 connect/send）的 socket 绑定到探测到的物理网卡。
    /// 没有探测到物理网卡（未触发 auto_route 防环回逻辑）时为空操作。
    pub fn bind_socket_to_physical_interface(fd: std::os::unix::io::RawFd, target: IpAddr) {
        match target {
            IpAddr::V4(_) => {
                if let Some(idx) = physical_if_index_v4() {
                    unsafe {
                        let _ = libc::setsockopt(
                            fd,
                            libc::IPPROTO_IP,
                            libc::IP_BOUND_IF,
                            &idx as *const u32 as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        );
                    }
                }
            }
            IpAddr::V6(_) => {
                if let Some(idx) = physical_if_index_v6() {
                    unsafe {
                        let _ = libc::setsockopt(
                            fd,
                            libc::IPPROTO_IPV6,
                            libc::IPV6_BOUND_IF,
                            &idx as *const u32 as *const libc::c_void,
                            std::mem::size_of::<u32>() as libc::socklen_t,
                        );
                    }
                }
            }
        }
    }
}

// ── 本机地址段登记（direct 出站回环防护，对齐 sing-box isMyLoopbackAddress）──
//
// sing-box 的 direct 出站在拨号前检查目标地址是否落在本机任一网卡的子网内
//（protocol/direct/outbound.go `isMyLoopbackAddress`），命中则直接拒绝
//（"loopback connection to TUN range"）。TUN auto_route 场景下，被误路由到
// direct 的本机网段目标（TUN 网段、fakeip 泄漏、恶意地址）会形成数据环路，
// 拨号层拒绝是最后一道安全网。语义对齐：
//   - 收集所有 UP 且非 loopback 网卡的 (地址, 前缀长度)；
//   - 非 macOS 上，目标地址与某前缀基址完全相同时豁免（允许连回本机自身
//     地址；sing-box 对 Darwin 之外平台的特殊处理）；
//   - 其余命中子网即拒绝。
// 缓存带 TTL（10 秒）：TUN 接口在应用启动流程中才创建，TTL 轮转保证 TUN
// 网段迟早进入登记表，无需在各平台 TUN setup 里显式打点。
#[cfg(any(unix, target_os = "windows"))]
pub mod local_ranges {
    use std::net::IpAddr;
    use std::sync::RwLock;
    use std::time::Duration;

    const REFRESH_TTL: Duration = Duration::from_secs(10);

    static PREFIXES: RwLock<Vec<(IpAddr, u8)>> = RwLock::new(Vec::new());
    /// 最近一次刷新的 UNIX 时间戳（秒）；0 表示尚未刷新。
    // 用 portable_atomic：mips/mipsel 等 32 位平台 std 不提供 AtomicU64。
    static LAST_REFRESH_SECS: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn stale() -> bool {
        now_secs().saturating_sub(LAST_REFRESH_SECS.load(
            portable_atomic::Ordering::Relaxed,
        )) > REFRESH_TTL.as_secs()
    }

    /// 重新枚举本机网卡地址段并更新缓存。
    pub fn refresh() {
        let prefixes = collect();
        *PREFIXES.write().unwrap_or_else(|e| e.into_inner()) = prefixes;
        LAST_REFRESH_SECS.store(now_secs(), portable_atomic::Ordering::Relaxed);
    }

    /// 目标地址是否落在本机任一网卡子网内。
    pub fn is_local_loopback(addr: IpAddr) -> bool {
        if stale() {
            refresh();
        }
        let prefixes = PREFIXES.read().unwrap_or_else(|e| e.into_inner());
        is_local_in(addr, &prefixes)
    }

    /// 目标地址是否为本机某个网卡自身配置的地址（与 sing-box 的
    /// "prefix.Addr() == address" 精确匹配语义一致）。典型用途：识别
    /// TUN 劫持 DNS 地址（本机 TUN 网卡自身 IP）以排除系统 DNS 列表。
    pub fn is_own_address(addr: IpAddr) -> bool {
        if stale() {
            refresh();
        }
        let prefixes = PREFIXES.read().unwrap_or_else(|e| e.into_inner());
        prefixes.iter().any(|(base, _)| *base == addr)
    }

    fn is_local_in(addr: IpAddr, prefixes: &[(IpAddr, u8)]) -> bool {
        for (base, plen) in prefixes {
            // 对齐 sing-box：非 Darwin 平台豁免与本机地址完全相等的目标
            #[cfg(not(target_os = "macos"))]
            if *base == addr {
                continue;
            }
            if ip_in_subnet(*base, *plen, addr) {
                return true;
            }
        }
        false
    }

    fn ip_in_subnet(base: IpAddr, prefix_len: u8, target: IpAddr) -> bool {
        match (base, target) {
            (IpAddr::V4(b), IpAddr::V4(t)) => {
                if prefix_len == 0 {
                    return true;
                }
                let shift = 32u32.saturating_sub(prefix_len as u32);
                (u32::from(b) >> shift) == (u32::from(t) >> shift)
            }
            (IpAddr::V6(b), IpAddr::V6(t)) => {
                if prefix_len == 0 {
                    return true;
                }
                let shift = 128u32.saturating_sub(prefix_len as u32);
                (u128::from(b) >> shift) == (u128::from(t) >> shift)
            }
            _ => false,
        }
    }

    /// 枚举所有 UP 且非 loopback 网卡的 (地址, 前缀长度)。
    #[cfg(unix)]
    fn collect() -> Vec<(IpAddr, u8)> {
        let mut out: Vec<(IpAddr, u8)> = Vec::new();
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) != 0 {
                return out;
            }
            let mut ifa = ifap;
            while !ifa.is_null() {
                let r = &*ifa;
                ifa = r.ifa_next;
                if r.ifa_addr.is_null() {
                    continue;
                }
                // 只关心 UP 且非 loopback 的网卡（与 linux::list_interfaces 一致）
                if r.ifa_flags & libc::IFF_UP as u32 == 0 {
                    continue;
                }
                if r.ifa_flags & libc::IFF_LOOPBACK as u32 != 0 {
                    continue;
                }
                match (*r.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sa = &*(r.ifa_addr as *const libc::sockaddr_in);
                        let ip = IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                            sa.sin_addr.s_addr,
                        )));
                        let plen = if !r.ifa_netmask.is_null() {
                            let nm = &*(r.ifa_netmask as *const libc::sockaddr_in);
                            u32::from_be(nm.sin_addr.s_addr).count_ones() as u8
                        } else {
                            32
                        };
                        out.push((ip, plen));
                    }
                    libc::AF_INET6 => {
                        let sa = &*(r.ifa_addr as *const libc::sockaddr_in6);
                        let ip =
                            IpAddr::V6(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr));
                        let plen = if !r.ifa_netmask.is_null() {
                            let nm = &*(r.ifa_netmask as *const libc::sockaddr_in6);
                            nm.sin6_addr
                                .s6_addr
                                .iter()
                                .map(|b| b.count_ones() as u8)
                                .sum()
                        } else {
                            128
                        };
                        out.push((ip, plen));
                    }
                    _ => {}
                }
            }
            libc::freeifaddrs(ifap);
        }
        out
    }

    /// Windows：GetAdaptersAddresses 枚举 UP 状态、非 loopback 网卡的
    /// 单播地址及其 OnLinkPrefixLength。
    #[cfg(target_os = "windows")]
    fn collect() -> Vec<(IpAddr, u8)> {
        use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
        use windows::Win32::NetworkManagement::IpHelper::{
            GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
            GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6};

        let mut out: Vec<(IpAddr, u8)> = Vec::new();
        let mut size: u32 = 16 * 1024;
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        loop {
            let mut buf = vec![0u8; size as usize];
            let adapters = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
            let rc = unsafe {
                GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, Some(adapters), &mut size)
            };
            // windows 0.58 中 GetAdaptersAddresses 返回 u32；
            // ERROR_BUFFER_OVERFLOW = 122
            if rc == ERROR_BUFFER_OVERFLOW.0 {
                size = size.saturating_mul(2);
                continue;
            }
            if rc != 0 {
                return out;
            }
            let mut p = adapters;
            while !p.is_null() {
                let a = unsafe { &*p };
                // IfOperStatusUp = 1；IF_TYPE_SOFTWARE_LOOPBACK = 24
                if a.OperStatus.0 == 1 && a.IfType != 24 {
                    let mut ua = a.FirstUnicastAddress;
                    while !ua.is_null() {
                        let u = unsafe { &*ua };
                        ua = u.Next;
                        let sa = u.Address.lpSockaddr;
                        if sa.is_null() {
                            continue;
                        }
                        unsafe {
                            match (*sa).sa_family.0 {
                                2 => {
                                    // AF_INET
                                    let sa4 = *(sa as *const SOCKADDR_IN);
                                    let ip = IpAddr::V4(std::net::Ipv4Addr::from(
                                        u32::from_be(sa4.sin_addr.S_un.S_addr),
                                    ));
                                    out.push((ip, u.OnLinkPrefixLength as u8));
                                }
                                23 => {
                                    // AF_INET6
                                    let sa6 = *(sa as *const SOCKADDR_IN6);
                                    let ip = IpAddr::V6(std::net::Ipv6Addr::from(
                                        sa6.sin6_addr.u.Byte,
                                    ));
                                    out.push((ip, u.OnLinkPrefixLength as u8));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                p = a.Next;
            }
            break;
        }
        let _ = std::mem::size_of::<SOCKADDR>();
        out
    }

    /// 测试钩子：直接注入前缀表并把 TTL 顺延，避免测试期间被真实枚举覆盖。
    #[doc(hidden)]
    pub fn set_for_test(prefixes: Vec<(IpAddr, u8)>) {
        *PREFIXES.write().unwrap_or_else(|e| e.into_inner()) = prefixes;
        LAST_REFRESH_SECS.store(
            now_secs() + 3600,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

// 非 unix/windows 平台：无实现，检查恒为 false（空表）。
#[cfg(not(any(unix, target_os = "windows")))]
pub mod local_ranges {
    use std::net::IpAddr;

    pub fn refresh() {}
    pub fn is_local_loopback(_addr: IpAddr) -> bool {
        false
    }
}
