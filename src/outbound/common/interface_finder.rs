//! 网卡查找与默认路由检测（仅 Linux）。
//!
//! 参照 sing-box `AutoDetectInterfaceFunc` 的两步逻辑：
//!   1. 若目标 IP 属于某张本地网卡的子网 → bind 到那张网卡（局域网直连）
//!   2. 否则 → bind 到当前系统默认路由对应的网卡（公网直连）
//!
//! 非 Linux 平台编译为空操作，行为与修改前完全一致。

#[cfg(target_os = "linux")]
mod linux {
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
