#![allow(dead_code)]

//! 接口监控（B8 修复：netlink 事件驱动，对齐 sing-tun monitor_linux.go）。
//!
//! sing-tun 的 `networkUpdateMonitor` 通过 netlink 多播订阅
//! RouteSubscribe / LinkSubscribe / AddrSubscribe 三类事件，
//! `loopUpdate(time.Second)` 做 1 秒防抖后 emit 回调。
//!
//! reflex 的实现：
//! - Linux/Android：AF_NETLINK/NETLINK_ROUTE socket 绑定
//!   RTNLGRP_LINK / RTNLGRP_IPV4_IFADDR / RTNLGRP_IPV4_ROUTE /
//!   RTNLGRP_IPV6_IFADDR / RTNLGRP_IPV6_ROUTE 多播组，事件驱动扫描；
//! - netlink 不可用（Android 部分内核禁用 netlink、无权限）时回退 5s 轮询；
//! - 扫描改为 getifaddrs（修复旧实现 addresses 恒为空的问题），
//!   diff 后仅通知变化的接口。

use std::collections::HashSet;
use tokio::sync::Mutex;
use tracing::info;
// warn! 只在 netlink 事件路径使用（linux/android），避免其他平台 unused import 告警
#[cfg(any(target_os = "linux", target_os = "android"))]
use tracing::warn;

static INTERFACE_MONITOR: once_cell::sync::Lazy<Mutex<InterfaceMonitorInner>> =
    once_cell::sync::Lazy::new(|| Mutex::new(InterfaceMonitorInner::default()));

#[derive(Default)]
#[allow(clippy::type_complexity)]
struct InterfaceMonitorInner {
    callbacks: Vec<(usize, Box<dyn Fn(&InterfaceEvent) + Send + Sync>)>,
    next_id: usize,
    task_running: bool,
}

/// 接口事件。
#[derive(Debug, Clone)]
pub struct InterfaceEvent {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub mtu: u32,
    pub addresses: Vec<std::net::IpAddr>,
    /// Android：系统 VPN 是否启用（通过 0x20000 fwmark 检测）。
    #[cfg(target_os = "android")]
    pub android_vpn_enabled: bool,
}

/// 注册接口变更回调。返回回调 ID，可用于取消注册。
pub async fn register<F>(cb: F) -> usize
where
    F: Fn(&InterfaceEvent) + Send + Sync + 'static,
{
    let mut monitor = INTERFACE_MONITOR.lock().await;
    let id = monitor.next_id;
    monitor.next_id += 1;
    monitor.callbacks.push((id, Box::new(cb)));

    if !monitor.task_running {
        monitor.task_running = true;
        tokio::spawn(monitor_task());
    }

    id
}

/// 取消注册回调。
pub async fn unregister(id: usize) {
    let mut monitor = INTERFACE_MONITOR.lock().await;
    monitor.callbacks.retain(|(i, _)| *i != id);
}

/// 手动触发接口扫描（通常在路由更新时调用）。
pub async fn scan_and_notify() {
    let events = scan_interfaces();
    let monitor = INTERFACE_MONITOR.lock().await;
    for event in &events {
        for (_, cb) in &monitor.callbacks {
            cb(event);
        }
    }
}

// ── Linux/Android：netlink 路由事件订阅 ──────────────────────────────────────

#[cfg(any(target_os = "linux", target_os = "android"))]
mod netlink_events {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

    // RTNLGRP_* 多播组编号（linux/rtnetlink.h）
    const RTNLGRP_LINK: u32 = 1;
    const RTNLGRP_IPV4_IFADDR: u32 = 5;
    const RTNLGRP_IPV4_ROUTE: u32 = 7;
    const RTNLGRP_IPV6_IFADDR: u32 = 9;
    const RTNLGRP_IPV6_ROUTE: u32 = 11;

    /// netlink 路由事件 socket。
    ///
    /// 对齐 sing-tun 的 RouteSubscribe/LinkSubscribe/AddrSubscribe：
    /// 一次 socket 同时加入 link / addr / route 多播组（v4+v6）。
    pub struct NetlinkEventSocket {
        fd: OwnedFd,
    }

    impl NetlinkEventSocket {
        /// 建立 socket 并加入多播组。失败返回 None（Android netlink 被禁、
        /// 无权限等，对齐 sing-tun 的 ErrNetlinkBanned 探测）。
        pub fn open() -> Option<Self> {
            unsafe {
                let fd = libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                    libc::NETLINK_ROUTE,
                );
                if fd < 0 {
                    return None;
                }
                let groups: u32 = (1 << (RTNLGRP_LINK - 1))
                    | (1 << (RTNLGRP_IPV4_IFADDR - 1))
                    | (1 << (RTNLGRP_IPV4_ROUTE - 1))
                    | (1 << (RTNLGRP_IPV6_IFADDR - 1))
                    | (1 << (RTNLGRP_IPV6_ROUTE - 1));
                let mut addr: libc::sockaddr_nl = std::mem::zeroed();
                addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
                addr.nl_pid = 0;
                addr.nl_groups = groups;
                if libc::bind(
                    fd,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                ) < 0
                {
                    libc::close(fd);
                    return None;
                }
                Some(Self {
                    fd: OwnedFd::from_raw_fd(fd),
                })
            }
        }

        pub fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }

        /// 非阻塞读出全部待处理消息，返回其中是否含 link/addr/route 变更。
        ///
        /// 只解析 nlmsghdr（len/type），不依赖完整 payload 解析——
        /// 未知消息类型直接跳过，保证对内核版本的前向兼容。
        pub fn drain(&self) -> bool {
            let mut buf = vec![0u8; 65536];
            let mut relevant = false;
            loop {
                let n = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        libc::MSG_DONTWAIT,
                    )
                };
                if n <= 0 {
                    break;
                }
                let n = n as usize;
                if parse_messages(&buf[..n]) {
                    relevant = true;
                }
            }
            relevant
        }
    }

    /// 遍历 netlink 消息流，判断是否含接口/地址/路由变更事件。
    pub fn parse_messages(mut data: &[u8]) -> bool {
        let mut relevant = false;
        loop {
            if data.len() < 16 {
                return relevant;
            }
            let len = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if len < 16 || len > data.len() {
                return relevant;
            }
            let msg_type = u16::from_ne_bytes([data[4], data[5]]);
            match msg_type {
                libc::RTM_NEWLINK | libc::RTM_DELLINK => relevant = true,
                libc::RTM_NEWADDR | libc::RTM_DELADDR => relevant = true,
                libc::RTM_NEWROUTE | libc::RTM_DELROUTE => relevant = true,
                _ => {}
            }
            data = &data[len..];
        }
    }

    impl AsRawFd for NetlinkEventSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }
}

// ── 平台相关的扫描实现 ────────────────────────────────────────────────────────

/// 扫描当前所有网络接口。
///
/// B8 修复：改用 getifaddrs 获取接口与地址（旧实现遍历 /sys/class/net，
/// addresses 恒为空数组）；MTU 仍从 sysfs 读取（getifaddrs 不提供 MTU）。
fn scan_interfaces() -> Vec<InterfaceEvent> {
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        allow(unused_mut)
    )]
    let mut events = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::net::IpAddr;

        // name -> (index, mtu, up)
        let mut ifaces: Vec<(String, u32, u32, bool)> = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let index = read_uint_file(&entry.path().join("ifindex")).unwrap_or(0) as u32;
                let up = read_string_file(&entry.path().join("operstate"))
                    .map(|s| s.trim() == "up")
                    .unwrap_or(false);
                let mtu = read_uint_file(&entry.path().join("mtu")).unwrap_or(1500) as u32;
                ifaces.push((name, index, mtu, up));
            }
        }

        // getifaddrs：接口地址 + up 状态（IFF_UP，比 operstate 更权威）
        let mut addr_map: std::collections::HashMap<String, Vec<IpAddr>> =
            std::collections::HashMap::new();
        let mut up_map: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) == 0 {
                let mut cursor = ifap;
                while !cursor.is_null() {
                    let ifa = &*cursor;
                    let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .to_string();
                    let flags = ifa.ifa_flags as libc::c_int;
                    up_map.insert(name.clone(), flags & libc::IFF_UP != 0);
                    if !ifa.ifa_addr.is_null() {
                        let family = (*ifa.ifa_addr).sa_family as libc::c_int;
                        let ip = match family {
                            libc::AF_INET => {
                                let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                                Some(IpAddr::from(std::net::Ipv4Addr::from(
                                    sa.sin_addr.s_addr.to_be(),
                                )))
                            }
                            libc::AF_INET6 => {
                                let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                                Some(IpAddr::from(std::net::Ipv6Addr::from(sa.sin6_addr.s6_addr)))
                            }
                            _ => None,
                        };
                        if let Some(ip) = ip {
                            addr_map.entry(name.clone()).or_default().push(ip);
                        }
                    }
                    cursor = ifa.ifa_next;
                }
                libc::freeifaddrs(ifap);
            }
        }

        for (name, index, mtu, sysfs_up) in ifaces {
            let up = up_map.get(&name).copied().unwrap_or(sysfs_up);
            let addresses = addr_map.remove(&name).unwrap_or_default();
            events.push(InterfaceEvent {
                name,
                index,
                up,
                mtu,
                addresses,
                #[cfg(target_os = "android")]
                android_vpn_enabled: check_android_vpn_active(),
            });
        }

        #[cfg(target_os = "android")]
        // Android: 额外添加虚拟 VPN 状态事件
        if !events.iter().any(|e| e.name == "__android_vpn__") {
            events.push(InterfaceEvent {
                name: "__android_vpn__".to_string(),
                index: 0,
                up: false,
                mtu: 0,
                addresses: vec![],
                android_vpn_enabled: check_android_vpn_active(),
            });
        }
    }

    events
}

/// Android：检测系统 VPN 是否启用（通过 0x20000 fwmark 规则）。
#[cfg(target_os = "android")]
fn check_android_vpn_active() -> bool {
    use std::process::Command;
    let out = Command::new("ip").args(["rule", "show"]).output().ok();
    match out {
        Some(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout
                .lines()
                .any(|line| line.contains("fwmark") && line.contains("0x20000"))
        }
        _ => false,
    }
}

/// 比较两组接口事件，返回新增、移除、变更的事件。
pub fn diff_events(old: &[InterfaceEvent], new: &[InterfaceEvent]) -> Vec<InterfaceEvent> {
    let old_set: HashSet<&str> = old.iter().map(|e| e.name.as_str()).collect();
    let new_set: HashSet<&str> = new.iter().map(|e| e.name.as_str()).collect();

    let mut changes = Vec::new();

    for event in new {
        if !old_set.contains(event.name.as_str()) {
            changes.push(event.clone());
        } else if let Some(old_event) = old.iter().find(|e| e.name == event.name) {
            if old_event.up != event.up
                || old_event.mtu != event.mtu
                || old_event.addresses != event.addresses
            {
                changes.push(event.clone());
            }
            #[cfg(target_os = "android")]
            if old_event.android_vpn_enabled != event.android_vpn_enabled {
                changes.push(event.clone());
            }
        }
    }

    for event in old {
        if !new_set.contains(event.name.as_str()) {
            let mut removed = event.clone();
            removed.up = false;
            changes.push(removed);
        }
    }

    changes
}

/// 扫描并与上次状态比较，通知回调（仅变化部分）。
async fn rescan_and_notify(last_events: &mut Vec<InterfaceEvent>) {
    let current = scan_interfaces();
    let changed = diff_events(last_events, &current);
    if changed.is_empty() {
        return;
    }
    *last_events = current;
    let monitor = INTERFACE_MONITOR.lock().await;
    for event in &changed {
        for (_, cb) in &monitor.callbacks {
            cb(event);
        }
    }
}

/// netlink 订阅句柄（跨平台包装：非 Linux/Android 平台退化为纯轮询）。
enum NetlinkWatch {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Active(tokio::io::unix::AsyncFd<netlink_events::NetlinkEventSocket>),
    None,
}

impl NetlinkWatch {
    /// 挂起直到相关 netlink 事件（link/addr/route 变更）到达并 drain 完毕。
    /// 无订阅（订阅失败或非 Linux 平台）时永久挂起，由轮询分支兜底。
    async fn wait_events(&self) -> bool {
        match self {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            NetlinkWatch::Active(fd) => loop {
                let mut guard: tokio::io::unix::AsyncFdReadyGuard<'_, _> = match fd.readable().await
                {
                    Ok(g) => g,
                    Err(e) => {
                        warn!(err = %e, "interface monitor: netlink readable error");
                        return false;
                    }
                };
                // drain 循环 recv 直到 EAGAIN，读完后 clear_ready 重挂兴趣
                let has_events = guard.get_ref().get_ref().drain();
                guard.clear_ready();
                drop(guard);
                if has_events {
                    return true;
                }
                // 虚假唤醒（无关消息类型）：继续等待
            },
            NetlinkWatch::None => std::future::pending().await,
        }
    }
}

/// 监控后台任务。
///
/// netlink 事件驱动（1s 防抖，对齐 sing-tun loopUpdate(time.Second)），
/// 轮询兜底（netlink 不可用或事件丢失时的安全网）。
async fn monitor_task() {
    // ── netlink 路由事件订阅（B8 修复）──
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let netlink = {
        match netlink_events::NetlinkEventSocket::open() {
            Some(sock) => match tokio::io::unix::AsyncFd::new(sock) {
                Ok(fd) => {
                    info!("interface monitor: started (netlink event-driven, 1s debounce)");
                    NetlinkWatch::Active(fd)
                }
                Err(e) => {
                    warn!(err = %e, "interface monitor: AsyncFd wrap failed, polling fallback");
                    NetlinkWatch::None
                }
            },
            None => {
                warn!(
                    "interface monitor: netlink subscribe failed (banned or no permission), \
                     polling every 5s"
                );
                NetlinkWatch::None
            }
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let netlink = NetlinkWatch::None;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    info!("interface monitor: started (polling every 5s)");

    let mut last_events: Vec<InterfaceEvent> = scan_interfaces();
    let mut poll = tokio::time::interval(std::time::Duration::from_secs(5));
    // 对齐 sing-tun loopUpdate 的最小发射间隔：事件风暴合并为一次扫描
    const DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(1);
    let mut pending = false;
    let mut next_emit = tokio::time::Instant::now();

    loop {
        enum Trigger {
            Poll,
            Debounce,
        }

        let trigger: Trigger = tokio::select! {
            _ = poll.tick() => Trigger::Poll,
            has_events = netlink.wait_events() => {
                if has_events {
                    if tokio::time::Instant::now() >= next_emit {
                        next_emit = tokio::time::Instant::now() + DEBOUNCE;
                        rescan_and_notify(&mut last_events).await;
                        pending = false;
                    } else {
                        pending = true;
                    }
                }
                continue;
            }
            _ = tokio::time::sleep_until(next_emit), if pending => Trigger::Debounce,
        };

        match trigger {
            Trigger::Poll => {
                // 轮询兜底：netlink 活跃时作为安全网，否则为主路径
                rescan_and_notify(&mut last_events).await;
                pending = false;
            }
            Trigger::Debounce => {
                rescan_and_notify(&mut last_events).await;
                pending = false;
                next_emit = tokio::time::Instant::now() + DEBOUNCE;
            }
        }
    }
}

// ── 文件辅助 ──────────────────────────────────────────────────────────────────

fn read_uint_file(path: &std::path::Path) -> Option<u64> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

fn read_string_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_events_detects_address_change() {
        let mk = |addrs: Vec<std::net::IpAddr>| InterfaceEvent {
            name: "eth0".into(),
            index: 2,
            up: true,
            mtu: 1500,
            addresses: addrs,
            #[cfg(target_os = "android")]
            android_vpn_enabled: false,
        };
        let a = mk(vec!["192.168.1.2".parse().unwrap()]);
        let b = mk(vec![
            "192.168.1.2".parse().unwrap(),
            "192.168.1.3".parse().unwrap(),
        ]);
        assert!(diff_events(&[a], &[b]).len() == 1);
        // 无变化
        let c = mk(vec!["192.168.1.2".parse().unwrap()]);
        let c2 = c.clone();
        assert!(diff_events(&[c2], &[c]).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_messages_relevant_types() {
        // nlmsghdr: len(u32) type(u16) flags(u16) seq(u32) pid(u32)
        let mk_msg = |t: u16| -> Vec<u8> {
            let mut m = vec![0u8; 16];
            m[0..4].copy_from_slice(&16u32.to_ne_bytes());
            m[4..6].copy_from_slice(&t.to_ne_bytes());
            m
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&mk_msg(libc::RTM_NEWLINK as u16));
        assert!(netlink_events::parse_messages(&buf));
        let mut buf2 = Vec::new();
        buf2.extend_from_slice(&mk_msg(libc::RTM_NEWADDR as u16));
        buf2.extend_from_slice(&mk_msg(libc::RTM_DELROUTE as u16));
        assert!(netlink_events::parse_messages(&buf2));
        // 无关类型（如 NLMSG_ERROR=2）
        let mut buf3 = Vec::new();
        buf3.extend_from_slice(&mk_msg(2));
        assert!(!netlink_events::parse_messages(&buf3));
    }
}
