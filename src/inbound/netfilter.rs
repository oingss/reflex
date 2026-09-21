//! Linux netfilter 透明代理共用工具（redir / tproxy 入站共享）。
//!
//! 仅在 linux / android 编译（与 redir / tproxy 模块的 cfg 保持一致），
//! Windows 构建不包含本模块。

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::{AsRawFd, RawFd},
};

use tokio::net::TcpStream;

// ── 原始目标地址 ──────────────────────────────────────────────────────────────

/// 通过 `SO_ORIGINAL_DST`（IPv4）/ `IP6T_SO_ORIGINAL_DST`（IPv6，=80）
/// getsockopt 取回被 netfilter REDIRECT / TPROXY 改写前的原始目标地址。
///
/// 协议族先按 accept socket 的本地地址判定——mihomo `redir.parserPacket` /
/// sing-box `GetOriginalDestination` 均直接用 `conn.LocalAddr()` 判族。
/// 旧实现"先盲试 IPv4、再试 IPv6"：双栈监听上对 AF_INET6 socket 查询
/// SOL_IP/SO_ORIGINAL_DST 的行为依赖内核版本，可能得到不可靠结果；
/// 按族精确选择更稳。首选族失败时仍回退尝试另一族。
pub(crate) fn get_original_dst_tcp(stream: &TcpStream) -> anyhow::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    let prefer_v4 = match stream.local_addr() {
        Ok(SocketAddr::V4(_)) => true,
        // to_ipv4_mapped（稳定版 API）：仅对 ::ffff:x.y.z.w 返回 Some
        Ok(SocketAddr::V6(a)) => a.ip().to_ipv4_mapped().is_some(),
        // local_addr 失败不致命：回退到旧的尝试顺序
        Err(_) => true,
    };
    unsafe {
        let dst = if prefer_v4 {
            get_original_dst_v4(fd).or_else(|| get_original_dst_v6(fd))
        } else {
            get_original_dst_v6(fd).or_else(|| get_original_dst_v4(fd))
        };
        dst.ok_or_else(|| {
            anyhow::anyhow!(
                "SO_ORIGINAL_DST failed: {}",
                std::io::Error::last_os_error()
            )
        })
    }
}

/// IPv4：`getsockopt(SOL_IP, SO_ORIGINAL_DST)` → `sockaddr_in`
///
/// 参考 sing-box `redir/redir_linux.go` 的 `GetOriginalDestination` 实现。
unsafe fn get_original_dst_v4(fd: RawFd) -> Option<SocketAddr> {
    let mut addr: libc::sockaddr_in = std::mem::zeroed();
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    if libc::getsockopt(
        fd,
        libc::SOL_IP,
        libc::SO_ORIGINAL_DST,
        &mut addr as *mut _ as *mut libc::c_void,
        &mut len,
    ) == 0
    {
        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        return Some(SocketAddr::V4(SocketAddrV4::new(
            ip,
            u16::from_be(addr.sin_port),
        )));
    }
    None
}

/// IPv6：`getsockopt(IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST = 80)` → `sockaddr_in6`
unsafe fn get_original_dst_v6(fd: RawFd) -> Option<SocketAddr> {
    let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
    let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
    if libc::getsockopt(
        fd,
        libc::IPPROTO_IPV6,
        80, // IP6T_SO_ORIGINAL_DST
        &mut addr6 as *mut _ as *mut libc::c_void,
        &mut len6,
    ) == 0
    {
        let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
        return Some(SocketAddr::V6(SocketAddrV6::new(
            ip,
            u16::from_be(addr6.sin6_port),
            0,
            0,
        )));
    }
    None
}

// ── TCP keepalive ────────────────────────────────────────────────────────────

/// 对 accept 的入站连接统一设置 TCP keepalive。
///
/// 对齐 mihomo `listener/redir/tcp.go` / `listener/tproxy/tproxy.go` 中
/// 对每条连接调用 `keepalive.TCPKeepAlive(conn)` 的行为。
/// redir / tproxy 这类无协议握手的透明代理入站，若不设 keepalive，
/// 客户端异常消失（网络中断、NAT 超时）后连接将永久停留在半开状态，
/// 只能等内核默认探测（Linux 默认 idle 2 小时）兜底。
///
/// 参数取 reflex 项目统一值（与 `outbound::set_socket_opts` 及
/// mixed / socks 的 UDP ASSOCIATE 控制连接一致）：idle 60s / interval 15s。
pub(crate) fn set_tcp_keepalive(stream: &TcpStream) {
    let sock_ref = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(60))
        .with_interval(std::time::Duration::from_secs(15));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
}
