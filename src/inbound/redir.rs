use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::TcpListener, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::RedirInboundConfig,
    inbound::{display_sockaddr, InboundTcpStream, SniffedStream, Target},
};

// ── SO_ORIGINAL_DST 常量 ──────────────────────────────────────────────────────
// IPPROTO_IP  level, SO_ORIGINAL_DST = 80
// IPPROTO_IPV6 level, IP6T_SO_ORIGINAL_DST = 80（同值，不同 level）

const SO_ORIGINAL_DST: libc::c_int = 80;

// ── 公开结构 ──────────────────────────────────────────────────────────────────

pub struct RedirInbound {
    config: RedirInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl RedirInbound {
    pub fn new(config: RedirInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            crate::inbound::parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = self.config.tag.clone();

        info!(tag=%tag, addr=%bind, "redir inbound starting");

        let listener = create_redir_tcp_listener(bind)?;
        run_tcp(listener, self.tcp_tx, tag).await
    }
}

// ── Socket 创建 ───────────────────────────────────────────────────────────────

/// 创建用于接收 REDIRECT 流量的 TCP listener。
///
/// Redirect 不需要 `IP_TRANSPARENT`；内核已将连接目标改写为本机地址，
/// listener 只需普通绑定即可。`SO_REUSEADDR` 保证进程重启时不等待 TIME_WAIT。
///
/// IPv6 监听地址需显式置 `IPV6_V6ONLY=false`：与 tproxy listener 同样的理由，
/// Rust socket2 不像 Go stdlib 会对 AF_INET6 socket 隐式置 V6ONLY=0，
/// 若系统 `net.ipv6.bindv6only=1`，`::` 监听将收不到 IPv4 流量，导致
/// `iptables -t nat -j REDIRECT` 拦截的 IPv4 连接全部被 drop。
fn create_redir_tcp_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let is_v6 = addr.is_ipv6();
    let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    if is_v6 {
        // 显式 IPV6_V6ONLY=false：确保 "::" 监听能同时接收 IPv4-mapped 流量
        sock.set_only_v6(false)?;
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    // backlog 4096：与 tproxy 保持一致，应对突发连接
    sock.listen(4096)?;
    Ok(TcpListener::from_std(std::net::TcpListener::from(sock))?)
}

// ── TCP accept 循环 ───────────────────────────────────────────────────────────

async fn run_tcp(
    listener: TcpListener,
    tx: mpsc::Sender<InboundTcpStream>,
    tag: String,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                let raw = e.raw_os_error();
                // EMFILE(24)/ENFILE(23)：FD 耗尽，退避后重试（与 tproxy 保持一致）
                if raw == Some(libc::EMFILE) || raw == Some(libc::ENFILE) {
                    error!(err=%e, "redir tcp accept error (fd exhausted, backing off 200ms)");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                } else {
                    error!(err=%e, "redir tcp accept error");
                }
                continue;
            }
        };

        // TCP_NODELAY：Go 运行时（sing-box）对 accept 的连接默认启用 NODELAY，
        // Rust tokio 不会自动设置。与 tproxy 入站保持一致（见 tproxy.rs）。
        let _ = stream.set_nodelay(true);

        // 从连接 fd 上读取原始目标地址（SO_ORIGINAL_DST）
        let target = match get_original_dst(&stream) {
            Ok(dst) => Target::Socket(dst),
            Err(e) => {
                warn!(peer=%display_sockaddr(peer), err=%e, "redir: failed to get original dst, dropping");
                continue;
            }
        };

        debug!(peer=%display_sockaddr(peer), target=%target, "redir tcp accepted");

        if tx
            .send(InboundTcpStream {
                stream: SniffedStream::new(stream),
                target,
                inbound_tag: tag.clone(),
                sniffed_protocol: None,
                sniffed_domain: None,
            })
            .await
            .is_err()
        {
            // Dispatcher 已关闭，退出
            break;
        }
    }
    Ok(())
}

// ── 获取原始目标地址 ──────────────────────────────────────────────────────────

/// 通过 `SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` getsockopt 取回
/// 被 REDIRECT 改写前的真实目标地址。
///
/// 参考 sing-box `redir/redir_linux.go` 的 `GetOriginalDestination` 实现：
/// - IPv4：`getsockopt(IPPROTO_IP, SO_ORIGINAL_DST)` → `sockaddr_in`
/// - IPv6：`getsockopt(IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST=80)` → `sockaddr_in6`
fn get_original_dst(stream: &tokio::net::TcpStream) -> anyhow::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    unsafe {
        // ── IPv4 ──────────────────────────────────────────────────────────────
        let mut addr4: libc::sockaddr_in = std::mem::zeroed();
        let mut len4 = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::IPPROTO_IP,
            SO_ORIGINAL_DST,
            &mut addr4 as *mut _ as *mut libc::c_void,
            &mut len4,
        ) == 0
        {
            let ip = Ipv4Addr::from(u32::from_be(addr4.sin_addr.s_addr));
            return Ok(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(addr4.sin_port),
            )));
        }

        // ── IPv6 (IP6T_SO_ORIGINAL_DST = 80，level = IPPROTO_IPV6) ───────────
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            SO_ORIGINAL_DST, // IP6T_SO_ORIGINAL_DST = 80
            &mut addr6 as *mut _ as *mut libc::c_void,
            &mut len6,
        ) == 0
        {
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            return Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(addr6.sin6_port),
                0,
                0,
            )));
        }
    }

    anyhow::bail!(
        "SO_ORIGINAL_DST failed: {}",
        std::io::Error::last_os_error()
    )
}
