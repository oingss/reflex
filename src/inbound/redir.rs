use std::{net::SocketAddr, time::Duration};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::TcpListener, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::RedirInboundConfig,
    inbound::{InboundTcpStream, SniffedStream, Target, display_sockaddr, netfilter},
};

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

        // TCP keepalive：对齐 mihomo listener/redir/tcp.go 的
        // keepalive.TCPKeepAlive(conn)，及时清理半开连接（见 netfilter.rs）。
        netfilter::set_tcp_keepalive(&stream);

        // 从连接 fd 上读取原始目标地址（SO_ORIGINAL_DST）
        let target = match netfilter::get_original_dst_tcp(&stream) {
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
