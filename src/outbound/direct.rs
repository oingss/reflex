use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::StreamExt;
use tokio::net::TcpStream;
use tracing::debug;

#[cfg(unix)]
use crate::outbound::common::interface_finder;
use crate::{
    config::outbound::DirectOutboundConfig,
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, apply_mark_to_udp, relay, resolve_target_with_dns, set_tcp_opts,
        Outbound, OutboundStatus,
    },
};

// ── Direct ────────────────────────────────────────────────────────────────────

pub struct DirectOutbound {
    config: DirectOutboundConfig,
    /// 内部 DNS 解析器，用于域名解析（替代系统 getaddrinfo）
    resolver: Option<Arc<DnsResolver>>,
    /// SO_MARK（来自 route.default_mark），0 表示不设置
    routing_mark: u32,
    /// 多网卡时自动选择出口网卡（来自 route.auto_detect_interface）
    auto_detect_interface: bool,
    /// 手动指定出口网卡名称（来自 route.default_interface），优先于自动检测
    default_interface: Option<String>,
}

impl DirectOutbound {
    pub fn new(config: DirectOutboundConfig) -> Self {
        Self {
            config,
            resolver: None,
            routing_mark: 0,
            auto_detect_interface: false,
            default_interface: None,
        }
    }

    pub fn with_resolver(config: DirectOutboundConfig, resolver: Arc<DnsResolver>) -> Self {
        Self {
            config,
            resolver: Some(resolver),
            routing_mark: 0,
            auto_detect_interface: false,
            default_interface: None,
        }
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    pub fn with_auto_detect_interface(mut self, enabled: bool) -> Self {
        self.auto_detect_interface = enabled;
        self
    }

    pub fn with_default_interface(mut self, iface: Option<String>) -> Self {
        self.default_interface = iface;
        self
    }

    /// 对 socket fd 应用网卡绑定逻辑：
    ///   1. default_interface 指定了 → 直接绑定
    ///   2. auto_detect_interface 为 true → 按目标 IP 自动选卡
    #[cfg(target_os = "linux")]
    fn apply_interface_bind(&self, fd: std::os::unix::io::RawFd, target_ip: std::net::IpAddr) {
        if let Some(ref iface) = self.default_interface {
            let _ = interface_finder::bind_to_interface(fd, iface);
        } else if self.auto_detect_interface {
            interface_finder::auto_bind_interface_for_target(fd, target_ip);
        }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    fn apply_interface_bind(&self, _fd: std::os::unix::io::RawFd, _target_ip: std::net::IpAddr) {}

    #[cfg(not(unix))]
    #[allow(dead_code)]
    fn apply_interface_bind(&self, _fd: i32, _target_ip: std::net::IpAddr) {}

    const TCP_CONNECT_TIMEOUT_SECS: u64 = 5;

    /// 向已解析的目标地址建立 TCP 连接，尊重 bind_address / auto_detect_interface / default_interface。
    async fn tcp_connect_addr(&self, addr: SocketAddr) -> anyhow::Result<TcpStream> {
        let connect_timeout = tokio::time::Duration::from_secs(Self::TCP_CONNECT_TIMEOUT_SECS);

        let stream = if let Some(bind_ip) = &self.config.bind_address {
            // 用户手动指定出口 IP
            let bind_addr: SocketAddr = format!("{bind_ip}:0").parse()?;
            let socket = if bind_addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            socket.set_reuseaddr(true)?;
            socket.bind(bind_addr)?;
            tokio::time::timeout(connect_timeout, socket.connect(addr))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "direct tcp connect timeout ({}s) to {}",
                        Self::TCP_CONNECT_TIMEOUT_SECS,
                        addr
                    )
                })??
        } else if self.default_interface.is_some() || self.auto_detect_interface {
            // 网卡绑定模式：在 connect 之前用 SO_BINDTODEVICE 绑定正确网卡
            let socket = if addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            socket.set_reuseaddr(true)?;
            {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    self.apply_interface_bind(socket.as_raw_fd(), addr.ip());
                }
            }
            tokio::time::timeout(connect_timeout, socket.connect(addr))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "direct tcp connect timeout ({}s) to {}",
                        Self::TCP_CONNECT_TIMEOUT_SECS,
                        addr
                    )
                })??
        } else {
            tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "direct tcp connect timeout ({}s) to {}",
                        Self::TCP_CONNECT_TIMEOUT_SECS,
                        addr
                    )
                })??
        };
        set_tcp_opts(&stream)?;
        apply_mark_to_tcp(&stream, self.routing_mark)?;
        Ok(stream)
    }

    /// 解析目标并建立 TCP 连接的统一入口。
    ///
    /// 域名目标在配置了 `network_strategy = "happy_eyeballs"` 且内部 DNS
    /// resolver 可用时，会并发/错峰尝试多个候选地址（IPv4 + IPv6，对齐
    /// sing-box `network_strategy` / `fallback_delay`）；其余情况（IP 目标、
    /// 未启用该策略、resolver 不可用、或解析候选为空）保持原有的单地址
    /// 解析 + 连接行为不变。
    async fn dial_tcp(&self, target: &crate::inbound::Target) -> anyhow::Result<TcpStream> {
        use crate::inbound::Target;

        let use_happy_eyeballs = self
            .config
            .network_strategy
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("happy_eyeballs"));

        if use_happy_eyeballs {
            if let (Target::Domain(host, port), Some(resolver)) = (target, self.resolver.as_ref()) {
                match resolver.resolve_domain_all(host).await {
                    Ok(ips) if !ips.is_empty() => {
                        let candidates: Vec<SocketAddr> = ips
                            .into_iter()
                            .map(|ip| SocketAddr::new(ip, *port))
                            .collect();
                        let fallback_delay = tokio::time::Duration::from_millis(
                            self.config.fallback_delay_ms.unwrap_or(250),
                        );
                        debug!(
                            tag=%self.config.tag,
                            host=%host,
                            candidates=candidates.len(),
                            fallback_delay_ms=fallback_delay.as_millis() as u64,
                            "happy_eyeballs: dialing multiple candidates"
                        );
                        return self
                            .connect_tcp_happy_eyeballs(&candidates, fallback_delay)
                            .await;
                    }
                    Ok(_) => {
                        // 候选为空，落到下面的常规单地址路径（会得到一致的报错信息）
                    }
                    Err(e) => {
                        debug!(
                            tag=%self.config.tag, host=%host, err=%e,
                            "happy_eyeballs: resolve_domain_all failed, falling back to single-address path"
                        );
                    }
                }
            }
        }

        let addr = resolve_target_with_dns(target, self.resolver.as_ref()).await?;
        self.tcp_connect_addr(addr).await
    }

    /// Happy Eyeballs（RFC 8305）风格的多候选地址拨号：按 `candidates` 顺序
    /// （已由 `resolve_domain_all` 按 strategy 排好优先级）逐个启动连接尝试，
    /// 每隔 `fallback_delay` 启动下一个候选而不必等前一个失败或超时；任意一个
    /// 候选率先连接成功就立即返回，其余仍在进行中的尝试随 `inflight` 一起被
    /// 丢弃，其底层 socket 在 drop 时自动关闭。
    async fn connect_tcp_happy_eyeballs(
        &self,
        candidates: &[SocketAddr],
        fallback_delay: tokio::time::Duration,
    ) -> anyhow::Result<TcpStream> {
        if candidates.is_empty() {
            anyhow::bail!("direct: no candidate addresses to connect");
        }
        if candidates.len() == 1 {
            return self.tcp_connect_addr(candidates[0]).await;
        }

        let mut remaining = candidates.iter().copied().peekable();
        let mut inflight = futures_util::stream::FuturesUnordered::new();
        let mut last_err: Option<anyhow::Error> = None;

        // 启动第一个候选（最优先地址，不必等待 fallback_delay）。
        if let Some(addr) = remaining.next() {
            inflight.push(self.tcp_connect_addr(addr));
        }

        loop {
            if inflight.is_empty() && remaining.peek().is_none() {
                break;
            }
            let has_more = remaining.peek().is_some();
            tokio::select! {
                biased;
                res = inflight.next(), if !inflight.is_empty() => {
                    match res {
                        Some(Ok(stream)) => return Ok(stream),
                        Some(Err(e)) => {
                            debug!(
                                tag=%self.config.tag, err=%e,
                                "happy_eyeballs: candidate failed, trying next if available"
                            );
                            last_err = Some(e);
                            if let Some(addr) = remaining.next() {
                                inflight.push(self.tcp_connect_addr(addr));
                            }
                        }
                        None => {}
                    }
                }
                _ = tokio::time::sleep(fallback_delay), if has_more => {
                    if let Some(addr) = remaining.next() {
                        debug!(
                            tag=%self.config.tag, addr=%addr,
                            "happy_eyeballs: fallback_delay elapsed, starting next candidate"
                        );
                        inflight.push(self.tcp_connect_addr(addr));
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("direct: all candidate addresses failed to connect")
        }))
    }

    /// 为单次 UDP 发送创建一个独立 socket，支持网卡绑定。
    async fn new_udp_socket(&self, dst: SocketAddr) -> anyhow::Result<tokio::net::UdpSocket> {
        if let Some(bind_ip) = &self.config.bind_address {
            let bind_addr: SocketAddr = format!("{bind_ip}:0").parse()?;
            let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
            apply_mark_to_udp(&sock, self.routing_mark)?;
            return Ok(sock);
        }

        let bind_addr = if dst.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let sock = tokio::net::UdpSocket::bind(bind_addr).await?;

        if self.default_interface.is_some() || self.auto_detect_interface {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                self.apply_interface_bind(sock.as_raw_fd(), dst.ip());
            }
        }

        apply_mark_to_udp(&sock, self.routing_mark)?;
        Ok(sock)
    }
}

#[async_trait::async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Direct".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = crate::inbound::Target::Domain(host.to_string(), port);
        let stream = self.dial_tcp(&target).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(tag=%self.config.tag, target=%conn.target, "direct tcp");
        let remote = self.dial_tcp(&conn.target).await?;
        let (up, down) = relay(conn.stream, remote).await;
        debug!(tag=%self.config.tag, up=%up, down=%down, "direct tcp done");
        Ok((up, down))
    }

    async fn handle_tcp_live(
        &self,
        mut conn: crate::inbound::InboundTcpStream,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) -> anyhow::Result<(u64, u64)> {
        conn.stream.set_live_counters(live_up, live_down);
        self.handle_tcp(conn).await
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let first_dst = resolve_target_with_dns(&packet.target, self.resolver.as_ref()).await?;
        debug!(tag=%self.config.tag, target=%packet.target, dst=%first_dst, "direct udp");

        let sock = std::sync::Arc::new(self.new_udp_socket(first_dst).await?);
        sock.send_to(&packet.data, first_dst).await?;

        let reply_tx = packet.session.reply_tx.clone();
        let client_src = packet.src;
        let tag = self.config.tag.clone();

        if let Some(mut rx) = packet.upstream_rx.take() {
            let sock_send = sock.clone();
            let resolver = self.resolver.clone();
            // 会话按 (src, outbound) 聚合后，同一客户端 socket 访问多个目标时
            // 复用一条出站 socket；每包需按 target 解析得到 dst。
            // 用 HashMap 缓存避免同一目标每包都走 DNS（DnsResolver 自身也有
            // 缓存，这里只是避免重复的 HashMap 查询与 Arc clone）。
            let first_target = packet.target.clone();
            tokio::spawn(async move {
                let mut dst_cache: std::collections::HashMap<Target, SocketAddr> =
                    std::collections::HashMap::new();
                dst_cache.insert(first_target, first_dst);
                while let Some((target, data)) = rx.recv().await {
                    let dst = match dst_cache.get(&target).copied() {
                        Some(d) => d,
                        None => match resolve_target_with_dns(&target, resolver.as_ref()).await {
                            Ok(d) => {
                                dst_cache.insert(target, d);
                                d
                            }
                            Err(e) => {
                                debug!(target=%target, err=%e, "direct udp: dns resolve error");
                                continue;
                            }
                        },
                    };
                    if let Err(e) = sock_send.send_to(&data, dst).await {
                        debug!(dst=%dst, err=%e, "direct udp: upstream send error");
                        break;
                    }
                }
            });
        }

        let sock_recv = sock;
        let guards = packet.lifetime_guards;
        // 参照 sing-box route.go routePacketConnection：FakeIP 命中时保存了
        // 原 fakeip SocketAddr 到 origin_destination，UDP 回包需把源地址伪装回
        // fakeip（对应 sing-box 的 bufio.NewNATPacketConn 包装）；
        // 非 FakeIP 场景回退到真实服务器地址 first_dst（保持原行为）。
        let spoofed_src = packet.origin_destination.unwrap_or(first_dst);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                if reply_tx.is_closed() {
                    break;
                }
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(30),
                    sock_recv.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _from))) => {
                        let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if reply_tx
                            .send((data, client_src, spoofed_src))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(tag=%tag, dst=%first_dst, err=%e, "direct udp: recv error");
                        break;
                    }
                    Err(_) => {
                        debug!(tag=%tag, dst=%first_dst, "direct udp: idle timeout (30s), closing recv loop");
                        break;
                    }
                }
            }
            drop(guards);
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_direct() -> DirectOutbound {
        DirectOutbound::new(DirectOutboundConfig {
            tag: "direct".into(),
            bind_address: None,
            network_strategy: Some("happy_eyeballs".into()),
            fallback_delay_ms: Some(50),
        })
    }

    /// 返回一个当前没有任何进程监听的本地地址：先 bind 拿到一个空闲端口，
    /// 再立刻 drop 监听器。在 loopback 上连接一个刚刚关闭的端口几乎总是
    /// 立刻收到 ECONNREFUSED（不会等到 5 秒连接超时），适合用来模拟"候选
    /// 地址连接失败"且不拖慢测试。
    async fn unused_addr() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn happy_eyeballs_falls_back_to_working_candidate() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let bad_addr = unused_addr().await;
        let ob = make_direct();

        let result = ob
            .connect_tcp_happy_eyeballs(
                &[bad_addr, good_addr],
                tokio::time::Duration::from_millis(50),
            )
            .await;
        assert!(
            result.is_ok(),
            "expected happy eyeballs to succeed via the working candidate, got {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_single_candidate_behaves_like_direct_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let ob = make_direct();
        let result = ob
            .connect_tcp_happy_eyeballs(&[addr], tokio::time::Duration::from_millis(50))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn happy_eyeballs_empty_candidates_errors() {
        let ob = make_direct();
        let result = ob
            .connect_tcp_happy_eyeballs(&[], tokio::time::Duration::from_millis(50))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn happy_eyeballs_all_candidates_failing_returns_error() {
        let bad1 = unused_addr().await;
        let bad2 = unused_addr().await;
        let ob = make_direct();
        let result = ob
            .connect_tcp_happy_eyeballs(&[bad1, bad2], tokio::time::Duration::from_millis(50))
            .await;
        assert!(result.is_err());
    }
}
