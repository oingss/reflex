//! ShadowQuic 服务端入站（0-RTT QUIC + JLS SNI 伪装，对齐 flux-master
//! `src/shadowquic/mod.rs` 的服务端胶水层，交付模型对齐 reflex vless 入站）。
//!
//! ## 协议概述
//! - 0-RTT QUIC：首包即数据，降低握手延迟
//! - JLS：SNI 伪装，TLS 握手呈现的是伪装域名（`server_name`），未认证流量
//!   透明转发到 `jls_upstream`（伪装上游）
//! - 认证：JLS 凭证即 `users` 列表的 username/password，由 crate 在 QUIC
//!   握手层完成，reflex 无需协议层解析
//!
//! ## 实现方式
//! shadowquic crate 提供高层 [`ShadowQuicServer`]（实现 crate 的 `Inbound`
//! trait，内部自行创建并绑定 UDP socket、跑 QUIC accept 循环）：
//! - `init()` 启动后台 QUIC accept 循环
//! - `accept()` 返回 [`ProxyRequest`]（Tcp 虚拟流 或 Udp 会话）
//!
//! reflex 适配层把请求桥接到 dispatcher：
//! - TCP：SQConnect 头已被 crate 消费，直接把虚拟流装箱为
//!   [`SniffedStream::from_encrypted`]（`raw_tcp: None`，底层是 QUIC 流而非
//!   TCP）交给 dispatcher 路由
//! - UDP：每个 QUIC UDP associate 会话独占一个会话 task，上行包逐包投递
//!   [`InboundUdpPacket`]（`upstream_rx: None`），回包经 `reply_tx` 回到
//!   会话 task 后经 crate 的 `UdpSend` 通道写回 QUIC（源地址伪装为原始目标）
//!
//! ## 已知限制（TODO）
//! - shadowquic crate 的 `ProxyRequest` 不暴露 QUIC 连接远端地址
//!   （`AnyTcp = Box<dyn TcpTrait>` 类型擦除，`UdpSession.bind_addr` 私有），
//!   因此 TCP 对端地址为占位 `0.0.0.0:0`，UDP 会话使用 `100.64.0.0/10` 段
//!   的每会话唯一伪源地址（保证 dispatcher 按 (src, outbound) 聚合会话时
//!   不同 QUIC 会话不被误合并）。日志中的对端地址不是真实客户端地址。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use shadowquic::{Inbound, ProxyRequest};
use shadowquic::shadowquic::inbound::ShadowQuicServer;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::inbound::ShadowQuicInboundConfig;
use crate::inbound::{
    InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession, display_sockaddr,
    parse_listen_addr,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::shadowquic::{build_server_cfg, socks_addr_to_target, target_to_socks_addr};

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct ShadowquicInbound {
    config: ShadowQuicInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

/// TCP 连接的占位对端地址（crate 不暴露 QUIC 远端地址，见模块注释）。
const TCP_PEER_PLACEHOLDER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

/// UDP 会话伪源地址计数器：映射到 `100.64.0.0/10`（CGNAT 保留段，不会与
/// 真实客户端地址冲突），末两个八位组承载会话序号。
static UDP_SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// 为每个 QUIC UDP associate 会话分配一个唯一的伪源地址。
///
/// dispatcher 按 `(src, outbound_tag)` 聚合 UDP 会话：同一 QUIC 会话的所有
/// 包必须共享同一伪源（复用一条出站连接），不同 QUIC 会话必须不同伪源
/// （避免不同客户端/不同 associate 的回包被误路由到第一条会话的 reply 通道）。
/// 序号取低 16 位回绕（65536 个会话后重用），实际并发生话间隔如此之大的
/// 情况可忽略。
fn next_pseudo_src() -> SocketAddr {
    let seq = UDP_SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(0x6440_0000u32.wrapping_add((seq & 0xFFFF) as u32))),
        0,
    )
}

impl ShadowquicInbound {
    pub fn new(
        config: ShadowQuicInboundConfig,
        tcp_tx: mpsc::Sender<InboundTcpStream>,
        udp_tx: mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self {
            config,
            tcp_tx,
            udp_tx,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());

        // JLS 伪装上游必填：缺失时无法构造 ShadowQuicServerCfg
        let jls_upstream = self.config.jls_upstream.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "shadowquic inbound '{}' requires jls_upstream (JLS 伪装上游 host:port)",
                self.config.tag
            )
        })?;

        // JLS 凭证即用户列表，空列表意味着没有任何客户端能通过认证
        anyhow::ensure!(
            !self.config.users.is_empty(),
            "shadowquic inbound '{}' requires at least one user (JLS credential)",
            self.config.tag
        );
        let users: Vec<(String, String)> = self
            .config
            .users
            .iter()
            .map(|u| (u.username.clone(), u.password.clone()))
            .collect();

        // 预绑定探测：shadowquic crate 的 QuicServer 自行创建并绑定 socket，
        // 且绑定失败时直接 panic（`expect("Failed to listening on udp")`）。
        // 此处先用 tokio 预绑定做端口占用预检，随即释放，把失败转化为
        // 优雅的 anyhow 错误而非 panic。
        let probe = UdpSocket::bind(bind)
            .await
            .map_err(|e| anyhow::anyhow!("shadowquic inbound '{tag}' bind {bind}: {e}"))?;
        drop(probe);

        let sq_cfg = build_server_cfg(
            bind,
            users,
            &jls_upstream,
            self.config.server_name.clone(),
            &self.config.congestion_control,
        );

        let mut server = ShadowQuicServer::new(sq_cfg)
            .await
            .map_err(|e| anyhow::anyhow!("shadowquic server create: {e}"))?;
        server
            .init()
            .await
            .map_err(|e| anyhow::anyhow!("shadowquic server init: {e}"))?;

        info!(
            tag = %tag,
            addr = %bind,
            users = self.config.users.len(),
            jls_upstream = %jls_upstream,
            "shadowquic inbound listening"
        );

        let tcp_tx = self.tcp_tx;
        let udp_tx = self.udp_tx;

        loop {
            match server.accept().await {
                Ok(ProxyRequest::Tcp(sess)) => {
                    let stream = sess.stream;
                    let dst = sess.dst;
                    let tcp_tx = tcp_tx.clone();
                    let tag = tag.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp(stream, dst, tcp_tx, tag).await {
                            debug!(err = %e, "shadowquic inbound tcp error");
                        }
                    });
                }
                Ok(ProxyRequest::Udp(sess)) => {
                    let udp_tx = udp_tx.clone();
                    let tag = tag.clone();
                    tokio::spawn(async move {
                        handle_udp_session(sess, udp_tx, tag).await;
                    });
                }
                Err(e) => {
                    warn!(err = %e, "shadowquic inbound accept error");
                    // 短暂休眠避免 busy loop（对齐 flux）
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

// ── TCP ──────────────────────────────────────────────────────────────────────

/// shadowquic `AnyTcp`（`Box<dyn TcpTrait>`）→ tokio 读写 trait 适配器。
///
/// shadowquic 使用自己的 `TcpTrait`（supertrait 含 Send + Sync），与
/// reflex 的 `AsyncReadWrite` 不是同一 trait，需手动委托。
struct SqStream(shadowquic::AnyTcp);

impl tokio::io::AsyncRead for SqStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SqStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

/// 处理一条 SQConnect 虚拟流：装箱交给 dispatcher 路由。
///
/// - SQConnect 请求头已被 crate 消费，无 prefix 可 prepend
/// - 底层是 QUIC bi-stream 而非 TCP，`raw_tcp: None`（无 Drop-RST 语义）
async fn handle_tcp(
    stream: shadowquic::AnyTcp,
    dst: shadowquic::msgs::socks5::SocksAddr,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    let target = socks_addr_to_target(&dst);
    // Box<dyn TcpTrait> → Box<dyn AsyncReadWrite>：Tokio 的 AsyncRead/AsyncWrite
    // 与 shadowquic 的 TcpTrait 是两套 trait，需显式适配器委托转发
    let inner: Box<dyn AsyncReadWrite> = Box::new(SqStream(stream));
    let sniffed = SniffedStream::from_encrypted(inner, TCP_PEER_PLACEHOLDER, None);

    debug!(tag = %tag, target = %target, "shadowquic tcp connect");

    tcp_tx
        .send(InboundTcpStream {
            stream: sniffed,
            target,
            inbound_tag: (*tag).clone(),
            sniffed_protocol: None,
            sniffed_domain: None,
        })
        .await
        .ok();
    Ok(())
}

// ── UDP ──────────────────────────────────────────────────────────────────────

/// 处理一个 QUIC UDP associate 会话（每个会话独占一个 task）。
///
/// - 上行：`UdpRecv::recv_from` 读到 `(payload, target)`，逐包投递
///   [`InboundUdpPacket`]（`upstream_rx: None`，dispatcher 自建会话上行通道；
///   伪源地址保证会话聚合正确）
/// - 下行：dispatcher 出站的回包经 `reply_tx` 回来，源地址优先使用回包元组
///   携带的伪造源地址（即客户端请求的真实目标），域名目标回退"最近上行目标"
///   （保留域名形式，使客户端 NAT 能按域名匹配），经 `UdpSend::send_to`
///   写回 QUIC 会话
async fn handle_udp_session(
    sess: shadowquic::UdpSession,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) {
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
    // 最近一次上行包的目标（域名目标回包的源地址回退；Socket 目标用回包
    // 元组的伪造源地址，精确到每个回包）
    let last_target: Arc<Mutex<Option<Target>>> = Arc::new(Mutex::new(None));
    let pseudo_src = next_pseudo_src();

    // crate 的会话句柄：recv 为 Box<dyn UdpRecv>（&mut 调用），
    // send 为 Arc<dyn UdpSend>（可 clone，&self 调用）
    let mut recv = sess.recv;
    let send = sess.send;

    // ── 上行：QUIC 会话 → dispatcher ─────────────────────────────────────────
    let uplink = {
        let udp_tx = udp_tx.clone();
        let tag = tag.clone();
        let last_target = last_target.clone();
        async move {
            loop {
                let (data, dst) = match recv.recv_from().await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(err = %e, "shadowquic udp session recv ended");
                        break;
                    }
                };
                let target = socks_addr_to_target(&dst);
                *last_target.lock().unwrap() = Some(target.clone());
                let packet = InboundUdpPacket {
                    data,
                    src: pseudo_src,
                    target,
                    inbound_tag: (*tag).clone(),
                    session: UdpSession {
                        reply_tx: reply_tx.clone(),
                    },
                    sniffed_protocol: None,
                    sniffed_domain: None,
                    origin_destination: None,
                    upstream_rx: None,
                    lifetime_guards: vec![],
                };
                if udp_tx.send(packet).await.is_err() {
                    break;
                }
            }
        }
    };

    // ── 下行：dispatcher 回包 → QUIC 会话 ────────────────────────────────────
    let downlink = {
        let last_target = last_target.clone();
        async move {
            while let Some((data, _client, spoofed)) = reply_rx.recv().await {
                // 源地址：出站伪造源地址（= 客户端请求的 Socket 目标）精确可用；
                // 域名目标的伪造地址是 0.0.0.0:port 占位（IP 未指定），回退到
                // 最近上行目标（保留域名形式）
                let addr = if spoofed.ip().is_unspecified() {
                    let t = last_target.lock().unwrap().clone();
                    match t {
                        Some(t) => target_to_socks_addr(&t),
                        None => {
                            debug!("shadowquic udp reply: no routable address, dropping");
                            continue;
                        }
                    }
                } else {
                    spoofed.into()
                };
                if send.send_to(data, addr).await.is_err() {
                    break;
                }
            }
        }
    };

    // 会话生命周期：任一方向结束即退出。QUIC 断开 → recv 出错 → 上行结束；
    // dispatcher 侧 udp_timeout 回收 → reply_rx 关闭 → 下行结束。
    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
    }
    debug!(tag = %tag, peer = %display_sockaddr(pseudo_src), "shadowquic udp session closed");
}
