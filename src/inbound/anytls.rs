//! AnyTLS 服务端入站（对齐 sing-box `protocol/anytls/inbound.go` 行为面，
//! 参考实现：flux-master `src/anytls/server.rs` + `session.rs`）。
//!
//! ## 协议（服务端视角，完整线格式见 [`crate::protocol::anytls`] 模块头）
//! 1. TLS accept（AnyTLS 强制 TLS：启动时校验 `tls.enabled`，为 false 直接报错）
//! 2. 认证帧：`[sha256(password) 32B][padding0_len 2B BE][padding0]`，
//!    对照 users 列表各用户 sha256(password)（多用户哈希表，取
//!    `ProxyUser.password` 字段）
//! 3. 会话循环（复用 [`crate::protocol::anytls::run_server_session`]）：
//!    每个 cmdSYN 打开一条 stream，stream 首个 cmdPSH 载荷为 SOCKS5 目标地址：
//!    - 普通 TCP 目标 → [`ServerStream`](crate::protocol::anytls::ServerStream) 装箱为 [`SniffedStream::from_encrypted`]
//!      交给 dispatcher 路由（目标 = 客户端请求地址；peer = TLS 前捕获的
//!      客户端 socket）
//!    - 魔术地址 `sp.v2.udp-over-tcp.arpa` → sing UoT v2 UDP-over-session 模式
//!
//! ## UDP 说明
//! flux 参考实现没有 UDP 会话，但 reflex 自家 outbound 客户端通过 UoT v2
//! 魔术地址承载 UDP（见 `outbound/anytls.rs` `handle_udp`），服务端必须实现
//! 对应接收端才能与自家客户端互通 UDP，故此处实现 **UoT v2 无连接模式**
//! （isConnect=0，每包携带目标地址，reflex/sing-box 客户端均使用此模式；
//! isConnect=1 连接模式不支持，直接关闭 stream）。每个 UDP 包 → 一个
//! [`InboundUdpPacket`]（`upstream_rx: None`，dispatcher 按 src 自建会话通道），
//! 回包经 `session.reply_tx` 泵回此 stream（回包源地址取 dispatcher 的伪造
//! 源地址；域名目标时为 0.0.0.0 占位，reflex 客户端不校验回包地址）。
//!
//! ## raw_tcp 说明
//! [`SniffedStream::from_encrypted`] 的 `raw_tcp` 传 `None`：AnyTLS 是单条
//! TLS 连接上的多路复用，stream 是会话子流而非独立 TCP 连接；若提供整个
//! 会话 socket 的克隆，Drop-RST（拨号失败 / reject 的 SO_LINGER=0）会把
//! RST 发给**整个会话**，误杀同会话其他活跃 stream。VLESS/VMess 等 1:1
//! TLS 入站可以安全提供 raw_tcp，AnyTLS 不行。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::inbound::AnytlsInboundConfig;
use crate::inbound::proxy_common::bind_dual_stack_listener;
use crate::inbound::{
    display_sockaddr, parse_listen_addr, InboundTcpStream, InboundUdpPacket, SniffedStream, Target,
    UdpSession,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::anytls as proto;

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct AnytlsInbound {
    config: AnytlsInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl AnytlsInbound {
    pub fn new(
        config: AnytlsInboundConfig,
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
        // AnyTLS 是 TLS-only 协议（对齐 sing-box：anytls inbound 必须配置 tls）
        anyhow::ensure!(
            self.config.tls.enabled,
            "anytls inbound '{}': tls.enabled must be true (AnyTLS is TLS-only)",
            self.config.tag
        );

        // 用户表：sha256(password) → 用户名（认证帧直接比对哈希，无需明文）
        let mut users: HashMap<[u8; 32], String> = HashMap::new();
        for u in &self.config.users {
            if let Some(p) = &u.password {
                users
                    .entry(proto::password_hash(p))
                    .or_insert_with(|| u.name.clone().unwrap_or_else(|| "anonymous".to_string()));
            }
        }
        anyhow::ensure!(
            !users.is_empty(),
            "anytls inbound '{}': no users with password configured",
            self.config.tag
        );
        let users = Arc::new(users);

        // padding scheme（自定义 scheme 非法时报错退出）
        let padding = proto::SharedPadding::new_default();
        if let Some(s) = &self.config.padding_scheme {
            anyhow::ensure!(
                padding.update(s.as_bytes()),
                "anytls inbound '{}': invalid padding_scheme",
                self.config.tag
            );
        }

        // TLS（必需）
        let acceptor = Arc::new(crate::inbound::tls_server::build_acceptor(
            &self.config.tls,
        )?);

        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());
        let listener = bind_dual_stack_listener(bind).await?;
        info!(tag = %tag, addr = %bind, "anytls inbound starting");

        let tcp_tx = self.tcp_tx;
        let udp_tx = self.udp_tx;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(tag = %tag, err = %e, "anytls inbound accept error");
                    continue;
                }
            };

            let tcp_tx = tcp_tx.clone();
            let udp_tx = udp_tx.clone();
            let tag = tag.clone();
            let users = users.clone();
            let acceptor = acceptor.clone();
            let padding = padding.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_conn(stream, peer, acceptor, users, padding, tcp_tx, udp_tx, tag).await
                {
                    debug!(
                        peer = %display_sockaddr(peer),
                        err = %e,
                        "anytls inbound conn error"
                    );
                }
            });
        }
    }
}

// ── 连接处理 ─────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
    users: Arc<HashMap<[u8; 32], String>>,
    padding: proto::SharedPadding,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // 注意：不 try_clone 原始 TCP 作为 raw_tcp —— AnyTLS stream 是多路复用
    // 子流，会话级 RST 会误杀同会话其他 stream（见模块头说明）。
    let tls = acceptor
        .accept(stream)
        .await
        .map_err(|e| anyhow::anyhow!("anytls tls handshake: {e}"))?;
    let mut conn: Box<dyn AsyncReadWrite> = Box::new(tls);

    // 认证帧：sha256(password)[32] + padding0_len[2] + padding0（padding0 丢弃）
    let pwd_hash = proto::read_auth_packet(&mut conn)
        .await
        .map_err(|e| anyhow::anyhow!("anytls: read auth packet: {e}"))?;
    let Some(user) = users.get(&pwd_hash) else {
        anyhow::bail!("anytls: auth failed (unknown password)");
    };

    info!(
        peer = %display_sockaddr(peer),
        user = %user,
        tag = %tag,
        "anytls authenticated"
    );

    // 会话多路复用主循环；每条 stream 一个异步任务
    proto::run_server_session(conn, padding, move |stream| {
        let tcp_tx = tcp_tx.clone();
        let udp_tx = udp_tx.clone();
        let tag = tag.clone();
        async move {
            if let Err(e) = handle_stream(stream, peer, tcp_tx, udp_tx, tag).await {
                debug!(
                    peer = %display_sockaddr(peer),
                    err = %e,
                    "anytls stream error"
                );
            }
        }
    })
    .await
}

// ── Stream 处理 ──────────────────────────────────────────────────────────────

/// 处理一条新打开的会话 stream：
/// 1. 读 SOCKS5 目标地址（stream 首个 cmdPSH 载荷）
/// 2. UoT 魔术地址 → UDP 会话；否则包装为 [`InboundTcpStream`] 交给 dispatcher
async fn handle_stream(
    mut stream: proto::ServerStream,
    peer: SocketAddr,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    let target = proto::read_socks_addr(&mut stream).await?;
    debug!(
        peer = %display_sockaddr(peer),
        target = %target,
        sid = stream.stream_id,
        tag = %tag,
        "anytls stream opened"
    );

    if proto::is_uot_magic(&target) {
        run_uot_udp(stream, peer, udp_tx, tag).await;
        return Ok(());
    }

    // 普通 TCP：目标地址字节已从 stream 内部缓冲消费，剩余数据由 ServerStream
    // 自带缓冲无缝续读，无需 prepend。SYNACK 由 ServerStream 首次写时自动发送
    // （对齐 sing-anytls：拨号成功有下行数据才回 SYNACK；拨号失败客户端只见 FIN/EOF）。
    let inner: Box<dyn AsyncReadWrite> = Box::new(stream);
    let sniffed = SniffedStream::from_encrypted(inner, peer, None);

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

// ── UoT v2 UDP over session ──────────────────────────────────────────────────

/// UoT v2 无连接模式 UDP 会话主循环（对齐 outbound `handle_udp` 的发送端格式）。
///
/// - 上行：读请求头 `[isConnect][SOCKS5 目标]`（isConnect!=0 不支持，直接关闭），
///   然后逐帧读 `[sing ATYP][ADDR][PORT][LEN][DATA]` → 每包投递
///   [`InboundUdpPacket`]（`upstream_rx: None`，dispatcher 按 src 聚合会话）。
/// - 下行：dispatcher 回包经 `session.reply_tx` 到达，按伪造源地址（回包元组
///   第三元素）构建 UoT 每包帧写回 stream。
/// - 退出：上行 EOF（客户端 FIN / 会话关闭）或下行通道关闭。`select!` 退出时
///   两半都被丢弃 → ServerStream Drop 尽力发送 cmdFIN。
async fn run_uot_udp(
    stream: proto::ServerStream,
    peer: SocketAddr,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) {
    // stream 拆分为读写两半：上行循环与下行泵并发使用
    let (mut rd, mut wr) = tokio::io::split(stream);

    // 读 UoT v2 请求头：[isConnect 1B][SOCKS5 ATYP 目标][PORT 2B BE]
    let mut is_connect = [0u8; 1];
    if rd.read_exact(&mut is_connect).await.is_err() {
        return;
    }
    if is_connect[0] != 0 {
        // 连接模式（isConnect=1）不支持：reflex/sing-box 客户端恒用无连接模式。
        // 直接关闭 stream（ServerStream Drop 发 FIN），客户端读到 EOF。
        warn!(
            peer = %display_sockaddr(peer),
            tag = %tag,
            "anytls uot: connect-mode (isConnect=1) not supported, closing stream"
        );
        return;
    }
    let first_target = match proto::read_socks_addr(&mut rd).await {
        Ok(t) => t,
        Err(_) => return,
    };
    debug!(
        peer = %display_sockaddr(peer),
        first_target = %first_target,
        tag = %tag,
        "anytls uot udp session opened"
    );

    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);

    // ── 上行：读每包帧 → 投递 InboundUdpPacket ───────────────────────────────
    let uplink = {
        let udp_tx = udp_tx.clone();
        let tag = tag.clone();
        async move {
            while let Ok((target, data)) = proto::read_uot_packet(&mut rd).await {
                let packet = InboundUdpPacket {
                    data,
                    src: peer,
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

    // ── 下行：dispatcher 回包 → UoT 每包帧写回 stream ────────────────────────
    let downlink = async move {
        while let Some((data, _client, spoofed_src)) = reply_rx.recv().await {
            // 回包源地址用 dispatcher 提供的伪造源地址（域名为 0.0.0.0 占位，
            // reflex 客户端不校验回包地址，sing-box 用它做 NAT 匹配时以
            // 端口为准，可接受）
            let frame = proto::build_uot_packet(&Target::Socket(spoofed_src), &data);
            if wr.write_all(&frame).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    };

    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
    }
    debug!(
        peer = %display_sockaddr(peer),
        tag = %tag,
        "anytls uot udp session closed"
    );
}
