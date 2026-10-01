//! TUIC v5 服务端入站（QUIC，对齐 sing-box `protocol/tuic` inbound 与
//! flux `tuic/server.rs + connection.rs` 的行为面，配置格式与 sing-box 一致）。
//!
//! ## 协议（详见 `crate::protocol::tuic` 模块头）
//! - 客户端在任一 uni-stream 上发送 Authenticate 帧
//!   `[Ver 0x05][Cmd 0x00][UUID 16B][Token 32B]`，Token 为
//!   `export_keying_material(label=uuid 16B, context=password 字节, 32B)`
//!   （与 flux `validate_token`、reflex outbound 客户端完全一致）。
//! - TCP：Connect（bi-stream，客户端首写合并 `[Ver][Cmd=0x01][ADDR]` 与用户
//!   数据）→ 服务端精确读出帧头后，把 bi-stream 双向转发给 dispatcher 路由。
//! - UDP：Packet（datagram 或 uni-stream packet-stream，按客户端首包记忆
//!   模式）→ 分片重组后逐包投递 `InboundUdpPacket`（`upstream_rx: None`，
//!   dispatcher 自建会话上行通道）；回包经 `session.reply_tx` 到达 pump，
//!   按客户端 UDP 模式以 datagram 或 uni-stream 写回（对齐 flux
//!   `relay_udp_to_client`）。Dissociate（uni-stream）或空闲超时回收会话。
//! - 心跳：服务端每 `heartbeat` 秒向客户端发送 `[Ver][Cmd=0x04]` datagram
//!   （对齐 sing-box `loopHeartbeats`），不依赖 QUIC 原生 PING 保活。
//!
//! ## 认证模型
//! 每条 QUIC 连接独立认证（auth_timeout 内未认证即断开）；Connect/Packet
//! 等后续命令在认证完成前挂起等待（对齐 flux `Authenticated::wait`）。
//!
//! ## 交付模型
//! TCP：`SniffedStream::from_encrypted`（quinn bi-stream 适配为
//! `Box<dyn AsyncReadWrite>`，peer 为 QUIC 远端地址）交给 dispatcher。
//! UDP：每个 TUIC session（SessionID）一条回包 pump 任务 + `reply_tx` 通道，
//! 回包元组 `(data, client_addr, spoofed_src)`，spoofed_src 取回包目标地址。

use std::{
    collections::HashMap,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, Mutex as AsyncMutex, Notify},
};
use tracing::{debug, info, warn};

use crate::config::inbound::TuicInboundConfig;
use crate::inbound::{
    display_sockaddr, parse_listen_addr, InboundTcpStream, InboundUdpPacket, SniffedStream, Target,
    UdpSession,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::tuic::{
    build_heartbeat_frame, build_udp_packet_header, is_tuic_prefix, parse_address, parse_udp_datagram,
    parse_uuid, send_udp_fragmented, CMD_AUTHENTICATE, CMD_CONNECT, CMD_DISSOCIATE, CMD_HEARTBEAT,
    CMD_PACKET, ATYP_EMPTY, ATYP_FQDN, ATYP_IPV4, ATYP_IPV6, IDLE_TIMEOUT_MS, ParsedAddr,
    QUIC_CONN_WINDOW, QUIC_STREAM_WINDOW, TUIC_ALPN, TUIC_ALPN_H3, UdpPacketMeta,
};

/// UDP 会话空闲超时：回包通道无流量且上行停滞后回收 pump（sing-box tuic
/// 服务端 udp_timeout 语义，默认 60s）。
const UDP_SESSION_IDLE: Duration = Duration::from_secs(60);

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct TuicInbound {
    config: TuicInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

/// 用户表条目：显示名 + 密码（Token 校验的 context）
struct UserEntry {
    name: String,
    password: String,
}

impl TuicInbound {
    pub fn new(
        config: TuicInboundConfig,
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
        // TUIC 是 QUIC 协议，必须 TLS（build_server_config 内部也会校验，
        // 此处给出更明确的错误信息）
        anyhow::ensure!(
            self.config.tls.enabled,
            "tuic inbound: tls.enabled is required (TUIC runs over QUIC/TLS 1.3)"
        );

        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());

        // ── 用户表：uuid → (name, password) ─────────────────────────────────
        let mut users: HashMap<[u8; 16], UserEntry> = HashMap::new();
        for u in &self.config.users {
            let uuid = parse_uuid(&u.uuid)?;
            users.entry(uuid).or_insert_with(|| UserEntry {
                name: u.name.clone().unwrap_or_else(|| "anonymous".to_string()),
                password: u.password.clone(),
            });
        }
        anyhow::ensure!(!users.is_empty(), "tuic inbound: no users configured");
        let users = Arc::new(users);

        // ── TLS 服务端配置（复用 inbound::tls_server，QUIC 要求 TLS 1.3）─────
        let mut tls_cfg = (*crate::inbound::tls_server::build_server_config(&self.config.tls)?)
            .clone();

        // ALPN：用户显式配置优先；缺省同时接受标准 TUIC v5 的 "h3"
        // （sing-box / flux 客户端）与 reflex 客户端缺省的 "tuic"
        if self.config.tls.alpn.is_empty() {
            tls_cfg.alpn_protocols = vec![TUIC_ALPN_H3.to_vec(), TUIC_ALPN.to_vec()];
        }

        // 0-RTT：对齐 flux `max_early_data_size = u32::MAX`
        if self.config.zero_rtt_handshake {
            tls_cfg.max_early_data_size = u32::MAX;
        }

        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg)
            .map_err(|e| anyhow::anyhow!("tuic inbound: QUIC crypto config: {e}"))?;

        // ── QUIC 传输参数（镜像 outbound 客户端侧的构造）────────────────────
        let mut transport = quinn::TransportConfig::default();
        transport
            .stream_receive_window(
                quinn::VarInt::from_u64(QUIC_STREAM_WINDOW).unwrap_or(quinn::VarInt::MAX),
            )
            .receive_window(quinn::VarInt::from_u64(QUIC_CONN_WINDOW).unwrap_or(quinn::VarInt::MAX))
            .send_window(QUIC_CONN_WINDOW)
            .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
            .max_idle_timeout(Some(quinn::VarInt::from_u32(IDLE_TIMEOUT_MS).into()))
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(512))
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(512));

        // ── 拥塞控制（与 outbound 侧一致：cubic/new_reno→Cubic，bbr→BBR）─────
        let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
            match self.config.congestion_control.to_ascii_lowercase().as_str() {
                "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
                _ => Arc::new(quinn::congestion::CubicConfig::default()),
            };
        transport.congestion_controller_factory(cc_factory);

        let mut server_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        server_cfg.transport_config(Arc::new(transport));

        let endpoint = quinn::Endpoint::server(server_cfg, bind)
            .map_err(|e| anyhow::anyhow!("tuic inbound: endpoint bind {bind}: {e}"))?;

        info!(
            tag = %tag,
            addr = %bind,
            users = users.len(),
            cc = %self.config.congestion_control,
            zero_rtt = self.config.zero_rtt_handshake,
            "tuic inbound listening"
        );

        let heartbeat = Duration::from_secs(self.config.heartbeat.max(1));
        let auth_timeout = Duration::from_secs(self.config.auth_timeout.max(1));

        // ── Accept 循环 ─────────────────────────────────────────────────────
        loop {
            let Some(incoming) = endpoint.accept().await else {
                warn!(tag = %tag, "tuic inbound endpoint closed");
                break;
            };
            let connecting = match incoming.accept() {
                Ok(c) => c,
                Err(e) => {
                    debug!(tag = %tag, err = %e, "tuic inbound accept error");
                    continue;
                }
            };
            let conn = match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    // ALPN 不匹配等握手失败属正常探测流量
                    debug!(tag = %tag, err = %e, "tuic inbound handshake failed");
                    continue;
                }
            };

            let ctx = Arc::new(ConnCtx {
                conn,
                users: users.clone(),
                tag: (*tag).clone(),
                tcp_tx: self.tcp_tx.clone(),
                udp_tx: self.udp_tx.clone(),
                auth: AuthState::new(),
                auth_timeout,
                heartbeat,
                udp_sessions: AsyncMutex::new(HashMap::new()),
                udp_mode: Mutex::new(None),
                defrag: AsyncMutex::new(HashMap::new()),
            });

            tokio::spawn(async move {
                ctx.run().await;
            });
        }

        Ok(())
    }
}

// ── 连接上下文 ───────────────────────────────────────────────────────────────

/// 每条 QUIC 连接的共享状态（Arc 包装，事件循环 spawn 的任务共享）。
struct ConnCtx {
    conn: quinn::Connection,
    users: Arc<HashMap<[u8; 16], UserEntry>>,
    tag: String,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    auth: AuthState,
    auth_timeout: Duration,
    heartbeat: Duration,
    /// TUIC UDP 会话表：session_id → 会话句柄
    udp_sessions: AsyncMutex<HashMap<u16, UdpSessHandle>>,
    /// 客户端 UDP 传输模式（首包记忆；datagram vs uni-stream packet-stream）
    udp_mode: Mutex<Option<UdpMode>>,
    /// 分片重组表：packet_id → (重组缓冲, 最近活跃时刻)，按连接维度共享
    defrag: AsyncMutex<HashMap<u16, (TuicFragBuffer, std::time::Instant)>>,
}

/// 客户端 UDP 传输模式（对齐 flux `UdpMode`）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UdpMode {
    /// QUIC datagram 模式（reflex / sing-box 默认）
    Native,
    /// uni-stream packet-stream 模式
    Quic,
}

/// 一个 TUIC UDP 会话的回包通道句柄。
/// 持有方全部 drop（Dissociate / pump 退出清理）后 pump 自然退出。
struct UdpSessHandle {
    reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
}

/// 认证状态（对齐 flux `Authenticated`：Notify 广播 + 双重检查）。
struct AuthState {
    user: Mutex<Option<String>>,
    notify: Notify,
}

impl AuthState {
    fn new() -> Self {
        Self {
            user: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    fn is_authenticated(&self) -> bool {
        self.user.lock().unwrap().is_some()
    }

    fn set(&self, name: String) {
        *self.user.lock().unwrap() = Some(name);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        if self.is_authenticated() {
            return;
        }
        let notified = self.notify.notified();
        // 双重检查：注册 notified 与检查之间可能已被 set
        if self.is_authenticated() {
            return;
        }
        notified.await;
    }
}

// ── 事件循环 ─────────────────────────────────────────────────────────────────

impl ConnCtx {
    async fn run(self: Arc<Self>) {
        let peer = self.conn.remote_address();
        info!(tag = %self.tag, peer = %display_sockaddr(peer), "tuic connection opened");

        // 认证超时看门狗：auth_timeout 内未认证则断开（对齐 flux）
        {
            let ctx = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(ctx.auth_timeout).await;
                if !ctx.auth.is_authenticated() {
                    warn!(tag = %ctx.tag, peer = %display_sockaddr(peer), "tuic auth timeout, closing");
                    ctx.conn.close(quinn::VarInt::from_u32(0), b"auth timeout");
                }
            });
        }

        // 服务端 → 客户端应用层心跳（对齐 sing-box loopHeartbeats / flux）
        {
            let ctx = self.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(ctx.heartbeat);
                // 跳过第一次立即触发（连接刚建立，无需立即发心跳）
                ticker.tick().await;
                loop {
                    if ctx.conn.close_reason().is_some() {
                        return;
                    }
                    ticker.tick().await;
                    if ctx.conn.close_reason().is_some() {
                        return;
                    }
                    if ctx.conn.send_datagram(build_heartbeat_frame()).is_err() {
                        return;
                    }
                }
            });
        }

        // 事件循环：uni-stream（Authenticate/Packet-stream/Dissociate）、
        // bi-stream（Connect）、datagram（Packet/Heartbeat）并发处理
        loop {
            if self.conn.close_reason().is_some() {
                break;
            }
            let event = async {
                tokio::select! {
                    res = self.conn.accept_uni() => {
                        let recv = res?;
                        let ctx = self.clone();
                        tokio::spawn(async move { ctx.handle_uni(recv).await });
                    }
                    res = self.conn.accept_bi() => {
                        let (send, recv) = res?;
                        let ctx = self.clone();
                        tokio::spawn(async move { ctx.handle_bi(send, recv).await });
                    }
                    res = self.conn.read_datagram() => {
                        let dg = res?;
                        let ctx = self.clone();
                        tokio::spawn(async move { ctx.handle_datagram(dg).await });
                    }
                }
                Ok::<(), anyhow::Error>(())
            };

            if event.await.is_err() {
                // QUIC 连接关闭/流耗尽 → 事件循环退出
                break;
            }
        }

        debug!(tag = %self.tag, peer = %display_sockaddr(peer), "tuic connection closed");
    }

    // ── uni-stream：Authenticate / Packet（stream 模式）/ Dissociate ─────────

    async fn handle_uni(self: Arc<Self>, mut recv: quinn::RecvStream) {
        // 读 2 字节 Ver+Cmd 前缀并校验（对齐 flux handle_uni）
        let mut prefix = [0u8; 2];
        if recv.read_exact(&mut prefix).await.is_err() {
            return;
        }
        if !is_tuic_prefix(prefix) {
            warn!(tag = %self.tag, "tuic: non-TUIC uni stream, ignoring");
            return;
        }

        match prefix[1] {
            CMD_AUTHENTICATE => {
                let mut buf = [0u8; 48];
                if recv.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let uuid: [u8; 16] = buf[..16].try_into().unwrap();
                let token: [u8; 32] = buf[16..].try_into().unwrap();
                self.handle_authenticate(uuid, token).await;
            }
            CMD_PACKET => {
                // 等待认证（对齐 flux：Packet 处理前挂起至认证完成）
                if !self.wait_auth().await {
                    return;
                }
                let Some(meta) = self.read_packet_header(&mut recv).await else {
                    return;
                };
                let mut payload = vec![0u8; meta.data_len];
                if recv.read_exact(&mut payload).await.is_err() {
                    return;
                }
                self.handle_packet_data(meta, Bytes::from(payload), UdpMode::Quic)
                    .await;
            }
            CMD_DISSOCIATE => {
                if !self.wait_auth().await {
                    return;
                }
                let mut buf = [0u8; 2];
                if recv.read_exact(&mut buf).await.is_err() {
                    return;
                }
                let session_id = u16::from_be_bytes(buf);
                debug!(tag = %self.tag, session = session_id, "tuic udp dissociate");
                self.udp_sessions.lock().await.remove(&session_id);
            }
            CMD_HEARTBEAT => {
                debug!(tag = %self.tag, "tuic heartbeat (uni stream)");
            }
            cmd => {
                warn!(tag = %self.tag, cmd, "tuic: unexpected command on uni stream");
            }
        }
    }

    // ── bi-stream：Connect（TCP）────────────────────────────────────────────

    async fn handle_bi(self: Arc<Self>, send: quinn::SendStream, mut recv: quinn::RecvStream) {
        let mut prefix = [0u8; 2];
        if recv.read_exact(&mut prefix).await.is_err() {
            return;
        }
        if !is_tuic_prefix(prefix) {
            warn!(tag = %self.tag, "tuic: non-TUIC bi stream, ignoring");
            return;
        }
        if prefix[1] != CMD_CONNECT {
            warn!(tag = %self.tag, cmd = prefix[1], "tuic: unexpected command on bi stream");
            return;
        }

        // 等待认证（对齐 flux：Connect 处理前挂起至认证完成）
        if !self.wait_auth().await {
            return;
        }

        // 解析 Connect 地址。客户端首写合并 `[Ver][Cmd][ADDR]` 与用户数据，
        // read_exact 精确消费帧头，剩余数据保留在 RecvStream 中。
        let Some((addr, _)) = read_address(&mut recv).await else {
            warn!(tag = %self.tag, "tuic: truncated connect address");
            return;
        };
        let Some(target) = addr.to_target() else {
            warn!(tag = %self.tag, "tuic: connect with empty address");
            return;
        };

        debug!(
            tag = %self.tag,
            peer = %display_sockaddr(self.conn.remote_address()),
            target = %target,
            "tuic tcp connect"
        );

        // quinn bi-stream → AsyncReadWrite → SniffedStream 交付 dispatcher。
        // 帧头已精确消费，无需 prepend。
        let inner: Box<dyn AsyncReadWrite> = Box::new(QuinnBiStream { send, recv });
        let stream = SniffedStream::from_encrypted(inner, self.conn.remote_address(), None);

        self.tcp_tx
            .send(InboundTcpStream {
                stream,
                target,
                inbound_tag: self.tag.clone(),
                sniffed_protocol: None,
                sniffed_domain: None,
            })
            .await
            .ok();
    }

    // ── datagram：Packet（datagram 模式）/ Heartbeat ────────────────────────

    async fn handle_datagram(self: Arc<Self>, dg: Bytes) {
        if dg.len() < 2 || !is_tuic_prefix([dg[0], dg[1]]) {
            return;
        }

        match dg[1] {
            CMD_HEARTBEAT => {
                debug!(tag = %self.tag, "tuic heartbeat (datagram)");
                return;
            }
            CMD_PACKET => {}
            _ => {
                warn!(tag = %self.tag, cmd = dg[1], "tuic: unexpected datagram command");
                return;
            }
        }

        // 等待认证（对齐 flux）
        if !self.wait_auth().await {
            return;
        }

        let Some(meta) = parse_udp_datagram(&dg) else {
            debug!(tag = %self.tag, "tuic: malformed packet datagram, dropping");
            return;
        };
        let payload = dg.slice(meta.data_offset..meta.data_offset + meta.data_len);
        self.handle_packet_data(meta, payload, UdpMode::Native).await;
    }

    // ── 认证 ────────────────────────────────────────────────────────────────

    async fn handle_authenticate(&self, uuid: [u8; 16], token: [u8; 32]) {
        if self.auth.is_authenticated() {
            debug!(tag = %self.tag, "tuic: duplicate authentication, ignoring");
            return;
        }

        let Some(user) = self.users.get(&uuid) else {
            warn!(tag = %self.tag, "tuic: unknown uuid, closing");
            self.conn.close(quinn::VarInt::from_u32(0), b"auth failed");
            return;
        };

        // Token 校验：TLS keying material exporter
        // label = uuid 原始 16 字节，context = password 字节（与 flux
        // `validate_token`、sing-tuic、reflex outbound 客户端完全一致）
        let mut expected = [0u8; 32];
        let valid = self
            .conn
            .export_keying_material(&mut expected, &uuid, user.password.as_bytes())
            .is_ok()
            && expected == token;

        if valid {
            info!(tag = %self.tag, user = %user.name, "tuic authenticated");
            self.auth.set(user.name.clone());
        } else {
            warn!(tag = %self.tag, user = %user.name, "tuic authentication failed, closing");
            self.conn.close(quinn::VarInt::from_u32(0), b"auth failed");
        }
    }

    /// 等待认证完成（带 auth_timeout 上限）。返回 false 表示超时。
    async fn wait_auth(&self) -> bool {
        if self.auth.is_authenticated() {
            return true;
        }
        tokio::select! {
            () = self.auth.wait() => true,
            () = tokio::time::sleep(self.auth_timeout) => {
                warn!(tag = %self.tag, "tuic: auth wait timeout on stream/datagram");
                false
            }
        }
    }

    // ── UDP ─────────────────────────────────────────────────────────────────

    /// 从流中读取 Packet 帧头（8B 定长字段 + 可变长 ADDR），stream 模式用。
    async fn read_packet_header(&self, recv: &mut quinn::RecvStream) -> Option<UdpPacketMeta> {
        let mut buf = [0u8; 8];
        recv.read_exact(&mut buf).await.ok()?;
        let session_id = u16::from_be_bytes([buf[0], buf[1]]);
        let packet_id = u16::from_be_bytes([buf[2], buf[3]]);
        let frag_total = buf[4];
        let frag_id = buf[5];
        let data_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        let (addr, _) = read_address(recv).await?;
        Some(UdpPacketMeta {
            session_id,
            packet_id,
            frag_total,
            frag_id,
            addr,
            data_offset: 0,
            data_len,
        })
    }

    /// 处理一个（可能为分片的）UDP Packet（datagram / uni-stream 两种模式共用）。
    async fn handle_packet_data(self: Arc<Self>, meta: UdpPacketMeta, payload: Bytes, mode: UdpMode) {
        // 记忆客户端 UDP 模式（对齐 flux udp_mode：首包定型，混用仅告警）
        {
            let mut m = self.udp_mode.lock().unwrap();
            match *m {
                None => *m = Some(mode),
                Some(existing) => {
                    if existing != mode {
                        debug!(
                            tag = %self.tag,
                            "tuic: udp mode mismatch (expected {existing:?}, got {mode:?})"
                        );
                    }
                }
            }
        }

        let session_id = meta.session_id;
        let peer = self.conn.remote_address();

        // 获取或创建 TUIC UDP 会话（回包 pump + reply 通道）
        let reply_tx = {
            let mut sessions = self.udp_sessions.lock().await;
            if let Some(h) = sessions.get(&session_id) {
                h.reply_tx.clone()
            } else {
                let (reply_tx, reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
                sessions.insert(
                    session_id,
                    UdpSessHandle {
                        reply_tx: reply_tx.clone(),
                    },
                );
                // 回包 pump：reply_tx 全部 drop（Dissociate/空闲超时）后退出并自我清理
                let pump_ctx = self.clone();
                let cleanup_ctx = pump_ctx.clone();
                tokio::spawn(async move {
                    Self::pump_udp_reply(pump_ctx, session_id, reply_rx).await;
                    cleanup_ctx.udp_sessions.lock().await.remove(&session_id);
                });
                reply_tx
            }
        };

        // ── 分片处理（对齐 sing-quic udpDefragger / flux TuicFragBuffer）────
        if meta.frag_total <= 1 {
            let Some(target) = meta.addr.to_target() else {
                debug!(tag = %self.tag, "tuic udp: packet without address, dropping");
                return;
            };
            self.deliver_udp(session_id, peer, target, payload, reply_tx)
                .await;
            return;
        }

        // 分片重组：frag_id=0 携带目标地址，其余分片地址为 Empty
        let frag_addr = if meta.frag_id == 0 {
            Some(meta.addr.clone())
        } else {
            None
        };

        let reassembled = {
            let mut defrag = self.defrag.lock().await;
            let now = std::time::Instant::now();
            let entry = defrag
                .entry(meta.packet_id)
                .or_insert_with(|| (TuicFragBuffer::new(meta.frag_total), now));
            // frag_total 不一致（客户端重发/混乱）→ 重建缓冲，防索引越界
            if entry.0.frag_total != meta.frag_total {
                *entry = (TuicFragBuffer::new(meta.frag_total), now);
            }
            entry.1 = now;
            match entry.0.insert(meta.frag_id, payload, frag_addr) {
                Some((data, addr)) => {
                    defrag.remove(&meta.packet_id);
                    addr.to_target().map(|t| (data, t))
                }
                None => None,
            }
        };

        // 清理超时的未完成重组组，防内存泄漏
        if self.defrag.lock().await.len() > 8 {
            let now = std::time::Instant::now();
            self.defrag.lock().await.retain(|_, (_, last)| {
                now.duration_since(*last) < crate::protocol::tuic::FRAG_REASSEMBLY_TIMEOUT
            });
        }

        if let Some((data, target)) = reassembled {
            debug!(
                tag = %self.tag,
                session = session_id,
                pkt = meta.packet_id,
                len = data.len(),
                "tuic udp reassembled"
            );
            self.deliver_udp(session_id, peer, target, data, reply_tx)
                .await;
        }
    }

    /// 投递一个完整的 UDP 包给 dispatcher。
    async fn deliver_udp(
        &self,
        _session_id: u16,
        peer: SocketAddr,
        target: Target,
        data: Bytes,
        reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
    ) {
        let packet = InboundUdpPacket {
            data,
            src: peer,
            target,
            inbound_tag: self.tag.clone(),
            session: UdpSession { reply_tx },
            sniffed_protocol: None,
            sniffed_domain: None,
            origin_destination: None,
            // dispatcher 自建会话上行通道（对齐 vless run_udp_over_tcp 交付模型）
            upstream_rx: None,
            lifetime_guards: vec![],
        };
        if self.udp_tx.send(packet).await.is_err() {
            debug!(tag = %self.tag, "tuic: udp dispatcher closed");
        }
    }

    /// 回包 pump：从 reply 通道读 `(data, client_addr, spoofed_src)`，
    /// 按客户端 UDP 模式写回（对齐 flux `relay_udp_to_client`）。
    async fn pump_udp_reply(
        ctx: Arc<ConnCtx>,
        session_id: u16,
        mut reply_rx: mpsc::Receiver<(Bytes, SocketAddr, SocketAddr)>,
    ) {
        let mut pkt_id: u16 = 0;
        loop {
            match tokio::time::timeout(UDP_SESSION_IDLE, reply_rx.recv()).await {
                Ok(Some((data, _client, spoofed))) => {
                    pkt_id = pkt_id.wrapping_add(1);
                    // 回包 ADDR 用伪造源地址（即客户端请求时的目标地址）
                    let target = Target::Socket(spoofed);
                    let mode = *ctx.udp_mode.lock().unwrap();
                    match mode {
                        Some(UdpMode::Quic) => {
                            // packet-stream 模式：header + payload 写入 uni-stream
                            if data.len() > u16::MAX as usize {
                                debug!("tuic udp reply: oversized packet in stream mode, dropping");
                                continue;
                            }
                            let header = build_udp_packet_header(
                                session_id,
                                pkt_id,
                                0,
                                1,
                                &target,
                                data.len(),
                            );
                            match ctx.conn.open_uni().await {
                                Ok(mut s) => {
                                    let _ = s.write_all(&header).await;
                                    let _ = s.write_all(&data).await;
                                    let _ = s.finish();
                                }
                                Err(_) => break,
                            }
                        }
                        _ => {
                            // datagram 模式（含未定型）：大包自动分片
                            if send_udp_fragmented(&ctx.conn, session_id, pkt_id, &target, &data)
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
                Ok(None) => break, // 会话被 Dissociate / 所有 reply_tx 已 drop
                Err(_) => break,   // 空闲超时
            }
        }
    }
}

// ── 分片重组缓冲（对齐 flux TuicFragBuffer / sing-quic udpDefragger）─────────

/// TUIC UDP 分片重组缓冲区。
///
/// 当 UDP 包超过 QUIC datagram MTU 时，客户端将其拆分为多个分片。只有
/// frag_id=0 携带目标地址，其余分片地址为 Empty。服务端收集全部分片后
/// 按 frag_id 顺序拼接。
struct TuicFragBuffer {
    frag_total: u8,
    frags: Vec<Option<Bytes>>,
    received: u8,
    /// 来自 frag_id=0 的目标地址（其余分片地址为 Empty）
    addr: Option<ParsedAddr>,
}

impl TuicFragBuffer {
    fn new(frag_total: u8) -> Self {
        Self {
            frag_total,
            frags: vec![None; frag_total as usize],
            received: 0,
            addr: None,
        }
    }

    /// 插入一个分片。返回 `Some((payload, addr))` 表示全部分片已到齐并重组完成。
    /// 对齐 sing-quic udpDefragger.feed：重复 frag_id 不计数。
    fn insert(
        &mut self,
        frag_id: u8,
        payload: Bytes,
        addr: Option<ParsedAddr>,
    ) -> Option<(Bytes, ParsedAddr)> {
        if frag_id >= self.frag_total || frag_id as usize >= self.frags.len() {
            return None;
        }
        let slot = &mut self.frags[frag_id as usize];
        if slot.is_some() {
            return None; // 重复分片，忽略
        }
        *slot = Some(payload);
        self.received += 1;

        // frag_id=0 携带目标地址
        if frag_id == 0 {
            if let Some(a) = addr {
                self.addr = Some(a);
            }
        }

        if self.received >= self.frag_total {
            let addr = self.addr.clone()?;
            let total_len: usize = self
                .frags
                .iter()
                .filter_map(|f| f.as_ref().map(|b| b.len()))
                .sum();
            let mut buf = bytes::BytesMut::with_capacity(total_len);
            for b in self.frags.iter().flatten() {
                buf.extend_from_slice(b);
            }
            Some((buf.freeze(), addr))
        } else {
            None
        }
    }
}

// ── 流式地址读取 ─────────────────────────────────────────────────────────────

/// 从 QUIC 流中精确读取一个 TUIC 地址（按 ATYP 分段 read_exact）。
///
/// 返回 `(地址, 消耗总字节数)`；帧头之后的数据保留在流中。
async fn read_address(recv: &mut quinn::RecvStream) -> Option<(ParsedAddr, usize)> {
    let mut atyp = [0u8; 1];
    recv.read_exact(&mut atyp).await.ok()?;

    // 按类型读出剩余定长/变长片段，拼成完整编码后交给 parse_address 校验
    let mut rest: Vec<u8> = Vec::new();
    match atyp[0] {
        ATYP_EMPTY => {
            return Some((ParsedAddr::Empty, 1));
        }
        ATYP_FQDN => {
            let mut len_buf = [0u8; 1];
            recv.read_exact(&mut len_buf).await.ok()?;
            let len = len_buf[0] as usize;
            // 流中此时剩余的是 domain(len 字节) + port(2 字节)，
            // 不应再额外多读 1 字节（此前误将 len_buf 也计入 rest 容量，
            // 导致 read_exact 多消费了 domain 的第一个字节乃至后续用户数据）。
            rest.resize(len + 2, 0);
            recv.read_exact(&mut rest).await.ok()?;
            let mut full_rest = Vec::with_capacity(1 + rest.len());
            full_rest.push(len_buf[0]);
            full_rest.extend_from_slice(&rest);
            rest = full_rest;
        }
        ATYP_IPV4 => {
            rest.resize(6, 0);
            recv.read_exact(&mut rest).await.ok()?;
        }
        ATYP_IPV6 => {
            rest.resize(18, 0);
            recv.read_exact(&mut rest).await.ok()?;
        }
        _ => return None,
    }

    let mut full = Vec::with_capacity(1 + rest.len());
    full.push(atyp[0]);
    full.extend_from_slice(&rest);
    let (addr, _) = parse_address(&full).ok()?;
    Some((addr, full.len()))
}

// ── QUIC bi-stream → AsyncReadWrite 适配器 ───────────────────────────────────

/// quinn 双向流的 AsyncRead + AsyncWrite 适配（TCP Connect 交付用，
/// 与 outbound/hysteria2 的 QuinnBiStream 同构）。
struct QuinnBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuinnBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuinnBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}
