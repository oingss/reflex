//! Hysteria2 服务端入站（QUIC-based，对齐 sing-box `protocol/hysteria2/inbound.go`
//! 与官方 hysteria2 服务端的行为面）。
//!
//! ## 协议
//! 基于 QUIC（quinn 0.11 + rustls ring，ALPN `h3`），线路格式见
//! [`crate::protocol::hysteria2`] 模块文档：
//! - 认证：HTTP/3 `POST https://hysteria/auth`（手写 H3/QPACK 编解码，
//!   与 outbound 客户端共享原语，无 h3 crate 依赖）；
//!   密码校验 config.users（取 `password` 字段），成功回 `:status 233` +
//!   `hysteria-cc-rx`（服务端下行带宽 bytes/s；ignore_client_bandwidth 或
//!   未配置 down_mbps 时回 "0" → 客户端自行决定 BBR / 本地速率），失败回 403
//! - TCP：双向流首 varint `0x401` + 目标地址；回 OK 响应后把 quinn 双向流
//!   装箱为 [`SniffedStream::from_encrypted`]（`raw_tcp: None`，底层是 QUIC 流）
//!   交给 dispatcher 路由
//! - UDP：QUIC datagram（session_id/packet_id/分片头 + addr），每个 session_id
//!   一个会话 task：上行分片重组后逐包投递 [`InboundUdpPacket`]
//!   （`upstream_rx: None`），回包经 `reply_tx` 回到会话 task 后按
//!   `spoofed_src`（出站回包元组携带的伪造源地址 = 原始目标）构造下行
//!   datagram 帧（超 MTU 自动分片）写回 QUIC
//!
//! ## 会话聚合语义
//! dispatcher 按 (src, outbound) 聚合 UDP 会话。同一 QUIC 连接上的多个
//! hysteria2 UDP session（不同 session_id）若共用 QUIC 对端地址作为 src，
//! 会被 dispatcher 误合并（回包 session_id 错配）。参照 shadowquic 入站的
//! 做法：每个 session_id 分配一个 `100.64.0.0/10` 段内唯一的伪源地址，
//! 保证 dispatcher 把它们视为独立 UDP 会话。
//!
//! ## 拥塞控制
//! quinn 0.11 不支持运行时替换拥塞控制器，采用与 outbound 相同的
//! "握手前预设"策略：配置了 up_mbps（服务端上行 → 客户端下行方向）时用
//! BBR + Brutal 近似初始大窗口（cwnd ≈ up_bps * 100ms / 8），否则 BBR 默认。
//!
//! ## 已知限制（TODO）
//! - masquerade 仅极简实现：认证前的非 `/auth` H3 请求回 404，不支持
//!   proxy/404 伪装站点（对齐 flux 的极简路径；真实浏览器探测返回 404）
//! - UDP 分片重组表无全局内存上限（仅每会话最多 64 个未完成 packet_id）

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::inbound::Hysteria2InboundConfig;
use crate::config::outbound::mbps_to_bps;
use crate::inbound::{
    display_sockaddr, parse_listen_addr, InboundTcpStream, InboundUdpPacket, SniffedStream, Target,
    UdpSession,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::hysteria2::{
    open_h3_control_streams, parse_addr_to_target, parse_headers_from_qpack, parse_udp_datagram,
    read_h3_frame, read_tcp_request, read_varint_async, send_udp_fragmented,
    write_auth_fail_response, write_auth_ok_response, write_h3_not_found_response,
    write_tcp_response, QuinnBiStream, AUTH_URL_PATH, FRAME_TYPE_TCP_REQUEST, H3_FRAME_HEADERS,
    H3_FRAME_SETTINGS, HY2_ALPN, QUIC_MAX_CONNECTION_RECEIVE_WINDOW, QUIC_STREAM_RECEIVE_WINDOW,
};

/// Brutal 近似：初始拥塞窗口预估的 RTT（100ms）。
/// cwnd_bytes = up_bps * rtt / 8（参考 sing-quic hysteria/congestion/brutal.go）
const BRUTAL_APPROX_INITIAL_RTT_MS: u64 = 100;

/// QUIC 最大并发双向流数（对齐 flux：1024）
const MAX_INCOMING_STREAMS: u32 = 1024;

/// QUIC 空闲超时（30s，与 sing-box DefaultMaxIdleTimeout 一致）
const MAX_IDLE_TIMEOUT_MS: u32 = 30_000;

/// UDP 会话空闲超时（60s，对齐 flux）
const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// 每会话最多同时等待重组的分片包数（防内存膨胀）
const MAX_PENDING_FRAG_SETS: usize = 64;

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct Hysteria2Inbound {
    config: Hysteria2InboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl Hysteria2Inbound {
    pub fn new(
        config: Hysteria2InboundConfig,
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
        let tag = Arc::new(self.config.tag.clone());

        // Hysteria2 必须使用 TLS：启动期硬校验
        anyhow::ensure!(
            self.config.tls.enabled,
            "hysteria2 inbound '{}' requires tls.enabled=true (Hysteria2 协议必须启用 TLS)",
            self.config.tag
        );

        // 密码表：users[].password
        let passwords: Vec<String> = self
            .config
            .users
            .iter()
            .filter_map(|u| u.password.clone())
            .collect();
        anyhow::ensure!(
            !passwords.is_empty(),
            "hysteria2 inbound '{}' requires at least one user with a password",
            self.config.tag
        );
        let passwords = Arc::new(passwords);

        // hysteria-cc-rx（服务端下行带宽，bytes/s）：
        // - ignore_client_bandwidth=true 或未配置 down_mbps → "0"：
        //   客户端收到 0 后 tx_bps=0 → 回退 BBR（auto 模式，sing-box 语义）
        // - 配置了 down_mbps → 告知客户端服务端接收速率（客户端取 min(本地 up, 服务端)）
        let cc_rx = Arc::new(if self.config.ignore_client_bandwidth {
            "0".to_string()
        } else {
            match self.config.down_mbps {
                Some(mbps) => mbps_to_bps(mbps as u64).to_string(),
                None => "0".to_string(),
            }
        });

        // ── TLS → rustls ServerConfig（ALPN 强制 h3）─────────────────────────
        let mut tls_cfg = (*crate::inbound::tls_server::build_server_config(&self.config.tls)?)
            .clone();
        tls_cfg.alpn_protocols = vec![HY2_ALPN.to_vec()];

        // ── QUIC TransportConfig（与 outbound 客户端对齐）────────────────────
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_INCOMING_STREAMS))
            .stream_receive_window(
                quinn::VarInt::from_u64(QUIC_STREAM_RECEIVE_WINDOW).unwrap_or(quinn::VarInt::MAX),
            )
            .receive_window(
                quinn::VarInt::from_u64(QUIC_MAX_CONNECTION_RECEIVE_WINDOW)
                    .unwrap_or(quinn::VarInt::MAX),
            )
            .max_idle_timeout(Some(quinn::VarInt::from_u32(MAX_IDLE_TIMEOUT_MS).into()))
            .keep_alive_interval(Some(Duration::from_secs(10)))
            // 启用 QUIC unreliable datagram（UDP 代理依赖此功能）
            .datagram_receive_buffer_size(Some(2 * 1024 * 1024)); // 2 MiB 接收缓冲

        // 拥塞控制（对齐 outbound 的"握手前预设"策略）：
        // - 配置 up_mbps（服务端上行）→ BBR + Brutal 近似初始大窗口
        // - 未配置 → BBR 默认（auto 模式）
        let up_bps: u64 = mbps_to_bps(self.config.up_mbps.unwrap_or(0) as u64);
        let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
            if up_bps > 0 {
                let brutal_cwnd = (up_bps * BRUTAL_APPROX_INITIAL_RTT_MS / 1000 / 8).max(1024);
                let mut bbr = quinn::congestion::BbrConfig::default();
                bbr.initial_window(brutal_cwnd);
                Arc::new(bbr)
            } else {
                Arc::new(quinn::congestion::BbrConfig::default())
            };
        transport.congestion_controller_factory(cc_factory);

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_cfg)?,
        ));
        server_config.transport_config(Arc::new(transport));

        // ── 绑定 UDP socket 并创建 quinn Endpoint ────────────────────────────
        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let socket = std::net::UdpSocket::bind(bind)
            .map_err(|e| anyhow::anyhow!("hysteria2 inbound '{tag}' bind {bind}: {e}"))?;
        socket.set_nonblocking(true)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| anyhow::anyhow!("hysteria2 inbound: quinn endpoint create failed: {e}"))?;

        info!(tag = %tag, addr = %bind, tls = true, "hy2 inbound listening");

        let tcp_tx = self.tcp_tx;
        let udp_tx = self.udp_tx;
        // 每连接 UDP 伪源地址分配计数器（100.64.0.0/10 段，见模块文档）
        let session_counter = Arc::new(AtomicU32::new(0));

        loop {
            let Some(incoming) = endpoint.accept().await else {
                break; // endpoint 已停止
            };
            let passwords = passwords.clone();
            let cc_rx = cc_rx.clone();
            let tcp_tx = tcp_tx.clone();
            let udp_tx = udp_tx.clone();
            let tag = tag.clone();
            let session_counter = session_counter.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_connection(incoming, passwords, cc_rx, tcp_tx, udp_tx, tag, session_counter)
                        .await
                {
                    debug!(err = %e, "hy2 inbound connection ended");
                }
            });
        }

        Ok(())
    }
}

// ── 连接处理 ─────────────────────────────────────────────────────────────────

async fn handle_connection(
    incoming: quinn::Incoming,
    passwords: Arc<Vec<String>>,
    cc_rx: Arc<String>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
    session_counter: Arc<AtomicU32>,
) -> anyhow::Result<()> {
    let conn: quinn::Connection = incoming.await?;
    let peer = conn.remote_address();
    info!(tag = %tag, peer = %display_sockaddr(peer), "hy2 inbound: QUIC connection established");

    // ── 后台接收客户端 uni stream（H3 control / QPACK 流），读后丢弃 ────────
    // quic-go/http3 客户端在握手后立即打开 uni stream 发送 SETTINGS；
    // 若服务端不接收，客户端流控满后会拒绝处理请求。
    {
        let c = conn.clone();
        tokio::spawn(async move {
            while let Ok(stream) = c.accept_uni().await {
                tokio::spawn(async move {
                    let mut s = stream;
                    let mut buf = [0u8; 4096];
                    // quinn RecvStream 固有 read 返回 Ok(Option<usize>)
                    loop {
                        match s.read(&mut buf).await {
                            Ok(Some(0)) | Ok(None) | Err(_) => break,
                            Ok(Some(_)) => {}
                        }
                    }
                });
            }
        });
    }

    // ── 服务端侧 H3 连接初始化（control + QPACK uni 流）─────────────────────
    // quic-go 客户端要求对端存在这三条流（RFC 9204 §4.2 MUST），否则以
    // H3_QPACK_DECOMPRESSION_FAILED 拒绝请求。失败不影响 TCP/UDP 代理
    //（仅影响 quic-go 客户端的 H3 认证路径），故仅记录。
    if let Err(e) = open_h3_control_streams(&conn).await {
        warn!(tag = %tag, err = %e, "hy2 inbound: failed to open h3 control streams");
    }

    // ── 阶段一：等待认证 ─────────────────────────────────────────────────────
    loop {
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(v) => v,
            Err(e) => {
                debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: accept_bi ended before auth");
                return Ok(());
            }
        };

        let frame_type = match read_varint_async(&mut recv).await {
            Ok(t) => t,
            Err(e) => {
                debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: bad pre-auth stream");
                continue;
            }
        };

        match frame_type {
            H3_FRAME_HEADERS => {
                let (_, payload) = match read_h3_frame(&mut recv).await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: bad pre-auth HEADERS frame");
                        continue;
                    }
                };
                let headers = match parse_headers_from_qpack(&payload) {
                    Ok(h) => h,
                    Err(e) => {
                        debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: bad QPACK block");
                        continue;
                    }
                };

                // 仅处理 POST /auth；其余请求做极简 masquerade（404）
                let get = |k: &str| {
                    headers
                        .iter()
                        .find(|(n, _)| n == k)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default()
                };
                let is_auth =
                    get(":method") == "POST" && get(":path") == AUTH_URL_PATH;

                if !is_auth {
                    debug!(tag = %tag, peer = %display_sockaddr(peer), path = %get(":path"), "hy2 inbound: non-auth h3 request, masquerading 404");
                    let _ = write_h3_not_found_response(&mut send).await;
                    let _ = send.finish();
                    continue;
                }

                let auth_val = headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("hysteria-auth"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();

                if passwords.iter().any(|p| p == &auth_val) {
                    info!(
                        tag = %tag,
                        peer = %display_sockaddr(peer),
                        cc_rx = %cc_rx,
                        "hy2 inbound: auth OK"
                    );
                    write_auth_ok_response(&mut send, &cc_rx).await?;
                    let _ = send.finish();
                    break; // 进入阶段二
                }

                warn!(tag = %tag, peer = %display_sockaddr(peer), "hy2 inbound: auth failed");
                let _ = write_auth_fail_response(&mut send).await;
                let _ = send.finish();
                // 等待响应字节冲刷到网络后再关闭连接（quinn close 不等待流数据）
                tokio::time::sleep(Duration::from_millis(100)).await;
                conn.close(quinn::VarInt::from_u32(1), b"auth failed");
                return Ok(());
            }
            H3_FRAME_SETTINGS => {
                // H3 控制流开在双向流上（非标准），忽略
                continue;
            }
            other => {
                // 认证前出现非 H3 流（如未认证的 TCP 代理流 0x401）→ 拒绝连接
                debug!(tag = %tag, peer = %display_sockaddr(peer), frame_type = format!("0x{other:x}"), "hy2 inbound: proxy stream before auth, closing");
                conn.close(quinn::VarInt::from_u32(1), b"auth failed");
                return Ok(());
            }
        }
    }

    // ── 阶段二：认证通过，TCP / UDP 两个循环并发跑 ───────────────────────────
    //
    // auth 后所有双向流统一由 quic_tcp_loop 接收（读首 varint 区分 0x401 TCP 流
    // 与 H3 流），UDP 由 datagram 循环处理。任一循环结束即关闭连接。

    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    let tcp_task = {
        let conn2 = conn.clone();
        let tcp_tx = tcp_tx.clone();
        let tag2 = tag.clone();
        tokio::spawn(async move { quic_tcp_loop(conn2, peer, tcp_tx, tag2).await })
    };
    let udp_task = {
        let conn2 = conn.clone();
        let udp_tx = udp_tx.clone();
        let tag2 = tag.clone();
        let counter = session_counter.clone();
        tokio::spawn(async move { quic_udp_loop(conn2, peer, sessions, udp_tx, tag2, counter).await })
    };

    tokio::select! {
        _ = tcp_task => {},
        _ = udp_task => {},
    }

    conn.close(quinn::VarInt::from_u32(0), b"");
    info!(tag = %tag, peer = %display_sockaddr(peer), "hy2 inbound: connection closed");
    Ok(())
}

// ── TCP 代理循环 ─────────────────────────────────────────────────────────────

async fn quic_tcp_loop(
    conn: quinn::Connection,
    peer: SocketAddr,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) {
    loop {
        let (send, mut recv) = match conn.accept_bi().await {
            Ok(v) => v,
            Err(e) => {
                debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: tcp accept_bi ended");
                break;
            }
        };

        let frame_type = match read_varint_async(&mut recv).await {
            Ok(t) => t,
            Err(e) => {
                debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: bad stream frame type");
                continue;
            }
        };

        match frame_type {
            FRAME_TYPE_TCP_REQUEST => {
                let tcp_tx = tcp_tx.clone();
                let tag = tag.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp_request(send, recv, peer, tcp_tx, tag).await {
                        debug!(peer = %display_sockaddr(peer), err = %e, "hy2 inbound: tcp stream error");
                    }
                });
            }
            H3_FRAME_SETTINGS | H3_FRAME_HEADERS => {
                // H3 控制流/请求流误入（正常客户端 auth 后不再发普通 H3 请求），
                // 静默忽略，不 reset，避免影响连接
                debug!(tag = %tag, peer = %display_sockaddr(peer), frame_type = format!("0x{frame_type:x}"), "hy2 inbound: h3 stream after auth, ignoring");
            }
            other => {
                debug!(tag = %tag, peer = %display_sockaddr(peer), frame_type = format!("0x{other:x}"), "hy2 inbound: unknown frame type, ignoring");
            }
        }
    }
}

/// 处理一条 TCP 代理流：读目标地址 → 回 OK 响应 → 交付 dispatcher。
async fn handle_tcp_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    let addr = read_tcp_request(&mut recv).await?;
    let target = parse_addr_to_target(&addr)?;

    debug!(
        tag = %tag,
        peer = %display_sockaddr(peer),
        target = %target,
        "hy2 inbound: tcp request"
    );

    // 回 OK 响应并显式 flush（quinn 会缓冲；不 flush 客户端在进入转发阶段前收不到响应）
    write_tcp_response(&mut send, true, "OK").await?;
    send.flush().await?;

    let inner: Box<dyn AsyncReadWrite> = Box::new(QuinnBiStream { send, recv });
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

// ── UDP 代理 ─────────────────────────────────────────────────────────────────

/// UDP 会话上行帧（datagram 解析后、重组前的投递单元）
struct UdpFrameIn {
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    target: Target,
    payload: Bytes,
}

/// session_id → 上行帧通道（会话 task 持有 Receiver）
type SessionMap = Arc<Mutex<HashMap<u32, mpsc::Sender<UdpFrameIn>>>>;

/// 为每个 hysteria2 UDP session 分配 `100.64.0.0/10` 段内的唯一伪源地址。
///
/// dispatcher 按 (src, outbound) 聚合 UDP 会话；同一 QUIC 连接的不同
/// session_id 若共用 QUIC 对端地址，会被误合并导致回包 session_id 错配。
/// 计数器 c（每连接自增）映射：IP 第二段 64..127、第三段 0..255、
/// 端口 16384..32767，c < 2^28 内保证 (ip, port) 唯一。
fn pseudo_session_addr(c: u32) -> SocketAddr {
    let o2 = 64 + ((c >> 14) & 0x3f) as u8;
    let o3 = ((c >> 20) & 0xff) as u8;
    let port = 0x4000 + (c & 0x3fff);
    SocketAddr::from(([100, o2, o3, 1], port as u16))
}

async fn quic_udp_loop(
    conn: quinn::Connection,
    peer: SocketAddr,
    sessions: SessionMap,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
    session_counter: Arc<AtomicU32>,
) {
    loop {
        let data = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: datagram loop ended");
                break;
            }
        };

        let frame = match parse_udp_datagram(&data) {
            Ok(f) => f,
            Err(e) => {
                warn!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: bad udp datagram");
                continue;
            }
        };
        let target = match parse_addr_to_target(&frame.addr) {
            Ok(t) => t,
            Err(e) => {
                debug!(tag = %tag, peer = %display_sockaddr(peer), err = %e, "hy2 inbound: bad udp addr");
                continue;
            }
        };

        // 路由到已有会话，或为新 session_id 创建会话 task
        let tx = {
            let mut map = sessions.lock().unwrap();
            if let Some(tx) = map.get(&frame.session_id) {
                tx.clone()
            } else {
                let (reply_tx, reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
                let (in_tx, in_rx) = mpsc::channel::<UdpFrameIn>(64);
                let pseudo_src = pseudo_session_addr(session_counter.fetch_add(1, Ordering::Relaxed));
                map.insert(frame.session_id, in_tx.clone());

                let conn2 = conn.clone();
                let udp_tx2 = udp_tx.clone();
                let tag2 = tag.clone();
                let sessions2 = sessions.clone();
                let sid = frame.session_id;
                tokio::spawn(async move {
                    run_udp_session(
                        sid,
                        pseudo_src,
                        in_rx,
                        reply_tx,
                        reply_rx,
                        conn2,
                        udp_tx2,
                        tag2,
                        sessions2,
                    )
                    .await;
                });
                in_tx
            }
        };

        if tx
            .send(UdpFrameIn {
                packet_id: frame.packet_id,
                frag_id: frame.frag_id,
                frag_count: frame.frag_count,
                target,
                payload: frame.payload,
            })
            .await
            .is_err()
        {
            // 会话 task 已退出（空闲超时等），清理映射，下个包重建会话
            sessions.lock().unwrap().remove(&frame.session_id);
        }
    }
}

/// UDP 会话主循环：上行分片重组 + 逐包投递 dispatcher；下行回包经 reply_tx
/// 回来后以同 session_id 的 datagram 帧写回 QUIC。空闲超时退出并清理映射。
#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    session_id: u32,
    pseudo_src: SocketAddr,
    mut in_rx: mpsc::Receiver<UdpFrameIn>,
    reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
    mut reply_rx: mpsc::Receiver<(Bytes, SocketAddr, SocketAddr)>,
    conn: quinn::Connection,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
    sessions: SessionMap,
) {
    let mut frag_table: HashMap<u16, FragBuf> = HashMap::new();
    // 服务端→客户端方向的 packet_id 计数器，每个回包递增保证唯一
    let mut reply_pkt_id: u16 = 0;
    let mut idle_deadline = tokio::time::Instant::now() + UDP_SESSION_IDLE_TIMEOUT;

    loop {
        tokio::select! {
            maybe = in_rx.recv() => {
                let Some(input) = maybe else { break };
                idle_deadline = tokio::time::Instant::now() + UDP_SESSION_IDLE_TIMEOUT;

                // 分片重组（frag_count <= 1 直接透传）
                let data = if input.frag_count <= 1 {
                    Some(input.payload)
                } else {
                    if frag_table.len() >= MAX_PENDING_FRAG_SETS {
                        if let Some(oldest) = frag_table.keys().next().copied() {
                            frag_table.remove(&oldest);
                        }
                    }
                    let entry = frag_table
                        .entry(input.packet_id)
                        .or_insert_with(|| FragBuf::new(input.frag_count));
                    match entry.insert(input.frag_id, input.payload) {
                        Some(full) => {
                            frag_table.remove(&input.packet_id);
                            Some(full)
                        }
                        None => None,
                    }
                };

                let Some(data) = data else { continue };

                let packet = InboundUdpPacket {
                    data,
                    src: pseudo_src,
                    target: input.target,
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
                    break; // dispatcher 已关闭
                }
            }
            maybe = reply_rx.recv() => {
                let Some((data, _client, spoofed)) = maybe else { break };
                idle_deadline = tokio::time::Instant::now() + UDP_SESSION_IDLE_TIMEOUT;

                reply_pkt_id = reply_pkt_id.wrapping_add(1);
                // 下行帧 addr = 回包元组的伪造源地址（原始目标 / 出站侧实际远端）
                if let Err(e) =
                    send_udp_fragmented(&conn, session_id, reply_pkt_id, &spoofed.to_string(), &data)
                {
                    debug!(tag = %tag, session_id, err = %e, "hy2 inbound: udp reply send failed");
                    break;
                }
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                debug!(tag = %tag, session_id, "hy2 inbound: udp session idle timeout");
                break;
            }
        }
    }

    sessions.lock().unwrap().remove(&session_id);
    debug!(tag = %tag, session_id, peer = %display_sockaddr(pseudo_src), "hy2 inbound: udp session closed");
}

/// 客户端 → 服务端方向的分片重组缓冲（对齐 sing-box udpDefragger：
/// 仅在新 frag_id 时递增计数，重复分片不计数，避免错误重组）
struct FragBuf {
    total: u8,
    received: usize,
    frags: HashMap<u8, Bytes>,
}

impl FragBuf {
    fn new(total: u8) -> Self {
        Self {
            total,
            received: 0,
            frags: HashMap::new(),
        }
    }

    /// 插入一个分片；集齐后返回按 frag_id 顺序拼接的完整载荷
    fn insert(&mut self, frag_id: u8, payload: Bytes) -> Option<Bytes> {
        let is_new = self.frags.insert(frag_id, payload).is_none();
        if is_new {
            self.received += 1;
        }
        if self.received < self.total as usize {
            return None;
        }
        let mut ids: Vec<u8> = self.frags.keys().copied().collect();
        ids.sort_unstable();
        let mut out = BytesMut::new();
        for id in ids {
            out.extend_from_slice(&self.frags[&id]);
        }
        Some(out.freeze())
    }
}
