//! TUIC v5 出站。
//!
//! 严格对照 sing-box 使用的 `github.com/sagernet/sing-quic/tuic` 实现，
//! 关键协议细节全部对齐（旧实现多处分歧导致服务端拒绝/解析错位）：
//!
//! ## Token 派生（最关键）
//! - 旧：`blake3(password || uuid)` → 服务端用 TLS Keying Material 重新派生后对不上
//! - 新：`quinn::Connection::export_keying_material(label=uuid_bytes, context=password_bytes, 32)`
//!   与 sing-tuic `clientHandshake` 中的 `TLS.ExportKeyingMaterial` 完全一致
//!
//! ## 帧格式（所有帧首两字节固定为 [Version=0x05][Command]）
//! 与 sing-tuic `protocol.go` 完全一致：
//! - `CommandAuthenticate = 0x00`（旧实现误用 0x02）
//! - `CommandConnect      = 0x01`（旧实现误用 0x00）
//! - `CommandPacket       = 0x02`（旧实现误用 0x01）
//! - `CommandDissociate   = 0x03`
//! - `CommandHeartbeat    = 0x04`
//!
//! ### Authenticate
//! `[Version 1B][CMD=0x00 1B][UUID 16B][TOKEN 32B]` = 50B
//! （旧实现缺少 Version 字节，且命令值错误）
//!
//! ### TCP Connect（首帧，写在 bi-stream 开头）
//! `[Version 1B][CMD=0x01 1B][ADDR+PORT][用户数据]`
//! （旧实现错误地在每个 TCP 帧前都加 UUID+TOKEN，与服务端解析不匹配）
//!
//! ### UDP Packet（QUIC datagram 承载）
//! `[Version 1B][CMD=0x02 1B][SessionID u16 BE][PacketID u16 BE]`
//! `[FragTotal u8][FragID u8][DataLen u16 BE][ADDR+PORT][DATA]`
//! （旧实现多带 UUID+TOKEN；FragID/FragTotal 顺序颠倒）
//!
//! ### Heartbeat
//! `[Version 1B][CMD=0x04 1B]`，每 10s 发送一次
//! （旧实现完全没有心跳，长连接会被服务端空闲断开）
//!
//! ## Address 编码（sing-tuic AddressSerializer，**非 SOCKS5**）
//! - FQDN:  `0x00 [len u8][domain][port u16 BE]`
//! - IPv4:  `0x01 [4B ip][port u16 BE]`
//! - IPv6:  `0x02 [16B ip][port u16 BE]`
//! （旧实现误用 SOCKS5: IPv6=0x04, Domain=0x03）

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::Mutex;
use tracing::debug;

use crate::{
    config::outbound::TuicOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{relay, AsyncReadWrite, Outbound, OutboundStatus},
};

// ── 协议常量（与 sing-quic/tuic/protocol.go 严格一致）─────────────────────────

const VERSION: u8 = 0x05;

const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;

// Address type byte（sing-tuic AddressSerializer，**不是 SOCKS5**）
const ATYP_FQDN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;

// QUIC 传输参数
const QUIC_STREAM_WINDOW: u64 = 8 * 1024 * 1024; // 8 MiB
const QUIC_CONN_WINDOW: u64 = 15 * 1024 * 1024; // 15 MiB
const IDLE_TIMEOUT_MS: u32 = 30_000; // 30s
const KEEPALIVE_SECS: u64 = 10;
const HEARTBEAT_SECS: u64 = 10;

const TUIC_ALPN: &[u8] = b"tuic";

// ── 连接池 ────────────────────────────────────────────────────────────────────

/// UDP datagram 分发器：解决多 UDP 会话共享同一 QUIC 连接时的竞争问题。
///
/// 旧实现每个 `handle_udp` 独立调用 `conn.read_datagram()`，多会话并发时
/// datagram 被随机分配给某个 receiver，绝大多数包被丢弃。
struct DatagramRouter {
    sessions: tokio::sync::Mutex<std::collections::HashMap<u16, tokio::sync::mpsc::Sender<Bytes>>>,
}

impl DatagramRouter {
    fn new() -> Self {
        Self {
            sessions: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    async fn register(&self, session_id: u16) -> tokio::sync::mpsc::Receiver<Bytes> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        self.sessions.lock().await.insert(session_id, tx);
        rx
    }

    async fn unregister(&self, session_id: u16) {
        self.sessions.lock().await.remove(&session_id);
    }

    async fn dispatch(&self, session_id: u16, frag: Bytes) {
        let sessions = self.sessions.lock().await;
        if let Some(tx) = sessions.get(&session_id) {
            let _ = tx.try_send(frag);
        }
    }
}

struct CachedConn {
    conn: quinn::Connection,
    router: Arc<DatagramRouter>,
}

pub struct TuicOutbound {
    config: TuicOutboundConfig,
    quic_config: Arc<quinn::ClientConfig>,
    uuid: [u8; 16],
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<crate::dns::DnsResolver>>,
    /// UDP session ID 计数器
    udp_session: AtomicU16,
    cached: Arc<Mutex<Option<CachedConn>>>,
}

impl TuicOutbound {
    pub fn new(config: TuicOutboundConfig) -> anyhow::Result<Self> {
        let uuid = parse_uuid(&config.uuid)?;
        let quic_config = build_quic_config(&config)?;
        Ok(Self {
            config,
            quic_config,
            uuid,
            udp_session: AtomicU16::new(0),
            cached: Arc::new(Mutex::new(None)),
            routing_mark: 0,
            resolver: None,
        })
    }

    pub fn with_resolver(mut self, resolver: Arc<crate::dns::DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 连接管理 ─────────────────────────────────────────────────────────────

    async fn get_conn(&self) -> anyhow::Result<(quinn::Connection, Arc<DatagramRouter>)> {
        let mut guard = self.cached.lock().await;

        if let Some(cached) = guard.as_ref() {
            if cached.conn.close_reason().is_none() {
                return Ok((cached.conn.clone(), cached.router.clone()));
            }
            debug!(tag = %self.config.tag, "tuic cached conn closed, reconnecting");
            *guard = None;
        }

        let conn = self.new_conn().await?;
        // 立即发送认证包（uni-stream）。Token 必须从已建立的 TLS session 派生。
        self.authenticate(&conn).await?;

        let router = Arc::new(DatagramRouter::new());

        // 启动单一 datagram 接收任务：读取所有 QUIC datagram，按 session_id 分发。
        // sing-tuic 的 datagram 帧布局：
        //   [Version 1B][CMD=0x02 1B][SessionID u16 BE][PacketID u16 BE]
        //   [FragTotal u8][FragID u8][DataLen u16 BE][ADDR][DATA]
        // 故 SessionID 在 offset 2-3。
        {
            let conn_bg = conn.clone();
            let router_bg = router.clone();
            tokio::spawn(async move {
                loop {
                    match conn_bg.read_datagram().await {
                        Ok(data) => {
                            // 最小 4 字节 = Version + CMD + SessionID(2)
                            if data.len() < 4 || data[0] != VERSION || data[1] != CMD_PACKET {
                                continue;
                            }
                            let sid = u16::from_be_bytes([data[2], data[3]]);
                            router_bg.dispatch(sid, Bytes::from(data)).await;
                        }
                        Err(_) => break,
                    }
                }
            });
        }

        // 启动心跳任务：与 sing-tuic loopHeartbeats 一致，每 10s 发送
        // `[Version 1B][CMD=0x04 1B]`，否则服务端会按 idle_timeout 断开连接。
        {
            let conn_bg = conn.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(HEARTBEAT_SECS));
                // 跳过第一次立即触发（连接刚建立，没必要立即发心跳）
                ticker.tick().await;
                loop {
                    ticker.tick().await;
                    if conn_bg
                        .send_datagram(Bytes::from_static(&[VERSION, CMD_HEARTBEAT]))
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }

        *guard = Some(CachedConn {
            conn: conn.clone(),
            router: router.clone(),
        });
        Ok((conn, router))
    }

    async fn new_conn(&self) -> anyhow::Result<quinn::Connection> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let sni = self
            .config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(server.as_str());

        let addr = crate::outbound::resolve_server_addr(server, port, self.resolver.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("tuic DNS failed for {server}: {e}"))?;

        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()?;
        let mut endpoint = crate::outbound::new_marked_quic_endpoint(bind, self.routing_mark)
            .map_err(|e| anyhow::anyhow!("tuic endpoint bind failed: {e}"))?;
        endpoint.set_default_client_config((*self.quic_config).clone());

        let conn = tokio::time::timeout(Duration::from_secs(10), endpoint.connect(addr, sni)?)
            .await
            .map_err(|_| anyhow::anyhow!("tuic connect timeout"))?
            .map_err(|e| anyhow::anyhow!("tuic QUIC connect: {e}"))?;

        debug!(tag = %self.config.tag, server = %addr, "tuic QUIC connected");
        Ok(conn)
    }

    /// 发送 Authenticate 帧（sing-tuic 协议）。
    ///
    /// 帧布局：`[Version=0x05 1B][CMD=0x00 1B][UUID 16B][TOKEN 32B]` = 50B
    ///
    /// Token 通过 TLS Keying Material Exporter (RFC 5705) 派生：
    /// `export_keying_material(label=uuid_bytes, context=password_bytes, length=32)`
    /// 与 sing-tuic `clientHandshake` 中的 `TLS.ExportKeyingMaterial` 完全一致。
    /// 旧实现用 `blake3(password || uuid)` 自创算法，与服务端不匹配。
    async fn authenticate(&self, conn: &quinn::Connection) -> anyhow::Result<()> {
        let mut stream = conn
            .open_uni()
            .await
            .map_err(|e| anyhow::anyhow!("tuic open uni stream: {e}"))?;

        // 关键：token 必须基于已建立的 TLS session 派生
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &self.uuid, self.config.password.as_bytes())
            .map_err(|e| anyhow::anyhow!("tuic export keying material: {e:?}"))?;

        let mut buf = BytesMut::with_capacity(2 + 16 + 32);
        buf.put_u8(VERSION);
        buf.put_u8(CMD_AUTHENTICATE);
        buf.put_slice(&self.uuid);
        buf.put_slice(&token);

        stream.write_all(&buf).await?;
        stream
            .finish()
            .map_err(|e| anyhow::anyhow!("tuic finish stream: {e}"))?;
        debug!(tag = %self.config.tag, "tuic authenticate sent");
        Ok(())
    }

    // ── TCP 连接（bi-stream + Connect 帧）───────────────────────────────────

    async fn open_tcp_stream(
        &self,
        target: &Target,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream, Bytes)> {
        let (conn, _router) = self.get_conn().await?;
        let (send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| anyhow::anyhow!("tuic open bi stream: {e}"))?;

        // 注意：sing-tuic 的 TCP Connect 帧不在握手时单独发送，
        // 而是在首次 Write 时与用户数据合并发送：
        //   `[Version 1B][CMD=0x01 1B][ADDR+PORT][用户数据]`
        // 该逻辑由 TuicTcpStream 的 pending_header 机制实现（见下方）。
        let header = build_connect_header(target);
        Ok((send, recv, header))
    }
}

// ── Outbound impl ─────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for TuicOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "TUIC".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let (send, recv, header) = self.open_tcp_stream(&target).await?;
        Ok(Box::new(TuicTcpStream::new(send, recv, header)))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let (send, recv, header) = self.open_tcp_stream(&conn.target).await?;
        debug!(tag = %self.config.tag, target = %conn.target, "tuic tcp relay");
        let proxy_stream = TuicTcpStream::new(send, recv, header);
        Ok(relay(conn.stream, proxy_stream).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let (conn, router) = self.get_conn().await?;
        let session_id = self.udp_session.fetch_add(1, Ordering::Relaxed);

        // 同一 UDP 会话的所有上行包必须使用相同的 session_id（服务端据此关联
        // 上下行）。packet_id 在会话内单调递增，便于服务端去重/排序。
        let dgram = build_udp_packet(
            session_id,
            0, // packet_id（首包）
            0, // frag_id
            1, // frag_total
            &packet.target,
            &packet.data,
        );
        conn.send_datagram(dgram)
            .map_err(|e| anyhow::anyhow!("tuic send datagram: {e}"))?;
        debug!(tag = %self.config.tag, target = %packet.target, "tuic udp datagram sent");

        // 在共享 router 中注册本会话，获取专属的接收通道。
        let mut frag_rx = router.register(session_id).await;

        // 若有后续上行包，spawn task 持续发送
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let conn_send = conn.clone();
            // 旧实现误把 session_id 当成每个包递增的计数器，导致每个数据包都被
            // 服务端视为新会话——上行下行无法关联，UDP 实质不可用。
            // 修正：复用 session_id，packet_id 单调递增。
            tokio::spawn(async move {
                let mut pkt_id: u16 = 1;
                while let Some((target, data)) = upstream_rx.recv().await {
                    let dgram = build_udp_packet(session_id, pkt_id, 0, 1, &target, &data);
                    pkt_id = pkt_id.wrapping_add(1);
                    if conn_send.send_datagram(dgram).is_err() {
                        break;
                    }
                }
            });
        }

        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());
        let timeout = Duration::from_secs(10);
        let guards = packet.lifetime_guards;
        let tag = self.config.tag.clone();
        let router_clone = router.clone();

        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(timeout, frag_rx.recv()).await {
                    Ok(Some(data)) => {
                        if let Some(payload) = parse_udp_packet_payload(&data) {
                            if reply_tx.send((payload, src, spoofed_src)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(None) => break,   // router 关闭
                    Err(_) => break,     // idle timeout
                }
            }
            // 注销会话并尝试发送 Dissociate（与 sing-tuic 行为一致）
            let mut disc = BytesMut::with_capacity(4);
            disc.put_u8(VERSION);
            disc.put_u8(CMD_DISSOCIATE);
            disc.put_u16(session_id);
            let _ = conn.send_datagram(disc.freeze());
            router_clone.unregister(session_id).await;
            drop(guards);
            let _ = tag; // 避免 unused warning
        });

        Ok(())
    }
}

// ── 协议帧构建 ────────────────────────────────────────────────────────────────

/// 构建 TCP Connect 帧头（不含用户数据，由 TuicTcpStream 在首次写入时拼接）。
///
/// 与 sing-tuic `clientConn.Write` 一致：
/// `[Version=0x05 1B][CMD=0x01 1B][ADDR+PORT]`
fn build_connect_header(target: &Target) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 64);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_CONNECT);
    write_target(&mut buf, target);
    buf.freeze()
}

/// 编码 TUIC 地址（sing-tuic AddressSerializer，**非 SOCKS5**）。
///
/// 与 sing-tuic `address.go` 一致：
/// - FQDN: `0x00 [len u8][domain][port u16 BE]`
/// - IPv4: `0x01 [4B ip][port u16 BE]`
/// - IPv6: `0x02 [16B ip][port u16 BE]`
///
/// 旧实现误用 SOCKS5 ATYP（IPv6=0x04, Domain=0x03），导致服务端无法解析
/// IPv6 与域名目标。
fn write_target(buf: &mut BytesMut, target: &Target) {
    use std::net::IpAddr;
    match target {
        Target::Domain(host, port) => {
            buf.put_u8(ATYP_FQDN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
            buf.put_u16(*port);
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
        },
    }
}

/// 构建 UDP Packet datagram（sing-tuic `udpMessage.pack`）。
///
/// 布局：
/// `[Version 1B][CMD=0x02 1B][SessionID u16 BE][PacketID u16 BE]`
/// `[FragTotal u8][FragID u8][DataLen u16 BE][ADDR+PORT][DATA]`
///
/// 注意 FragTotal 在前、FragID 在后（旧实现顺序颠倒）。
/// datagram 中**不携带 UUID 与 TOKEN**（认证信息已在 Authenticate 帧中发送，
/// 后续帧仅靠 QUIC stream/datagram 关联到已认证会话）。
fn build_udp_packet(
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    target: &Target,
    data: &[u8],
) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 2 + 2 + 1 + 1 + 2 + 64 + data.len());
    buf.put_u8(VERSION);
    buf.put_u8(CMD_PACKET);
    buf.put_u16(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_total);
    buf.put_u8(frag_id);
    buf.put_u16(data.len() as u16);
    write_target(&mut buf, target);
    buf.put_slice(data);
    buf.freeze()
}

/// 从收到的 UDP Packet datagram 中提取载荷（跳过 header 与 ADDR）。
///
/// 布局（与 `build_udp_packet` 对应）：
/// `[Version 1B][CMD 1B][SessionID 2B][PacketID 2B]`
/// `[FragTotal 1B][FragID 1B][DataLen 2B][ADDR ...][DATA]`
/// 固定 header = 10 字节，ADDR 可变长，DATA 在末尾 DataLen 字节。
fn parse_udp_packet_payload(data: &[u8]) -> Option<Bytes> {
    const MIN_HDR: usize = 10;
    if data.len() < MIN_HDR {
        return None;
    }
    if data[0] != VERSION || data[1] != CMD_PACKET {
        return None;
    }
    let size = u16::from_be_bytes([data[8], data[9]]) as usize;
    // 跳过 ADDR（可变长），取最后 size 字节
    if data.len() < size {
        return None;
    }
    let payload_start = data.len() - size;
    Some(Bytes::copy_from_slice(&data[payload_start..]))
}

// ── UUID 解析 ─────────────────────────────────────────────────────────────────

fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "tuic: invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

// ── QUIC 配置 ─────────────────────────────────────────────────────────────────

fn build_quic_config(config: &TuicOutboundConfig) -> anyhow::Result<Arc<quinn::ClientConfig>> {
    let mut tls_config = (*crate::outbound::tls::build_client_config(&config.tls)?).clone();

    // TUIC 默认 ALPN = "tuic"。仅当用户未显式配置 ALPN 时回填（与 sing-box
    // 行为一致：用户在 tls.alpn 里配什么就用什么，但缺省时给 "tuic"）。
    if !config.tls.alpn.is_empty() {
        tls_config.alpn_protocols = config
            .tls
            .alpn
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
    } else {
        tls_config.alpn_protocols = vec![TUIC_ALPN.to_vec()];
    }

    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(
            quinn::VarInt::from_u64(QUIC_STREAM_WINDOW).unwrap_or(quinn::VarInt::MAX),
        )
        .receive_window(quinn::VarInt::from_u64(QUIC_CONN_WINDOW).unwrap_or(quinn::VarInt::MAX))
        .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
        .max_idle_timeout(Some(quinn::VarInt::from_u32(IDLE_TIMEOUT_MS).into()))
        .keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));

    // heartbeat 配置（覆盖默认 keepalive）
    if let Some(ref hb) = config.heartbeat {
        if let Ok(d) = crate::config::outbound::parse_duration(hb) {
            transport.keep_alive_interval(Some(d));
        }
    }

    let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    quic_cfg.transport_config(Arc::new(transport));

    Ok(Arc::new(quic_cfg))
}

// ── TuicTcpStream：在 bi-stream 上实现 Connect 帧 ────────────────────────────
//
// 与 sing-tuic `clientConn.Write` 行为一致：首次写入时合并
//   `[Version 1B][CMD=0x01 1B][ADDR+PORT][用户数据]`
// 后续写入直接透传。无响应头需要跳过（TUIC TCP Connect 无服务端响应帧）。

use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TuicTcpStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// 首次写入时与数据合并的 Connect 帧头
    pending_header: Option<Bytes>,
    /// 待发送的合并缓冲（header + data），处理部分写或 Pending
    pending_write: Option<Bytes>,
    /// pending_write 全部发出后应上报的"已写字节数"（即原始 data.len()）
    pending_reported: usize,
}

impl TuicTcpStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream, header: Bytes) -> Self {
        Self {
            send,
            recv,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
        }
    }
}

impl AsyncRead for TuicTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for TuicTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // 1. 优先完成上一次未写完的合并缓冲区
        if let Some(pending) = self.pending_write.take() {
            return match Pin::new(&mut self.send).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = self.pending_reported;
                    self.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    // 部分写：保留剩余，下次继续
                    self.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    self.pending_reported = 0;
                    Poll::Ready(Err(e.into()))
                }
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. 首次写：合并 header + data（与 sing-tuic clientConn.Write 一致）
        if let Some(header) = self.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            return match Pin::new(&mut self.send).poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) if n >= combined.len() => Poll::Ready(Ok(data.len())),
                Poll::Ready(Ok(n)) => {
                    self.pending_write = Some(combined.slice(n..));
                    self.pending_reported = data.len();
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                Poll::Pending => {
                    self.pending_write = Some(combined);
                    self.pending_reported = data.len();
                    Poll::Pending
                }
            };
        }

        // 3. 无 header，直接透传
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u[0], 0xaa);
        assert_eq!(u[15], 0xee);
    }

    #[test]
    fn parse_uuid_no_dashes() {
        let u = parse_uuid("aabbccdd11223344aabbccdd11223344").unwrap();
        assert_eq!(u.len(), 16);
    }

    #[test]
    fn build_udp_packet_layout() {
        // 与 sing-tuic udpMessage.pack 严格对齐：
        // [Version 1B][CMD 1B][SessionID 2B][PacketID 2B][FragTotal 1B][FragID 1B]
        // [DataLen 2B][ADDR][DATA]
        let target = Target::Domain("example.com".into(), 443);
        let data = b"hello";
        let pkt = build_udp_packet(0x1234, 0x5678, 0, 1, &target, data);

        assert_eq!(pkt[0], VERSION);
        assert_eq!(pkt[1], CMD_PACKET);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x5678);
        assert_eq!(pkt[6], 1); // frag_total
        assert_eq!(pkt[7], 0); // frag_id
        assert_eq!(u16::from_be_bytes([pkt[8], pkt[9]]), 5); // data_len
        // ADDR: FQDN=0x00, len=11, "example.com", port=443
        assert_eq!(pkt[10], ATYP_FQDN);
        assert_eq!(pkt[11], 11);
        assert_eq!(&pkt[12..23], b"example.com");
        assert_eq!(u16::from_be_bytes([pkt[23], pkt[24]]), 443);
        // DATA
        assert_eq!(&pkt[25..30], b"hello");
    }

    #[test]
    fn parse_udp_packet_payload_roundtrip() {
        let target = Target::Domain("example.com".into(), 443);
        let data = b"hello world";
        let pkt = build_udp_packet(1, 0, 0, 1, &target, data);
        let payload = parse_udp_packet_payload(&pkt).expect("parse ok");
        assert_eq!(payload.as_ref(), data);
    }

    #[test]
    fn parse_udp_packet_payload_rejects_non_packet() {
        // Heartbeat 帧不应被当作 UDP Packet 解析
        let heartbeat = [VERSION, CMD_HEARTBEAT];
        assert!(parse_udp_packet_payload(&heartbeat).is_none());
    }

    #[test]
    fn connect_header_layout() {
        let target = Target::Domain("example.com".into(), 443);
        let hdr = build_connect_header(&target);
        assert_eq!(hdr[0], VERSION);
        assert_eq!(hdr[1], CMD_CONNECT);
        // ADDR: FQDN=0x00, len=11, "example.com", port=443
        assert_eq!(hdr[2], ATYP_FQDN);
        assert_eq!(hdr[3], 11);
        assert_eq!(&hdr[4..15], b"example.com");
        assert_eq!(u16::from_be_bytes([hdr[15], hdr[16]]), 443);
    }

    #[test]
    fn write_target_ipv4() {
        let mut buf = BytesMut::new();
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        write_target(&mut buf, &target);
        // [ATYP_IPV4=0x01][4B ip][port u16 BE]
        assert_eq!(buf[0], ATYP_IPV4);
        assert_eq!(&buf[1..5], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([buf[5], buf[6]]), 80);
    }

    #[test]
    fn write_target_ipv6() {
        let mut buf = BytesMut::new();
        let target = Target::Socket("[2001:db8::1]:443".parse().unwrap());
        write_target(&mut buf, &target);
        // [ATYP_IPV6=0x02][16B ip][port u16 BE]
        assert_eq!(buf[0], ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);
        assert_eq!(u16::from_be_bytes([buf[17], buf[18]]), 443);
    }
}
