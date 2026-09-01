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
    protocol::tuic::{
        build_authenticate_frame, build_connect_header, build_dissociate_frame,
        build_heartbeat_frame, parse_udp_packet_meta, parse_uuid, send_udp_fragmented, CMD_PACKET,
        FRAG_REASSEMBLY_TIMEOUT, IDLE_TIMEOUT_MS, KEEPALIVE_SECS, QUIC_CONN_WINDOW,
        QUIC_STREAM_WINDOW, TUIC_ALPN, VERSION,
    },
};

// ── 协议常量与帧编解码原语已提升至 crate::protocol::tuic ─────────────────────
// （命令字节、地址编解码、Authenticate/Connect/Dissociate/Heartbeat 帧构建、
//   UDP Packet 分片与解析，见 protocol/tuic.rs 模块头文档。）

// QUIC 传输参数（服务端心跳默认间隔；其余常量见 protocol::tuic）
const HEARTBEAT_SECS: u64 = 10;

// ── 连接池 ────────────────────────────────────────────────────────────────────

/// UDP datagram 分发器：解决多 UDP 会话共享同一 QUIC 连接时的竞争问题。
///
/// 旧实现每个 `handle_udp` 独立调用 `conn.read_datagram()`，多会话并发时
/// datagram 被随机分配给某个 receiver，绝大多数包被丢弃。
///
/// 性能优化（对齐 sing-quic tuic/packet.go `inputPacket` 的 `select/default`
/// 非阻塞投递）：旧实现用 `tokio::sync::Mutex<HashMap>`，每收到一个 datagram
/// 都要 `.lock().await`（异步互斥锁 + 调度点）。大流量 UDP（如视频/QUIC
/// over QUIC）下每秒数千 datagram，锁竞争与异步调度开销显著。
/// 改用 `DashMap`：分片无锁读，`try_send` 满即丢弃（与 sing-quic `default`
/// 分支语义一致——接收队列满时丢弃新包而非阻塞 reader）。
struct DatagramRouter {
    /// session_id → 该会话的接收通道。
    /// DashMap 分片锁，读路径（dispatch）无全局锁竞争。
    sessions: dashmap::DashMap<u16, tokio::sync::mpsc::Sender<Bytes>>,
}

impl DatagramRouter {
    fn new() -> Self {
        Self {
            sessions: dashmap::DashMap::new(),
        }
    }

    /// 注册一个 UDP 会话，返回用于接收分片数据的 Receiver
    fn register(&self, session_id: u16) -> tokio::sync::mpsc::Receiver<Bytes> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        self.sessions.insert(session_id, tx);
        rx
    }

    /// 注销会话
    fn unregister(&self, session_id: u16) {
        self.sessions.remove(&session_id);
    }

    /// 将一个 datagram 分片投递到对应 session。
    /// `try_send`：通道满时丢弃（非阻塞），与 sing-quic `select/default` 语义一致，
    /// 避免慢消费者阻塞全局 datagram reader。
    fn dispatch(&self, session_id: u16, frag: Bytes) {
        if let Some(entry) = self.sessions.get(&session_id) {
            let _ = entry.try_send(frag);
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
                while let Ok(data) = conn_bg.read_datagram().await {
                    // 最小 4 字节 = Version + CMD + SessionID(2)
                    if data.len() < 4 || data[0] != VERSION || data[1] != CMD_PACKET {
                        continue;
                    }
                    let sid = u16::from_be_bytes([data[2], data[3]]);
                    // dispatch 同步无锁，避免大流量下 reader 任务被阻塞。
                    router_bg.dispatch(sid, data);
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
                        .send_datagram(build_heartbeat_frame())
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

    /// 发送 Authenticate 帧（sing-tuic 协议，帧构建见 protocol::tuic）。
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

        let frame = build_authenticate_frame(&self.uuid, &token);
        stream.write_all(&frame).await?;
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
        // 大包自动分片（与 sing-box tuic/packet.go fragUDPMessage 对齐），
        // 仅 frag_id=0 携带真实目标 ADDR。
        send_udp_fragmented(&conn, session_id, 0, &packet.target, &packet.data)?;
        debug!(tag = %self.config.tag, target = %packet.target, "tuic udp datagram sent");

        // 在共享 router 中注册本会话，获取专属的接收通道。
        let mut frag_rx = router.register(session_id);

        // 若有后续上行包，spawn task 持续发送
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let conn_send = conn.clone();
            // 复用 session_id，packet_id 单调递增；每包按需分片。
            tokio::spawn(async move {
                let mut pkt_id: u16 = 1;
                while let Some((target, data)) = upstream_rx.recv().await {
                    if send_udp_fragmented(&conn_send, session_id, pkt_id, &target, &data)
                        .is_err()
                    {
                        break;
                    }
                    pkt_id = pkt_id.wrapping_add(1);
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
            // ── 分片重组状态（per session）──────────────────────────────────
            // key = packet_id，value = (frag_total, received_frags, last_activity)
            // 与 sing-box tuic udpDefragger 对齐：按 packet_id 聚合，齐了按 frag_id 顺序拼接。
            let mut reasm: std::collections::HashMap<
                u16,
                (u8, Vec<Option<Bytes>>, std::time::Instant),
            > = std::collections::HashMap::new();

            loop {
                match tokio::time::timeout(timeout, frag_rx.recv()).await {
                    Ok(Some(data)) => {
                        let Some((_, pid, frag_total, frag_id, dlen, doff)) =
                            parse_udp_packet_meta(&data)
                        else {
                            continue;
                        };
                        // 零拷贝切分：data 是 quinn read_datagram 返回的 Bytes
                        // （引用计数底层分配），`slice` 仅偏移+长度，不复制数据。
                        // 旧实现 `Bytes::copy_from_slice` 每收一个分片复制一次 payload，
                        // 大流量 UDP 下（每秒数千包）复制开销显著；且多分片重组拼接时
                        // 又会复制一次。
                        let payload = data.slice(doff..doff + dlen);

                        if frag_total <= 1 {
                            // 无需重组，直接交付
                            if reply_tx.send((payload, src, spoofed_src)).await.is_err() {
                                break;
                            }
                            continue;
                        }

                        // 分片重组
                        let now = std::time::Instant::now();
                        let entry = reasm
                            .entry(pid)
                            .or_insert_with(|| (frag_total, vec![None; frag_total as usize], now));
                        // frag_total 不一致（服务端重发？）→ 重建
                        if entry.0 != frag_total {
                            *entry = (frag_total, vec![None; frag_total as usize], now);
                        }
                        entry.2 = now;
                        let idx = frag_id as usize;
                        if idx < entry.1.len() && entry.1[idx].is_none() {
                            entry.1[idx] = Some(payload);
                        }
                        let received = entry.1.iter().flatten().count();
                        if received == entry.1.len() {
                            // 全部到齐，按 frag_id 顺序拼接
                            let total: usize = entry.1.iter().flatten().map(|b| b.len()).sum();
                            let mut out = BytesMut::with_capacity(total);
                            for frag in entry.1.iter().flatten() {
                                out.put_slice(frag);
                            }
                            let assembled = out.freeze();
                            reasm.remove(&pid);
                            if reply_tx.send((assembled, src, spoofed_src)).await.is_err() {
                                break;
                            }
                        }

                        // 顺带清理超时的未完成重组组，防内存泄漏
                        if reasm.len() > 8 {
                            reasm.retain(|_, (_, _, last)| {
                                now.duration_since(*last) < FRAG_REASSEMBLY_TIMEOUT
                            });
                        }
                    }
                    Ok(None) => break, // router 关闭
                    Err(_) => break,   // idle timeout
                }
            }
            // 注销会话并发送 Dissociate（与 sing-tuic packet.go:343-355 一致：
            // 通过 **uni-stream** 发送，而非 datagram）。
            // 旧实现误用 datagram 发送 Dissociate，服务端按 CMD 字段在 uni-stream
            // 上解析，datagram 形式的 Dissociate 会被当作 UDP Packet 处理（CMD=0x02
            // 才进 datagram 路径），导致 Dissociate 实际不生效。
            if let Ok(mut stream) = conn.open_uni().await {
                let disc = build_dissociate_frame(session_id);
                let _ = stream.write_all(&disc).await;
                let _ = stream.finish();
            }
            router_clone.unregister(session_id);
            drop(guards);
            let _ = tag;
        });

        Ok(())
    }
}

// ── UUID 解析已提升至 protocol::tuic::parse_uuid ─────────────────────────────

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
        // 调大发送窗口，高 BDP 链路上提升单 stream 吞吐。
        .send_window(QUIC_CONN_WINDOW)
        .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
        .max_idle_timeout(Some(quinn::VarInt::from_u32(IDLE_TIMEOUT_MS).into()))
        .keep_alive_interval(Some(Duration::from_secs(KEEPALIVE_SECS)));

    // heartbeat 配置（覆盖默认 keepalive）
    if let Some(ref hb) = config.heartbeat {
        if let Ok(d) = crate::config::outbound::parse_duration(hb) {
            transport.keep_alive_interval(Some(d));
        }
    }

    // ── 拥塞控制选择（与 sing-box tuic/client.go:62-68 + congestion.go 对齐）──
    // sing-box TUIC 支持 cubic / new_reno / bbr（默认 cubic）。
    // quinn 0.11 仅内置 Cubic 与 BBR；new_reno 行为接近 Cubic（均为基于丢包的
    // 算法），此处降级为 Cubic。BBR 在高延迟/有丢包链路上吞吐显著优于 Cubic。
    let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        match config.congestion_control.to_ascii_lowercase().as_str() {
            "bbr" => {
                debug!(tag = %config.tag, "tuic: using BBR congestion control");
                Arc::new(quinn::congestion::BbrConfig::default())
            }
            "new_reno" | "newreno" | "reno" => {
                // quinn 无独立 NewReno 实现，降级为 Cubic（同为基于丢包的算法）
                debug!(
                    tag = %config.tag,
                    cc = %config.congestion_control,
                    "tuic: NewReno not built-in, falling back to Cubic"
                );
                Arc::new(quinn::congestion::CubicConfig::default())
            }
            _ => {
                // "cubic" 及任何未知值 → Cubic（默认）
                Arc::new(quinn::congestion::CubicConfig::default())
            }
        };
    transport.congestion_controller_factory(cc_factory);

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

// ── 测试 ──────────────────────────────────────────────────────────────────────
//
// 帧格式原语的单元测试（parse_uuid / write_target / build_udp_packet /
// parse_udp_packet_meta / authenticate 等）已随原语迁移至 protocol/tuic.rs；
// 此处保留客户端分片行为的测试。

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tuic::{
        addr_serialize_len, build_udp_packet, write_target, ATYP_FQDN, ATYP_IPV4,
        MAX_DATAGRAM_PAYLOAD,
    };

    /// 将一个 UDP 包按 `MAX_DATAGRAM_PAYLOAD` 分片，生成多个 datagram（仅测试用）。
    ///
    /// 生产路径用 `protocol::tuic::send_udp_fragmented` 直接发送（避免
    /// `Vec<Bytes>` 分配），本函数仅用于测试验证分片 wire 格式
    /// （frag_id/frag_total/ADDR 置空）。逻辑与 `send_udp_fragmented`
    /// 多分片路径一致，保持同步。
    fn build_udp_packets_fragmented(
        session_id: u16,
        packet_id: u16,
        target: &Target,
        data: &[u8],
    ) -> Vec<Bytes> {
        let addr_len = addr_serialize_len(target);
        let header_overhead = 10 + addr_len + 2; // fixed(10) + addr + data_len(2)
        let chunk_size = MAX_DATAGRAM_PAYLOAD.saturating_sub(header_overhead).max(1);

        if data.len() <= chunk_size {
            return vec![build_udp_packet(session_id, packet_id, 0, 1, target, data)];
        }

        let frag_total = data.len().div_ceil(chunk_size);
        let mut out = Vec::with_capacity(frag_total);
        for (frag_id, chunk) in data.chunks(chunk_size).enumerate() {
            let mut buf = BytesMut::with_capacity(10 + addr_len + 2 + chunk.len());
            buf.put_slice(&build_udp_packet_header_for_test(
                session_id,
                packet_id,
                frag_id as u8,
                frag_total as u8,
                if frag_id == 0 { Some(target) } else { None },
                chunk.len(),
            ));
            buf.put_slice(chunk);
            out.push(buf.freeze());
        }
        out
    }

    /// 测试辅助：构造分片 Packet 头（首片带 ADDR，后续片 Empty）。
    fn build_udp_packet_header_for_test(
        session_id: u16,
        packet_id: u16,
        frag_id: u8,
        frag_total: u8,
        target: Option<&Target>,
        data_len: usize,
    ) -> BytesMut {
        let mut buf = BytesMut::with_capacity(10 + 64);
        buf.put_u8(VERSION);
        buf.put_u8(CMD_PACKET);
        buf.put_u16(session_id);
        buf.put_u16(packet_id);
        buf.put_u8(frag_total);
        buf.put_u8(frag_id);
        buf.put_u16(data_len as u16);
        match target {
            Some(t) => write_target(&mut buf, t),
            None => buf.put_u8(0xff),
        }
        buf
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
    fn parse_udp_packet_meta_handles_empty_addr_fragment() {
        // 模拟后续分片（ATYP=0xff Empty）
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(CMD_PACKET);
        buf.put_u16(0x1234u16); // session
        buf.put_u16(0x0001u16); // packet_id
        buf.put_u8(2); // frag_total
        buf.put_u8(1); // frag_id
        buf.put_u16(4u16); // data_len
        buf.put_u8(0xff); // Empty ADDR
        buf.put_slice(b"frag");
        let meta = parse_udp_packet_meta(&buf).expect("parse ok");
        assert_eq!(meta, (0x1234, 0x0001, 2, 1, 4, 11));
    }

    #[test]
    fn build_udp_packets_fragmented_small_packet_no_split() {
        // 小包不应分片，返回单个 datagram（frag_total=1）
        let target = Target::Domain("example.com".into(), 443);
        let data = b"hello";
        let pkts = build_udp_packets_fragmented(1, 0, &target, data);
        assert_eq!(pkts.len(), 1);
        assert_eq!(pkts[0][6], 1); // frag_total
        assert_eq!(pkts[0][7], 0); // frag_id
    }

    #[test]
    fn build_udp_packets_fragmented_large_packet_splits() {
        // 大包应分片：首片带 ADDR，后续片 ADDR=0xff Empty
        let target = Target::Socket("1.2.3.4:53".parse().unwrap());
        // 构造超过单 datagram payload 的数据（1197 - overhead 后仍不够）
        let data = vec![0xABu8; 3000];
        let pkts = build_udp_packets_fragmented(7, 42, &target, &data);
        assert!(pkts.len() > 1, "should fragment large packet");
        // 首片 frag_id=0，携带真实 ADDR
        assert_eq!(pkts[0][7], 0); // frag_id
        assert_eq!(pkts[0][10], ATYP_IPV4); // 真实 ADDR
                                            // 后续片 frag_id>0，ADDR=0xff
        for (i, p) in pkts.iter().enumerate().skip(1) {
            assert_eq!(p[7], i as u8); // frag_id 递增
            assert_eq!(p[10], 0xff); // Empty ADDR
        }
        // frag_total 一致
        let ft = pkts[0][6];
        assert!(ft > 1);
        for p in &pkts {
            assert_eq!(p[6], ft);
        }
        // 验证重组后数据完整
        let mut reassembled = Vec::new();
        // 用 parse_udp_packet_meta 提取每片 data
        let mut frags: Vec<Bytes> = vec![Bytes::new(); ft as usize];
        for p in &pkts {
            let (_, _, _, fid, dlen, doff) = parse_udp_packet_meta(p).unwrap();
            frags[fid as usize] = Bytes::copy_from_slice(&p[doff..doff + dlen]);
        }
        for f in frags {
            reassembled.extend_from_slice(&f);
        }
        assert_eq!(reassembled, data);
    }

    #[test]
    fn build_udp_packets_fragmented_fragment_count_fits_u8() {
        // 确保分片数不超过 u8 上限（255）
        let target = Target::Domain("x.io".into(), 53);
        let data = vec![0u8; 300_000]; // 约 250+ 片
        let pkts = build_udp_packets_fragmented(1, 0, &target, &data);
        assert!(pkts.len() <= 255);
        assert_eq!(pkts[0][6] as usize, pkts.len());
    }

    #[test]
    fn connect_header_layout() {
        let target = Target::Domain("example.com".into(), 443);
        let hdr = build_connect_header(&target);
        assert_eq!(hdr[0], VERSION);
        assert_eq!(hdr[1], 0x01); // CMD_CONNECT
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
        assert_eq!(buf[0], 0x02);
        assert_eq!(buf.len(), 1 + 16 + 2);
        assert_eq!(u16::from_be_bytes([buf[17], buf[18]]), 443);
    }
}
