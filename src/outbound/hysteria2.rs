//! Hysteria2 出站（QUIC-based 客户端，对齐 sing-box `protocol/hysteria2/outbound.go`）。
//!
//! 线路格式与共享编解码原语见 [`crate::protocol::hysteria2`]（模块头文档 +
//! 实现）。本文件只保留客户端角色逻辑：QUIC 连接池、HTTP/3 认证握手、
//! TCP/UDP 请求发起、Brutal 近似拥塞控制预设与 UDP 分片重组接收路径。
//!
//! ## 连接复用
//! 连接池缓存已认证的 QUIC 连接；datagram 接收由单一后台任务完成
//!（[`DatagramRouter`] 按 session_id 分发，解决多会话抢包问题）。

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::{
    config::outbound::{mbps_to_bps, Hysteria2OutboundConfig},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{relay, Outbound},
};

// ── 共享协议原语（crate::protocol::hysteria2）────────────────────────────────

use crate::protocol::hysteria2::{
    open_h3_control_streams, parse_headers_from_qpack, parse_udp_frag_header, put_literal_header,
    random_padding, read_h3_frame, read_varint_async, send_udp_fragmented, target_to_addr_str,
    write_h3_frame, write_varint, QuinnBiStream, AUTH_URL_HOST, AUTH_URL_PATH,
    FRAME_TYPE_TCP_REQUEST, H3_FRAME_DATA, H3_FRAME_HEADERS, HY2_ALPN, MAX_MESSAGE_LENGTH,
    MAX_PADDING_LENGTH, QUIC_MAX_CONNECTION_RECEIVE_WINDOW, QUIC_STREAM_RECEIVE_WINDOW,
    RESP_HEADER_CC_RX, RESP_HEADER_UDP, STATUS_AUTH_OK,
};

/// Brutal 近似：初始拥塞窗口预估的 RTT（100ms）。
/// 用于在握手前根据配置的 up_mbps 预设 BBR 初始窗口，近似 Brutal 的"启动即满速"行为。
/// 公式（参考 sing-quic hysteria/congestion/brutal.go）：cwnd_bytes = tx_bps * rtt / 8
const BRUTAL_APPROX_INITIAL_RTT: Duration = Duration::from_millis(100);

/// UDP 分片重组超时（与 sing-quic tuic/packet.go 的 LRU 10s 对齐，hy2 同源）。
/// 旧值 2s 在高延迟链路上会误丢未到齐的分片。
const FRAG_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(5);

// ── 认证结果 ──────────────────────────────────────────────────────────────────

/// 认证握手后从服务端响应头中解析出的协商结果
#[derive(Debug, Clone)]
struct AuthInfo {
    /// 服务端是否允许 UDP
    udp_enabled: bool,
    /// 协商后实际使用的发送带宽（bps）；0 = 不启用 Brutal
    tx_bps: u64,
}

// ── UDP datagram 分发器 ───────────────────────────────────────────────────────

/// UDP datagram 分发器：解决多 UDP 会话共享同一 QUIC 连接时的竞争问题。
///
/// 旧实现每个 `handle_udp` 独立调用 `conn.read_datagram()`，导致：
///   - 第一个会话的接收循环会"偷走"所有后续会话的回包
///   - 多会话并发时 datagram 随机分配给某个 receiver，绝大多数包被丢弃
///
/// 修复：单一后台任务读取所有 datagram，按 session_id 路由到对应会话。
///
/// 性能优化（对齐 sing-quic packet_wait.go `select/default` 非阻塞投递）：
/// 用 `DashMap` 分片无锁读，`try_send` 满即丢弃（与 sing-quic `default`
/// 分支语义一致——接收队列满时丢弃新包而非阻塞 reader）。
struct DatagramRouter {
    /// session_id → 该会话的接收通道。DashMap 分片锁，读路径（dispatch）无全局锁竞争。
    sessions: dashmap::DashMap<u32, tokio::sync::mpsc::Sender<Bytes>>,
}

impl DatagramRouter {
    fn new() -> Self {
        Self {
            sessions: dashmap::DashMap::new(),
        }
    }

    /// 注册一个 UDP 会话，返回用于接收分片数据的 Receiver
    fn register(&self, session_id: u32) -> tokio::sync::mpsc::Receiver<Bytes> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        self.sessions.insert(session_id, tx);
        rx
    }

    /// 注销会话
    fn unregister(&self, session_id: u32) {
        self.sessions.remove(&session_id);
    }

    /// 将一个 datagram 分片投递到对应 session。
    /// `try_send`：通道满时丢弃（非阻塞），避免慢消费者阻塞全局 datagram reader。
    fn dispatch(&self, session_id: u32, frag: Bytes) {
        if let Some(entry) = self.sessions.get(&session_id) {
            let _ = entry.try_send(frag);
        }
    }
}

/// 缓存已认证的 QUIC 连接
struct CachedConn {
    conn: quinn::Connection,
    auth: AuthInfo,
    /// 共享的 datagram 分发器（单 reader 多 consumer）
    router: Arc<DatagramRouter>,
}

pub struct Hysteria2Outbound {
    config: Hysteria2OutboundConfig,
    quic_config: Arc<quinn::ClientConfig>,
    /// UDP session ID 自增计数器（每条 UDP 会话递增）
    udp_session_id: AtomicU32,
    /// 连接池：复用已建立的 QUIC 连接，避免每次请求重新握手
    cached_conn: Arc<Mutex<Option<CachedConn>>>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    ///
    /// 使用 RwLock 以支持运行时更新：app 初始化分两阶段构建 DNS resolver，
    /// 第一阶段（outbounds 未就绪）注入的 resolver 中 detour 字段为 None，
    /// 第二阶段（outbounds 就绪）重建后才有正确的 detour。
    /// `update_resolver` 供第二阶段完成后替换为带正确 detour 的 resolver。
    resolver: std::sync::RwLock<Option<Arc<crate::dns::DnsResolver>>>,
}

impl Hysteria2Outbound {
    pub fn new(config: Hysteria2OutboundConfig) -> anyhow::Result<Self> {
        let quic_config = build_quic_config(&config)?;
        Ok(Self {
            config,
            quic_config,
            udp_session_id: AtomicU32::new(0),
            cached_conn: Arc::new(Mutex::new(None)),
            routing_mark: 0,
            resolver: std::sync::RwLock::new(None),
        })
    }

    pub fn with_resolver(self, resolver: Arc<crate::dns::DnsResolver>) -> Self {
        *self.resolver.write().unwrap() = Some(resolver);
        self
    }

    /// 运行时更新 resolver（供 app 第二阶段 DNS resolver 重建后调用）。
    pub fn update_resolver(&self, resolver: Arc<crate::dns::DnsResolver>) {
        *self.resolver.write().unwrap() = Some(resolver);
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 获取或新建 QUIC 连接（连接池）
    ///
    /// 优先复用已有的健康连接，避免每次请求都进行完整的 QUIC+HTTP/3 握手。
    /// 若缓存连接已关闭（close_reason 返回 Some 或 open_bi 失败），自动重建。
    async fn get_or_create_connection(
        &self,
    ) -> anyhow::Result<(quinn::Connection, AuthInfo, Arc<DatagramRouter>)> {
        debug!(tag = %self.config.tag, "hy2: get_or_create_connection acquiring lock");
        let mut guard = self.cached_conn.lock().await;
        debug!(tag = %self.config.tag, "hy2: get_or_create_connection lock acquired");

        // 检查缓存连接是否仍然健康
        if let Some(cached) = guard.as_ref() {
            // quinn::Connection::close_reason() 返回 Some 表示连接已关闭
            if cached.conn.close_reason().is_none() {
                debug!(tag = %self.config.tag, "hy2: reusing cached connection");
                return Ok((
                    cached.conn.clone(),
                    cached.auth.clone(),
                    cached.router.clone(),
                ));
            }
            // 连接已断开，清除缓存
            debug!(tag = %self.config.tag, "hy2 cached connection closed, reconnecting");
            *guard = None;
        }

        // 建立新连接
        debug!(tag = %self.config.tag, "hy2: calling new_connection");
        let (conn, auth) = self.new_connection().await?;
        let router = Arc::new(DatagramRouter::new());

        // 启动单一 datagram 接收任务：读取所有 QUIC datagram，按 session_id 分发
        {
            let conn_bg = conn.clone();
            let router_bg = router.clone();
            tokio::spawn(async move {
                while let Ok(data) = conn_bg.read_datagram().await {
                    // 解析 session_id（前 4 字节，big-endian）
                    if data.len() < 8 {
                        continue;
                    }
                    let sid = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    // 分片重组交由会话侧处理，这里只投递原始 datagram。
                    // dispatch 同步无锁，避免大流量下 reader 任务被阻塞。
                    router_bg.dispatch(sid, data);
                }
            });
        }

        *guard = Some(CachedConn {
            conn: conn.clone(),
            auth: auth.clone(),
            router: router.clone(),
        });
        Ok((conn, auth, router))
    }

    /// 建立 QUIC 连接并完成 Hysteria2 认证握手，返回连接和协商结果
    async fn new_connection(&self) -> anyhow::Result<(quinn::Connection, AuthInfo)> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let sni = self.config.tls.server_name.as_deref().unwrap_or(server);

        let resolver_opt = self.resolver.read().unwrap().clone();
        debug!(tag = %self.config.tag, server = %server, port, resolver_set = resolver_opt.is_some(),
            "hy2: new_connection starting");

        // 防环：解析自身服务器域名时排除 detour 指向本出站的 DNS 上游，
        // 并加 5s 超时。否则（DNS remote 上游 detour=本出站时）会形成
        // 「建连 → 解析 → 再建连」的互斥锁死锁，表现为 DNS 全部超时且
        // 没有任何连接错误日志（Windows TUN auto_route 实测踩坑）。
        let addr = crate::outbound::resolve_server_addr_for(
            &self.config.tag,
            server,
            port,
            resolver_opt.as_ref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;

        debug!(tag = %self.config.tag, addr = %addr, "hy2: server address resolved, creating QUIC endpoint");

        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()?;

        let mut endpoint = crate::outbound::new_marked_quic_endpoint(bind, self.routing_mark)
            .map_err(|e| anyhow::anyhow!("hy2 endpoint bind failed: {e}"))?;
        endpoint.set_default_client_config((*self.quic_config).clone());

        let timeout = Duration::from_secs(10); // 固定 10s，与 sing-box 默认行为一致
        debug!(tag = %self.config.tag, addr = %addr, sni = %sni, "hy2: starting QUIC connect (10s timeout)");
        let conn = tokio::time::timeout(timeout, endpoint.connect(addr, sni)?)
            .await
            .map_err(|_| anyhow::anyhow!("hy2 connect timeout"))?
            .map_err(|e| anyhow::anyhow!("hy2 QUIC connect: {e}"))?;

        debug!(tag = %self.config.tag, server = %addr, "hy2 QUIC connection established");

        // ── 后台接收服务端 uni stream（HTTP/3 control stream）──────────────────
        // quic-go/http3 服务端在握手后立即打开 uni stream 发送 SETTINGS 帧。
        // 若客户端不接收，服务端流控满后会拒绝处理请求（connection lost）。
        {
            let conn_bg = conn.clone();
            tokio::spawn(async move {
                // 接收服务端的所有 uni stream 并静默丢弃
                for _ in 0..8 {
                    match tokio::time::timeout(Duration::from_secs(5), conn_bg.accept_uni()).await {
                        Ok(Ok(mut stream)) => {
                            // 读取 stream type byte 和 SETTINGS，然后持有（不关闭）
                            let conn_inner = conn_bg.clone();
                            tokio::spawn(async move {
                                let mut buf = vec![0u8; 4096];
                                let _ = stream.read(&mut buf).await;
                                // 持有 stream 直到连接结束（而非固定 sleep 3600s）
                                conn_inner.closed().await;
                                drop(stream);
                            });
                        }
                        Ok(Err(_)) | Err(_) => break,
                    }
                }
            });
        }

        // Hysteria2 认证握手（HTTP/3 POST https://hysteria/auth）
        let auth_info = self.authenticate(&conn).await?;

        // 拥塞控制已在 build_quic_config 阶段根据 up_mbps 预设（BBR / Brutal 近似），
        // quinn 0.11 不支持运行时替换，故此处仅记录协商出的实际 tx_bps 供观测。
        // sing-box 在握手后通过 quicConn.SetCongestionControl 动态切换 Brutal，
        // quinn 无等价接口；BBR + 大初始窗口的预设策略在多数场景下已能近似其效果。
        if auth_info.tx_bps > 0 {
            debug!(
                tag = %self.config.tag,
                tx_bps = auth_info.tx_bps,
                "hy2: negotiated tx_bps (CC preset at config stage)"
            );
        }

        Ok((conn, auth_info))
    }

    /// Hysteria2 认证握手
    ///
    /// 官方实现（core/client/client.go）使用 quic-go/http3.Transport.RoundTrip 发送：
    ///   POST https://hysteria/auth
    ///   Hysteria-Auth: <password>
    ///   Hysteria-CC-RX: <rx_bps>
    ///   Hysteria-Padding: <random 256-2047 bytes>
    ///
    /// HTTP/3 连接建立流程（必须严格遵守 RFC 9114 + RFC 9204）：
    ///   1. 客户端打开单向 control stream（type=0x00），发送 SETTINGS 帧
    ///   2. 客户端打开单向 QPACK encoder stream（type=0x02）—— RFC 9204 §4.2 MUST
    ///   3. 客户端打开单向 QPACK decoder stream（type=0x03）—— RFC 9204 §4.2 MUST
    ///   4. 同时在双向流上发送 HEADERS 帧（请求），接收 HEADERS 帧（响应）
    ///   5. 服务端（quic-go/http3）在处理请求前会先等待上述三条 uni stream
    ///
    /// 返回服务端协商结果（UDP 是否启用、实际 tx 带宽）。
    async fn authenticate(&self, conn: &quinn::Connection) -> anyhow::Result<AuthInfo> {
        // ── 步骤1+2+3：H3 连接初始化（control / QPACK encoder / decoder 流）───
        // RFC 9114 §6.2.1 要求客户端建立连接后立即发送 control stream；
        // QPACK 两条流是 RFC 9204 §4.2 MUST，缺失时 quic-go 服务端以
        // H3_QPACK_DECOMPRESSION_FAILED(0x200) 拒绝。见共享原语
        // open_h3_control_streams（服务端入站复用同一实现）。
        open_h3_control_streams(conn).await.map_err(|e| {
            warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to open h3 control streams");
            e
        })?;

        let (mut send, mut recv) = conn.open_bi().await?;

        let password = &self.config.password;

        // 客户端声明的下行带宽（告知服务端我能接收多少）
        // 与 sing-box 对齐：up_mbps / down_mbps 整数字段
        let rx_bps: u64 = mbps_to_bps(self.config.down_mbps);
        let tx_bps_local: u64 = mbps_to_bps(self.config.up_mbps);

        // 随机 padding（官方：256–2047 字节）
        let padding = random_padding(256, 2048);
        let rx_str = rx_bps.to_string();

        // ── 构造 QPACK Header Block（RFC 9204 §4.5.6）────────────────────────
        // Literal Header Field Without Name Reference 格式，见共享原语
        // put_literal_header 的文档。
        let mut qpack = BytesMut::new();
        qpack.put_u8(0x00); // Required Insert Count = 0
        qpack.put_u8(0x00); // S=0, Delta Base = 0

        put_literal_header(&mut qpack, b":method", b"POST");
        put_literal_header(&mut qpack, b":scheme", b"https");
        put_literal_header(&mut qpack, b":authority", AUTH_URL_HOST.as_bytes());
        put_literal_header(&mut qpack, b":path", AUTH_URL_PATH.as_bytes());
        put_literal_header(&mut qpack, b"hysteria-auth", password.as_bytes());
        put_literal_header(&mut qpack, b"hysteria-cc-rx", rx_str.as_bytes());
        // padding 可能超过 127 字节；put_literal_header 内的多字节长度编码已处理
        put_literal_header(&mut qpack, b"hysteria-padding", padding.as_bytes());

        // ── 发送 HTTP/3 HEADERS frame（frame type = 0x01）───────────────────
        let qpack_bytes = qpack.freeze();
        debug!(tag = %self.config.tag, qpack_len = qpack_bytes.len(), "hy2 auth: sending HEADERS frame");
        let mut frame = BytesMut::new();
        write_h3_frame(&mut frame, 0x01, &qpack_bytes);
        send.write_all(&frame).await.map_err(|e| {
            warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to send HEADERS frame");
            e
        })?;
        send.finish().map_err(|e| {
            warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to finish send stream");
            e
        })?;
        debug!(tag = %self.config.tag, "hy2 auth: HEADERS sent, waiting for response");

        // ── 读取服务端响应：跳过 DATA/其他控制帧，找 HEADERS 帧 ──────────────
        // quic-go/http3 服务端可能先发 DATA 或其他帧，需循环直到拿到 HEADERS
        let headers = loop {
            let (frame_type, payload) = read_h3_frame(&mut recv).await.map_err(|e| {
                warn!(tag = %self.config.tag, err = %e, "hy2 auth: failed to read response frame");
                e
            })?;
            debug!(tag = %self.config.tag, frame_type = frame_type, payload_len = payload.len(), "hy2 auth: got response frame");
            match frame_type {
                H3_FRAME_HEADERS => {
                    // HEADERS frame
                    break parse_headers_from_qpack(&payload).map_err(|e| {
                        warn!(tag = %self.config.tag, err = %e, "hy2 auth: QPACK parse error, payload={:?}", &payload[..payload.len().min(64)]);
                        e
                    })?;
                }
                H3_FRAME_DATA => {
                    // DATA frame，跳过
                    debug!(tag = %self.config.tag, "hy2 auth: skipping DATA frame");
                    continue;
                }
                other => {
                    warn!(tag = %self.config.tag, frame_type = other, "hy2 auth: unexpected H3 frame type");
                    anyhow::bail!(
                        "hy2 auth: unexpected H3 frame type 0x{other:02x}, expected HEADERS(0x01)"
                    );
                }
            }
        };

        // 验证状态码
        let status_str = headers
            .iter()
            .find(|(k, _)| k == ":status")
            .map(|(_, v)| v.as_str())
            .unwrap_or("");
        debug!(tag = %self.config.tag, status = status_str, headers = ?headers, "hy2 auth: response headers parsed");
        let status_code: u16 = status_str.parse().map_err(|_| {
            warn!(tag = %self.config.tag, status = status_str, "hy2 auth: invalid :status value");
            anyhow::anyhow!("hy2 auth: invalid :status value: {status_str:?}")
        })?;
        if status_code != STATUS_AUTH_OK {
            warn!(tag = %self.config.tag, status = status_code, "hy2 auth: server rejected");
            anyhow::bail!(
                "hy2 auth failed: server returned status {status_code}, expected {STATUS_AUTH_OK}"
            );
        }

        // 解析 Hysteria-UDP
        let udp_enabled = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(RESP_HEADER_UDP))
            .map(|(_, v)| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // 解析 Hysteria-CC-RX 并与本地 tx 取小值
        // "auto" = 服务端无限制，使用本地配置值
        let tx_bps = {
            let server_rx = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(RESP_HEADER_CC_RX))
                .map(|(_, v)| {
                    if v.eq_ignore_ascii_case("auto") {
                        u64::MAX
                    } else {
                        v.parse::<u64>().unwrap_or(0)
                    }
                })
                .unwrap_or(0);

            if tx_bps_local == 0 {
                // 本地未配置带宽，不启用 Brutal
                0
            } else if server_rx == 0 {
                // 服务端未返回限制，使用本地值
                tx_bps_local
            } else {
                // 取二者较小值（与官方 actualTx = min(serverRx, clientTx) 一致）
                tx_bps_local.min(server_rx)
            }
        };

        debug!(
            tag = %self.config.tag,
            udp_enabled,
            tx_bps,
            "hy2 auth OK"
        );
        Ok(AuthInfo {
            udp_enabled,
            tx_bps,
        })
    }

    /// 打开 TCP 代理 stream，写入 Hysteria2 TCP 请求帧，读取响应
    async fn open_tcp_stream(
        &self,
        conn: &quinn::Connection,
        target: &Target,
    ) -> anyhow::Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, mut recv) = conn.open_bi().await?;

        // TCP 请求帧：[0x401 varint][addr_len varint][addr][padding_len varint][padding]
        let addr = target_to_addr_str(target);
        let padding = random_padding(64, 512);
        let mut buf = BytesMut::new();
        write_varint(&mut buf, FRAME_TYPE_TCP_REQUEST);
        write_varint(&mut buf, addr.len() as u64);
        buf.put_slice(addr.as_bytes());
        write_varint(&mut buf, padding.len() as u64);
        buf.put_slice(padding.as_bytes());

        debug!(tag = %self.config.tag, target = %target, frame_len = buf.len(), "hy2 tcp: sending request frame");
        send.write_all(&buf).await?;

        // 读取 TCP 响应：[status 1B][msg_len varint][msg][padding_len varint][padding]
        let status = recv.read_u8().await.map_err(|e| {
            warn!(tag = %self.config.tag, target = %target, err = %e, "hy2 tcp: failed to read response status");
            e
        })?;
        debug!(tag = %self.config.tag, target = %target, status = status, "hy2 tcp: got response status");
        let msg_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(msg_len <= MAX_MESSAGE_LENGTH, "hy2 response: msg too long");
        if msg_len > 0 {
            let mut msg = vec![0u8; msg_len as usize];
            recv.read_exact(&mut msg).await?;
            if status != 0 {
                let msg_str = String::from_utf8_lossy(&msg);
                warn!(tag = %self.config.tag, target = %target, status = status, msg = %msg_str, "hy2 tcp: proxy rejected");
                anyhow::bail!("hy2 TCP proxy rejected: {}", msg_str);
            }
        } else if status != 0 {
            warn!(tag = %self.config.tag, target = %target, status = status, "hy2 tcp: proxy rejected with no message");
            anyhow::bail!("hy2 TCP proxy rejected (status={status})");
        }
        let padding_len = read_varint_async(&mut recv).await?;
        anyhow::ensure!(
            padding_len <= MAX_PADDING_LENGTH,
            "hy2 response: padding too long"
        );
        if padding_len > 0 {
            let mut pad = vec![0u8; padding_len as usize];
            recv.read_exact(&mut pad).await?;
        }

        Ok((send, recv))
    }
}

#[async_trait::async_trait]
impl Outbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    /// 建立经由 Hysteria2 代理的 TCP 隧道连接，供 DNS detour 使用。
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        debug!(tag = %self.config.tag, host = %host, port = %port, "hy2: connect_tcp (dns detour) entry");
        let target = Target::Domain(host.to_string(), port);
        let (qconn, _auth, _router) = self.get_or_create_connection().await?;
        let (send, recv) = self.open_tcp_stream(&qconn, &target).await?;
        debug!(tag = %self.config.tag, host = %host, port = %port, "hy2 dns detour connected");
        Ok(Box::new(QuinnBiStream { send, recv }))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let (qconn, _auth, _router) = self.get_or_create_connection().await?;
        let (send, recv) = self.open_tcp_stream(&qconn, &conn.target).await?;

        debug!(tag = %self.config.tag, target = %conn.target, "hy2 tcp stream opened");

        let hy2_io = QuinnBiStream { send, recv };
        Ok(relay(conn.stream, hy2_io).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let (qconn, auth, router) = self.get_or_create_connection().await?;

        if !auth.udp_enabled {
            anyhow::bail!("hy2 server has UDP disabled");
        }

        let session_id = self.udp_session_id.fetch_add(1, Ordering::Relaxed);
        let addr = target_to_addr_str(&packet.target);

        // 发送第一个包（首包独立 session，packet_id=0 即可）
        send_udp_fragmented(&qconn, session_id, 0, &addr, &packet.data)?;
        debug!(tag = %self.config.tag, target = %packet.target, session_id, "hy2 udp datagram sent");

        // 在共享 router 中注册本会话，获取专属的分片接收通道。
        // 旧实现每个会话独立调用 conn.read_datagram()，多会话并发时
        // datagram 被随机分配给某个 receiver，绝大多数包被丢弃。
        let mut frag_rx = router.register(session_id);

        // 若有后续上行包，spawn task 持续发送
        // 注意：必须复用同一个 session_id，仅递增 packet_id。
        // 旧实现在此处又调用了一次 fetch_add 取了新的 session_id，
        // 导致同一会话的后续包被服务端当作新会话处理，回包无法关联。
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let qconn_send = qconn.clone();
            tokio::spawn(async move {
                // 首包已用 packet_id=0 发送，这里从 1 开始单调递增，
                // 保证同 session 内分片重组不会错配。
                let mut pkt_id: u16 = 1;
                while let Some((target, data)) = upstream_rx.recv().await {
                    // 会话按 (src, outbound) 聚合后每包目标可能不同，
                    // 需按每包 target 重新计算 addr 字符串。
                    let addr = target_to_addr_str(&target);
                    if send_udp_fragmented(&qconn_send, session_id, pkt_id, &addr, &data).is_err() {
                        break;
                    }
                    pkt_id = pkt_id.wrapping_add(1);
                }
            });
        }

        // 持续接收回包直到超时。
        // 从专属通道读取分片，不再直接调用 conn.read_datagram()。
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());
        let timeout = Duration::from_secs(10);
        let guards = packet.lifetime_guards;
        let router_clone = router.clone();

        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(timeout, frag_rx.recv()).await {
                    Ok(Some(data)) => match reassemble_from_fragments(&data, &mut frag_rx).await {
                        Ok(Some(payload)) => {
                            if reply_tx.send((payload, src, spoofed_src)).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(err = %e, "hy2 udp reassemble error");
                            break;
                        }
                    },
                    Ok(None) => break, // router 关闭
                    Err(_) => break,   // idle timeout
                }
            }
            // 注销会话，释放 router 中的通道资源
            router_clone.unregister(session_id);
            drop(guards);
        });

        Ok(())
    }
}

// ── QUIC 配置 ─────────────────────────────────────────────────────────────────

fn build_quic_config(config: &Hysteria2OutboundConfig) -> anyhow::Result<Arc<quinn::ClientConfig>> {
    let mut tls_config = (*crate::outbound::tls::build_client_config(&config.tls)?).clone();
    tls_config.alpn_protocols = vec![HY2_ALPN.to_vec()];

    // ── QUIC TransportConfig（与 sing-box hysteria/protocol.go 对齐）────────
    let mut transport = quinn::TransportConfig::default();
    transport
        .stream_receive_window(
            quinn::VarInt::from_u64(QUIC_STREAM_RECEIVE_WINDOW).unwrap_or(quinn::VarInt::MAX),
        )
        .receive_window(
            quinn::VarInt::from_u64(QUIC_MAX_CONNECTION_RECEIVE_WINDOW)
                .unwrap_or(quinn::VarInt::MAX),
        )
        // 调大发送窗口（quinn 默认较小），高 BDP 链路上显著提升单 stream 吞吐。
        .send_window(QUIC_MAX_CONNECTION_RECEIVE_WINDOW)
        // 启用 QUIC unreliable datagram（UDP 代理依赖此功能）
        .datagram_receive_buffer_size(Some(2 * 1024 * 1024)) // 2 MiB 接收缓冲
        // 保持连接
        .max_idle_timeout(Some(
            quinn::VarInt::from_u32(30_000).into(), // 30s，与 sing-box DefaultMaxIdleTimeout 一致
        ))
        .keep_alive_interval(Some(Duration::from_secs(10)));

    // ── 拥塞控制选择（与 sing-box client.go:259-276 对齐）──────────────────
    // sing-box 逻辑：
    //   - 服务端要求 auto（RxAuto）或 actualTx==0 → 使用 BBR（congestion_meta2）
    //   - actualTx>0 且服务端给出明确 rx → 使用 Brutal（固定速率）
    //
    // quinn 0.11 不支持运行时替换拥塞控制器，且未内置 Brutal。
    // 此处采用"握手前预设"策略：
    //   - 客户端配置了 up_mbps（→ 会协商出 actualTx>0）：用 BBR + 调大初始窗口
    //     近似 Brutal 的"启动即满速"行为。cwnd_bytes = tx_bps * initial_rtt / 8，
    //     与 hysteria/congestion/brutal.go 的 cwnd 公式一致。BBR 在探测到瓶颈后
    //     会自然降速，不会因预设大窗口而过发导致持续丢包。
    //   - 客户端未配 up_mbps（→ actualTx==0，auto 模式）：用 BBR 默认配置。
    //     相比 quinn 默认的 Cubic，BBR 在高延迟/有丢包链路上吞吐显著更高，
    //     与 sing-box auto 模式行为一致。
    let tx_bps_local: u64 = mbps_to_bps(config.up_mbps);
    let cc_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        if tx_bps_local > 0 {
            // Brutal 近似：BBR + 大初始窗口
            let brutal_cwnd =
                (tx_bps_local * BRUTAL_APPROX_INITIAL_RTT.as_millis() as u64 / 1000 / 8).max(1024);
            debug!(
                tag = %config.tag,
                up_mbps = config.up_mbps,
                brutal_cwnd_bytes = brutal_cwnd,
                "hy2: using BBR with Brutal-like initial window"
            );
            let mut bbr = quinn::congestion::BbrConfig::default();
            bbr.initial_window(brutal_cwnd);
            Arc::new(bbr)
        } else {
            // auto 模式：BBR 默认
            debug!(tag = %config.tag, "hy2: using BBR (auto bandwidth mode)");
            Arc::new(quinn::congestion::BbrConfig::default())
        };
    transport.congestion_controller_factory(cc_factory);

    let mut quic_cfg = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    quic_cfg.transport_config(Arc::new(transport));

    Ok(Arc::new(quic_cfg))
}

// ── UDP 分片重组 ──────────────────────────────────────────────────────────────

/// 从专属 mpsc 通道读取分片并重组。
///
/// 旧实现 `recv_udp_reassemble` 直接调用 `conn.read_datagram()` 读取后续分片，
/// 在多会话共享同一连接时会"偷走"其他会话的回包。
/// 新实现从 router 分配给本会话的通道中读取分片，彻底解决竞争问题。
///
/// 若 frag_count == 1，直接返回 payload（无需重组）。
/// 若 frag_count > 1，在超时窗口内从通道收集所有分片后拼接返回。
/// 分片不完整时返回 Ok(None)。
async fn reassemble_from_fragments(
    first: &Bytes,
    rx: &mut tokio::sync::mpsc::Receiver<Bytes>,
) -> anyhow::Result<Option<Bytes>> {
    // 解析第一帧头
    let (payload0, frag_id0, frag_count, session_id, packet_id) = parse_udp_frag_header(first)?;

    if frag_count == 1 {
        // 无需重组
        return Ok(Some(payload0));
    }

    // 分片收集
    let mut frags: Vec<Option<Bytes>> = vec![None; frag_count as usize];
    frags[frag_id0 as usize] = Some(payload0);
    let mut received = 1usize;

    let deadline = tokio::time::Instant::now() + FRAG_REASSEMBLY_TIMEOUT;
    while received < frag_count as usize {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(buf)) => {
                if let Ok((payload, frag_id, fc, sid, pid)) = parse_udp_frag_header(&buf) {
                    // 只接受同一 session+packet 的分片
                    if sid == session_id && pid == packet_id && fc == frag_count {
                        let idx = frag_id as usize;
                        if idx < frags.len() && frags[idx].is_none() {
                            frags[idx] = Some(payload);
                            received += 1;
                        }
                    }
                }
            }
            _ => return Ok(None),
        }
    }

    // 按 frag_id 顺序拼接
    let total: usize = frags.iter().flatten().map(|b| b.len()).sum();
    let mut out = BytesMut::with_capacity(total);
    for frag in frags.into_iter().flatten() {
        out.put(frag);
    }
    Ok(Some(out.freeze()))
}

// ── Brutal 拥塞控制 ───────────────────────────────────────────────────────────
//
// Brutal 拥塞控制（sing-quic hysteria/congestion/brutal.go）的核心是固定发送速率
// + 基于 ackRate 放大 pacing 间隔，cwnd = bps * rtt / 8 / ackRate。
//
// quinn 0.11 的限制：
//   1. 不支持运行时替换已建连接的拥塞控制器（quic-go 的 SetCongestionControl 无等价）
//   2. 未内置 Brutal 实现，仅有 Cubic 与 BBR
//
// 因此 reflex 采用"握手前预设"策略（见 build_quic_config）：
//   - 配置了 up_mbps → BBR + 大初始窗口（cwnd ≈ up_bps * 100ms / 8）近似 Brutal
//   - 未配置 → BBR 默认（与 sing-box auto 模式一致，congestion_meta2 = BBR）
//
// 若后续 quinn 暴露完整的 Controller trait 且支持运行时注入，
// 可在此实现真正的 BrutalController 并在握手后通过新接口替换。
// 当前实现已显著优于旧的空操作（旧版 apply_brutal 什么都不做，实际跑 Cubic）。

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::hysteria2::build_udp_header;

    #[test]
    fn udp_frag_header_roundtrip() {
        let addr = "example.com:443";
        let data = b"hello";
        let mut buf = build_udp_header(42, 7, 0, 1, addr);
        buf.put_slice(data);
        let (payload, frag_id, frag_count, session_id, packet_id) =
            parse_udp_frag_header(&buf.freeze()).unwrap();
        assert_eq!(&payload[..], data);
        assert_eq!(frag_id, 0);
        assert_eq!(frag_count, 1);
        assert_eq!(session_id, 42);
        assert_eq!(packet_id, 7);
    }

    #[tokio::test]
    async fn reassemble_single_fragment() {
        let addr = "1.2.3.4:80";
        let mut buf = build_udp_header(1, 1, 0, 1, addr);
        buf.put_slice(b"payload");
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let frag = buf.freeze();
        tx.send(frag.clone()).await.unwrap();
        let out = reassemble_from_fragments(&frag, &mut rx).await.unwrap();
        assert_eq!(out.unwrap(), Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn reassemble_multi_fragment() {
        let addr = "1.2.3.4:80";
        let frag0 = {
            let mut b = build_udp_header(100, 9, 0, 2, addr);
            b.put_slice(b"abcde");
            b.freeze()
        };
        let frag1 = {
            let mut b = build_udp_header(100, 9, 1, 2, addr);
            b.put_slice(b"fghij");
            b.freeze()
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        tx.send(frag1).await.unwrap();
        let out = reassemble_from_fragments(&frag0, &mut rx).await.unwrap();
        assert_eq!(out.unwrap(), Bytes::from_static(b"abcdefghij"));
    }

    #[test]
    fn target_addr_format() {
        let t = Target::Domain("example.com".into(), 443);
        assert_eq!(target_to_addr_str(&t), "example.com:443");
        let t = Target::Socket("1.2.3.4:80".parse().unwrap());
        assert_eq!(target_to_addr_str(&t), "1.2.3.4:80");
    }
}
