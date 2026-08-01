use std::sync::Arc;

use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use http::{Method, Request, StatusCode, Uri};
use rand::Rng;
use rustls::ClientConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    config::outbound::NaiveOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        anytls::{
            build_uot_packet, build_uot_request, read_uot_packet, UOT_MAGIC_ADDRESS, UOT_MAGIC_PORT,
        },
        apply_mark_to_tcp, relay, resolve_server_addr, set_tcp_opts,
        tls::build_client_config,
        Outbound,
    },
};

// ── 协议常量 ──────────────────────────────────────────────────────────────────

/// padding 帧数（与 sing-box naive inbound `paddingCount` 一致）
const PADDING_COUNT: u32 = 8;

/// 单个 padding 帧最大数据尺寸（与 sing-box `writeChunked` 一致，u16 上限）
const MAX_PADDING_CHUNK: usize = 65535;

/// padding 头字符集（与 sing-box `generatePaddingHeader` 一致）
const PADDING_HEADER_CHARSET: &[u8] = b"!#$()+<>?@[]^`{}";

// ── NaiveOutbound ─────────────────────────────────────────────────────────────

pub struct NaiveOutbound {
    config: NaiveOutboundConfig,
    tls_config: Arc<ClientConfig>,
    routing_mark: u32,
    resolver: Option<Arc<crate::dns::DnsResolver>>,
}

impl NaiveOutbound {
    pub fn new(config: NaiveOutboundConfig) -> anyhow::Result<Self> {
        validate(&config)?;
        let tls_config = build_client_config(&config.tls)?;
        Ok(Self {
            config,
            tls_config,
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

    /// 建立到目标的 NaiveProxy 隧道
    async fn dial(&self, target: &Target) -> anyhow::Result<NaiveStream> {
        // 1. TCP 连接到 naive 服务器
        let addr = resolve_server_addr(
            &self.config.server,
            self.config.server_port,
            self.resolver.as_ref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("naive: resolve server {} failed: {e}", self.config.server))?;

        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        // 2. TLS 握手（使用 ALPN 协商 h2）
        let sni = self
            .config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server);
        let tls_stream =
            crate::outbound::tls::connect_tls(tcp, sni, self.tls_config.clone()).await?;

        // 3. h2 握手
        let (send_req, connection) = h2::client::handshake(tls_stream)
            .await
            .map_err(|e| anyhow::anyhow!("naive: h2 handshake failed: {e}"))?;

        // 4. 后台驱动 h2 连接
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("naive: h2 connection ended: {e}");
            }
        });

        // 5. 构建 CONNECT 请求
        let authority = format!("{}:{}", target.host(), target.port());
        let uri = Uri::builder()
            .scheme("https")
            .authority(authority.as_str())
            .build()
            .map_err(|e| anyhow::anyhow!("naive: invalid authority '{authority}': {e}"))?;

        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.config.username, self.config.password));

        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("Proxy-Authorization", format!("Basic {auth}"))
            .header("Padding", generate_padding_header());

        for (k, v) in &self.config.extra_headers {
            builder = builder.header(k.as_str(), v.as_str());
        }

        let request = builder
            .body(())
            .map_err(|e| anyhow::anyhow!("naive: build CONNECT request failed: {e}"))?;

        // 6. 发送 CONNECT 请求
        let mut h2_ready = send_req
            .ready()
            .await
            .map_err(|e| anyhow::anyhow!("naive: h2 ready failed: {e}"))?;
        let (response, send_stream) = h2_ready
            .send_request(request, false)
            .map_err(|e| anyhow::anyhow!("naive: send CONNECT failed: {e}"))?;

        // 7. 等待 200 响应
        let response = response
            .await
            .map_err(|e| anyhow::anyhow!("naive: CONNECT response failed: {e}"))?;
        if response.status() != StatusCode::OK {
            anyhow::bail!("naive: CONNECT failed with status {}", response.status());
        }

        let recv_stream = response.into_body();

        debug!(
            tag = %self.config.tag,
            target = %target,
            "naive: CONNECT tunnel established"
        );

        Ok(NaiveStream::new(send_stream, recv_stream))
    }
}

// ── 配置校验 ──────────────────────────────────────────────────────────────────

fn validate(config: &NaiveOutboundConfig) -> anyhow::Result<()> {
    // TLS 必须启用
    if !config.tls.enabled {
        anyhow::bail!("naive outbound requires TLS to be enabled");
    }

    // QUIC 模式暂不支持
    if config.quic {
        anyhow::bail!("naive outbound: QUIC (HTTP/3) mode is not yet supported in reflex");
    }

    // 校验 quic_congestion_control 值
    match config.quic_congestion_control.as_str() {
        "" | "bbr" | "bbr2" | "cubic" | "reno" => {}
        other => anyhow::bail!("naive outbound: invalid quic_congestion_control '{other}'"),
    }

    Ok(())
}

// ── padding header 生成 ───────────────────────────────────────────────────────

/// 生成 Padding HTTP 头（与 sing-box `generatePaddingHeader` 完全一致）。
///
/// 长度 30~61，前 16 字符取自 `PADDING_HEADER_CHARSET`，其余为 `~`。
fn generate_padding_header() -> String {
    let mut rng = rand::thread_rng();
    let padding_len = rng.gen_range(30..=61); // rand.Intn(32) + 30
    let mut padding = vec![0u8; padding_len];

    let mut bits = rng.gen::<u64>();
    for b in padding.iter_mut().take(16.min(padding_len)) {
        *b = PADDING_HEADER_CHARSET[(bits & 15) as usize];
        bits >>= 4;
    }
    padding[16..padding_len].fill(b'~');

    // 全部字符在 ASCII 范围内，from_utf8 不会失败
    String::from_utf8(padding).expect("padding header is ASCII")
}

// ── NaiveStream：包装 h2 SendStream + RecvStream，带 padding 分帧 ────────────
//
// 与 sing-box naive inbound 的 paddingConn 对齐：
// - 前 8 个写操作：每帧 [data_size u16 BE][padding_size u8][data][padding zeros]
//   数据按 65535 上限分块（writeChunked）
// - 前 8 个读操作：解析 3 字节头，读取 data_size 字节数据，跳过 padding_size 字节填充
// - 之后：原始读写

pub struct NaiveStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,

    // 读侧 padding 状态
    read_buf: BytesMut,
    /// 剩余 padding 帧数（初始 = 8）
    read_padding_left: u32,
    /// 当前帧剩余数据字节数
    read_data_left: usize,
    /// 当前帧剩余填充字节数
    read_pad_left: usize,

    // 写侧 padding 状态
    /// 剩余 padding 帧数（初始 = 8）
    write_padding_left: u32,
}

impl NaiveStream {
    fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            read_padding_left: PADDING_COUNT,
            read_data_left: 0,
            read_pad_left: 0,
            write_padding_left: PADDING_COUNT,
        }
    }

    /// 从 h2 RecvStream 拉取一个数据块到 read_buf。
    /// 返回 Poll<Ok(())>：表示有新数据到达或遇到 EOF（read_buf 可能为空）。
    fn poll_recv_data(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        match self.recv.poll_data(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                let len = bytes.len();
                self.read_buf.extend_from_slice(&bytes);
                // 释放流量控制窗口，否则对端窗口耗尽后阻塞
                let _ = self.recv.flow_control().release_capacity(len);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncRead for NaiveStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::{ready, Poll};
        let this = &mut *self;

        loop {
            // 1. 当前数据帧还有数据未读
            if this.read_data_left > 0 {
                if this.read_buf.is_empty() {
                    ready!(this.poll_recv_data(cx))?;
                    if this.read_buf.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                }
                let n = buf
                    .remaining()
                    .min(this.read_data_left)
                    .min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                this.read_buf.advance(n);
                this.read_data_left -= n;
                return Poll::Ready(Ok(()));
            }

            // 2. 跳过当前帧的 padding
            while this.read_pad_left > 0 {
                if this.read_buf.is_empty() {
                    ready!(this.poll_recv_data(cx))?;
                    if this.read_buf.is_empty() {
                        return Poll::Ready(Ok(())); // EOF
                    }
                }
                let n = this.read_pad_left.min(this.read_buf.len());
                this.read_buf.advance(n);
                this.read_pad_left -= n;
            }

            // 3. 还在 padding 阶段 → 读取下一帧的 3 字节头
            if this.read_padding_left > 0 {
                while this.read_buf.len() < 3 {
                    ready!(this.poll_recv_data(cx))?;
                    if this.read_buf.is_empty() {
                        // header 未读完就 EOF
                        return Poll::Ready(Ok(()));
                    }
                }
                let data_size = u16::from_be_bytes([this.read_buf[0], this.read_buf[1]]) as usize;
                let padding_size = this.read_buf[2] as usize;
                this.read_buf.advance(3);
                this.read_data_left = data_size;
                this.read_pad_left = padding_size;
                this.read_padding_left -= 1;
                // continue → 回到步骤 1 返回数据
                continue;
            }

            // 4. 原始模式（padding 帧已全部消费完）
            if this.read_buf.is_empty() {
                ready!(this.poll_recv_data(cx))?;
                if this.read_buf.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }
            }
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.advance(n);
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for NaiveStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = &mut *self;

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // padding 阶段：分块为 ≤65535 的帧；非 padding 阶段：直接发
        let (chunk_size, frame) = if this.write_padding_left > 0 {
            let cs = data.len().min(MAX_PADDING_CHUNK);
            let padding_size: u8 = rand::thread_rng().gen();
            let mut f = BytesMut::with_capacity(3 + cs + padding_size as usize);
            f.extend_from_slice(&(cs as u16).to_be_bytes());
            f.put_u8(padding_size);
            f.extend_from_slice(&data[..cs]);
            f.put_bytes(0, padding_size as usize);
            (cs, f.freeze())
        } else {
            (data.len(), Bytes::copy_from_slice(data))
        };

        // 等待流控容量
        this.send.reserve_capacity(frame.len());
        if this.send.capacity() < frame.len() {
            // poll_capacity 返回 Poll<Option<Result<usize, Error>>>
            // None 表示流已关闭
            match this.send.poll_capacity(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "naive: h2 stream closed",
                    )))
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(std::io::Error::other(e))),
                Poll::Ready(Some(Ok(_))) => {}
            }
        }

        match this.send.send_data(frame, false) {
            Ok(()) => {
                if this.write_padding_left > 0 {
                    this.write_padding_left -= 1;
                }
                Poll::Ready(Ok(chunk_size))
            }
            Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        let _ = this.send.send_data(Bytes::new(), true);
        std::task::Poll::Ready(Ok(()))
    }
}

// ── Outbound trait ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for NaiveOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let stream = self.dial(&target).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            "naive tcp connecting"
        );
        let stream = self.dial(&conn.target).await?;
        Ok(relay(conn.stream, stream).await)
    }

    /// UDP 使用 sing-box UDP-over-TCP v2 协议承载（复用 anytls 的 UoT v2 实现）。
    ///
    /// 流程与 anytls `handle_udp` 一致：
    /// 1. 向 naive 服务端发起目标 = `sp.v2.udp-over-tcp.arpa:443` 的 CONNECT
    /// 2. 写 UoT v2 请求头（包含真实目标地址）
    /// 3. 发送第一个 UDP 包
    /// 4. spawn task 持续写入后续上行包
    /// 5. 当前 task 持续读取下行 UDP 包并回给入站
    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let uot_enabled = self
            .config
            .udp_over_tcp
            .as_ref()
            .map(|u| u.enabled)
            .unwrap_or(false);

        if !uot_enabled {
            anyhow::bail!("naive outbound: UDP requires udp_over_tcp enabled");
        }

        debug!(
            tag = %self.config.tag,
            target = %packet.target,
            "naive udp session (UoT v2)"
        );

        let uot_target = Target::Domain(UOT_MAGIC_ADDRESS.to_string(), UOT_MAGIC_PORT);
        let mut stream = self.dial(&uot_target).await?;

        // 写 UoT v2 请求头
        let req_hdr = build_uot_request(&packet.target);
        stream.write_all(&req_hdr).await?;

        // 发送第一个 UDP 数据包
        let first = build_uot_packet(&packet.target, &packet.data);
        stream.write_all(&first).await?;

        let timeout = std::time::Duration::from_secs(30);
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());

        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // 上行任务：持续将后续 UDP 包写入隧道
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            tokio::spawn(async move {
                while let Some((target, data)) = upstream_rx.recv().await {
                    let frame = build_uot_packet(&target, &data);
                    if write_half.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 下行：读取 UoT v2 封装的 UDP 包并回给入站
        loop {
            match tokio::time::timeout(timeout, read_uot_packet(&mut read_half)).await {
                Ok(Ok((_target, data))) => {
                    let _ = reply_tx.send((data, src, spoofed_src)).await;
                }
                Ok(Err(e)) => {
                    let s = e.to_string();
                    if s.contains("eof")
                        || s.contains("EOF")
                        || s.contains("closed")
                        || s.contains("reset")
                    {
                        break;
                    }
                    return Err(e);
                }
                Err(_) => break, // timeout
            }
        }

        Ok(())
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_header_format() {
        let hdr = generate_padding_header();
        // 长度在 30..=61
        assert!(hdr.len() >= 30 && hdr.len() <= 61);
        // 前 16 字符在字符集内
        for b in hdr.bytes().take(16) {
            assert!(
                PADDING_HEADER_CHARSET.contains(&b),
                "char {} not in charset",
                b
            );
        }
        // 其余为 ~
        for b in hdr.bytes().skip(16) {
            assert_eq!(b, b'~');
        }
    }

    #[test]
    fn validate_rejects_no_tls() {
        let mut cfg = NaiveOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            username: String::new(),
            password: String::new(),
            insecure_concurrency: 0,
            extra_headers: Default::default(),
            stream_receive_window: Default::default(),
            udp_over_tcp: None,
            quic: false,
            quic_congestion_control: String::new(),
            quic_session_receive_window: Default::default(),
            tls: crate::config::outbound::TlsConfig {
                enabled: false,
                ..Default::default()
            },
        };
        assert!(validate(&cfg).is_err());

        // 启用 TLS 后校验通过（TLS 配置本身不在此处检查）
        cfg.tls.enabled = true;
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn validate_rejects_quic_mode() {
        let cfg = NaiveOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            username: String::new(),
            password: String::new(),
            insecure_concurrency: 0,
            extra_headers: Default::default(),
            stream_receive_window: Default::default(),
            udp_over_tcp: None,
            quic: true,
            quic_congestion_control: String::new(),
            quic_session_receive_window: Default::default(),
            tls: crate::config::outbound::TlsConfig {
                enabled: true,
                ..Default::default()
            },
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_quic_congestion_control_values() {
        let valid = ["", "bbr", "bbr2", "cubic", "reno"];
        for cc in &valid {
            let cfg = NaiveOutboundConfig {
                tag: "test".into(),
                server: "example.com".into(),
                server_port: 443,
                username: String::new(),
                password: String::new(),
                insecure_concurrency: 0,
                extra_headers: Default::default(),
                stream_receive_window: Default::default(),
                udp_over_tcp: None,
                quic: false,
                quic_congestion_control: cc.to_string(),
                quic_session_receive_window: Default::default(),
                tls: crate::config::outbound::TlsConfig {
                    enabled: true,
                    ..Default::default()
                },
            };
            assert!(validate(&cfg).is_ok(), "should accept cc='{cc}'");
        }

        let cfg = NaiveOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            username: String::new(),
            password: String::new(),
            insecure_concurrency: 0,
            extra_headers: Default::default(),
            stream_receive_window: Default::default(),
            udp_over_tcp: None,
            quic: false,
            quic_congestion_control: "invalid".into(),
            quic_session_receive_window: Default::default(),
            tls: crate::config::outbound::TlsConfig {
                enabled: true,
                ..Default::default()
            },
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn base64_auth_encoding() {
        let auth = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert_eq!(auth, "dXNlcjpwYXNz");
    }
}
