use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::{
        client::IntoClientRequest, http::HeaderValue, protocol::WebSocketConfig, Message,
    },
    WebSocketStream,
};
use tracing::debug;

use crate::config::outbound::{TlsConfig, WsTransportConfig};
use crate::dns::DnsResolver;
use crate::outbound::{apply_mark_to_tcp, resolve_server_addr, set_tcp_opts, AsyncReadWrite};

// ── 连接建立 ─────────────────────────────────────────────────────────────────

/// 建立一条 WebSocket 连接。
///
/// 当 `tls` 为 `Some` 且 `tls.enabled = true` 时，先通过
/// [`crate::outbound::tls::connect_tls_or_utls`] 建立 TLS 流（支持 uTLS），
/// 再在该 TLS 流上进行 WS 握手；否则直接在 TCP 上进行 WS 握手。
///
/// # 参数
///
/// - `server` / `port`：出站节点自身的地址。
/// - `sni`：TLS SNI（也用于 Host 头回填），通常等于 `server_name` 或 `server`。
/// - `tls`：完整 TLS 配置。`None` 或 `tls.enabled = false` 表示明文 WS。
///   传入时会克隆一份并强制 ALPN 为 `http/1.1`（若用户未显式配置），
///   因为 WebSocket Upgrade 必须走 HTTP/1.1（RFC 6455）。
/// - `ws_cfg`：WebSocket 传输配置（路径、自定义请求头等）。
/// - `routing_mark`：全局 SO_MARK，0 表示不设置。
/// - `resolver`：用于解析 `server` 域名，None 时回退系统 DNS。
pub async fn connect(
    server: &str,
    port: u16,
    sni: &str,
    tls: Option<&TlsConfig>,
    ws_cfg: &WsTransportConfig,
    routing_mark: u32,
    resolver: Option<Arc<DnsResolver>>,
) -> anyhow::Result<WebSocketStream<Box<dyn AsyncReadWrite>>> {
    let addr = resolve_server_addr(server, port, resolver.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;

    let tcp = TcpStream::connect(addr).await?;
    set_tcp_opts(&tcp)?;
    apply_mark_to_tcp(&tcp, routing_mark)?;

    // 确保 path 以 `/` 开头（与 sing-box v2raywebsocket/client.go:55-57 一致）
    let path = if ws_cfg.path.starts_with('/') {
        ws_cfg.path.clone()
    } else {
        format!("/{}", ws_cfg.path)
    };

    let tls_enabled = tls.is_some_and(|t| t.enabled);

    // URL 始终使用 ws:// scheme（与 clash-rs 一致）。
    // TLS 由底层 connect_tls_or_utls 在传入的 stream 上处理，与 WS 请求 URL 的
    // scheme 无关。client_async_with_config 不会根据 scheme 发起 TLS。
    //
    // Host 头由 URL authority 自动生成（sni:port），与 sing-box 使用
    // serverAddr.String()（host:port）一致。
    //
    // 旧实现在此处将 Host 覆盖为仅 sni（去掉端口），导致非标准端口的请求被
    // 反向代理/CDN 拒绝或路由错误 → VLESS+WS+TLS 握手失败。
    // 修正：不再覆盖 Host 头，保留 URL 中的 sni:port。用户可通过 ws_cfg.headers
    // 自定义 Host。
    let url = format!("ws://{sni}:{port}{path}");
    let mut request = url.into_client_request()?;
    for (k, v) in &ws_cfg.headers {
        request.headers_mut().insert(
            k.parse::<tokio_tungstenite::tungstenite::http::header::HeaderName>()?,
            HeaderValue::from_str(v)?,
        );
    }
    // 设置默认 User-Agent（与 sing-box client.go:63-65 一致）
    if !request.headers().contains_key("user-agent") {
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::USER_AGENT,
            HeaderValue::from_static("Go-http-client/1.1"),
        );
    }

    // 构建底层 I/O 流：TLS 启用时先建立 TLS 流（支持 uTLS），否则用明文 TCP。
    // 与 sing-box 一致：WS 握手在已建立的 TLS 流上进行，TLS 配置由
    // `connect_tls_or_utls` 统一处理（含 uTLS 指纹、自签证书、ALPN）。
    let io: Box<dyn AsyncReadWrite> = if tls_enabled {
        // WS over TLS 必须使用 http/1.1 ALPN（RFC 6455 要求 HTTP Upgrade）。
        // 若 ALPN 协商出 h2，WS 握手会失败（tokio-tungstenite 的 client_async
        // 走 HTTP/1.1 Upgrade，不支持 h2）。
        //
        // 旧实现仅在 alpn 为空时回填 http/1.1，导致用户配置 ["h2","http/1.1"]
        // 时服务端可能协商出 h2 → WS 握手失败。
        // 修正：WS 强制 ALPN 为 http/1.1，覆盖用户配置的 h2。
        let mut tls_cfg = tls.cloned().expect("tls is Some when tls_enabled");
        tls_cfg.alpn = vec!["http/1.1".to_string()];
        let tls_stream = crate::outbound::tls::connect_tls_or_utls(tcp, sni, &tls_cfg).await?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    // 在已建立的流（TLS 或 TCP）上进行 WS 握手，不再依赖 tokio-tungstenite
    // 内置的 TLS connector，从而保证 TLS 配置走统一入口。
    //
    // write_buffer_size=0：每次 write 即刻将帧写入底层流，不再缓冲到 128KB。
    // 与 sing-box v2raywebsocket/conn.go Write() 每次各自成帧、立即发送一致。
    // 虽然 relay() 在每次 write_all 后调用 flush，但 write_buffer_size=0 可确保
    // 即使 flush 延迟（如 tokio::io::split 锁竞争），帧也能尽早到达服务端。
    let ws_config = WebSocketConfig {
        write_buffer_size: 0,
        ..Default::default()
    };
    let (ws_stream, _) = client_async_with_config(request, io, Some(ws_config)).await?;
    debug!(%server, port, tls_enabled, "websocket connected");
    Ok(ws_stream)
}

// ── WsStream 适配器 ──────────────────────────────────────────────────────────

pin_project! {
    /// 将 `WebSocketStream` 适配为 `AsyncRead + AsyncWrite`。
    ///
    /// 行为与 sing-box v2ray transport ws 一致：每次写入各自成帧，
    /// 读取时从 Binary 帧取出载荷。
    ///
    /// # 构造方式
    ///
    /// - [`WsStream::new`]：不带握手头（适用于 VMess、Shadowsocks）。
    /// - [`WsStream::with_header`]：带握手头，首次写入时将 header 与数据合并为一帧
    ///   （适用于 VLESS、Trojan）。
    /// - [`WsStream::skip_vless_response`]：链式启用 VLESS 响应头跳过。
    pub struct WsStream<S> {
        #[pin]
        inner: S,
        pending_header: Option<Bytes>,
        read_buf: Bytes,
        skip_vless_response: bool,
        response_header_skipped: bool,
    }
}

impl<S> WsStream<S> {
    /// 创建一个不带握手头的 WS 适配器（适用于 VMess、Shadowsocks）。
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending_header: None,
            read_buf: Bytes::new(),
            skip_vless_response: false,
            response_header_skipped: false,
        }
    }

    /// 创建一个带握手头的 WS 适配器，首次写入时将 header 与数据合并为一帧
    /// （适用于 VLESS、Trojan）。
    pub fn with_header(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
            skip_vless_response: false,
            response_header_skipped: false,
        }
    }

    /// 启用 VLESS 响应头跳过：首次读到的 Binary 帧会被解析并跳过
    /// `[Ver 1B][Addon Len 1B][Addon ...]` 响应头。
    pub fn skip_vless_response(mut self) -> Self {
        self.skip_vless_response = true;
        self
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        loop {
            if !this.read_buf.is_empty() {
                let n = buf.remaining().min(this.read_buf.len());
                buf.put_slice(&this.read_buf[..n]);
                *this.read_buf = this.read_buf.slice(n..);
                return Poll::Ready(Ok(()));
            }
            match this.inner.as_mut().poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)))
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(data) => {
                        let data = Bytes::from(data);
                        if *this.skip_vless_response && !*this.response_header_skipped {
                            *this.response_header_skipped = true;
                            match parse_vless_response_header(&data) {
                                Ok(skip) => {
                                    *this.read_buf = data.slice(skip..);
                                }
                                // 解析失败时保留完整数据，避免丢包
                                Err(_) => {
                                    *this.read_buf = data;
                                }
                            }
                        } else {
                            *this.read_buf = data;
                        }
                    }
                    // tokio-tungstenite 默认在底层自动回 Pong；显式忽略 Ping/Pong，
                    // 避免被当噪声丢掉后被对端判定超时。
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(_) => return Poll::Ready(Ok(())),
                    _ => {}
                },
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        if this.inner.as_mut().poll_ready(cx).map_err(ws_err)?.is_pending() {
            return Poll::Pending;
        }
        // 注意：先构建 payload 但不 take header，直到 start_send 成功后再 take。
        // 旧实现在 start_send 前 take，若 start_send 失败则 header 已丢失且未发送，
        // 重试时只发裸数据 → 协议帧错位。
        let (payload, header_consumed) = if let Some(header) = this.pending_header.as_ref() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(header);
            combined.put_slice(data);
            (combined.freeze().into(), true)
        } else {
            (data.to_vec(), false)
        };
        let len = data.len();
        match this.inner.as_mut().start_send(Message::Binary(payload)) {
            Ok(()) => {
                // start_send 成功后才安全消费 header
                if header_consumed {
                    *this.pending_header = None;
                }
                Poll::Ready(Ok(len))
            }
            Err(e) => Poll::Ready(Err(ws_err(e))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx).map_err(ws_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx).map_err(ws_err)
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::BrokenPipe, e)
}

/// 解析 VLESS 响应头 `[Ver 1B][Addon Len 1B][Addon ...]`，返回需要跳过的字节数。
///
/// 与 `crate::outbound::common::proto::vless_parse_response` 语义一致，
/// 此处内联以避免传输层对协议帧模块的依赖。
fn parse_vless_response_header(buf: &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(buf.len() >= 2, "vless response too short");
    anyhow::ensure!(
        buf[0] == 0x00,
        "unsupported vless response version: {}",
        buf[0]
    );
    let addon_len = buf[1] as usize;
    anyhow::ensure!(buf.len() >= 2 + addon_len, "vless response addon truncated");
    Ok(2 + addon_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_response_ok() {
        assert_eq!(parse_vless_response_header(&[0x00, 0x00]).unwrap(), 2);
        assert_eq!(
            parse_vless_response_header(&[0x00, 0x03, 0x01, 0x02, 0x03]).unwrap(),
            5
        );
    }

    #[test]
    fn parse_vless_response_bad_version() {
        assert!(parse_vless_response_header(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn parse_vless_response_too_short() {
        assert!(parse_vless_response_header(&[0x00]).is_err());
        assert!(parse_vless_response_header(&[0x00, 0x05, 0x01]).is_err());
    }

    /// Build a minimal VLESS TCP request header for testing:
    /// [Ver=0][UUID 16B][AddonLen=0][Cmd=1][Port u16 BE][ATYP=2 domain][Len][Domain]
    fn test_vless_header() -> Bytes {
        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(0x00); // Version
        buf.put_slice(&[0xaau8; 16]); // UUID
        buf.put_u8(0x00); // Addon length = 0
        buf.put_u8(0x01); // Command: TCP
        buf.put_u16(443); // Port
        buf.put_u8(0x02); // ATYP: domain
        buf.put_u8(11); // domain length
        buf.put_slice(b"example.com");
        buf.freeze()
    }

    /// End-to-end test: VLESS header merge + response skip over a real
    /// WebSocket connection (no TLS, just WS over a duplex stream).
    #[tokio::test]
    async fn vless_ws_roundtrip() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio_tungstenite::accept_async;

        let (client_io, server_io) = tokio::io::duplex(8192);

        // VLESS header = [Ver 1][UUID 16][AddonLen 1][Cmd 1][Port 2][ATYP 1][Len 1][Domain 11] = 34
        let header = test_vless_header();
        let hdr_len = header.len();
        let header_for_check = header.clone();

        // ── Server side: accept WS, verify first frame = VLESS header + data,
        //    then send VLESS response header + payload. ─────────────────────
        let server = tokio::spawn(async move {
            let mut ws = accept_async(server_io).await.expect("ws accept");

            // First Binary frame must contain VLESS header + first data chunk.
            let msg = ws.next().await.expect("msg").expect("ok");
            assert!(msg.is_binary(), "expected binary frame");
            let frame = msg.into_data();

            // Verify VLESS header prefix.
            assert_eq!(&frame[..hdr_len], &header_for_check[..]);
            // After header, the first data chunk should follow.
            assert_eq!(&frame[hdr_len..], b"hello");

            // Send VLESS response header [Ver=0][AddonLen=0] + payload.
            let mut reply = Vec::new();
            reply.push(0x00); // Ver
            reply.push(0x00); // Addon len
            reply.extend_from_slice(b"world");
            ws.send(Message::Binary(reply)).await.expect("send reply");
            ws.flush().await.expect("flush reply");
        });

        // ── Client side: WS handshake, then wrap with WsStream. ──────────────
        let (ws_stream, _resp) =
            tokio_tungstenite::client_async("ws://localhost/test", client_io)
                .await
                .expect("ws connect");

        let mut ws = WsStream::with_header(ws_stream, header).skip_vless_response();

        // Write first data — should be merged with VLESS header into one frame.
        ws.write_all(b"hello").await.expect("write");
        ws.flush().await.expect("flush");

        // Read response — VLESS response header [0x00, 0x00] should be skipped.
        let mut buf = [0u8; 64];
        let n = ws.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"world", "payload after response header");

        server.await.unwrap();
    }

    /// End-to-end test: VLESS + WS + TLS with uTLS fallback.
    ///
    /// Verifies the three fixes that make VLESS+WS+TLS work:
    /// 1. `connect_tls_or_utls` falls back to standard rustls when uTLS is
    ///    enabled (the custom uTLS impl has a key_share mismatch bug).
    /// 2. WS handshake works over the TLS stream with ALPN `http/1.1`.
    /// 3. VLESS header merge + response skip work over WS+TLS.
    #[tokio::test]
    async fn vless_ws_tls_roundtrip() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::server::TlsAcceptor;
        use tokio_tungstenite::accept_async;

        // rustls 0.23 要求显式安装 CryptoProvider（生产代码在 main() 中安装）。
        // 多次调用安全：已安装时 install_default 返回 Err，此处忽略。
        let _ = rustls::crypto::ring::default_provider().install_default();

        // ── Generate self-signed cert for "localhost" ───────────────────────
        let cert_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let key_pair = rcgen::KeyPair::generate().expect("key pair");
        let cert = cert_params.self_signed(&key_pair).expect("self-signed cert");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
            .expect("private key der");

        // ── TLS server config ───────────────────────────────────────────────
        let server_config = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

        // ── TCP listener ────────────────────────────────────────────────────
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let header = test_vless_header();
        let hdr_len = header.len();
        let header_for_check = header.clone();

        // ── Server: TCP → TLS → WS → verify VLESS header + send response ───
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let tls = acceptor.accept(tcp).await.expect("tls accept");
            let mut ws = accept_async(tls).await.expect("ws accept");

            let msg = ws.next().await.expect("msg").expect("ok");
            assert!(msg.is_binary(), "expected binary frame");
            let frame = msg.into_data();
            assert_eq!(&frame[..hdr_len], &header_for_check[..], "vless header prefix");
            assert_eq!(&frame[hdr_len..], b"hello", "data after header");

            let mut reply = Vec::new();
            reply.push(0x00); // Ver
            reply.push(0x00); // Addon len
            reply.extend_from_slice(b"world");
            ws.send(Message::Binary(reply)).await.expect("send reply");
            ws.flush().await.expect("flush reply");
        });

        // ── Client: TCP → TLS (uTLS fallback) → WS → VLESS header merge ────
        let tcp = TcpStream::connect(addr).await.expect("connect");

        // TLS config with uTLS enabled — must fall back to standard rustls.
        let tls_config = crate::config::outbound::TlsConfig {
            enabled: true,
            server_name: Some("localhost".to_string()),
            insecure: true,
            alpn: vec!["http/1.1".to_string()],
            utls: Some(crate::config::outbound::UtlsConfig {
                enabled: true,
                fingerprint: crate::config::outbound::UtlsFingerprint::Chrome,
            }),
            ..Default::default()
        };

        let tls_stream =
            crate::outbound::tls::connect_tls_or_utls(tcp, "localhost", &tls_config)
                .await
                .expect("tls connect (utls fallback)");

        let (ws_stream, _resp) =
            tokio_tungstenite::client_async("ws://localhost/test", tls_stream)
                .await
                .expect("ws connect");

        let mut ws = WsStream::with_header(ws_stream, header).skip_vless_response();

        ws.write_all(b"hello").await.expect("write");
        ws.flush().await.expect("flush");

        let mut buf = [0u8; 64];
        let n = ws.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"world", "payload after response header");

        server.await.unwrap();
    }

    /// Integration test: go through `connect()` to verify the Host header
    /// includes the port and end-to-end VLESS+WS+TLS works.
    ///
    /// This test catches the bug where `connect()` overrode the Host header
    /// with just the SNI (without port), causing routing failures on servers
    /// that match on `host:port`.
    #[tokio::test]
    async fn connect_includes_port_in_host_header() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::server::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();

        // ── Generate self-signed cert for "localhost" ───────────────────────
        let cert_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let key_pair = rcgen::KeyPair::generate().expect("key pair");
        let cert = cert_params.self_signed(&key_pair).expect("self-signed cert");
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der())
            .expect("private key der");

        let server_config = rustls::server::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(server_config));

        // ── TCP listener on a random port ──────────────────────────────────
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let port = addr.port();

        let header = test_vless_header();
        let hdr_len = header.len();
        let header_for_check = header.clone();

        // ── Server: TCP → TLS → read raw HTTP request → WS accept ──────────
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor.accept(tcp).await.expect("tls accept");

            // Read the raw HTTP upgrade request to capture the Host header.
            let mut req_buf = vec![0u8; 4096];
            let n = tls.read(&mut req_buf).await.expect("read http request");
            let req_str = String::from_utf8_lossy(&req_buf[..n]);

            // Extract Host header from the raw HTTP request.
            let host = req_str
                .lines()
                .find_map(|line| {
                    let line = line.trim();
                    if line.to_ascii_lowercase().starts_with("host:") {
                        Some(line[5..].trim().to_string())
                    } else {
                        None
                    }
                })
                .expect("Host header not found");

            // Verify Host header includes the port (the bug stripped it).
            assert!(
                host.contains(&format!(":{port}")),
                "Host header '{host}' must include port :{port}"
            );

            // Send a valid WS upgrade response.
            // Extract Sec-WebSocket-Key from the request.
            let key = req_str
                .lines()
                .find_map(|line| {
                    let line = line.trim();
                    if line.to_ascii_lowercase().starts_with("sec-websocket-key:") {
                        Some(line.split(':').nth(1).unwrap().trim().to_string())
                    } else {
                        None
                    }
                })
                .expect("Sec-WebSocket-Key not found");

            let accept_key =
                tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept_key}\r\n\
                 \r\n"
            );
            tls.write_all(response.as_bytes()).await.expect("write ws response");
            tls.flush().await.expect("flush ws response");

            // Now the TLS stream is a WS stream. Wrap it with accept_async
            // to get a WebSocketStream for frame-level read/write.
            // We need to use from_partially_read since we already consumed some bytes.
            let ws = tokio_tungstenite::WebSocketStream::from_partially_read(
                tls,
                Vec::new(),
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            let mut ws = ws;

            // Verify VLESS header + data in first frame.
            let msg = ws.next().await.expect("msg").expect("ok");
            assert!(msg.is_binary(), "expected binary frame");
            let frame = msg.into_data();
            assert_eq!(&frame[..hdr_len], &header_for_check[..], "vless header prefix");
            assert_eq!(&frame[hdr_len..], b"hello", "data after header");

            // Send VLESS response header + payload.
            let mut reply = Vec::new();
            reply.push(0x00); // Ver
            reply.push(0x00); // Addon len
            reply.extend_from_slice(b"world");
            ws.send(Message::Binary(reply)).await.expect("send reply");
            ws.flush().await.expect("flush reply");
        });

        // ── Client: use connect() with TLS enabled ────────────────────────
        let ws_cfg = crate::config::outbound::WsTransportConfig {
            path: "/test".to_string(),
            headers: std::collections::HashMap::new(),
            early_data_header_name: None,
            max_early_data: 0,
        };
        let tls_config = crate::config::outbound::TlsConfig {
            enabled: true,
            server_name: Some("localhost".to_string()),
            insecure: true,
            alpn: vec!["http/1.1".to_string()],
            ..Default::default()
        };

        let ws_stream = connect(
            // server（连接用）：用 127.0.0.1 避免 localhost 在某些系统解析为
            // IPv6 ::1（服务器绑定 IPv4 127.0.0.1，IPv6 连接会被拒绝）。
            "127.0.0.1",
            port,
            // sni（Host 头用）：保留 localhost，测试 Host 头包含端口。
            "localhost",
            Some(&tls_config),
            &ws_cfg,
            0,
            None,
        )
        .await
        .expect("ws connect");

        let mut ws = WsStream::with_header(ws_stream, header).skip_vless_response();
        ws.write_all(b"hello").await.expect("write");
        ws.flush().await.expect("flush");

        let mut buf = [0u8; 64];
        let n = ws.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], b"world", "payload after response header");

        server.await.unwrap();
    }
}
