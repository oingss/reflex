//! WebSocket 传输层实现
//!
//! 为 Reflex 的出站协议（VLESS、VMess、Trojan、Shadowsocks）提供统一的
//! WebSocket 传输模式。参照 Xray-core 的 `transport/internet/websocket`。
//!
//! # 工作原理
//!
//! 客户端与服务器建立 WebSocket 连接（可选 TLS），随后将代理协议的字节流
//! 承载于 WS Binary 帧上双向传输。与 sing-box 的 v2ray transport ws 行为一致：
//! 每次写入各自成帧，读取时从 Binary 帧中取出载荷。
//!
//! # TLS 路径
//!
//! 与 sing-box 一致，WS over TLS **先建立 TLS 流（走统一的
//! `tls::connect_tls_or_utls`，支持 uTLS 指纹伪造）**，再在已建立的 TLS 流上
//! 进行 WS 握手。这样所有出站协议的 TLS 配置（含 uTLS、自签证书、ALPN）统一
//! 走同一入口，不再在 `new()` 时提前压成 `rustls::ClientConfig` 丢失字段。
//!
//! # WsStream 适配器
//!
//! [`WsStream`] 将 `WebSocketStream` 适配为 `AsyncRead + AsyncWrite`：
//! - 可选的握手头（`pending_header`）：首次写入时与数据合并为一个 WS Binary 帧
//!   （VLESS、Trojan 需要）。
//! - 可选的 VLESS 响应头跳过：首次读取时解析并跳过
//!   `[Ver 1B][Addon Len 1B][Addon ...]` 响应头（仅 VLESS 需要）。

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
        client::IntoClientRequest,
        http::HeaderValue,
        protocol::WebSocketConfig,
        Message,
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

    let tls_enabled = tls.map_or(false, |t| t.enabled);

    // URL 始终包含端口（与 sing-box 一致），Host 头由 URL 自动派生
    let url = if tls_enabled {
        format!("wss://{sni}:{port}{path}")
    } else {
        format!("ws://{server}:{port}{path}")
    };
    let mut request = url.into_client_request()?;
    for (k, v) in &ws_cfg.headers {
        request.headers_mut().insert(
            k.parse::<tokio_tungstenite::tungstenite::http::header::HeaderName>()?,
            HeaderValue::from_str(v)?,
        );
    }
    // 仅在用户未显式配置 Host 时回填 SNI（非默认端口时 URL 已含端口）
    if !ws_cfg.headers.contains_key("Host") {
        request.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::HOST,
            HeaderValue::from_str(sni)?,
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
        // 若 ALPN 协商出 h2，WS 握手会失败。与 sing-box client.go:38-40 一致：
        // 仅当用户未显式配置 ALPN 时回填 http/1.1。
        let mut tls_cfg = tls.cloned().expect("tls is Some when tls_enabled");
        if tls_cfg.alpn.is_empty() {
            tls_cfg.alpn = vec!["http/1.1".to_string()];
        }
        let tls_stream =
            crate::outbound::tls::connect_tls_or_utls(tcp, sni, &tls_cfg).await?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    // 在已建立的流（TLS 或 TCP）上进行 WS 握手，不再依赖 tokio-tungstenite
    // 内置的 TLS connector，从而保证 TLS 配置走统一入口。
    let (ws_stream, _) = client_async_with_config(request, io, None::<WebSocketConfig>).await?;
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
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        e,
                    )))
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
        if let Poll::Pending = this.inner.as_mut().poll_ready(cx).map_err(ws_err)? {
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
}
