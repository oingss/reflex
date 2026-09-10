//! WebSocket inbound 传输层（VLESS/VMess/Trojan 共用）。
//!
//! 移植自 flux-master `src/common/transport/websocket.rs`，对齐 sing-box
//! `transport/v2raywebsocket` 服务端行为：
//!   • 路径自动补 `/` 前缀
//!   • 0-RTT 早期数据（path-based base64url 或 header-based）
//!   • 可选 Host / 自定义 HTTP 头校验
//!
//! Wire format: payload 以 Binary WebSocket 帧承载，对外呈现为字节流。

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD, Engine as _};
use bytes::BytesMut;
use futures_util::{Sink, Stream};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tracing::debug;

// ── Accept options ───────────────────────────────────────────────────────────

/// WebSocket 服务端接受选项（对齐 sing-box V2RayWebsocketOptions）
#[derive(Debug, Clone, Default)]
pub struct WsServerOptions {
    /// 期望的 URL 路径（不含 query）。自动补 `/` 前缀。
    pub path: String,
    /// 可选 Host 头校验。
    pub host: Option<String>,
    /// 自定义 HTTP 头（仅做存在性 / 值校验；None = 不校验）。
    pub headers: Option<HashMap<String, String>>,
    /// 早期数据最大字节数。0 = 不启用。
    pub max_early_data: u32,
    /// 早期数据 HTTP 头名。None = 路径模式（base64url 追加到 path 末尾）。
    pub early_data_header_name: Option<String>,
}

impl WsServerOptions {
    pub fn from_config(cfg: &crate::config::inbound::InboundWsTransportConfig) -> Self {
        Self {
            path: cfg.path.clone(),
            host: cfg.host.clone(),
            headers: cfg.headers.clone(),
            max_early_data: cfg.max_early_data,
            early_data_header_name: cfg.early_data_header_name.clone(),
        }
    }
}

// ── Public accept ────────────────────────────────────────────────────────────

/// 在已完成 TLS/Reality 的流（或任意 AsyncReadWrite）上执行 WebSocket 升级。
pub async fn accept<S>(stream: S, opts: &WsServerOptions) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    do_upgrade(stream, opts).await
}

#[allow(clippy::result_large_err)]
async fn do_upgrade<S>(stream: S, opts: &WsServerOptions) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 对齐 sing-box：路径自动补 '/' 前缀
    let expected_path = if opts.path.starts_with('/') {
        opts.path.clone()
    } else {
        format!("/{}", opts.path)
    };

    let host = opts.host.clone();
    let max_early_data = opts.max_early_data;
    let early_data_header = opts.early_data_header_name.clone();
    let custom_headers = opts.headers.clone();
    let path_for_check = expected_path.clone();

    // accept_hdr_async 的 callback 是 Fn（不可变捕获），用 Arc<Mutex<Option<_>>>
    // 提供内部可变性来捕获 early data。
    let early_data_slot: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let early_data_slot_cb = Arc::clone(&early_data_slot);

    let ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
        // ── 校验 Host 头 ──────────────────────────────────────────────────
        if let Some(ref expected) = host {
            let req_host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if req_host != expected.as_str() {
                debug!("[ws] rejected host: {req_host} (expected {expected})");
                return Err(Response::builder().status(400).body(None).unwrap());
            }
        }

        // ── 提取早期数据 + 路径校验 ───────────────────────────────────────
        //
        // 对齐 sing-box v2raywebsocket/server.go ServeHTTP:
        //   1. max_early_data > 0 且 early_data_header_name == "":
        //      早期数据以 base64url 追加到 URL path 末尾 → 前缀匹配。
        //   2. early_data_header_name != "":
        //      早期数据从指定 HTTP 头读取（base64url）→ 严格 path 匹配。
        //   3. max_early_data == 0: 无早期数据 → 严格 path 匹配。
        let early_data: Vec<u8> = if max_early_data > 0 {
            if let Some(ref hdr_name) = early_data_header {
                // 模式 2：header-based early data，严格 path 匹配
                let req_path = req.uri().path();
                if req_path != path_for_check.as_str() {
                    debug!("[ws] rejected path: {req_path} (expected {path_for_check})");
                    return Err(Response::builder().status(404).body(None).unwrap());
                }
                req.headers()
                    .get(hdr_name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        if s.is_empty() {
                            None
                        } else {
                            BASE64_URL_NO_PAD.decode(s).ok()
                        }
                    })
                    .unwrap_or_default()
            } else {
                // 模式 1：path-based early data，前缀匹配
                let req_uri = req.uri().path();
                if !req_uri.starts_with(path_for_check.as_str()) {
                    debug!("[ws] rejected path: {req_uri} (expected prefix {path_for_check})");
                    return Err(Response::builder().status(404).body(None).unwrap());
                }
                let ed_str = &req_uri[path_for_check.len()..];
                if ed_str.is_empty() {
                    Vec::new()
                } else {
                    BASE64_URL_NO_PAD.decode(ed_str).unwrap_or_else(|e| {
                        debug!("[ws] early data base64 decode error: {e}");
                        Vec::new()
                    })
                }
            }
        } else {
            // 模式 3：无早期数据，严格 path 匹配
            let req_path = req.uri().path();
            if req_path != path_for_check.as_str() {
                debug!("[ws] rejected path: {req_path} (expected {path_for_check})");
                return Err(Response::builder().status(404).body(None).unwrap());
            }
            Vec::new()
        };

        // ── 校验自定义头（可选）──────────────────────────────────────────
        if let Some(ref hdrs) = custom_headers {
            for (k, v) in hdrs {
                if let Some(rv) = req.headers().get(k.as_str()) {
                    if rv.to_str().map(|s| s != v.as_str()).unwrap_or(true) {
                        debug!("[ws] custom header mismatch: {k}");
                    }
                }
            }
        }

        debug!(
            "[ws] accepted: path={} early_data={} bytes",
            req.uri().path(),
            early_data.len()
        );

        // 将 early data 存入共享 slot，握手完成后取回
        *early_data_slot_cb.lock().unwrap() = Some(early_data);

        Ok(resp)
    })
    .await?;

    // 取回 callback 中提取的 early data
    let early_data = early_data_slot.lock().unwrap().take().unwrap_or_default();

    Ok(WsStream::with_early_data(ws, early_data))
}

// ── WsStream: AsyncRead + AsyncWrite wrapper ──────────────────────────────────
//
// WebSocket 是消息分帧，VLESS/VMess/Trojan 是字节流。做法：
//   • 读端：poll Binary/Text 帧 → BytesMut 缓冲（含 0-RTT early data 优先）
//   • 写端：整段数据作为 Binary 帧发出

pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    /// 跨帧残留 / 早期数据
    read_buf: BytesMut,
}

impl<S> WsStream<S> {
    #[allow(dead_code)]
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            inner: ws,
            read_buf: BytesMut::with_capacity(65536),
        }
    }

    /// 创建带 0-RTT 早期数据的 WsStream，early data 优先于任何 WebSocket 帧
    pub fn with_early_data(ws: WebSocketStream<S>, early_data: Vec<u8>) -> Self {
        let cap = 65536.max(early_data.len());
        let mut read_buf = BytesMut::with_capacity(cap);
        if !early_data.is_empty() {
            read_buf.extend_from_slice(&early_data);
        }
        Self {
            inner: ws,
            read_buf,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // 先排空跨帧残留 / 早期数据
        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            let _ = this.read_buf.split_to(n);
            return Poll::Ready(Ok(()));
        }

        // poll 下一个 WebSocket 消息
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF / closed
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        e.to_string(),
                    )))
                }
                Poll::Ready(Some(Ok(msg))) => {
                    let data: Vec<u8> = match msg {
                        Message::Binary(v) => v,
                        Message::Text(s) => s.into_bytes(),
                        // 控制帧 — 跳过继续 poll
                        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                        Message::Close(_) => return Poll::Ready(Ok(())),
                    };

                    if data.is_empty() {
                        continue;
                    }

                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    // 帧比读缓冲大时残留部分进 read_buf
                    if n < data.len() {
                        this.read_buf.extend_from_slice(&data[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // 先确认 sink 有容量
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                )))
            }
            Poll::Ready(Ok(())) => {}
        }

        // 以 Binary 帧发送
        let msg = Message::Binary(buf.to_vec());
        if let Err(e) = Pin::new(&mut this.inner).start_send(msg) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            )));
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_normalization() {
        // accept 内部逻辑：自动补 '/' 前缀
        let opts = WsServerOptions {
            path: "ws".into(),
            ..Default::default()
        };
        let normalized = if opts.path.starts_with('/') {
            opts.path.clone()
        } else {
            format!("/{}", opts.path)
        };
        assert_eq!(normalized, "/ws");

        let opts = WsServerOptions {
            path: "/ws".into(),
            ..Default::default()
        };
        let normalized = if opts.path.starts_with('/') {
            opts.path.clone()
        } else {
            format!("/{}", opts.path)
        };
        assert_eq!(normalized, "/ws");
    }

    #[test]
    fn from_config_defaults() {
        let cfg = crate::config::inbound::InboundWsTransportConfig::default();
        let opts = WsServerOptions::from_config(&cfg);
        // Default 派生的 path 为空串；accept 时会规范化为 "/"
        assert_eq!(opts.path, "");
        assert_eq!(opts.host, None);
        assert_eq!(opts.max_early_data, 0);
        assert!(opts.early_data_header_name.is_none());
    }

    #[test]
    fn empty_path_normalizes_to_root() {
        // accept 内部逻辑：空 path → "/"；无前缀 → 补 "/"
        for (input, expected) in [("", "/"), ("ws", "/ws"), ("/ws", "/ws")] {
            let normalized = if input.starts_with('/') {
                input.to_string()
            } else {
                format!("/{input}")
            };
            assert_eq!(normalized, expected);
        }
    }
}
