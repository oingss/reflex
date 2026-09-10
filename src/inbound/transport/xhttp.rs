//! XHTTP (SplitHTTP) inbound 传输层（VLESS/VMess/Trojan 共用）。
//!
//! 移植自 flux-master `src/common/transport/xhttp.rs`，对齐 Xray
//! `transport/internet/splithttp` 的 packet-up 模式：
//!
//! 一个逻辑连接 = 多个独立 TCP 连接：
//!   GET  /<base>/<sessionId>        → downlink（长连接流式响应）
//!   POST /<base>/<sessionId>/<seq>  → packet-up（每包一个短连接）
//!   POST /<base>/<sessionId>        → stream-up（长连接流式上行）
//!   GET  /<base>                    → stream-one（上下行同一连接）
//!
//! 因此 session 表必须跨 TCP 连接共享（XhttpServer 为 Clone 的共享句柄）。

use anyhow::Result;
use bytes::{Buf, BytesMut};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::PollSender;
use tracing::{debug, warn};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct XhttpServerOptions {
    pub path: String,
    pub host: Option<String>,
}

impl Default for XhttpServerOptions {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
        }
    }
}

impl XhttpServerOptions {
    pub fn from_config(cfg: &crate::config::inbound::InboundXhttpTransportConfig) -> Self {
        Self {
            path: cfg.path.clone(),
            host: cfg.host.clone(),
        }
    }

    /// 对齐 Xray `Config.GetNormalizedPath`（`splithttp/config.go`）：
    ///   - 空或非 `/` 开头 → 前补 `/`
    ///   - 末尾保证有 `/`（便于 `parse_path` 切 sessionId/seq）
    ///
    /// 注意 `/` 不能被规范化成 `//`（trim 后为空串 → 规范化为 `/`）。
    pub fn normalized_path(&self) -> String {
        let mut p = self.path.trim_end_matches('/').to_string();
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        if p.is_empty() {
            p.push('/');
        }
        if !p.ends_with('/') {
            p.push('/');
        }
        p
    }
}

// ── 上行数据包 ─────────────────────────────────────────────────────────────────

enum UploadPacket {
    Chunk(bytes::Bytes),
    Packet { seq: u64, data: bytes::Bytes },
    Eof,
}

// ── Session ───────────────────────────────────────────────────────────────────

struct Session {
    /// POST handler 写上行数据
    up_tx: mpsc::Sender<UploadPacket>,
    /// GET handler 到达时取走，构造 XhttpStream 的读端
    up_rx: Option<mpsc::Receiver<UploadPacket>>,
    /// XhttpStream 写端写下行数据。
    /// GET handler 到达时 take（不再 clone）：只有当所有 down_tx 都被释放后，
    /// down_rx 才会返回 None，GET 响应才会结束（否则下行连接挂死到 TTL）。
    down_tx: Option<mpsc::Sender<bytes::Bytes>>,
    /// GET handler 到达时取走，作为 response body
    down_rx: Option<mpsc::Receiver<bytes::Bytes>>,
    /// GET 到达通知（供 TTL 任务监听）
    get_arrived: Arc<Notify>,
}

// ── XhttpServer ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct XhttpServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    cfg: XhttpServerOptions,
    sessions: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
    ready_tx: mpsc::Sender<XhttpStream>,
    ready_rx: Mutex<mpsc::Receiver<XhttpStream>>,
}

impl XhttpServer {
    pub fn new(cfg: XhttpServerOptions) -> Self {
        let (ready_tx, ready_rx) = mpsc::channel(64);
        Self {
            inner: Arc::new(ServerInner {
                cfg,
                sessions: Mutex::new(HashMap::new()),
                ready_tx,
                ready_rx: Mutex::new(ready_rx),
            }),
        }
    }

    /// 等待下一个完整的 xhttp 逻辑连接就绪，返回 XhttpStream
    pub async fn accept(&self) -> Option<XhttpStream> {
        self.inner.ready_rx.lock().await.recv().await
    }

    /// 把一个已完成 TLS/Reality 握手的流交给 hyper（立即返回，不阻塞）
    pub fn feed_tls<S>(&self, stream: S, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            serve_conn(hyper_util::rt::TokioIo::new(stream), peer, inner).await;
        });
    }
}

// ── hyper 连接 ────────────────────────────────────────────────────────────────

async fn serve_conn<IO>(io: IO, peer: SocketAddr, inner: Arc<ServerInner>)
where
    IO: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let inner = Arc::clone(&inner);
        async move {
            let resp = handle_request(req, &inner, peer).await;
            Ok::<_, std::convert::Infallible>(resp)
        }
    });
    if let Err(e) =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, svc)
            .await
    {
        debug!("[xhttp] {peer} conn closed: {e}");
    }
}

// ── Session 管理 ───────────────────────────────────────────────────────────────

async fn get_or_create_session(inner: &Arc<ServerInner>, session_id: &str) -> Arc<Mutex<Session>> {
    let mut map = inner.sessions.lock().await;
    if let Some(s) = map.get(session_id) {
        return Arc::clone(s);
    }

    // 容量 512：packet-up 模式下客户端每个 chunk 一个 POST，
    // 高并发时容量太小会导致 up_tx.send() 阻塞占用 hyper 连接
    let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(512);
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(512);
    let get_arrived = Arc::new(Notify::new());

    let session = Arc::new(Mutex::new(Session {
        up_tx,
        up_rx: Some(up_rx),
        down_tx: Some(down_tx),
        down_rx: Some(down_rx),
        get_arrived: Arc::clone(&get_arrived),
    }));
    map.insert(session_id.to_string(), Arc::clone(&session));

    // TTL：30s 内 GET 未到则清理；GET 到达后由 ResponseBody cleanup 回调负责
    let inner2 = Arc::clone(inner);
    let sid = session_id.to_string();
    tokio::spawn(async move {
        let get_timed_out = tokio::time::timeout(Duration::from_secs(30), get_arrived.notified())
            .await
            .is_err();

        if get_timed_out {
            debug!("[xhttp] session {sid} TTL expired (no GET)");
            if let Some(s) = inner2.sessions.lock().await.remove(&sid) {
                let s = s.lock().await;
                let _ = s.up_tx.send(UploadPacket::Eof).await;
            }
        }
    });

    session
}

// ── 路径解析 ───────────────────────────────────────────────────────────────────

fn parse_path(req_path: &str, base_path: &str) -> Option<(Option<String>, Option<String>)> {
    let base_no_slash = base_path.trim_end_matches('/');

    let rest = if req_path == base_no_slash || req_path == base_path {
        ""
    } else {
        let s = req_path.strip_prefix(base_path)?;
        s.trim_start_matches('/')
    };

    if rest.is_empty() {
        return Some((None, None));
    }

    let mut parts = rest.splitn(2, '/');
    let session_id = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    let seq = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    Some((session_id, seq))
}

// ── HTTP 请求处理 ──────────────────────────────────────────────────────────────

/// 对齐 Xray `internet.IsValidHTTPHost`：大小写不敏感；带端口仅比较 host 部分
fn is_valid_http_host(request: &str, config: &str) -> bool {
    let r = request.to_lowercase();
    let c = config.to_lowercase();
    if let Some((h, _)) = r.rsplit_once(':') {
        // IPv6 字面量 `[::1]:443` → h="[::1]" 仍正确
        h == c
    } else {
        r == c
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(expected) = &inner.cfg.host {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_valid_http_host(req_host, expected) {
            warn!("[xhttp] {peer} bad host: {req_host} != {expected}");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref());
        }
    }

    if *req.method() == Method::OPTIONS {
        return cors_ok(origin.as_deref());
    }

    let base_path = inner.cfg.normalized_path();
    let req_path = req.uri().path().to_string();

    let (session_id, seq_str) = match parse_path(&req_path, &base_path) {
        Some(p) => p,
        None => {
            warn!("[xhttp] {peer} bad path: {req_path} (base={base_path})");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref());
        }
    };

    debug!(
        "[xhttp] {peer} {} session={session_id:?} seq={seq_str:?}",
        req.method()
    );

    let is_downlink = *req.method() == Method::GET && seq_str.is_none();
    if is_downlink {
        handle_get(req, inner, session_id.as_deref(), peer, origin).await
    } else {
        handle_post(
            req,
            inner,
            session_id.as_deref(),
            seq_str.as_deref(),
            peer,
            origin,
        )
        .await
    }
}

/// GET handler：downlink 或 stream-one
async fn handle_get(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
) -> Response<ResponseBody> {
    // ── stream-one：无 sessionId ────────────────────────────────────────────
    if session_id.is_none() {
        let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(64);
        let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(64);

        let mut body = req.into_body();
        tokio::spawn(async move {
            loop {
                match body.frame().await {
                    None => break,
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        debug!("[xhttp] {peer} stream-one up: {e}");
                        break;
                    }
                }
            }
            let _ = up_tx.send(UploadPacket::Eof).await;
        });

        let xhs = XhttpStream::new(up_rx, down_tx);
        let _ = inner.ready_tx.send(xhs).await;

        return downlink_response(down_rx, origin.as_deref(), None);
    }

    // ── stream-down：有 sessionId ───────────────────────────────────────────
    let sid = session_id.unwrap();
    let session_arc = get_or_create_session(inner, sid).await;
    let mut session = session_arc.lock().await;

    let up_rx = match session.up_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} duplicate GET for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };
    let down_rx = match session.down_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} down_rx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };
    // take（不是 clone）：XhttpStream 释放 down_tx 后所有 sender 消失，
    // down_rx 才会返回 None，GET 响应才能正常结束
    let down_tx = match session.down_tx.take() {
        Some(t) => t,
        None => {
            warn!("[xhttp] {peer} down_tx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };

    // 通知 TTL 任务：GET 已到达
    session.get_arrived.notify_one();
    drop(session);
    // 不从 map 移除 session：up_tx 留在 session 里，后续 POST 仍可拿到

    let xhs = XhttpStream::new(up_rx, down_tx);
    let _ = inner.ready_tx.send(xhs).await;

    // cleanup：GET 响应流结束时移除 session（对齐 Xray hub.go 的 defer delete）
    let inner_clone = Arc::clone(inner);
    let sid_owned = sid.to_string();
    let cleanup: Option<Box<dyn FnOnce() + Send + 'static>> = Some(Box::new(move || {
        tokio::spawn(async move {
            if let Some(s) = inner_clone.sessions.lock().await.remove(&sid_owned) {
                debug!("[xhttp] session removed on GET response end");
                let _ = s.lock().await.up_tx.send(UploadPacket::Eof).await;
            }
        });
    }));

    downlink_response(down_rx, origin.as_deref(), cleanup)
}

/// POST/PUT handler：接收上行数据
async fn handle_post(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    seq_str: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
) -> Response<ResponseBody> {
    let up_tx = if let Some(sid) = session_id {
        let session_arc = get_or_create_session(inner, sid).await;
        let session = session_arc.lock().await;
        session.up_tx.clone()
    } else {
        warn!("[xhttp] {peer} POST without sessionId");
        return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
    };

    match seq_str {
        None => {
            // stream-up
            let mut body = req.into_body();
            tokio::spawn(async move {
                loop {
                    match body.frame().await {
                        None => break,
                        Some(Ok(frame)) => {
                            if let Ok(data) = frame.into_data() {
                                if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Err(e)) => {
                            debug!("[xhttp] stream-up: {e}");
                            break;
                        }
                    }
                }
                let _ = up_tx.send(UploadPacket::Eof).await;
            });
            // 对齐 Xray hub.go：stream-up 响应设置 X-Accel-Buffering / Cache-Control
            return stream_up_response(origin.as_deref());
        }
        Some(s) => {
            // packet-up：同步收完 body 再返回 200（否则 hyper 可能先处理下一个
            // pipelined 请求，破坏 HTTP/1.1 分帧）
            let seq: u64 = match s.parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!("[xhttp] {peer} invalid seq: {s}");
                    return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
                }
            };
            let body = req.into_body();
            let had_body = match body.collect().await {
                Ok(c) => {
                    let bytes = c.to_bytes();
                    let had = !bytes.is_empty();
                    let _ = up_tx
                        .send(UploadPacket::Packet { seq, data: bytes })
                        .await;
                    had
                }
                Err(e) => {
                    debug!("[xhttp] {peer} packet-up collect: {e}");
                    return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
                }
            };
            // 对齐 Xray hub.go：无 body 的 POST 显式 no-store 防中间件缓存
            if !had_body {
                return packet_up_response_no_body(origin.as_deref());
            }
        }
    }

    plain_with_cors(StatusCode::OK, origin.as_deref())
}

/// 对齐 Xray `Config.WriteResponseHeader`：无 Origin → `*`；有 Origin → 回写
fn cors_origin_header(
    builder: http::response::Builder,
    origin: Option<&str>,
) -> http::response::Builder {
    match origin {
        Some(o) => builder
            .header("Access-Control-Allow-Origin", o)
            .header("Access-Control-Allow-Credentials", "true")
            .header("Vary", "Origin"),
        None => builder.header("Access-Control-Allow-Origin", "*"),
    }
}

fn downlink_response(
    down_rx: mpsc::Receiver<bytes::Bytes>,
    origin: Option<&str>,
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        // text/event-stream 让 nginx/CDN 关闭缓冲（对齐 Xray hub.go）
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-store")
        .header("X-Accel-Buffering", "no");
    let builder = cors_origin_header(builder, origin);
    builder
        .body(ResponseBody::Stream {
            rx: down_rx,
            cleanup,
        })
        .unwrap()
}

/// stream-up 响应
fn stream_up_response(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("X-Accel-Buffering", "no")
        .header("Cache-Control", "no-store");
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

/// packet-up 无 body 响应
fn packet_up_response_no_body(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store");
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

fn plain_with_cors(code: StatusCode, origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder().status(code);
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

fn cors_ok(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder().status(StatusCode::OK);
    let builder = cors_origin_header(builder, origin);
    builder
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(ResponseBody::Empty)
        .unwrap()
}

// ── Response body ─────────────────────────────────────────────────────────────

enum ResponseBody {
    Empty,
    Stream {
        rx: mpsc::Receiver<bytes::Bytes>,
        /// 响应流结束（poll_frame 返回 None）时执行一次，清理 session
        cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
    },
}

impl http_body::Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ResponseBody::Empty => Poll::Ready(None),
            ResponseBody::Stream { rx, cleanup } => match rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => {
                    if let Some(c) = cleanup.take() {
                        c();
                    }
                    Poll::Ready(None)
                }
                Poll::Ready(Some(d)) => Poll::Ready(Some(Ok(http_body::Frame::data(d)))),
            },
        }
    }
}

// ── XhttpStream ───────────────────────────────────────────────────────────────

struct PktQueue {
    heap: BinaryHeap<Reverse<PktEntry>>,
    next_seq: u64,
    leftover: BytesMut,
}

#[derive(Eq, PartialEq)]
struct PktEntry {
    seq: u64,
    data: bytes::Bytes,
}

impl Ord for PktEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq.cmp(&other.seq)
    }
}
impl PartialOrd for PktEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct XhttpStream {
    up_rx: mpsc::Receiver<UploadPacket>,
    pkt_queue: PktQueue,
    stream_buf: BytesMut,
    eof: bool,
    down_tx: PollSender<bytes::Bytes>,
}

impl XhttpStream {
    fn new(up_rx: mpsc::Receiver<UploadPacket>, down_tx: mpsc::Sender<bytes::Bytes>) -> Self {
        Self {
            up_rx,
            pkt_queue: PktQueue {
                heap: BinaryHeap::new(),
                next_seq: 0,
                leftover: BytesMut::new(),
            },
            stream_buf: BytesMut::new(),
            eof: false,
            down_tx: PollSender::new(down_tx),
        }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pkt_queue.leftover.is_empty() {
                let n = this.pkt_queue.leftover.len().min(buf.remaining());
                buf.put_slice(&this.pkt_queue.leftover[..n]);
                this.pkt_queue.leftover.advance(n);
                return Poll::Ready(Ok(()));
            }
            if !this.stream_buf.is_empty() {
                let n = this.stream_buf.len().min(buf.remaining());
                buf.put_slice(&this.stream_buf[..n]);
                this.stream_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(Reverse(top)) = this.pkt_queue.heap.peek() {
                if top.seq == this.pkt_queue.next_seq {
                    let Reverse(entry) = this.pkt_queue.heap.pop().unwrap();
                    let n = entry.data.len().min(buf.remaining());
                    buf.put_slice(&entry.data[..n]);
                    if n < entry.data.len() {
                        this.pkt_queue.leftover.extend_from_slice(&entry.data[n..]);
                    }
                    this.pkt_queue.next_seq += 1;
                    return Poll::Ready(Ok(()));
                }
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.up_rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(pkt)) => match pkt {
                    UploadPacket::Chunk(data) => {
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            this.stream_buf.extend_from_slice(&data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    UploadPacket::Packet { seq, data } => {
                        this.pkt_queue.heap.push(Reverse(PktEntry { seq, data }));
                    }
                    UploadPacket::Eof => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.down_tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "xhttp downlink closed",
            ))),
            Poll::Ready(Ok(())) => {
                match this.down_tx.send_item(bytes::Bytes::copy_from_slice(buf)) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(_) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "xhttp downlink closed",
                    ))),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // close() 释放 PollSender 持有的 down_tx；session 已 take，所有 sender
        // 消失后 down_rx 返回 None → GET 响应结束 → cleanup 移除 session。
        // 不关闭的话远端断开后 GET 响应流永远不结束，客户端下行挂死。
        self.down_tx.close();
        Poll::Ready(Ok(()))
    }
}

// ── 单元测试 ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalized_path() {
        // 默认 `/` 不能被规范化成 `//`
        assert_eq!(
            XhttpServerOptions::default().normalized_path(),
            "/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "".into(),
                host: None,
            }
            .normalized_path(),
            "/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "/vless".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "/vless//".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
        assert_eq!(
            XhttpServerOptions {
                path: "vless".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
    }

    #[test]
    fn test_parse_path() {
        // 默认 base `/`
        assert_eq!(parse_path("/", "/"), Some((None, None)));
        assert_eq!(parse_path("/sid", "/"), Some((Some("sid".into()), None)));
        assert_eq!(
            parse_path("/sid/42", "/"),
            Some((Some("sid".into()), Some("42".into())))
        );

        let base = "/vless/";
        assert_eq!(parse_path("/vless", base), Some((None, None)));
        assert_eq!(parse_path("/vless/", base), Some((None, None)));

        let sid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            parse_path(&format!("/vless/{sid}"), base),
            Some((Some(sid.into()), None))
        );
        assert_eq!(
            parse_path(&format!("/vless/{sid}/42"), base),
            Some((Some(sid.into()), Some("42".into())))
        );
        assert_eq!(parse_path("/other", base), None);
    }

    #[test]
    fn test_is_valid_http_host() {
        assert!(is_valid_http_host("Example.com", "example.com"));
        assert!(is_valid_http_host("example.com:443", "example.com"));
        assert!(is_valid_http_host("[::1]:443", "[::1]"));
        assert!(!is_valid_http_host("evil.com", "example.com"));
    }
}
