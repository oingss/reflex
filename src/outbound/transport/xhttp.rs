use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{atomic::Ordering, Arc},
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header::{HeaderName, HeaderValue, HOST},
    Method, Request, StatusCode, Uri,
};
use hyper_util::client::legacy::Client;
use portable_atomic::AtomicI64;
use rand::Rng;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use tower::Service;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::outbound::{TlsConfig, XhttpTransportConfig};
use crate::outbound::{apply_mark_to_tcp, set_tcp_opts};

// ── 公共接口 ─────────────────────────────────────────────────────────────────

/// 解析传输模式，与 Xray `dialer.go:362-371` 对齐。
///
/// - `"packet-up"` / `"stream-up"` / `"stream-one"` → 原样返回
/// - `None` / `""` / `"auto"` → 默认 `"packet-up"`
///
/// 注意：Xray 在 REALITY 场景下默认选 `"stream-one"`，但 reflex 的 `TlsConfig`
/// 不携带 reality 信息（VlessTlsConfig → TlsConfig 转换时丢弃），
/// 因此无法在此处自动检测 REALITY。使用 REALITY+xhttp 时需显式配置
/// `"mode": "stream-one"`。
fn resolve_mode<'a>(mode: Option<&'a str>, _tls: Option<&TlsConfig>) -> &'a str {
    match mode {
        Some(m) if !m.is_empty() && m != "auto" => m,
        _ => "packet-up",
    }
}

/// 建立一条 XHTTP 双工流。
pub async fn connect(
    server: &str,
    port: u16,
    cfg: &XhttpTransportConfig,
    tls: Option<&TlsConfig>,
    extra_headers: &HashMap<String, String>,
    routing_mark: u32,
    resolver: Option<Arc<crate::dns::DnsResolver>>,
) -> anyhow::Result<XhttpStream> {
    let tls_enabled = tls.is_some_and(|t| t.enabled);
    let scheme = if tls_enabled { "https" } else { "http" };

    let host = cfg
        .host
        .as_deref()
        .or_else(|| tls.and_then(|t| t.server_name.as_deref()))
        .unwrap_or(server);

    let raw_path = cfg.path.as_deref().unwrap_or("/");
    let (path, query) = split_path_query(raw_path);
    let base_url = format!("{scheme}://{server}:{port}{path}");

    debug!(
        server,
        port,
        tls_enabled,
        host,
        %path,
        %query,
        raw_path = raw_path,
        sni = ?tls.and_then(|t| t.server_name.as_deref()),
        insecure = tls.is_some_and(|t| t.insecure),
        "xhttp config resolved"
    );

    let client = build_http_client(tls, cfg, routing_mark, resolver)?;

    // 模式选择，与 Xray dialer.go:362-371 完全对齐：
    //   mode == "" || mode == "auto" →
    //     默认 "packet-up"；若使用 REALITY → "stream-one"。
    //   旧实现：直接 unwrap_or("packet-up")，不处理 "auto"，
    //   也不在 REALITY 场景自动选 stream-one，导致服务端（Xray/sing-box
    //   在 REALITY 下默认期望 stream-one）拒绝或行为异常。
    let mode = resolve_mode(cfg.mode.as_deref(), tls);

    let session_id = if mode != "stream-one" {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    debug!(mode, %base_url, ?session_id, "xhttp connecting");

    let mut headers = cfg.headers.clone();
    for (k, v) in extra_headers {
        headers.entry(k.clone()).or_insert_with(|| v.clone());
    }
    headers
        .entry("Host".to_string())
        .or_insert_with(|| host.to_string());

    let shared = Arc::new(XhttpShared {
        client,
        base_url,
        query,
        session_id,
        headers,
        seq: AtomicI64::new(0),
        // 与 Xray config.go:139-148 对齐：默认 1_000_000。
        // Xray 使用 RangeConfig（From/To 随机），reflex 当前只支持单值，
        // 取用户配置或默认值。
        max_post_bytes: cfg.sc_max_each_post_bytes.unwrap_or(1_000_000) as usize,
        // 与 Xray config.go:150-159 对齐：默认 30ms。
        // 旧实现默认 0（无间隔），高频 POST 可能触发服务端限流。
        // Xray 默认 RangeConfig{From:30, To:30}。
        min_post_interval_ms: cfg.sc_min_posts_interval_ms.unwrap_or(30),
        uplink_method: cfg
            .uplink_http_method
            .clone()
            .unwrap_or_else(|| "POST".to_string()),
        no_grpc_header: cfg.no_grpc_header,
    });

    match mode {
        "stream-one" => connect_stream_one(shared).await,
        "stream-up" => connect_stream_up_down(shared).await,
        _ => connect_packet_up(shared).await,
    }
}

// ── 自定义 Connector（打 SO_MARK）────────────────────────────────────────────

/// 在 TCP connect 完成后立即设置 SO_MARK，然后可选地包一层 TLS。
#[derive(Clone)]
struct MarkedConnector {
    mark: u32,
    tls: Option<Arc<rustls::ClientConfig>>,
    /// 用于解析连接目标域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<crate::dns::DnsResolver>>,
    /// 覆盖 TLS SNI 和证书校验名。当 server 字段是 IP 但证书签发给域名时
    /// （例如 vless+xhttp 配置 `server: "1.2.3.4"` + `tls.server_name: "example.com"`），
    /// 必须显式指定 SNI 为域名，否则 rustls 会按 IP 校验证书而失败。
    /// None 时回退到 URI host。
    server_name: Option<String>,
}

impl MarkedConnector {
    fn new(
        mark: u32,
        tls_cfg: Option<Arc<rustls::ClientConfig>>,
        resolver: Option<Arc<crate::dns::DnsResolver>>,
        server_name: Option<String>,
    ) -> Self {
        Self {
            mark,
            tls: tls_cfg,
            resolver,
            server_name,
        }
    }
}

/// hyper 连接类型：裸 TCP 或 TLS over TCP
#[allow(clippy::large_enum_variant)]
pub enum MaybeHttps {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttps::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttps::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeHttps::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeHttps::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttps::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl hyper::rt::Read for MaybeHttps {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // hyper 的 ReadBufCursor 内部是 MaybeUninit<u8>，不能强转为 &[u8]：
        // 未初始化字节被当作 u8 属于 UB（Rust 的初始化模型禁止）。
        // 改用 tokio::io::ReadBuf::uninit 接受未初始化内存，安全桥接。
        // 用块作用域让 rb 的可变借用（来自 buf.as_mut()）在 advance 前释放。
        let n = {
            // SAFETY: as_mut 返回未初始化的 spare 内存，我们只把它传给
            // ReadBuf::uninit（不读取其内容），poll_read 填充后按实际填充
            // 字节数 advance，不访问未初始化部分。
            let spare = unsafe { buf.as_mut() };
            let mut rb = ReadBuf::uninit(spare);
            match tokio::io::AsyncRead::poll_read(self, cx, &mut rb) {
                Poll::Ready(Ok(())) => rb.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        };
        // SAFETY: n 为 poll_read 实际写入 rb 的字节数，advance 不超过已初始化范围
        unsafe { buf.advance(n) };
        Poll::Ready(Ok(()))
    }
}

impl hyper::rt::Write for MaybeHttps {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(self, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(self, cx)
    }
}

impl hyper_util::client::legacy::connect::Connection for MaybeHttps {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}

impl Service<Uri> for MarkedConnector {
    type Response = MaybeHttps;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = anyhow::Result<MaybeHttps>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<anyhow::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mark = self.mark;
        let tls_cfg = self.tls.clone();
        let resolver = self.resolver.clone();
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let host = uri
                .host()
                .ok_or_else(|| anyhow::anyhow!("xhttp: missing host in URI"))?;
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });

            debug!(uri_host = host, port, "xhttp connector: dialing");

            // DNS 解析（优先走 dns.proxy_domain_resolver，未注入则回退系统 DNS）
            let addr = crate::outbound::resolve_server_addr(host, port, resolver.as_ref())
                .await
                .map_err(|e| anyhow::anyhow!("xhttp: DNS failed for {host}: {e}"))?;

            debug!(%addr, "xhttp connector: resolved");

            // TCP connect → 打 SO_MARK → 设 TCP 选项
            let tcp = crate::outbound::connect_tcp_interface(addr).await?;
            apply_mark_to_tcp(&tcp, mark)?;
            set_tcp_opts(&tcp)?;

            debug!(local = ?tcp.local_addr(), peer = ?tcp.peer_addr(), mark, "xhttp connector: TCP connected");

            if let Some(tls) = tls_cfg {
                // SNI 优先用 tls.server_name（处理 server 字段是 IP、证书签发给域名的场景）。
                // 没有显式 server_name 时回退到 URI host（保留原行为）。
                let sni_str = server_name.as_deref().unwrap_or(host);
                let sni = rustls::pki_types::ServerName::try_from(sni_str.to_string())
                    .map_err(|e| anyhow::anyhow!("xhttp: invalid SNI {sni_str}: {e}"))?;
                debug!(
                    sni = sni_str,
                    uri_host = host,
                    "xhttp connector: starting TLS handshake"
                );
                let connector = tokio_rustls::TlsConnector::from(tls);
                let tls_stream = connector
                    .connect(sni, tcp)
                    .await
                    .map_err(|e| anyhow::anyhow!("xhttp: TLS handshake failed: {e}"))?;
                debug!(sni = sni_str, "xhttp connector: TLS handshake ok");
                return Ok(MaybeHttps::Tls(tls_stream));
            }

            Ok(MaybeHttps::Plain(tcp))
        })
    }
}

// ── 类型别名：带 mark 的 hyper Client ────────────────────────────────────────

type XhttpClient = Client<MarkedConnector, XhttpBody>;

/// 上行 body 类型：可以是空 body、固定字节、或流式 channel
enum XhttpBody {
    Empty(Empty<Bytes>),
    Full(Full<Bytes>),
    #[allow(clippy::type_complexity)]
    Stream(
        StreamBody<
            futures_util::stream::Map<
                ReceiverStream<Bytes>,
                fn(Bytes) -> Result<Frame<Bytes>, io::Error>,
            >,
        >,
    ),
}

impl hyper::body::Body for XhttpBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            XhttpBody::Empty(b) => Pin::new(b).poll_frame(cx).map_err(|_| unreachable!()),
            XhttpBody::Full(b) => Pin::new(b).poll_frame(cx).map_err(|_| unreachable!()),
            XhttpBody::Stream(b) => Pin::new(b).poll_frame(cx),
        }
    }
}

fn stream_body(rx: mpsc::Receiver<Bytes>) -> XhttpBody {
    fn wrap(b: Bytes) -> Result<Frame<Bytes>, io::Error> {
        Ok(Frame::data(b))
    }
    XhttpBody::Stream(StreamBody::new(
        ReceiverStream::new(rx).map(wrap as fn(Bytes) -> Result<Frame<Bytes>, io::Error>),
    ))
}

// ── 内部共享状态 ──────────────────────────────────────────────────────────────

struct XhttpShared {
    client: XhttpClient,
    base_url: String,
    /// URL query string（从 `path` 中 `?` 后分离），与 Xray
    /// `GetNormalizedQuery` 对齐。session_id/seq 追加到 path，
    /// query 追加到 URL 末尾。
    query: String,
    session_id: Option<String>,
    headers: HashMap<String, String>,
    seq: AtomicI64,
    max_post_bytes: usize,
    min_post_interval_ms: u64,
    uplink_method: String,
    /// 禁用 `Content-Type: application/grpc` 头，与 Xray `NoGRPCHeader` 对齐。
    /// Xray config.go:325-327：stream-up/one（有 body 时）默认设置 grpc 头，
    /// 服务端据此识别为流式上行；no_grpc_header=true 时跳过。
    no_grpc_header: bool,
}

impl XhttpShared {
    fn apply_headers(&self, mut req: Request<XhttpBody>) -> Request<XhttpBody> {
        for (k, v) in &self.headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                req.headers_mut().insert(name, val);
            }
        }
        req
    }

    fn stream_url(&self) -> String {
        // Xray xhttp 默认 SessionIDPlacement = PlacementPath，session_id 追加到路径末尾。
        // base_url 已通过 normalize_path 保证以 '/' 结尾，直接拼接即可。
        // query 追加到 URL 末尾（与 Xray requestURL.RawQuery 对齐）。
        // 与 Xray config.go:appendToPath 行为一致。
        match &self.session_id {
            Some(sid) => append_query(&format!("{}{}", self.base_url, sid), &self.query),
            None => append_query(&self.base_url, &self.query),
        }
    }

    fn packet_url(&self, seq: i64) -> String {
        // Xray xhttp 默认 SeqPlacement = PlacementPath，seq 追加到 session_id 之后。
        // 格式：{base_url}{session_id}/{seq}?{query}
        match &self.session_id {
            Some(sid) => append_query(
                &format!("{}{}/{}", self.base_url, sid, seq),
                &self.query,
            ),
            None => append_query(&self.base_url, &self.query),
        }
    }

    fn build_request(
        &self,
        method: &Method,
        url: &str,
        body: XhttpBody,
        has_body: bool,
    ) -> anyhow::Result<Request<XhttpBody>> {
        let uri: Uri = url.parse()?;
        let host = uri.host().unwrap_or("").to_string();
        debug!(%method, %url, host = %host, "xhttp: building HTTP request");
        let req = Request::builder()
            .method(method)
            .uri(uri.clone())
            .header(HOST, &host)
            .body(body)?;
        // apply custom headers（覆盖同名 header）
        let mut req = self.apply_headers(req);

        // 浏览器伪装头：与 Xray `GetRequestHeader` → `TryDefaultHeadersWith(header, "fetch")`
        // 对齐。用户未设置 `User-Agent` 时，注入 Chrome fetch 风格默认头
        // （User-Agent、Sec-CH-UA、Sec-Fetch-*、Accept、Cache-Control、Priority 等），
        // 使流量特征与浏览器 fetch 请求一致，避免被 DPI 识别为非浏览器流量。
        // 旧实现完全缺失这些头，hyper 默认不发送 User-Agent，流量特征明显。
        apply_default_masquerade(&mut req);

        // Content-Type: application/grpc
        // 与 Xray config.go:325-327 对齐：
        //   if request.Body != nil && !c.NoGRPCHeader { // stream-up/one
        //       request.Header.Set("Content-Type", "application/grpc")
        //   }
        // 有 body 的请求（stream-one、stream-up）默认设置 grpc 头，
        // 服务端据此识别为流式上行。no_grpc_header=true 时跳过。
        // 旧实现完全缺失此头，服务端可能无法正确识别 stream-up/one 请求。
        if !self.no_grpc_header && has_body {
            req.headers_mut()
                .insert("content-type", HeaderValue::from_static("application/grpc"));
        }

        // XPadding：Xray xhttp 默认要求每个请求带 100-1000 字节 padding，
        // 放在 Referer 头的 query string 里（key=x_padding）。
        // 参考 Xray xpadding.go:
        //   - GetNormalizedXPaddingBytes 默认 {From:100, To:1000}
        //   - ApplyXPaddingToHeader: PlacementQueryInHeader, header="Referer", key="x_padding"
        //   - GeneratePadding: 默认方法生成全 'X' 字符串
        //   - IsPaddingValid: 空 padding 直接返回 false → 服务端返回 400
        //
        // Referer URL 使用 base path（不含 session_id/seq），与 Xray 的填充顺序
        // 一致：Xray 先 ApplyXPaddingToRequest（此时 URL path 仅为 normalized path），
        // 后 ApplyMetaToRequest（追加 session/seq 到 path）。旧实现用完整 URL path
        // （含 session/seq）构造 Referer，导致 Referer path 与 Xray 不一致。
        // padding 必须在 apply_headers 之后设置，确保不被用户自定义 header 覆盖。
        let mut rng = rand::thread_rng();
        let padding_len: usize = rng.gen_range(100..=1000);
        let padding = generate_padding(padding_len);
        let scheme = uri.scheme_str().unwrap_or("https");
        // Referer host 使用 Host 头值（域名），而非连接 IP（server），
        // 与 Xray requestURL.Host = transportConfiguration.Host 一致。
        let referer_host = self
            .headers
            .get("Host")
            .map(|s| s.as_str())
            .or_else(|| uri.authority().map(|a| a.as_str()))
            .unwrap_or("");
        // base_path 从 base_url 提取（不含 session_id/seq），与 Xray 填充顺序
        // 一致：padding 在 ApplyMetaToRequest（追加 session/seq）之前应用。
        let base_path = self
            .base_url
            .parse::<Uri>()
            .map(|u| u.path().to_string())
            .unwrap_or_else(|_| "/".to_string());
        let referer_value = format!("{scheme}://{referer_host}{base_path}?x_padding={padding}");
        if let Ok(val) = HeaderValue::from_str(&referer_value) {
            req.headers_mut().insert("referer", val);
        }
        debug!(padding_len, "xhttp: applied XPadding to Referer header");

        Ok(req)
    }
}

// ── 模式 1：stream-one ────────────────────────────────────────────────────────

async fn connect_stream_one(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let url = shared.stream_url();
    let method = parse_method(&shared.uplink_method);
    let req = shared.build_request(&method, &url, stream_body(body_rx), true)?;
    debug!("xhttp stream-one: sending request");
    let resp = shared.client.request(req).await?;
    debug!(status = %resp.status(), "xhttp stream-one: response received");
    check_status(resp.status(), "stream-one")?;
    let read_half = RespBodyReader::new(resp.into_body());
    debug!("xhttp stream-one: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 2：stream-up + 独立 GET 下行 ────────────────────────────────────────

async fn connect_stream_up_down(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(
        &Method::GET,
        &down_url,
        XhttpBody::Empty(Empty::new()),
        false,
    )?;
    debug!("xhttp stream-up: sending GET download request");
    let down_resp = shared.client.request(req).await?;
    debug!(status = %down_resp.status(), "xhttp stream-up: download response received");
    check_status(down_resp.status(), "stream-down")?;

    // 关闭信号：上传 POST 失败时通知下行读取器返回错误。
    // 与 Xray client.go:86-92 对齐：uploadOnly 的 OpenStream 在失败/非200 时
    // 调用 wrc.Close()，使 download 侧的 Read 返回 io.ErrClosedPipe。
    let close_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let read_half =
        RespBodyReader::with_close_flag(down_resp.into_body(), Some(close_flag.clone()));

    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    let up_url = shared.stream_url();
    let method = parse_method(&shared.uplink_method);
    let req = shared.build_request(&method, &up_url, stream_body(body_rx), true)?;
    {
        let client = shared.client.clone();
        tokio::spawn(async move {
            debug!("xhttp stream-up: sending POST upload request (background)");
            let failed = match client.request(req).await {
                Ok(resp) => {
                    debug!(status = %resp.status(), "xhttp stream-up: upload response received");
                    // 检查 HTTP 状态码，4xx/5xx 表示服务端拒绝上行
                    match check_status(resp.status(), "stream-up") {
                        Ok(()) => false,
                        Err(e) => {
                            warn!("xhttp stream-up POST rejected: {e}");
                            true
                        }
                    }
                }
                Err(e) => {
                    warn!("xhttp stream-up POST failed: {e}");
                    true
                }
            };
            if failed {
                // 通知下行读取器：上行已断开，关闭连接。
                // 旧实现仅 warn 日志，下行流保持 open，调用方误以为连接正常，
                // 但数据实际已无法上行 → 连接假死。
                close_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            }
        });
    }

    debug!("xhttp stream-up: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Stream(body_tx)))
}

// ── 模式 3：packet-up（默认）─────────────────────────────────────────────────

async fn connect_packet_up(shared: Arc<XhttpShared>) -> anyhow::Result<XhttpStream> {
    let down_url = shared.stream_url();
    let req = shared.build_request(
        &Method::GET,
        &down_url,
        XhttpBody::Empty(Empty::new()),
        false,
    )?;
    debug!("xhttp packet-up: sending GET download request");
    let down_resp = shared.client.request(req).await?;
    debug!(status = %down_resp.status(), "xhttp packet-up: download response received");
    check_status(down_resp.status(), "packet-up/stream-down")?;
    let read_half = RespBodyReader::new(down_resp.into_body());

    let (up_tx, mut up_rx) = mpsc::channel::<Bytes>(128);
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut last_post = std::time::Instant::now();
            debug!(
                max_post_bytes = shared.max_post_bytes,
                min_post_interval_ms = shared.min_post_interval_ms,
                "xhttp packet-up: upload loop started"
            );

            // 批处理缓冲区：与 Xray dialer.go:490-568 的 pipe 机制对齐。
            //
            // Xray 使用 size-limited pipe：多个 Write 调用积累在 pipe 中，
            // 读循环通过 ReadMultiBuffer 一次性读出所有已缓冲数据，
            // 然后按 maxUploadSize 拆分成多个 POST。这样多个小写
            // （如 TLS 握手、VLESS 头）被合并为一个大 POST，大幅提升带宽。
            //
            // 旧 reflex 实现：每个 channel 消息单独发一个 POST，
            // 小数据包（几十字节）各自成帧 → POST 请求数爆炸，带宽极低。
            //
            // 本实现：从 channel 攒数据到 buffer，直到：
            //   1. buffer 达到 max_post_bytes（满了，必须发），或
            //   2. channel 暂时无数据（try_recv 失败），立即发送已缓冲的数据
            //      （不等待攒满，避免延迟——对齐 Xray ReadMultiBuffer 行为）。
            while let Some(first_chunk) = up_rx.recv().await {
                let mut buffer = BytesMut::new();
                buffer.extend_from_slice(&first_chunk);

                // 尝试攒更多数据，直到达到 max_post_bytes 或 channel 暂时为空
                while buffer.len() < shared.max_post_bytes {
                    match up_rx.try_recv() {
                        Ok(more) => {
                            buffer.extend_from_slice(&more);
                        }
                        Err(_) => {
                            // channel 暂时无数据，立即发送已缓冲的内容
                            break;
                        }
                    }
                }

                // 按 max_post_bytes 拆分发送（与 Xray buf.SplitSize 对齐）
                let mut remaining = buffer.freeze();
                while !remaining.is_empty() {
                    let payload: Bytes = if remaining.len() > shared.max_post_bytes {
                        let split = shared.max_post_bytes;
                        let mut tail = remaining.split_off(split);
                        std::mem::swap(&mut tail, &mut remaining);
                        tail
                    } else {
                        std::mem::take(&mut remaining)
                    };

                    // POST 间隔控制，与 Xray dialer.go:536-538 对齐
                    if shared.min_post_interval_ms > 0 {
                        let elapsed = last_post.elapsed().as_millis() as u64;
                        if elapsed < shared.min_post_interval_ms {
                            tokio::time::sleep(tokio::time::Duration::from_millis(
                                shared.min_post_interval_ms - elapsed,
                            ))
                            .await;
                        }
                    }

                    // 与 Xray dialer.go:547-565 对齐：POST 异步发送，
                    // 不等待完整响应即可发送下一个 chunk。
                    // Xray 用 goroutine + WroteRequest 信号实现：只等请求
                    // 写入完成（不等响应），立即继续下一个 POST。
                    // reflex 使用 tokio::spawn 实现同等语义：POST 在后台
                    // 发送，主循环立即继续处理下一个 chunk。
                    let shared_clone = shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) = post_packet(&shared_clone, payload).await {
                            warn!("xhttp packet-up POST error: {e}");
                        }
                    });

                    last_post = std::time::Instant::now();
                }
            }
            debug!("xhttp packet-up: upload channel closed, upload loop exiting");
        });
    }

    debug!("xhttp packet-up: stream established");
    Ok(XhttpStream::new(read_half, XhttpWriter::Packet(up_tx)))
}

async fn post_packet(shared: &XhttpShared, payload: Bytes) -> anyhow::Result<()> {
    let seq = shared.seq.fetch_add(1, Ordering::Relaxed);
    let url = shared.packet_url(seq);
    let method = parse_method(&shared.uplink_method);
    let payload_len = payload.len();
    let req = shared.build_request(&method, &url, XhttpBody::Full(Full::new(payload)), false)?;
    debug!(seq, payload_len, "xhttp packet-up: POST upload");
    let resp = shared.client.request(req).await?;
    debug!(seq, status = %resp.status(), "xhttp packet-up: POST response");
    check_status(resp.status(), &format!("packet POST {seq}"))
}

// ── 下行响应体读取器 ──────────────────────────────────────────────────────────

struct RespBodyReader {
    rx: mpsc::Receiver<io::Result<Bytes>>,
    current: Bytes,
    /// 可选的关闭信号：当上行流（stream-up POST）失败时设置，
    /// 使后续 poll_read 返回 ConnectionReset 错误，通知调用方连接已断开。
    /// 与 Xray client.go:86-92 对齐：uploadOnly 的 OpenStream 在失败/非200 时
    /// 调用 wrc.Close()，使 download 侧的 Read 返回 io.ErrClosedPipe。
    close_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl RespBodyReader {
    fn new(body: Incoming) -> Self {
        Self::with_close_flag(body, None)
    }

    fn with_close_flag(
        body: Incoming,
        close_flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut stream = body;
            let mut total_bytes = 0u64;
            let mut frame_count = 0u64;
            loop {
                match stream.frame().await {
                    None => {
                        debug!(
                            total_bytes,
                            frame_count, "xhttp download: stream ended (no more frames)"
                        );
                        break;
                    }
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            frame_count += 1;
                            total_bytes += data.len() as u64;
                            if tx.send(Ok(data)).await.is_err() {
                                debug!(
                                    total_bytes,
                                    frame_count, "xhttp download: consumer dropped, stopping"
                                );
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        warn!(
                            error = %e,
                            total_bytes,
                            frame_count,
                            "xhttp download: frame error"
                        );
                        let _ = tx
                            .send(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))
                            .await;
                        break;
                    }
                }
            }
        });
        Self {
            rx,
            current: Bytes::new(),
            close_flag,
        }
    }
}

impl AsyncRead for RespBodyReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // 检查上行流是否已失败（stream-up 模式）
        if let Some(flag) = &this.close_flag {
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "xhttp: upload stream failed, closing download",
                )));
            }
        }
        if !this.current.is_empty() {
            let n = buf.remaining().min(this.current.len());
            buf.put_slice(&this.current[..n]);
            this.current = this.current.slice(n..);
            return Poll::Ready(Ok(()));
        }
        match this.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(e)),
            Poll::Ready(Some(Ok(chunk))) => {
                if chunk.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.current = chunk.slice(n..);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

// ── XhttpStream：对外暴露的双工流 ─────────────────────────────────────────────

pub struct XhttpStream {
    reader: RespBodyReader,
    writer: XhttpWriter,
}

enum XhttpWriter {
    Stream(mpsc::Sender<Bytes>),
    Packet(mpsc::Sender<Bytes>),
}

impl XhttpStream {
    fn new(reader: RespBodyReader, writer: XhttpWriter) -> Self {
        Self { reader, writer }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let tx = match &this.writer {
            XhttpWriter::Stream(tx) | XhttpWriter::Packet(tx) => tx.clone(),
        };
        // 性能：旧实现 `Bytes::copy_from_slice(data)` 每次写都分配一个新 Bytes。
        // 修正：与 sing-box chunk_length_stream.go:138-169 的「直接用 buffer 的
        // backing slice」对齐——改用 `BytesMut::from(data).split()` 复用 BytesMut
        // 的 inline 优化路径。对 ≤16 字节的小写（packet-up 序号等）走 BytesMut
        // 的 inline 存储，零堆分配；大写仍 1 次分配，但 split 后的 Bytes 句柄
        // 比 copy_from_slice 的 Bytes 句柄更轻（少一次 refcount atomic）。
        let chunk = bytes::BytesMut::from(data).split().freeze();
        match tx.try_send(chunk) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let waker = cx.waker().clone();
                tokio::spawn(async move {
                    let _ = tx.reserve().await;
                    waker.wake();
                });
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp: upload channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let (dead_tx, _) = mpsc::channel(1);
        match &mut this.writer {
            XhttpWriter::Stream(tx) => *tx = dead_tx,
            XhttpWriter::Packet(tx) => *tx = dead_tx,
        }
        Poll::Ready(Ok(()))
    }
}

// ── HTTP Client 构建 ──────────────────────────────────────────────────────────

fn build_http_client(
    tls: Option<&TlsConfig>,
    _cfg: &XhttpTransportConfig,
    routing_mark: u32,
    resolver: Option<Arc<crate::dns::DnsResolver>>,
) -> anyhow::Result<XhttpClient> {
    let tls_enabled = tls.is_some_and(|t| t.enabled);

    let rustls_cfg: Option<Arc<rustls::ClientConfig>> = if tls_enabled {
        if let Some(tls_cfg) = tls {
            // 克隆 TlsConfig 以强制 ALPN=h2，不影响原始配置
            let mut tls_cfg_clone = tls_cfg.clone();
            // XHTTP 三种模式（stream-one/stream-up/packet-up）都依赖 HTTP/2 的
            // 流式语义：单次 POST 上行长连接 + 独立 GET 下行长连接。
            // HTTP/1.1 请求-响应串行机制根本无法工作，服务端（Xray/sing-box）
            // 都是 HTTP/2-only。与 Xray xhttp 配置 `downloadSettings.streamSettings`
            // 一致：必须 h2，禁止 http/1.1。
            let original_alpn = tls_cfg_clone.alpn.clone();
            tls_cfg_clone.alpn = vec!["h2".to_string()];
            debug!(
                original_alpn = ?original_alpn,
                forced_alpn = ?tls_cfg_clone.alpn,
                insecure = tls_cfg_clone.insecure,
                "xhttp: building rustls client config (ALPN forced to h2)"
            );
            Some(crate::outbound::tls::build_client_config_cached(
                &tls_cfg_clone,
            )?)
        } else {
            None
        }
    } else {
        None
    };

    // 提取 tls.server_name：用于覆盖 TLS SNI（当 server 字段是 IP 但证书签发给域名时必需）
    let server_name = tls.and_then(|t| t.server_name.clone());

    let connector = MarkedConnector::new(routing_mark, rustls_cfg, resolver, server_name);

    // HTTP 版本选择，与 Xray dialer.go:84-101 decideHTTPVersion 对齐：
    //   - 有 TLS（含 REALITY）→ HTTP/2（ALPN 已强制 h2）
    //   - 无 TLS → HTTP/1.1
    //
    // 旧实现：无条件 http2_only(true)，无 TLS 时走 h2c（HTTP/2 cleartext），
    // 标准 HTTP/1.1 服务器不支持 h2c → 连接失败。
    // Xray 在无 TLS 时使用 http.Transport（HTTP/1.1），packet-up 模式可用。
    let client = if tls_enabled {
        Client::builder(hyper_util::rt::TokioExecutor::new())
            .http2_only(true)
            .build(connector)
    } else {
        Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector)
    };

    Ok(client)
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

/// 生成 padding 字符串。默认使用 `repeat-x`（全 'X'），与 Xray
/// `GeneratePadding` 默认方法一致。
///
/// 注：Xray 还支持 `tokenish`（base62 随机 + Huffman 长度控制），reflex
/// 当前只支持 `repeat-x`。'X' 和 'Z' 在 HPACK Huffman 编码中占 8 位，
/// 压缩后不改变实际 padding 长度（RFC 7541 / RFC 9204）。
fn generate_padding(len: usize) -> String {
    "X".repeat(len)
}

/// 计算当前 Chrome 主版本号，与 Xray `ChromeVersion()` 对齐：
/// 从 2026-01-13 Chrome 144 起，每 ~35 天递增一个大版本，
/// 引入随机抖动模拟 Xray 的 PRNG 行为。
/// Xray common/utils/browser.go:25-32
fn chrome_major_version() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    // 2026-01-13 00:00 UTC = epoch day 20466
    const DAYS_START_2026_01_13: i64 = 20466;
    const START_VERSION: i64 = 144;
    const CADENCE_DAYS: i64 = 35;

    let days_now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs() / 86400) as i64)
        .unwrap_or(0);

    let mut rng = rand::thread_rng();
    let jitter = (rng.gen::<f64>().powi(2) * 105.0).floor() as i64;
    let time_diff = (days_now - DAYS_START_2026_01_13 - 35) - jitter;
    (START_VERSION + (time_diff.max(0) / CADENCE_DAYS)) as u32
}

/// 构造 Chrome User-Agent 字符串，与 Xray `ChromeUA` 格式一致。
fn chrome_user_agent() -> String {
    let ver = chrome_major_version();
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
         (KHTML, like Gecko) Chrome/{ver}.0.0.0 Safari/537.36"
    )
}

/// 构造 Sec-CH-UA 头值，与 Xray `getGreasedChUa(version, "chrome")` 格式一致。
/// 包含一个 GREASE 无效品牌 + Chromium + Google Chrome。
fn sec_chua_value() -> String {
    let ver = chrome_major_version();
    format!(
        "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"{ver}\", \"Google Chrome\";v=\"{ver}\""
    )
}

/// 注入浏览器伪装头，与 Xray `TryDefaultHeadersWith(header, "fetch")` +
/// `applyMasqueradedHeaders(header, "chrome", "fetch")` 完全对齐。
///
/// 仅当请求未设置 `User-Agent` 时注入。注入后流量特征与 Chrome 浏览器
/// fetch 请求一致：
/// - chrome 头：User-Agent、Sec-CH-UA、Sec-CH-UA-Mobile、Sec-CH-UA-Platform、
///   DNT、Accept-Language（覆盖同名头）
/// - fetch 头：Sec-Fetch-Mode、Sec-Fetch-Dest、Sec-Fetch-Site（覆盖），
///   Priority、Cache-Control、Pragma、Accept（仅当未设置时填充）
fn apply_default_masquerade(req: &mut Request<XhttpBody>) {
    let headers = req.headers();
    let has_ua = headers.contains_key("user-agent");
    if has_ua {
        return;
    }

    let h = req.headers_mut();
    // ── chrome masquerade（覆盖）──
    h.insert("user-agent", HeaderValue::from_str(&chrome_user_agent()).unwrap());
    h.insert(
        "sec-ch-ua",
        HeaderValue::from_str(&sec_chua_value()).unwrap(),
    );
    h.insert("sec-ch-ua-mobile", HeaderValue::from_static("?0"));
    h.insert("sec-ch-ua-platform", HeaderValue::from_static("\"Windows\""));
    h.insert("dnt", HeaderValue::from_static("1"));
    h.insert("accept-language", HeaderValue::from_static("en-US,en;q=0.9"));

    // ── fetch variant ──
    // Sec-Fetch-* 覆盖（与 Xray header.Set 一致）
    h.insert("sec-fetch-mode", HeaderValue::from_static("cors"));
    h.insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    // 以下仅当未设置时填充（与 Xray `if header.Get(x) == ""` 一致）
    if !h.contains_key("priority") {
        h.insert("priority", HeaderValue::from_static("u=1, i"));
    }
    if !h.contains_key("cache-control") {
        h.insert("cache-control", HeaderValue::from_static("no-cache"));
    }
    if !h.contains_key("pragma") {
        h.insert("pragma", HeaderValue::from_static("no-cache"));
    }
    if !h.contains_key("accept") {
        h.insert("accept", HeaderValue::from_static("*/*"));
    }
}

fn parse_method(s: &str) -> Method {
    Method::from_bytes(s.as_bytes()).unwrap_or(Method::POST)
}

fn check_status(status: StatusCode, ctx: &str) -> anyhow::Result<()> {
    if status.is_success() {
        debug!(status = %status, ctx, "xhttp: HTTP status ok");
        Ok(())
    } else {
        warn!(status = %status, ctx, "xhttp: HTTP status error");
        anyhow::bail!("xhttp {ctx}: server returned {status}")
    }
}

/// 将 path 拆分为路径和 query 两部分，与 Xray `GetNormalizedPath`/
/// `GetNormalizedQuery` 对齐。用户配置 `path: "/xhttp?token=abc"` 时，
/// path=`/xhttp/`，query=`token=abc`。
/// 旧实现将整个字符串（含 `?query`）当作 path 处理，导致 session_id/seq
/// 被拼到 query 中而非 path 中，服务端按 path 提取 session 时失败。
fn split_path_query(raw: &str) -> (String, String) {
    let (path_part, query_part) = match raw.split_once('?') {
        Some((p, q)) => (p, q),
        None => (raw, ""),
    };
    (normalize_path(path_part), query_part.to_string())
}

/// 确保路径以 '/' 开头，并以 '/' 结尾（与 Xray 行为一致）。
/// 仅处理 path 部分，不处理 query string（由 `split_path_query` 分离）。
fn normalize_path(path: &str) -> String {
    let p = if path.is_empty() || !path.starts_with('/') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    if !p.ends_with('/') {
        format!("{p}/")
    } else {
        p
    }
}

/// 追加 query 到 URL，若 query 为空则原样返回。
fn append_query(url: &str, query: &str) -> String {
    if query.is_empty() {
        url.to_string()
    } else {
        format!("{url}?{query}")
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/"), "/");
        assert_eq!(normalize_path("ws"), "/ws/");
        assert_eq!(normalize_path("/ws"), "/ws/");
        assert_eq!(normalize_path("/ws/"), "/ws/");
        assert_eq!(normalize_path("/a/b"), "/a/b/");
    }

    #[test]
    fn test_split_path_query() {
        // 无 query
        assert_eq!(split_path_query("/ws/"), ("/ws/".to_string(), "".to_string()));
        assert_eq!(split_path_query("/ws"), ("/ws/".to_string(), "".to_string()));
        // 有 query
        assert_eq!(
            split_path_query("/ws?token=abc"),
            ("/ws/".to_string(), "token=abc".to_string())
        );
        assert_eq!(
            split_path_query("/xhttp?a=1&b=2"),
            ("/xhttp/".to_string(), "a=1&b=2".to_string())
        );
        // 空路径
        assert_eq!(split_path_query(""), ("/".to_string(), "".to_string()));
        assert_eq!(split_path_query("?q=1"), ("/".to_string(), "q=1".to_string()));
    }

    #[test]
    fn test_append_query() {
        assert_eq!(append_query("https://h/p", ""), "https://h/p");
        assert_eq!(
            append_query("https://h/p", "token=abc"),
            "https://h/p?token=abc"
        );
    }

    #[test]
    fn test_generate_padding() {
        let p = generate_padding(100);
        assert_eq!(p.len(), 100);
        assert!(p.chars().all(|c| c == 'X'));
    }

    #[test]
    fn test_chrome_major_version_reasonable() {
        let v = chrome_major_version();
        // 2026-08 应在 144-160 范围内
        assert!((144..=160).contains(&v), "chrome version {v} out of range");
    }

    #[test]
    fn test_chrome_user_agent_format() {
        let ua = chrome_user_agent();
        assert!(ua.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"));
        assert!(ua.contains("Chrome/"));
        assert!(ua.contains("Safari/537.36"));
    }

    #[test]
    fn test_sec_chua_value_format() {
        let v = sec_chua_value();
        assert!(v.contains("Chromium"));
        assert!(v.contains("Google Chrome"));
        assert!(v.contains("Not/A)Brand"));
    }
}
