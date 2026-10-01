use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use futures_util::ready;
use h2::{RecvStream, SendStream};
use http::{Request, Uri, Version};
use prost::encoding::{decode_varint, encode_varint};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, Mutex},
};
use tracing::warn;

use crate::config::outbound::{GrpcTransportConfig, TlsConfig};
use crate::dns::DnsResolver;
use crate::outbound::{apply_mark_to_tcp, resolve_server_addr, set_tcp_opts, AsyncReadWrite};

// ── 连接建立 ─────────────────────────────────────────────────────────────────

/// 建立一条 gRPC 双工流。
///
/// 当 `tls` 为 `Some` 且 `tls.enabled = true` 时，先通过
/// [`crate::outbound::tls::connect_tls_or_utls`] 建立 TLS 流（支持 uTLS），
/// 再在该 TLS 流上进行 h2 握手；否则直接在 TCP 上进行 h2 握手。
///
/// # 参数
///
/// - `server` / `port`：出站节点自身的地址。
/// - `sni`：TLS SNI（也用作 HTTP/2 :authority），通常等于 `server_name` 或 `server`。
/// - `tls`：完整 TLS 配置。`None` 或 `tls.enabled = false` 表示明文 gRPC（h2c）。
///   传入时会克隆一份并强制 ALPN 为 `h2`（gRPC 必须基于 HTTP/2）。
/// - `grpc_cfg`：gRPC 传输配置（service name 等）。
/// - `routing_mark`：全局 SO_MARK，0 表示不设置。
/// - `resolver`：用于解析 `server` 域名，None 时回退系统 DNS。
pub async fn connect(
    server: &str,
    port: u16,
    sni: &str,
    tls: Option<&TlsConfig>,
    grpc_cfg: &GrpcTransportConfig,
    routing_mark: u32,
    resolver: Option<Arc<DnsResolver>>,
) -> anyhow::Result<GrpcStream> {
    let addr = resolve_server_addr(server, port, resolver.as_ref())
        .await
        .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;

    let tcp = crate::outbound::connect_tcp_interface(addr).await?;
    set_tcp_opts(&tcp)?;
    apply_mark_to_tcp(&tcp, routing_mark)?;

    let tls_enabled = tls.is_some_and(|t| t.enabled);

    // 构建底层 I/O 流：TLS 启用时先建立 TLS 流（支持 uTLS），否则用明文 TCP。
    // 与 sing-box 一致：h2 握手在已建立的 TLS 流上进行，TLS 配置由
    // `connect_tls_or_utls` 统一处理（含 uTLS 指纹、自签证书、ALPN）。
    let io: Box<dyn AsyncReadWrite> = if tls_enabled {
        // gRPC over TLS 必须使用 h2 ALPN（HTTP/2 协商）。
        // 若 ALPN 协商出 http/1.1，h2 握手会失败。与 sing-box 一致：
        // 仅当用户未显式配置 ALPN 时回填 h2。
        let mut tls_cfg = tls.cloned().expect("tls is Some when tls_enabled");
        if tls_cfg.alpn.is_empty() {
            tls_cfg.alpn = vec!["h2".to_string()];
        }
        let tls_stream = crate::outbound::tls::connect_tls_or_utls(tcp, sni, &tls_cfg).await?;
        Box::new(tls_stream)
    } else {
        Box::new(tcp)
    };

    // 在已建立的流（TLS 或 TCP）上进行 h2 握手。
    let host = grpc_cfg.host.clone().unwrap_or_else(|| sni.to_string());
    let path = grpc_cfg
        .service_name
        .clone()
        .map(|p| {
            if p.starts_with('/') {
                p
            } else {
                format!("/{p}")
            }
        })
        .unwrap_or_else(|| "/".to_string());

    let client = GrpcClient::new(host, path);
    let stream = client.proxy_stream(io).await?;
    Ok(stream)
}

// ── GrpcClient ───────────────────────────────────────────────────────────────

/// gRPC 客户端：封装 host（HTTP/2 :authority）与 path（service name）。
///
/// 与 clash-rs `proxy::transport::grpc::Client` 等价。
pub struct GrpcClient {
    pub host: String,
    pub path: http::uri::PathAndQuery,
}

impl GrpcClient {
    pub fn new(host: String, path: String) -> Self {
        let path: http::uri::PathAndQuery = path
            .try_into()
            .unwrap_or_else(|_| http::uri::PathAndQuery::from_static("/"));
        Self { host, path }
    }

    fn req(&self) -> io::Result<Request<()>> {
        let uri: Uri = {
            Uri::builder()
                .scheme("https")
                .authority(self.host.as_str())
                .path_and_query(format!("{}/Tun", self.path.as_str()))
                .build()
                .map_err(map_io_error)?
        };
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .version(Version::HTTP_2)
            .header("content-type", "application/grpc")
            .header("user-agent", "tonic/0.10");
        Ok(request.body(()).unwrap())
    }

    /// 在已建立的流（TLS 或 TCP）上进行 h2 握手，并启动 gRPC 流。
    pub async fn proxy_stream(&self, stream: Box<dyn AsyncReadWrite>) -> io::Result<GrpcStream> {
        let (client, h2) = h2::client::Builder::new()
            .initial_connection_window_size(0x7FFFFFFF)
            .initial_window_size(0x7FFFFFFF)
            .initial_max_send_streams(1024)
            .enable_push(false)
            .handshake(stream)
            .await
            .map_err(map_io_error)?;
        let mut client = client.ready().await.map_err(map_io_error)?;

        let req = self.req()?;
        let (resp, send_stream) = client.send_request(req, false).map_err(map_io_error)?;
        tokio::spawn(async move {
            if let Err(e) = h2.await {
                warn!("http2 got err:{:?}", e);
            }
        });

        let (init_sender, init_ready) = mpsc::channel(1);
        let recv_stream = Arc::new(Mutex::new(None));

        {
            let recv_stream = recv_stream.clone();
            tokio::spawn(async move {
                match resp.await {
                    Ok(resp) => {
                        match resp.status() {
                            http::StatusCode::OK => {}
                            _ => {
                                warn!(
                                    "grpc handshake resp err: {:?}",
                                    resp.into_body().data().await
                                );
                                let _ = init_sender.send(()).await;
                                return;
                            }
                        }
                        let stream = resp.into_body();
                        recv_stream.lock().await.replace(stream);
                    }
                    Err(e) => {
                        warn!("grpc resp err: {:?}", e);
                    }
                }
                let _ = init_sender.send(()).await;
            });
        }

        Ok(GrpcStream::new(init_ready, recv_stream, send_stream))
    }
}

// ── GrpcStream：AsyncRead + AsyncWrite 适配器 ────────────────────────────────

/// 将 gRPC 双向流适配为 `AsyncRead + AsyncWrite`。
///
/// 内部对写入数据按 `[grpc header 5B][protobuf field][varint len][data]` 编码，
/// 对读取数据按相同格式解码后透传给上层。
///
/// 与 clash-rs `GrpcStream` 实现一致。
pub struct GrpcStream {
    init_ready: mpsc::Receiver<()>,
    recv: Arc<Mutex<Option<RecvStream>>>,
    send: SendStream<bytes::Bytes>,
    buffer: BytesMut,
    payload_len: usize,
}

impl std::fmt::Debug for GrpcStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcStream")
            .field("buffer", &self.buffer)
            .field("payload_len", &self.payload_len)
            .finish()
    }
}

impl GrpcStream {
    pub fn new(
        init_ready: mpsc::Receiver<()>,
        recv: Arc<Mutex<Option<RecvStream>>>,
        send: SendStream<bytes::Bytes>,
    ) -> Self {
        Self {
            init_ready,
            recv,
            send,
            buffer: BytesMut::with_capacity(1024 * 4),
            payload_len: 0,
        }
    }

    // encode data to grpc + protobuf format
    //
    // 性能：旧实现 3 次分配（protobuf_header BytesMut + freeze + 最终 buf BytesMut）。
    // 修正：与 sing-box chunk_length_stream.go:138-169 的「单 buffer 预留头尾空间」对齐，
    // 一次 `BytesMut::with_capacity` 把 grpc header(5) + protobuf header(≤11) + data
    // 全部装进同一个连续 buffer，只有 1 次堆分配。
    fn encode_buf(&self, data: &[u8]) -> bytes::Bytes {
        // 先算 protobuf header 长度：1 字节 tag(0x0a) + varint(data.len())，varint ≤ 10 字节
        let varint_len = varint_len(data.len() as u64);
        let protobuf_header_len = 1 + varint_len;
        let grpc_payload_len = (protobuf_header_len + data.len()) as u32;
        let total = 5 + protobuf_header_len + data.len();

        let mut buf = BytesMut::with_capacity(total);
        // gRPC 帧头：[compressed 1B][length 4B BE]
        buf.put_u8(0x00); // 不压缩
        buf.put_u32(grpc_payload_len);
        // protobuf 字段：[tag 0x0a][varint length][data]
        buf.put_u8(0x0a);
        encode_varint(data.len() as u64, &mut buf);
        buf.put_slice(data);
        buf.freeze()
    }
}

impl AsyncRead for GrpcStream {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.init_ready.poll_recv(cx));

        let recv = self.recv.clone();

        let mut recv = recv.try_lock().unwrap();
        if recv.is_none() {
            warn!("grpc initialization error");
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "initialization error",
            )));
        }

        if (self.payload_len > 0 && !self.buffer.is_empty())
            || (self.payload_len == 0 && self.buffer.len() > 6)
        {
            if self.payload_len == 0 {
                self.buffer.advance(6);
                let payload_len = decode_varint(&mut self.buffer).map_err(map_io_error)?;
                self.payload_len = payload_len as usize;
            }

            let to_read = std::cmp::min(buf.remaining(), self.payload_len);
            let to_read = std::cmp::min(to_read, self.buffer.len());

            if to_read == 0 {
                assert!(buf.remaining() > 0);
                return Poll::Pending;
            }

            let data = self.buffer.split_to(to_read);

            self.payload_len -= to_read;
            buf.put_slice(&data[..]);
            return Poll::Ready(Ok(()));
        }

        match ready!(Pin::new(&mut recv.as_mut().unwrap()).poll_data(cx)) {
            Some(Ok(b)) => {
                let b: bytes::Bytes = b;
                self.buffer.reserve(b.len());
                self.buffer.extend_from_slice(&b[..]);

                while self.payload_len > 0 || self.buffer.len() > 6 {
                    if self.payload_len == 0 {
                        self.buffer.advance(6);
                        let payload_len = decode_varint(&mut self.buffer).map_err(map_io_error)?;
                        self.payload_len = payload_len as usize;
                    }
                    let to_read = std::cmp::min(self.buffer.len(), self.payload_len);
                    let to_read = std::cmp::min(buf.remaining(), to_read);
                    if to_read == 0 {
                        break;
                    }

                    buf.put_slice(self.buffer.split_to(to_read).freeze().as_ref());
                    self.payload_len -= to_read;
                }

                recv.as_mut()
                    .unwrap()
                    .flow_control()
                    .release_capacity(b.len())
                    .map_or_else(
                        |e| Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e))),
                        |_| Poll::Ready(Ok(())),
                    )
            }
            _ => {
                assert_eq!(self.payload_len, 0);
                if recv.as_mut().unwrap().is_end_stream() {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let encoded_buf = self.encode_buf(buf);

        self.send.reserve_capacity(encoded_buf.len());

        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(_)) => self.send.send_data(encoded_buf, false).map_or_else(
                |e| {
                    warn!("grpc write error: {}", e);
                    Err(io::Error::new(io::ErrorKind::BrokenPipe, e))
                },
                |_| Ok(buf.len()),
            ),
            Some(Err(e)) => {
                warn!("grpc poll_capacity error: {}", e);
                Err(io::Error::new(io::ErrorKind::BrokenPipe, e))
            }
            _ => Err(io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe")),
        })
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.send_reset(h2::Reason::NO_ERROR);
        self.send
            .poll_reset(cx)
            .map_err(map_io_error)
            .map(|_| Ok(()))
    }
}

fn map_io_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> io::Error {
    io::Error::other(e)
}

/// 计算 protobuf varint 编码 `n` 所需的字节数（1..=10）。
/// 用于 gRPC 帧编码时一次性预分配 buffer，避免 `encode_varint` 内部多次 reserve。
#[inline]
fn varint_len(mut n: u64) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}
