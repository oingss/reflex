//! gRPC inbound 传输层（VLESS/VMess/Trojan 共用）。
//!
//! 基于 h2 server 实现，与 reflex outbound 的 gRPC 客户端
//! （`outbound/transport/grpc.rs`）互为对偶，也与 Xray/sing-box 的
//! gRPC 传输兼容：
//!   • 客户端发起 `POST /<service_name>/Tun`（content-type: application/grpc）；
//!   • 服务端回 200 + application/grpc 响应头；
//!   • 双向数据按 gRPC message 帧 + protobuf 字段封装：
//!     `[flag 1B][len 4B BE] [0x0a][varint len][data]`。

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::ready;
use http::{Method, Response, StatusCode};
use prost::encoding::encode_varint;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use crate::outbound::AsyncReadWrite;

// ── Accept options ───────────────────────────────────────────────────────────

/// gRPC 服务端接受选项（对齐 sing-box V2RayGRPCOptions）
#[derive(Debug, Clone, Default)]
pub struct GrpcServerOptions {
    /// gRPC 服务名（客户端 path 为 /<service_name>/Tun），空 = "/Tun"
    pub service_name: String,
    /// 可选 Host（:authority）校验
    pub host: Option<String>,
}

impl GrpcServerOptions {
    pub fn from_config(cfg: &crate::config::inbound::InboundGrpcTransportConfig) -> Self {
        Self {
            service_name: cfg.service_name.clone(),
            host: cfg.host.clone(),
        }
    }

    /// 期望的完整 path（对齐 outbound 客户端的 `/<path>/Tun` 构造）
    fn expected_path(&self) -> String {
        let base = if self.service_name.is_empty() {
            "/".to_string()
        } else if self.service_name.starts_with('/') {
            self.service_name.clone()
        } else {
            format!("/{}", self.service_name)
        };
        if base == "/" {
            "/Tun".to_string()
        } else {
            format!("{}/Tun", base.trim_end_matches('/'))
        }
    }
}

// ── Accept ───────────────────────────────────────────────────────────────────

/// 在已完成 TLS/Reality 的流（或任意 AsyncReadWrite）上建立 gRPC 双工流。
pub async fn accept<S>(io: S, opts: &GrpcServerOptions) -> anyhow::Result<Box<dyn AsyncReadWrite>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut conn = h2::server::Builder::new()
        .initial_window_size(0x7FFFFFFF)
        .initial_connection_window_size(0x7FFFFFFF)
        .enable_connect_protocol()
        .handshake::<S, Bytes>(io)
        .await
        .map_err(|e| anyhow::anyhow!("grpc h2 server handshake: {e}"))?;

    let (request, mut respond) = conn
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("grpc: connection closed before request"))?
        .map_err(|e| anyhow::anyhow!("grpc: accept request: {e}"))?;

    // ── 校验 method / host / path ──────────────────────────────────────────
    if request.method() != Method::POST {
        anyhow::bail!("grpc: unexpected method {}", request.method());
    }
    if let Some(expected_host) = &opts.host {
        let req_host = request
            .uri()
            .authority()
            .map(|a| a.as_str())
            .or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|v| v.to_str().ok())
            })
            .unwrap_or("");
        if req_host != expected_host.as_str() {
            anyhow::bail!("grpc: host mismatch {req_host} != {expected_host}");
        }
    }
    let expected_path = opts.expected_path();
    let req_path = request.uri().path().to_string();
    if req_path != expected_path {
        anyhow::bail!("grpc: path mismatch {req_path} != {expected_path}");
    }
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/grpc") {
        debug!("grpc: content-type {content_type} (expected application/grpc*)");
    }

    // ── 回 200 + grpc 响应头 ───────────────────────────────────────────────
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .body(())
        .expect("static response");
    let send_stream = respond
        .send_response(response, false)
        .map_err(|e| anyhow::anyhow!("grpc: send response: {e}"))?;

    let recv_stream = request.into_body();

    // 继续驱动 h2 连接（处理后续流/连接级帧；只接受第一个流作为代理流）
    tokio::spawn(async move {
        loop {
            match conn.accept().await {
                Some(Ok((_extra_req, mut extra_respond))) => {
                    // 多余的流直接 RST（gRPC 传输只用一条 Tun 流）
                    debug!("grpc: extra stream {} rejected", _extra_req.uri().path());
                    extra_respond.send_reset(h2::Reason::REFUSED_STREAM);
                }
                Some(Err(e)) => {
                    debug!("grpc: conn accept error: {e}");
                    break;
                }
                None => break,
            }
        }
    });

    Ok(Box::new(GrpcServerStream::new(recv_stream, send_stream)))
}

// ── GrpcServerStream：h2 双向流 → 字节流 ────────────────────────────────────

/// 读取方向解析 `[flag 1B][len 4B BE] [0x0a][varint len][data]` 帧，
/// 写入方向按相同格式封装。与 outbound 客户端的 GrpcStream 互为镜像。
pub struct GrpcServerStream {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    /// h2 数据缓冲
    buffer: BytesMut,
    /// 当前 grpc 帧剩余字节数（0 = 需要读新帧头）
    frame_left: usize,
    /// 当前 protobuf 字段剩余数据字节数（0 = 需要解析 protobuf 头）
    inner_left: usize,
    /// recv 端已结束
    recv_ended: bool,
}

impl GrpcServerStream {
    fn new(recv: h2::RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self {
            recv,
            send,
            buffer: BytesMut::with_capacity(4096),
            frame_left: 0,
            inner_left: 0,
            recv_ended: false,
        }
    }

    /// 从 h2 拉更多数据进 buffer；返回 false 表示流已结束
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        if self.recv_ended {
            return Poll::Ready(Ok(false));
        }
        match Pin::new(&mut self.recv).poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.recv_ended = true;
                Poll::Ready(Ok(false))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                e,
            ))),
            Poll::Ready(Some(Ok(data))) => {
                let len = data.len();
                self.buffer.extend_from_slice(&data);
                // gRPC 大流量必须释放 h2 流量控制窗口
                let _ = self.recv.flow_control().release_capacity(len);
                Poll::Ready(Ok(true))
            }
        }
    }
}

impl AsyncRead for GrpcServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            // 1. 有待交付的 protobuf 字段数据
            if this.inner_left > 0 {
                if this.buffer.is_empty() {
                    if this.frame_left == 0 {
                        // 帧边界与字段数据应同时耗尽，出现这种状态说明对端帧格式异常
                        return Poll::Ready(Err(std::io::Error::other(
                            "grpc: protobuf field exceeds frame boundary",
                        )));
                    }
                    match this.poll_fill(cx)? {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(false) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "grpc: stream ended mid-message",
                            )))
                        }
                        Poll::Ready(true) => continue,
                    }
                }
                let n = this.inner_left.min(this.buffer.len()).min(buf.remaining());
                let data = this.buffer.split_to(n);
                this.inner_left -= n;
                this.frame_left = this.frame_left.saturating_sub(n);
                buf.put_slice(&data);
                return Poll::Ready(Ok(()));
            }

            // 2. 帧内还有 protobuf 头（tag + varint）需要解析
            if this.frame_left > 0 {
                if this.buffer.is_empty() {
                    match this.poll_fill(cx)? {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(false) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "grpc: stream ended mid-frame",
                            )))
                        }
                        Poll::Ready(true) => continue,
                    }
                }
                // tag 字节：0x0a = field 1 (LEN)
                let tag = this.buffer[0];
                this.buffer.advance(1);
                this.frame_left -= 1;
                if tag != 0x0a {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "grpc: unexpected protobuf tag {tag:#x}"
                    ))));
                }
                // varint 可能跨 DATA 块，逐字节收集
                let mut value: u64 = 0;
                let mut shift = 0u32;
                loop {
                    if this.buffer.is_empty() {
                        if this.frame_left == 0 {
                            return Poll::Ready(Err(std::io::Error::other(
                                "grpc: varint exceeds frame boundary",
                            )));
                        }
                        match this.poll_fill(cx)? {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(false) => {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "grpc: stream ended mid-varint",
                                )))
                            }
                            Poll::Ready(true) => continue,
                        }
                    }
                    let b = this.buffer[0];
                    this.buffer.advance(1);
                    this.frame_left -= 1;
                    value |= u64::from(b & 0x7f) << shift;
                    if b & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                    if shift >= 64 {
                        return Poll::Ready(Err(std::io::Error::other("grpc: varint too long")));
                    }
                }
                this.inner_left = value as usize;
                continue;
            }

            // 3. 需要新帧头（5 字节）
            if this.buffer.len() < 5 {
                match this.poll_fill(cx)? {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(false) => {
                        // 流结束：若 buffer 还有残余（<5B）视为对端异常，否则正常 EOF
                        if this.buffer.is_empty() {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "grpc: stream ended mid-frame-header",
                        )));
                    }
                    Poll::Ready(true) => continue,
                }
            }
            let _flag = this.buffer[0]; // compressed 标志，未启用压缩
            let frame_len = u32::from_be_bytes([
                this.buffer[1],
                this.buffer[2],
                this.buffer[3],
                this.buffer[4],
            ]) as usize;
            this.buffer.advance(5);
            this.frame_left = frame_len;
        }
    }
}

impl GrpcServerStream {
    /// 与 outbound 客户端 encode_buf 完全一致的封装
    fn encode_buf(&self, data: &[u8]) -> Bytes {
        let varint_len = varint_len(data.len() as u64);
        let protobuf_header_len = 1 + varint_len;
        let grpc_payload_len = (protobuf_header_len + data.len()) as u32;
        let total = 5 + protobuf_header_len + data.len();

        let mut buf = BytesMut::with_capacity(total);
        // gRPC 帧头：[compressed 1B][length 4B BE]
        buf.put_u8(0x00);
        buf.put_u32(grpc_payload_len);
        // protobuf 字段：[tag 0x0a][varint length][data]
        buf.put_u8(0x0a);
        encode_varint(data.len() as u64, &mut buf);
        buf.put_slice(data);
        buf.freeze()
    }
}

impl AsyncWrite for GrpcServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let encoded = self.encode_buf(buf);
        self.send.reserve_capacity(encoded.len());
        Poll::Ready(match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(_)) => self.send.send_data(encoded, false).map_or_else(
                |e| {
                    warn!("grpc server write error: {e}");
                    Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                },
                |_| Ok(buf.len()),
            ),
            Some(Err(e)) => {
                warn!("grpc server poll_capacity error: {e}");
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "grpc: stream closed",
            )),
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.send.send_reset(h2::Reason::NO_ERROR);
        Poll::Ready(Ok(()))
    }
}

/// 计算 protobuf varint 编码 `n` 所需的字节数（1..=10）
#[inline]
fn varint_len(mut n: u64) -> usize {
    let mut len = 1;
    while n >= 0x80 {
        n >>= 7;
        len += 1;
    }
    len
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use prost::encoding::decode_varint;

    #[test]
    fn expected_path_matches_outbound() {
        // outbound: path = "/" + service_name，请求 = path + "/Tun"
        let opts = GrpcServerOptions {
            service_name: "mygrpc".into(),
            host: None,
        };
        assert_eq!(opts.expected_path(), "/mygrpc/Tun");

        let opts = GrpcServerOptions::default();
        assert_eq!(opts.expected_path(), "/Tun");

        let opts = GrpcServerOptions {
            service_name: "/abs".into(),
            host: None,
        };
        assert_eq!(opts.expected_path(), "/abs/Tun");
    }

    #[test]
    fn encode_roundtrip_varint() {
        // encode_buf 产出与 outbound 相同的帧格式
        let data = vec![0xABu8; 70000]; // 触发 3 字节 varint
        let stream_frame = {
            let varint_len = varint_len(data.len() as u64);
            let mut buf = BytesMut::with_capacity(5 + 1 + varint_len + data.len());
            buf.put_u8(0x00);
            buf.put_u32((1 + varint_len + data.len()) as u32);
            buf.put_u8(0x0a);
            encode_varint(data.len() as u64, &mut buf);
            buf.put_slice(&data);
            buf.freeze()
        };
        // 解析回来
        assert_eq!(stream_frame[0], 0x00);
        let payload_len =
            u32::from_be_bytes([stream_frame[1], stream_frame[2], stream_frame[3], stream_frame[4]])
                as usize;
        assert_eq!(payload_len, 1 + 3 + 70000);
        let mut cur = &stream_frame[5..];
        assert_eq!(cur[0], 0x0a);
        cur.advance(1);
        let inner = decode_varint(&mut cur).unwrap();
        assert_eq!(inner as usize, 70000);
        assert_eq!(cur.len(), 70000);
        assert_eq!(cur[0], 0xAB);
    }

    #[test]
    fn varint_len_matches_encoding() {
        for n in [0u64, 1, 127, 128, 16383, 16384, 70000, u32::MAX as u64] {
            let mut buf = BytesMut::new();
            encode_varint(n, &mut buf);
            assert_eq!(buf.len(), varint_len(n), "n={n}");
        }
    }
}
