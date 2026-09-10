//! NaiveProxy 协议共享原语（客户端 / 服务端共用）。
//!
//! ## 协议概览（参考 flux-master naiveproxy 实现 / klzgrad/naiveproxy）
//!
//! 服务端核心握手：
//! 1. TLS（ALPN 协商 h2；明文模式下为 h2 prior knowledge）。
//! 2. HTTP/2 CONNECT 隧道：`:method = CONNECT`、`:authority = host:port`。
//!    h2 的 CONNECT 语义本身就是双向字节流，建连（回 200）成功后 stream
//!    上的 DATA 帧即是原始隧道字节，无需 HTTP/1.1 式 upgrade。
//! 3. `Proxy-Authorization: Basic base64(user:pass)` 鉴权。
//! 4. 可选 padding：双方通过 CONNECT 请求/响应里是否携带 [`PADDING_HEADER_NAME`]
//!    头协商是否启用（服务端配置开启 **且** 客户端带了该头才启用）。
//!
//! ## padding 分帧（wire format，双方向独立计数，前 [`PADDING_COUNT`] 次读/写）
//!
//! ```text
//! [data_size: u16 BE][padding_size: u8][data: data_size B][zeros: padding_size B]
//! ```
//!
//! - 数据超过 [`MAX_PADDING_CHUNK`] 时按上限分块发送（sing-box `writeChunked`）。
//! - `padding_size` 为随机值；之后降级为原始读写。
//!
//! 本模块只放 wire-format 原语：padding 分帧流包装（[`NaiveStream`]）、
//! padding 头生成、Basic Auth 编解码、CONNECT authority 解析。
//! 连接管理 / 鉴权策略 / 隧道调度由 inbound / outbound 各自实现。

use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ── 协议常量 ─────────────────────────────────────────────────────────────────

/// padding 帧数（与 sing-box naive `paddingCount` 一致）
pub const PADDING_COUNT: u32 = 8;

/// 单个 padding 帧最大数据尺寸（与 sing-box `writeChunked` 一致，u16 上限）
pub const MAX_PADDING_CHUNK: usize = 65535;

/// padding 头字符集（与 sing-box `generatePaddingHeader` 一致）
pub const PADDING_HEADER_CHARSET: &[u8] = b"!#$()+<>?@[]^`{}";

/// CONNECT 请求/响应中协商 padding 的头名
pub const PADDING_HEADER_NAME: &str = "padding";

/// 代理鉴权头名（`Proxy-Authorization`）
pub const PROXY_AUTHORIZATION_HEADER: &str = "proxy-authorization";

/// NaiveProxy 协商的 ALPN 协议名
pub const ALPN_H2: &str = "h2";

// ── padding 头生成 ───────────────────────────────────────────────────────────

/// 生成 Padding HTTP 头（与 sing-box `generatePaddingHeader` 完全一致）。
///
/// 长度 30~61，前 16 字符取自 [`PADDING_HEADER_CHARSET`]，其余为 `~`。
pub fn generate_padding_header() -> String {
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

// ── Basic Auth ───────────────────────────────────────────────────────────────

/// 构建 `Proxy-Authorization` 头的值：`Basic base64(user:pass)`。
pub fn build_basic_auth_value(username: &str, password: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    format!("Basic {encoded}")
}

/// 解析 `Proxy-Authorization: Basic ...` 头，返回 `(username, password)`。
///
/// 头缺失、非 Basic 方案、Base64/UTF-8 解码失败、缺少 `:` 分隔时返回 `None`。
pub fn parse_basic_auth(header: Option<&http::header::HeaderValue>) -> Option<(String, String)> {
    let value = header?.to_str().ok()?;
    let b64 = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// 校验 Basic Auth 是否命中用户列表。
///
/// 用户列表为空时一律返回 `false`（naiveproxy 必须配置至少一个用户）。
pub fn verify_basic_auth(header: Option<&http::header::HeaderValue>, users: &[(String, String)]) -> bool {
    if users.is_empty() {
        return false;
    }
    match parse_basic_auth(header) {
        Some((user, pass)) => users
            .iter()
            .any(|(u, p)| u == &user && p == &pass),
        None => false,
    }
}

// ── CONNECT authority 解析 ───────────────────────────────────────────────────

/// 解析 CONNECT `:authority`（`host:port` / `[IPv6]:port`）为 `(host, port)`。
///
/// CONNECT 必须携带端口；缺失或非法时返回 `None`（调用方回 502）。
pub fn parse_connect_authority(authority: &http::uri::Authority) -> Option<(String, u16)> {
    let s = authority.as_str();

    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        // IPv6 字面量：[::1]:443
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = after.strip_prefix(':')?.parse::<u16>().ok()?;
        (host, port)
    } else {
        let (host, port) = s.rsplit_once(':')?;
        (host, port.parse::<u16>().ok()?)
    };

    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

// ── NaiveStream：包装 h2 SendStream + RecvStream，带 padding 分帧 ────────────
//
// 与 sing-box naive 的 paddingConn 对齐（客户端与服务端通用：协议本身是
// 对称的——各自方向的前 8 次写做分帧、前 8 次读做解帧）：
// - 前 [`PADDING_COUNT`] 个写操作：每帧 [data_size u16 BE][padding_size u8]
//   [data][padding zeros]，数据按 [`MAX_PADDING_CHUNK`] 上限分块
// - 前 [`PADDING_COUNT`] 个读操作：解析 3 字节头，读取 data_size 字节数据，
//   跳过 padding_size 字节填充
// - 之后：原始读写（[`NaiveStream::new_plain`] 则从头到尾都是原始读写）

pub struct NaiveStream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,

    // 读侧 padding 状态
    read_buf: BytesMut,
    /// 剩余 padding 帧数（初始 = 8；明文模式为 0）
    read_padding_left: u32,
    /// 当前帧剩余数据字节数
    read_data_left: usize,
    /// 当前帧剩余填充字节数
    read_pad_left: usize,

    // 写侧 padding 状态
    /// 剩余 padding 帧数（初始 = 8；明文模式为 0）
    write_padding_left: u32,
}

impl NaiveStream {
    /// 创建启用 padding 的隧道流（前 8 次读/写分帧）。
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
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

    /// 创建不启用 padding 的明文隧道流（对端未协商 padding 时使用）。
    pub fn new_plain(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            read_padding_left: 0,
            read_data_left: 0,
            read_pad_left: 0,
            write_padding_left: 0,
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

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_header_format() {
        let hdr = generate_padding_header();
        assert!(hdr.len() >= 30 && hdr.len() <= 61);
        for b in hdr.bytes().take(16) {
            assert!(PADDING_HEADER_CHARSET.contains(&b));
        }
        for b in hdr.bytes().skip(16) {
            assert_eq!(b, b'~');
        }
    }

    #[test]
    fn basic_auth_roundtrip() {
        let value = build_basic_auth_value("user", "pass");
        assert_eq!(value, "Basic dXNlcjpwYXNz");

        let parsed = parse_basic_auth(Some(&http::HeaderValue::from_str(&value).unwrap()));
        assert_eq!(parsed, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn basic_auth_password_with_colon() {
        let value = build_basic_auth_value("u", "p:1:2");
        let parsed = parse_basic_auth(Some(&http::HeaderValue::from_str(&value).unwrap()));
        assert_eq!(parsed, Some(("u".to_string(), "p:1:2".to_string())));
    }

    #[test]
    fn verify_basic_auth_user_list() {
        let users = vec![("alice".to_string(), "wonder".to_string())];
        let good = build_basic_auth_value("alice", "wonder");
        let bad = build_basic_auth_value("alice", "wrong");
        let hg = http::HeaderValue::from_str(&good).unwrap();
        let hb = http::HeaderValue::from_str(&bad).unwrap();
        assert!(verify_basic_auth(Some(&hg), &users));
        assert!(!verify_basic_auth(Some(&hb), &users));
        assert!(!verify_basic_auth(None, &users));
        assert!(!verify_basic_auth(Some(&hg), &[])); // 空用户列表一律拒绝
    }

    #[test]
    fn parse_authority_variants() {
        let a: http::uri::Authority = "example.com:443".parse().unwrap();
        assert_eq!(
            parse_connect_authority(&a),
            Some(("example.com".to_string(), 443))
        );

        let a: http::uri::Authority = "[::1]:8443".parse().unwrap();
        assert_eq!(parse_connect_authority(&a), Some(("::1".to_string(), 8443)));

        let a: http::uri::Authority = "example.com".parse().unwrap();
        assert_eq!(parse_connect_authority(&a), None); // CONNECT 必须带端口

        let a: http::uri::Authority = "example.com:notaport".parse().unwrap();
        assert_eq!(parse_connect_authority(&a), None);
    }
}
