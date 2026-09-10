//! HTTP 代理出站（HTTP CONNECT 隧道）。
//!
//! 握手逻辑对齐 sing 官方实现 `github.com/sagernet/sing/protocol/http`
//! （`client.go` 的 `Client.DialContext`），要点：
//!
//! - 仅支持 TCP；`ListenPacket`（此处对应 `handle_udp`）返回错误，
//!   与官方 `os.ErrInvalid` 语义一致——HTTP/1.1 CONNECT 不承载 UDP。
//! - 认证使用 HTTP Basic：`Proxy-Authorization: Basic base64(user:pass)`。
//! - `headers` 中若包含 `Host` 键，会被摘出单独使用：请求行 URL 采用
//!   `Opaque` 形式（不出现在 authority 部分），且此时若同时配置了
//!   `path` 则直接报错——这是官方行为原样保留，而不是我们臆造的限制。
//! - 用标准 HTTP 响应解析读取状态行 + 全部响应头（而不是自行逐行判断
//!   空行），只有状态码等于 200 才算成功，其余一律失败并给出可读错误。
//!   解析响应时 bufio 读取器可能多缓冲出属于隧道数据的字节，这部分要
//!   放到返回的流最前面，避免丢包。
//! - 可选 TLS：当 `tls.enabled = true` 时，先与代理服务器完成
//!   TLS/uTLS 握手，再在加密通道内发送明文 CONNECT 请求（HTTPS 代理）。

use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use base64::Engine;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
};
use tracing::debug;

use crate::{
    config::outbound::HttpOutboundConfig,
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, relay, resolve_server_addr, set_tcp_opts,
        tls::connect_tls_or_utls,
        AsyncReadWrite, Outbound, OutboundStatus,
    },
};

/// CONNECT 响应头读取的最大字节数（含状态行）。防止异常/恶意服务端
/// 不发送 "\r\n\r\n" 终止符导致无限读取占用内存。
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
/// 单次底层读取的缓冲块大小。
const READ_CHUNK: usize = 4096;

pub struct HttpOutbound {
    config: HttpOutboundConfig,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<DnsResolver>>,
}

impl HttpOutbound {
    pub fn new(config: HttpOutboundConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            routing_mark: 0,
            resolver: None,
        })
    }

    pub fn with_resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 连接到代理服务器（含可选 TLS）───────────────────────────────────────

    async fn connect_proxy_tcp(&self) -> anyhow::Result<TcpStream> {
        let addr = resolve_server_addr(
            &self.config.server,
            self.config.server_port,
            self.resolver.as_ref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("http: DNS lookup failed for {}: {e}", self.config.server))?;
        let stream = crate::outbound::connect_tcp_interface(addr).await?;
        set_tcp_opts(&stream)?;
        apply_mark_to_tcp(&stream, self.routing_mark)?;
        Ok(stream)
    }

    /// 建立底层连接：TLS 关闭时直接返回 TCP 流，
    /// TLS 启用时先完成 TLS/uTLS 握手（即 HTTPS 代理）。
    async fn connect_proxy(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let tcp = self.connect_proxy_tcp().await?;
        if self.config.tls.enabled {
            let sni = self
                .config
                .tls
                .server_name
                .as_deref()
                .unwrap_or(&self.config.server);
            let tls_stream = connect_tls_or_utls(tcp, sni, &self.config.tls).await?;
            Ok(Box::new(tls_stream))
        } else {
            Ok(Box::new(tcp))
        }
    }

    // ── HTTP CONNECT 握手 ────────────────────────────────────────────────────

    /// 发送 CONNECT 请求并校验响应，返回已完成握手、可直接用于透明转发
    /// 的流（响应头之后可能多读到的字节已重新放回流最前面）。
    async fn connect_tunnel(&self, target: &Target) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let mut stream = self.connect_proxy().await?;

        let dest_authority = target_authority(target);
        let (host_header, extra_headers) = self.config.take_host_and_headers();
        let dest_fqdn_matches_host = match (target, &host_header) {
            (Target::Domain(host, _), Some(h)) => host == h,
            _ => false,
        };

        // ── Host 头 与 path 互斥校验（原样保留官方行为）───────────────────
        // 官方逻辑：仅当 `c.host != "" && c.host != destination.Fqdn` 时才会用
        // Opaque 形式并校验 path 冲突；如果 Host 头恰好等于目标域名，则视为
        // 未设置（走普通 authority 形式），此时允许 path 生效。
        let use_opaque_host = host_header.is_some() && !dest_fqdn_matches_host;
        if use_opaque_host && self.config.path.is_some() {
            anyhow::bail!("http: Host header and path are not allowed at the same time");
        }

        // ── 构造请求行 ────────────────────────────────────────────────────
        // 普通形式：CONNECT host:port HTTP/1.1
        // Opaque 形式（自定义 Host 头且与目标不同）：CONNECT host:port HTTP/1.1
        //   （请求目标 authority 仍是 destination，但发送的 Host 头是自定义值）
        // 带 path 形式：CONNECT host:port/path HTTP/1.1（少数网关要求）
        let request_target = if let Some(p) = &self.config.path {
            let p = p.strip_prefix('/').unwrap_or(p);
            format!("{dest_authority}/{p}")
        } else {
            dest_authority.clone()
        };

        let effective_host = if use_opaque_host {
            host_header.clone().unwrap()
        } else {
            dest_authority.clone()
        };

        let mut req = String::with_capacity(256);
        req.push_str(&format!("CONNECT {request_target} HTTP/1.1\r\n"));
        req.push_str(&format!("Host: {effective_host}\r\n"));
        req.push_str("Proxy-Connection: Keep-Alive\r\n");

        if let Some(user) = &self.config.username {
            let pass = self.config.password.as_deref().unwrap_or("");
            let credential =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            req.push_str(&format!("Proxy-Authorization: Basic {credential}\r\n"));
        }

        for (name, value) in &extra_headers {
            if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
                anyhow::bail!("http: header '{name}' contains illegal control characters");
            }
            req.push_str(&format!("{name}: {value}\r\n"));
        }

        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        // ── 读取响应：累积字节直到解析出完整响应头（"\r\n\r\n"）─────────────
        // 用 httparse 一次性解析状态行 + 全部头部，多读到的字节（属于隧道
        // 数据本体）保留下来，随连接一起返回，而不是原样丢弃。
        let mut raw = Vec::with_capacity(1024);
        let mut chunk = [0u8; READ_CHUNK];
        let (header_end, status_code) = loop {
            let n = stream.read(&mut chunk).await?;
            anyhow::ensure!(n > 0, "http: connection closed before CONNECT response");
            raw.extend_from_slice(&chunk[..n]);
            anyhow::ensure!(
                raw.len() <= MAX_RESPONSE_HEADER_BYTES,
                "http: CONNECT response header too large"
            );

            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(&raw) {
                Ok(httparse::Status::Complete(offset)) => {
                    let code = response.code.ok_or_else(|| {
                        anyhow::anyhow!("http: CONNECT response missing status code")
                    })?;
                    break (offset, code);
                }
                Ok(httparse::Status::Partial) => continue,
                Err(e) => anyhow::bail!("http: malformed CONNECT response: {e}"),
            }
        };

        // 只认 200；其余状态一律失败，对常见失败给出可读提示——
        // 与官方 `Client.DialContext` 的 switch 分支保持一致。
        match status_code {
            200 => {}
            407 => anyhow::bail!("http: proxy authentication required"),
            405 => anyhow::bail!("http: proxy rejected CONNECT method (405 method not allowed)"),
            other => anyhow::bail!("http: unexpected status from proxy: {other}"),
        }

        // 响应头之后多读到的字节属于隧道数据本体，塞回流最前面。
        let leftover = raw[header_end..].to_vec();
        Ok(Box::new(PrefixedStream {
            prefix: leftover,
            prefix_pos: 0,
            inner: stream,
        }))
    }
}

// ── Outbound trait 实现 ───────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for HttpOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "HTTP".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(tag = %self.config.tag, target = %conn.target, "http tcp");
        let remote = self.connect_tunnel(&conn.target).await?;
        let (up, down) = relay(conn.stream, remote).await;
        debug!(tag = %self.config.tag, up, down, "http tcp done");
        Ok((up, down))
    }

    async fn handle_udp(&self, _packet: InboundUdpPacket) -> anyhow::Result<()> {
        // HTTP CONNECT 不承载 UDP，等价于官方 `ListenPacket` 返回
        // `os.ErrInvalid`：直接报错，由上层丢弃该包。
        anyhow::bail!("http outbound does not support UDP (CONNECT tunnels TCP only)")
    }

    /// 建立经由 HTTP 代理的 TCP 隧道，供 DNS upstream detour 使用。
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        self.connect_tunnel(&target).await
    }
}

// ── 辅助函数 / 类型 ────────────────────────────────────────────────────────────

/// 目标的 `host:port` 形式，用于 CONNECT 请求行 authority 与默认 Host 头。
fn target_authority(target: &Target) -> String {
    match target {
        Target::Domain(host, port) => format!("{host}:{port}"),
        Target::Socket(addr) => addr.to_string(),
    }
}

/// 包装底层流：把 HTTP 响应解析时多读到、但属于隧道数据本体的字节
/// 放在最前面读出，读完 prefix 后透明转发到 inner。
///
/// 对应官方实现中 `bufio.NewCachedConn(conn, buffer)` 的作用——
/// `net/http` 的 `bufio.Reader` 读取响应时会做块读取，经常会连带把
/// 紧跟在响应头后面的首批隧道数据一并读入缓冲区，如果不回放这部分
/// 字节，会导致连接开始阶段丢包。
struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.prefix_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// 注：不需要手写 `impl AsyncReadWrite for PrefixedStream<S>`。
// `outbound::mod.rs` 已有 blanket impl：
//   impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncReadWrite for T {}
// `PrefixedStream<S>` 只要满足这四个 bound 就会自动获得 AsyncReadWrite，
// 手写会与 blanket impl 冲突（E0119 conflicting implementations）。

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_authority_domain() {
        let t = Target::Domain("example.com".into(), 443);
        assert_eq!(target_authority(&t), "example.com:443");
    }

    #[test]
    fn target_authority_socket() {
        let t = Target::Socket("1.2.3.4:80".parse().unwrap());
        assert_eq!(target_authority(&t), "1.2.3.4:80");
    }

    #[test]
    fn take_host_and_headers_extracts_host_case_insensitive() {
        use crate::config::outbound::{HttpHeaderValue, HttpHeadersConfig, HttpOutboundConfig, TlsConfig};
        let mut map = std::collections::HashMap::new();
        map.insert(
            "hOsT".to_string(),
            HttpHeaderValue::Single("custom.internal".into()),
        );
        map.insert(
            "X-Extra".to_string(),
            HttpHeaderValue::Single("v".into()),
        );
        let cfg = HttpOutboundConfig {
            tag: "t".into(),
            server: "example.com".into(),
            server_port: 8080,
            username: None,
            password: None,
            path: None,
            headers: HttpHeadersConfig(map),
            tls: TlsConfig::default(),
        };
        let (host, headers) = cfg.take_host_and_headers();
        assert_eq!(host.as_deref(), Some("custom.internal"));
        assert_eq!(headers, vec![("X-Extra".to_string(), "v".to_string())]);
    }

    #[tokio::test]
    async fn prefixed_stream_yields_prefix_then_inner() {
        // 用内存 duplex 管道代替 tokio_test::io::Builder（避免引入未声明的
        // 测试专用依赖）：写入 "world" 到管道一端，读取端包一层 PrefixedStream。
        let (mut writer, reader) = tokio::io::duplex(64);
        writer.write_all(b"world").await.unwrap();
        drop(writer); // 让 inner 读到 EOF 前只有这一次写入

        let mut s = PrefixedStream {
            prefix: b"hello ".to_vec(),
            prefix_pos: 0,
            inner: reader,
        };
        let mut buf = [0u8; 32];
        let n1 = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], b"hello ");
        let n2 = s.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"world");
    }
}
