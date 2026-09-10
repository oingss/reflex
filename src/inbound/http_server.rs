//! HTTP 服务端入站（移植自 flux，标准 HTTP/1.1 CONNECT 代理，RFC 9110 §9.3.6）。
//!
//! 与客户端本地用途的 [`crate::inbound::http`] 的区别：面向公网服务端场景，
//! 支持可选 TLS 包装（`tls.enabled` 时为 HTTPS 代理），转发普通 HTTP 请求时
//! 剥离 `Proxy-*` 头（flux 行为）。
//!
//! 支持两种使用方式：
//!   1. `CONNECT host:port HTTP/1.1`    — 建立隧道，之后透传任意协议
//!   2. `GET http://host/path HTTP/1.1` — 绝对 URI 形式的普通 HTTP 转发
//!
//! 与 flux 的差异：reflex 架构下入站不直接拨号，解析出目标后交给
//! dispatcher 按路由规则选择出站；拨号失败由 dispatcher 侧回 RST。

use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, error, info};

use crate::{
    config::inbound::HttpServerInboundConfig,
    inbound::{display_sockaddr, tls_server, InboundTcpStream, SniffedStream, Target},
};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_LINES: usize = 128;

pub struct HttpServerInbound {
    config: HttpServerInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl HttpServerInbound {
    pub fn new(config: HttpServerInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        // 可选 TLS：enabled 时先做 TLS accept 再解析 HTTP（HTTPS 代理）
        let tls_acceptor = if self.config.tls.enabled {
            Some(Arc::new(tls_server::build_acceptor(&self.config.tls)?))
        } else {
            None
        };

        let bind: SocketAddr =
            crate::inbound::parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());
        let config = Arc::new(self.config);

        info!(
            tag = %tag,
            addr = %bind,
            tls = tls_acceptor.is_some(),
            auth = if config.users.is_empty() { "none" } else { "basic" },
            "http-server inbound starting"
        );

        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "http-server inbound accept error");
                    continue;
                }
            };

            // 提前 try_clone 原始 TCP：TLS 路径下 SniffedStream 需要 raw_tcp
            // 保留 Drop-RST 语义；明文路径下也可直接复用。
            let raw = stream.try_clone().ok();
            let tcp_tx = self.tcp_tx.clone();
            let tag = tag.clone();
            let config = config.clone();
            let acc = tls_acceptor.clone();

            tokio::spawn(async move {
                let result = match acc {
                    None => handle(stream, raw, peer, config, tcp_tx, tag).await,
                    Some(acc) => match acc.accept(stream).await {
                        Ok(tls) => handle(tls, raw, peer, config, tcp_tx, tag).await,
                        Err(e) => {
                            // 客户端发来非 TLS 流量属正常现象，记 debug
                            debug!(
                                peer = %display_sockaddr(peer),
                                err = %e,
                                "http-server TLS handshake failed"
                            );
                            return Ok(());
                        }
                    },
                };
                if let Err(e) = result {
                    debug!(peer = %display_sockaddr(peer), err = %e, "http-server conn error");
                }
                Ok::<(), anyhow::Error>(())
            });
        }
    }
}

async fn handle<S>(
    stream: S,
    raw: Option<TcpStream>,
    peer: SocketAddr,
    config: Arc<HttpServerInboundConfig>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(stream);
    let (request_line, headers) = read_headers(&mut reader).await?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target_raw = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if method.is_empty() || target_raw.is_empty() {
        anyhow::bail!("malformed request line: {request_line:?}");
    }

    // ── 鉴权 ─────────────────────────────────────────────────────────────────
    if !config.users.is_empty() {
        let auth_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, v)| v.as_str());

        if !check_basic_auth(auth_header, &config.users) {
            let mut w = reader.into_inner();
            let body = b"Proxy Authentication Required";
            let resp = format!(
                "HTTP/1.1 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"reflex\"\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let _ = w.write_all(resp.as_bytes()).await;
            let _ = w.write_all(body).await;
            let _ = w.shutdown().await;
            anyhow::bail!("auth failed from {}", display_sockaddr(peer));
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.1 —— target 本身就是 "host:port"
        let target = parse_connect_target(&target_raw)?;
        // BufReader 内部缓冲区里可能已经读入了紧跟在 CONNECT 请求头之后的数据
        // （比如客户端把 CONNECT 请求和 TLS ClientHello 粘在同一个 TCP 包里发送）。
        // into_inner() 会直接丢弃这部分缓冲，必须先取出来，隧道建立后原样转发。
        let leftover = reader.buffer().to_vec();
        let mut inner = reader.into_inner();
        inner
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let mut sniffed = SniffedStream::from_encrypted(Box::new(inner), peer, raw);
        if !leftover.is_empty() {
            sniffed.prepend(Bytes::from(leftover));
        }
        info!(
            peer = %display_sockaddr(peer),
            target = %target,
            tag = %tag,
            "http-server CONNECT"
        );
        tcp_tx
            .send(InboundTcpStream {
                stream: sniffed,
                target,
                inbound_tag: (*tag).clone(),
                sniffed_protocol: None,
                sniffed_domain: None,
            })
            .await
            .ok();
        return Ok(());
    }

    // ── 普通方法（GET/POST/...），绝对 URI 转发 ─────────────────────────────────
    let (target, path_and_query) = parse_absolute_uri(&target_raw)?;
    info!(
        peer = %display_sockaddr(peer),
        method = %method,
        target = %target,
        tag = %tag,
        "http-server forward"
    );

    // 把请求行改写成 origin-form（去掉绝对 URI 里的 scheme://host 部分），
    // 剥离给代理自己看的 Proxy-* 头，再把剩余的连接数据（可能含请求体）
    // 作为前缀交给 dispatcher 路由后的出站，由上游按
    // Content-Length / chunked 处理。
    let mut rewritten = Vec::new();
    rewritten.extend_from_slice(format!("{method} {path_and_query} {version}\r\n").as_bytes());
    for (k, v) in &headers {
        // Proxy-* 头是给代理自己看的，不透传给上游
        if k.eq_ignore_ascii_case("proxy-authorization")
            || k.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        rewritten.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    rewritten.extend_from_slice(b"\r\n");
    // 请求体（POST body 等）可能已经被 BufReader 提前读入内部缓冲区，
    // 必须拼在前缀之后原样保留，否则请求体开头会丢字节。
    rewritten.extend_from_slice(reader.buffer());

    let inner = reader.into_inner();
    let mut sniffed = SniffedStream::from_encrypted(Box::new(inner), peer, raw);
    sniffed.prepend(Bytes::from(rewritten));
    tcp_tx
        .send(InboundTcpStream {
            stream: sniffed,
            target,
            inbound_tag: (*tag).clone(),
            sniffed_protocol: None,
            sniffed_domain: None,
        })
        .await
        .ok();

    Ok(())
}

/// 读取请求行 + headers（直到空行），返回 (request_line, [(header_name, header_value)]).
/// 消耗掉的字节不含 body —— body（如果有）留在底层流/BufReader 缓冲里，由后续转发逻辑处理。
async fn read_headers<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> anyhow::Result<(String, Vec<(String, String)>)> {
    let mut total = 0usize;
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .map_err(|e| anyhow::anyhow!("read request line: {e}"))?;
    total += request_line.len();
    let request_line = request_line.trim_end().to_string();
    if request_line.is_empty() {
        anyhow::bail!("empty request line");
    }

    let mut headers = Vec::new();
    loop {
        if headers.len() > MAX_HEADER_LINES || total > MAX_HEADER_BYTES {
            anyhow::bail!("header too large");
        }
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| anyhow::anyhow!("read header line: {e}"))?;
        if n == 0 {
            anyhow::bail!("connection closed while reading headers");
        }
        total += n;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Ok((request_line, headers))
}

/// 校验 `Proxy-Authorization: Basic base64(user:pass)` 是否命中用户列表。
fn check_basic_auth(header: Option<&str>, users: &[crate::config::inbound::AuthUser]) -> bool {
    use base64::Engine;

    let Some(header) = header else { return false };
    let Some(b64) = header.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, pass)) = decoded.split_once(':') else {
        return false;
    };
    users
        .iter()
        .any(|u| u.username == user && u.password == pass)
}

/// 解析 CONNECT 的 target（`host:port` / `[IPv6]:port`）为 [`Target`]。
/// 保持域名形式交给路由层处理 DNS（与 flux 语义一致：只校验端口存在）。
fn parse_connect_target(raw: &str) -> anyhow::Result<Target> {
    // [IPv6]:port
    if let Some(rest) = raw.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 literal in CONNECT target: {raw:?}"))?;
        let host = &rest[..end];
        let port_str = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("CONNECT target missing port: {raw:?}"))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid port in CONNECT target: {raw:?}"))?;
        return Ok(Target::Domain(host.to_string(), port));
    }
    let (host, port_str) = raw
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("CONNECT target missing port: {raw:?}"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid port in CONNECT target: {raw:?}"))?;
    Ok(Target::Domain(host.to_string(), port))
}

/// 把 `http://host[:port]/path?query` 拆成 ([`Target`], `/path?query`)。
/// 仅支持绝对 URI 形式（标准代理请求的写法）；https 流量应走 CONNECT。
fn parse_absolute_uri(raw: &str) -> anyhow::Result<(Target, String)> {
    let rest = raw.strip_prefix("http://").ok_or_else(|| {
        anyhow::anyhow!("only absolute http:// URIs are supported as a plain proxy: {raw:?}")
    })?;

    let (authority, path_and_query) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    // authority 已含端口（host:port / [IPv6]:port）则直接解析，
    // 否则按 HTTP 默认端口 80 补齐（与 flux 行为一致）
    let target = if authority.contains(':') {
        parse_connect_target(authority)?
    } else {
        parse_connect_target(&format!("{authority}:80"))?
    };

    Ok((target, path_and_query.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_target_host_port() {
        let t = parse_connect_target("example.com:443").unwrap();
        assert!(matches!(t, Target::Domain(ref h, 443) if h == "example.com"));
    }

    #[test]
    fn connect_target_ipv6() {
        let t = parse_connect_target("[2001:db8::1]:8443").unwrap();
        assert!(matches!(t, Target::Domain(ref h, 8443) if h == "2001:db8::1"));
    }

    #[test]
    fn connect_target_missing_port() {
        assert!(parse_connect_target("example.com").is_err());
    }

    #[test]
    fn connect_target_invalid_port() {
        assert!(parse_connect_target("example.com:abc").is_err());
    }

    #[test]
    fn absolute_uri_default_port() {
        let (t, path) = parse_absolute_uri("http://example.com/path?x=1").unwrap();
        assert!(matches!(t, Target::Domain(ref h, 80) if h == "example.com"));
        assert_eq!(path, "/path?x=1");
    }

    #[test]
    fn absolute_uri_explicit_port() {
        let (t, path) = parse_absolute_uri("http://example.com:8080/").unwrap();
        assert!(matches!(t, Target::Domain(ref h, 8080) if h == "example.com"));
        assert_eq!(path, "/");
    }

    #[test]
    fn absolute_uri_rejects_https() {
        assert!(parse_absolute_uri("https://example.com/").is_err());
    }

    #[test]
    fn absolute_uri_origin_only() {
        // 无 path 时回退 "/"
        let (t, path) = parse_absolute_uri("http://example.com").unwrap();
        assert!(matches!(t, Target::Domain(ref h, 80) if h == "example.com"));
        assert_eq!(path, "/");
    }

    #[test]
    fn basic_auth_ok() {
        let users = vec![crate::config::inbound::AuthUser {
            username: "admin".into(),
            password: "secret".into(),
        }];
        // base64("admin:secret") = "YWRtaW46c2VjcmV0"
        assert!(check_basic_auth(Some("Basic YWRtaW46c2VjcmV0"), &users));
        assert!(!check_basic_auth(Some("Basic WRONg=="), &users));
        assert!(!check_basic_auth(Some("Bearer xyz"), &users));
        assert!(!check_basic_auth(None, &users));
    }
}
