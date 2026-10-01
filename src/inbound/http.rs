use std::net::SocketAddr;
use std::sync::Arc;

use base64::{engine::general_purpose, Engine};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};
use tracing::{debug, error, info};

use crate::{
    config::inbound::{AuthUser, HttpInboundConfig},
    inbound::{display_sockaddr, InboundTcpStream, SniffedStream, Target},
};

pub struct HttpInbound {
    config: HttpInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl HttpInbound {
    pub fn new(config: HttpInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            crate::inbound::parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());
        let config = Arc::new(self.config);

        info!(tag = %tag, addr = %bind, "http inbound starting");

        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "http inbound accept error");
                    continue;
                }
            };

            let tcp_tx = self.tcp_tx.clone();
            let tag = tag.clone();
            let config = config.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_http(stream, peer, config, tcp_tx, tag).await {
                    debug!(peer = %display_sockaddr(peer), err = %e, "http inbound conn error");
                }
            });
        }
    }
}

const MAX_HEADER_TOTAL: usize = 65536;

/// 407 Proxy Authentication Required 响应
const RESP_407: &str =
    "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n";

async fn handle_http(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    config: Arc<HttpInboundConfig>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // 读取请求头直到 \r\n\r\n，同时保留可能的 body 起始字节
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("HTTP client closed before sending complete headers");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        anyhow::ensure!(
            buf.len() <= MAX_HEADER_TOTAL,
            "HTTP headers too large (>{MAX_HEADER_TOTAL})"
        );
    }

    let request = std::str::from_utf8(&buf[..header_end])?;

    // ── 认证检查 ──────────────────────────────────────────────────────────────
    if !config.users.is_empty() {
        let auth_header = find_header(request, "proxy-authorization");
        match auth_header.and_then(parse_basic_auth) {
            Some((user, pass)) => {
                if !check_auth(&config.users, &user, &pass) {
                    stream.write_all(RESP_407.as_bytes()).await?;
                    anyhow::bail!("HTTP proxy auth failed");
                }
            }
            None => {
                stream.write_all(RESP_407.as_bytes()).await?;
                anyhow::bail!("HTTP proxy auth required");
            }
        }
    }

    // ── 解析目标 ──────────────────────────────────────────────────────────────
    let (target, is_connect) = match parse_http_request(request) {
        Ok(v) => v,
        Err(e) => {
            // 畸形请求：回 400 Bad Request 后关闭连接
            let _ = stream
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            anyhow::bail!("malformed HTTP request: {e}");
        }
    };

    debug!(peer = %display_sockaddr(peer), target = %target, connect = is_connect, "http request");

    if is_connect {
        // CONNECT 隧道：先回复 200，再透传
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let mut sniffed = SniffedStream::new(stream);
        // CONNECT 客户端通常等 200 后才发数据，但以防万一保留 header 之后的字节
        if buf.len() > header_end {
            sniffed.prepend(bytes::Bytes::copy_from_slice(&buf[header_end..]));
        }
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
    } else {
        // 普通转发代理：RFC 7230 §5.3.2 要求把 absolute-form 请求行改写为 origin-form
        // `GET http://example.com/path HTTP/1.1` → `GET /path HTTP/1.1` + `Host: example.com`
        let rewritten = rewrite_request_for_forward(request, &buf, header_end);
        let mut sniffed = SniffedStream::new(stream);
        sniffed.prepend(rewritten);
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
    }

    Ok(())
}

/// 解析 absolute-form URI（`http://host:port/path` 或 `https://host:port/path`）。
/// 返回 Target::Domain。端口未指定时 http→80，https→443。
fn parse_absolute_uri(uri: &str) -> Option<Target> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))?;
    // 取 // 之后到第一个 / 之前的部分作为 authority
    let authority = match rest.find('/') {
        Some(pos) => &rest[..pos],
        None => rest,
    };
    let default_port = if uri.starts_with("https://") { 443 } else { 80 };
    let (host, port) = parse_host_port(authority, default_port).ok()?;
    Some(Target::Domain(host, port))
}

/// 解析 `host:port` / `[IPv6]:port` / `host`（无端口）格式。
/// 返回 (host_without_brackets, port)。
/// - `[::1]:443` → (`::1`, 443)
/// - `example.com:443` → (`example.com`, 443)
/// - `example.com` → (`example.com`, default_port)
fn parse_host_port(s: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    // IPv6 字面量：[...]:port 或 [...]
    if let Some(rest) = s.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            if let Some(port_str) = after.strip_prefix(':') {
                let port: u16 = port_str
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid port in '{s}'"))?;
                return Ok((host.to_string(), port));
            }
            return Ok((host.to_string(), default_port));
        }
        anyhow::bail!("malformed IPv6 literal: '{s}'");
    }
    // 普通 host:port
    match s.rsplit_once(':') {
        Some((host, port_str)) => {
            // 端口必须是纯数字，否则当作 host 含冒号（不应该）
            match port_str.parse::<u16>() {
                Ok(port) => Ok((host.to_string(), port)),
                Err(_) => Ok((s.to_string(), default_port)),
            }
        }
        None => Ok((s.to_string(), default_port)),
    }
}

/// 为转发代理改写请求：把 absolute-form 请求行转为 origin-form。
/// 输入：原始请求文本 + 原始 buf 字节 + header_end 位置。
/// 输出：改写后的完整请求字节（请求行已改写，headers 不变，含 header 之后的 body 起始字节）。
///
/// 若请求行不是 absolute-form，原样返回 buf 的拷贝。
fn rewrite_request_for_forward(request: &str, buf: &[u8], header_end: usize) -> bytes::Bytes {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return bytes::Bytes::copy_from_slice(buf);
    }
    let method = parts[0];
    let target = parts[1];
    let version = parts[2];

    // 仅处理 absolute-form（http:// 或 https:// 开头）
    if !target.starts_with("http://") && !target.starts_with("https://") {
        return bytes::Bytes::copy_from_slice(buf);
    }

    // 提取 path（含 query）：http://host[:port]/path?query → /path?query
    let after_scheme = target
        .split_once("://")
        .map(|(_, after)| after)
        .unwrap_or("");
    let path = match after_scheme.find('/') {
        Some(pos) => &after_scheme[pos..],
        None => "/",
    };

    // 构造新请求行：METHOD SP path SP version
    let new_first_line = format!("{method} {path} {version}");
    let new_first_line_bytes = new_first_line.as_bytes();

    // 找到原始 buf 中第一行结束位置（第一个 \n）
    let first_line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(header_end);

    // 拼接：新请求行 + 原始 buf 中第一行之后的所有内容（含其余 headers + body）
    let mut out = Vec::with_capacity(new_first_line_bytes.len() + (buf.len() - first_line_end));
    out.extend_from_slice(new_first_line_bytes);
    out.extend_from_slice(&buf[first_line_end..]);
    bytes::Bytes::from(out)
}

/// 在 buf 中查找 headers 结束位置（`\r\n\r\n` 或 `\n\n` 的末尾）
fn find_header_end(buf: &[u8]) -> Option<usize> {
    // 优先匹配 \r\n\r\n（标准 HTTP），其次匹配 \n\n（容忍裸 LF 客户端）
    // 必须先检查 \r\n\r\n，否则 \n\n 会把 \r\n\r\n 的后两个字节误判为 \n\n
    if buf.len() >= 4 {
        for i in 0..=buf.len() - 4 {
            if &buf[i..i + 4] == b"\r\n\r\n" {
                return Some(i + 4);
            }
        }
    }
    if buf.len() >= 2 {
        for i in 0..buf.len() - 1 {
            if &buf[i..i + 2] == b"\n\n" {
                return Some(i + 2);
            }
        }
    }
    None
}

/// 解析 HTTP 请求，返回 (目标地址, 是否为 CONNECT)
fn parse_http_request(request: &str) -> anyhow::Result<(Target, bool)> {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    anyhow::ensure!(parts.len() >= 2, "malformed HTTP request line");

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.1（支持 [IPv6]:port 形式）
        let (host, port) = parse_host_port(target, 443)?;
        return Ok((Target::Domain(host, port), true));
    }

    // 非 CONNECT：可能是 absolute-form（GET http://example.com/path HTTP/1.1）
    // 或 origin-form（GET /path HTTP/1.1）+ Host 头
    if let Some(t) = parse_absolute_uri(target) {
        return Ok((t, false));
    }

    // 从 Host 头提取目标（大小写不敏感）
    if let Some(host_str) = find_header(request, "host") {
        let (host, port) = parse_host_port(host_str, 80)?;
        return Ok((Target::Domain(host, port), false));
    }

    anyhow::bail!("no Host header in HTTP request")
}

/// 在请求头中查找指定 header（大小写不敏感）
fn find_header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    for line in request.lines().skip(1) {
        if let Some(colon) = line.find(':') {
            if line[..colon].eq_ignore_ascii_case(name) {
                return Some(line[colon + 1..].trim());
            }
        }
    }
    None
}

/// 解析 `Basic <base64(user:pass)>` 格式的认证信息
fn parse_basic_auth(header_value: &str) -> Option<(String, String)> {
    // scheme 大小写不敏感（RFC 7617 §2.1）
    let (scheme, rest) = header_value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let decoded = general_purpose::STANDARD.decode(rest.trim()).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// 校验用户名/密码
fn check_auth(users: &[AuthUser], username: &str, password: &str) -> bool {
    users
        .iter()
        .any(|u| u.username == username && u.password == password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (t, is_connect) = parse_http_request(req).unwrap();
        assert!(is_connect);
        assert!(matches!(t, Target::Domain(ref h, 443) if h == "example.com"));
    }

    #[test]
    fn parse_absolute_uri_http() {
        let req = "GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (t, is_connect) = parse_http_request(req).unwrap();
        assert!(!is_connect);
        assert!(matches!(t, Target::Domain(ref h, 80) if h == "example.com"));
    }

    #[test]
    fn parse_absolute_uri_https_port() {
        let req = "GET https://example.com:8443/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (t, _) = parse_http_request(req).unwrap();
        assert!(matches!(t, Target::Domain(ref h, 8443) if h == "example.com"));
    }

    #[test]
    fn parse_absolute_uri_default_https() {
        let t = parse_absolute_uri("https://example.com/path").unwrap();
        assert!(matches!(t, Target::Domain(ref h, 443) if h == "example.com"));
    }

    #[test]
    fn parse_origin_form_with_host() {
        let req = "GET /path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let (t, is_connect) = parse_http_request(req).unwrap();
        assert!(!is_connect);
        assert!(matches!(t, Target::Domain(ref h, 8080) if h == "example.com"));
    }

    #[test]
    fn parse_origin_form_default_port() {
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (t, _) = parse_http_request(req).unwrap();
        assert!(matches!(t, Target::Domain(ref h, 80) if h == "example.com"));
    }

    #[test]
    fn basic_auth_parse() {
        // base64("admin:secret") = "YWRtaW46c2VjcmV0"
        let v = "Basic YWRtaW46c2VjcmV0";
        let (u, p) = parse_basic_auth(v).unwrap();
        assert_eq!(u, "admin");
        assert_eq!(p, "secret");
    }

    #[test]
    fn auth_check() {
        let users = vec![
            AuthUser {
                username: "admin".into(),
                password: "secret".into(),
            },
            AuthUser {
                username: "guest".into(),
                password: "pass".into(),
            },
        ];
        assert!(check_auth(&users, "admin", "secret"));
        assert!(check_auth(&users, "guest", "pass"));
        assert!(!check_auth(&users, "admin", "wrong"));
        assert!(!check_auth(&users, "unknown", "secret"));
    }

    #[test]
    fn find_header_case_insensitive() {
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic abc\r\n\r\n";
        assert_eq!(find_header(req, "proxy-authorization"), Some("Basic abc"));
        assert_eq!(find_header(req, "HOST"), Some("example.com"));
        assert_eq!(find_header(req, "x-custom"), None);
    }

    #[test]
    fn header_end_detection() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nbody"),
            Some(27)
        );
    }
}
