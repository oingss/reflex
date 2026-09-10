use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::outbound::Outbound;

use super::dot::dot_tls_on_boxed;

fn set_doh_query_id_zero(msg: Bytes) -> (Bytes, u16) {
    if msg.len() < 2 {
        return (msg, 0);
    }
    let original_id = u16::from_be_bytes([msg[0], msg[1]]);
    let mut buf = msg.to_vec();
    buf[0] = 0;
    buf[1] = 0;
    (Bytes::from(buf), original_id)
}

fn restore_doh_response_id(resp: Bytes, original_id: u16) -> Bytes {
    if resp.len() < 2 {
        return resp;
    }
    let mut buf = resp.to_vec();
    buf[0..2].copy_from_slice(&original_id.to_be_bytes());
    Bytes::from(buf)
}

/// 带连接池的直连 DoH 查询（对齐 sing-box http2.Transport 自动池化）。
///
/// HTTP/2 支持多路复用，一个 h2 连接可并发多个请求。
///
/// **池化策略（已修复 take/put 浪费连接 bug）**：
///
/// `h2::client::SendRequest` 是 `Clone` 的，多个 clone 共享底层 h2 连接。
/// 因此采用 **clone 模式**而非 take/put：
/// - 从 pool 中 clone 一份 `SendRequest`（如已有）；否则新建 TCP+TLS+h2 并存一份 clone 到 pool
/// - 使用自己的 clone 发送请求；pool 中的那份保持存活供下次复用
/// - 失败时通过 `pool_reset` 让 pool 整体重建（避免卡死连接被反复复用）
///
/// 这避免了旧实现「take 后并发 caller 看到 None 各自新建，第一个归还者的连接被 drop」的浪费。
///
/// **修复 SO_MARK 应用 bug**：旧实现直接 `TcpStream::connect` 后未应用 `routing_mark`，
/// 配置了 mark 的环境下 DoH 不会绑定正确网卡。现增加 `mark` 参数。
///
/// **修复 IPv6 host 带括号致 SNI 无效 bug**：parse_doh_url 返回的 host 不再带 `[]`。
///
/// **修复 URI 默认端口 bug**：port==443 时不写入 `:443`（对齐 sing-box）。
///
/// **新增超时重置 pool 行为**：调用方在外层 timeout 失败时调用 pool 的 reset。
#[allow(clippy::too_many_arguments)]
pub(super) async fn doh_query_pooled_direct(
    ip: IpAddr,
    host: &str,
    port: u16,
    path: &str,
    tls_cfg: std::sync::Arc<rustls::ClientConfig>,
    msg: Bytes,
    pool: &tokio::sync::Mutex<Option<h2::client::SendRequest<Bytes>>>,
    mark: u32,
) -> anyhow::Result<Bytes> {
    // 重写 query ID 为 0（对齐 sing-box https.go:176 + RFC 8484 §4.2 SHOULD）
    let (msg, original_id) = set_doh_query_id_zero(msg);

    // 1. 从 pool 中 clone 一份 SendRequest（如已有）
    //    若 pool 为空，会进入 None 分支新建连接
    let send_req_owned: h2::client::SendRequest<Bytes> = {
        let guard = pool.lock().await;
        match guard.as_ref() {
            Some(sr) => sr.clone(),
            None => {
                drop(guard);
                // 新建 TCP + TLS + h2 handshake
                let addr = SocketAddr::new(ip, port);
                // 连接前绑定物理网卡（Windows IP_UNICAST_IF / macOS IP_BOUND_IF），
                // 对齐 sing-box：SYN 发出后再事后绑定在 TUN auto_route 下无效。
                let tcp = crate::outbound::connect_tcp_interface(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("DoH TCP connect to {addr} failed: {e}"))?;
                // 修复 SO_MARK 应用：与 DoT/DoQ 对齐，必须在 h2 handshake 之前应用
                crate::outbound::apply_mark_to_tcp(&tcp, mark)?;

                let mut cfg = (*tls_cfg).clone();
                cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                let cfg = std::sync::Arc::new(cfg);

                let tls = crate::outbound::tls::connect_tls(tcp, host, cfg)
                    .await
                    .map_err(|e| anyhow::anyhow!("DoH TLS handshake with {host} failed: {e}"))?;

                let negotiated = tls.get_ref().1.alpn_protocol();
                if negotiated != Some(b"h2") {
                    // 服务器不支持 h2，回退到无连接池的 h1 查询
                    let resp = doh_h1_query(tls, host, port, path, msg).await?;
                    return Ok(restore_doh_response_id(resp, original_id));
                }

                let (send_req, conn) = h2::client::handshake(tls)
                    .await
                    .map_err(|e| anyhow::anyhow!("h2 handshake failed: {e}"))?;
                // 后台驱动 h2 连接
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                // 把一份 clone 存入 pool 供下次复用，本次查询用另一份 clone
                let mut guard = pool.lock().await;
                *guard = Some(send_req.clone());
                send_req
            }
        }
    };

    // 2. 发送请求（使用自己的 send_req_owned，不与 pool 共享所有权）
    //    port==443 时不写入端口（对齐 sing-box https.go:85-87）
    //    IPv6 地址加方括号（RFC 3986 §3.2.2），修复旧实现对 IPv6 未 bracket 的 bug
    let authority = build_http_authority(host, port);
    let uri = format!("https://{authority}{path}")
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("invalid DoH URI: {e}"))?;

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", msg.len().to_string())
        .body(())
        .map_err(|e| anyhow::anyhow!("h2 request build failed: {e}"))?;

    // SendRequest::ready() 消费 self 并在 await 后归还 ReadySendRequest，
    // 而 ReadySendRequest::send_request 返回 (ResponseFuture, SendStream<Bytes>)。
    // SendRequest 实现 Clone，因此可以 clone 一份留在 pool 中，本次查询用另一份。
    let mut send_req = match send_req_owned.ready().await {
        Ok(r) => r,
        Err(e) => {
            debug!(host=%host, err=%e, "DoH h2 query failed (ready), resetting pool");
            // 连接已坏，清空 pool 让下次重建
            *pool.lock().await = None;
            return Err(anyhow::anyhow!("h2 send_request not ready: {e}"));
        }
    };
    let (resp_future, mut send_stream) = match send_req.send_request(req, false) {
        Ok(pair) => pair,
        Err(e) => {
            debug!(host=%host, err=%e, "DoH h2 query failed (send_request), resetting pool");
            *pool.lock().await = None;
            return Err(anyhow::anyhow!("h2 send_request failed: {e}"));
        }
    };
    if let Err(e) = send_stream.send_data(msg, true) {
        debug!(host=%host, err=%e, "DoH h2 query failed (send_data), resetting pool");
        *pool.lock().await = None;
        return Err(anyhow::anyhow!("h2 send_data failed: {e}"));
    }
    let response = match resp_future.await {
        Ok(r) => r,
        Err(e) => {
            debug!(host=%host, err=%e, "DoH h2 query failed (response), resetting pool");
            *pool.lock().await = None;
            return Err(anyhow::anyhow!("h2 response failed: {e}"));
        }
    };
    let status = response.status();
    if status != http::StatusCode::OK {
        debug!(host=%host, status=%status, "DoH h2 query failed (status), resetting pool");
        *pool.lock().await = None;
        return Err(anyhow::anyhow!("DoH h2 server returned non-200: {status}"));
    }
    let mut body = response.into_parts().1;
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        match chunk {
            Ok(c) => data.extend_from_slice(&c),
            Err(e) => {
                debug!(host=%host, err=%e, "DoH h2 query failed (body), resetting pool");
                *pool.lock().await = None;
                return Err(anyhow::anyhow!("h2 body read failed: {e}"));
            }
        }
    }
    Ok(restore_doh_response_id(Bytes::from(data), original_id))
}

/// 经 detour 的 DoH：通过 CONNECT 隧道建立 TCP，再套 TLS，再做 HTTP。
pub(super) async fn doh_query_via_detour(
    outbound: &dyn Outbound,
    host: &str,
    port: u16,
    path: &str,
    tls_cfg: std::sync::Arc<rustls::ClientConfig>,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    // 重写 query ID 为 0（对齐 sing-box https.go:176 + RFC 8484 §4.2 SHOULD）
    let (msg, original_id) = set_doh_query_id_zero(msg);

    let tcp_stream = outbound.connect_tcp(host, port).await?;

    let mut cfg = (*tls_cfg).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let cfg = std::sync::Arc::new(cfg);

    let tls = dot_tls_on_boxed(tcp_stream, host, cfg)
        .await
        .map_err(|e| anyhow::anyhow!("DoH TLS handshake via detour with {host} failed: {e}"))?;

    let negotiated = tls.get_ref().1.alpn_protocol();
    let resp = if negotiated == Some(b"h2") {
        doh_h2_query(tls, host, port, path, msg).await?
    } else {
        doh_h1_query(tls, host, port, path, msg).await?
    };
    Ok(restore_doh_response_id(resp, original_id))
}

/// HTTP/1.1 DoH（application/dns-message POST），Connection: close 模式。
pub(super) async fn doh_h1_query<S>(
    mut stream: S,
    host: &str,
    port: u16,
    path: &str,
    msg: Bytes,
) -> anyhow::Result<Bytes>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let body = msg.as_ref();
    // 修复 Host 头：port==443 时不写入端口；IPv6 地址加方括号。
    // 对齐 sing-box https.go:78-87 的 authority 构建逻辑。
    let authority = build_http_authority(host, port);
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Content-Type: application/dns-message\r\n\
         Accept: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    // 读取全部响应（Connection: close 保证服务端关闭连接后 read_to_end 返回）
    let mut resp_buf = Vec::with_capacity(4096);
    stream.read_to_end(&mut resp_buf).await?;

    parse_doh_http_response(&resp_buf)
}

/// HTTP/2 DoH，复用单个 h2 连接。
pub(super) async fn doh_h2_query<S>(
    stream: S,
    host: &str,
    port: u16,
    path: &str,
    msg: Bytes,
) -> anyhow::Result<Bytes>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    use h2::client;

    let (send_req, conn) = client::handshake(stream)
        .await
        .map_err(|e| anyhow::anyhow!("h2 handshake failed: {e}"))?;
    // 在后台驱动连接
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let uri = format!("https://{}{path}", build_http_authority(host, port))
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("invalid DoH URI: {e}"))?;

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", msg.len().to_string())
        .body(())
        .map_err(|e| anyhow::anyhow!("h2 request build failed: {e}"))?;

    // ready() 消费 send_req 并返回 ReadySendRequest，send_request() 在其上调用
    let mut ready = send_req
        .ready()
        .await
        .map_err(|e| anyhow::anyhow!("h2 send_request not ready: {e}"))?;
    let (resp_future, mut send_stream) = ready
        .send_request(req, false)
        .map_err(|e| anyhow::anyhow!("h2 send_request failed: {e}"))?;

    send_stream
        .send_data(msg, true)
        .map_err(|e| anyhow::anyhow!("h2 send_data failed: {e}"))?;

    let mut response = resp_future
        .await
        .map_err(|e| anyhow::anyhow!("h2 response failed: {e}"))?;

    let status = response.status();
    anyhow::ensure!(
        status == http::StatusCode::OK,
        "DoH h2 server returned non-200: {status}"
    );

    let body = response.body_mut();
    let mut data = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(|e| anyhow::anyhow!("h2 body read failed: {e}"))?;
        data.extend_from_slice(&chunk);
    }

    Ok(Bytes::from(data))
}

/// 解析 HTTP/1.x 响应，提取 body。
///
/// **修复 status code 解析 bug**：旧实现使用 `status_line.contains("200")` 模糊匹配，
/// 可能将 `HTTP/1.1 1200 OK`、`HTTP/1.1 2000 ...`、reason phrase 中含 "200" 的非 200
/// 响应误判为成功。改为严格按 RFC 7230 §3.1.2 状态行格式
/// `HTTP-Version SP Status-Code SP Reason-Phrase` 解析 3 位状态码。
///
/// **新增 chunked 传输编码支持**：旧实现只识别 Content-Length，依赖
/// `Connection: close` 让 `read_to_end` 读到 EOF。但 RFC 7230 §6.3 允许 server
/// 即使在 `Connection: close` 下也使用 `Transfer-Encoding: chunked`。新增 dechunk
/// 解码以兼容这种场景。
pub(super) fn parse_doh_http_response(resp: &[u8]) -> anyhow::Result<Bytes> {
    let header_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("malformed DoH HTTP response: no header boundary"))?;

    // 状态行：从开头到第一个 \r
    let status_line_end = resp.iter().position(|&b| b == b'\r').unwrap_or(header_end);
    let status_line = std::str::from_utf8(&resp[..status_line_end])
        .map_err(|_| anyhow::anyhow!("DoH status line not UTF-8"))?;
    let status_code = parse_http_status_code(status_line)
        .ok_or_else(|| anyhow::anyhow!("malformed DoH HTTP status line: {status_line}"))?;
    anyhow::ensure!(
        status_code == 200,
        "DoH server returned non-200: {status_line}"
    );

    let body_start = header_end + 4;

    // 解析 headers：Content-Length 与 Transfer-Encoding
    let headers_str = std::str::from_utf8(&resp[..header_end]).unwrap_or("");
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    // 跳过第一行（状态行）
    for line in headers_str.lines().skip(1) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_lower = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name_lower == "content-length" {
            content_length = value.parse::<usize>().ok();
        } else if name_lower == "transfer-encoding"
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    // 优先 chunked（RFC 7230 §6.3：Transfer-Encoding 优先于 Content-Length）
    if chunked {
        let body = dechunk(&resp[body_start..])
            .map_err(|e| anyhow::anyhow!("DoH chunked decode failed: {e}"))?;
        anyhow::ensure!(!body.is_empty(), "DoH response body is empty (chunked)");
        return Ok(Bytes::from(body));
    }

    let body = if let Some(len) = content_length {
        anyhow::ensure!(
            body_start + len <= resp.len(),
            "DoH response body truncated (expected {len} bytes)"
        );
        &resp[body_start..body_start + len]
    } else {
        // 无明确长度：读至 EOF（caller 已 read_to_end）
        &resp[body_start..]
    };

    anyhow::ensure!(!body.is_empty(), "DoH response body is empty");
    Ok(Bytes::copy_from_slice(body))
}

/// 解析 HTTP 状态行 `HTTP/<version> SP <status-code> [SP <reason-phrase>]`，
/// 返回 3 位状态码。修复旧实现 `contains("200")` 模糊匹配 bug。
fn parse_http_status_code(line: &str) -> Option<u16> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let code_str = parts.next()?;
    code_str.parse::<u16>().ok()
}

/// HTTP/1.1 chunked transfer-encoding 解码（RFC 7230 §4.1）。
/// 输入为响应 body 部分（header 边界后的内容），输出拼接后的解码 body。
fn dechunk(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0usize;
    while pos < input.len() {
        // 读取 chunk size 行（hex digits 直到 `;` chunk extension 或 `\r\n`）
        let line_end = input[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow::anyhow!("chunk size line missing CRLF"))?;
        let size_str = std::str::from_utf8(&input[pos..pos + line_end])
            .map_err(|_| anyhow::anyhow!("chunk size not UTF-8"))?;
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| anyhow::anyhow!("invalid chunk size: {size_str}"))?;
        pos += line_end + 2; // 跳过 size 行 + \r\n
        if chunk_size == 0 {
            // 最后一个 chunk（trailer headers 后跟 \r\n，这里不解析 trailer）
            break;
        }
        anyhow::ensure!(
            pos + chunk_size <= input.len(),
            "chunk body truncated (expected {chunk_size} bytes)"
        );
        out.extend_from_slice(&input[pos..pos + chunk_size]);
        pos += chunk_size;
        // 跳过 chunk 后的 \r\n
        if pos + 2 <= input.len() && &input[pos..pos + 2] == b"\r\n" {
            pos += 2;
        } else {
            return Err(anyhow::anyhow!("chunk trailer CRLF missing"));
        }
    }
    Ok(out)
}

// ── HTTP authority 构建 ───────────────────────────────────────────────────────

/// 构建 HTTP/1.1 `Host` 头或 HTTP/2 `:authority` 伪头用的 authority 字符串。
///
/// 对齐 sing-box `https.go:78-87` 的行为：
/// - 端口为 443（HTTPS 默认端口）时省略端口号
/// - IPv6 地址加方括号（RFC 3986 §3.2.2：IPv6 地址在 URI 中必须 bracket）
///
/// **修复两个 bug**：
/// 1. 旧 `doh_h1_query` / `doh_h2_query` 总是写入 `:port`，对 443 也写入，
///    与 sing-box 不一致，部分严格服务器会拒绝。
/// 2. 旧实现对 IPv6 地址（如 `2001:db8::1`）未加 `[]`，产生
///    `https://2001:db8::1:443/dns-query` 这种歧义/非法 URI。
fn build_http_authority(host: &str, port: u16) -> String {
    let is_ipv6 = host.parse::<std::net::Ipv6Addr>().is_ok();
    if port == 443 {
        if is_ipv6 {
            format!("[{host}]")
        } else {
            host.to_string()
        }
    } else if is_ipv6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

// ── DoH URL 解析 ──────────────────────────────────────────────────────────────

/// 解析 DoH URL，返回 (host, port, path)。
///
/// **修复 IPv6 无端口解析 bug**：
/// 旧实现用 `host_port.rfind(':')` 提取端口，对 `https://[::1]/dns-query` 会匹配到 IPv6 内部的 `:`，
/// 导致 `"1]".parse::<u16>()` 失败。修复后：
/// - IPv6（以 `[` 开头）：用 `find(']')` 定位结束位置，再判断后面是否有 `:port`
/// - IPv4/域名：用最后一个 `:` 切分（避免与 IPv6 冲突）
///
/// **修复 IPv6 host 带括号致 TLS SNI 无效 bug**：
/// 返回的 host 不再包含 `[]` 括号，直接用 IP 字符串（rustls 会识别为 IpAddress）。
pub(super) fn parse_doh_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow::anyhow!("DoH URL must start with https://: {url}"))?;

    let (host_port, path) = if let Some(pos) = rest.find('/') {
        (&rest[..pos], rest[pos..].to_string())
    } else {
        (rest, "/".to_string())
    };

    // 区分 IPv6（含括号）与 IPv4/域名
    let (host, port) = if host_port.starts_with('[') {
        // IPv6：[::1] 或 [::1]:port
        let end = host_port
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 DoH host: missing ']' in {url}"))?;
        let host = host_port[1..end].to_string(); // 去掉括号
        let after = &host_port[end + 1..];
        let port = if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("invalid DoH port in: {url}"))?
        } else if after.is_empty() {
            443u16
        } else {
            return Err(anyhow::anyhow!("malformed DoH host: {url}"));
        };
        (host, port)
    } else if let Some(pos) = host_port.rfind(':') {
        // IPv4 或域名带端口
        let port: u16 = host_port[pos + 1..]
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid DoH port in: {url}"))?;
        (host_port[..pos].to_string(), port)
    } else {
        // 无端口，默认 443
        (host_port.to_string(), 443u16)
    };

    Ok((host, port, path))
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_doh_standard() {
        let (h, p, path) = parse_doh_url("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(h, "1.1.1.1");
        assert_eq!(p, 443);
        assert_eq!(path, "/dns-query");
    }
    #[test]
    fn parse_doh_custom_port() {
        let (h, p, path) = parse_doh_url("https://dns.example.com:8443/resolve").unwrap();
        assert_eq!(h, "dns.example.com");
        assert_eq!(p, 8443);
        assert_eq!(path, "/resolve");
    }
    #[test]
    fn parse_doh_no_path() {
        let (h, p, path) = parse_doh_url("https://dns.example.com").unwrap();
        assert_eq!(h, "dns.example.com");
        assert_eq!(p, 443);
        assert_eq!(path, "/");
    }
    #[test]
    fn parse_doh_bad_scheme() {
        assert!(parse_doh_url("http://1.1.1.1/dns-query").is_err());
    }
    // 修复 IPv6 无端口解析 bug 的回归测试
    #[test]
    fn parse_doh_ipv6_no_port() {
        let (h, p, path) = parse_doh_url("https://[::1]/dns-query").unwrap();
        assert_eq!(h, "::1");
        assert_eq!(p, 443);
        assert_eq!(path, "/dns-query");
    }
    // 修复 IPv6 带端口解析 bug 的回归测试
    #[test]
    fn parse_doh_ipv6_with_port() {
        let (h, p, path) = parse_doh_url("https://[2001:db8::1]:8443/dns-query").unwrap();
        assert_eq!(h, "2001:db8::1");
        assert_eq!(p, 8443);
        assert_eq!(path, "/dns-query");
    }

    // ── parse_http_status_code 回归测试（修复 contains("200") 模糊匹配 bug）──────
    #[test]
    fn http_status_code_standard_200() {
        assert_eq!(parse_http_status_code("HTTP/1.1 200 OK"), Some(200));
    }
    #[test]
    fn http_status_code_no_reason() {
        assert_eq!(parse_http_status_code("HTTP/1.1 200"), Some(200));
    }
    #[test]
    fn http_status_code_404() {
        assert_eq!(parse_http_status_code("HTTP/1.1 404 Not Found"), Some(404));
    }
    #[test]
    fn http_status_code_1200_should_not_match_200() {
        // 旧实现 contains("200") 会误判 1200 为成功
        assert_eq!(parse_http_status_code("HTTP/1.1 1200 OK"), Some(1200));
    }
    #[test]
    fn http_status_code_reason_containing_200() {
        // 旧实现 contains("200") 会误判这种 reason phrase
        assert_eq!(
            parse_http_status_code("HTTP/1.1 500 Error 200 occurred"),
            Some(500)
        );
    }
    #[test]
    fn http_status_code_bad_format() {
        assert_eq!(parse_http_status_code("garbage"), None);
        assert_eq!(parse_http_status_code("HTTP/1.1"), None);
        assert_eq!(parse_http_status_code("HTTP/1.1 abc OK"), None);
    }

    // ── dechunk 回归测试（新增 chunked 传输编码支持）──────────────────────────
    #[test]
    fn dechunk_single_chunk() {
        // 1 chunk + 终止 chunk
        let input = b"5\r\nhello\r\n0\r\n\r\n";
        assert_eq!(dechunk(input).unwrap(), b"hello");
    }
    #[test]
    fn dechunk_multiple_chunks() {
        let input = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        assert_eq!(dechunk(input).unwrap(), b"hello world");
    }
    #[test]
    fn dechunk_with_extension() {
        // chunk extension（;name=value）应被忽略
        let input = b"5;name=value\r\nhello\r\n0\r\n\r\n";
        assert_eq!(dechunk(input).unwrap(), b"hello");
    }
    #[test]
    fn dechunk_empty_body() {
        let input = b"0\r\n\r\n";
        assert_eq!(dechunk(input).unwrap(), b"");
    }

    // ── parse_doh_http_response 回归测试 ─────────────────────────────────────
    #[test]
    fn parse_doh_resp_with_content_length() {
        let body = b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut resp = resp.into_bytes();
        resp.extend_from_slice(body);
        let parsed = parse_doh_http_response(&resp).unwrap();
        assert_eq!(parsed.as_ref(), body);
    }
    #[test]
    fn parse_doh_resp_chunked() {
        let body = b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00";
        // 把 body 切两半用 chunked 编码
        let (a, b) = body.split_at(6);
        let mut resp = "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_string()
            .into_bytes();
        resp.extend_from_slice(format!("{:x}\r\n", a.len()).as_bytes());
        resp.extend_from_slice(a);
        resp.extend_from_slice(b"\r\n");
        resp.extend_from_slice(format!("{:x}\r\n", b.len()).as_bytes());
        resp.extend_from_slice(b);
        resp.extend_from_slice(b"\r\n0\r\n\r\n");
        let parsed = parse_doh_http_response(&resp).unwrap();
        assert_eq!(parsed.as_ref(), body);
    }
    #[test]
    fn parse_doh_resp_rejects_non_200() {
        // 旧实现 contains("200") 会因 reason phrase 含 "200" 而误判
        let resp = b"HTTP/1.1 500 Error 200 occurred\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_doh_http_response(resp).is_err());
    }
    #[test]
    fn parse_doh_resp_rejects_1200() {
        // 旧实现 contains("200") 会误判 1200 为成功
        let resp = b"HTTP/1.1 1200 OK\r\nContent-Length: 0\r\n\r\n";
        assert!(parse_doh_http_response(resp).is_err());
    }

    // ── DoH query ID=0 归一化测试（对齐 RFC 8484 §4.2 SHOULD）────────────────
    #[test]
    fn doh_id_zero_rewrite() {
        // 原始报文 ID=0xABCD
        let msg = Bytes::from_static(b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_doh_query_id_zero(msg);
        assert_eq!(original_id, 0xABCD);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        // 其余字节保持不变
        assert_eq!(&rewritten[2..], b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    }
    #[test]
    fn doh_id_zero_short_msg_noop() {
        // 报文短于 2 字节：不修改，原 ID 视为 0
        let msg = Bytes::from_static(b"\xAB");
        let (rewritten, original_id) = set_doh_query_id_zero(msg);
        assert_eq!(original_id, 0);
        assert_eq!(rewritten.as_ref(), b"\xAB");
    }
    #[test]
    fn doh_response_id_restore() {
        // 响应 ID=0，恢复为原始 ID=0xABCD
        let resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00");
        let restored = restore_doh_response_id(resp, 0xABCD);
        assert_eq!(&restored[..2], b"\xAB\xCD");
        assert_eq!(&restored[2..], b"\x81\x80\x00\x00");
    }
    #[test]
    fn doh_response_id_restore_short_noop() {
        // 响应短于 2 字节：原样返回
        let resp = Bytes::from_static(b"\x00");
        let restored = restore_doh_response_id(resp, 0xABCD);
        assert_eq!(restored.as_ref(), b"\x00");
    }
    #[test]
    fn doh_id_roundtrip() {
        // 模拟完整往返：原报文 → ID=0 发送 → 响应 ID=0 → 恢复为原 ID
        let original_msg = Bytes::from_static(b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_doh_query_id_zero(original_msg.clone());
        assert_eq!(original_id, 0xABCD);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        // 服务器返回 ID=0 的响应
        let server_resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00");
        let restored_resp = restore_doh_response_id(server_resp, original_id);
        // 响应的 ID 应等于原始请求 ID
        assert_eq!(&restored_resp[..2], &original_msg[..2]);
    }

    // ── build_http_authority 回归测试 ────────────────────────────────────────
    // 修复两个 bug：
    //   (1) 旧实现对 IPv6 地址未加 `[]`，产生 `https://2001:db8::1:443/...` 非法 URI
    //   (2) 旧实现 port==443 时仍写入 `:443`，与 sing-box https.go:78-87 不一致
    // 对齐 sing-box：端口 443 省略；IPv6 地址必须 bracket（RFC 3986 §3.2.2）
    #[test]
    fn build_authority_ipv4_default_port_omitted() {
        // port==443 时省略端口（对齐 sing-box https.go:85-87）
        assert_eq!(build_http_authority("1.1.1.1", 443), "1.1.1.1");
    }
    #[test]
    fn build_authority_ipv4_custom_port() {
        assert_eq!(build_http_authority("1.1.1.1", 8443), "1.1.1.1:8443");
    }
    #[test]
    fn build_authority_ipv6_default_port_bracketed_no_port() {
        // IPv6 + port 443：加方括号但不写端口（RFC 3986 §3.2.2）
        assert_eq!(build_http_authority("2001:db8::1", 443), "[2001:db8::1]");
    }
    #[test]
    fn build_authority_ipv6_custom_port_bracketed_with_port() {
        // IPv6 + 非 443 端口：加方括号并写端口
        assert_eq!(
            build_http_authority("2001:db8::1", 8443),
            "[2001:db8::1]:8443"
        );
    }
    #[test]
    fn build_authority_ipv6_loopback_default_port() {
        // ::1 这种简写形式也要正确 bracket
        assert_eq!(build_http_authority("::1", 443), "[::1]");
    }
    #[test]
    fn build_authority_domain_default_port_omitted() {
        // 域名 + port 443：不写端口
        assert_eq!(
            build_http_authority("dns.example.com", 443),
            "dns.example.com"
        );
    }
    #[test]
    fn build_authority_domain_custom_port() {
        assert_eq!(
            build_http_authority("dns.example.com", 8443),
            "dns.example.com:8443"
        );
    }
    #[test]
    fn build_authority_ipv4_zero_port_written() {
        // port=0 不是 443，仍写入端口（边界情况）
        assert_eq!(build_http_authority("1.1.1.1", 0), "1.1.1.1:0");
    }
    #[test]
    fn build_authority_ipv6_zero_port_bracketed_with_port() {
        // IPv6 + port=0：加方括号并写 :0
        assert_eq!(build_http_authority("::1", 0), "[::1]:0");
    }
    #[test]
    fn build_authority_ipv6_full_form() {
        // 完整 IPv6 地址形式
        assert_eq!(
            build_http_authority("fe80::1234:5678:9abc:def0", 443),
            "[fe80::1234:5678:9abc:def0]"
        );
    }

    // ── build_http_authority 与 parse_doh_url 的 round-trip 一致性测试 ────────
    // parse_doh_url 返回的 host 不带 []，build_http_authority 重新加上 []，
    // 两者组合后必须能还原原始 URI 的 authority 部分。
    #[test]
    fn build_authority_roundtrip_ipv6_with_port() {
        let url = "https://[2001:db8::1]:8443/dns-query";
        let (host, port, _path) = parse_doh_url(url).unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8443);
        // 重建 authority
        assert_eq!(build_http_authority(&host, port), "[2001:db8::1]:8443");
    }
    #[test]
    fn build_authority_roundtrip_ipv6_default_port() {
        let url = "https://[::1]/dns-query";
        let (host, port, _path) = parse_doh_url(url).unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 443);
        // port=443 时省略端口，但 IPv6 仍需 bracket
        assert_eq!(build_http_authority(&host, port), "[::1]");
    }
    #[test]
    fn build_authority_roundtrip_ipv4_default_port() {
        let url = "https://1.1.1.1/dns-query";
        let (host, port, _path) = parse_doh_url(url).unwrap();
        assert_eq!(build_http_authority(&host, port), "1.1.1.1");
    }
}
