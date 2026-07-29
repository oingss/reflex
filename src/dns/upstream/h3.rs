//! DNS-over-HTTP/3（DoH3）协议实现（RFC 9464）：QUIC + HTTP/3，POST application/dns-message。
//!
//! 对齐 sing-box `dns/transport/quic/http3.go`：
//! - **底层传输**：QUIC（ALPN "h3"）+ HTTP/3 帧
//! - **请求方式**：POST `application/dns-message`（RFC 8484 风格，被 RFC 9464 引用）
//! - **Message ID = 0**（对齐 sing-box `https.go:176 exMessage.Id = 0` + RFC 8484 §4.2 SHOULD）：
//!   HTTP request/response 配对，不依赖 DNS Message ID 区分；某些严格的 DoH3 服务器会拒绝
//!   ID != 0 的请求。查询前重写为 0，响应恢复为原始 ID。
//! - **连接池**：单 QUIC 连接 + 多 HTTP/3 stream（QUIC 多 stream 复用），
//!   `h3::client::SendRequest` 是 `Clone` 的，每次查询 clone 一份发送请求。
//! - **失败重试**：连接级错误（idle timeout / reset / connection lost）时清空 pool，重新建连再试一次。
//! - **endpoint 与 connection 同生命周期**（与 DoQ 一致）：避免 endpoint drop 致 socket 失效。
//!
//! 与 DoQ 的区别：
//! - DoQ 用 2 字节长度前缀帧；DoH3 用 HTTP/3 帧（HEADERS + DATA）
//! - DoQ ALPN = "doq"；DoH3 ALPN = "h3"
//! - DoQ 是 RFC 9250；DoH3 是 RFC 9464

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use tracing::debug;

// ── 协议实现：DoH3 ────────────────────────────────────────────────────────────

/// 将 DNS 查询报文的 ID 重写为 0（对齐 sing-box `https.go:176 exMessage.Id = 0`
/// + RFC 8484 §4.2 "the message ID of the DNS message SHOULD be 0"）。
///
/// DoH3 与 DoH 一样使用 HTTP request/response 配对，不依赖 DNS ID 区分查询；某些严格的
/// DoH3 服务器会拒绝 ID != 0 的请求。返回 (重写后的报文, 原始 ID)
/// 供 caller 在响应上恢复 ID，保持上下游 ID 配对语义不变。
fn set_h3_query_id_zero(msg: Bytes) -> (Bytes, u16) {
    if msg.len() < 2 {
        return (msg, 0);
    }
    let original_id = u16::from_be_bytes([msg[0], msg[1]]);
    let mut buf = msg.to_vec();
    buf[0] = 0;
    buf[1] = 0;
    (Bytes::from(buf), original_id)
}

/// 将响应的 ID 还原为原始查询 ID（`set_h3_query_id_zero` 的逆操作）。
/// 多数 DoH3 服务器返回 ID=0，但即使非 0 也强制覆盖，确保 caller 看到的
/// 响应 ID 与自己发出的请求 ID 一致。
fn restore_h3_response_id(resp: Bytes, original_id: u16) -> Bytes {
    if resp.len() < 2 {
        return resp;
    }
    let mut buf = resp.to_vec();
    buf[0..2].copy_from_slice(&original_id.to_be_bytes());
    Bytes::from(buf)
}

/// DoH3 连接池条目：同时持有 endpoint、quinn::Connection、h3 SendRequest。
///
/// 与 DoQ 同理：endpoint 必须与 connection 共存亡，否则 endpoint drop 致底层 UDP socket
/// 失效，QUIC 连接因无法收发包而失效。h3 SendRequest 持有 QUIC stream opener，
/// 必须保持底层 QUIC 连接存活才能开新 stream。
pub struct H3Conn {
    /// 持有 endpoint 保持 UDP socket 存活（字段本身不读取）。
    #[allow(dead_code)]
    pub endpoint: quinn::Endpoint,
    /// QUIC 连接，用于 close_reason() 检查存活与显式 close。
    pub quic_conn: quinn::Connection,
    /// HTTP/3 请求发送器，Clone 后可并发发送多个请求（HTTP/3 多 stream 复用）。
    /// 类型参数是 h3_quinn::OpenStreams（由 h3::client::new 内部从 Connection::opener() 取得）。
    pub send_req: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
}

impl H3Conn {
    /// 是否还存活（对齐 sing-box `IsAlive`：close_reason 为 None 表示连接仍开着）。
    fn is_alive(&self) -> bool {
        self.quic_conn.close_reason().is_none()
    }
}

/// 带连接池的 DoH3 查询（对齐 sing-box `http3.go` + ConnPoolSingle 模式）。
///
/// QUIC + HTTP/3 支持多 stream 复用，一个连接可并发开多个 HTTP/3 请求 stream。
///
/// 流程：
/// 1. 从 pool 取出 `H3Conn`，如失效则重建
/// 2. clone `SendRequest`，开新 stream 发 POST 请求
/// 3. 成功则返回；失败时若为 retryable 错误，清空 pool 后再试一次
pub(super) async fn h3_query_pooled(
    addr: SocketAddr,
    sni: &str,
    path: &str,
    quic_cfg: Arc<quinn::ClientConfig>,
    msg: Bytes,
    mark: u32,
    pool: &tokio::sync::Mutex<Option<H3Conn>>,
) -> anyhow::Result<Bytes> {
    // 重写 query ID 为 0（对齐 RFC 8484 §4.2 + sing-box https.go:176）
    let (msg, original_id) = set_h3_query_id_zero(msg);

    // 对齐 sing-box `for range 2`：最多两次尝试
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        match h3_query_once(addr, sni, path, quic_cfg.clone(), &msg, mark, pool).await {
            Ok(resp) => {
                return Ok(restore_h3_response_id(resp, original_id));
            }
            Err(e) => {
                let is_retry = super::doq::is_quic_retry_error(&e);
                debug!(
                    addr=%addr,
                    attempt,
                    retryable=is_retry,
                    err=%e,
                    "DoH3 query attempt failed"
                );
                if is_retry && attempt == 0 {
                    // 清空 pool 让下次重建连接（对齐 sing-box `t.Reset()`）
                    let mut guard = pool.lock().await;
                    if let Some(old) = guard.take() {
                        old.quic_conn.close(0u32.into(), b"");
                    }
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoH3 query exhausted retries")))
}

/// 单次 DoH3 查询：从 pool 取连接（或新建），发送 HTTP/3 POST。
async fn h3_query_once(
    addr: SocketAddr,
    sni: &str,
    path: &str,
    quic_cfg: Arc<quinn::ClientConfig>,
    msg: &Bytes,
    mark: u32,
    pool: &tokio::sync::Mutex<Option<H3Conn>>,
) -> anyhow::Result<Bytes> {
    // 1. 取出或建立连接（clone SendRequest，pool 内仍持有 H3Conn 不被替换）
    let mut send_req: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> = {
        let mut guard = pool.lock().await;
        let need_rebuild = match guard.as_ref() {
            None => true,
            Some(c) => !c.is_alive(),
        };
        if need_rebuild {
            if let Some(old) = guard.take() {
                old.quic_conn.close(0u32.into(), b"");
            }
            let (endpoint, quic_conn) = dial_h3(addr, sni, quic_cfg.clone(), mark).await?;
            // 初始化 h3 client：返回 (Connection driver, SendRequest)
            let (mut driver, send_req) =
                h3::client::new(h3_quinn::Connection::new(quic_conn.clone()))
                    .await
                    .map_err(|e| anyhow::anyhow!("DoH3 client init failed: {e}"))?;
            // 后台驱动 h3 connection（处理 control stream、QPACK 等）
            // 对齐 sing-box http3.go 在新连接上启动 goroutine 驱动
            tokio::spawn(async move {
                use futures_util::future::poll_fn;
                let _ = poll_fn(|cx| driver.poll_close(cx)).await;
            });
            *guard = Some(H3Conn {
                endpoint,
                quic_conn,
                send_req,
            });
        }
        guard.as_ref().unwrap().send_req.clone()
    };

    // 2. 构造 POST 请求
    // URI 用 https://<sni><path> 形式（h3 crate 会解析 :authority/:method/:path 伪头）
    // port==443 时不写入端口（对齐 sing-box https.go:85-87）；DoH3 默认端口 443
    let uri = format!("https://{sni}{path}")
        .parse::<http::Uri>()
        .map_err(|e| anyhow::anyhow!("invalid DoH3 URI: {e}"))?;

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .header("content-length", msg.len().to_string())
        .body(())
        .map_err(|e| anyhow::anyhow!("h3 request build failed: {e}"))?;

    // 3. 发送请求：send_request 开新 stream + 写 HEADERS，send_data 写 body，finish 半关闭
    let mut stream = send_req
        .send_request(req)
        .await
        .map_err(|e| anyhow::anyhow!("h3 send_request failed: {e}"))?;
    stream
        .send_data(msg.clone())
        .await
        .map_err(|e| anyhow::anyhow!("h3 send_data failed: {e}"))?;
    stream
        .finish()
        .await
        .map_err(|e| anyhow::anyhow!("h3 finish failed: {e}"))?;

    // 4. 接收响应：recv_response 取 HEADERS，recv_data 循环读 body
    let resp = stream
        .recv_response()
        .await
        .map_err(|e| anyhow::anyhow!("h3 recv_response failed: {e}"))?;
    let status = resp.status();
    if status != http::StatusCode::OK {
        return Err(anyhow::anyhow!("DoH3 server returned non-200: {status}"));
    }

    let mut data = Vec::new();
    while let Some(chunk) = stream
        .recv_data()
        .await
        .map_err(|e| anyhow::anyhow!("h3 recv_data failed: {e}"))?
    {
        // chunk: impl Buf —— 用 chunk() 取连续切片
        data.extend_from_slice(chunk.chunk());
    }
    Ok(Bytes::from(data))
}

/// 建立新的 DoH3 连接：创建 endpoint + QUIC handshake。
/// 返回 (endpoint, connection)，调用方需保持 endpoint 存活。
async fn dial_h3(
    addr: SocketAddr,
    sni: &str,
    quic_cfg: Arc<quinn::ClientConfig>,
    mark: u32,
) -> anyhow::Result<(quinn::Endpoint, quinn::Connection)> {
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()?;
    let mut endpoint = crate::outbound::new_marked_quic_endpoint(bind, mark)
        .map_err(|e| anyhow::anyhow!("DoH3 endpoint bind failed: {e}"))?;
    endpoint.set_default_client_config((*quic_cfg).clone());

    let new_conn = endpoint
        .connect(addr, sni)
        .map_err(|e| anyhow::anyhow!("DoH3 connect config error: {e}"))?
        .await
        .map_err(|e| anyhow::anyhow!("DoH3 QUIC connect to {addr} failed: {e}"))?;

    Ok((endpoint, new_conn))
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // DoH3 的完整集成测试需要真实 HTTP/3 服务器，这里仅做单元测试覆盖 ID 归一化逻辑。
    // 行为对齐由 sing-box 参考实现的逻辑保证。

    // ── DoH3 query ID=0 归一化测试（RFC 8484 §4.2 SHOULD + RFC 9464 引用其语义）──

    #[test]
    fn h3_id_zero_rewrite() {
        // 原始报文 ID=0xABCD
        let msg = Bytes::from_static(b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_h3_query_id_zero(msg);
        assert_eq!(original_id, 0xABCD);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        assert_eq!(&rewritten[2..], b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    }

    #[test]
    fn h3_id_zero_short_msg_noop() {
        // 报文短于 2 字节：不修改，原 ID 视为 0
        let msg = Bytes::from_static(b"\xAB");
        let (rewritten, original_id) = set_h3_query_id_zero(msg);
        assert_eq!(original_id, 0);
        assert_eq!(rewritten.as_ref(), b"\xAB");
    }

    #[test]
    fn h3_id_zero_empty_msg_noop() {
        let msg = Bytes::new();
        let (rewritten, original_id) = set_h3_query_id_zero(msg);
        assert_eq!(original_id, 0);
        assert!(rewritten.is_empty());
    }

    #[test]
    fn h3_id_zero_already_zero() {
        let msg = Bytes::from_static(b"\x00\x00\x01\x00\x00\x01");
        let (rewritten, original_id) = set_h3_query_id_zero(msg);
        assert_eq!(original_id, 0);
        assert_eq!(&rewritten[..2], b"\x00\x00");
    }

    #[test]
    fn h3_response_id_restore() {
        let resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00");
        let restored = restore_h3_response_id(resp, 0xABCD);
        assert_eq!(&restored[..2], b"\xAB\xCD");
        assert_eq!(&restored[2..], b"\x81\x80\x00\x00");
    }

    #[test]
    fn h3_response_id_restore_short_noop() {
        let resp = Bytes::from_static(b"\x00");
        let restored = restore_h3_response_id(resp, 0xABCD);
        assert_eq!(restored.as_ref(), b"\x00");
    }

    #[test]
    fn h3_response_id_restore_overwrites_nonzero() {
        // 即使服务器返回非 0 ID，也强制覆盖为原始 ID
        let resp = Bytes::from_static(b"\xFF\xFF\x81\x80");
        let restored = restore_h3_response_id(resp, 0x1234);
        assert_eq!(&restored[..2], b"\x12\x34");
        assert_eq!(&restored[2..], b"\x81\x80");
    }

    #[test]
    fn h3_id_roundtrip() {
        // 模拟完整往返：原报文 → ID=0 发送 → 响应 ID=0 → 恢复为原 ID
        let original_msg = Bytes::from_static(b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_h3_query_id_zero(original_msg.clone());
        assert_eq!(original_id, 0xABCD);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        let server_resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00");
        let restored_resp = restore_h3_response_id(server_resp, original_id);
        assert_eq!(&restored_resp[..2], &original_msg[..2]);
    }

    #[test]
    fn h3_id_roundtrip_max_id() {
        let original_msg = Bytes::from_static(b"\xFF\xFF\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_h3_query_id_zero(original_msg.clone());
        assert_eq!(original_id, 0xFFFF);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        let server_resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00");
        let restored_resp = restore_h3_response_id(server_resp, original_id);
        assert_eq!(&restored_resp[..2], b"\xFF\xFF");
    }
}
