use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tracing::debug;

fn set_doq_query_id_zero(msg: Bytes) -> (Bytes, u16) {
    if msg.len() < 2 {
        return (msg, 0);
    }
    let original_id = u16::from_be_bytes([msg[0], msg[1]]);
    let mut buf = msg.to_vec();
    buf[0] = 0;
    buf[1] = 0;
    (Bytes::from(buf), original_id)
}

fn restore_doq_response_id(resp: Bytes, original_id: u16) -> Bytes {
    if resp.len() < 2 {
        return resp;
    }
    let mut buf = resp.to_vec();
    buf[0..2].copy_from_slice(&original_id.to_be_bytes());
    Bytes::from(buf)
}

/// DoQ 连接池条目：同时持有 endpoint 和 connection。
///
/// **修复 endpoint drop 致连接失效 bug**：
/// quinn 的 `Endpoint` 拥有底层 UDP socket（`UdpSocket`）。
/// QUIC 是基于 UDP 的协议，连接维持需要持续收发数据包。
/// 若 endpoint 被 drop，socket 也随之 drop，QUIC 连接因无法收发包而失效。
///
/// 对齐 sing-box `dns/transport/quic/quic.go:121-127`：sing-box 用 dialer 持有
/// `rawConn` (UDP socket)，并启动 goroutine `<-earlyConnection.Context().Done(); rawConn.Close()`，
/// 保证 socket 与连接同生命周期。Rust 这里通过结构体字段达到同样效果。
pub struct DoqConn {
    /// 持有 endpoint 保持 UDP socket 存活。Connection 退出后由外部清理时 drop。
    /// 字段本身不读取，仅靠 Drop 副作用保持 socket 存活。
    #[allow(dead_code)]
    pub endpoint: quinn::Endpoint,
    /// QUIC 连接，可 open_bi 多个 stream。
    pub conn: quinn::Connection,
}

impl DoqConn {
    /// 是否还存活（对齐 sing-box `IsAlive`：`conn != nil && !common.Done(conn.Context())`）。
    fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }
}

/// 带连接池的 DoQ 查询（对齐 sing-box ConnPoolSingle + Acquire/Release/Reset 模式）。
///
/// QUIC 支持多 stream 复用，一个连接可并发开多个 bi-stream。
///
/// 流程：
/// 1. 从 pool 取出 `DoqConn`（含 endpoint+conn），如失效则重建
/// 2. 在 conn 上 open_bi 开新 stream 做一次查询
/// 3. 成功则归还；失败时若为 retryable 错误，清空 pool 后再试一次
pub(super) async fn doq_query_pooled(
    addr: SocketAddr,
    sni: &str,
    quic_cfg: Arc<quinn::ClientConfig>,
    msg: Bytes,
    mark: u32,
    pool: &tokio::sync::Mutex<Option<DoqConn>>,
) -> anyhow::Result<Bytes> {
    // RFC 9250 §4.2：DoQ 报文 ID MUST 为 0。对齐 sing-box `quic.go:159`
    // `transport.WriteMessage(stream, 0, message)`：sing-box 在 WriteMessage 内部
    // 将 `exMessage.Id = 0`。reflex 在查询前重写为 0，响应恢复原始 ID。
    let (msg, original_id) = set_doq_query_id_zero(msg);

    // 对齐 sing-box `for range 2`：最多两次尝试
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        match doq_query_once(addr, sni, quic_cfg.clone(), &msg, mark, pool).await {
            Ok(resp) => {
                // 恢复原始 ID，保持上下游 ID 配对语义
                return Ok(restore_doq_response_id(resp, original_id));
            }
            Err(e) => {
                let is_retry = is_quic_retry_error(&e);
                debug!(
                    addr=%addr,
                    attempt,
                    retryable=is_retry,
                    err=%e,
                    "DoQ query attempt failed"
                );
                if is_retry && attempt == 0 {
                    // 清空 pool 让下次重建连接（对齐 sing-box `t.Reset()`）
                    let mut guard = pool.lock().await;
                    if let Some(old) = guard.take() {
                        // 主动关闭旧连接（quinn 会发送 CONNECTION_CLOSE 帧）
                        old.conn.close(0u32.into(), b"");
                        // endpoint 在 drop 时关闭 socket
                    }
                    last_err = Some(e);
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoQ query exhausted retries")))
}

/// 单次 DoQ 查询：从 pool 取连接（或新建），开 stream 收发。
async fn doq_query_once(
    addr: SocketAddr,
    sni: &str,
    quic_cfg: Arc<quinn::ClientConfig>,
    msg: &Bytes,
    mark: u32,
    pool: &tokio::sync::Mutex<Option<DoqConn>>,
) -> anyhow::Result<Bytes> {
    // 1. 取出或建立连接（先 clone 出 conn，pool 内仍持有 DoqConn 不被替换）
    let conn = {
        let mut guard = pool.lock().await;
        let need_rebuild = match guard.as_ref() {
            None => true,
            Some(c) => !c.is_alive(),
        };
        if need_rebuild {
            // 旧连接已失效或不存在：丢弃并新建
            if let Some(old) = guard.take() {
                old.conn.close(0u32.into(), b"");
            }
            let new_conn = dial_doq(addr, sni, quic_cfg.clone(), mark).await?;
            *guard = Some(DoqConn {
                endpoint: new_conn.0,
                conn: new_conn.1.clone(),
            });
            new_conn.1
        } else {
            guard.as_ref().unwrap().conn.clone()
        }
    };

    // 2. 开新 bi-stream 做查询
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("DoQ open stream failed: {e}"))?;

    // 合并 len(2B) + msg 为单次写入，减少 QUIC stream write 操作
    // （对齐 sing-box quic.go:157-161 的单次 WriteMessage 行为）
    let len = msg.len() as u16;
    let mut framed = Vec::with_capacity(2 + msg.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(msg);
    send.write_all(&framed)
        .await
        .map_err(|e| anyhow::anyhow!("DoQ stream write failed: {e}"))?;
    // half-close 发送端（对齐 sing-box stream.Close()）
    send.finish()
        .map_err(|e| anyhow::anyhow!("DoQ stream finish failed: {e}"))?;

    let resp_len =
        recv.read_u16()
            .await
            .map_err(|e| anyhow::anyhow!("DoQ read response length failed: {e}"))? as usize;
    anyhow::ensure!(resp_len <= 65535, "DoQ response too large: {resp_len}");
    let mut buf = vec![0u8; resp_len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| anyhow::anyhow!("DoQ read response body failed: {e}"))?;
    Ok(Bytes::from(buf))
}

/// 建立新的 DoQ 连接：创建 endpoint + QUIC handshake。
/// 返回 (endpoint, connection)，调用方需保持 endpoint 存活。
async fn dial_doq(
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
        .map_err(|e| anyhow::anyhow!("DoQ endpoint bind failed: {e}"))?;
    endpoint.set_default_client_config((*quic_cfg).clone());

    let new_conn = endpoint
        .connect(addr, sni)
        .map_err(|e| anyhow::anyhow!("DoQ connect config error: {e}"))?
        .await
        .map_err(|e| anyhow::anyhow!("DoQ QUIC connect to {addr} failed: {e}"))?;

    Ok((endpoint, new_conn))
}

/// 判定 DoQ 错误是否可重试（对齐 sing-box `isQUICRetryError`）。
///
/// 可重试 = 连接级错误（idle timeout / stateless reset / connection lost / 0RTT rejected）。
/// 不可重试 = stream 级错误（如 stream stopped 但连接仍可用）。
///
/// 实现上采取宽松策略：除明显是 stream 级的 "stream stopped" 外，都视为可重试，
/// 因为旧连接可能已 idle timeout 但 quinn 未及时察觉（与 sing-box `os.ErrClosed` 也算可重试接近）。
pub(super) fn is_quic_retry_error(e: &anyhow::Error) -> bool {
    use quinn::{ConnectionError, ReadError, WriteError};

    // 检查 ConnectionError（dial 失败时常见，open_bi 也可能返回）
    if let Some(ce) = e.root_cause().downcast_ref::<ConnectionError>() {
        return matches!(
            ce,
            ConnectionError::TimedOut              // idle timeout
            | ConnectionError::Reset                // stateless reset
            | ConnectionError::ApplicationClosed(_) // peer 应用层关闭
            | ConnectionError::ConnectionClosed(_) // peer 协议层关闭
            | ConnectionError::LocallyClosed // 本地关（pool reset 触发）
        );
    }
    // 检查 ReadError（stream 读失败时常见）
    if let Some(re) = e.root_cause().downcast_ref::<ReadError>() {
        return matches!(
            re,
            ReadError::ConnectionLost(_)
            | ReadError::Reset(_)            // stream reset 常因连接坏
            | ReadError::ZeroRttRejected
        );
    }
    // 检查 WriteError（stream 写失败时常见）
    if let Some(we) = e.root_cause().downcast_ref::<WriteError>() {
        return matches!(
            we,
            WriteError::ConnectionLost(_)
            // Stopped 表示 peer 主动 stop了这个 stream，连接本身可能仍可用，但保险起见也重试
            | WriteError::Stopped(_)
            | WriteError::ZeroRttRejected
        );
    }
    // 兜底：无法识别的错误默认视为可重试
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // DoQ 的完整集成测试需要真实服务器，这里仅做单元测试覆盖 ID 归一化逻辑。
    // 行为对齐由 sing-box 参考实现的逻辑保证。

    // ── DoQ query ID=0 归一化测试（RFC 9250 §4.2 强制要求）──────────────────
    // 对齐 sing-box `quic.go:159` 的 `WriteMessage(stream, 0, message)`：
    // sing-box 在 WriteMessage 内部将 `exMessage.Id = 0`。
    // reflex 在查询前重写为 0，响应恢复原始 ID。

    #[test]
    fn doq_id_zero_rewrite() {
        // 原始报文 ID=0xABCD
        let msg = Bytes::from_static(b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_doq_query_id_zero(msg);
        assert_eq!(original_id, 0xABCD);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        // 其余字节保持不变
        assert_eq!(&rewritten[2..], b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
    }

    #[test]
    fn doq_id_zero_short_msg_noop() {
        // 报文短于 2 字节：不修改，原 ID 视为 0
        let msg = Bytes::from_static(b"\xAB");
        let (rewritten, original_id) = set_doq_query_id_zero(msg);
        assert_eq!(original_id, 0);
        assert_eq!(rewritten.as_ref(), b"\xAB");
    }

    #[test]
    fn doq_id_zero_empty_msg_noop() {
        // 空报文：不修改，原 ID 视为 0
        let msg = Bytes::new();
        let (rewritten, original_id) = set_doq_query_id_zero(msg);
        assert_eq!(original_id, 0);
        assert!(rewritten.is_empty());
    }

    #[test]
    fn doq_id_zero_already_zero() {
        // ID 已为 0：仍正确提取 original_id=0
        let msg = Bytes::from_static(b"\x00\x00\x01\x00\x00\x01");
        let (rewritten, original_id) = set_doq_query_id_zero(msg);
        assert_eq!(original_id, 0);
        assert_eq!(&rewritten[..2], b"\x00\x00");
    }

    #[test]
    fn doq_response_id_restore() {
        // 响应 ID=0，恢复为原始 ID=0xABCD
        let resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00");
        let restored = restore_doq_response_id(resp, 0xABCD);
        assert_eq!(&restored[..2], b"\xAB\xCD");
        assert_eq!(&restored[2..], b"\x81\x80\x00\x00");
    }

    #[test]
    fn doq_response_id_restore_short_noop() {
        // 响应短于 2 字节：原样返回
        let resp = Bytes::from_static(b"\x00");
        let restored = restore_doq_response_id(resp, 0xABCD);
        assert_eq!(restored.as_ref(), b"\x00");
    }

    #[test]
    fn doq_response_id_restore_overwrites_nonzero() {
        // RFC 9250 要求服务器返回 ID=0，但即使非 0 也强制覆盖，确保 caller
        // 看到的响应 ID 与自己发出的请求 ID 一致（对齐 sing-box client.go:307）
        let resp = Bytes::from_static(b"\xFF\xFF\x81\x80");
        let restored = restore_doq_response_id(resp, 0x1234);
        assert_eq!(&restored[..2], b"\x12\x34");
        assert_eq!(&restored[2..], b"\x81\x80");
    }

    #[test]
    fn doq_id_roundtrip() {
        // 模拟完整往返：原报文 → ID=0 发送 → 响应 ID=0 → 恢复为原 ID
        let original_msg = Bytes::from_static(b"\xAB\xCD\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_doq_query_id_zero(original_msg.clone());
        assert_eq!(original_id, 0xABCD);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        // 服务器返回 ID=0 的响应
        let server_resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00");
        let restored_resp = restore_doq_response_id(server_resp, original_id);
        // 响应的 ID 应等于原始请求 ID
        assert_eq!(&restored_resp[..2], &original_msg[..2]);
    }

    #[test]
    fn doq_id_roundtrip_max_id() {
        // 边界情况：ID=0xFFFF
        let original_msg = Bytes::from_static(b"\xFF\xFF\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00");
        let (rewritten, original_id) = set_doq_query_id_zero(original_msg.clone());
        assert_eq!(original_id, 0xFFFF);
        assert_eq!(&rewritten[..2], b"\x00\x00");
        let server_resp = Bytes::from_static(b"\x00\x00\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00");
        let restored_resp = restore_doq_response_id(server_resp, original_id);
        assert_eq!(&restored_resp[..2], b"\xFF\xFF");
    }
}
