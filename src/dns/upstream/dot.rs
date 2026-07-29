//! DNS-over-TLS 协议实现：带连接池的 DoT 查询、经 detour 的 DoT、BoxStream 适配器。
//!
//! 对齐 sing-box `dns/transport/tls.go`：
//! - **失败重试**（对齐 sing-box `for range 2` + `Release(conn, false)`）：
//!   复用旧连接失败 → 丢弃旧连接、新建连接重试一次
//!   新建连接失败 → 直接返回错误（重试也没用）
//! - **take/put 独占模式**（reflex 现状，简化实现）：
//!   DNS-over-TCP framing 同步 request-response，无需 queryId 匹配。
//!   代价是失去多并发复用，但 DoT 不是主流协议，take/put 够用。

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::TcpStream;
use tracing::debug;

use super::util::tcp_framed_exchange;

// ── 协议实现：DoT ─────────────────────────────────────────────────────────────

/// 带连接池的 DoT 查询（对齐 sing-box `TLSTransport.Exchange` 的重试逻辑）。
///
/// 流程：
/// 1. 从 pool 取出空闲 TLS 连接；若无则新建（标记 `created=true`）
/// 2. 在连接上做一次 framed 请求-响应交换
/// 3. 成功则归还连接，失败则丢弃
/// 4. **若失败且连接是复用的**（created=false）：清空 pool 后新建连接重试一次
///    （对齐 sing-box：旧连接可能 idle timeout 失效，重试一次拿新连接）
/// 5. **若失败且连接是新建的**：直接返回错误（重试也没用）
pub(super) async fn dot_query_pooled(
    addr: SocketAddr,
    sni: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    msg: Bytes,
    mark: u32,
    pool: &tokio::sync::Mutex<Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
) -> anyhow::Result<Bytes> {
    // 对齐 sing-box `for range 2`：最多两次尝试
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        // 1. 取出或建立连接
        let (mut tls, created) = acquire_or_dial(addr, sni, tls_cfg.clone(), mark, pool).await?;

        // 2. 在连接上做 framed 交换
        match tcp_framed_exchange(&mut tls, msg.clone()).await {
            Ok(resp) => {
                // 成功则归还连接
                *pool.lock().await = Some(tls);
                return Ok(resp);
            }
            Err(e) => {
                debug!(
                    addr=%addr,
                    attempt,
                    created,
                    err=%e,
                    "DoT pooled exchange failed, dropping connection"
                );
                // 失败则丢弃连接（不归还）
                last_err = Some(e);
                if created {
                    // 新建连接就失败：重试也没用
                    return Err(last_err.unwrap());
                }
                // 复用旧连接失败：清空 pool（pool 已经空了，但显式声明）后重试
                continue;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoT query exhausted retries")))
}

/// 从 pool 取出连接，如无则新建。
/// 返回 (tls_stream, created)：created=true 表示是新建的连接。
async fn acquire_or_dial(
    addr: SocketAddr,
    sni: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    mark: u32,
    pool: &tokio::sync::Mutex<Option<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>>,
) -> anyhow::Result<(tokio_rustls::client::TlsStream<tokio::net::TcpStream>, bool)> {
    // 先尝试从 pool 取
    let pooled = pool.lock().await.take();
    if let Some(tls) = pooled {
        return Ok((tls, false));
    }
    // pool 为空：新建
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| anyhow::anyhow!("DoT TCP connect to {addr} failed: {e}"))?;
    crate::outbound::apply_mark_to_tcp(&tcp, mark)?;
    let tls = crate::outbound::tls::connect_tls(tcp, sni, tls_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("DoT TLS handshake with {sni} failed: {e}"))?;
    Ok((tls, true))
}

pub(super) async fn dot_query_via_detour(
    outbound: &dyn crate::outbound::Outbound,
    host: String,
    port: u16,
    sni: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    // 先通过 detour 建立 TCP 隧道，再在上面套 TLS
    let tcp_stream = outbound.connect_tcp(&host, port).await?;
    // connect_tcp 返回 Box<dyn AsyncReadWrite>，需要转为 TcpStream-like
    // 这里利用 tokio-rustls 支持任意 AsyncRead+AsyncWrite 的能力
    let tls = dot_tls_on_boxed(tcp_stream, sni, tls_cfg).await?;
    // tls 实现了 AsyncRead+AsyncWrite，可直接用
    let mut tls = tls;
    tcp_framed_exchange(&mut tls, msg).await
}

pub(super) async fn dot_tls_on_boxed(
    stream: Box<dyn crate::outbound::AsyncReadWrite>,
    sni: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
) -> anyhow::Result<tokio_rustls::client::TlsStream<BoxStream>> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let connector = TlsConnector::from(tls_cfg);
    let server_name =
        ServerName::try_from(sni.to_string()).map_err(|_| anyhow::anyhow!("invalid SNI: {sni}"))?;
    let tls = connector
        .connect(server_name, BoxStream(stream))
        .await
        .map_err(|e| anyhow::anyhow!("DoT TLS handshake via detour with {sni} failed: {e}"))?;
    Ok(tls)
}

// 将 Box<dyn AsyncReadWrite> 包装成实现 AsyncRead+AsyncWrite 的新类型，
// 供 tokio-rustls 使用。
// 标记 pub(super) 以便 dot_tls_on_boxed 的返回类型可被同模块树（如 doh.rs）使用。
pub(super) struct BoxStream(pub(super) Box<dyn crate::outbound::AsyncReadWrite>);

impl tokio::io::AsyncRead for BoxStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BoxStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}
