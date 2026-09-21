use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tracing::debug;

use super::util::tcp_framed_exchange;

type DotTlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// DoT 连接池：容量有限的多连接池，替代原来的单连接 `Mutex<Option<TlsStream>>`。
///
/// **问题背景**：DNS-over-TCP framing（DoT 的底层帧格式）不支持在一条连接上
/// 并发复用（一发一收，串行），这一点没错；但这不等于只能维护一条连接。
/// 旧实现用 `Mutex<Option<TlsStream>>` 做"取用-归还"：并发查询时，后来者拿到
/// `None` 会新建一条连接，用完后两者都尝试把连接放回同一个 `Option` 槽位，
/// 后放的会覆盖先放的，被覆盖的连接直接丢弃关闭——池子实际容量恒为 1，
/// 高并发下等于没有池化，且反复握手开销大。
///
/// 对齐 sing-box `dns/transport/tls.go` 的做法：sing-box 用 `ConnPool`
/// （`MaxInflight: 8`）维护多条连接，每条连接同一时刻服务一个请求，允许
/// 多条连接并发工作。这里采用同样的思路：`VecDeque` 存空闲连接 +
/// `Semaphore` 限制同时在用的连接数（含新建中的），避免瞬时高并发下无限制
/// 建连，同时保留原来的失败重建、超时后统一丢弃等语义。
pub struct DotConnPool {
    idle: AsyncMutex<VecDeque<DotTlsStream>>,
    permits: Semaphore,
}

impl DotConnPool {
    /// 池中最多保留的空闲连接数，同时也是同时在用连接数的上限。
    /// 对齐 sing-box tls.go `ConnPool` 的 `MaxInflight: 8`。
    const CAPACITY: usize = 8;

    pub fn new() -> Self {
        Self {
            idle: AsyncMutex::new(VecDeque::with_capacity(Self::CAPACITY)),
            permits: Semaphore::new(Self::CAPACITY),
        }
    }

    /// 取出一条空闲连接（如有）。
    async fn take_idle(&self) -> Option<DotTlsStream> {
        self.idle.lock().await.pop_front()
    }

    /// 归还一条可复用的连接；池已满则直接丢弃（Drop 自然关闭）。
    async fn put_back(&self, conn: DotTlsStream) {
        let mut idle = self.idle.lock().await;
        if idle.len() < Self::CAPACITY {
            idle.push_back(conn);
        }
    }

    /// 清空所有空闲连接（外层 timeout 触发时调用，对齐旧接口
    /// `*conn_pool.lock().await = None` 的调用点语义）。
    pub async fn reset(&self) {
        self.idle.lock().await.clear();
    }
}

impl Default for DotConnPool {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) async fn dot_query_pooled(
    addr: SocketAddr,
    sni: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    msg: Bytes,
    mark: u32,
    pool: &DotConnPool,
) -> anyhow::Result<Bytes> {
    // 限制同时在用的连接数（含新建中的），排队等待而非无限制建连。
    let _permit = pool
        .permits
        .acquire()
        .await
        .map_err(|_| anyhow::anyhow!("DoT connection pool closed"))?;

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 0..2 {
        // 1. 取出或建立连接
        let (mut tls, created) = acquire_or_dial(addr, sni, tls_cfg.clone(), mark, pool).await?;

        // 2. 在连接上做 framed 交换
        match tcp_framed_exchange(&mut tls, msg.clone()).await {
            Ok(resp) => {
                // 成功则归还连接
                pool.put_back(tls).await;
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
                // 复用旧连接失败：重试（下一轮会新建）
                continue;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("DoT query exhausted retries")))
}

/// 从 pool 取出一条空闲连接，如无则新建。
/// 返回 (tls_stream, created)：created=true 表示是新建的连接。
async fn acquire_or_dial(
    addr: SocketAddr,
    sni: &str,
    tls_cfg: Arc<rustls::ClientConfig>,
    mark: u32,
    pool: &DotConnPool,
) -> anyhow::Result<(DotTlsStream, bool)> {
    // 先尝试从 pool 取
    if let Some(tls) = pool.take_idle().await {
        return Ok((tls, false));
    }
    // pool 为空：新建
    // 连接前绑定物理网卡（Windows IP_UNICAST_IF / macOS IP_BOUND_IF），对齐
    // sing-box：SYN 已按 TUN 默认路由发出后再事后绑定是无效的。
    let tcp = crate::outbound::connect_tcp_interface(addr)
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
