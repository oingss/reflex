pub mod block;
pub mod direct;
pub mod socks;

pub mod anytls;
pub mod common;
pub mod hy2;
pub mod naive;
pub mod shadowquic;
pub mod shadowsocks;
pub mod ssh;
pub mod tailscale;
pub mod tls;
pub mod transport;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;
pub mod wireguard;

use crate::dns::DnsResolver;
use crate::inbound::{InboundTcpStream, InboundUdpPacket, Target};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

// ── SO_MARK 工具 ──────────────────────────────────────────────────────────────

/// 对已创建的 TCP socket（tokio::net::TcpStream）设置 SO_MARK。
/// 仅 Linux 生效；其他平台为空操作（编译通过，无运行时开销）。
#[allow(unused_variables)]
pub fn apply_mark_to_tcp(stream: &TcpStream, mark: u32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if mark != 0 {
            use std::os::unix::io::AsRawFd;
            let fd = stream.as_raw_fd();
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// 对已创建的 UDP socket（tokio::net::UdpSocket）设置 SO_MARK。
/// 仅 Linux 生效；其他平台为空操作。
#[allow(unused_variables)]
pub fn apply_mark_to_udp(sock: &tokio::net::UdpSocket, mark: u32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        if mark != 0 {
            use std::os::unix::io::AsRawFd;
            let fd = sock.as_raw_fd();
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// 创建一个绑定到 `bind` 地址、并在 Linux 上设置了 SO_MARK 的 quinn Endpoint。
///
/// quinn 的 Endpoint 不暴露底层 fd，必须在 bind 之前通过 socket2 设置 mark，
/// 再将 socket 传给 `quinn::Endpoint::new()`。
#[allow(unused_variables)]
pub fn new_marked_quic_endpoint(
    bind: std::net::SocketAddr,
    mark: u32,
) -> anyhow::Result<quinn::Endpoint> {
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if bind.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;

    #[cfg(target_os = "linux")]
    if mark != 0 {
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }

    sock.bind(&bind.into())?;
    let std_udp: std::net::UdpSocket = sock.into();
    std_udp.set_nonblocking(true)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        std_udp,
        std::sync::Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| anyhow::anyhow!("quinn endpoint create failed: {e}"))?;
    Ok(endpoint)
}

// ── TCP 连接辅助 ──────────────────────────────────────────────────────────────

/// 内核 TCP keepalive 参数。
///
/// 历史值参照 sing-box constant/timeout.go：idle=300s, interval=75s，最坏需 ~10min+
/// 才能探测到对端已死。现调小为 idle=60s, interval=15s, 作为应用层 idle sweeper
/// （见 ConnectionTracker::spawn_idle_sweeper）之外的"内核层双保险"：
///   - sweeper 处理"我这边 task 卡死、socket 没报错"的场景（基于流量计数变化）；
///   - 内核 keepalive 处理"对端无响应、socket 层能探测到"的场景（基于 TCP 探测包）。
///
/// 两者覆盖不同失效模式。调小后内核 keepalive 在 ~1.5min 内可让 socket 报错，
/// 从而触发 relay_tracked future 结束并 Drop ConnGuard，连接从列表移除。
const TCP_KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// 对 TcpStream 统一设置 nodelay + keepalive。
/// keepalive 能及时检测并清理死连接（网络中断、NAT 超时等），
/// 避免连接长期占用资源。
pub fn set_tcp_opts(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    sock.set_tcp_keepalive(&ka)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundStatus {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<OutboundDelay>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboundDelay {
    /// 出站节点的 tag 名
    pub name: String,
    /// 延迟（毫秒）
    pub delay: u64,
}

// ── Outbound trait ────────────────────────────────────────────────────────────

/// 所有出站实现共享的接口。
/// 返回 `(bytes_up, bytes_down)` 供统计层记录。
#[async_trait::async_trait]
pub trait Outbound: Send + Sync + 'static {
    /// 处理一条 TCP 连接，返回 (上行字节数, 下行字节数)
    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)>;

    /// 处理一条 TCP 连接，并实时更新 `live_up` / `live_down` 原子计数器。
    /// 默认实现将计数器注入 `conn.stream`（SniffedStream），
    /// 后续所有出站对该流的 read/write 都会实时更新计数器，无需各出站单独覆盖。
    async fn handle_tcp_live(
        &self,
        mut conn: crate::inbound::InboundTcpStream,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) -> anyhow::Result<(u64, u64)> {
        conn.stream.set_live_counters(live_up, live_down);
        self.handle_tcp(conn).await
    }
    /// 处理一个 UDP 包
    async fn handle_udp(&self, packet: InboundUdpPacket) -> anyhow::Result<()>;
    fn tag(&self) -> &str;

    /// 向下转型支持（用于 provider watcher 识别 SelectorOutbound / UrlTestOutbound）
    fn as_any(&self) -> &dyn std::any::Any {
        // 默认实现返回 unit，具体类型需覆盖此方法
        &()
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.tag().to_string(),
            type_name: "Proxy".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    fn select_child(&self, _tag: &str) -> anyhow::Result<()> {
        anyhow::bail!("outbound '{}' is not selectable", self.tag())
    }

    /// 建立一条经由该出站的 TCP 隧道连接，供 DNS upstream 的 detour 使用。
    ///
    /// 默认实现直接连接目标地址（等同于 direct），出站实现可覆盖以走代理隧道。
    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let addr = tokio::net::lookup_host(format!("{host}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}:{port}"))?;
        let stream = tokio::net::TcpStream::connect(addr).await?;
        set_tcp_opts(&stream)?;
        Ok(Box::new(stream))
    }

    /// 建立一条经由该出站的 UDP 关联，用于 DNS-over-UDP 走 detour。
    ///
    /// 返回一个 `UdpRelay`，调用方通过 `send_to` / `recv_from` 收发 UDP 数据报，
    /// 数据报会经过代理隧道转发（如 SOCKS5 UDP ASSOCIATE、Shadowsocks UDP relay 等）。
    ///
    /// 默认返回 `None` 表示该出站不支持 UDP 转发，调用方应降级为 TCP。
    /// 对齐 sing-box `N.Dialer.ListenPacket`：支持 UDP 的出站返回 PacketConn，
    /// 不支持的降级。reflex 的 DNS UDP 查询在 detour 不支持 UDP 时降级为 TCP。
    async fn connect_udp(&self) -> anyhow::Result<Option<Box<dyn UdpRelay>>> {
        Ok(None)
    }
}

/// 经由代理出站的 UDP 数据报中继，供 DNS-over-UDP detour 使用。
///
/// `send_to` 将数据报发往指定的目标地址（代理负责转发），
/// `recv_from` 接收代理返回的响应数据报及其来源地址。
pub trait UdpRelay: Send + Sync {
    fn send_to(&self, buf: &[u8], target: std::net::SocketAddr) -> UdpRelayFut<'_>;
    fn recv_from(&self, buf: &mut [u8]) -> UdpRelayRecvFut<'_>;
}

/// `UdpRelay::send_to` 返回的 boxed future。
pub type UdpRelayFut<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>>;

/// `UdpRelay::recv_from` 返回的 boxed future（返回读到的字节数与来源地址）。
pub type UdpRelayRecvFut<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = std::io::Result<(usize, std::net::SocketAddr)>>
            + Send
            + 'a,
    >,
>;

/// 供 `connect_tcp` 返回值使用的类型别名：可读写的异步流。
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncReadWrite for T {}

// ── 双向转发 ──────────────────────────────────────────────────────────────────

// 在两个异步读写流之间双向透明转发，支持 TCP half-close。
//
// 参照 sing-box `connectionCopy`：某方向读到 EOF 后调用对端的 `shutdown()`
// 发送 TCP FIN，让对端能干净地感知到写端关闭，而不是悬挂等待超时。
//
// 使用 64 KiB buffer（sing-box 批量 size），相比默认 8 KiB 对大流量吞吐
// 提升明显（减少系统调用次数）。
//
// 返回 `(a→b 字节数, b→a 字节数)`。

// ── CountedStream：包装任意 AsyncRead+AsyncWrite，实时更新计数器 ───────────────

/// 透明包装一个双向流，在每次 read（下载）和 write（上传）时
/// 实时更新 `live_up` / `live_down` 原子计数器。
/// 用于在不修改各出站实现的情况下，为所有代理出站提供实时流量统计。
pub struct CountedStream<S> {
    inner: S,
    live_up: std::sync::Arc<portable_atomic::AtomicI64>,
    live_down: std::sync::Arc<portable_atomic::AtomicI64>,
}

impl<S> CountedStream<S> {
    pub fn new(
        inner: S,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) -> Self {
        Self {
            inner,
            live_up,
            live_down,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::sync::atomic::Ordering;
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        if after > before {
            self.live_down
                .fetch_add((after - before) as i64, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::sync::atomic::Ordering;
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = &result {
            self.live_up.fetch_add(*n as i64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 与 `relay` 相同，但每次转发时实时更新 `live_up` / `live_down` 原子计数器。
/// 供连接追踪器实时上报上传/下载字节数使用。
pub async fn relay_tracked<A, B>(
    a: A,
    b: B,
    live_up: std::sync::Arc<portable_atomic::AtomicI64>,
    live_down: std::sync::Arc<portable_atomic::AtomicI64>,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    const BUF_SIZE: usize = 65536;

    let (r1, r2) = tokio::join!(
        copy_half_tracked(&mut ar, &mut bw, BUF_SIZE, live_up),
        copy_half_tracked(&mut br, &mut aw, BUF_SIZE, live_down),
    );
    (r1, r2)
}

async fn copy_half_tracked<R, W>(
    reader: &mut R,
    writer: &mut W,
    buf_size: usize,
    counter: std::sync::Arc<portable_atomic::AtomicI64>,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use std::sync::atomic::Ordering;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        // 与 copy_half 同步：WS 路径必须显式 flush 才会把数据真正写入底层 TCP。
        if writer.flush().await.is_err() {
            break;
        }
        total += n as u64;
        counter.fetch_add(n as i64, Ordering::Relaxed);
    }
    let _ = writer.shutdown().await;
    total
}

pub async fn relay<A, B>(a: A, b: B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);

    const BUF_SIZE: usize = 65536;

    let (r1, r2) = tokio::join!(
        copy_half(&mut ar, &mut bw, BUF_SIZE),
        copy_half(&mut br, &mut aw, BUF_SIZE),
    );
    (r1, r2)
}

/// 单方向 copy：读到 EOF 后向写端发 shutdown（TCP half-close FIN）。
async fn copy_half<R, W>(reader: &mut R, writer: &mut W, buf_size: usize) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; buf_size];
    let mut total = 0u64;
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
        // 必须显式 flush：
        // 对 WebSocket（tokio-tungstenite）而言，poll_write 仅把 Binary 帧放入
        // tungstenite 内部 out_buffer，必须调用 poll_flush 才会真正写入底层 TCP。
        // 不加 flush 会导致 VLESS/Trojan + WS 的请求头与载荷滞留在缓冲区，
        // 服务端永远收不到请求，连接表现为卡死。
        // 对 TCP+TLS 路径 flush 几乎无开销（rustls 在 poll_write 时已写入 TCP）。
        if writer.flush().await.is_err() {
            break;
        }
        total += n as u64;
    }
    // 发送 FIN，通知对端写完了；忽略错误（连接可能已被对端关闭）
    let _ = writer.shutdown().await;
    total
}

// ── 目标地址解析 ──────────────────────────────────────────────────────────────

/// 解析「代理出站节点自身的服务器地址」（即各协议 outbound 配置里的 `server` 字段）。
///
/// - 若 `server` 已是 IP，直接返回，不查询 DNS。
/// - 若提供了 `resolver`，使用 `DnsResolver::resolve_proxy_domain`
///   （即 `dns.proxy_domain_resolver` 指定的上游，未配置则回退 dns.final 默认上游）。
/// - 若未注入 `resolver`（如未启用内置 DNS 模块），回退到系统 DNS，行为与之前一致。
pub async fn resolve_server_addr(
    server: &str,
    port: u16,
    resolver: Option<&Arc<DnsResolver>>,
) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Some(r) = resolver {
        let ip = r.resolve_proxy_domain(server).await?;
        Ok(SocketAddr::new(ip, port))
    } else {
        tokio::net::lookup_host((server, port))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {server}"))
    }
}

pub async fn resolve_target(target: &Target) -> anyhow::Result<SocketAddr> {
    match target {
        Target::Socket(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            let addr = tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))?;
            Ok(addr)
        }
    }
}

/// 优先用内部 DNS 解析器解析域名，避免走系统 getaddrinfo。
/// 若 resolver 为 None 则退回系统解析（向后兼容）。
pub async fn resolve_target_with_dns(
    target: &Target,
    resolver: Option<&Arc<DnsResolver>>,
) -> anyhow::Result<SocketAddr> {
    match target {
        Target::Socket(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            if let Some(r) = resolver {
                let ip = r.resolve_domain(host).await?;
                Ok(SocketAddr::new(ip, *port))
            } else {
                let addr = tokio::net::lookup_host((host.as_str(), *port))
                    .await?
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("DNS lookup failed for {host}"))?;
                Ok(addr)
            }
        }
    }
}
