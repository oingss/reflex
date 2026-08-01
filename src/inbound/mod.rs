pub mod dns;
pub mod http;
pub mod mixed;
#[cfg(target_os = "linux")]
pub mod redir;
pub mod socks;
#[cfg(target_os = "linux")]
pub mod tproxy;
pub mod tun;

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};

// ── 监听地址解析工具 ───────────────────────────────────────────────────────────

/// 将 `listen`（IP 字符串）和 `port` 组合为 `SocketAddr`。
///
/// 支持三种填写方式，语义与 sing-box 完全一致：
///
/// | `listen` 值 | 含义                           | 组合结果           |
/// |-------------|--------------------------------|--------------------|
/// | `0.0.0.0`   | 监听所有 IPv4 接口             | `0.0.0.0:PORT`     |
/// | `127.0.0.1` | 仅本机 IPv4 回环               | `127.0.0.1:PORT`   |
/// | `::`        | 监听所有接口（IPv4 + IPv6）    | `[::]:PORT`        |
/// | `::1`       | 仅本机 IPv6 回环               | `[::1]:PORT`       |
///
/// IPv6 地址会自动加方括号，`format!("{}:{}", "::", port)` 产生的非法格式
/// `:::::PORT` 由此修正。
pub fn parse_listen_addr(listen: &str, port: u16) -> anyhow::Result<SocketAddr> {
    // 先尝试 "host:port" 格式（兼容用户直接填了含端口的字符串）
    let addr_str = if listen.contains(':') && !listen.starts_with('[') {
        // 裸 IPv6 地址（如 "::" 或 "::1"），需要加方括号
        format!("[{listen}]:{port}")
    } else {
        // IPv4 地址或已含方括号的 IPv6（如 "[::1]"）
        format!("{listen}:{port}")
    };
    addr_str
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("invalid listen address '{listen}:{port}': {e}"))
}

/// 解析 `external_controller` 风格的完整地址字符串（含端口）。
///
/// 支持：
/// - `0.0.0.0:9090`
/// - `127.0.0.1:9090`
/// - `[::]:9090`（标准 IPv6 含端口格式）
/// - `:::9090`（用户常见误填，自动修正为 `[::]:9090`）
/// - `:9090`（等价于 `0.0.0.0:9090`，sing-box 支持）
pub fn parse_controller_addr(addr: &str) -> anyhow::Result<SocketAddr> {
    // 标准格式：直接解析
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }

    // ":PORT" 简写 → "0.0.0.0:PORT"
    if let Some(port_str) = addr.strip_prefix(':') {
        if !port_str.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
            }
        }
    }

    // ":::PORT" 或 "HOST:PORT" 中 HOST 是裸 IPv6 的情况
    // 找最后一个 ':' 分割 host 和 port
    if let Some(colon_pos) = addr.rfind(':') {
        let (host, port_str) = (&addr[..colon_pos], &addr[colon_pos + 1..]);
        if let Ok(port) = port_str.parse::<u16>() {
            // host 是裸 IPv6（含有 ':'）且没有方括号
            let normalized = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            };
            if let Ok(sa) = normalized.parse::<SocketAddr>() {
                return Ok(sa);
            }
        }
    }

    Err(anyhow::anyhow!(
        "invalid address '{addr}': expected HOST:PORT, [IPv6]:PORT, or :PORT"
    ))
}

// ── 共享抽象 ──────────────────────────────────────────────────────────────────

/// 一条已建立的入站 TCP 连接，携带原始目标地址。
/// 路由层拿到它后决定走哪个出站。
pub struct InboundTcpStream {
    /// TCP 流（可能携带嗅探时 peek 出的前缀字节）
    pub stream: SniffedStream,
    /// 连接的真实目标（域名或 IP:Port）
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名（override_destination=false 时不覆盖 target，但保存在此）
    pub sniffed_domain: Option<String>,
}

// ── SniffedStream ─────────────────────────────────────────────────────────────

/// 对 [`TcpStream`] 的薄包装，允许在嗅探时将 peek 出的字节归还回去，
/// 使后续的出站读取对这些字节无感知。
///
/// 读取顺序：先消耗 `prefix`，再透传 `inner`。
/// 写入、关闭等操作直接委托给 `inner`。
pub struct SniffedStream {
    /// 嗅探阶段 peek 出的字节（未嗅探时为空）
    pub prefix: Bytes,
    pub inner: TcpStream,
    /// 实时流量计数器（可选）：由 `handle_tcp_live` 注入，在 poll_read/poll_write 里更新
    pub live_down: Option<std::sync::Arc<portable_atomic::AtomicI64>>,
    pub live_up: Option<std::sync::Arc<portable_atomic::AtomicI64>>,
    /// 缓存的 peer_addr：第一次调用 peer_addr() 成功后缓存，避免后续重复 syscall。
    /// router 的 route_tcp/route_tcp_after_sniff/route_tcp_after_resolve 三个
    /// 方法都会调用 peer_addr()，单条 TCP 连接会触发 3 次 getpeername syscall，
    /// 缓存后只调用 1 次。失败时不缓存（连接可能已关闭，下次重试也无意义，
    /// 但保持原语义：调用方拿到 Err）。
    peer_addr_cache: std::cell::OnceCell<std::net::SocketAddr>,
}

impl SniffedStream {
    /// 直接从裸 [`TcpStream`] 创建，prefix 为空（未嗅探）。
    pub fn new(stream: TcpStream) -> Self {
        Self {
            prefix: Bytes::new(),
            inner: stream,
            live_down: None,
            live_up: None,
            peer_addr_cache: std::cell::OnceCell::new(),
        }
    }

    /// 注入实时计数器，后续每次 read/write 都会更新对应原子值。
    pub fn set_live_counters(
        &mut self,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) {
        self.live_up = Some(live_up);
        self.live_down = Some(live_down);
    }

    /// 嗅探完成后，将 peek 出的字节作为 prefix 归还。
    pub fn prepend(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        if self.prefix.is_empty() {
            self.prefix = data;
        } else {
            // 极少见：多次 prepend，直接拼接
            let mut buf = bytes::BytesMut::with_capacity(self.prefix.len() + data.len());
            buf.extend_from_slice(&self.prefix);
            buf.extend_from_slice(&data);
            self.prefix = buf.freeze();
        }
    }
    /// 委托给内层 TcpStream 的 `peer_addr()`，首次成功调用后缓存结果。
    /// router 的 route_tcp/route_tcp_after_sniff/route_tcp_after_resolve 三个方法
    /// 都会调用 peer_addr()，单条 TCP 连接在 dispatcher 热路径上会触发 3 次
    /// getpeername syscall；缓存后只调用 1 次。失败时不缓存。
    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        if let Some(cached) = self.peer_addr_cache.get() {
            return Ok(*cached);
        }
        let addr = self.inner.peer_addr()?;
        let _ = self.peer_addr_cache.set(addr);
        Ok(addr)
    }
}

impl AsyncRead for SniffedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let amt = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..amt]);
            self.prefix.advance(amt);
            if let Some(c) = &self.live_down {
                c.fetch_add(amt as i64, std::sync::atomic::Ordering::Relaxed);
            }
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let n = buf.filled().len() - before;
            if n > 0 {
                if let Some(c) = &self.live_down {
                    c.fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        result
    }
}

impl AsyncWrite for SniffedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &result {
            if let Some(c) = &self.live_up {
                c.fetch_add(*n as i64, std::sync::atomic::Ordering::Relaxed);
            }
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// 一个入站 UDP 数据包（或 UDP 会话的第一个包），携带原始目标地址。
pub struct InboundUdpPacket {
    /// 数据载荷
    pub data: bytes::Bytes,
    /// 发送方地址（用于回包）
    pub src: SocketAddr,
    /// 真实目标地址
    pub target: Target,
    /// 来自哪个入站 tag
    pub inbound_tag: String,
    /// 嗅探识别出的应用层协议（如 `"dns"`），未嗅探时为 None
    pub sniffed_protocol: Option<String>,
    /// 嗅探识别出的域名（override_destination=false 时不覆盖 target，但保存在此）
    pub sniffed_domain: Option<String>,
    /// 原始 FakeIP 目标地址（参照 sing-box metadata.OriginDestination）。
    ///
    /// 仅在 dispatcher 做 FakeIP 反向查找命中时被设置：原本 `target` 是
    /// `Socket(fakeip, port)`，反向查到域名后被改写为 `Domain(domain, port)`，
    /// 此字段保存原 FakeIP SocketAddr，用于 UDP 回包时把源地址伪装回 fakeip
    /// （参照 sing-box `bufio.NewNATPacketConn` 的写回源地址改写）。
    ///
    /// 出站实现构造回包时应优先使用本字段，缺失时回退到 `target.to_socket_addr_lossy()`。
    pub origin_destination: Option<SocketAddr>,
    /// UDP 会话句柄（用于后续回包）
    pub session: UdpSession,
    /// 后续上行包通道（仅在 dispatcher run_udp_session 里非 None）。
    /// 出站实现收到后应持续从此通道读取并发往服务端，直到通道关闭或超时。
    /// 这保证整个会话共用同一个出站 socket（固定源端口），游戏协议要求此行为。
    ///
    /// 每个元素携带该包的目标 `(Target, Bytes)`：会话按 (src, outbound) 聚合后，
    /// 同一客户端 socket 访问多个目标的包会复用同一条出站连接，因此每包必须
    /// 携带自己的目标地址，出站实现据此构建协议帧（对齐 mihomo natTable 按 src 聚合）。
    pub upstream_rx: Option<tokio::sync::mpsc::Receiver<(Target, bytes::Bytes)>>,
    /// 需要与会话生命周期绑定的守卫对象（ConnGuard / UdpGuard 等）。
    /// 出站实现应将此字段 move 进持久 task，确保连接在 clash API 中保持可见。
    pub lifetime_guards: Vec<Box<dyn std::any::Any + Send>>,
}

/// 连接目标：域名或 IP
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Target {
    /// 域名 + 端口（来自 SOCKS5/HTTP CONNECT 握手，或 DNS 嗅探）
    Domain(String, u16),
    /// IP + 端口（来自 TProxy 或已解析）
    Socket(SocketAddr),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Domain(_, p) => *p,
            Self::Socket(a) => a.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Domain(d, _) => d.clone(),
            Self::Socket(a) => a.ip().to_string(),
        }
    }

    /// 将 Target 转为 SocketAddr，Domain 类型使用 0.0.0.0 占位（仅用于回包伪造源地址场景）
    pub fn to_socket_addr_lossy(&self) -> SocketAddr {
        match self {
            Self::Socket(a) => *a,
            Self::Domain(_, p) => SocketAddr::from(([0, 0, 0, 0], *p)),
        }
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(d, p) => write!(f, "{d}:{p}"),
            Self::Socket(a) => write!(f, "{a}"),
        }
    }
}

/// UDP 会话句柄，入站层持有，用于将出站的回包写回给客户端。
#[derive(Debug, Clone)]
pub struct UdpSession {
    /// 用于回包：(数据, 客户端地址, 伪造源地址=原始目标IP)
    pub reply_tx: tokio::sync::mpsc::Sender<(bytes::Bytes, SocketAddr, SocketAddr)>,
}

#[cfg(test)]
mod addr_tests {
    use super::*;

    // ── parse_listen_addr ──────────────────────────────────────────────────

    #[test]
    fn ipv4_any() {
        let a = parse_listen_addr("0.0.0.0", 7890).unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:7890");
        assert!(a.is_ipv4());
    }

    #[test]
    fn ipv4_loopback() {
        let a = parse_listen_addr("127.0.0.1", 1080).unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:1080");
    }

    #[test]
    fn ipv6_any_bare() {
        // "::" 裸 IPv6，必须自动加方括号
        let a = parse_listen_addr("::", 7890).unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 7890);
    }

    #[test]
    fn ipv6_loopback_bare() {
        let a = parse_listen_addr("::1", 5353).unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 5353);
    }

    #[test]
    fn invalid_listen_rejected() {
        assert!(parse_listen_addr("not-an-ip", 80).is_err());
    }

    // ── parse_controller_addr ─────────────────────────────────────────────

    #[test]
    fn controller_ipv4() {
        let a = parse_controller_addr("0.0.0.0:9090").unwrap();
        assert_eq!(a.to_string(), "0.0.0.0:9090");
    }

    #[test]
    fn controller_loopback() {
        let a = parse_controller_addr("127.0.0.1:9090").unwrap();
        assert_eq!(a.to_string(), "127.0.0.1:9090");
    }

    #[test]
    fn controller_ipv6_bracketed() {
        // 标准写法 [::]:9090
        let a = parse_controller_addr("[::]:9090").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 9090);
    }

    #[test]
    fn controller_ipv6_bare_triple_colon() {
        // 用户常见误填 :::9090，自动修正
        let a = parse_controller_addr(":::9090").unwrap();
        assert!(a.is_ipv6());
        assert_eq!(a.port(), 9090);
    }

    #[test]
    fn controller_shorthand_port_only() {
        // :9090 等价于 0.0.0.0:9090
        let a = parse_controller_addr(":9090").unwrap();
        assert_eq!(a.port(), 9090);
    }

    #[test]
    fn controller_invalid_rejected() {
        assert!(parse_controller_addr("notanaddr").is_err());
        assert!(parse_controller_addr("0.0.0.0").is_err()); // 缺端口
    }
}
