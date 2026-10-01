pub mod block;
pub mod direct;
pub mod http;
pub mod socks;

pub mod anytls;
pub mod common;
pub mod hysteria2;
pub mod naive;
pub mod shadowquic;
pub mod shadowsocks;
pub mod ssh;
pub mod tailscale;
pub mod tls;
pub mod transport;
pub mod trojan;
pub mod tuic;
pub mod vision;
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

/// 全局出站 routing mark（来自 route.default_mark，app 启动护栏统一下发）。
///
/// `connect_tcp_interface` 是所有代理协议与 DNS TCP 上游共用的连接入口，
/// 它拿不到各自 outbound 实例的 routing_mark 字段，因此用进程级全局值。
/// Linux 上 SO_MARK 必须在 connect() 之前设置才会影响首个 SYN 的路由选择，
/// connect 之后设置对已建立的连接完全无效（历史环回 bug 的根源之一）。
static GLOBAL_ROUTING_MARK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// 由 app 启动护栏在检测到 auto_route TUN 入站时调用，统一下发出站 mark。
pub fn set_global_routing_mark(mark: u32) {
    GLOBAL_ROUTING_MARK.store(mark, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(target_os = "linux")]
fn global_routing_mark() -> u32 {
    GLOBAL_ROUTING_MARK.load(std::sync::atomic::Ordering::Relaxed)
}

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
    // 防环回的网卡绑定（Windows IP_UNICAST_IF / macOS IP_BOUND_IF）已统一前移
    // 到 `connect_tcp_interface` 在 connect **之前**完成——所有代理协议
    //（vmess/vless/trojan/shadowsocks/anytls/naive/http/socks/ssh 及
    // transport/{websocket,grpc,xhttp}）与 direct 出站均经该入口拨号，首个
    // SYN 即走物理网卡；QUIC 协议（hysteria2/tuic/shadowquic）经
    // `new_marked_quic_endpoint` 在 bind 前设置同样的绑定。
    //
    // 因此本函数 connect 之后的 Windows/macOS 分支是「冗余二次绑定」安全网：
    // 对已建立连接为 no-op，仅兜底任何绕过 connect_tcp_interface 的调用（当前
    // 不存在）。Linux 分支负责把「每个 outbound 实例自身的 routing_mark」设到
    // socket（connect 时用的是进程级 GLOBAL_ROUTING_MARK，已建立连接的路由不会
    // 因 post-connect 改 mark 而变，此处仅作标记/记账用途）。
    #[cfg(target_os = "windows")]
    {
        if let Ok(peer) = stream.peer_addr() {
            use std::os::windows::io::AsRawSocket;
            crate::outbound::common::interface_finder::windows_iface::bind_socket_to_physical_interface(
                stream.as_raw_socket(),
                peer.ip(),
            );
        }
    }
    // macOS：没有 SO_MARK，用 IP_BOUND_IF/IPV6_BOUND_IF 做等价处理（同上
    // Windows 分支，时序上的注意事项一致）。
    #[cfg(target_os = "macos")]
    {
        if let Ok(peer) = stream.peer_addr() {
            use std::os::unix::io::AsRawFd;
            crate::outbound::common::interface_finder::macos_iface::bind_socket_to_physical_interface(
                stream.as_raw_fd(),
                peer.ip(),
            );
        }
    }
    // Android：内核是 Linux，有 SO_MARK，但 Rust 的 `target_os = "linux"`
    // 不包含 android（它是独立的 target_os 值），上面的 Linux 分支不会为
    // Android 编译，之前完全没处理。这里不用自定义 mark，而是复用
    // `inbound::tun::platform::android` 已经装好的那条系统规则——
    // Android 的 VpnService.protect(socket) 本来就是靠给 socket 打
    // 0x20000（ANDROID_VPN_PROTECT_MARK）这个 fwmark，配合
    // `ip rule fwmark 0x20000 lookup main` 绕过 TUN 的；reflex 自己的出站
    // socket 打上同一个 mark 就能直接吃到这条已有规则，不需要再新增
    // 路由规则。注意：这个值必须跟 android.rs 里的 PROTECTED_FROM_VPN_MARK
    // 保持一致，改动其中一处务必同步另一处。
    #[cfg(target_os = "android")]
    {
        const ANDROID_VPN_PROTECT_MARK: u32 = 0x20000;
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &ANDROID_VPN_PROTECT_MARK as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
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
    // 同上，下沉到共用函数，Windows 上用 IP_UNICAST_IF/IPV6_UNICAST_IF 绑定
    // 物理网卡。UDP 场景下各协议普遍是先创建/bind socket、调用这个函数，
    // 再发第一个包，属于"发送前绑定"，时序上是正确的。
    #[cfg(target_os = "windows")]
    {
        if let Ok(local) = sock.local_addr() {
            use std::os::windows::io::AsRawSocket;
            crate::outbound::common::interface_finder::windows_iface::bind_socket_to_physical_interface(
                sock.as_raw_socket(),
                local.ip(),
            );
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(local) = sock.local_addr() {
            use std::os::unix::io::AsRawFd;
            crate::outbound::common::interface_finder::macos_iface::bind_socket_to_physical_interface(
                sock.as_raw_fd(),
                local.ip(),
            );
        }
    }
    // Android：见 apply_mark_to_tcp 里的说明，复用 VpnService.protect() 用的
    // 0x20000 fwmark，吃 android.rs 已装好的 `fwmark 0x20000 lookup main` 规则。
    #[cfg(target_os = "android")]
    {
        const ANDROID_VPN_PROTECT_MARK: u32 = 0x20000;
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &ANDROID_VPN_PROTECT_MARK as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
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

    // Android：在 bind 之前打上 VpnService.protect() 用的 0x20000 fwmark，
    // 复用 android.rs 已装好的 `fwmark 0x20000 lookup main` 规则，跟上面
    // Linux 分支的时序（bind 之前）保持一致。
    #[cfg(target_os = "android")]
    {
        const ANDROID_VPN_PROTECT_MARK: u32 = 0x20000;
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &ANDROID_VPN_PROTECT_MARK as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
        }
    }

    // Windows/macOS：先设 IP_UNICAST_IF 再 bind（对齐 clash-rs new_udp_socket
    // 顺序：must_bind_socket_on_interface 在 socket.bind 之前调用）。
    // 先绑接口再 bind，确保系统在 bind 时即按物理网卡分配本地地址，
    // 避免 TUN 路由已生效时 bind 走到 TUN 接口。hysteria2/tuic/shadowquic
    // 这几个基于 quinn 的协议因此自动获得防环回保护。
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        crate::outbound::common::interface_finder::windows_iface::bind_socket_to_physical_interface(
            sock.as_raw_socket(),
            bind.ip(),
        );
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        crate::outbound::common::interface_finder::macos_iface::bind_socket_to_physical_interface(
            sock.as_raw_fd(),
            bind.ip(),
        );
    }

    // Windows：bind 用传入的 0.0.0.0:0 / [::]:0（INADDR_ANY），让系统按
    // 出站接口（由 IP_UNICAST_IF 钉在物理网卡）自动选源 IP。对齐 clash-rs
    // socket_helpers.rs new_udp_socket 在 Windows 上的写法（"binding is
    // not necessary for linux but is required on windows" 指的是必须
    // bind 以获得有效 local_addr，而非必须 bind src_ip）。
    //
    // 不再替换 bind 为 src_ip:0：曾基于"仅 IP_UNICAST_IF 在 Windows 11
    // 23H2 不能阻止 QUIC UDP 包环回"的判断加了 src_ip bind，但日志分析
    // 表明该判断是误判。启用 src_ip bind 后 QUIC connect 仍 10s 超时
    //（没收到回包），反而可能破坏 Windows 路由层源 IP 自动选择。
    {
        sock.bind(&bind.into())?;
    }

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

/// 建立到 `addr` 的 TCP 连接，并在 **connect 之前** 把 socket 绑定到物理网卡
/// （Windows `IP_UNICAST_IF` / macOS `IP_BOUND_IF`），避免 auto_route 接管
/// 默认路由后 reflex 自身出站（无论协议）被 TUN 重新截获形成环路。
///
/// 与 `apply_mark_to_tcp` 的区别：`apply_mark_to_tcp` 在 connect **之后**调用，
/// 对 Windows/macOS 来说首包（SYN）已经按 TUN 默认路由发出并被 TUN 截获，
/// 事后绑定无效（实际表现为日志里反复出现
/// `tun: tcp v4 NAT src=<tun地址> dst=<代理服务器>` 的环回条目）。
/// 本函数用 `tokio::net::TcpSocket` 在 connect 之前完成绑定，对齐
/// sing-box common/dialer 的 `bind_interface` 语义。Linux/Android 不做网卡
/// 绑定，但会在 connect 之前打 SO_MARK（见下方 cfg 分支与 `GLOBAL_ROUTING_MARK`）。
pub async fn connect_tcp_interface(addr: std::net::SocketAddr) -> std::io::Result<TcpStream> {
    let sock = match addr {
        std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
        std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
    };
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        // IP_UNICAST_IF：钉住物理网卡，影响 egress 接口选择。
        //
        // 不再显式 bind(src_ip:0)：曾基于"仅 IP_UNICAST_IF 在 Windows 11
        // 23H2 不能阻止 TCP SYN 走 TUN"的判断加了 src_ip bind，但后续日志
        // 分析表明该判断是误判（TUN NAT 表里 src=172.31.0.1 是应用流量
        // NAT，不是 reflex 自身环回）。启用 src_ip bind 后 direct TCP connect
        // 仍 5s 超时、UDP 30s idle timeout（都没收到回包），反而可能破坏
        // Windows 路由层的源 IP 自动选择。回退到 clash-rs 验证过的方案：
        // 仅 IP_UNICAST_IF + connect 时由系统按出站接口自动选源 IP。
        crate::outbound::common::interface_finder::windows_iface::bind_socket_to_physical_interface(
            sock.as_raw_socket(),
            addr.ip(),
        );
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::io::AsRawFd;
        crate::outbound::common::interface_finder::macos_iface::bind_socket_to_physical_interface(
            sock.as_raw_fd(),
            addr.ip(),
        );
    }
    // Linux：connect 之前设置 SO_MARK（修复：旧实现只依赖各协议 connect 之后
    // 调用 apply_mark_to_tcp 打 mark，对已完成的 connect 路由选择完全无效，
    // 首个 SYN 仍会按 TUN 默认路由进入 TUN 形成环回）。mark 与
    // `ip rule not fwmark <mark>` 排除规则配套，由 app 启动护栏统一下发。
    #[cfg(target_os = "linux")]
    {
        let mark = global_routing_mark();
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
    // Android：VpnService 的 protect 机制同样要求在 connect 前打
    // ANDROID_VPN_PROTECT_MARK（与 inbound/tun/platform/android.rs 及
    // apply_mark_to_tcp 的 Android 分支保持同一常量），否则首个 SYN 已被
    // VpnService 路由进 TUN。
    #[cfg(target_os = "android")]
    {
        const ANDROID_VPN_PROTECT_MARK: u32 = 0x20000;
        use std::os::unix::io::AsRawFd;
        let fd = sock.as_raw_fd();
        unsafe {
            let _ = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &ANDROID_VPN_PROTECT_MARK as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
        }
    }
    sock.connect(addr).await
}

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

/// 对 TcpStream 统一设置 nodelay + keepalive + TCP Fast Open。
/// keepalive 能及时检测并清理死连接（网络中断、NAT 超时等），
/// 避免连接长期占用资源。
///
/// TCP Fast Open（Linux 4.11+）：
/// 与 sing-box `common/dialer/tfo.go` 对齐。`TCP_FASTOPEN_CONNECT` 让内核在
/// `connect()` 时自动尝试 TFO——若本地已有 TFO cookie，则把首包数据（SYN payload）
/// 一并发出，省 1-RTT。无 cookie 时退化为普通三次握手，无副作用。
/// 对 VLESS+TLS：首字节 TLS ClientHello 可与 SYN 同发，实现 1-RTT 起步
/// （0-RTT 需要 TLS session resumption 配合，由 P0.1 的 ClientConfig 缓存启用）。
pub fn set_tcp_opts(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL);
    sock.set_tcp_keepalive(&ka)?;

    // TCP Fast Open：仅 Linux 支持。
    // socket2 0.5 的 SockRef 未暴露 set_tcp_fastopen_connect，直接用 libc setsockopt
    // 设置 TCP_FASTOPEN_CONNECT（Linux 4.11+）。与 sing-box common/dialer/tfo.go 对齐：
    // 让内核在 connect() 时自动尝试 TFO——若本地已有 TFO cookie，则把首包数据
    // （SYN payload）一并发出，省 1-RTT。无 cookie 时退化为普通三次握手，无副作用。
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        // TCP_FASTOPEN_CONNECT = 30 on Linux
        const TCP_FASTOPEN_CONNECT: libc::c_int = 30;
        let fd = stream.as_raw_fd();
        let on: libc::c_int = 1;
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_FASTOPEN_CONNECT,
                &on as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }

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
        // T3：武装 Drop-RST —— 拨号失败时内核发 RST 而非 FIN，客户端立即感知
        // 拒绝（成功传输数据后自动解除，见 SniffedStream）。
        conn.stream.arm_rst_on_drop();
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
        let stream = connect_tcp_interface(addr).await?;
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
    resolve_server_addr_for("", server, port, resolver).await
}

/// `resolve_server_addr` 的防环版本：`self_tag` 为本出站的 tag。
///
/// 必须用本函数替代旧版的原因（TUN auto_route 场景实测踩坑）：
/// 解析代理服务器域名时若 DNS 上游 detour 指向本出站自身，会形成
/// 「建连 → 解析 → 再建连」的死锁（连接缓存互斥锁被外层持有，嵌套调用
/// 永久阻塞），日志表现为 DNS 全部 `deadline has elapsed` 且没有任何
/// 代理连接错误。此版本：
///   1. 过滤掉 detour 指向 `self_tag` 自身的 DNS 上游（对齐 sing-box
///      对 domain_resolver 的 loop 约束）；
///   2. 整个解析过程加 5s 超时——即使上游卡死（如系统 DNS 被 TUN 劫持
///      后黑洞），也会快速报错而不是无限挂起。
pub async fn resolve_server_addr_for(
    self_tag: &str,
    server: &str,
    port: u16,
    resolver: Option<&Arc<DnsResolver>>,
) -> anyhow::Result<SocketAddr> {
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        tracing::debug!(outbound = %self_tag, server = %server, %ip, "resolve_server_addr_for: literal IP, no DNS");
        return Ok(SocketAddr::new(ip, port));
    }
    tracing::debug!(outbound = %self_tag, server = %server, resolver_set = resolver.is_some(),
        "resolve_server_addr_for: domain, resolving");
    if let Some(r) = resolver {
        const BOOTSTRAP_DNS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        let ip = tokio::time::timeout(
            BOOTSTRAP_DNS_TIMEOUT,
            r.resolve_proxy_domain_for_outbound(server, self_tag),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "bootstrap DNS timeout ({BOOTSTRAP_DNS_TIMEOUT:?}) resolving proxy \
                 server '{server}' (outbound '{self_tag}'); the DNS upstream is likely \
                 unreachable or looped through this outbound itself"
            )
        })??;
        Ok(SocketAddr::new(ip, port))
    } else {
        tracing::warn!(outbound = %self_tag, server = %server,
            "resolve_server_addr_for: no resolver, falling back to system getaddrinfo (with 5s timeout)");
        const SYS_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        tokio::time::timeout(
            SYS_LOOKUP_TIMEOUT,
            tokio::net::lookup_host((server, port)),
        )
        .await
        .map_err(|_| anyhow::anyhow!(
            "system getaddrinfo timeout ({SYS_LOOKUP_TIMEOUT:?}) for '{server}' (outbound '{self_tag}')"
        ))??
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
