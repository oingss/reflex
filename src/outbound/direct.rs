use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::net::TcpStream;
use tracing::debug;

#[cfg(any(target_os = "linux", target_os = "windows"))]
use crate::outbound::common::interface_finder;
use crate::outbound::common::interface_finder::local_ranges;
use crate::{
    config::dns::ResolveStrategy,
    config::outbound::DirectOutboundConfig,
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, apply_mark_to_udp, relay, resolve_target_with_dns, set_tcp_opts,
        Outbound, OutboundStatus,
    },
};

// ── Direct ────────────────────────────────────────────────────────────────────

pub struct DirectOutbound {
    config: DirectOutboundConfig,
    /// 内部 DNS 解析器，用于域名解析（替代系统 getaddrinfo）
    resolver: Option<Arc<DnsResolver>>,
    /// SO_MARK（来自 route.default_mark），0 表示不设置
    routing_mark: u32,
    /// 多网卡时自动选择出口网卡（来自 route.auto_detect_interface）
    auto_detect_interface: bool,
    /// 手动指定出口网卡名称（来自 route.default_interface），优先于自动检测
    default_interface: Option<String>,
    /// TCP 连接超时（来自 connect_timeout_ms，默认 5s）
    connect_timeout: Duration,
    /// 域名解析偏好（来自 domain_strategy），None 表示由 resolver 全局策略决定
    domain_strategy: Option<ResolveStrategy>,
}

impl DirectOutbound {
    const DEFAULT_TCP_CONNECT_TIMEOUT_MS: u64 = 5000;

    fn build(config: DirectOutboundConfig, resolver: Option<Arc<DnsResolver>>) -> Self {
        let connect_timeout = Duration::from_millis(
            config
                .connect_timeout_ms
                .unwrap_or(Self::DEFAULT_TCP_CONNECT_TIMEOUT_MS),
        );
        let domain_strategy = config.domain_strategy;
        Self {
            config,
            resolver,
            routing_mark: 0,
            auto_detect_interface: false,
            default_interface: None,
            connect_timeout,
            domain_strategy,
        }
    }

    pub fn new(config: DirectOutboundConfig) -> Self {
        Self::build(config, None)
    }

    pub fn with_resolver(config: DirectOutboundConfig, resolver: Arc<DnsResolver>) -> Self {
        Self::build(config, Some(resolver))
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    pub fn with_auto_detect_interface(mut self, enabled: bool) -> Self {
        self.auto_detect_interface = enabled;
        self
    }

    pub fn with_default_interface(mut self, iface: Option<String>) -> Self {
        self.default_interface = iface;
        self
    }

    /// 对 socket fd 应用网卡绑定逻辑：
    ///   1. default_interface 指定了 → 直接绑定
    ///   2. auto_detect_interface 为 true → 按目标 IP 自动选卡
    #[cfg(target_os = "linux")]
    fn apply_interface_bind(&self, fd: std::os::unix::io::RawFd, target_ip: std::net::IpAddr) {
        if let Some(ref iface) = self.default_interface {
            let _ = interface_finder::bind_to_interface(fd, iface);
        } else if self.auto_detect_interface {
            interface_finder::auto_bind_interface_for_target(fd, target_ip);
        }
    }

    /// macOS 版网卡绑定：没有 SO_MARK，用 IP_BOUND_IF / IPV6_BOUND_IF 把
    /// socket 钉在 auto_route 生效前探测到的物理网卡上（未注册时为空操作），
    /// 与 connect_tcp_interface 的 macOS 分支保持一致。
    #[cfg(target_os = "macos")]
    fn apply_interface_bind(&self, fd: std::os::unix::io::RawFd, target_ip: std::net::IpAddr) {
        crate::outbound::common::interface_finder::macos_iface::bind_socket_to_physical_interface(
            fd, target_ip,
        );
    }

    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    fn apply_interface_bind(&self, _fd: std::os::unix::io::RawFd, _target_ip: std::net::IpAddr) {}

    /// 在 connect 之前对未连接 socket 设置 SO_MARK。
    ///
    /// 修复：旧实现只在 connect 成功后通过 apply_mark_to_tcp 打 mark，
    /// 而路由选择发生在 connect() 时——post-connect 的 mark 对首个 SYN
    /// 完全无效，auto_route 下 direct 出站的首包仍会进入 TUN 形成环回。
    #[cfg(target_os = "linux")]
    fn apply_mark_pre_connect(&self, sock: &tokio::net::TcpSocket) -> std::io::Result<()> {
        if self.routing_mark != 0 {
            use std::os::unix::io::AsRawFd;
            let fd = sock.as_raw_fd();
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &self.routing_mark as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                )
            };
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    #[allow(unused_variables)]
    fn apply_mark_pre_connect(&self, _sock: &tokio::net::TcpSocket) -> std::io::Result<()> {
        Ok(())
    }

    /// Windows 版网卡绑定：没有 SO_BINDTODEVICE，用 IP_UNICAST_IF /
    /// IPV6_UNICAST_IF 把 socket 绑定到 TUN auto_route 生效前探测到的物理
    /// 网卡，避免 direct 出站流量被 TUN 接管的默认路由重新截获、形成环路。
    /// default_interface 指定网卡名的场景在 Windows 上按 auto_detect 的物理
    /// 网卡处理（Windows 侧暂不支持按名称精确指定，与 auto_detect_interface
    /// 等价对待，优先保证不环回）。
    #[cfg(target_os = "windows")]
    fn apply_interface_bind(
        &self,
        raw_socket: std::os::windows::io::RawSocket,
        target_ip: std::net::IpAddr,
    ) {
        interface_finder::windows_iface::bind_socket_to_physical_interface(raw_socket, target_ip);
    }

    /// Windows：在 connect 前显式 bind 到物理网卡的源 IP（v4 / v6 自适应）。
    ///
    /// 历史背景：曾尝试用 `bind(socket, <phys_src_ip>:0)` 把源 IP 钉到物理
    /// 网卡，理由是"Windows 11 23H2 上仅 IP_UNICAST_IF 不能可靠阻止 TCP SYN
    /// 与 UDP datagram 经由 TUN 默认路由环回"。但后续日志分析表明：
    ///   1. 之前观察到的 TUN NAT 表里 src=172.31.0.1 是**应用流量**的 NAT
    ///      条目（src=172.31.0.1:<TUN listener port>），并非 reflex 自身
    ///      socket 流量环回——TUN 给应用 TCP 流量做 NAT 时源 IP 就是 TUN
    ///      自身 IP，这是正常的 NAT 行为，不是环回。
    ///   2. 启用 src_ip bind 后 direct TCP connect 仍 5s 超时，UDP 30s
    ///      idle timeout（同样没收到回包）——bind 反而可能破坏 Windows
    ///      路由层的源 IP 自动选择，导致回包路径异常。
    ///   3. clash-rs 在 Windows 上仅用 IP_UNICAST_IF + bind(0.0.0.0:0)
    ///      （socket_helpers.rs new_tcp_stream/new_udp_socket），不显式 bind
    ///      src_ip，生产环境工作正常。
    ///
    /// 据此回退到 clash-rs 验证过的方案：仅依赖 IP_UNICAST_IF 钉物理网卡，
    /// bind 让系统自动选源 IP。函数保留为 no-op，避免改动 3 处调用点。
    /// 如未来确认 IP_UNICAST_IF 单独确实不够（需用 TUN NAT 表中 reflex
    /// 自身 socket 流量条目佐证，而非应用流量 NAT），再恢复实现。
    #[cfg(target_os = "windows")]
    #[allow(unused_variables)]
    fn bind_to_physical_src_ip(
        &self,
        socket: &tokio::net::TcpSocket,
        target_ip: std::net::IpAddr,
    ) -> std::io::Result<()> {
        // no-op：仅 IP_UNICAST_IF（apply_interface_bind 已设置）+ 隐式 bind
        // （由 tokio::net::TcpSocket::connect 自动完成，bind 到 0.0.0.0:0
        // 让 Windows 按出站接口自动选源 IP）。
        Ok(())
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    #[allow(dead_code)]
    fn apply_interface_bind(&self, _fd: i32, _target_ip: std::net::IpAddr) {}

    /// 按 `domain_strategy` 过滤/排序解析结果（对齐 sing-box domain_strategy）。
    /// 不依赖 &self：UDP 会话的 spawn 任务里也要用（静态调用）。
    fn apply_domain_strategy(mut ips: Vec<IpAddr>, strategy: ResolveStrategy) -> Vec<IpAddr> {
        match strategy {
            ResolveStrategy::Ipv4Only => ips.retain(|ip| ip.is_ipv4()),
            ResolveStrategy::Ipv6Only => ips.retain(|ip| ip.is_ipv6()),
            // sort_by_key 是稳定排序：仅调整 v4/v6 相对顺序，不改变同族内
            // DNS 返回的原始顺序
            ResolveStrategy::PreferIpv4 => ips.sort_by_key(|ip| !ip.is_ipv4()),
            ResolveStrategy::PreferIpv6 => ips.sort_by_key(|ip| !ip.is_ipv6()),
        }
        ips
    }

    /// 解析目标为候选地址列表：IP 目标原样返回；域名目标在 resolver 可用时
    /// 取全部记录并按 domain_strategy 过滤/排序；无 resolver 或解析异常时
    /// 回退单地址解析路径（保持原有行为与报错）。
    async fn resolve_candidates(&self, target: &Target) -> anyhow::Result<Vec<SocketAddr>> {
        Self::resolve_candidates_with(target, self.resolver.as_ref(), self.domain_strategy).await
    }

    async fn resolve_candidates_with(
        target: &Target,
        resolver: Option<&Arc<DnsResolver>>,
        strategy: Option<ResolveStrategy>,
    ) -> anyhow::Result<Vec<SocketAddr>> {
        match target {
            Target::Socket(addr) => Ok(vec![*addr]),
            Target::Domain(host, port) => {
                if let Some(resolver) = resolver {
                    match resolver.resolve_domain_all(host).await {
                        Ok(ips) if !ips.is_empty() => {
                            let ips = match strategy {
                                Some(s) => Self::apply_domain_strategy(ips, s),
                                None => ips,
                            };
                            if ips.is_empty() {
                                anyhow::bail!(
                                    "direct: domain_strategy filtered out all addresses for {host}"
                                );
                            }
                            return Ok(ips
                                .into_iter()
                                .map(|ip| SocketAddr::new(ip, *port))
                                .collect());
                        }
                        Ok(_) => {
                            // 候选为空，落到下面的常规单地址路径（会得到一致的报错信息）
                        }
                        Err(e) => {
                            debug!(
                                host = %host, err = %e,
                                "direct: resolve_domain_all failed, falling back to single-address path"
                            );
                        }
                    }
                }
                let addr = resolve_target_with_dns(target, resolver).await?;
                Ok(vec![addr])
            }
        }
    }

    /// 对齐 sing-box direct 出站的 isMyLoopbackAddress 检查：目标地址落在本机
    /// 任一网卡子网内（含 TUN 网段）时直接拒绝，防止 auto_route 下的数据环路。
    /// 任一候选命中即拒绝整次拨号（与 sing-box DialParallel 行为一致）。
    fn reject_local_loopback(candidates: &[SocketAddr]) -> anyhow::Result<()> {
        for c in candidates {
            if local_ranges::is_local_loopback(c.ip()) {
                anyhow::bail!("loopback connection to TUN range: {}", c.ip());
            }
        }
        Ok(())
    }

    /// 向已解析的目标地址建立 TCP 连接，尊重 bind_address / auto_detect_interface / default_interface。
    async fn tcp_connect_addr(&self, addr: SocketAddr) -> anyhow::Result<TcpStream> {
        let connect_timeout = self.connect_timeout;

        let stream = if let Some(bind_ip) = &self.config.bind_address {
            // 用户手动指定出口 IP
            let bind_addr: SocketAddr = format!("{bind_ip}:0").parse()?;
            let socket = if bind_addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            socket.set_reuseaddr(true)?;
            socket.bind(bind_addr)?;
            // bind_address 模式同样需要防回环：绑定了源 IP 仍会被 TUN
            // 接管的默认路由截获（Windows/macOS 绑物理网卡；Linux 打 mark）
            {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    self.apply_interface_bind(socket.as_raw_fd(), addr.ip());
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::io::AsRawSocket;
                    self.apply_interface_bind(socket.as_raw_socket(), addr.ip());
                }
            }
            self.apply_mark_pre_connect(&socket)?;
            tokio::time::timeout(connect_timeout, socket.connect(addr))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "direct tcp connect timeout ({}ms) to {}",
                        self.connect_timeout.as_millis() as u64,
                        addr
                    )
                })??
        } else if self.default_interface.is_some() || self.auto_detect_interface {
            // 网卡绑定模式：在 connect 之前用 SO_BINDTODEVICE 绑定正确网卡
            let socket = if addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            socket.set_reuseaddr(true)?;
            {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    self.apply_interface_bind(socket.as_raw_fd(), addr.ip());
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::io::AsRawSocket;
                    self.apply_interface_bind(socket.as_raw_socket(), addr.ip());
                    // 关键：仅 IP_UNICAST_IF 在 Windows 11 23H2 实测不够，
                    // 还需显式 bind 到物理网卡源 IP，否则 TCP SYN 仍走 TUN。
                    self.bind_to_physical_src_ip(&socket, addr.ip())?;
                }
            }
            // SO_MARK 必须在 connect 之前设置（见 apply_mark_pre_connect）
            self.apply_mark_pre_connect(&socket)?;
            tokio::time::timeout(connect_timeout, socket.connect(addr))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "direct tcp connect timeout ({}ms) to {}",
                        self.connect_timeout.as_millis() as u64,
                        addr
                    )
                })??
        } else {
            // 无绑定配置：也改用 TcpSocket 在 connect 之前完成防回环设置。
            // 修复：旧实现用 TcpStream::connect（无法在 connect 前干预），
            // Linux 上 post-connect 的 SO_MARK 对首个 SYN 无效、Windows/macOS
            // 上完全未绑定网卡，auto_route 下均会形成 direct → TUN 环回。
            let socket = if addr.is_ipv6() {
                tokio::net::TcpSocket::new_v6()?
            } else {
                tokio::net::TcpSocket::new_v4()?
            };
            {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    self.apply_interface_bind(socket.as_raw_fd(), addr.ip());
                }
                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::io::AsRawSocket;
                    self.apply_interface_bind(socket.as_raw_socket(), addr.ip());
                    // 关键：仅 IP_UNICAST_IF 在 Windows 11 23H2 实测不够，
                    // 还需显式 bind 到物理网卡源 IP，否则 TCP SYN 仍走 TUN。
                    self.bind_to_physical_src_ip(&socket, addr.ip())?;
                }
            }
            self.apply_mark_pre_connect(&socket)?;
            tokio::time::timeout(connect_timeout, socket.connect(addr))
                .await
                .map_err(|_| {
                    anyhow::anyhow!(
                        "direct tcp connect timeout ({}ms) to {}",
                        self.connect_timeout.as_millis() as u64,
                        addr
                    )
                })??
        };
        set_tcp_opts(&stream)?;
        apply_mark_to_tcp(&stream, self.routing_mark)?;
        Ok(stream)
    }

    /// 解析目标并建立 TCP 连接的统一入口。
    ///
    /// 域名目标在配置了 `network_strategy = "happy_eyeballs"` 且内部 DNS
    /// resolver 可用时，会并发/错峰尝试多个候选地址（IPv4 + IPv6，对齐
    /// sing-box `network_strategy` / `fallback_delay`）；其余情况（IP 目标、
    /// 未启用该策略、resolver 不可用、或解析候选为空）保持单地址连接。
    /// 拨号前对候选列表做本机地址段回环检查（对齐 sing-box
    /// isMyLoopbackAddress），命中直接拒绝。
    async fn dial_tcp(&self, target: &crate::inbound::Target) -> anyhow::Result<TcpStream> {
        let candidates = self.resolve_candidates(target).await?;
        Self::reject_local_loopback(&candidates)?;

        let use_happy_eyeballs = self
            .config
            .network_strategy
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("happy_eyeballs"));

        if use_happy_eyeballs && candidates.len() > 1 {
            let fallback_delay = Duration::from_millis(
                self.config.fallback_delay_ms.unwrap_or(250),
            );
            debug!(
                tag=%self.config.tag,
                candidates=candidates.len(),
                fallback_delay_ms=fallback_delay.as_millis() as u64,
                "happy_eyeballs: dialing multiple candidates"
            );
            return self
                .connect_tcp_happy_eyeballs(&candidates, fallback_delay)
                .await;
        }

        self.tcp_connect_addr(candidates[0]).await
    }

    /// Happy Eyeballs（RFC 8305）风格的多候选地址拨号：按 `candidates` 顺序
    /// （已由 `resolve_domain_all` 按 strategy 排好优先级）逐个启动连接尝试，
    /// 每隔 `fallback_delay` 启动下一个候选而不必等前一个失败或超时；任意一个
    /// 候选率先连接成功就立即返回，其余仍在进行中的尝试随 `inflight` 一起被
    /// 丢弃，其底层 socket 在 drop 时自动关闭。
    async fn connect_tcp_happy_eyeballs(
        &self,
        candidates: &[SocketAddr],
        fallback_delay: tokio::time::Duration,
    ) -> anyhow::Result<TcpStream> {
        if candidates.is_empty() {
            anyhow::bail!("direct: no candidate addresses to connect");
        }
        if candidates.len() == 1 {
            return self.tcp_connect_addr(candidates[0]).await;
        }

        let mut remaining = candidates.iter().copied().peekable();
        let mut inflight = futures_util::stream::FuturesUnordered::new();
        let mut last_err: Option<anyhow::Error> = None;

        // 启动第一个候选（最优先地址，不必等待 fallback_delay）。
        if let Some(addr) = remaining.next() {
            inflight.push(self.tcp_connect_addr(addr));
        }

        loop {
            if inflight.is_empty() && remaining.peek().is_none() {
                break;
            }
            let has_more = remaining.peek().is_some();
            tokio::select! {
                biased;
                res = inflight.next(), if !inflight.is_empty() => {
                    match res {
                        Some(Ok(stream)) => return Ok(stream),
                        Some(Err(e)) => {
                            debug!(
                                tag=%self.config.tag, err=%e,
                                "happy_eyeballs: candidate failed, trying next if available"
                            );
                            last_err = Some(e);
                            if let Some(addr) = remaining.next() {
                                inflight.push(self.tcp_connect_addr(addr));
                            }
                        }
                        None => {}
                    }
                }
                _ = tokio::time::sleep(fallback_delay), if has_more => {
                    if let Some(addr) = remaining.next() {
                        debug!(
                            tag=%self.config.tag, addr=%addr,
                            "happy_eyeballs: fallback_delay elapsed, starting next candidate"
                        );
                        inflight.push(self.tcp_connect_addr(addr));
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("direct: all candidate addresses failed to connect")
        }))
    }

    /// 为单次 UDP 发送创建一个独立 socket，支持网卡绑定。
    async fn new_udp_socket(&self, dst: SocketAddr) -> anyhow::Result<tokio::net::UdpSocket> {
        if let Some(bind_ip) = &self.config.bind_address {
            let bind_addr: SocketAddr = format!("{bind_ip}:0").parse()?;
            let sock = tokio::net::UdpSocket::bind(bind_addr).await?;
            apply_mark_to_udp(&sock, self.routing_mark)?;
            return Ok(sock);
        }

        // Windows：必须用 socket2 手动控制 create → IP_UNICAST_IF → bind 序列，
        // tokio::net::UdpSocket::bind 一步完成 create+bind，没机会在中间插
        // setsockopt，导致 IP_UNICAST_IF 在已 bind 的 socket 上不生效。
        //
        // bind 用 0.0.0.0:0 / [::]:0（INADDR_ANY），让 Windows 按出站接口
        //（由 IP_UNICAST_IF 钉在物理网卡）自动选源 IP——对齐 clash-rs
        // socket_helpers.rs new_udp_socket 在 Windows 上的写法。曾尝试
        // 显式 bind(src_ip:0) 但日志显示 direct UDP 仍 30s idle timeout
        //（没收到回包），且可能破坏 Windows 路由层的源 IP 自动选择。
        #[cfg(target_os = "windows")]
        #[allow(clippy::needless_return)] // cfg 分支结构需要 return 保持跨平台类型一致
        {
            use socket2::{Domain, Protocol, Socket, Type};
            let domain = if dst.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_reuse_address(true)?;
            // 1. IP_UNICAST_IF：钉住物理网卡，影响 egress 接口选择
            use std::os::windows::io::AsRawSocket;
            self.apply_interface_bind(sock.as_raw_socket(), dst.ip());
            // 2. bind 到 INADDR_ANY:0，让系统按出站接口自动选源 IP
            //    （clash-rs socket_helpers.rs new_udp_socket 同款写法）
            let bind_addr: SocketAddr = if dst.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            sock.bind(&bind_addr.into())?;
            tracing::debug!(
                tag = %self.config.tag, dst = %dst, bind_addr = %bind_addr,
                "direct: created UDP socket bound to INADDR_ANY (IP_UNICAST_IF set)"
            );
            // socket2 → std → tokio
            let std_sock: std::net::UdpSocket = sock.into();
            std_sock.set_nonblocking(true)?;
            let tokio_sock = tokio::net::UdpSocket::from_std(std_sock)?;
            apply_mark_to_udp(&tokio_sock, self.routing_mark)?;
            return Ok(tokio_sock);
        }

        #[cfg(not(target_os = "windows"))]
        {
            let bind_addr = if dst.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
            let sock = tokio::net::UdpSocket::bind(bind_addr).await?;

            if self.default_interface.is_some() || self.auto_detect_interface {
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    self.apply_interface_bind(sock.as_raw_fd(), dst.ip());
                }
            }

            apply_mark_to_udp(&sock, self.routing_mark)?;
            Ok(sock)
        }
    }
}

#[async_trait::async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Direct".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = crate::inbound::Target::Domain(host.to_string(), port);
        let stream = self.dial_tcp(&target).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(tag=%self.config.tag, target=%conn.target, "direct tcp");
        let remote = self.dial_tcp(&conn.target).await?;
        let (up, down) = relay(conn.stream, remote).await;
        debug!(tag=%self.config.tag, up=%up, down=%down, "direct tcp done");
        Ok((up, down))
    }

    async fn handle_tcp_live(
        &self,
        mut conn: crate::inbound::InboundTcpStream,
        live_up: std::sync::Arc<portable_atomic::AtomicI64>,
        live_down: std::sync::Arc<portable_atomic::AtomicI64>,
    ) -> anyhow::Result<(u64, u64)> {
        conn.stream.set_live_counters(live_up, live_down);
        // T3：武装 Drop-RST —— 直连拨号失败（连接拒绝/超时等）时内核发 RST，
        // 客户端立即感知（成功传输数据后自动解除，见 SniffedStream）。
        conn.stream.arm_rst_on_drop();
        self.handle_tcp(conn).await
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let candidates = self.resolve_candidates(&packet.target).await?;
        let first_dst = *candidates.first().ok_or_else(|| {
            anyhow::anyhow!("direct: no addresses resolved for {}", packet.target)
        })?;
        // 本机地址段回环检查（对齐 sing-box ListenPacket）：
        Self::reject_local_loopback(&candidates)?;
        debug!(tag=%self.config.tag, target=%packet.target, dst=%first_dst, "direct udp");

        let sock = std::sync::Arc::new(self.new_udp_socket(first_dst).await?);
        sock.send_to(&packet.data, first_dst).await?;

        let reply_tx = packet.session.reply_tx.clone();
        let client_src = packet.src;
        let tag = self.config.tag.clone();

        if let Some(mut rx) = packet.upstream_rx.take() {
            let sock_send = sock.clone();
            let resolver = self.resolver.clone();
            let strategy = self.domain_strategy;
            // 会话按 (src, outbound) 聚合后，同一客户端 socket 访问多个目标时
            // 复用一条出站 socket；每包需按 target 解析得到 dst。
            // 用 HashMap 缓存避免同一目标每包都走 DNS（DnsResolver 自身也有
            // 缓存，这里只是避免重复的 HashMap 查询与 Arc clone）。
            let first_target = packet.target.clone();
            tokio::spawn(async move {
                let mut dst_cache: std::collections::HashMap<Target, SocketAddr> =
                    std::collections::HashMap::new();
                dst_cache.insert(first_target, first_dst);
                while let Some((target, data)) = rx.recv().await {
                    let dst = match dst_cache.get(&target).copied() {
                        Some(d) => d,
                        None => {
                            let candidates = match Self::resolve_candidates_with(
                                &target,
                                resolver.as_ref(),
                                strategy,
                            )
                            .await
                            {
                                Ok(c) => c,
                                Err(e) => {
                                    debug!(target=%target, err=%e, "direct udp: dns resolve error");
                                    continue;
                                }
                            };
                            let Some(d) = candidates.first().copied() else {
                                continue;
                            };
                            // 本机网段目标不发出（与 TCP 路径一致的防护，
                            // 但 UDP 逐包处理，只丢弃该包不杀死会话）
                            if local_ranges::is_local_loopback(d.ip()) {
                                debug!(target=%target, dst=%d, "direct udp: dropping loopback-range packet");
                                continue;
                            }
                            dst_cache.insert(target, d);
                            d
                        }
                    };
                    if let Err(e) = sock_send.send_to(&data, dst).await {
                        debug!(dst=%dst, err=%e, "direct udp: upstream send error");
                        break;
                    }
                }
            });
        }

        let sock_recv = sock;
        let guards = packet.lifetime_guards;
        // 参照 sing-box route.go routePacketConnection：FakeIP 命中时保存了
        // 原 fakeip SocketAddr 到 origin_destination，UDP 回包需把源地址伪装回
        // fakeip（对应 sing-box 的 bufio.NewNATPacketConn 包装）；
        // 非 FakeIP 场景回退到真实服务器地址 first_dst（保持原行为）。
        let spoofed_src = packet.origin_destination.unwrap_or(first_dst);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                if reply_tx.is_closed() {
                    break;
                }
                match tokio::time::timeout(
                    tokio::time::Duration::from_secs(30),
                    sock_recv.recv_from(&mut buf),
                )
                .await
                {
                    Ok(Ok((n, _from))) => {
                        let data = bytes::Bytes::copy_from_slice(&buf[..n]);
                        if reply_tx
                            .send((data, client_src, spoofed_src))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(tag=%tag, dst=%first_dst, err=%e, "direct udp: recv error");
                        break;
                    }
                    Err(_) => {
                        debug!(tag=%tag, dst=%first_dst, "direct udp: idle timeout (30s), closing recv loop");
                        break;
                    }
                }
            }
            drop(guards);
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_direct() -> DirectOutbound {
        DirectOutbound::new(DirectOutboundConfig {
            tag: "direct".into(),
            bind_address: None,
            network_strategy: Some("happy_eyeballs".into()),
            fallback_delay_ms: Some(50),
            domain_strategy: None,
            connect_timeout_ms: None,
        })
    }

    /// 返回一个当前没有任何进程监听的本地地址：先 bind 拿到一个空闲端口，
    /// 再立刻 drop 监听器。在 loopback 上连接一个刚刚关闭的端口几乎总是
    /// 立刻收到 ECONNREFUSED（不会等到 5 秒连接超时），适合用来模拟"候选
    /// 地址连接失败"且不拖慢测试。
    async fn unused_addr() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[tokio::test]
    async fn happy_eyeballs_falls_back_to_working_candidate() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let bad_addr = unused_addr().await;
        let ob = make_direct();

        let result = ob
            .connect_tcp_happy_eyeballs(
                &[bad_addr, good_addr],
                tokio::time::Duration::from_millis(50),
            )
            .await;
        assert!(
            result.is_ok(),
            "expected happy eyeballs to succeed via the working candidate, got {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_single_candidate_behaves_like_direct_connect() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let ob = make_direct();
        let result = ob
            .connect_tcp_happy_eyeballs(&[addr], tokio::time::Duration::from_millis(50))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn happy_eyeballs_empty_candidates_errors() {
        let ob = make_direct();
        let result = ob
            .connect_tcp_happy_eyeballs(&[], tokio::time::Duration::from_millis(50))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn happy_eyeballs_all_candidates_failing_returns_error() {
        let bad1 = unused_addr().await;
        let bad2 = unused_addr().await;
        let ob = make_direct();
        let result = ob
            .connect_tcp_happy_eyeballs(&[bad1, bad2], tokio::time::Duration::from_millis(50))
            .await;
        assert!(result.is_err());
    }

    // ── domain_strategy ─────────────────────────────────────────────────────

    #[test]
    fn domain_strategy_orders_and_filters() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let ips = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
        ];
        // prefer_ipv4：v4 排前，同族内保持原顺序（稳定排序）
        let got = DirectOutbound::apply_domain_strategy(
            ips.clone(),
            ResolveStrategy::PreferIpv4,
        );
        assert_eq!(
            got,
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]
        );
        // prefer_ipv6：v6 排前
        let got = DirectOutbound::apply_domain_strategy(
            ips.clone(),
            ResolveStrategy::PreferIpv6,
        );
        assert_eq!(got[0], IpAddr::V6(Ipv6Addr::LOCALHOST));
        // ipv4_only / ipv6_only：过滤
        let got =
            DirectOutbound::apply_domain_strategy(ips.clone(), ResolveStrategy::Ipv4Only);
        assert!(got.iter().all(|ip| ip.is_ipv4()) && got.len() == 2);
        let got = DirectOutbound::apply_domain_strategy(ips, ResolveStrategy::Ipv6Only);
        assert!(got.iter().all(|ip| ip.is_ipv6()) && got.len() == 2);
    }

    // ── 本机地址段回环防护 ────────────────────────────────────────────────────

    #[test]
    fn local_loopback_guard_rejects_own_subnet_but_allows_exact_self() {
        use std::net::Ipv4Addr;
        // 注入 192.0.2.0/24（TEST-NET-1，不会与本机/测试网络冲突）
        local_ranges::set_for_test(vec![(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
            24,
        )]);
        // 同子网其它地址 → 拒绝
        assert!(local_ranges::is_local_loopback(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 100))));
        // 与前缀基址完全相等的本机地址 → 非 macOS 平台豁免
        assert!(!local_ranges::is_local_loopback(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))));
        // 异网段 → 放行
        assert!(!local_ranges::is_local_loopback(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        // 协议族不匹配 → 放行
        assert!(!local_ranges::is_local_loopback(
            IpAddr::V6("2001:db8::1".parse().unwrap())
        ));
    }

    #[tokio::test]
    async fn dial_tcp_rejects_loopback_range_target() {
        use std::net::Ipv4Addr;
        local_ranges::set_for_test(vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)]);
        let ob = make_direct();
        let target = Target::Socket(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 123)),
            80,
        ));
        let err = ob.dial_tcp(&target).await.unwrap_err();
        assert!(
            err.to_string().contains("loopback connection to TUN range"),
            "unexpected error: {err}"
        );
    }
}
       