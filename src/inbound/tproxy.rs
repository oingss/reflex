use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::unix::io::{AsRawFd, RawFd},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::unix::AsyncFd,
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::TProxyInboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession},
};

pub struct TProxyInbound {
    config: TProxyInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl TProxyInbound {
    pub fn new(
        config: TProxyInboundConfig,
        tcp_tx: mpsc::Sender<InboundTcpStream>,
        udp_tx: mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self {
            config,
            tcp_tx,
            udp_tx,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            crate::inbound::parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = self.config.tag.clone();
        let net = self.config.network;
        let routing_mark = self.config.routing_mark;

        info!(tag=%tag, addr=%bind, "tproxy inbound starting");

        let mut handles = vec![];

        if net.tcp() {
            let listener = create_tproxy_tcp_listener(bind)?;
            let tx = self.tcp_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(
                async move { run_tcp(listener, tx, tag).await },
            ));
        }

        if net.udp() {
            let socket = create_tproxy_udp_socket(bind)?;
            let tx = self.udp_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(async move {
                run_udp(socket, tx, tag, routing_mark).await
            }));
        }

        for h in handles {
            h.await??;
        }
        Ok(())
    }
}

// ── TCP ───────────────────────────────────────────────────────────────────────

fn create_tproxy_tcp_listener(addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let is_v6 = addr.is_ipv6();
    let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    // 对齐 sing-box redir.TProxy（common/redir/tproxy_linux.go）：
    // - IPv4 socket：IP_TRANSPARENT(SOL_IP)
    // - IPv6 socket：IP_TRANSPARENT(SOL_IP) + IPV6_TRANSPARENT(SOL_IPV6)
    //   sing-box 对 IPv6 监听同时设置两者，这里对齐。
    sock.set_ip_transparent(true)?;
    if is_v6 {
        // 显式 IPV6_V6ONLY=false：确保 "::" 监听能同时接收 IPv4-mapped 流量。
        // Rust socket2 不像 Go stdlib 会对 AF_INET6 socket 隐式置 V6ONLY=0，
        // 若系统 sysctl net.ipv6.bindv6only=1，默认 V6ONLY=true 会导致 IPv4
        // 流量无法到达 tproxy listener。显式设置 false 以保证双栈兼容。
        sock.set_only_v6(false)?;
        // IPV6_TRANSPARENT：对齐 sing-box（socket2 0.5 无此方法，手动 setsockopt）
        unsafe {
            let one: libc::c_int = 1;
            let ret = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                warn!(err=%std::io::Error::last_os_error(), "failed to set IPV6_TRANSPARENT on tproxy tcp listener");
            }
        }
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(4096)?;
    Ok(TcpListener::from_std(std::net::TcpListener::from(sock))?)
}

async fn run_tcp(
    listener: TcpListener,
    tx: mpsc::Sender<InboundTcpStream>,
    tag: String,
) -> anyhow::Result<()> {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // EMFILE (24) / ENFILE (23)：FD 耗尽，短暂退避后继续。
                // 立即重试只会产生无意义的错误风暴并消耗 CPU。
                // 参考 sing-box loopTCPIn 的 Temporary() 处理逻辑。
                let raw = e.raw_os_error();
                if raw == Some(libc::EMFILE) || raw == Some(libc::ENFILE) {
                    error!(err=%e, "tproxy tcp accept error (fd exhausted, backing off 200ms)");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                } else {
                    error!(err=%e, "tproxy tcp accept error");
                }
                continue;
            }
        };

        let target = match get_original_dst_tcp(&stream) {
            Ok(dst) => Target::Socket(dst),
            Err(e) => {
                warn!(peer=%peer, err=%e, "failed to get original dst");
                continue;
            }
        };

        debug!(peer=%peer, target=%target, "tproxy tcp accepted");

        if tx
            .send(InboundTcpStream {
                stream: SniffedStream::new(stream),
                target,
                inbound_tag: tag.clone(),
                sniffed_protocol: None,
                sniffed_domain: None,
            })
            .await
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

fn get_original_dst_tcp(stream: &TcpStream) -> anyhow::Result<SocketAddr> {
    let fd = stream.as_raw_fd();
    unsafe {
        // IPv4
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        ) == 0
        {
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            return Ok(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(addr.sin_port),
            )));
        }
        // IPv6 (IP6T_SO_ORIGINAL_DST = 80)
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        if libc::getsockopt(
            fd,
            libc::IPPROTO_IPV6,
            80,
            &mut addr6 as *mut _ as *mut libc::c_void,
            &mut len6,
        ) == 0
        {
            let ip = Ipv6Addr::from(addr6.sin6_addr.s6_addr);
            return Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(addr6.sin6_port),
                0,
                0,
            )));
        }
    }
    anyhow::bail!(
        "SO_ORIGINAL_DST failed: {}",
        std::io::Error::last_os_error()
    )
}

// ── UDP ───────────────────────────────────────────────────────────────────────

/// UDP 会话：(src, dst) → 回包 sender，带最后活跃时间
struct UdpSessionEntry {
    /// (数据, 客户端地址, 伪造源地址) — 伪造源地址 = 原始目标（游戏服务器IP:port）
    reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
    last_seen: Instant,
    /// 该会话的空闲超时时长（按目标端口决定）
    timeout: Duration,
}

fn create_tproxy_udp_socket(addr: SocketAddr) -> anyhow::Result<std::net::UdpSocket> {
    let is_v6 = addr.is_ipv6();
    let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    // 对齐 sing-box redir.TProxy：IPv4 设 IP_TRANSPARENT，IPv6 额外设 IPV6_TRANSPARENT
    sock.set_ip_transparent(true)?;
    if is_v6 {
        // 显式 IPV6_V6ONLY=false：确保 "::" 双栈监听能收到 IPv4-mapped 流量。
        // 下方 IP_RECVORIGDSTADDR 双栈处理逻辑依赖 V6ONLY=false（否则永远收不到
        // IPv4-mapped 流量，对应的 cmsg 选项也就无意义）。若系统
        // net.ipv6.bindv6only=1，不显式置 false 会导致 IPv4 UDP 流量全部丢失。
        sock.set_only_v6(false)?;
        // IPV6_TRANSPARENT（对齐 sing-box，socket2 0.5 无此方法，手动 setsockopt）
        unsafe {
            let one: libc::c_int = 1;
            let ret = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                warn!(err=%std::io::Error::last_os_error(), "failed to set IPV6_TRANSPARENT on tproxy udp socket");
            }
        }
    }
    sock.set_nonblocking(true)?;

    // 关键修复：监听地址为 "::"（双栈）时，内核会同时接收原生 IPv6 流量
    // 和经 IPv4-mapped 地址（::ffff:a.b.c.d）进入的 IPv4 流量。
    // 这两类流量在 recvmsg 时分别需要 IPV6_RECVORIGDSTADDR 和
    // IP_RECVORIGDSTADDR 才能拿到 TPROXY 的原始目标地址 cmsg；
    // 二者并非互斥关系，必须都设置，否则双栈 socket 收到的 IPv4-mapped
    // 流量会因为只开了 v6 选项而拿不到 cmsg，导致 recvmsg 报
    // "no original dst in cmsg" 并被丢弃（IPv4 UDP 流量——例如绝大多数
    // 游戏的 UDP 对战流量——会因此完全无法建立 tproxy 会话）。
    //
    // 对纯 IPv4-only socket（listen 配置了具体的 IPv4 地址而非 "::"/"0.0.0.0"
    // 双栈地址），设置 IPV6_RECVORIGDSTADDR 会因为协议族不对而失败，这里忽略
    // 该 setsockopt 的返回值即可，不影响 IPv4 选项的生效。
    unsafe {
        let one: libc::c_int = 1;

        // 是否为可能承载 IPv4-mapped 流量的双栈 / IPv6 socket
        let is_ipv6_socket = addr.is_ipv6();

        if !is_ipv6_socket {
            // 纯 IPv4 socket：只设置 IPv4 选项
            let ret = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                warn!(err=%std::io::Error::last_os_error(), "failed to set IP_RECVORIGDSTADDR");
            }
        } else {
            // IPv6 / 双栈 socket：两个选项都要设置
            let ret_v6 = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret_v6 != 0 {
                warn!(err=%std::io::Error::last_os_error(), "failed to set IPV6_RECVORIGDSTADDR");
            }

            // 仅当不是 IPV6_V6ONLY 时，这个 socket 才可能收到 IPv4-mapped 流量。
            // 默认（未显式设置 IPV6_V6ONLY）Linux 双栈 socket 是关闭 V6ONLY 的，
            // 即会接收 IPv4-mapped 流量，所以始终尝试设置 IPv4 选项；
            // 若失败（例如某些系统强制 V6ONLY 导致协议层拒绝），忽略错误即可，
            // 不影响纯 IPv6 流量正常工作。
            let ret_v4 = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVORIGDSTADDR,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret_v4 != 0 {
                debug!(
                    err=%std::io::Error::last_os_error(),
                    "failed to set IP_RECVORIGDSTADDR on dual-stack socket (expected if V6ONLY is forced)"
                );
            }
        }
    }
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// tproxy UDP 会话空闲超时（参照 sing-box：默认 5 分钟，DNS/NTP/STUN 用 10 s）
const TPROXY_UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

fn tproxy_udp_timeout_for_port(port: u16) -> Duration {
    match port {
        53 | 123 | 3478 => Duration::from_secs(10),
        443 => Duration::from_secs(30),
        _ => TPROXY_UDP_SESSION_TIMEOUT,
    }
}

async fn run_udp(
    socket: std::net::UdpSocket,
    tx: mpsc::Sender<InboundUdpPacket>,
    tag: String,
    routing_mark: u32,
) -> anyhow::Result<()> {
    let local_addr = socket.local_addr()?;
    info!(tag=%tag, addr=%local_addr, routing_mark=%routing_mark, "tproxy udp listener started");
    let async_fd = Arc::new(AsyncFd::new(socket)?);
    // (数据, 客户端地址, 伪造源地址=游戏服务器IP:port)
    let (global_reply_tx, mut global_reply_rx) =
        mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(256);

    // 回包发送循环：照抄 sing-box tproxyPacketWriter 的做法
    // 新建一个 IP_TRANSPARENT socket，bind 到游戏服务器的 IP:port，
    // 然后直接 send_to 客户端——客户端收到的源地址天然就是游戏服务器地址。
    // 同时必须设置 SO_MARK = routing_mark，否则新 socket 发出的包会被
    // nftables 的 proxy_out 链再次拦截，导致回包永远发不出去。
    //
    // 性能优化：sing-box 会按源/目的对缓存 writeback socket，避免每包都走
    // socket/reuse/transparent/mark/bind 一整套 syscall 造成 TIME_WAIT 堆积
    // 与端口耗尽。这里以伪造源地址（server_addr）为 key 缓存 socket——同一个
    // server_addr 只需 bind 一次，即可对任意 client_addr 反复 send_to。
    // 该缓存仅被本任务消费，无需跨线程同步。
    tokio::spawn(async move {
        let mut cache: HashMap<SocketAddr, (Socket, Instant)> = HashMap::new();
        let mut sweep = tokio::time::interval(Duration::from_secs(60));
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = sweep.tick() => {
                    let before = cache.len();
                    cache.retain(|_, (_, last_used)| last_used.elapsed() < WRITEBACK_SOCKET_IDLE);
                    if before != cache.len() {
                        debug!(before, after = cache.len(), "tproxy writeback socket cache swept");
                    }
                }
                pkt = global_reply_rx.recv() => {
                    let Some((data, client_addr, server_addr)) = pkt else { break; };
                    if !cache.contains_key(&server_addr) {
                        // 超过上限时淘汰最久未用的条目
                        if cache.len() >= WRITEBACK_CACHE_CAP {
                            if let Some((&k, _)) =
                                cache.iter().min_by_key(|(_, (_, last_used))| *last_used)
                            {
                                cache.remove(&k);
                            }
                        }
                        match create_tproxy_writeback_socket(server_addr, routing_mark) {
                            Ok(s) => {
                                cache.insert(server_addr, (s, Instant::now()));
                            }
                            Err(e) => {
                                warn!(
                                    err = %e,
                                    client = %client_addr,
                                    server = %server_addr,
                                    "tproxy udp writeback: create socket failed"
                                );
                                continue;
                            }
                        }
                    }
                    let Some((sock, last_used)) = cache.get_mut(&server_addr) else {
                        continue;
                    };
                    *last_used = Instant::now();
                    // writeback socket 按 server_addr 的协议族创建。双栈 tproxy 监听
                    // socket 的 recvmsg 对 IPv4 流量返回的是 IPv4-mapped IPv6 地址
                    //（::ffff:a.b.c.d）。用 IPv4-only socket 对该 V6 地址 send_to 会被
                    // 内核以 EAFNOSUPPORT 拒绝，导致回包发不出去；这里规整成匹配的协议族。
                    let send_addr = normalize_addr_family(client_addr, server_addr.is_ipv6());
                    // writeback socket 是 nonblocking：send buffer 满时返回 WouldBlock。
                    // UDP 允许丢包，这里丢弃并记录 debug，不阻塞 writeback 任务。
                    if let Err(e) = sock.send_to(data.as_ref(), &send_addr.into()) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!(
                                client = %client_addr,
                                server = %server_addr,
                                "tproxy udp writeback: send buffer full, dropping packet"
                            );
                        } else {
                            warn!(
                                err = %e,
                                client = %client_addr,
                                server = %server_addr,
                                "tproxy udp writeback error"
                            );
                        }
                    }
                }
            }
        }
    });

    let mut sessions: HashMap<(SocketAddr, SocketAddr), UdpSessionEntry> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    let fd = async_fd.get_ref().as_raw_fd();

    // GC 定时器：每 30 秒清理过期会话，不依赖包计数
    // 参照 sing-box canceler 的 context + timer 设计，以时间为基准而非流量
    let mut gc_ticker = tokio::time::interval(Duration::from_secs(30));
    gc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased; // 优先处理数据包，GC 是低优先级

            readable = async_fd.readable() => {
                let mut guard = readable?;

                // edge-trigger 模式：必须循环读到 EAGAIN，否则缓冲区里剩余的包
                // 不会再触发 epoll 事件，导致这些包被永久丢弃。
                loop {
                    let (n, src, dst) = match recvmsg_with_dst(fd, &mut buf) {
                        Ok(v) => v,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // 缓冲区已清空，清除 ready 标记，等待下次 epoll 事件
                            guard.clear_ready();
                            break;
                        }
                        Err(e) => {
                            // 单个包解析失败（通常是非 TPROXY 重定向的杂散包，
                            // 例如直接发到本端口的探测/扫描包，内核不会附带
                            // IP_ORIGDSTADDR cmsg）。这类包丢弃即可，不应中断
                            // 本次 edge-trigger 唤醒里后续正常包的处理，
                            // 否则会导致同批次到达的其它合法包被延迟到下次
                            // epoll 事件才能读取。
                            debug!(err=%e, "tproxy udp recvmsg: dropping malformed/non-tproxy packet");
                            continue;
                        }
                    };

                    let data = Bytes::copy_from_slice(&buf[..n]);
                    let timeout = tproxy_udp_timeout_for_port(dst.port());

                    let key = (src, dst);
                    let entry = sessions.entry(key).or_insert_with(|| {
                        debug!(src=%src, dst=%dst, "tproxy udp new session");
                        UdpSessionEntry {
                            reply_tx: global_reply_tx.clone(),
                            last_seen: Instant::now(),
                            timeout,
                        }
                    });
                    entry.last_seen = Instant::now();

                    let session = UdpSession {
                        reply_tx: entry.reply_tx.clone(),
                    };
                    let packet = InboundUdpPacket {
                        data,
                        src,
                        target: Target::Socket(dst),
                        inbound_tag: tag.clone(),
                        session,
                        sniffed_protocol: None,
                        sniffed_domain: None,
                        origin_destination: None,
                        upstream_rx: None,
                        lifetime_guards: vec![],
                    };

                    if tx.send(packet).await.is_err() {
                        return Ok(());
                    }
                }
            }

            _ = gc_ticker.tick() => {
                // 按每个会话自身的超时清理，而不是全局固定 60 s
                sessions.retain(|_, v| v.last_seen.elapsed() < v.timeout);
                debug!(sessions=%sessions.len(), "tproxy udp gc done");
            }
        }
    }
}

// ── recvmsg（同步，在 readable 回调里调用）────────────────────────────────────

fn recvmsg_with_dst(
    fd: RawFd,
    buf: &mut [u8],
) -> Result<(usize, SocketAddr, SocketAddr), std::io::Error> {
    const CMSG_SPACE: usize = 128;
    let mut cmsg_buf = [0u8; CMSG_SPACE];
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = CMSG_SPACE as _;

    let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let src = sockaddr_storage_to_socketaddr(&src_storage).map_err(std::io::Error::other)?;
    let dst = extract_original_dst_from_cmsg(&msg).map_err(std::io::Error::other)?;
    Ok((n as usize, src, dst))
}

fn sockaddr_storage_to_socketaddr(ss: &libc::sockaddr_storage) -> anyhow::Result<SocketAddr> {
    unsafe {
        match ss.ss_family as libc::c_int {
            libc::AF_INET => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in);
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port),
                )))
            }
            libc::AF_INET6 => {
                let sa = &*(ss as *const _ as *const libc::sockaddr_in6);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sa.sin6_addr.s6_addr),
                    u16::from_be(sa.sin6_port),
                    0,
                    0,
                )))
            }
            other => anyhow::bail!("unknown address family: {other}"),
        }
    }
}

// ── tproxy writeback socket ───────────────────────────────────────────────────
//
// sing-box 的做法：新建一个 IP_TRANSPARENT socket，bind 到游戏服务器的 IP:port，
// 然后直接 send_to 客户端。客户端看到的源地址天然就是游戏服务器地址。
// 参考：sing-box tproxyPacketWriter.WritePacket

/// writeback socket 缓存上限（参照 sing-box 有界缓存）
const WRITEBACK_CACHE_CAP: usize = 1024;
/// writeback socket 空闲超时：超过该时长未发送的 socket 会被关闭回收，
/// 与 UDP 会话默认空闲超时（5 分钟）对齐。
const WRITEBACK_SOCKET_IDLE: Duration = Duration::from_secs(300);

/// 创建 tproxy UDP 回包用的 IP_TRANSPARENT socket，bind 到 `server_addr`
///（伪造源地址 = 原始目标 / 游戏服务器 IP:port），并设置 SO_MARK 绕过 TProxy 规则。
///
/// 由 writeback 任务按 `server_addr` 缓存复用，避免每包都走
/// socket/reuse/transparent/mark/bind 一整套 syscall。
///
/// 对齐 sing-box `redir.TProxyWriteBack`（common/redir/tproxy_linux.go）：
/// - IPv4 目的：`IP_TRANSPARENT`(SOL_IP)
/// - IPv6 目的：`IPV6_TRANSPARENT`(SOL_IPV6)
///   虽然 Linux 内核里 `IP_TRANSPARENT` 对 IPv6 socket 也设置 `inet->transparent`，
///   但 sing-box 按地址族分别设置更明确，这里对齐其做法。
fn create_tproxy_writeback_socket(
    server_addr: SocketAddr, // bind 到哪（游戏服务器IP:port，作为伪造源地址）
    routing_mark: u32,       // SO_MARK，让新 socket 绕过 nftables TProxy 规则
) -> std::io::Result<Socket> {
    let is_v6 = server_addr.is_ipv6();
    let sock = Socket::new(
        if is_v6 { Domain::IPV6 } else { Domain::IPV4 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    if is_v6 {
        // IPv6 socket：设置 IPV6_TRANSPARENT（对齐 sing-box TProxyWriteBack）。
        // socket2 0.5 没有 set_ipv6_transparent，手动 setsockopt。
        unsafe {
            let one: libc::c_int = 1;
            let ret = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if ret != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
    } else {
        sock.set_ip_transparent(true)?;
    }
    // nonblocking：send_to 在 send buffer 满时返回 EAGAIN，由调用方丢弃包。
    // 阻塞模式会在高流量时卡住整个 writeback 任务（它跑在 tokio async block 里
    // 做同步 send_to），导致后续回包全部延迟。UDP 本身允许丢包，EAGAIN 时丢弃
    // 比阻塞更合理。sing-box 不显式设置（Go stdlib 接管），reflex 用同步 send_to
    // 必须自己确保 nonblocking。
    sock.set_nonblocking(true)?;
    // 设置 SO_MARK，让这个 socket 发出的包匹配 nftables proxy_out 里的 GID/mark 豁免规则
    // 否则新建的 socket 没有 mark，发出的包会被 TProxy 规则再次拦截，回包变成死循环
    if routing_mark != 0 {
        unsafe {
            let fd = sock.as_raw_fd();
            let mark = routing_mark;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
        }
    }
    sock.bind(&server_addr.into())?;
    Ok(sock)
}

/// 将 `addr` 规整为与 `want_ipv6` 一致的协议族表示。
///
/// - `want_ipv6 == false` 且 `addr` 是 IPv4-mapped IPv6（`::ffff:a.b.c.d`）
///   → 转换为对应的纯 IPv4 `SocketAddr`。
/// - `want_ipv6 == true` 且 `addr` 是纯 IPv4 → 转换为 IPv4-mapped IPv6。
/// - 其余情况（协议族已经匹配，或无法转换的真正异构地址）原样返回。
fn normalize_addr_family(addr: SocketAddr, want_ipv6: bool) -> SocketAddr {
    match (addr, want_ipv6) {
        (SocketAddr::V6(v6), false) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                SocketAddr::V4(SocketAddrV4::new(v4, v6.port()))
            } else {
                addr
            }
        }
        (SocketAddr::V4(v4), true) => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        _ => addr,
    }
}

fn extract_original_dst_from_cmsg(msg: &libc::msghdr) -> anyhow::Result<SocketAddr> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg as *const _);
        while !cmsg.is_null() {
            let c = &*cmsg;
            if c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == libc::IP_ORIGDSTADDR {
                let sa = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in);
                return Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
                    u16::from_be(sa.sin_port),
                )));
            }
            // IPV6_ORIGDSTADDR = 74
            if c.cmsg_level == libc::IPPROTO_IPV6 && c.cmsg_type == 74 {
                let sa = &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6);
                return Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sa.sin6_addr.s6_addr),
                    u16::from_be(sa.sin6_port),
                    0,
                    0,
                )));
            }
            cmsg = libc::CMSG_NXTHDR(msg as *const _, cmsg);
        }
    }
    anyhow::bail!("no original dst in cmsg")
}
