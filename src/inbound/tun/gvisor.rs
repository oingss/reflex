use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use super::netstack::{NetStack, Packet};
use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, warn};

use super::{ip_in_local_subnets_v4, ip_in_local_subnets_v6};
use crate::inbound::{
    dns::{DnsQuery, DnsQuerySource, DnsQueryTx},
    InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession,
};

/// gvisor 栈的 UDP 会话超时（秒）。与 system 栈的 DEFAULT_UDP_TIMEOUT_SECS 对齐。
const NETSTACK_UDP_TIMEOUT: Duration = Duration::from_secs(300);

/// 运行 gvisor 栈的 TUN inbound。
///
/// 调用者负责在调用前完成 TUN 设备创建 + auto_route 配置，传入已 split 的
/// `(reader, writer)`。本函数启动四个并行 task：
/// 1. tun_reader：从 TUN 读 IP 包 → stack_sink
/// 2. stack_writer：从 stack_stream 读出站包 → 写回 TUN
/// 3. tcp_dispatch：accept TCP 流 → 发给 tcp_tx
/// 4. udp_dispatch：收 UDP 包 → 发给 udp_tx
#[allow(clippy::too_many_arguments)]
pub async fn run_gvisor(
    dev: tokio::io::ReadHalf<impl tokio::io::AsyncRead + Unpin + Send + 'static>,
    tun_writer: Arc<Mutex<impl tokio::io::AsyncWrite + Unpin + Send + 'static>>,
    mtu: usize,
    tag: Arc<String>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    local_subnets_v4: Vec<(Ipv4Addr, u8)>,
    local_subnets_v6: Vec<(Ipv6Addr, u8)>,
    dns_tx: Option<DnsQueryTx>,
    dns_hijack: bool,
) -> anyhow::Result<()> {
    // 创建用户态协议栈：TCP + UDP 都走 smoltcp
    let (stack, mut tcp_listener, udp_socket) = NetStack::new(mtu);
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    info!(
        tag = %tag, mtu,
        v4_subnets = local_subnets_v4.len(),
        v6_subnets = local_subnets_v6.len(),
        "tun(gvisor): netstack started"
    );

    // ── Task 1: TUN → stack_sink（注入入站 IP 包）──────────────────────
    // 在注入 smoltcp 前过滤本地子网流量，避免 LAN/Docker 流量进入代理路径形成死循环。
    let tun_reader_tag = tag.clone();
    let tun_reader = tokio::spawn(async move {
        let mut dev = dev;
        let mut buf = vec![0u8; mtu + 64];
        loop {
            match dev.read(&mut buf).await {
                Ok(0) => {
                    info!(tag = %tun_reader_tag, "tun(gvisor): device closed (read 0)");
                    break;
                }
                Ok(n) => {
                    let raw = &buf[..n];
                    // 本地子网过滤：若 src 或 dst 落在本地网卡子网内，跳过。
                    if (!local_subnets_v4.is_empty() || !local_subnets_v6.is_empty())
                        && is_local_subnet_packet(raw, &local_subnets_v4, &local_subnets_v6)
                    {
                        continue;
                    }
                    let pkt = Packet::new(Bytes::copy_from_slice(raw));
                    use futures_util::SinkExt;
                    if let Err(e) = stack_sink.send(pkt).await {
                        error!(err = %e, "tun(gvisor): stack_sink send failed");
                        break;
                    }
                }
                Err(e) => {
                    error!(err = %e, "tun(gvisor): tun read error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    });

    // ── Task 2: stack_stream → TUN（写出站 IP 包）──────────────────────
    // clone tun_writer 供 UDP 回包直接写 TUN（绕过 smoltcp，因为 smoltcp 的
    // udp_socket.send 要求源地址是协议栈已绑定的地址，而回包源是远端服务器地址，
    // smoltcp 无法构造。直接构造原始 IP 包写回 TUN 与 system 栈行为一致）。
    let udp_reply_writer = tun_writer.clone();
    let stack_writer = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(pkt_result) = stack_stream.next().await {
            match pkt_result {
                Ok(pkt) => {
                    let data = pkt.into_bytes();
                    let mut w = tun_writer.lock().await;
                    if let Err(e) = w.write_all(&data).await {
                        error!(err = %e, "tun(gvisor): tun write failed");
                        break;
                    }
                    // 立即 flush，避免 smoltcp 出站 ACK 被延迟。
                    let _ = w.flush().await;
                }
                Err(e) => {
                    error!(err = %e, "tun(gvisor): stack_stream error");
                    break;
                }
            }
        }
    });

    // ── Task 3: TCP dispatch（accept → bridge → SniffedStream → tcp_tx）─
    let tcp_tag = tag.clone();
    let tcp_dispatch = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(stream) = tcp_listener.next().await {
            let remote = stream.remote_addr();
            debug!(remote = %remote, "tun(gvisor): new TCP stream");

            match bridge_to_tcpstream(stream).await {
                Ok(tcp_stream) => {
                    let inbound = InboundTcpStream {
                        stream: SniffedStream::new(tcp_stream),
                        target: Target::Socket(remote),
                        inbound_tag: (*tcp_tag).clone(),
                        sniffed_protocol: None,
                        sniffed_domain: None,
                    };
                    if tcp_tx.send(inbound).await.is_err() {
                        debug!("tun(gvisor): tcp_tx closed");
                        break;
                    }
                }
                Err(e) => {
                    debug!(err = %e, remote = %remote, "tun(gvisor): bridge failed, dropping");
                }
            }
        }
    });

    // ── Task 4: UDP dispatch（recv → InboundUdpPacket → udp_tx）────────
    let udp_tag = tag.clone();
    let udp_dispatch = tokio::spawn(async move {
        let udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpReplyEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // GC task：定期清理超时 UDP 会话
        {
            let sessions = udp_sessions.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(NETSTACK_UDP_TIMEOUT / 2);
                loop {
                    ticker.tick().await;
                    sessions
                        .lock()
                        .await
                        .retain(|_, v| v.last_seen.elapsed() < NETSTACK_UDP_TIMEOUT);
                }
            });
        }

        while let Some(pkt) = udp_read.recv().await {
            let src = pkt.local_addr;
            let dst = pkt.remote_addr;
            let data = Bytes::copy_from_slice(pkt.data());

            // TUN 层 DNS 劫持：参考 clash-rs datagram.rs:97-168，
            // 在端口 53 且 hijack_dns 启用时直接通过 DNS 解析器响应。
            if dns_hijack && dst.port() == 53 {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let query = DnsQuery {
                    message: data,
                    from: src,
                    inbound_tag: (*udp_tag).clone(),
                    source: DnsQuerySource::Hijacked,
                    reply_tx,
                };
                if let Some(ref tx) = dns_tx {
                    if tx.send(query).await.is_err() {
                        debug!("tun(gvisor): dns_tx closed, skip DNS hijack");
                        continue;
                    }
                    match reply_rx.await {
                        Ok(response) => {
                            if let Some(pkt) = super::build_udp_reply_packet(dst, src, &response) {
                                let is_v6 = matches!(dst, SocketAddr::V6(_));
                                super::tun_write(&udp_reply_writer, &pkt, is_v6).await;
                            }
                        }
                        Err(_) => {
                            debug!("tun(gvisor): DNS reply rx dropped");
                        }
                    }
                }
                continue;
            }

            let key = (src, dst);
            let mut sessions = udp_sessions.lock().await;
            let entry = sessions.entry(key).or_insert_with(|| {
                debug!(src = %src, dst = %dst, "tun(gvisor): new UDP session");
                let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
                let writer = udp_reply_writer.clone();
                // 回包 task：直接构造原始 IP 包写回 TUN（绕过 smoltcp）。
                // smoltcp 的 udp_socket.send 要求源地址是栈已绑定的地址，
                // 而回包源是远端服务器地址，smoltcp 无法构造。
                // 直接构造 IP 包与 system 栈 build_udp_reply_packet 行为一致。
                tokio::spawn(async move {
                    while let Some((payload, _client_src, server_src)) = reply_rx.recv().await {
                        // 回包：IP src = 服务器(server_src)，IP dst = 客户端(src)。
                        if let Some(pkt) = super::build_udp_reply_packet(server_src, src, &payload)
                        {
                            let is_v6 = matches!(server_src, SocketAddr::V6(_));
                            super::tun_write(&writer, &pkt, is_v6).await;
                        }
                    }
                });
                UdpReplyEntry {
                    reply_tx,
                    last_seen: Instant::now(),
                }
            });
            entry.last_seen = Instant::now();
            let session = UdpSession {
                reply_tx: entry.reply_tx.clone(),
            };
            drop(sessions);

            let packet = InboundUdpPacket {
                data,
                src,
                target: Target::Socket(dst),
                inbound_tag: (*udp_tag).clone(),
                session,
                sniffed_protocol: None,
                sniffed_domain: None,
                origin_destination: None,
                upstream_rx: None,
                lifetime_guards: vec![],
            };
            if udp_tx.send(packet).await.is_err() {
                debug!("tun(gvisor): udp_tx closed");
                break;
            }
        }
        info!(tag = %udp_tag, "tun(gvisor): udp socket closed");
    });

    // 等待任一 task 结束（TUN 设备关闭通常最先发生）
    tokio::select! {
        _ = tun_reader => debug!("tun(gvisor): tun_reader task exited"),
        _ = stack_writer => debug!("tun(gvisor): stack_writer task exited"),
        _ = tcp_dispatch => debug!("tun(gvisor): tcp_dispatch task exited"),
        _ = udp_dispatch => debug!("tun(gvisor): udp_dispatch task exited"),
    }

    Ok(())
}

/// UDP 回包条目，与会话表配合。
struct UdpReplyEntry {
    reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
    last_seen: Instant,
}

/// 判断一个原始 IP 包的 src 或 dst 是否落在本地子网内。
///
/// 用于 gvisor/mixed 栈的 TUN 读循环，在注入 smoltcp 前过滤 LAN/Docker 流量，
/// 避免 auto_route 劫持本地流量后形成死循环。与 system 栈 process_ipv4/v6 中
/// 的过滤逻辑等价。
fn is_local_subnet_packet(
    raw: &[u8],
    local_subnets_v4: &[(Ipv4Addr, u8)],
    local_subnets_v6: &[(Ipv6Addr, u8)],
) -> bool {
    if raw.is_empty() {
        return false;
    }
    match raw[0] >> 4 {
        4 => {
            if raw.len() < 20 {
                return false;
            }
            let src = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
            let dst = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
            ip_in_local_subnets_v4(src, local_subnets_v4)
                || ip_in_local_subnets_v4(dst, local_subnets_v4)
        }
        6 => {
            if raw.len() < 40 {
                return false;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap_or([0u8; 16]));
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));
            ip_in_local_subnets_v6(src, local_subnets_v6)
                || ip_in_local_subnets_v6(dst, local_subnets_v6)
        }
        _ => false,
    }
}

/// 把 netstack 的 `TcpStream` 桥接为真实的 `tokio::net::TcpStream`。
///
/// 实现方式：绑定 `127.0.0.1:0` 建一条本地 OS socket，spawn 一个双向 copy task
/// 在 netstack 流和 OS socket 之间搬运字节，返回 accept 到的 `TcpStream`。
///
/// 代价：每条 TCP 连接多一对 OS socket + 一个 copy task。
/// 好处：避免对 `SniffedStream`/`Outbound` trait/15+ outbound 实现做泛型化重构。
async fn bridge_to_tcpstream(
    netstack_stream: super::netstack::TcpStream,
) -> std::io::Result<tokio::net::TcpStream> {
    // 绑定本地 listener，仅接受一条连接
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr = listener.local_addr()?;

    // 发起本地 connect（用本地 OS socket 作为 SniffedStream 的载体）
    let os_stream = tokio::net::TcpStream::connect(local_addr).await?;
    // 设置 NODELAY，避免桥接层引入 Nagle 延迟
    let _ = os_stream.set_nodelay(true);

    let (accepted, _) = listener.accept().await?;
    // listener 已完成使命，drop 释放端口

    // 双向 copy：netstack ↔ accepted
    tokio::spawn(async move {
        let (mut ns_read, mut ns_write) = tokio::io::split(netstack_stream);
        let (mut acc_read, mut acc_write) = tokio::io::split(accepted);

        let c2s = async { tokio::io::copy(&mut acc_read, &mut ns_write).await };
        let s2c = async { tokio::io::copy(&mut ns_read, &mut acc_write).await };
        // 任一方向结束即关闭整条连接
        let _ = tokio::join!(c2s, s2c);
    });

    Ok(os_stream)
}

/// 运行 mixed 栈的 TUN inbound：TCP 走 system NAT，UDP 走 gvisor。
///
/// mixed 栈的设计参照 sing-tun `stack_mixed.go`：
/// - **TCP**：复用 reflex 现有的 system 栈逻辑（TCP NAT 表 + 在 TUN 地址上 bind
///   TcpListener + accept_loop）。TCP 包不进入 smoltcp，直接由内核协议栈处理，
///   享受内核 TCP 状态机的成熟与性能。
/// - **UDP**：走 gvisor（smoltcp 用户态协议栈）。UDP 无连接，gvisor 处理可避免
///   为每个 UDP 流在内核建 socket。
///
/// 实现上 TUN 读循环按 IP 协议号分流：
/// - TCP 包（IPPROTO_TCP=6）→ 调用 system 栈的 `handle_tcp_v4/v6` 做 NAT 改写
/// - UDP 包（IPPROTO_UDP=17）→ 注入 `stack_sink`（smoltcp 处理）
/// - ICMP 包 → 走 system 栈的 ICMP 响应
///
/// 出站包合流：system 栈的 TCP 回包直接写 TUN，gvisor 的 UDP 回包也写 TUN。
/// 两者共享同一个 `tun_writer`。
#[allow(clippy::too_many_arguments)]
pub async fn run_mixed(
    dev: tokio::io::ReadHalf<impl tokio::io::AsyncRead + Unpin + Send + 'static>,
    tun_writer: Arc<Mutex<impl tokio::io::AsyncWrite + Unpin + Send + 'static>>,
    mtu: usize,
    tag: Arc<String>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    // system 栈 TCP NAT 所需的地址（与 system 栈 run() 一致）
    inet4_server_addr: Option<std::net::Ipv4Addr>,
    inet4_client_addr: Option<std::net::Ipv4Addr>,
    inet6_server_addr: Option<std::net::Ipv6Addr>,
    inet6_client_addr: Option<std::net::Ipv6Addr>,
    inet4_prefixes: Vec<(std::net::Ipv4Addr, u8)>,
    inet6_prefixes: Vec<(std::net::Ipv6Addr, u8)>,
    inet4_loopback: std::net::Ipv4Addr,
    inet6_loopback: std::net::Ipv6Addr,
    tcp_mss: Option<u16>,
    local_subnets_v4: Vec<(Ipv4Addr, u8)>,
    local_subnets_v6: Vec<(Ipv6Addr, u8)>,
    dns_tx: Option<DnsQueryTx>,
    dns_hijack: bool,
) -> anyhow::Result<()> {
    use super::{
        handle_icmpv4, handle_icmpv6, handle_tcp_v4, handle_tcp_v6, TcpNat,
        DEFAULT_UDP_TIMEOUT_SECS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP,
        IPV4_VERSION, IPV6_VERSION,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ── system 栈的 TCP NAT 表 ──────────────────────────────────────────
    let tcp_nat: Arc<TcpNat> = Arc::new(TcpNat::new());

    // ── 在 TUN 地址上 bind TCP Listener（system 栈 TCP 路径）────────────
    let mut accept_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    // IPv4 listener（带重试，对齐 system 栈：Windows 上 netsh 设地址后
    // 需要短暂时间才真正生效）
    let tcp_port_v4: u16 = if let Some(addr) = inet4_server_addr {
        let listen_addr = SocketAddr::new(IpAddr::V4(addr), 0);
        let mut bound: Option<TcpListener> = None;
        for attempt in 0..3u32 {
            match TcpListener::bind(listen_addr).await {
                Ok(l) => {
                    info!(tag = %tag, addr = %l.local_addr().unwrap(), "tun(mixed): TCP v4 listener ready");
                    bound = Some(l);
                    break;
                }
                Err(e) if attempt < 2 => {
                    warn!(err = %e, attempt, "tun(mixed): TCP v4 bind failed, retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    anyhow::bail!("tun(mixed): failed to bind TCP listener on {listen_addr}: {e}");
                }
            }
        }
        if let Some(listener) = bound {
            let port = listener.local_addr()?.port();
            let listener = Arc::new(listener);
            let tcp_nat_clone = tcp_nat.clone();
            let tcp_tx_clone = tcp_tx.clone();
            let tag_clone = tag.clone();
            let prefixes: Arc<Vec<(IpAddr, u8)>> = Arc::new(
                inet4_prefixes
                    .iter()
                    .map(|(ip, pl)| (IpAddr::V4(*ip), *pl))
                    .collect(),
            );
            accept_tasks.push(tokio::spawn(async move {
                super::accept_loop(
                    listener,
                    tcp_nat_clone,
                    tcp_tx_clone,
                    tag_clone,
                    prefixes,
                    false,
                    (inet4_loopback, inet6_loopback),
                )
                .await;
            }));
            port
        } else {
            0
        }
    } else {
        0
    };

    // IPv6 listener（带重试；Windows IPv6 DAD 会导致地址刚配置时 bind 失败）
    let tcp_port_v6: u16 = if let Some(addr) = inet6_server_addr {
        let listen_addr = SocketAddr::new(IpAddr::V6(addr), 0);
        let mut bound: Option<TcpListener> = None;
        for attempt in 0..3u32 {
            match TcpListener::bind(listen_addr).await {
                Ok(l) => {
                    info!(tag = %tag, addr = %l.local_addr().unwrap(), "tun(mixed): TCP v6 listener ready");
                    bound = Some(l);
                    break;
                }
                Err(e) if attempt < 2 => {
                    warn!(err = %e, attempt, "tun(mixed): TCP v6 bind failed, retrying");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => {
                    warn!(err = %e, "tun(mixed): failed to bind TCP v6 listener, v6 TCP disabled");
                }
            }
        }
        if let Some(listener) = bound {
            let port = listener.local_addr()?.port();
            let listener = Arc::new(listener);
            let tcp_nat_clone = tcp_nat.clone();
            let tcp_tx_clone = tcp_tx.clone();
            let tag_clone = tag.clone();
            let prefixes: Arc<Vec<(IpAddr, u8)>> = Arc::new(
                inet6_prefixes
                    .iter()
                    .map(|(ip, pl)| (IpAddr::V6(*ip), *pl))
                    .collect(),
            );
            accept_tasks.push(tokio::spawn(async move {
                super::accept_loop(
                    listener,
                    tcp_nat_clone,
                    tcp_tx_clone,
                    tag_clone,
                    prefixes,
                    true,
                    (inet4_loopback, inet6_loopback),
                )
                .await;
            }));
            port
        } else {
            0
        }
    } else {
        0
    };

    // ── gvisor 协议栈（仅 UDP）──────────────────────────────────────────
    let (stack, _tcp_listener, udp_socket) = NetStack::new(mtu);
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();
    // _tcp_listener drop 会终止 smoltcp poll task。为了 UDP 能工作，
    // 必须保持它存活：把它 move 进一个长期 task。
    let _tcp_listener_handle = _tcp_listener;

    info!(
        tag = %tag,
        mtu,
        tcp_port_v4,
        tcp_port_v6,
        "tun(mixed): system TCP + gvisor UDP started"
    );

    // ── UDP 会话表（gvisor UDP 路径，与 run_gvisor 一致）─────────────────
    let udp_sessions: Arc<Mutex<HashMap<(SocketAddr, SocketAddr), UdpReplyEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));
    {
        let sessions = udp_sessions.clone();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(DEFAULT_UDP_TIMEOUT_SECS) / 2);
            loop {
                ticker.tick().await;
                sessions.lock().await.retain(|_, v| {
                    v.last_seen.elapsed() < Duration::from_secs(DEFAULT_UDP_TIMEOUT_SECS)
                });
            }
        });
    }

    // ── UDP dispatch task（gvisor UDP）──────────────────────────────────
    let udp_tag = tag.clone();
    let udp_reply_writer = tun_writer.clone();
    let udp_dispatch = tokio::spawn(async move {
        while let Some(pkt) = udp_read.recv().await {
            let src = pkt.local_addr;
            let dst = pkt.remote_addr;
            let data = Bytes::copy_from_slice(pkt.data());

            // TUN 层 DNS 劫持：参考 clash-rs datagram.rs:97-168，
            // 在端口 53 且 hijack_dns 启用时直接通过 DNS 解析器响应。
            if dns_hijack && dst.port() == 53 {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let query = DnsQuery {
                    message: data,
                    from: src,
                    inbound_tag: (*udp_tag).clone(),
                    source: DnsQuerySource::Hijacked,
                    reply_tx,
                };
                if let Some(ref tx) = dns_tx {
                    if tx.send(query).await.is_err() {
                        debug!("tun(mixed/gvisor): dns_tx closed, skip DNS hijack");
                        continue;
                    }
                    match reply_rx.await {
                        Ok(response) => {
                            if let Some(pkt) = super::build_udp_reply_packet(dst, src, &response) {
                                let is_v6 = matches!(dst, SocketAddr::V6(_));
                                super::tun_write(&udp_reply_writer, &pkt, is_v6).await;
                            }
                        }
                        Err(_) => {
                            debug!("tun(mixed/gvisor): DNS reply rx dropped");
                        }
                    }
                }
                continue;
            }

            let key = (src, dst);
            let mut sessions = udp_sessions.lock().await;
            let entry = sessions.entry(key).or_insert_with(|| {
                debug!(src = %src, dst = %dst, "tun(mixed/gvisor): new UDP session");
                let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
                let writer = udp_reply_writer.clone();
                // 回包：直接构造原始 IP 包写回 TUN（绕过 smoltcp，与 run_gvisor 一致）。
                tokio::spawn(async move {
                    while let Some((payload, _client_src, server_src)) = reply_rx.recv().await {
                        if let Some(pkt) = super::build_udp_reply_packet(server_src, src, &payload)
                        {
                            let is_v6 = matches!(server_src, SocketAddr::V6(_));
                            super::tun_write(&writer, &pkt, is_v6).await;
                        }
                    }
                });
                UdpReplyEntry {
                    reply_tx,
                    last_seen: Instant::now(),
                }
            });
            entry.last_seen = Instant::now();
            let session = UdpSession {
                reply_tx: entry.reply_tx.clone(),
            };
            drop(sessions);
            let packet = InboundUdpPacket {
                data,
                src,
                target: Target::Socket(dst),
                inbound_tag: (*udp_tag).clone(),
                session,
                sniffed_protocol: None,
                sniffed_domain: None,
                origin_destination: None,
                upstream_rx: None,
                lifetime_guards: vec![],
            };
            if udp_tx.send(packet).await.is_err() {
                debug!("tun(mixed/gvisor): udp_tx closed");
                break;
            }
        }
    });

    // ── stack_stream → TUN（gvisor UDP 出站包）──────────────────────────
    // 注意：此处必须用 clone，主 TUN 读循环仍需 tun_writer 写 TCP/ICMP 回包。
    let tun_writer_for_stack = tun_writer.clone();
    let stack_writer = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(pkt_result) = stack_stream.next().await {
            if let Ok(pkt) = pkt_result {
                let data = pkt.into_bytes();
                let mut w = tun_writer_for_stack.lock().await;
                if let Err(e) = w.write_all(&data).await {
                    error!(err = %e, "tun(mixed/gvisor): tun write failed");
                    break;
                }
                let _ = w.flush().await;
            }
        }
    });

    // ── TUN 读循环：按协议分流 TCP→system NAT，UDP→gvisor sink ──────────
    let mut reader = dev;
    let mut buf = vec![0u8; mtu + 64];
    loop {
        // 主循环只读 TUN；下游 task 退出由 TUN 关闭级联触发，无需在此 select!。
        let n = match reader.read(&mut buf).await {
            Ok(0) => {
                info!(tag = %tag, "tun(mixed): device closed");
                break;
            }
            Ok(n) => n,
            Err(e) => {
                error!(err = %e, "tun(mixed): tun read error");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        let pkt_slice = &buf[..n];
        if pkt_slice.is_empty() {
            continue;
        }
        // ── 本地子网流量过滤（与 system/gvisor 栈一致）─────────────────
        // 若 src 或 dst 落在本地网卡子网内，跳过，避免 LAN/Docker 流量死循环。
        if (!local_subnets_v4.is_empty() || !local_subnets_v6.is_empty())
            && is_local_subnet_packet(pkt_slice, &local_subnets_v4, &local_subnets_v6)
        {
            continue;
        }
        let version = pkt_slice[0] >> 4;
        match version {
            IPV4_VERSION => {
                let ihl = ((pkt_slice[0] & 0x0f) as usize) * 4;
                if pkt_slice.len() < ihl || ihl < 20 {
                    continue;
                }
                let src_ip =
                    Ipv4Addr::from([pkt_slice[12], pkt_slice[13], pkt_slice[14], pkt_slice[15]]);
                let dst_ip =
                    Ipv4Addr::from([pkt_slice[16], pkt_slice[17], pkt_slice[18], pkt_slice[19]]);
                let payload = &pkt_slice[ihl..];
                match pkt_slice[9] {
                    IPPROTO_TCP => {
                        // TCP → system NAT（回包直接写 TUN）
                        handle_tcp_v4(
                            pkt_slice,
                            payload,
                            src_ip,
                            dst_ip,
                            inet4_server_addr,
                            inet4_client_addr,
                            inet4_loopback,
                            tcp_port_v4,
                            tcp_mss,
                            tun_writer.clone(),
                            tcp_nat.clone(),
                        )
                        .await;
                    }
                    IPPROTO_UDP => {
                        // UDP → gvisor
                        let pkt = Packet::new(Bytes::copy_from_slice(pkt_slice));
                        use futures_util::SinkExt;
                        if let Err(e) = stack_sink.send(pkt).await {
                            error!(err = %e, "tun(mixed/gvisor): stack_sink send failed");
                            break;
                        }
                    }
                    IPPROTO_ICMP => {
                        handle_icmpv4(
                            pkt_slice,
                            ihl,
                            src_ip,
                            dst_ip,
                            inet4_server_addr,
                            tun_writer.clone(),
                        )
                        .await;
                    }
                    _ => {}
                }
            }
            IPV6_VERSION => {
                // IPv6 TCP → system NAT，UDP → gvisor，ICMPv6 → system
                if pkt_slice.len() < 40 {
                    continue;
                }
                let mut src_octets = [0u8; 16];
                let mut dst_octets = [0u8; 16];
                src_octets.copy_from_slice(&pkt_slice[8..24]);
                dst_octets.copy_from_slice(&pkt_slice[24..40]);
                let src_ip = Ipv6Addr::from(src_octets);
                let dst_ip = Ipv6Addr::from(dst_octets);
                let payload = &pkt_slice[40..];
                match pkt_slice[6] {
                    IPPROTO_TCP => {
                        handle_tcp_v6(
                            pkt_slice,
                            payload,
                            src_ip,
                            dst_ip,
                            inet6_server_addr,
                            inet6_client_addr,
                            inet6_loopback,
                            tcp_port_v6,
                            tcp_mss,
                            tun_writer.clone(),
                            tcp_nat.clone(),
                        )
                        .await;
                    }
                    IPPROTO_UDP => {
                        let pkt = Packet::new(Bytes::copy_from_slice(pkt_slice));
                        use futures_util::SinkExt;
                        if let Err(e) = stack_sink.send(pkt).await {
                            error!(err = %e, "tun(mixed/gvisor): stack_sink send failed");
                            break;
                        }
                    }
                    IPPROTO_ICMPV6 => {
                        handle_icmpv6(
                            pkt_slice,
                            src_ip,
                            dst_ip,
                            inet6_server_addr,
                            tun_writer.clone(),
                        )
                        .await;
                    }
                    _ => {}
                }
            }
            _ => {
                debug!(version, "tun(mixed): unknown IP version, dropping");
            }
        }
    }

    // TUN 已关闭，等待下游 task 级联退出后返回
    let _ = stack_writer.await;
    let _ = udp_dispatch.await;
    for handle in accept_tasks {
        let _ = handle.await;
    }

    Ok(())
}
