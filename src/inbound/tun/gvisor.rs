use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use super::netstack::{NetStack, Packet};
use bytes::Bytes;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{mpsc, Mutex},
};
use tracing::{debug, error, info, warn};

use crate::inbound::{
    dns::{DnsQuery, DnsQuerySource, DnsQueryTx},
    InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession,
};
use crate::app::outbound_mgr::OutboundManager;
use crate::router::Router;

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
    dev: super::native_tun::NativeTunReader,
    tun_writer: Arc<Mutex<impl tokio::io::AsyncWrite + Unpin + Send + 'static>>,
    mtu: usize,
    tag: Arc<String>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    udp_timeout: Duration,
    dns_tx: Option<DnsQueryTx>,
    dns_hijack: bool,
    // 路由器/出站管理器：注入后启用 ICMP 路由策略（`network:"icmp"` 规则）。
    // None 时退化为始终转发的旧行为。（仅 unix 的 ICMP forwarder 使用）
    #[cfg_attr(not(unix), allow(unused_variables))]
    router: Option<Arc<Router>>,
    #[cfg_attr(not(unix), allow(unused_variables))]
    outbound_mgr: Option<Arc<OutboundManager>>,
) -> anyhow::Result<()> {
    // 创建用户态协议栈：TCP + UDP 都走 smoltcp
    let (stack, mut tcp_listener, udp_socket) = NetStack::new(mtu);
    let (mut stack_sink, mut stack_stream) = stack.split();
    let (mut udp_read, _udp_write) = udp_socket.split();

    info!(
        tag = %tag, mtu,
        udp_timeout = udp_timeout.as_secs(),
        "tun(gvisor): netstack started"
    );

    // ── ICMP 转发器（gvisor 栈 ICMP 不经 smoltcp，由独立 forwarder 转发）──
    // 对齐 sing-tun stack_gvisor.go ICMPForwarder：拦截 ICMP Echo Request，
    // 通过 raw/ping socket 转发到上游，回包注入 TUN。
    #[cfg(unix)]
    let icmp_forwarder = {
        use super::icmp_forwarder::IcmpForwarder;
        let fwd = IcmpForwarder::new(tun_writer.clone());
        // 注入路由器/出站管理器：启用 `network:"icmp"` 规则匹配
        // （reject/block/非直连出站丢弃等）。未注入时退化为始终转发。
        let fwd = if let (Some(router), Some(outbound_mgr)) =
            (router.as_ref(), outbound_mgr.as_ref())
        {
            fwd.with_router(router.clone(), outbound_mgr.clone(), tag.clone())
        } else {
            fwd
        };
        Some(fwd)
    };
    // F8：非 unix 平台（Windows）的 ICMP 回环 Echo Reply 专用 writer。
    // 必须在 tun_reader spawn 前克隆，避免 async move 把 tun_writer
    // 整体 move 进 Task 1，导致 Task 2/4 无法使用。
    #[cfg(not(unix))]
    let icmp_echo_writer = tun_writer.clone();

    // ── Task 1: TUN → stack_sink（注入入站 IP 包）──────────────────────
    // 注入前过滤广播/组播目的（F1）；ICMP Echo Request 交给 IcmpForwarder
    // 转发（unix）或回环应答（Windows，F8），不进入 smoltcp。
    let tun_reader_tag = tag.clone();
    let tun_reader = tokio::spawn(async move {
        let mut dev = dev;
        loop {
            // NativeTunReader：已剥除 virtio_net_hdr，返回纯 IP 包。
            let raw = match dev.read_packet().await {
                Ok(p) => p,
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    info!(tag = %tun_reader_tag, "tun(gvisor): device closed");
                    break;
                }
                Err(e) => {
                    error!(err = %e, "tun(gvisor): tun read error");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            if raw.is_empty() {
                continue;
            }
            // B6 修复：不再按本地子网丢弃（对齐 system 栈 B5 与 sing-tun 语义），
            // LAN 连通性由路由层保证。
            // ICMP 交给 forwarder（unix 平台），不进入 smoltcp
            #[cfg(unix)]
            {
                if let Some(ref fwdr) = icmp_forwarder {
                    if fwdr.handle_packet(&raw).await {
                        continue;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                // F8 修复（对齐 sing-tun gvisor 栈 ICMPForwarder）：非 unix 平台
                //（Windows）无 raw-socket 转发器，旧实现 ICMP 包直接进入 smoltcp
                // 后被静默丢弃（smoltcp 只响应自身地址的 Echo），导致 gvisor 栈
                // ping 完全无响应。退化为回环 Echo Reply（与 system 栈
                // handle_icmpv4/v6 语义一致）。
                if raw.len() >= 20 && raw[0] >> 4 == 4 && raw[9] == 1 {
                    let ihl = ((raw[0] & 0x0f) as usize) * 4;
                    if raw.len() >= ihl + 8 && ihl >= 20 {
                        let src = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
                        let dst = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
                        super::handle_icmpv4(&raw, ihl, src, dst, None, icmp_echo_writer.clone())
                            .await;
                        continue;
                    }
                }
                if raw.len() >= 48 && raw[0] >> 4 == 6 && raw[6] == 58 {
                    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap_or([0u8; 16]));
                    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));
                    super::handle_icmpv6(&raw, src, dst, None, icmp_echo_writer.clone()).await;
                    continue;
                }
            }
            // F1 修复（对齐 sing-tun LinkEndpointFilter，stack_gvisor_filter.go）与
            // system 栈 UDP 过滤：目的为广播/组播/链路本地的包（mDNS、SSDP、NetBIOS
            // 等）不进入用户态协议栈，避免被当作单播流量送入代理路径。loopback
            // 目的保留：gvisor 栈无 reflect 实现，进栈后由桥接路径正常处理。
            if !is_stack_routable_unicast(&raw) {
                continue;
            }
            let pkt = Packet::new(Bytes::copy_from_slice(&raw));
            use futures_util::SinkExt;
            if let Err(e) = stack_sink.send(pkt).await {
                error!(err = %e, "tun(gvisor): stack_sink send failed");
                break;
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
    // F6：TCP DNS 劫持需要 dns_tx 副本（dns_tx 原本整体 move 进 udp_dispatch）。
    let dns_tx_for_tcp = dns_tx.clone();
    let tcp_dispatch = tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(stream) = tcp_listener.next().await {
            let remote = stream.remote_addr();
            debug!(remote = %remote, "tun(gvisor): new TCP stream");

            // F6：TCP DNS 劫持（对齐 sing-tun DNSMode=hijack 与 system 栈）——
            // 目标端口 53 的连接直接进 DNS-over-TCP handler，不走代理路径。
            if dns_hijack && remote.port() == 53 && dns_tx_for_tcp.is_some() {
                match bridge_to_tcpstream(stream).await {
                    Ok(tcp_stream) => {
                        tokio::spawn(super::handle_dns_tcp_stream(
                            tcp_stream,
                            remote,
                            dns_tx_for_tcp.clone(),
                            tcp_tag.clone(),
                        ));
                    }
                    Err(e) => {
                        debug!(err = %e, remote = %remote, "tun(gvisor): dns bridge failed");
                    }
                }
                continue;
            }

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
    // 回包 MTU（对齐 system 栈 F3：超 MTU 回包按协议分片 / ICMP 通告，不静默丢包）
    let reply_mtu = mtu;
    let udp_dispatch = tokio::spawn(async move {
// UDP 会话表（EIM，对齐 sing-tun tun_nat.go：key = 源地址）
let udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpReplyEntry>>> =
Arc::new(Mutex::new(HashMap::new()));

        // GC task：定期清理超时 UDP 会话（F3：使用配置的 udp_timeout，
        // 旧实现写死 300s 常量，配置 udp_timeout 不生效）
        {
            let sessions = udp_sessions.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(udp_timeout / 2);
                loop {
                    ticker.tick().await;
                    sessions
                        .lock()
                        .await
                        .retain(|_, v| v.last_seen.elapsed() < udp_timeout);
                }
            });
        }

        while let Some(pkt) = udp_read.recv().await {
            let src = pkt.local_addr;
            let dst = pkt.remote_addr;
            let data = Bytes::copy_from_slice(pkt.data());

            // TUN 层 DNS 劫持：参考 clash-rs datagram.rs:97-168，
            // 在端口 53 且 hijack_dns 启用时直接通过 DNS 解析器响应。
            // dns_tx 不可用（解析器未挂载）时回退到正常 UDP 会话路径，
            // 避免端口 53 流量被静默丢弃。
            if dns_hijack && dst.port() == 53 {
                if let Some(ref tx) = dns_tx {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let query = DnsQuery {
                        // clone：send 失败/无 dns_tx 时回退到正常 UDP 会话路径，
                        // `data` 仍需保留。
                        message: data.clone(),
                        from: src,
                        inbound_tag: (*udp_tag).clone(),
                        source: DnsQuerySource::Hijacked,
                        reply_tx,
                    };
                    if tx.send(query).await.is_err() {
                        debug!("tun(gvisor): dns_tx closed, fall back to normal UDP path");
                    } else {
                        match reply_rx.await {
                            Ok(response) => {
                                if let Some(pkt) =
                                    super::build_udp_reply_packet(dst, src, &response)
                                {
                                    let is_v6 = matches!(dst, SocketAddr::V6(_));
                                    // 对齐 system 栈 F3：DNS 响应可超过 TUN MTU，
                                    // 按 MTU 闭环写出（分片 / ICMP 通告）。
                                    super::tun_write_mtu(&udp_reply_writer, pkt, reply_mtu, is_v6)
                                        .await;
                                }
                            }
                            Err(_) => {
                                debug!("tun(gvisor): DNS reply rx dropped");
                            }
                        }
                        continue;
                    }
                }
            }

// EIM：key 只按源地址（对齐 sing-tun tun_nat.go）
let key = src;
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
                            // F3 对齐 system 栈：超 TUN MTU 的回包按 MTU 闭环写出
                            //（分片 / ICMP 通告），避免大包 UDP 被内核静默丢弃。
                            super::tun_write_mtu(&writer, pkt, reply_mtu, is_v6).await;
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

/// 判断一个原始 IP 包是否可进入用户态协议栈：目的地址为全局单播或 loopback。
///
/// F1 修复：对齐 sing-tun LinkEndpointFilter（stack_gvisor_filter.go）——
/// 广播/组播/链路本地目的的包（mDNS/SSDP/NetBIOS 等）不应进入协议栈，
/// 否则会被 UDP 通道解析后当作单播流量送入代理路径。loopback 保留。
fn is_stack_routable_unicast(raw: &[u8]) -> bool {
    if raw.is_empty() {
        return false;
    }
    match raw[0] >> 4 {
        4 => {
            if raw.len() < 20 {
                return false;
            }
            let dst = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
            dst.is_loopback() || super::is_global_unicast_v4(dst)
        }
        6 => {
            if raw.len() < 40 {
                return false;
            }
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));
            dst.is_loopback() || super::is_global_unicast_v6(dst)
        }
        _ => true,
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
    // 建桥失败时对 netstack 流发 RST（对齐 sing-tun NAT 失败语义）：
    // 否则 Drop 只发 FIN，客户端会重传等超时，感知不到失败。
    async fn bridge_inner() -> std::io::Result<(tokio::net::TcpStream, tokio::net::TcpStream)> {
        // 绑定本地 listener，仅接受一条连接
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;

        // 发起本地 connect（用本地 OS socket 作为 SniffedStream 的载体）
        let os_stream = tokio::net::TcpStream::connect(local_addr).await?;
        // 设置 NODELAY，避免桥接层引入 Nagle 延迟
        let _ = os_stream.set_nodelay(true);

        let (accepted, _) = listener.accept().await?;
        Ok((os_stream, accepted))
    }

    let (os_stream, accepted) = match bridge_inner().await {
        Ok(s) => s,
        Err(e) => {
            netstack_stream.abort();
            return Err(e);
        }
    };

    // 双向 copy：netstack ↔ accepted。
    //
    // 半关闭传播修复（对齐 sing-tun gonet.TCPConn 的 CloseRead/CloseWrite
    // 语义，stack_gvisor_lazy.go:159-193）：任一方向读到 EOF 后立即对该
    // 方向的写端 shutdown()，让 FIN 马上向对端传播。旧实现用
    // `tokio::io::copy` + join，copy 在 EOF 时不会 shutdown 目的写端，
    // TCP 半关闭（FIN）被吞掉，对端连接会挂到另一方向也结束才关。
    tokio::spawn(async move {
        let (mut ns_read, mut ns_write) = tokio::io::split(netstack_stream);
        let (mut acc_read, mut acc_write) = tokio::io::split(accepted);

        let c2s = async move {
            let _ = tokio::io::copy(&mut acc_read, &mut ns_write).await;
            let _ = ns_write.shutdown().await;
        };
        let s2c = async move {
            let _ = tokio::io::copy(&mut ns_read, &mut acc_write).await;
            let _ = acc_write.shutdown().await;
        };
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
    dev: super::native_tun::NativeTunReader,
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
    inet4_loopback: &[std::net::Ipv4Addr],
    inet6_loopback: &[std::net::Ipv6Addr],
    tcp_mss: Option<u16>,
    udp_timeout: Duration,
    dns_tx: Option<DnsQueryTx>,
    dns_hijack: bool,
    // R2：TUN 前缀（acceptLoop 目标重写用，与 system 栈 accept_loop 一致）
    inet4_prefixes: Vec<(std::net::Ipv4Addr, u8)>,
    inet6_prefixes: Vec<(std::net::Ipv6Addr, u8)>,
    // 路由器/出站管理器：mixed 栈 ICMP 仍走 system 栈的 handle_icmpv4/v6
    // （内核回环应答），不经过 IcmpForwarder，因此这两个参数在此栈下未使用，
    // 仅为与 run_gvisor 签名对齐而保留（system/gvisor 栈才会用到）。
    router: Option<Arc<Router>>,
    outbound_mgr: Option<Arc<OutboundManager>>,
) -> anyhow::Result<()> {
    use super::{
        handle_icmpv4, handle_icmpv6, handle_tcp_v4, handle_tcp_v6, TcpNat, IPPROTO_ICMP,
        IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, IPV4_VERSION, IPV6_VERSION,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // mixed 栈 ICMP 走 system 栈的 handle_icmpv4/v6（内核回环应答），
    // 不经过 IcmpForwarder，因此 router/outbound_mgr 在此栈下未使用。
    // 保留参数仅为与 run_gvisor 签名对齐，便于上层统一传参。
    let _ = (router, outbound_mgr);

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
            let p4 = inet4_prefixes.clone();
            let p6 = inet6_prefixes.clone();
            accept_tasks.push(tokio::spawn(async move {
                super::accept_loop(
                    listener,
                    tcp_nat_clone,
                    tcp_tx_clone,
                    tag_clone,
                    p4,
                    p6,
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
            let p4 = inet4_prefixes.clone();
            let p6 = inet6_prefixes.clone();
            accept_tasks.push(tokio::spawn(async move {
                super::accept_loop(
                    listener,
                    tcp_nat_clone,
                    tcp_tx_clone,
                    tag_clone,
                    p4,
                    p6,
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

    // ── TCP DNS 劫持监听器（F5 修复，对齐 system 栈 B2）───────────────────
    // 旧实现 mixed 栈 handle_tcp_v4/v6 的 dns_tcp_port 传 None：port 53 的 TCP
    // 连接被 NAT 重定向到通用 listener，被当作普通代理连接送入代理路径，
    // DNS-over-TCP 劫持完全失效。此处与 system 栈一致建立独立监听器。
    let (dns_tcp_port_v4, dns_tcp_port_v6) = if dns_hijack && dns_tx.is_some() {
        let mut p4: Option<u16> = None;
        let mut p6: Option<u16> = None;
        if let Some(addr) = inet4_server_addr {
            match TcpListener::bind(SocketAddr::new(IpAddr::V4(addr), 0)).await {
                Ok(l) => {
                    match l.local_addr() {
                        Ok(a) => p4 = Some(a.port()),
                        Err(e) => warn!(err = %e, "tun(mixed): dns tcp v4 local_addr failed"),
                    }
                    let listener = Arc::new(l);
                    accept_tasks.push(tokio::spawn(super::tcp_dns_accept_loop(
                        listener,
                        tcp_nat.clone(),
                        dns_tx.clone(),
                        tag.clone(),
                    )));
                }
                Err(e) => {
                    warn!(err = %e, "tun(mixed): failed to bind TCP DNS v4 listener");
                }
            }
        }
        if let Some(addr) = inet6_server_addr {
            match TcpListener::bind(SocketAddr::new(IpAddr::V6(addr), 0)).await {
                Ok(l) => {
                    match l.local_addr() {
                        Ok(a) => p6 = Some(a.port()),
                        Err(e) => warn!(err = %e, "tun(mixed): dns tcp v6 local_addr failed"),
                    }
                    let listener = Arc::new(l);
                    accept_tasks.push(tokio::spawn(super::tcp_dns_accept_loop(
                        listener,
                        tcp_nat.clone(),
                        dns_tx.clone(),
                        tag.clone(),
                    )));
                }
                Err(e) => {
                    warn!(err = %e, "tun(mixed): failed to bind TCP DNS v6 listener");
                }
            }
        }
        if p4.is_some() || p6.is_some() {
            info!(
                tag = %tag,
                v4_port = ?p4,
                v6_port = ?p6,
                "tun(mixed): TCP DNS hijack listener ready"
            );
        }
        (p4, p6)
    } else {
        (None, None)
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
        udp_timeout = udp_timeout.as_secs(),
        "tun(mixed): system TCP + gvisor UDP started"
    );

    // ── UDP 会话表（gvisor UDP 路径，与 run_gvisor 一致）─────────────────
// UDP 会话表（EIM，对齐 sing-tun tun_nat.go：key = 源地址）
let udp_sessions: Arc<Mutex<HashMap<SocketAddr, UdpReplyEntry>>> =
Arc::new(Mutex::new(HashMap::new()));
    {
        let sessions = udp_sessions.clone();
        tokio::spawn(async move {
            // F3：使用配置的 udp_timeout（旧实现写死 DEFAULT_UDP_TIMEOUT_SECS）
            let mut ticker = tokio::time::interval(udp_timeout / 2);
            loop {
                ticker.tick().await;
                sessions.lock().await.retain(|_, v| v.last_seen.elapsed() < udp_timeout);
            }
        });
    }

    // ── UDP dispatch task（gvisor UDP）──────────────────────────────────
    let udp_tag = tag.clone();
    let udp_reply_writer = tun_writer.clone();
    // 回包 MTU（对齐 system 栈 F3：超 MTU 回包分片 / ICMP 通告）
    let reply_mtu = mtu;
    let udp_dispatch = tokio::spawn(async move {
        while let Some(pkt) = udp_read.recv().await {
            let src = pkt.local_addr;
            let dst = pkt.remote_addr;
            let data = Bytes::copy_from_slice(pkt.data());

            // TUN 层 DNS 劫持：参考 clash-rs datagram.rs:97-168，
            // 在端口 53 且 hijack_dns 启用时直接通过 DNS 解析器响应。
            // dns_tx 不可用时回退正常 UDP 会话路径，避免 53 端口流量被丢弃。
            if dns_hijack && dst.port() == 53 {
                if let Some(ref tx) = dns_tx {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let query = DnsQuery {
                        // clone：send 失败/无 dns_tx 时回退到正常 UDP 会话路径，
                        // `data` 仍需保留。
                        message: data.clone(),
                        from: src,
                        inbound_tag: (*udp_tag).clone(),
                        source: DnsQuerySource::Hijacked,
                        reply_tx,
                    };
                    if tx.send(query).await.is_err() {
                        debug!("tun(mixed/gvisor): dns_tx closed, fall back to normal UDP path");
                    } else {
                        match reply_rx.await {
                            Ok(response) => {
                                if let Some(pkt) =
                                    super::build_udp_reply_packet(dst, src, &response)
                                {
                                    let is_v6 = matches!(dst, SocketAddr::V6(_));
                                    // F3 对齐 system 栈：DNS 响应按 TUN MTU 闭环写出
                                    super::tun_write_mtu(&udp_reply_writer, pkt, reply_mtu, is_v6)
                                        .await;
                                }
                            }
                            Err(_) => {
                                debug!("tun(mixed/gvisor): DNS reply rx dropped");
                            }
                        }
                        continue;
                    }
                }
            }

// EIM：key 只按源地址（对齐 sing-tun tun_nat.go）
let key = src;
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
                            // F3 对齐 system 栈：超 TUN MTU 的回包按 MTU 闭环写出
                            super::tun_write_mtu(&writer, pkt, reply_mtu, is_v6).await;
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
    loop {
        // 主循环只读 TUN；下游 task 退出由 TUN 关闭级联触发，无需在此 select!。
        // NativeTunReader：已剥除 virtio_net_hdr，返回纯 IP 包。
        let pkt = match reader.read_packet().await {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!(tag = %tag, "tun(mixed): device closed");
                break;
            }
            Err(e) => {
                error!(err = %e, "tun(mixed): tun read error");
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
        };
        if pkt.is_empty() {
            continue;
        }
        let pkt_slice = pkt.as_slice();
        // ── B6 修复：不再按本地子网丢弃（对齐 system 栈 B5 与 sing-tun 语义）──
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
                            dns_tcp_port_v4,
                            tcp_mss,
                            tun_writer.clone(),
                            tcp_nat.clone(),
                            dns_hijack,
                        )
                        .await;
                    }
                    IPPROTO_UDP => {
                        // F7 修复：与 system 栈 process_ipv4/sing-tun 一致，过滤
                        // 非全局单播目标（旧实现 v6 有过滤、v4 没有，mDNS/NetBIOS
                        // 广播被注入协议栈并送入代理路径）。
                        if !super::is_global_unicast_v4(dst_ip) {
                            continue;
                        }
                        // UDP → gvisor
                        let pkt = Packet::new(Bytes::copy_from_slice(pkt_slice));
                        use futures_util::SinkExt;
                        if let Err(e) = stack_sink.send(pkt).await {
                            error!(err = %e, "tun(mixed/gvisor): stack_sink send failed");
                            break;
                        }
                    }
                    IPPROTO_ICMP => {
                        // F7 修复：与 system 栈一致，非全局单播目标（含广播）直接丢弃
                        if !super::is_global_unicast_v4(dst_ip) {
                            continue;
                        }
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
                // 对齐 system 栈 process_ipv6（B3 修复）：遍历 hop-by-hop / routing /
                // destination-options 扩展头后再按协议分发，带扩展头的 TCP/UDP 包
                // 不再被误判为未知协议丢弃，或把扩展头当传输头解析。
                let (protocol, payload, is_fragment, transport_present) =
                    super::skip_ipv6_extension_headers(pkt_slice[6], &pkt_slice[40..]);
                if is_fragment || !transport_present {
                    // 分片包无法做 NAT/端口解析，与 system 栈语义一致直接丢弃。
                    continue;
                }
                match protocol {
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
                            dns_tcp_port_v6,
                            tcp_mss,
                            tun_writer.clone(),
                            tcp_nat.clone(),
                            dns_hijack,
                        )
                        .await;
                    }
                    IPPROTO_UDP => {
                        // 与 system 栈 process_ipv6 一致：过滤非全局单播目标。
                        if !super::is_global_unicast_v6(dst_ip) {
                            continue;
                        }
                        let pkt = Packet::new(Bytes::copy_from_slice(pkt_slice));
                        use futures_util::SinkExt;
                        if let Err(e) = stack_sink.send(pkt).await {
                            error!(err = %e, "tun(mixed/gvisor): stack_sink send failed");
                            break;
                        }
                    }
                    // F7 修复：与 system 栈/sing-tun 一致，非全局单播目标直接丢弃
                    //（handle_icmpv6 的回包构造假定 ICMPv6 头紧随固定头（offset 40）；
                    // 带扩展头的 ICMPv6（实践中不存在于 Echo Request）直接丢弃）。
                    IPPROTO_ICMPV6
                        if super::is_global_unicast_v6(dst_ip)
                            && payload.len() == pkt_slice.len() - 40 =>
                    {
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
