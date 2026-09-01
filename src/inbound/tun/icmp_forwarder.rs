#![allow(dead_code)]
#![cfg(unix)]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::{unix::AsyncFd, AsyncWriteExt},
    sync::{mpsc, Mutex},
};
use tracing::{debug, info, warn};

use crate::{
    app::outbound_mgr::OutboundManager,
    router::{RouteAction, Router},
};

use super::{
    checksum_with_pseudo_v6, internet_checksum, recompute_icmpv6_checksum, recompute_ipv4_checksum,
    tun_write, IPPROTO_ICMP, IPPROTO_ICMPV6, SYNTHESIZED_TTL,
};

/// ICMP flow 超时（与 sing-tun ICMPForwarder 默认 30s 对齐）。
const ICMP_FLOW_TIMEOUT: Duration = Duration::from_secs(30);

/// 单个 flow 的待发送队列容量。
const ICMP_SEND_QUEUE: usize = 64;

/// ICMP Echo Request 类型值。
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV4_DST_UNREACHABLE: u8 = 3;
/// ICMPv4 Destination Unreachable - Host Unreachable（对齐 sing-box 1.13.0
/// `reject` 默认方法对 ICMP 回复主机不可达的语义）。
const ICMPV4_CODE_HOST_UNREACHABLE: u8 = 1;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_DST_UNREACHABLE: u8 = 1;
/// ICMPv6 Destination Unreachable - Address Unreachable（IPv6 的"主机不可达"
/// 等价语义，对齐 sing-box 1.13.0 `reject` 默认方法）。
const ICMPV6_CODE_ADDR_UNREACHABLE: u8 = 3;

/// Flow key：(源 IP, 目的 IP, ICMP Identifier)。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    icmp_id: u16,
}

struct FlowEntry {
    /// 发往上游的 echo request payload 队列（不含 IP 头，含 ICMP 头）。
    send_tx: mpsc::Sender<Bytes>,
    last_seen: Instant,
}

/// gvisor 栈 ICMP 转发器。
///
/// 持有 flow 表，对每个 (src, dst, icmp_id) 维护一个长期 task 负责与上游通信。
/// 回包通过 `tun_writer` 直接写回 TUN（绕过 smoltcp）。
///
/// 若注入 `router` + `outbound_mgr`，每个 echo request 会先走路由策略
/// （对齐 sing-box 1.13.0 `network: "icmp"` 规则）：
/// - `route` → `direct` 出站：转 raw socket 转发（默认行为）
/// - `route` → 非直连出站：丢弃（代理出站不支持 ICMP，对齐 sing-box
///   `outbound.Network()` 不含 `NetworkICMP` 时的报错）
/// - `reject(default)`：回复 ICMP 主机不可达
/// - `reject(reply)`：回复 ICMP 回显应答（假装主机存活）
/// - `reject(drop)` / `block` / `hijack-dns`：静默丢弃
pub struct IcmpForwarder<W: AsyncWriteExt + Unpin + Send + 'static> {
    flows: Arc<Mutex<HashMap<FlowKey, FlowEntry>>>,
    tun_writer: Arc<Mutex<W>>,
    /// 路由器：注入后启用 ICMP 路由策略；None 时退化为始终转发的旧行为。
    router: Option<Arc<Router>>,
    /// 出站管理器：用于判断 `route` 动作指向的出站是否支持 ICMP（仅 direct 支持）。
    outbound_mgr: Option<Arc<OutboundManager>>,
    /// 入站 tag：传给路由器做 `inbound` 条件匹配。
    inbound_tag: Arc<String>,
}

impl<W: AsyncWriteExt + Unpin + Send + 'static> IcmpForwarder<W> {
    /// 旧式构造（不走路由策略，所有 echo request 直接转发到上游）。
    pub fn new(tun_writer: Arc<Mutex<W>>) -> Self {
        let forwarder = Self {
            flows: Arc::new(Mutex::new(HashMap::new())),
            tun_writer,
            router: None,
            outbound_mgr: None,
            inbound_tag: Arc::new(String::new()),
        };
        forwarder.spawn_gc();
        forwarder
    }

    /// 注入路由器与出站管理器，启用 ICMP 路由策略。
    pub fn with_router(
        mut self,
        router: Arc<Router>,
        outbound_mgr: Arc<OutboundManager>,
        inbound_tag: Arc<String>,
    ) -> Self {
        self.router = Some(router);
        self.outbound_mgr = Some(outbound_mgr);
        self.inbound_tag = inbound_tag;
        self
    }

    /// 处理一个原始 IP 包。若为 ICMP Echo Request，转发到上游；否则忽略。
    ///
    /// 返回 true 表示已处理（调用方应跳过后续 process_ipv4/v6）。
    pub async fn handle_packet(&self, raw: &[u8]) -> bool {
        if raw.is_empty() {
            return false;
        }
        let version = raw[0] >> 4;
        match version {
            4 => self.handle_v4(raw).await,
            6 => self.handle_v6(raw).await,
            _ => false,
        }
    }

    async fn handle_v4(&self, raw: &[u8]) -> bool {
        if raw.len() < 28 {
            return false;
        }
        let ihl = ((raw[0] & 0x0f) as usize) * 4;
        if raw.len() < ihl + 8 || ihl < 20 {
            return false;
        }
        if raw[9] != IPPROTO_ICMP || raw[ihl] != ICMPV4_ECHO_REQUEST || raw[ihl + 1] != 0 {
            return false;
        }
        let src = Ipv4Addr::from([raw[12], raw[13], raw[14], raw[15]]);
        let dst = Ipv4Addr::from([raw[16], raw[17], raw[18], raw[19]]);
        let icmp_id = u16::from_be_bytes([raw[ihl + 4], raw[ihl + 5]]);

        if self.route_and_apply_v4(raw, ihl, src, dst).await {
            return true;
        }
        // 路由决策为转发到 direct 出站（或未注入路由器）：走 raw socket 转发
        let payload = Bytes::copy_from_slice(&raw[ihl..]);
        self.forward(
            FlowKey {
                src: IpAddr::V4(src),
                dst: IpAddr::V4(dst),
                icmp_id,
            },
            payload,
            raw,
            false,
        )
        .await
    }

    async fn handle_v6(&self, raw: &[u8]) -> bool {
        if raw.len() < 48 {
            return false;
        }
        if raw[6] != IPPROTO_ICMPV6 || raw[40] != ICMPV6_ECHO_REQUEST || raw[41] != 0 {
            return false;
        }
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[8..24]).unwrap_or([0u8; 16]));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&raw[24..40]).unwrap_or([0u8; 16]));
        let icmp_id = u16::from_be_bytes([raw[44], raw[45]]);

        if self.route_and_apply_v6(raw, src, dst).await {
            return true;
        }
        let payload = Bytes::copy_from_slice(&raw[40..]);
        self.forward(
            FlowKey {
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                icmp_id,
            },
            payload,
            raw,
            true,
        )
        .await
    }

    /// 对 IPv4 echo request 做路由决策并应用非转发动作。
    /// 返回 true 表示已由路由动作处理（拒绝/阻断/回显应答等），调用方无需再转发；
    /// 返回 false 表示应按默认行为转发到上游（route→direct 或未注入路由器）。
    async fn route_and_apply_v4(
        &self,
        raw: &[u8],
        ihl: usize,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> bool {
        let (Some(router), Some(outbound_mgr)) = (&self.router, &self.outbound_mgr) else {
            return false;
        };
        let (action, _, _, _) = router.route_icmp(&self.inbound_tag, Some(IpAddr::V4(src)), IpAddr::V4(dst));
        match action {
            RouteAction::Outbound(tag) => {
                if Self::outbound_supports_icmp(outbound_mgr, tag) {
                    false // 走默认 raw socket 转发路径
                } else {
                    warn!(
                        outbound = %tag,
                        src = %src,
                        dst = %dst,
                        "tun(icmp): route outbound does not support icmp, dropping"
                    );
                    true
                }
            }
            RouteAction::Reject { method } => match method {
                crate::config::route::RejectMethod::Default => {
                    if let Some(pkt) = build_icmpv4_dst_unreachable(raw, ihl, ICMPV4_CODE_HOST_UNREACHABLE) {
                        tun_write(&self.tun_writer, &pkt, false).await;
                    }
                    true
                }
                crate::config::route::RejectMethod::Reply => {
                    if let Some(pkt) = build_echo_reply_v4(raw, ihl) {
                        tun_write(&self.tun_writer, &pkt, false).await;
                    }
                    true
                }
                crate::config::route::RejectMethod::Drop => true,
            },
            RouteAction::Block => true,
            RouteAction::DnsOut => true,
            // sniff/resolve 不应出现（route_icmp 已跳过），防御性处理：转发
            RouteAction::Sniff { .. } | RouteAction::Resolve { .. } => false,
        }
    }

    /// 对 IPv6 echo request 做路由决策并应用非转发动作（同 v4 版本）。
    async fn route_and_apply_v6(&self, raw: &[u8], src: Ipv6Addr, dst: Ipv6Addr) -> bool {
        let (Some(router), Some(outbound_mgr)) = (&self.router, &self.outbound_mgr) else {
            return false;
        };
        let (action, _, _, _) = router.route_icmp(&self.inbound_tag, Some(IpAddr::V6(src)), IpAddr::V6(dst));
        match action {
            RouteAction::Outbound(tag) => {
                if Self::outbound_supports_icmp(outbound_mgr, tag) {
                    false
                } else {
                    warn!(
                        outbound = %tag,
                        src = %src,
                        dst = %dst,
                        "tun(icmp): route outbound does not support icmp, dropping"
                    );
                    true
                }
            }
            RouteAction::Reject { method } => match method {
                crate::config::route::RejectMethod::Default => {
                    if let Some(pkt) = build_icmpv6_dst_unreachable(raw, ICMPV6_CODE_ADDR_UNREACHABLE) {
                        tun_write(&self.tun_writer, &pkt, true).await;
                    }
                    true
                }
                crate::config::route::RejectMethod::Reply => {
                    if let Some(pkt) = build_echo_reply_v6(raw) {
                        tun_write(&self.tun_writer, &pkt, true).await;
                    }
                    true
                }
                crate::config::route::RejectMethod::Drop => true,
            },
            RouteAction::Block => true,
            RouteAction::DnsOut => true,
            RouteAction::Sniff { .. } | RouteAction::Resolve { .. } => false,
        }
    }

    /// 判断出站是否支持 ICMP：仅 `direct` 出站支持（对齐 sing-box 中
    /// `outbound.Network()` 含 `NetworkICMP` 的语义——仅 direct/wireguard/
    /// tailscale 注册了 ICMP，reflex 的 raw socket 转发等价于 direct）。
    fn outbound_supports_icmp(outbound_mgr: &OutboundManager, tag: &str) -> bool {
        match outbound_mgr.get(tag) {
            Some(ob) => ob.status().type_name == "Direct",
            None => {
                // 出站不存在：交由默认转发路径（会因 socket 连接失败自然丢弃），
                // 避免路由配置滞后于出站注册时把所有 ping 都拦掉。
                debug!(outbound = %tag, "tun(icmp): route outbound not found, falling through");
                true
            }
        }
    }

    /// 查找或建立 flow，把 echo request payload 入队转发。
    async fn forward(&self, key: FlowKey, payload: Bytes, template: &[u8], is_v6: bool) -> bool {
        let mut flows = self.flows.lock().await;
        let entry = flows.entry(key).or_insert_with(|| {
            debug!(src = %key.src, dst = %key.dst, id = key.icmp_id, "tun(gvisor/icmp): new flow");
            let (send_tx, send_rx) = mpsc::channel::<Bytes>(ICMP_SEND_QUEUE);
            let tun_writer = self.tun_writer.clone();
            let tmpl = Bytes::copy_from_slice(template);
            tokio::spawn(flow_task(key, send_rx, tun_writer, tmpl, is_v6));
            FlowEntry {
                send_tx,
                last_seen: Instant::now(),
            }
        });
        entry.last_seen = Instant::now();
        let send_tx = entry.send_tx.clone();
        drop(flows);
        if send_tx.try_send(payload).is_err() {
            // flow task 已退出（socket 打开失败/异常结束）：移除死条目，
            // 让下一个请求重建 flow（旧实现死条目会驻留 30s，期间所有
            // 请求被静默丢弃）。
            self.flows.lock().await.remove(&key);
        }
        true
    }

    fn spawn_gc(&self) {
        let flows = self.flows.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;
                flows
                    .lock()
                    .await
                    .retain(|_, v| v.last_seen.elapsed() < ICMP_FLOW_TIMEOUT);
            }
        });
    }
}

/// 单个 flow 的转发 task：拥有 socket，循环转发 echo request → 上游，reply → TUN。
async fn flow_task<W: AsyncWriteExt + Unpin + Send + 'static>(
    key: FlowKey,
    mut send_rx: mpsc::Receiver<Bytes>,
    tun_writer: Arc<Mutex<W>>,
    tmpl: Bytes,
    is_v6: bool,
) {
    let (socket, is_raw) = match open_icmp_socket(key.dst) {
        Ok(s) => s,
        Err(e) => {
            warn!(err = %e, dst = %key.dst,
                  "tun(gvisor/icmp): open socket failed (need CAP_NET_RAW or ping_group)");
            return;
        }
    };
    // RAW IPv6 发送时需以本地源地址计算伪头部校验和（内核只补 IPv6 头，
    // 不计算 ICMPv6 校验和）；ping(DGRAM) socket 由内核计算。
    let local_src: Option<IpAddr> = if is_raw {
        socket
            .local_addr()
            .ok()
            .and_then(|a| a.as_socket())
            .map(|sa| sa.ip())
    } else {
        None
    };
    let async_fd = match AsyncFd::new(socket) {
        Ok(fd) => fd,
        Err(e) => {
            warn!(err = %e, "tun(gvisor/icmp): AsyncFd::new failed");
            return;
        }
    };
    let mut recv_buf: Vec<std::mem::MaybeUninit<u8>> = (0..65535)
        .map(|_| std::mem::MaybeUninit::uninit())
        .collect();
    loop {
        tokio::select! {
            // 上游回复到达
            guard = async_fd.readable() => {
                let mut guard = match guard {
                    Ok(g) => g,
                    Err(e) => {
                        debug!(err = %e, "tun(gvisor/icmp): readable error, flow ends");
                        break;
                    }
                };
                match guard.try_io(|fd| fd.get_ref().recv(&mut recv_buf)) {
                    Ok(Ok(n)) if n > 0 => {
                        // Safety: 内核已写入 n 字节，可安全假设已初始化
                        let data: &[u8] = unsafe {
                            std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, n)
                        };
                        // B4 修复：RAW socket recv 返回含 IP 头的完整包
                        // （Linux/Windows；对齐 sing-tun ping.go
                        // "An unconnected SOCK_RAW IPv4 socket delivers the
                        // full packet including the IP header"），必须先剥掉
                        // IP 头再当 ICMP payload 用；ping(DGRAM) socket 返回的
                        // 直接就是 ICMP 包。
                        let icmp_data = if is_raw {
                            match strip_raw_ip_header(data) {
                                Some(rest) => rest,
                                None => continue,
                            }
                        } else {
                            data
                        };
                        // 类型 + identifier 校验（对齐 gVisor ICMPForwarder /
                        // sing-tun stack_system.go:642-653 只回送 Echo）：
                        // RAW socket 会收到来自同一主机的所有 ICMP（目的
                        // 不可达、超时，以及本机其他进程 ping 同一主机时的
                        // 回包 —— 不同 identifier），这些都不能被伪造成
                        // Echo Reply 写回 TUN。
                        if icmp_data.len() < 8
                            || icmp_data[0] != if is_v6 { ICMPV6_ECHO_REPLY } else { ICMPV4_ECHO_REPLY }
                            || icmp_data[1] != 0
                            || u16::from_be_bytes([icmp_data[4], icmp_data[5]]) != key.icmp_id
                        {
                            debug!(type = icmp_data[0], "tun(gvisor/icmp): ignore non-echo-reply packet");
                            continue;
                        }
                        if let Some(pkt) = build_echo_reply_packet(&tmpl, key, icmp_data, is_v6) {
                            tun_write(&tun_writer, &pkt, is_v6).await;
                        }
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        debug!(err = %e, "tun(gvisor/icmp): recv error, flow ends");
                        break;
                    }
                    Err(_wb) => continue,
                }
            }
            // 新的 echo request 入队
            maybe_payload = send_rx.recv() => {
                match maybe_payload {
                    Some(payload) => {
                        let send_payload = prepare_send_payload(&payload, is_v6, is_raw, local_src, key.dst);
                        // 发送到上游
                        loop {
                            let mut guard = match async_fd.writable().await {
                                Ok(g) => g,
                                Err(_) => break,
                            };
                            match guard.try_io(|fd| fd.get_ref().send(&send_payload)) {
                                Ok(Ok(_)) | Ok(Err(_)) => break,
                                Err(_wb) => continue,
                            }
                        }
                    }
                    None => break,
                }
            }
        }
    }
    debug!(src = %key.src, dst = %key.dst, "tun(gvisor/icmp): flow task exited");
}

/// 剥离 RAW socket 收到的数据包的 IP 头。
/// IPv4 按 IHL 计算（含 options），IPv6 固定 40 字节（忽略扩展头——
/// echo reply 不会携带扩展头）。
fn strip_raw_ip_header(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() {
        return None;
    }
    match data[0] >> 4 {
        4 => {
            if data.len() < 20 {
                return None;
            }
            let ihl = ((data[0] & 0x0f) as usize) * 4;
            if ihl < 20 || data.len() < ihl + 8 {
                return None;
            }
            Some(&data[ihl..])
        }
        6 => {
            if data.len() < 48 {
                return None;
            }
            Some(&data[40..])
        }
        _ => None,
    }
}

/// 打开 ICMP socket（对齐 sing-tun openICMPEndpoint）。
/// 返回 (socket, is_raw)：is_raw 标记是否为 RAW socket（recv 含 IP 头、
/// send 需手动计算 ICMP 校验和；Linux ping/DGRAM socket 两者都不需要）。
fn open_icmp_socket(dst: IpAddr) -> std::io::Result<(Socket, bool)> {
    let domain = match dst {
        IpAddr::V4(_) => Domain::IPV4,
        IpAddr::V6(_) => Domain::IPV6,
    };
    let protocol = match dst {
        IpAddr::V4(_) => Protocol::ICMPV4,
        IpAddr::V6(_) => Protocol::ICMPV6,
    };

    // Linux/Android ping socket (SOCK_DGRAM) - 不需要 CAP_NET_RAW
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Ok(sock) = Socket::new(domain, Type::DGRAM, Some(protocol)) {
            if let Ok(sock) = configure_and_connect(sock, dst) {
                return Ok((sock, false));
            }
        }
    }

    // Raw socket fallback（需要 CAP_NET_RAW）
    let sock = configure_and_connect(Socket::new(domain, Type::RAW, Some(protocol))?, dst)?;
    Ok((sock, true))
}

fn configure_and_connect(sock: Socket, dst: IpAddr) -> std::io::Result<Socket> {
    // Android：自身流量 protect，防止 ICMP 回包/请求回环进 VPN
    // （对齐 sing-tun protectPath / VpnService.protect，SO_MARK = 0x20000，
    // 吃 android.rs 已装好的 `fwmark 0x20000 lookup main` 规则）。必须
    // 在 connect 之前设置，保证首个包就走物理网卡。
    #[cfg(target_os = "android")]
    {
        use std::os::unix::io::AsRawFd;
        const PROTECTED_FROM_VPN_MARK: u32 = 0x20000;
        let fd = sock.as_raw_fd();
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &PROTECTED_FROM_VPN_MARK as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            warn!(
                err = %std::io::Error::last_os_error(),
                "tun: icmp socket SO_MARK protect failed"
            );
        }
    }
    sock.set_nonblocking(true)?;
    let addr = SockAddr::from(std::net::SocketAddr::new(dst, 0));
    sock.connect(&addr)?;
    Ok(sock)
}

/// 准备发送到上游的 ICMP payload。
///
/// B4 修复：校验和计算以 `is_raw` 为条件（旧实现以平台为条件，Linux RAW
/// fallback 发送的 echo request 校验和恒为 0 → 上游丢弃）：
/// - RAW socket：内核只补 IP 头不计算 ICMP 校验和，必须手动计算
///   （IPv4 为简单校验和，IPv6 需以本地源地址 + 目的地址计算伪头部校验和）；
/// - Linux ping(DGRAM) socket：内核计算校验和，置 0 即可。
fn prepare_send_payload(
    payload: &[u8],
    is_v6: bool,
    is_raw: bool,
    local_src: Option<IpAddr>,
    dst: IpAddr,
) -> Vec<u8> {
    if payload.len() < 8 {
        return payload.to_vec();
    }
    let mut out = payload.to_vec();
    out[0] = if is_v6 {
        ICMPV6_ECHO_REQUEST
    } else {
        ICMPV4_ECHO_REQUEST
    };
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    if !is_raw {
        // Linux ping socket：内核计算校验和
        return out;
    }
    // RAW socket：手动计算校验和
    if is_v6 {
        // ICMPv6 强制校验和，覆盖伪头部（src/dst/长度/next header）
        let src: [u8; 16] = match local_src {
            Some(IpAddr::V6(v)) => v.octets(),
            // 本地地址未知时退化为全零（send 仍会发出，但可能被对端丢弃）
            _ => [0u8; 16],
        };
        let dst_octets: [u8; 16] = match dst {
            IpAddr::V6(v) => v.octets(),
            _ => [0u8; 16],
        };
        let cs = checksum_with_pseudo_v6(&src, &dst_octets, IPPROTO_ICMPV6, &out);
        out[2] = (cs >> 8) as u8;
        out[3] = (cs & 0xff) as u8;
    } else {
        let cs = internet_checksum(&out);
        out[2] = (cs >> 8) as u8;
        out[3] = (cs & 0xff) as u8;
    }
    out
}

fn build_echo_reply_packet(
    template: &[u8],
    key: FlowKey,
    reply_payload: &[u8],
    is_v6: bool,
) -> Option<Vec<u8>> {
    if is_v6 {
        build_echo_reply_v6_from_upstream(template, key, reply_payload)
    } else {
        build_echo_reply_v4_from_upstream(template, key, reply_payload)
    }
}

/// 构造 IPv4 Echo Reply 包（用于路由 `reject(reply)`：把原 echo request
/// 翻转为 reply，src/dst 互换）。
fn build_echo_reply_v4(template: &[u8], ihl: usize) -> Option<Vec<u8>> {
    if template.len() < ihl + 8 || ihl < 20 {
        return None;
    }
    let mut pkt = template.to_vec();
    // src = 原 dst，dst = 原 src（split_at_mut 避免同时两次可变借用）
    let (a, b) = pkt[12..20].split_at_mut(4);
    a.swap_with_slice(b);
    pkt[ihl] = ICMPV4_ECHO_REPLY;
    pkt[ihl + 1] = 0;
    pkt[ihl + 2] = 0;
    pkt[ihl + 3] = 0;
    let cs = internet_checksum(&pkt[ihl..]);
    pkt[ihl + 2] = (cs >> 8) as u8;
    pkt[ihl + 3] = (cs & 0xff) as u8;
    recompute_ipv4_checksum(&mut pkt);
    Some(pkt)
}

/// 构造 IPv6 Echo Reply 包（用于路由 `reject(reply)`）。
fn build_echo_reply_v6(template: &[u8]) -> Option<Vec<u8>> {
    if template.len() < 48 {
        return None;
    }
    let mut pkt = template.to_vec();
    // src = 原 dst，dst = 原 src（split_at_mut 避免同时两次可变借用）
    let (a, b) = pkt[8..40].split_at_mut(16);
    a.swap_with_slice(b);
    pkt[40] = ICMPV6_ECHO_REPLY;
    pkt[41] = 0;
    recompute_icmpv6_checksum(&mut pkt);
    Some(pkt)
}

/// 构造 IPv4 Echo Reply（用于上游回复回写：以上游 ICMP payload 替换原包 payload）。
fn build_echo_reply_v4_from_upstream(template: &[u8], key: FlowKey, reply_payload: &[u8]) -> Option<Vec<u8>> {
    if template.len() < 20 || reply_payload.is_empty() {
        return None;
    }
    let ihl = ((template[0] & 0x0f) as usize) * 4;
    if ihl < 20 || template.len() < ihl {
        return None;
    }
    let total_len = ihl + reply_payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[..ihl].copy_from_slice(&template[..ihl]);
    let dst_v4 = match key.dst {
        IpAddr::V4(v) => v,
        _ => return None,
    };
    let src_v4 = match key.src {
        IpAddr::V4(v) => v,
        _ => return None,
    };
    pkt[12..16].copy_from_slice(&dst_v4.octets());
    pkt[16..20].copy_from_slice(&src_v4.octets());
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[ihl..].copy_from_slice(reply_payload);
    pkt[ihl] = ICMPV4_ECHO_REPLY;
    pkt[ihl + 1] = 0;
    pkt[ihl + 2] = 0;
    pkt[ihl + 3] = 0;
    let cs = internet_checksum(&pkt[ihl..]);
    pkt[ihl + 2] = (cs >> 8) as u8;
    pkt[ihl + 3] = (cs & 0xff) as u8;
    recompute_ipv4_checksum(&mut pkt);
    Some(pkt)
}

/// 构造 IPv6 Echo Reply（用于上游回复回写）。
fn build_echo_reply_v6_from_upstream(template: &[u8], key: FlowKey, reply_payload: &[u8]) -> Option<Vec<u8>> {
    if template.len() < 40 || reply_payload.is_empty() {
        return None;
    }
    let total_len = 40 + reply_payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[..40].copy_from_slice(&template[..40]);
    let dst_v6 = match key.dst {
        IpAddr::V6(v) => v,
        _ => return None,
    };
    let src_v6 = match key.src {
        IpAddr::V6(v) => v,
        _ => return None,
    };
    pkt[8..24].copy_from_slice(&dst_v6.octets());
    pkt[24..40].copy_from_slice(&src_v6.octets());
    pkt[4..6].copy_from_slice(&(reply_payload.len() as u16).to_be_bytes());
    pkt[40..].copy_from_slice(reply_payload);
    pkt[40] = ICMPV6_ECHO_REPLY;
    pkt[41] = 0;
    recompute_icmpv6_checksum(&mut pkt);
    Some(pkt)
}

/// 构造 ICMPv4 Destination Unreachable 包（对齐 sing-box 1.13.0 `reject`
/// 默认方法对 ICMP 回复主机不可达）。
///
/// `orig` 为原始 IPv4 echo request 包（含 IP 头）；错误包 src = 原 dst、
/// dst = 原 src，内嵌原包头（对齐 sing-tun 的 ICMP 错误包语义）。
fn build_icmpv4_dst_unreachable(orig: &[u8], ihl: usize, code: u8) -> Option<Vec<u8>> {
    if orig.len() < ihl + 8 || ihl < 20 {
        return None;
    }
    // 错误包内嵌原 IP 头 + 至少 8 字节上层（对齐 RFC 792）。
    let payload_len = orig.len().min(576 - 20 - 8);
    let size = 20 + 8 + payload_len;
    let mut pkt = vec![0u8; size];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    pkt[8] = SYNTHESIZED_TTL;
    pkt[9] = IPPROTO_ICMP;
    pkt[12..16].copy_from_slice(&orig[16..20]); // src = 原 dst
    pkt[16..20].copy_from_slice(&orig[12..16]); // dst = 原 src
    let csum = internet_checksum(&pkt[..20]);
    pkt[10] = (csum >> 8) as u8;
    pkt[11] = (csum & 0xff) as u8;
    // ICMP：type=3 (DstUnreachable), code=传入值，unused=0
    pkt[20] = ICMPV4_DST_UNREACHABLE;
    pkt[21] = code;
    pkt[28..28 + payload_len].copy_from_slice(&orig[..payload_len]);
    let csum = internet_checksum(&pkt[20..]);
    pkt[22] = (csum >> 8) as u8;
    pkt[23] = (csum & 0xff) as u8;
    Some(pkt)
}

/// 构造 ICMPv6 Destination Unreachable 包（对齐 sing-box 1.13.0 `reject`
/// 默认方法对 ICMP 回复主机不可达 = Address Unreachable）。
fn build_icmpv6_dst_unreachable(orig: &[u8], code: u8) -> Option<Vec<u8>> {
    if orig.len() < 48 {
        return None;
    }
    let payload_len = orig.len().min(1280 - 40 - 8);
    let size = 40 + 8 + payload_len;
    let mut pkt = vec![0u8; size];
    pkt[0] = 0x60;
    let payload_len_field = (8 + payload_len) as u16;
    pkt[4..6].copy_from_slice(&payload_len_field.to_be_bytes());
    pkt[6] = IPPROTO_ICMPV6;
    pkt[7] = SYNTHESIZED_TTL;
    pkt[8..24].copy_from_slice(&orig[24..40]); // src = 原 dst
    pkt[24..40].copy_from_slice(&orig[8..24]); // dst = 原 src
    // ICMPv6：type=1 (DstUnreachable), code=传入值，unused=0
    pkt[40] = ICMPV6_DST_UNREACHABLE;
    pkt[41] = code;
    pkt[48..48 + payload_len].copy_from_slice(&orig[..payload_len]);
    let src: [u8; 16] = pkt[8..24].try_into().ok()?;
    let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
    let csum = checksum_with_pseudo_v6(&src, &dst, IPPROTO_ICMPV6, &pkt[40..]);
    pkt[42] = (csum >> 8) as u8;
    pkt[43] = (csum & 0xff) as u8;
    Some(pkt)
}

/// 单次启动日志（仅用于让上层确认路由策略是否启用）。
#[allow(dead_code)]
pub fn log_icmp_routing_enabled() {
    info!("tun(icmp): routing policy enabled (network:\"icmp\" rules active)");
}
