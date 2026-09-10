//! WireGuard 服务端入站（参考 flux `wireguard/server.rs` + sing-box wireguard endpoint）。
//!
//! ## 整体流程
//!
//! ```text
//!  UDP listen (listen:listen_port)
//!    │  recv_from
//!    ▼
//!  消息分派
//!    ├─ type=1 Initiation：Noise_IKpsk2 响应方（protocol::wireguard 共享原语）
//!    │    ├─ mac1 校验 → 解出对端静态公钥 → 查 peer 表
//!    │    ├─ TAI64N 时间戳防重放（必须严格递增）
//!    │    └─ build_response → 派生传输密钥 → 回 Response
//!    └─ type=4 Transport：按 receiver_index 查会话 → 重放窗口 → AEAD 解密
//!         │  明文 IP 包
//!         ├─ 长度校验/截断 + AllowedIPs 检查（对齐 sing-box receive.go）
//!         ▼
//!  per-peer smoltcp userspace 栈 actor（自研 VirtualIface，Medium::Ip）
//!    ├─ TCP 流：smoltcp listen(内层 dst) → Established → WgTcpStream 适配器
//!    │          → SniffedStream::from_encrypted → InboundTcpStream
//!    ├─ UDP 流：smoltcp bind(内层 dst) → datagram → InboundUdpPacket
//!    │          （dispatcher 回包经 reply_tx → UdpReply 回注栈）
//!    └─ 出站 IP 包 → 传输帧加密 → UDP 发回 peer 当前外部端点
//! ```
//!
//! ## 交付模型（对齐 vless 入站）
//! - TCP：每条内层 TCP 流封装为 [`WgTcpStream`]（AsyncRead+AsyncWrite，
//!   与 smoltcp socket 双向桥接，写路径带背压），经
//!   [`SniffedStream::from_encrypted`] 装箱为 [`InboundTcpStream`]；
//!   `peer` 为客户端的 UDP 外部源地址，`target` 为内层 IP 头的目的地址。
//! - UDP：每个 datagram 一个 [`InboundUdpPacket`]（`upstream_rx: None`），
//!   `src` 为 peer 的隧道内地址，`target` 为内层目的地址；回包元组的
//!   `spoofed_src` 即 target，回注 smoltcp 后源地址自动还原为 target。
//!
//! ## 与 flux 实现的差异
//! - flux 使用 boringtun（reflex 无此依赖）；本实现用 x25519-dalek +
//!   chacha20poly1305 + blake2 直接实现 Noise_IKpsk2 响应方（原语在
//!   `protocol::wireguard`，与 outbound 客户端共享并有握手互通测试）。
//! - 服务端不主动发 keepalive/重握手（客户端 PersistentKeepalive 负责
//!   NAT 保活；会话轮换由客户端发起新 Initiation 驱动，直接替换旧会话）。
//! - Cookie（type=3/mac2 过载保护）未实现：mac2 恒零，过载时依赖内核
//!   UDP 缓冲丢弃。

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context as AnyhowContext, Result};
use bytes::Bytes;
use futures::task::AtomicWaker;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{
        tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState},
        udp::{PacketBuffer, PacketMetadata, Socket as UdpSmolSocket, UdpMetadata},
    },
    time::Instant as SmolInstant,
    wire::{
        HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv4Cidr,
        Ipv6Address, Ipv6Cidr,
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::UdpSocket as TokioUdp,
    sync::{mpsc, Mutex},
};
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::inbound::WireGuardInboundConfig;
use crate::inbound::{
    parse_listen_addr, InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession,
};
use crate::protocol::wireguard::{
    build_response, build_transport_packet, decrypt_transport, decode_key_base64,
    parse_initiation, parse_transport_packet, packet_src_ip, validate_and_truncate_ip_packet,
    MSG_DATA, MSG_INITIATION,
};
use crate::outbound::AsyncReadWrite;

// ── 常量 ──────────────────────────────────────────────────────────────────────

const MAX_PACKET: usize = 65535;
/// 会话超时（WG 规范 180s；到期后仅拒绝新数据，等待客户端重握手轮换密钥）
const SESSION_TIMEOUT: Duration = Duration::from_secs(180);
/// 接收重放窗口（简化为 64 位滑动窗口；WG 规范为 2048 位，足以拒绝常规重放）
const REPLAY_WINDOW: u64 = 64;

const TCP_RX_BUF: usize = 128 * 1024;
const TCP_TX_BUF: usize = 128 * 1024;
const UDP_QUEUE: usize = 64;
const UDP_BUF: usize = 64 * 1024;
/// actor 写路径 pending 上限（smoltcp 发送缓冲之外的最大排队量）
const TX_PENDING_CAP: usize = 512 * 1024;
/// actor 读路径 pending 上限（超限时数据留在 smoltcp 接收缓冲以收窄 TCP 窗口）
const READ_PENDING_CAP: usize = 256 * 1024;
/// 流空闲淘汰：TCP 5 分钟，UDP 1 分钟
const TCP_IDLE: Duration = Duration::from_secs(300);
const UDP_IDLE: Duration = Duration::from_secs(60);

// ── 会话与 peer 状态 ──────────────────────────────────────────────────────────

/// 服务端传输会话（一次成功握手的产物）
struct ServerSession {
    /// 本端随机 index（Response 里的 sender_index，客户端 transport 包回填）
    local_idx: u32,
    /// 对端 sender index（transport 包的 receiver_index）
    remote_idx: u32,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    /// 接收重放窗口状态
    recv_counter_max: u64,
    replay_mask: u64,
    established_at: Instant,
}

impl ServerSession {
    fn is_expired(&self) -> bool {
        self.established_at.elapsed() > SESSION_TIMEOUT
    }

    /// 重放检查并更新窗口。返回 false 表示 counter 已见/过旧，应丢弃。
    fn replay_check_and_update(&mut self, counter: u64) -> bool {
        if counter + REPLAY_WINDOW <= self.recv_counter_max {
            return false;
        }
        if counter > self.recv_counter_max {
            let diff = counter - self.recv_counter_max;
            self.replay_mask = if diff >= REPLAY_WINDOW {
                0
            } else {
                self.replay_mask << diff
            };
            self.recv_counter_max = counter;
            self.replay_mask |= 1;
            true
        } else {
            let idx = self.recv_counter_max - counter;
            let bit = 1u64 << idx;
            if self.replay_mask & bit != 0 {
                false
            } else {
                self.replay_mask |= bit;
                true
            }
        }
    }
}

/// 单个 peer 的服务端状态（注册后不可变，可变部分均为 Arc<Mutex<..>>）
struct PeerEntry {
    /// 对端静态公钥（同时作为 HashMap key）
    #[allow(dead_code)]
    public_key: [u8; 32],
    psk: Option<[u8; 32]>,
    /// AllowedIPs：(网络地址, 前缀长度)；为空时视为允许全部（宽松模式）
    allowed_ips: Vec<(IpAddr, u8)>,
    /// 本端随机 index（多 peer 时区分 transport 包归属）
    local_idx: u32,
    /// peer 当前外部 UDP 端点（首次 Initiation 时记录）
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    session: Arc<Mutex<Option<ServerSession>>>,
    /// 最近一次 Initiation 的 TAI64N 时间戳（防重放）
    last_timestamp: Arc<Mutex<[u8; 12]>>,
    /// smoltcp 栈 actor 入口
    stack_tx: mpsc::Sender<ActorMsg>,
    /// 栈出站明文 IP 包 → 加密泵
    /// （actor 直接持有同通道的克隆，本字段仅保留 peer 维度的引用）
    #[allow(dead_code)]
    encrypt_tx: mpsc::Sender<Vec<u8>>,
}

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct WireguardInbound {
    config: WireGuardInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl WireguardInbound {
    pub fn new(
        config: WireGuardInboundConfig,
        tcp_tx: mpsc::Sender<InboundTcpStream>,
        udp_tx: mpsc::Sender<InboundUdpPacket>,
    ) -> Self {
        Self {
            config,
            tcp_tx,
            udp_tx,
        }
    }

    pub async fn run(self) -> Result<()> {
        let tag = Arc::new(self.config.tag.clone());

        // ── 服务端密钥 ────────────────────────────────────────────────────────
        let private_bytes = decode_key_base64(&self.config.private_key)
            .context("WireGuard inbound: private_key")?;
        let our_static = StaticSecret::from(private_bytes);
        let our_public = PublicKey::from(&our_static);

        // ── 服务端隧道地址（smoltcp 虚拟接口 IP，如 "10.0.0.1/24"）─────────────
        let server_cidrs: Vec<IpCidr> = self
            .config
            .address
            .iter()
            .filter_map(|s| match parse_ip_cidr(s) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(tag = %tag, cidr = %s, err = %e, "wireguard inbound: invalid address entry, ignored");
                    None
                }
            })
            .collect();
        if server_cidrs.is_empty() {
            warn!(
                tag = %tag,
                "wireguard inbound: address 未配置，smoltcp 接口无隧道地址（可能影响回包源地址）"
            );
        }

        // ── 绑定 UDP ──────────────────────────────────────────────────────────
        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let socket = Arc::new(TokioUdp::bind(bind).await.context("WireGuard inbound: bind UDP")?);
        info!(
            tag = %tag,
            addr = %bind,
            public_key = %hex::encode(our_public.as_bytes()),
            "wireguard inbound listening"
        );

        // ── 构建 peer 表 ──────────────────────────────────────────────────────
        let mut peers: HashMap<[u8; 32], Arc<PeerEntry>> = HashMap::new();
        for (idx, peer_cfg) in self.config.peers.iter().enumerate() {
            let pub_bytes = decode_key_base64(&peer_cfg.public_key)
                .context("WireGuard inbound: peer public_key")?;
            let psk = match &peer_cfg.pre_shared_key {
                Some(s) => Some(
                    decode_key_base64(s).context("WireGuard inbound: pre_shared_key")?,
                ),
                None => None,
            };
            let mut allowed_ips = Vec::new();
            for s in &peer_cfg.allowed_ips {
                match parse_allowed_ip(s) {
                    Ok(v) => allowed_ips.push(v),
                    Err(e) => warn!(tag = %tag, cidr = %s, err = %e, "wireguard inbound: invalid allowed_ips, ignored"),
                }
            }
            if allowed_ips.is_empty() {
                warn!(
                    tag = %tag,
                    "wireguard inbound: peer #{} allowed_ips 为空，按允许全部处理（宽松模式）",
                    idx
                );
            }

            let endpoint: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
            let session: Arc<Mutex<Option<ServerSession>>> = Arc::new(Mutex::new(None));
            let last_timestamp: Arc<Mutex<[u8; 12]>> = Arc::new(Mutex::new([0u8; 12]));

            // per-peer smoltcp 栈 actor 通道 + 加密回传通道
            let (stack_tx, stack_rx) = mpsc::channel::<ActorMsg>(2048);
            let (encrypt_tx, encrypt_rx) = mpsc::channel::<Vec<u8>>(1024);

            // 定时器：每 100ms 驱动一次 smoltcp（重传/保活/窗口探测）
            tokio::spawn({
                let fwd = stack_tx.clone();
                async move {
                    let mut tick = tokio::time::interval(Duration::from_millis(100));
                    loop {
                        tick.tick().await;
                        if fwd.send(ActorMsg::Tick).await.is_err() {
                            break;
                        }
                    }
                }
            });

            // actor 主循环
            tokio::spawn(run_stack_actor(
                server_cidrs.clone(),
                encrypt_tx.clone(),
                stack_tx.clone(),
                stack_rx,
                self.tcp_tx.clone(),
                self.udp_tx.clone(),
                Arc::clone(&tag),
                Arc::clone(&endpoint),
            ));

            // 加密回传泵：栈产生的明文 IP 包 → transport 帧加密 → UDP 发回 peer
            tokio::spawn(run_encrypt_pump(
                Arc::clone(&session),
                Arc::clone(&endpoint),
                Arc::clone(&socket),
                encrypt_rx,
                Arc::clone(&tag),
            ));

            peers.insert(
                pub_bytes,
                Arc::new(PeerEntry {
                    public_key: pub_bytes,
                    psk,
                    allowed_ips,
                    local_idx: idx as u32,
                    endpoint,
                    session,
                    last_timestamp,
                    stack_tx,
                    encrypt_tx,
                }),
            );

            info!(
                tag = %tag,
                peer = idx,
                allowed_ips = ?peer_cfg.allowed_ips,
                "wireguard inbound: peer registered"
            );
        }

        // ── 主接收循环 ────────────────────────────────────────────────────────
        let mut recv_buf = vec![0u8; MAX_PACKET];
        loop {
            let (n, src) = match socket.recv_from(&mut recv_buf).await {
                Ok(v) => v,
                Err(e) => {
                    debug!(tag = %tag, err = %e, "wireguard inbound: recv error");
                    continue;
                }
            };
            let raw = &recv_buf[..n];
            if raw.len() < 4 {
                continue;
            }
            let msg_type = u32::from_le_bytes(raw[0..4].try_into().unwrap());

            match msg_type {
                MSG_INITIATION => {
                    handle_initiation(
                        raw,
                        src,
                        &peers,
                        &our_static,
                        &our_public,
                        &socket,
                        &tag,
                    )
                    .await;
                }
                MSG_DATA => {
                    handle_transport(raw, src, &peers, &tag).await;
                }
                _ => {
                    // Response(2)/CookieReply(3) 不应出现在服务端视角，忽略
                    debug!(tag = %tag, msg_type, from = %src, "wireguard inbound: unexpected message type");
                }
            }
        }
    }
}

// ── 握手处理 ─────────────────────────────────────────────────────────────────

/// 处理握手 Initiation：解析 → 查 peer → 时间戳防重放 → 构建并回发 Response。
async fn handle_initiation(
    raw: &[u8],
    src: SocketAddr,
    peers: &HashMap<[u8; 32], Arc<PeerEntry>>,
    our_static: &StaticSecret,
    our_public: &PublicKey,
    socket: &TokioUdp,
    tag: &Arc<String>,
) {
    // 解析 Noise 状态（只依赖本端私钥；失败多为非法/伪造包，静默丢弃）
    let init = match parse_initiation(raw, our_static, our_public) {
        Ok(v) => v,
        Err(e) => {
            debug!(tag = %tag, from = %src, err = %e, "wireguard inbound: initiation rejected");
            return;
        }
    };

    // 按发起方静态公钥查 peer 表
    let Some(peer) = peers.get(&init.initiator_static) else {
        debug!(tag = %tag, from = %src, "wireguard inbound: initiation from unknown peer");
        return;
    };

    // 时间戳防重放：TAI64N 定宽大端编码，逐字节比较即可
    {
        let mut last = peer.last_timestamp.lock().await;
        if init.timestamp <= *last {
            debug!(tag = %tag, from = %src, "wireguard inbound: stale initiation timestamp (replay?)");
            return;
        }
        *last = init.timestamp;
    }

    // 混入 PSK、构建 Response 并派生传输密钥（响应方：send = k2, recv = k1）
    let (resp_msg, send_key, recv_key) =
        match build_response(&init, peer.psk, our_static, our_public, peer.local_idx) {
            Ok(v) => v,
            Err(e) => {
                warn!(tag = %tag, from = %src, err = %e, "wireguard inbound: build_response failed");
                return;
            }
        };

    // 会话轮换：新 Initiation 直接替换旧会话（对端负责重握手）
    *peer.session.lock().await = Some(ServerSession {
        local_idx: peer.local_idx,
        remote_idx: init.sender_idx,
        send_key,
        recv_key,
        send_counter: 0,
        recv_counter_max: 0,
        replay_mask: 0,
        established_at: Instant::now(),
    });
    *peer.endpoint.lock().await = Some(src);

    let _ = socket.send_to(&resp_msg, src).await;
    info!(tag = %tag, from = %src, peer_idx = peer.local_idx, "wireguard inbound: handshake completed");
}

// ── 传输数据处理 ─────────────────────────────────────────────────────────────

/// 处理 transport 数据包：按 receiver_index 查会话 → 重放检查 → 解密 →
/// 校验/AllowedIPs → 投递给 per-peer smoltcp 栈。
async fn handle_transport(
    raw: &[u8],
    src: SocketAddr,
    peers: &HashMap<[u8; 32], Arc<PeerEntry>>,
    tag: &Arc<String>,
) {
    let Some((receiver_idx, counter, ciphertext)) = parse_transport_packet(raw) else {
        return;
    };

    // 按 local_idx 查 peer（peer 数量小，线性扫描足够）
    let mut found: Option<Arc<PeerEntry>> = None;
    for peer in peers.values() {
        let guard = peer.session.lock().await;
        if let Some(s) = guard.as_ref() {
            if s.local_idx == receiver_idx {
                found = Some(Arc::clone(peer));
                break;
            }
        }
    }
    let Some(peer) = found else {
        debug!(tag = %tag, from = %src, idx = receiver_idx, "wireguard inbound: transport for unknown session");
        return;
    };

    // 更新外部端点（NAT 重绑定跟随）
    *peer.endpoint.lock().await = Some(src);

    let mut session_guard = peer.session.lock().await;
    let Some(session) = session_guard.as_mut() else {
        return;
    };
    if session.is_expired() {
        debug!(tag = %tag, from = %src, "wireguard inbound: session expired, awaiting rehandshake");
        return;
    }
    if !session.replay_check_and_update(counter) {
        debug!(tag = %tag, from = %src, counter, "wireguard inbound: replayed counter, dropping");
        return;
    }
    let plain = match decrypt_transport(&session.recv_key, counter, ciphertext) {
        Ok(v) => v,
        Err(e) => {
            debug!(tag = %tag, from = %src, err = %e, "wireguard inbound: transport decrypt failed");
            return;
        }
    };
    // 释放会话锁后再做栈处理
    drop(session_guard);

    // 空载荷 = keepalive
    if plain.is_empty() {
        return;
    }

    // IP 包长度校验/截断（对齐 sing-box receive.go）
    let mut ip_pkt = plain;
    if !validate_and_truncate_ip_packet(&mut ip_pkt) {
        debug!(tag = %tag, from = %src, "wireguard inbound: invalid IP packet, dropping");
        return;
    }

    // AllowedIPs 检查：内层源 IP 必须落在该 peer 的 allowed_ips 内
    let inner_src = packet_src_ip(&ip_pkt);
    if !allowed(&peer.allowed_ips, inner_src) {
        debug!(tag = %tag, from = %src, inner_src = %inner_src, "wireguard inbound: inner src not in allowed_ips, dropping");
        return;
    }

    let _ = peer.stack_tx.send(ActorMsg::Inbound(ip_pkt)).await;
}

/// AllowedIPs 匹配；空表按宽松模式放行（与 run() 注册时的告警一致）
fn allowed(allowed_ips: &[(IpAddr, u8)], ip: IpAddr) -> bool {
    if allowed_ips.is_empty() {
        return true;
    }
    allowed_ips
        .iter()
        .any(|(net, prefix)| ip_in_cidr(ip, *net, *prefix))
}

fn ip_in_cidr(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let p = prefix.min(32);
            let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let p = prefix.min(128);
            let ao = u128::from_be_bytes(a.octets());
            let bo = u128::from_be_bytes(b.octets());
            let mask = if p == 0 { 0 } else { u128::MAX << (128 - p) };
            (ao & mask) == (bo & mask)
        }
        _ => false,
    }
}

/// 解析 allowed_ips 条目："10.0.0.0/24" 或裸 IP "10.0.0.2"
fn parse_allowed_ip(s: &str) -> Result<(IpAddr, u8)> {
    let (ip_str, prefix) = match s.rsplit_once('/') {
        Some((ip, p)) => (
            ip,
            p.parse::<u8>().map_err(|_| anyhow!("invalid prefix in '{s}'"))?,
        ),
        None => (s, 0),
    };
    let ip: IpAddr = ip_str.parse().map_err(|_| anyhow!("invalid IP in '{s}'"))?;
    let prefix = if prefix == 0 && !s.contains('/') {
        match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    } else {
        prefix
    };
    Ok((ip, prefix))
}

/// 解析 CIDR 字符串为 smoltcp IpCidr
fn parse_ip_cidr(s: &str) -> Result<IpCidr> {
    let (ip_str, plen) = s
        .rsplit_once('/')
        .ok_or_else(|| anyhow!("invalid CIDR: {s}"))?;
    let plen: u8 = plen.parse()?;
    let ip: IpAddr = ip_str.parse()?;
    Ok(match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(o[0], o[1], o[2], o[3]), plen))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpCidr::Ipv6(Ipv6Cidr::new(
                Ipv6Address::new(s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]),
                plen,
            ))
        }
    })
}

// ── per-peer smoltcp 栈 actor ────────────────────────────────────────────────

/// actor 统一消息
enum ActorMsg {
    /// 解密后的入站明文 IP 包
    Inbound(Vec<u8>),
    /// WgTcpStream 关闭/丢弃 → 发送缓冲排空后 close() 发 FIN
    TcpClose { handle: SocketHandle },
    /// UDP 出站回包 → 注入 smoltcp UDP 发送缓冲
    UdpReply { handle: SocketHandle, data: Vec<u8> },
    /// 定时器：驱动 smoltcp 定时器、重试排空
    Tick,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    src: SocketAddr,
    dst: SocketAddr,
}

struct TcpFlow {
    handle: SocketHandle,
    /// smoltcp recv buf → WgTcpStream 读端（drop 即下游 EOF）
    read_tx: Option<mpsc::Sender<Vec<u8>>>,
    read_pending: VecDeque<Vec<u8>>,
    /// WgTcpStream 写端 → actor（背压由有界通道 + tx_pending 承载）
    write_rx: Option<mpsc::Receiver<Vec<u8>>>,
    tx_pending: VecDeque<Vec<u8>>,
    /// 写端背压唤醒器（actor 推进后唤醒 poll_write 重试）
    write_waker: Arc<AtomicWaker>,
    relay_started: bool,
    /// 下游已请求关闭：发送缓冲排空后 close() 触发 FIN
    close_requested: bool,
    last_active: Instant,
}

struct UdpFlow {
    handle: SocketHandle,
    /// dispatcher 回包通道 → actor UdpReply → smoltcp
    reply_tx: mpsc::Sender<(Bytes, SocketAddr, SocketAddr)>,
    last_active: Instant,
}

/// per-peer smoltcp 栈 actor 主循环（含 100ms Tick 由 run() 单独 spawn）。
#[allow(clippy::too_many_arguments)]
async fn run_stack_actor(
    server_cidrs: Vec<IpCidr>,
    encrypt_tx: mpsc::Sender<Vec<u8>>,
    actor_tx: mpsc::Sender<ActorMsg>,
    mut actor_rx: mpsc::Receiver<ActorMsg>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
) {
    let mut iface = VirtualIface::new(&server_cidrs);
    let mut tcp_flows: HashMap<FlowKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<FlowKey, UdpFlow> = HashMap::new();

    while let Some(msg) = actor_rx.recv().await {
        match msg {
            ActorMsg::Inbound(pkt) => {
                // 1. 解析流 key，按需建 smoltcp socket
                if let Some(key) = parse_flow_key(&pkt) {
                    match key.proto {
                        6 => ensure_tcp(&mut iface, &mut tcp_flows, &key),
                        17 => ensure_udp(&mut iface, &mut udp_flows, &key, &actor_tx),
                        _ => {}
                    }
                }

                // 2. 注入 smoltcp 并收集出站包
                let out = iface.inject_and_poll(pkt);
                flush_encrypt(&encrypt_tx, out).await;

                // 3. TCP/UDP 流处理（中继启动、排空、EOF、回收）
                process_tcp_flows(
                    &mut iface,
                    &mut tcp_flows,
                    &actor_tx,
                    &tcp_tx,
                    &tag,
                    &endpoint,
                )
                .await;
                process_udp_flows(&mut iface, &mut udp_flows, &udp_tx, &tag).await;
            }

            ActorMsg::TcpClose { handle } => {
                if let Some(flow) = tcp_flows.values_mut().find(|f| f.handle == handle) {
                    flow.close_requested = true;
                }
                process_tcp_flows(
                    &mut iface,
                    &mut tcp_flows,
                    &actor_tx,
                    &tcp_tx,
                    &tag,
                    &endpoint,
                )
                .await;
            }

            ActorMsg::UdpReply { handle, data } => {
                // 找 peer 的隧道内源端点作为 smoltcp UDP 发送目标；
                // 源地址由 socket 绑定端点（内层目的地址）决定，自动还原
                let peer_ep = udp_flows
                    .iter()
                    .find(|(_, f)| f.handle == handle)
                    .map(|(k, _)| k.src);
                if let Some(peer_ep) = peer_ep {
                    feed_udp_send(&mut iface, handle, peer_ep, &data);
                    let out = iface.poll_and_collect_tx();
                    flush_encrypt(&encrypt_tx, out).await;
                }
            }

            ActorMsg::Tick => {
                let out = iface.poll_and_collect_tx();
                flush_encrypt(&encrypt_tx, out).await;
                process_tcp_flows(
                    &mut iface,
                    &mut tcp_flows,
                    &actor_tx,
                    &tcp_tx,
                    &tag,
                    &endpoint,
                )
                .await;
                process_udp_flows(&mut iface, &mut udp_flows, &udp_tx, &tag).await;
                evict_flows(&mut iface, &mut tcp_flows, &mut udp_flows);
            }
        }
    }
}

/// TCP 流处理：写端排空/注入、中继启动、读端排空、EOF、关闭与回收。
async fn process_tcp_flows(
    iface: &mut VirtualIface,
    tcp_flows: &mut HashMap<FlowKey, TcpFlow>,
    actor_tx: &mpsc::Sender<ActorMsg>,
    tcp_tx: &mpsc::Sender<InboundTcpStream>,
    tag: &Arc<String>,
    endpoint: &Arc<Mutex<Option<SocketAddr>>>,
) {
    let now = Instant::now();

    for (key, flow) in tcp_flows.iter_mut() {
        // ── 写路径：write_rx → tx_pending（限制总量形成背压）──────────────────
        let mut pending_bytes: usize = flow.tx_pending.iter().map(|v| v.len()).sum();
        if let Some(rx) = flow.write_rx.as_mut() {
            while pending_bytes < TX_PENDING_CAP {
                match rx.try_recv() {
                    Ok(d) => {
                        pending_bytes += d.len();
                        flow.tx_pending.push_back(d);
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        flow.write_rx = None;
                        break;
                    }
                }
            }
        }

        // ── 写路径：tx_pending → smoltcp 发送缓冲（部分写入，余量下次推进）────
        let mut fed = false;
        while let Some(front) = flow.tx_pending.front_mut() {
            let sock = iface.sockets.get_mut::<TcpSocket>(flow.handle);
            if !sock.may_send() {
                break;
            }
            match sock.send_slice(front) {
                Ok(n) => {
                    fed = true;
                    flow.last_active = now;
                    if n == front.len() {
                        flow.tx_pending.pop_front();
                    } else {
                        // 发送缓冲已满，保留剩余部分等待窗口打开
                        front.drain(..n);
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if fed {
            // 写端此前因通道满而 Pending，推进后唤醒重试
            flow.write_waker.wake();
        }

        // ── 关闭请求：发送缓冲排空后 close() 触发 FIN ─────────────────────────
        if flow.close_requested && flow.tx_pending.is_empty() {
            let sock = iface.sockets.get_mut::<TcpSocket>(flow.handle);
            if sock.may_send() {
                sock.close();
                flow.close_requested = false;
            }
        }

        // ── 读路径：read_pending → read_tx（下游通道）─────────────────────────
        if let Some(read_tx) = flow.read_tx.clone() {
            while let Some(front) = flow.read_pending.front() {
                match read_tx.try_send(front.clone()) {
                    Ok(()) => {
                        flow.read_pending.pop_front();
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => break,
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        flow.read_tx = None;
                        break;
                    }
                }
            }
        }

        // ── 读路径：smoltcp recv → read_pending（超限时留在内核窗口内）────────
        // 无读端（中继未建立/已 EOF）时不排空，让 smoltcp 窗口自然收窄
        let mut queued: usize = flow.read_pending.iter().map(|v| v.len()).sum();
        loop {
            if flow.read_tx.is_none() {
                break;
            }
            let sock = iface.sockets.get_mut::<TcpSocket>(flow.handle);
            if !sock.may_recv() {
                break;
            }
            let queue_len = sock.recv_queue();
            if queue_len == 0 || queued >= READ_PENDING_CAP {
                break;
            }
            let mut buf = vec![0u8; queue_len.min(16 * 1024)];
            match sock.recv_slice(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.truncate(n);
                    queued += n;
                    flow.read_pending.push_back(buf);
                    flow.last_active = now;
                }
            }
        }

        // ── EOF：对端 FIN 且缓冲已排空 → 关闭读端（下游读到 0）────────────────
        if flow.read_tx.is_some() {
            let sock = iface.sockets.get::<TcpSocket>(flow.handle);
            if !sock.may_recv() && flow.read_pending.is_empty() {
                flow.read_tx = None;
            }
        }

        // ── 中继启动：Established → 交付 InboundTcpStream ─────────────────────
        if !flow.relay_started {
            let established = {
                let sock = iface.sockets.get::<TcpSocket>(flow.handle);
                sock.state() == TcpState::Established
            };
            if established {
                flow.relay_started = true;
                let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(256);
                let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(256);
                flow.read_tx = Some(read_tx);
                flow.write_rx = Some(write_rx);

                // peer = 客户端 UDP 外部源地址（路由/统计用）
                let outer = *endpoint.lock().await;
                let peer_addr =
                    outer.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

                let stream = WgTcpStream {
                    handle: flow.handle,
                    actor_tx: actor_tx.clone(),
                    read_rx,
                    read_buf: bytes::BytesMut::new(),
                    write_tx,
                    write_pending: VecDeque::new(),
                    write_waker: Arc::clone(&flow.write_waker),
                    closed: false,
                };
                let inner: Box<dyn AsyncReadWrite> = Box::new(stream);
                let sniffed = SniffedStream::from_encrypted(inner, peer_addr, None);
                let _ = tcp_tx
                    .send(InboundTcpStream {
                        stream: sniffed,
                        target: Target::Socket(key.dst),
                        inbound_tag: tag.as_ref().clone(),
                        sniffed_protocol: None,
                        sniffed_domain: None,
                    })
                    .await;
                debug!(tag = %tag, dst = %key.dst, "wireguard inbound: TCP flow established");
            }
        }
    }

    // ── 回收：完全关闭（FIN 完成）的流 ────────────────────────────────────────
    tcp_flows.retain(|_, f| {
        let closed = iface.sockets.get::<TcpSocket>(f.handle).state() == TcpState::Closed;
        if closed {
            iface.sockets.remove(f.handle);
            f.write_waker.wake();
        }
        !closed
    });
}

/// UDP 流处理：排空 smoltcp 接收缓冲，逐 datagram 交付 InboundUdpPacket。
async fn process_udp_flows(
    iface: &mut VirtualIface,
    udp_flows: &mut HashMap<FlowKey, UdpFlow>,
    udp_tx: &mpsc::Sender<InboundUdpPacket>,
    tag: &Arc<String>,
) {
    let now = Instant::now();
    for (key, flow) in udp_flows.iter_mut() {
        let sock = iface.sockets.get_mut::<UdpSmolSocket>(flow.handle);
        while sock.can_recv() {
            let payload = match sock.recv() {
                Ok((data, _meta)) => Bytes::copy_from_slice(data),
                Err(_) => break,
            };
            flow.last_active = now;
            let packet = InboundUdpPacket {
                data: payload,
                src: key.src,
                target: Target::Socket(key.dst),
                inbound_tag: tag.as_ref().clone(),
                sniffed_protocol: None,
                sniffed_domain: None,
                origin_destination: None,
                upstream_rx: None,
                session: UdpSession {
                    reply_tx: flow.reply_tx.clone(),
                },
                lifetime_guards: vec![],
            };
            if udp_tx.send(packet).await.is_err() {
                break;
            }
        }
    }
}

/// 新建 smoltcp TCP socket 并注册流状态（Established 后再建中继通道）
fn ensure_tcp(iface: &mut VirtualIface, tcp_flows: &mut HashMap<FlowKey, TcpFlow>, key: &FlowKey) {
    if tcp_flows.contains_key(key) {
        return;
    }

    let rx = SocketBuffer::new(vec![0u8; TCP_RX_BUF]);
    let tx = SocketBuffer::new(vec![0u8; TCP_TX_BUF]);
    let mut sock = TcpSocket::new(rx, tx);
    sock.set_nagle_enabled(false);
    sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));

    // 监听内层目的端点：SYN-ACK 的源地址即该端点（对内层目标透明）
    let ep = IpListenEndpoint {
        addr: Some(ip_to_smoltcp(key.dst.ip())),
        port: key.dst.port(),
    };
    if sock.listen(ep).is_err() {
        debug!(dst = %key.dst, "wireguard inbound: TCP listen failed");
        return;
    }

    let handle = iface.sockets.add(sock);
    tcp_flows.insert(
        key.clone(),
        TcpFlow {
            handle,
            read_tx: None,
            read_pending: VecDeque::new(),
            write_rx: None,
            tx_pending: VecDeque::new(),
            write_waker: Arc::new(AtomicWaker::new()),
            relay_started: false,
            close_requested: false,
            last_active: Instant::now(),
        },
    );
}

/// 新建 smoltcp UDP socket 并启动回包泵
fn ensure_udp(
    iface: &mut VirtualIface,
    udp_flows: &mut HashMap<FlowKey, UdpFlow>,
    key: &FlowKey,
    actor_tx: &mpsc::Sender<ActorMsg>,
) {
    if udp_flows.contains_key(key) {
        return;
    }

    let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; UDP_QUEUE], vec![0u8; UDP_BUF]);
    let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; UDP_QUEUE], vec![0u8; UDP_BUF]);
    let mut sock = UdpSmolSocket::new(rx, tx);
    let ep = IpListenEndpoint {
        addr: Some(ip_to_smoltcp(key.dst.ip())),
        port: key.dst.port(),
    };
    if sock.bind(ep).is_err() {
        debug!(dst = %key.dst, "wireguard inbound: UDP bind failed");
        return;
    }

    let handle = iface.sockets.add(sock);

    // 回包泵：dispatcher 回包（reply_tx）→ actor UdpReply → smoltcp
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
    tokio::spawn({
        let actor_tx = actor_tx.clone();
        async move {
            while let Some((data, _client, _spoofed)) = reply_rx.recv().await {
                let msg = ActorMsg::UdpReply {
                    handle,
                    data: data.to_vec(),
                };
                if actor_tx.send(msg).await.is_err() {
                    break;
                }
            }
        }
    });

    udp_flows.insert(
        key.clone(),
        UdpFlow {
            handle,
            reply_tx,
            last_active: Instant::now(),
        },
    );
}

/// 将回包注入 smoltcp UDP 发送缓冲（目标为 peer 的隧道内源端点）
fn feed_udp_send(iface: &mut VirtualIface, handle: SocketHandle, peer_ep: SocketAddr, data: &[u8]) {
    let sock = iface.sockets.get_mut::<UdpSmolSocket>(handle);
    let meta = UdpMetadata {
        endpoint: sock_to_smoltcp(peer_ep),
        local_address: None,
        meta: Default::default(),
    };
    if let Err(e) = sock.send_slice(data, meta) {
        debug!(err = ?e, "wireguard inbound: UDP send_slice failed");
    }
}

/// 流空闲淘汰
fn evict_flows(
    iface: &mut VirtualIface,
    tcp_flows: &mut HashMap<FlowKey, TcpFlow>,
    udp_flows: &mut HashMap<FlowKey, UdpFlow>,
) {
    let now = Instant::now();
    tcp_flows.retain(|_, f| {
        let keep = now.duration_since(f.last_active) < TCP_IDLE;
        if !keep {
            iface.sockets.remove(f.handle);
            f.write_waker.wake();
        }
        keep
    });
    udp_flows.retain(|_, f| {
        let keep = now.duration_since(f.last_active) < UDP_IDLE;
        if !keep {
            iface.sockets.remove(f.handle);
        }
        keep
    });
}

/// 加密回传泵：栈出站明文 IP 包 → transport 帧 → UDP 发回 peer
async fn run_encrypt_pump(
    session: Arc<Mutex<Option<ServerSession>>>,
    endpoint: Arc<Mutex<Option<SocketAddr>>>,
    socket: Arc<TokioUdp>,
    mut enc_rx: mpsc::Receiver<Vec<u8>>,
    tag: Arc<String>,
) {
    while let Some(ip) = enc_rx.recv().await {
        let ep = *endpoint.lock().await;
        let Some(ep) = ep else { continue };
        let mut guard = session.lock().await;
        let Some(s) = guard.as_mut() else { continue };
        let counter = s.send_counter;
        s.send_counter += 1;
        let pkt = build_transport_packet(s.remote_idx, counter, &s.send_key, &ip);
        drop(guard);
        if let Err(e) = socket.send_to(&pkt, ep).await {
            debug!(tag = %tag, err = %e, "wireguard inbound: encrypt pump send failed");
        }
    }
}

/// 栈出站包批量加密回传
async fn flush_encrypt(enc_tx: &mpsc::Sender<Vec<u8>>, pkts: Vec<Vec<u8>>) {
    for pkt in pkts {
        let _ = enc_tx.send(pkt).await;
    }
}

// ── 流 key / 地址解析工具 ─────────────────────────────────────────────────────

fn parse_flow_key(pkt: &[u8]) -> Option<FlowKey> {
    match pkt.first().map(|b| b >> 4)? {
        4 => parse_ipv4_flow(pkt),
        6 => parse_ipv6_flow(pkt),
        _ => None,
    }
}

fn parse_ipv4_flow(pkt: &[u8]) -> Option<FlowKey> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let proto = pkt[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let t = pkt.get(ihl..ihl + 4)?;
    Some(FlowKey {
        proto,
        src: SocketAddr::new(IpAddr::V4(src_ip), u16::from_be_bytes([t[0], t[1]])),
        dst: SocketAddr::new(IpAddr::V4(dst_ip), u16::from_be_bytes([t[2], t[3]])),
    })
}

fn parse_ipv6_flow(pkt: &[u8]) -> Option<FlowKey> {
    if pkt.len() < 44 {
        return None;
    }
    let proto = pkt[6];
    if proto != 6 && proto != 17 {
        return None;
    }
    let src_ip = ipv6_from_slice(&pkt[8..24]);
    let dst_ip = ipv6_from_slice(&pkt[24..40]);
    let t = pkt.get(40..44)?;
    Some(FlowKey {
        proto,
        src: SocketAddr::new(IpAddr::V6(src_ip), u16::from_be_bytes([t[0], t[1]])),
        dst: SocketAddr::new(IpAddr::V6(dst_ip), u16::from_be_bytes([t[2], t[3]])),
    })
}

fn ipv6_from_slice(b: &[u8]) -> Ipv6Addr {
    let mut a = [0u16; 8];
    for i in 0..8 {
        a[i] = u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]);
    }
    Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
}

fn ip_to_smoltcp(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddress::Ipv4(Ipv4Address::new(o[0], o[1], o[2], o[3]))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddress::Ipv6(Ipv6Address::new(
                s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
            ))
        }
    }
}

fn sock_to_smoltcp(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint {
        addr: ip_to_smoltcp(addr.ip()),
        port: addr.port(),
    }
}

// ── smoltcp 虚拟网卡/接口（Medium::Ip，参考 flux wireguard/iface.rs）─────────

/// 零拷贝"假网卡"：inject() 注入接收队列，poll() 消费并经 TxToken 写发送队列。
struct VirtualDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }

    /// 将明文 IP 包注入接收队列（供 smoltcp 消费）
    fn inject(&mut self, pkt: Vec<u8>) {
        self.rx.push_back(pkt);
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtRx
    where
        Self: 'a;
    type TxToken<'a>
        = VirtTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(VirtRx, VirtTx<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((VirtRx(pkt), VirtTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<VirtTx<'_>> {
        Some(VirtTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1420; // WireGuard 默认 MTU
        caps
    }
}

struct VirtRx(Vec<u8>);

impl RxToken for VirtRx {
    // smoltcp 0.13：consume 接收 FnOnce(&[u8])
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct VirtTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl TxToken for VirtTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

/// smoltcp Interface + SocketSet 封装
struct VirtualIface {
    device: VirtualDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
}

impl VirtualIface {
    fn new(local_addrs: &[IpCidr]) -> Self {
        let mut device = VirtualDevice::new();

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        iface.update_ip_addrs(|addrs| {
            for cidr in local_addrs {
                let _ = addrs.push(*cidr);
            }
        });

        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::UNSPECIFIED)
            .ok();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::UNSPECIFIED)
            .ok();

        let sockets = SocketSet::new(vec![]);

        Self {
            device,
            iface,
            sockets,
        }
    }

    /// 注入一个明文 IP 包并驱动 smoltcp poll，返回需要回传的出站包
    fn inject_and_poll(&mut self, pkt: Vec<u8>) -> Vec<Vec<u8>> {
        self.device.inject(pkt);
        self.poll_inner();
        self.device.tx.drain(..).collect()
    }

    /// 驱动 smoltcp 定时器并收集出站包（不注入新包）
    fn poll_and_collect_tx(&mut self) -> Vec<Vec<u8>> {
        self.poll_inner();
        self.device.tx.drain(..).collect()
    }

    fn poll_inner(&mut self) {
        let ts = SmolInstant::now();
        self.iface.poll(ts, &mut self.device, &mut self.sockets);
    }
}

// ── WgTcpStream：smoltcp socket ↔ AsyncRead/AsyncWrite 桥接 ──────────────────

/// 内层 TCP 流适配器，交付给 dispatcher 作为 [`InboundTcpStream`] 的底层流。
///
/// - 读：actor 排空 smoltcp 接收缓冲 → 有界通道 → 本结构的 poll_read。
///   通道关闭（对端 FIN / 流回收）即 EOF。
/// - 写：poll_write → 有界通道 → actor → smoltcp 发送缓冲（部分写入 +
///   tx_pending 承载余量）；通道满时 Pending 并经 [`AtomicWaker`] 等待推进。
/// - 关闭：poll_shutdown / Drop → TcpClose 消息 → 发送缓冲排空后 close() 发 FIN。
struct WgTcpStream {
    handle: SocketHandle,
    actor_tx: mpsc::Sender<ActorMsg>,
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: bytes::BytesMut,
    write_tx: mpsc::Sender<Vec<u8>>,
    write_pending: VecDeque<Vec<u8>>,
    write_waker: Arc<AtomicWaker>,
    closed: bool,
}

impl WgTcpStream {
    /// 尽量把 write_pending 推入 actor 通道；Ok 表示 pending 已空或暂时推不动。
    fn flush_write_pending(&mut self) -> std::io::Result<()> {
        loop {
            let Some(front) = self.write_pending.pop_front() else {
                return Ok(());
            };
            match self.write_tx.try_send(front) {
                Ok(()) => continue,
                Err(mpsc::error::TrySendError::Full(data)) => {
                    self.write_pending.push_front(data);
                    return Ok(());
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "wg inbound: tunnel flow closed",
                    ));
                }
            }
        }
    }
}

impl Drop for WgTcpStream {
    fn drop(&mut self) {
        // 流被丢弃（无论是否显式 shutdown）都通知 actor 关闭 smoltcp socket
        let _ = self
            .actor_tx
            .try_send(ActorMsg::TcpClose { handle: self.handle });
    }
}

impl AsyncRead for WgTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let amt = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf.split_to(amt));
            return Poll::Ready(Ok(()));
        }
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                self.read_buf.extend_from_slice(&data);
                let amt = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf.split_to(amt));
                Poll::Ready(Ok(()))
            }
            // 通道关闭（对端 FIN / 流回收）→ EOF
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WgTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wg inbound: stream closed",
            )));
        }
        self.write_pending.push_back(data.to_vec());
        match self.flush_write_pending() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(()) if self.write_pending.is_empty() => Poll::Ready(Ok(data.len())),
            Ok(()) => {
                // 通道已满：登记唤醒器，actor 推进后重试
                self.write_waker.register(cx.waker());
                Poll::Pending
            }
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.flush_write_pending() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(()) if self.write_pending.is_empty() => Poll::Ready(Ok(())),
            Ok(()) => {
                self.write_waker.register(cx.waker());
                Poll::Pending
            }
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // 尽量排空后请求关闭；smoltcp 会在发送缓冲排空后发 FIN
        match self.flush_write_pending() {
            Err(e) => Poll::Ready(Err(e)),
            Ok(()) => {
                self.closed = true;
                let _ = self
                    .actor_tx
                    .try_send(ActorMsg::TcpClose { handle: self.handle });
                if self.write_pending.is_empty() {
                    Poll::Ready(Ok(()))
                } else {
                    self.write_waker.register(cx.waker());
                    Poll::Pending
                }
            }
        }
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_ips_matching() {
        let rules = vec![
            parse_allowed_ip("10.0.0.0/24").unwrap(),
            parse_allowed_ip("fd00::/8").unwrap(),
        ];
        assert!(allowed(&rules, "10.0.0.99".parse().unwrap()));
        assert!(!allowed(&rules, "10.0.1.99".parse().unwrap()));
        assert!(allowed(&rules, "fd12::1".parse().unwrap()));
        assert!(!allowed(&rules, "fe80::1".parse().unwrap()));
        // 裸 IP 解析为主机前缀
        let (ip, p) = parse_allowed_ip("10.0.0.5").unwrap();
        assert_eq!((ip, p), ("10.0.0.5".parse().unwrap(), 32));
        // 空表宽松放行
        assert!(allowed(&[], "1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn replay_window() {
        let mut s = ServerSession {
            local_idx: 1,
            remote_idx: 2,
            send_key: [0; 32],
            recv_key: [0; 32],
            send_counter: 0,
            recv_counter_max: 0,
            replay_mask: 0,
            established_at: Instant::now(),
        };
        assert!(s.replay_check_and_update(0));
        assert!(!s.replay_check_and_update(0)); // 重放
        assert!(s.replay_check_and_update(5));
        assert!(!s.replay_check_and_update(5)); // 重放
        assert!(s.replay_check_and_update(3)); // 窗口内乱序
        assert!(s.replay_check_and_update(100)); // 跳跃推进
        assert!(!s.replay_check_and_update(36)); // 窗口外过旧（36+64 <= 100）
        assert!(s.replay_check_and_update(37)); // 窗口下沿 → 接受
        assert!(s.replay_check_and_update(50)); // 窗口内过旧未见过 → 接受
    }

    #[test]
    fn flow_key_parsing() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[8, 8, 8, 8]);
        pkt[20..22].copy_from_slice(&5353u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&9999u16.to_be_bytes());
        let key = parse_flow_key(&pkt).unwrap();
        assert_eq!(key.proto, 17);
        assert_eq!(key.src.to_string(), "10.0.0.2:5353");
        assert_eq!(key.dst.to_string(), "8.8.8.8:9999");
    }
}
