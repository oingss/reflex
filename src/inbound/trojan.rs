//! Trojan 服务端入站（对齐 sing-box `protocol/trojan/inbound.go` 的行为面，
//! 配置格式与 sing-box 的 trojan inbound 完全一致）。
//!
//! ## 协议（参考 flux-master trojan 服务端实现）
//! 请求头 `[SHA224(password) hex 56B][CRLF][CMD 1B][SOCKS_addr][CRLF]`：
//! - CMD：0x01=TCP，0x03=UDP，0x7f=Mux（拒绝）
//! - 服务端无响应头（TLS 握手成功后直接透传数据）
//!
//! ## UDP over TCP（cmd=0x03）
//! 每帧 `[SOCKS_addr][LEN 2B BE][CRLF][DATA]`，地址在帧内携带（支持域名）。
//!
//! ## 交付模型
//! TCP：解析请求头后把剩余流（含 TLS 解密层）装箱为 [`SniffedStream::from_encrypted`]
//! 交给 dispatcher 路由；UDP：按帧拆包逐包投递 `InboundUdpPacket`
//! （`upstream_rx: None`），回包经 `reply_tx` 用 [`trojan::build_udp_frame`]
//! 写回隧道。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::inbound::TrojanInboundConfig;
use crate::inbound::proxy_common::bind_dual_stack_listener;
use crate::inbound::transport::{InboundConnHandler, InboundStack};
use crate::inbound::{
    display_sockaddr, parse_listen_addr, InboundTcpStream, InboundUdpPacket, SniffedStream, Target,
    UdpSession,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::trojan::{
    build_udp_frame, derive_key, parse_request, CMD_TCP, CMD_UDP, CRLF, KEY_LEN,
};

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct TrojanInbound {
    config: TrojanInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl TrojanInbound {
    pub fn new(
        config: TrojanInboundConfig,
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
        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());

        // 密码 → 派生密钥 hex → 用户名
        let mut users: HashMap<[u8; KEY_LEN], String> = HashMap::new();
        for u in &self.config.users {
            let key = derive_key(u.password.as_deref().unwrap_or(""));
            users
                .entry(key)
                .or_insert_with(|| u.name.clone().unwrap_or_else(|| "anonymous".into()));
        }
        let users = Arc::new(users);

        // 传输栈：TLS/REALITY + 传输层（tcp/ws/grpc/xhttp）
        // （sing-box 要求 trojan inbound 启用 TLS；reality.enabled 时为 REALITY）
        if !self.config.tls.enabled {
            warn!(tag = %tag, "trojan inbound: tls disabled (clients normally expect TLS)");
        }
        let stack = Arc::new(InboundStack::build(
            &self.config.tls,
            self.config.transport.as_ref(),
        )?);

        let listener = bind_dual_stack_listener(bind).await?;
        info!(
            tag = %tag,
            addr = %bind,
            stack = %stack.describe(),
            "trojan inbound starting"
        );

        let tcp_tx = self.tcp_tx;
        let udp_tx = self.udp_tx;

        let handler: InboundConnHandler = {
            let users = users.clone();
            let tcp_tx = tcp_tx.clone();
            let udp_tx = udp_tx.clone();
            let tag = tag.clone();
            Arc::new(move |io, peer, raw_tcp| {
                Box::pin(handle_conn(
                    io,
                    raw_tcp,
                    peer,
                    users.clone(),
                    tcp_tx.clone(),
                    udp_tx.clone(),
                    tag.clone(),
                ))
            })
        };

        crate::inbound::transport::serve_inbound(listener, stack, handler).await
    }
}

// ── 连接处理 ─────────────────────────────────────────────────────────────────

async fn handle_conn(
    mut io: Box<dyn AsyncReadWrite>,
    raw_tcp: Option<TcpStream>,
    peer: SocketAddr,
    users: Arc<HashMap<[u8; KEY_LEN], String>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // 增量读取并解析 Trojan 请求头（截断 → 继续读；CRLF/命令错误 → 认证失败）
    let mut buf = BytesMut::with_capacity(128);
    let req = loop {
        match parse_request(&buf) {
            Ok(r) => break r,
            Err(e) => {
                let s = e.to_string();
                let is_truncation = s.contains("truncated") || s.contains("too short");
                anyhow::ensure!(
                    is_truncation && buf.len() < 1024,
                    "trojan: invalid request header: {e}"
                );
            }
        }
        let need = buf.len() + 64;
        read_exact_more(&mut io, &mut buf, need).await?;
    };

    // 密码认证
    let user_name = users
        .get(&req.key_hex)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("trojan: invalid password"))?;

    debug!(
        peer = %display_sockaddr(peer),
        user = %user_name,
        target = %req.target,
        cmd = req.command,
        tag = %tag,
        "trojan request"
    );

    let remaining = buf.split_off(req.consumed).freeze();

    match req.command {
        CMD_TCP => {
            // Trojan 无响应头：直接透传
            let mut sniffed = SniffedStream::from_encrypted(io, peer, raw_tcp);
            sniffed.prepend(remaining);

            tcp_tx
                .send(InboundTcpStream {
                    stream: sniffed,
                    target: req.target,
                    inbound_tag: (*tag).clone(),
                    sniffed_protocol: None,
                    sniffed_domain: None,
                })
                .await
                .ok();
        }
        CMD_UDP => {
            run_udp_over_tcp(io, peer, udp_tx, tag).await;
        }
        other => anyhow::bail!("trojan: unsupported command 0x{other:02x}"),
    }

    Ok(())
}

/// 从 `io` 读取至少 `min_bytes` 字节追加到 `buf`（阻塞直至达到）。
async fn read_exact_more(
    io: &mut Box<dyn AsyncReadWrite>,
    buf: &mut BytesMut,
    min_bytes: usize,
) -> anyhow::Result<()> {
    while buf.len() < min_bytes {
        let want = min_bytes - buf.len();
        let mut tmp = vec![0u8; want];
        let n = io.read(&mut tmp).await?;
        anyhow::ensure!(n > 0, "trojan: client closed during handshake");
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

// ── UDP over TCP ─────────────────────────────────────────────────────────────

/// 读取一帧 Trojan UDP 帧头：`[SOCKS_addr][LEN 2B BE][CRLF]`，返回 (目标, 长度)。
async fn read_frame_header(rd: &mut (impl AsyncRead + Unpin)) -> anyhow::Result<(Target, usize)> {
    let atyp = rd.read_u8().await?;
    let target = match atyp {
        0x01 => {
            let mut b = [0u8; 6]; // 4B ip + 2B port
            rd.read_exact(&mut b).await?;
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            Target::Socket(SocketAddr::new(ip, u16::from_be_bytes([b[4], b[5]])))
        }
        0x03 => {
            let dlen = rd.read_u8().await? as usize;
            anyhow::ensure!(dlen > 0, "trojan udp: empty domain");
            let mut d = vec![0u8; dlen + 2];
            rd.read_exact(&mut d).await?;
            let domain = String::from_utf8(d[..dlen].to_vec())?;
            Target::Domain(domain, u16::from_be_bytes([d[dlen], d[dlen + 1]]))
        }
        0x04 => {
            let mut b = [0u8; 18]; // 16B ip + 2B port
            rd.read_exact(&mut b).await?;
            let ip: [u8; 16] = b[..16].try_into().unwrap();
            Target::Socket(SocketAddr::new(
                std::net::IpAddr::V6(ip.into()),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        other => anyhow::bail!("trojan udp: unknown atyp 0x{other:02x}"),
    };
    let len = rd.read_u16().await? as usize;
    let mut crlf = [0u8; 2];
    rd.read_exact(&mut crlf).await?;
    anyhow::ensure!(crlf[..] == CRLF[..], "trojan udp: bad CRLF separator");
    Ok((target, len))
}

async fn run_udp_over_tcp(
    io: Box<dyn AsyncReadWrite>,
    peer: SocketAddr,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) {
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
    // 最近一次上行帧的地址（回包分帧地址；Trojan 帧支持域名）
    let last_target: Arc<Mutex<Option<Target>>> = Arc::new(Mutex::new(None));

    let (mut rd, mut wr) = tokio::io::split(io);

    // ── 上行：读帧 → 投递 ────────────────────────────────────────────────────
    let uplink = {
        let udp_tx = udp_tx.clone();
        let tag = tag.clone();
        let last_target = last_target.clone();
        async move {
            loop {
                let (target, len) = match read_frame_header(&mut rd).await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(err = %e, "trojan udp: frame header read end");
                        break;
                    }
                };
                let mut data = vec![0u8; len];
                if rd.read_exact(&mut data).await.is_err() {
                    break;
                }
                *last_target.lock().unwrap() = Some(target.clone());
                let packet = InboundUdpPacket {
                    data: Bytes::from(data),
                    src: peer,
                    target,
                    inbound_tag: (*tag).clone(),
                    session: UdpSession {
                        reply_tx: reply_tx.clone(),
                    },
                    sniffed_protocol: None,
                    sniffed_domain: None,
                    origin_destination: None,
                    upstream_rx: None,
                    lifetime_guards: vec![],
                };
                if udp_tx.send(packet).await.is_err() {
                    break;
                }
            }
        }
    };

    // ── 下行：回包 → 分帧写回 ────────────────────────────────────────────────
    let downlink = {
        let last_target = last_target.clone();
        async move {
            while let Some((data, _client, spoofed)) = reply_rx.recv().await {
                // Trojan 帧支持域名；优先最近上行帧地址，回退伪造源地址
                let target = match last_target.lock().unwrap().clone() {
                    Some(t) => Some(t),
                    None => {
                        if !spoofed.ip().is_unspecified() {
                            Some(Target::Socket(spoofed))
                        } else {
                            None
                        }
                    }
                };
                let Some(target) = target else {
                    debug!(peer = %display_sockaddr(peer), "trojan udp reply: no address, dropping");
                    continue;
                };
                let frame = build_udp_frame(&target, &data);
                if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        }
    };

    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
    }
    debug!(peer = %display_sockaddr(peer), tag = %tag, "trojan udp session closed");
}
