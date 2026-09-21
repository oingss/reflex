//! VLESS 服务端入站（对齐 sing-box `protocol/vless/inbound.go` 的行为面，
//! 配置格式与 sing-box 的 vless inbound 完全一致）。
//!
//! ## 协议（TCP）
//! 请求头 `[Ver 0x00][UUID 16B][AddonLen][Addon][Cmd][Port 2B BE][ATYP+ADDR]`，
//! 响应头 `[Ver 0x00][AddonLen 0x00]`。响应头延迟到首次向客户端写数据时发出
//! （对齐 sing-box：拨号失败时客户端直接收到 RST/关闭，而非先收到成功响应）。
//!
//! ## UDP over TCP（cmd=0x02，packetaddr 分帧）
//! 请求头目标地址为魔术地址 `sp.packet-addr.v2fly.arpa` 时进入 packetaddr 模式。
//! 每个 UDP 包 = 一个帧，兼容两种帧格式（自动检测，按首个上行帧记忆回包格式）：
//! - sing/reflex 风格：`[ATYP][ADDR][PORT][DATA]`（无长度前缀，帧边界由一次写入提供）
//! - Xray/flux 风格：`[LEN 2B BE][ATYP][ADDR][PORT][DATA]`（帧首字节 0x00 触发）
//!
//! packetaddr ATYP 与请求头 ATYP 不同：0x01=IPv4，0x02=IPv6，不支持域名
//! （对齐 sing-vmess packetaddr.AddressSerializer）。
//!
//! ## 交付模型
//! TCP：解析请求头后把剩余流（含 TLS 解密层）装箱为 [`SniffedStream::from_encrypted`]
//! 交给 dispatcher 路由；UDP：按帧拆包后逐包发送 `InboundUdpPacket`
//! （`upstream_rx: None`，dispatcher 自建会话通道），回包经 `reply_tx` 写回隧道。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::config::inbound::VlessInboundConfig;
use crate::inbound::proxy_common::{
    bind_dual_stack_listener, encode_packetaddr_frame, is_packetaddr_magic,
    parse_packetaddr_unit, resolve_reply_addr,
};
use crate::inbound::transport::{InboundConnHandler, InboundStack};
use crate::inbound::{
    display_sockaddr, parse_listen_addr, InboundTcpStream, InboundUdpPacket, SniffedStream, Target,
    UdpSession,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::vless::{parse_request, parse_uuid, ParsedRequest};

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct VlessInbound {
    config: VlessInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl VlessInbound {
    pub fn new(
        config: VlessInboundConfig,
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

        // uuid → (name) 用户表
        let mut users: HashMap<[u8; 16], String> = HashMap::new();
        for u in &self.config.users {
            let uuid = parse_uuid(u.uuid.as_deref().unwrap_or(""))?;
            users.entry(uuid).or_insert_with(|| {
                u.name.clone().unwrap_or_else(|| "anonymous".to_string())
            });
        }
        let users = Arc::new(users);

        // 传输栈：TLS/REALITY + 传输层（tcp/ws/grpc/xhttp）
        let stack = Arc::new(InboundStack::build(
            &self.config.tls,
            self.config.transport.as_ref(),
        )?);

        let listener = bind_dual_stack_listener(bind).await?;
        info!(
            tag = %tag,
            addr = %bind,
            stack = %stack.describe(),
            "vless inbound starting"
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
    users: Arc<HashMap<[u8; 16], String>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {

    // 增量读取并解析 VLESS 请求头（截断错误 → 继续读；其余 → 认证失败）
    let mut buf = BytesMut::with_capacity(64);
    let req: ParsedRequest = loop {
        match parse_request(&buf) {
            Ok(r) => break r,
            Err(e) => {
                let is_truncation = {
                    let s = e.to_string();
                    s.contains("truncated") || s.contains("too short")
                };
                anyhow::ensure!(
                    is_truncation && buf.len() < 1024,
                    "vless: invalid request header: {e}"
                );
            }
        }
        let prev = buf.len();
        buf.reserve(64);
        let n = io.read_buf(&mut buf).await?;
        anyhow::ensure!(n > 0, "vless: client closed during header");
        let _ = prev;
    };

    // UUID 认证
    let user_name = users
        .get(&req.uuid)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("vless: unknown user uuid"))?;

    // addon 中若携带 xtls-rprx-vision flow，reflex 服务端不支持直连裸流
    if !req.addon.is_empty() {
        let addon_str = String::from_utf8_lossy(&req.addon);
        if addon_str.contains("xtls-rprx-vision") {
            anyhow::bail!("vless: vision flow not supported on this inbound");
        }
    }

    debug!(
        peer = %display_sockaddr(peer),
        user = %user_name,
        target = %req.target,
        cmd = req.command,
        tag = %tag,
        "vless request"
    );

    let remaining = buf.split_off(req.consumed).freeze();

    match req.command {
        crate::protocol::vless::command::TCP => {
            // 流包装器：首次写时先发 VLESS 响应头（[0x00, 0x00]）
            let inner: Box<dyn AsyncReadWrite> =
                Box::new(VlessServerStream::new(io, Bytes::from_static(&[0x00, 0x00])));
            let mut sniffed = SniffedStream::from_encrypted(inner, peer, raw_tcp);
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
        crate::protocol::vless::command::UDP => {
            // 响应头立即发出（对齐 flux/Xray：UDP 路径在分帧前回响应头）
            io.write_all(&[0x00, 0x00]).await?;
            io.flush().await?;

            // packetaddr 模式：请求头目标是魔术地址；否则按 legacy 固定目标模式
            let packetaddr = is_packetaddr_magic(&req.target);
            run_udp_over_tcp(
                io,
                peer,
                req.target,
                packetaddr,
                udp_tx,
                tag,
            )
            .await;
        }
        other => anyhow::bail!("vless: unsupported command 0x{other:02x}"),
    }

    Ok(())
}

// ── VLESS 服务端响应头包装器 ─────────────────────────────────────────────────

/// 首次 `poll_write` 时先写出 VLESS 响应头，之后透明透传。
/// 对齐 sing-box 服务端"连接成功后才回响应头"的语义。
struct VlessServerStream {
    inner: Box<dyn AsyncReadWrite>,
    pending_header: Option<Bytes>,
}

impl VlessServerStream {
    fn new(inner: Box<dyn AsyncReadWrite>, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
        }
    }
}

impl AsyncRead for VlessServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VlessServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(header) = self.pending_header.take() {
            // 先写响应头（阻塞本次写直至完成，数据转入 pending 语义简化处理：
            // 响应头仅 2 字节，内核缓冲几乎必然可写）
            match Pin::new(&mut self.inner).poll_write(cx, &header) {
                Poll::Ready(Ok(n)) if n == header.len() => {}
                Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(std::io::Error::other(
                        "vless: failed to write response header",
                    )))
                }
                Poll::Pending => {
                    self.pending_header = Some(header);
                    return Poll::Pending;
                }
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── UDP over TCP（packetaddr / legacy 双格式）────────────────────────────────

/// UDP over TCP 会话主循环。
///
/// - `packetaddr=true`：每帧携带目标；`false`：所有包发往固定目标（legacy）。
/// - 上行读到的帧逐包投递 `InboundUdpPacket`（`upstream_rx: None`，dispatcher
///   会自建会话上行通道）；回包经 `reply_tx` 到达，按"最近一次上行目标"
///   （或回包元组携带的伪造源地址）构建下行帧写回隧道。
async fn run_udp_over_tcp(
    io: Box<dyn AsyncReadWrite>,
    peer: SocketAddr,
    first_target: Target,
    packetaddr: bool,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) {
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
    // 最近一次上行包的目标（回包分帧地址；packetaddr 帧只承载 IP，
    // 域名目标时回退到回包元组的伪造源地址）
    let last_target: Arc<Mutex<Option<Target>>> = Arc::new(Mutex::new(None));
    // 下行帧格式跟随客户端上行格式（首帧检测）
    let length_prefixed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let format_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let (mut rd, mut wr) = tokio::io::split(io);

    // ── 上行：读帧 → 投递 ────────────────────────────────────────────────────
    let uplink = {
        let udp_tx = udp_tx.clone();
        let tag = tag.clone();
        let last_target = last_target.clone();
        let length_prefixed = length_prefixed.clone();
        let format_seen = format_seen.clone();
        async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let n = match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let unit = &buf[..n];
                if !packetaddr {
                    // legacy 固定目标：整段读取内容即一个包的 payload
                    let target = first_target.clone();
                    *last_target.lock().unwrap() = Some(target.clone());
                    let packet = InboundUdpPacket {
                        data: Bytes::copy_from_slice(unit),
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
                    continue;
                }
                // packetaddr 模式
                let Some((frame, used_prefix)) = parse_packetaddr_unit(unit) else {
                    debug!(peer = %display_sockaddr(peer), "vless udp: unparseable frame, dropping");
                    continue;
                };
                if !format_seen.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    length_prefixed.store(used_prefix, std::sync::atomic::Ordering::Relaxed);
                }
                *last_target.lock().unwrap() = Some(frame.target.clone());
                let packet = InboundUdpPacket {
                    data: frame.data,
                    src: peer,
                    target: frame.target,
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
        let length_prefixed = length_prefixed.clone();
        async move {
            while let Some((data, _client, spoofed)) = reply_rx.recv().await {
                // 分帧地址：优先最近上行目标（Socket），回退伪造源地址
                let addr = resolve_reply_addr(&last_target.lock().unwrap().clone(), spoofed);
                let Some(addr) = addr else {
                    debug!(peer = %display_sockaddr(peer), "vless udp reply: no routable address, dropping");
                    continue;
                };
                let frame = encode_packetaddr_frame(
                    addr,
                    &data,
                    length_prefixed.load(std::sync::atomic::Ordering::Relaxed),
                );
                if wr.write_all(&frame).await.is_err() || wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        }
    };

    // UDP 会话空闲超时：无回包且上行关闭后自然退出；这里依赖 reply_rx/upstream
    // 生命周期兜底，dispatcher 侧的 udp_timeout 负责主动回收。
    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
    }
    debug!(peer = %display_sockaddr(peer), tag = %tag, "vless udp session closed");
}
