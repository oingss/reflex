//! VMess 服务端入站（仅 AEAD 模式，alterId=0；对齐 sing-box
//! `protocol/vmess/inbound.go` 的行为面，配置格式与 sing-box 一致）。
//!
//! ## 握手（对齐 sing-vmess 协议端）
//! ```text
//! [AuthID 16B][EncHeaderLen 2+16B][ConnNonce 8B][EncHeader N+16B]
//! ```
//! AuthID 用各用户 `user_key`（MD5(uuid+盐)）AES-ECB 解密校验匹配用户，
//! 请求头解密后得到 req_key/req_nonce（数据层密钥）、resp_token、option、
//! security、command、目标地址。
//!
//! ## 响应头
//! `[EncRespLen 2+16B][EncRespHeader 4+16B]`，明文 `[resp_token, option, 0, 0]`，
//! 密钥由 SHA256(req_key/req_nonce)[..16] 派生。TCP 路径延迟到首次写时发出
//! （对齐 sing-box：拨号失败客户端直接收到关闭而非成功响应）。
//!
//! ## 数据层
//! AEAD chunk 流：`[len(2B, 可选 Shake128 掩码)][密文+tag]`，计数器 nonce。
//! 客户端→服务端用 req_key/req_nonce；服务端→客户端用 SHA256 派生密钥。
//! 由 [`VmessStream::new_server`] 承载。
//!
//! ## UDP over TCP（cmd=0x02）
//! 请求头目标为魔术地址 `sp.packet-addr.v2fly.arpa` 时为 packetaddr 模式：
//! 每个解密 chunk = 一个 packetaddr 帧（兼容 Xray 的 2B 长度前缀变体，见
//! proxy_common）；否则为 legacy 固定目标模式：每个 chunk = 一个发往请求头
//! 目标的 UDP 包。下行每包一次 `poll_write`（≤15000B 保证单 chunk）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::config::inbound::VmessInboundConfig;
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
use crate::protocol::vmess::{
    build_response_header, parse_server_handshake, user_key, verify_auth_id, VmessStream, CMD_TCP,
    CMD_UDP,
};

/// AuthID 长度（16 字节）
const AUTH_ID_LEN: usize = 16;

/// AuthID 时间戳容忍窗口（sing-vmess 默认 ±2 分钟）
const AUTH_ID_WINDOW_SECS: u64 = 120;

/// UDP 下行单包上限（≤ VmessEncoder MAX_CHUNK=15000，保证一包一 chunk）
const UDP_MAX_DOWNLINK: usize = 15000;

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct VmessInbound {
    config: VmessInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl VmessInbound {
    pub fn new(
        config: VmessInboundConfig,
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

        // uuid → user_key（AuthID 匹配与请求头解密都用它）
        let mut users: HashMap<[u8; 16], String> = HashMap::new();
        for u in &self.config.users {
            let uuid = crate::protocol::vmess::parse_uuid(u.uuid.as_deref().unwrap_or(""))?;
            users
                .entry(user_key(&uuid))
                .or_insert_with(|| u.name.clone().unwrap_or_else(|| "anonymous".into()));
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
            "vmess inbound starting"
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

// ── 连接处理（握手 + 分发）───────────────────────────────────────────────────

async fn handle_conn(
    mut io: Box<dyn AsyncReadWrite>,
    raw_tcp: Option<TcpStream>,
    peer: SocketAddr,
    users: Arc<HashMap<[u8; 16], String>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // ── 阶段一：读取 AuthID 并匹配用户（反探测：失败静默关闭）───────────────
    let mut buf = BytesMut::with_capacity(256);
    read_exact_more(&mut io, &mut buf, AUTH_ID_LEN).await?;
    let auth_id: [u8; 16] = buf[..AUTH_ID_LEN].try_into().unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let matched_key: [u8; 16] = {
        let mut found = None;
        for key in users.keys() {
            if verify_auth_id(&auth_id, key, now, AUTH_ID_WINDOW_SECS).is_ok() {
                found = Some(*key);
                break;
            }
        }
        found.ok_or_else(|| anyhow::anyhow!("vmess: auth id did not match any user"))?
    };

    // ── 阶段二：读取完整握手并解密 ───────────────────────────────────────────
    // parse_server_handshake 对截断报错（"too short"/"truncated"），据此继续读
    let hs = loop {
        match parse_server_handshake(&buf, &matched_key) {
            Ok(hs) => break hs,
            Err(e) => {
                let s = e.to_string();
                anyhow::ensure!(
                    (s.contains("too short") || s.contains("truncated")) && buf.len() < 8192,
                    "vmess: invalid handshake: {e}"
                );
            }
        }
        let need = buf.len() + 128;
        read_exact_more(&mut io, &mut buf, need).await?;
    };
    buf.advance(hs.consumed);
    let remaining = buf.freeze();

    debug!(
        peer = %display_sockaddr(peer),
        target = %hs.target,
        cmd = hs.command,
        tag = %tag,
        "vmess request"
    );

    match hs.command {
        CMD_TCP => {
            // 响应头延迟到首次写（VmessServerRespStream 包装）
            let resp_header =
                build_response_header(&hs.req_key, &hs.req_nonce, hs.resp_token, hs.option)?;
            let vmess = VmessStream::new_server(
                io,
                hs.security,
                hs.option,
                &hs.req_key,
                &hs.req_nonce,
            );
            let inner: Box<dyn AsyncReadWrite> =
                Box::new(VmessServerRespStream::new(Box::new(vmess), resp_header));
            let mut sniffed = SniffedStream::from_encrypted(inner, peer, raw_tcp);
            sniffed.prepend(remaining);

            tcp_tx
                .send(InboundTcpStream {
                    stream: sniffed,
                    target: hs.target,
                    inbound_tag: (*tag).clone(),
                    sniffed_protocol: None,
                    sniffed_domain: None,
                })
                .await
                .ok();
        }
        CMD_UDP => {
            // 响应头立即发出（UDP 无"拨号成功"信号可等）
            let resp_header =
                build_response_header(&hs.req_key, &hs.req_nonce, hs.resp_token, hs.option)?;
            io.write_all(&resp_header).await?;
            io.flush().await?;

            let vmess = VmessStream::new_server(
                io,
                hs.security,
                hs.option,
                &hs.req_key,
                &hs.req_nonce,
            );
            let packetaddr = is_packetaddr_magic(&hs.target);
            run_udp_over_tcp(Box::new(vmess), peer, hs.target, packetaddr, udp_tx, tag).await;
        }
        other => anyhow::bail!("vmess: unsupported command 0x{other:02x}"),
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
        anyhow::ensure!(n > 0, "vmess: client closed during handshake");
        buf.extend_from_slice(&tmp[..n]);
    }
    Ok(())
}

// ── 响应头包装器 ─────────────────────────────────────────────────────────────

/// 首次 `poll_write` 时先写出 VMess AEAD 响应头，之后透传。
/// 对齐 sing-box"连接成功后才回响应头"语义。
struct VmessServerRespStream {
    inner: Box<dyn AsyncReadWrite>,
    pending_header: Option<Bytes>,
}

impl VmessServerRespStream {
    fn new(inner: Box<dyn AsyncReadWrite>, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
        }
    }
}

impl AsyncRead for VmessServerRespStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for VmessServerRespStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if let Some(header) = self.pending_header.take() {
            match Pin::new(&mut self.inner).poll_write(cx, &header) {
                Poll::Ready(Ok(n)) if n == header.len() => {}
                Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(std::io::Error::other(
                        "vmess: failed to write response header",
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

// ── UDP over TCP（packetaddr / legacy）───────────────────────────────────────

async fn run_udp_over_tcp(
    io: Box<dyn AsyncReadWrite>,
    peer: SocketAddr,
    first_target: Target,
    packetaddr: bool,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) {
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);
    let last_target: Arc<Mutex<Option<Target>>> = Arc::new(Mutex::new(None));
    let length_prefixed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let format_seen = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // VmessStream 内部已 split；再对外层 split 一次得到读写两半。
    // 每个 read()（buf 足够大时）恰好返回一个解密 chunk = 一个帧单元。
    let (mut rd, mut wr) = tokio::io::split(io);

    // ── 上行：读 chunk → 解析帧 → 投递 ───────────────────────────────────────
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
                    // legacy 固定目标：整个 chunk 即一个包的 payload
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
                let Some((frame, used_prefix)) = parse_packetaddr_unit(unit) else {
                    debug!(peer = %display_sockaddr(peer), "vmess udp: unparseable chunk, dropping");
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

    // ── 下行：回包 → 分帧 → 一次 write = 一个 chunk ─────────────────────────
    let downlink = {
        let last_target = last_target.clone();
        let length_prefixed = length_prefixed.clone();
        async move {
            while let Some((data, _client, spoofed)) = reply_rx.recv().await {
                let addr = resolve_reply_addr(&last_target.lock().unwrap().clone(), spoofed);
                let Some(addr) = addr else {
                    debug!(peer = %display_sockaddr(peer), "vmess udp reply: no routable address, dropping");
                    continue;
                };
                if data.len() > UDP_MAX_DOWNLINK {
                    debug!(len = data.len(), "vmess udp reply too large, dropping");
                    continue;
                }
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

    tokio::select! {
        _ = uplink => {},
        _ = downlink => {},
    }
    debug!(peer = %display_sockaddr(peer), tag = %tag, "vmess udp session closed");
}
