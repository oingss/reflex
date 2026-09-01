//! Shadowsocks（仅 SS2022）服务端入站（对齐 sing-box `protocol/shadowsocks` 入站的
//! 行为面，配置格式与 sing-box 的 shadowsocks inbound 完全一致）。
//!
//! 仅支持 AEAD-2022 方法（`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` /
//! `2022-blake3-chacha20-poly1305`），其余方法在启动时直接报错拒绝。
//!
//! ## 线格式（TCP，SS2022，参考 sing-shadowsocks2 `shadowaead_2022`）
//!
//! 请求（client → server）：
//! ```text
//! [salt: key_len 字节，明文]
//! [AEAD(nonce=0): type=0(1B) + timestamp(8B BE) + variableHeaderLen(2B BE)]  ← 无外层长度前缀
//! [AEAD(nonce=1): SOCKS_addr + paddingLen(2B BE) + padding]                 ← 长度=variableHeaderLen
//! [AEAD(nonce=n): 2B len][AEAD(nonce=n): payload]  …  n=2,3,…（标准分帧）
//! ```
//!
//! 响应（server → client）：
//! ```text
//! [resp_salt: key_len 字节，明文]
//! [AEAD(nonce=0): type=1(1B) + timestamp(8B BE) + requestSalt(key_len) + paddingLen(2B BE)]
//! [AEAD(nonce=1): padding]
//! [标准分帧 n=2,3,…]
//! ```
//!
//! subkey = BLAKE3-KDF(psk, salt)；PSK 为 Base64 解码后的 password。
//!
//! ## 线格式（UDP，原生 UDP 会话，非 UDP-over-TCP）
//!
//! AES 变体：`[AES-ECB(sessionId 8B | packetId 8B)][AEAD(body)+tag]`，
//! nonce = hdr[4..16]，subkey = BLAKE3-KDF(psk, sessionId)。
//! ChaCha20 变体：`[nonce 24B][XChaCha20(sessionId 8B | packetId 8B | body)+tag]`。
//!
//! body（请求）：`[type=0][timestamp 8B][paddingLen 2B][padding][SOCKS_addr][payload]`
//! body（响应）：`[type=1][timestamp 8B][clientSessionId 8B][paddingLen 2B][padding][SOCKS_addr][payload]`
//!
//! ## 交付模型
//! TCP：解析请求头后把解密流装箱为 [`SniffedStream::from_encrypted`]（响应 salt +
//! 响应头在首次写出时惰性发送）交给 dispatcher 路由；
//! UDP：单 socket `recv_from` 循环逐包投递 `InboundUdpPacket`
//! （`upstream_rx: None`），回包经 `reply_tx` 汇入统一 pump，按客户端地址
//! `send_to` 写回（多客户端共用一个监听 socket）。
//!
//! 安全性：TCP 与 UDP 均做时间戳校验（±30s）；TCP 另做 salt 重放窗口缓存
//! （对齐 flux-master / sing-shadowsocks2 服务端行为）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use bytes::Bytes;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::inbound::ShadowsocksInboundConfig;
use crate::inbound::proxy_common::{bind_dual_stack_listener, resolve_reply_addr};
use crate::inbound::transport::{InboundConnHandler, InboundStack};
use crate::inbound::{
    display_sockaddr, parse_listen_addr, InboundTcpStream, InboundUdpPacket, SniffedStream, Target,
    UdpSession,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::shadowsocks::{
    check_ss2022_timestamp, encode_target, now_unix_secs, parse_socks_addr, ss2022_is_aes,
    ss2022_session_key, ss2022_udp_build_server_body, ss2022_udp_open_aes_with_session,
    ss2022_udp_open_chacha_with_session, ss2022_udp_parse_client_body, ss2022_udp_seal_aes,
    ss2022_udp_seal_chacha, AeadCipher, Method, MAX_PAYLOAD, TAG_LEN, SS2022_HEADER_TYPE_CLIENT,
    SS2022_HEADER_TYPE_SERVER, SS2022_TCP_FIXED_HEADER_LEN,
};

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct ShadowsocksInbound {
    config: ShadowsocksInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl ShadowsocksInbound {
    pub fn new(
        config: ShadowsocksInboundConfig,
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
        let tag = Arc::new(self.config.tag.clone());

        // 方法校验：仅 SS2022
        let method = Method::from_str(&self.config.method)?;
        anyhow::ensure!(
            method.is_2022(),
            "shadowsocks inbound '{}': only SS2022 methods are supported \
             (2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm / \
             2022-blake3-chacha20-poly1305), got '{}'",
            tag,
            self.config.method
        );

        // PSK 解析：Base64 密码 → 密钥字节（SS2022 的 password 即密钥，无 KDF）
        let users = self.config.effective_users();
        anyhow::ensure!(
            !users.is_empty(),
            "shadowsocks inbound '{}': no password/users configured",
            tag
        );
        let mut psks: Vec<(Vec<u8>, String)> = Vec::with_capacity(users.len());
        for (name, password) in users {
            let psk = base64::engine::general_purpose::STANDARD
                .decode(password.trim())
                .map_err(|e| {
                    anyhow::anyhow!(
                        "shadowsocks inbound '{tag}': user '{name}' password must be \
                         base64-encoded SS2022 key: {e}"
                    )
                })?;
            anyhow::ensure!(
                psk.len() == method.key_len(),
                "shadowsocks inbound '{tag}': user '{name}' PSK length mismatch: \
                 expected {} bytes, got {}",
                method.key_len(),
                psk.len()
            );
            psks.push((psk, name));
        }
        let psks = Arc::new(psks);

        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let salt_cache = Arc::new(SaltCache::new());

        // ── 原生 UDP 会话（sing-box shadowsocks inbound 默认 TCP+UDP） ──────────
        if self.config.network.udp() {
            let udp = Arc::new(UdpSocket::bind(bind).await?);
            info!(
                tag = %tag,
                addr = %bind,
                method = %self.config.method,
                "shadowsocks inbound udp listening"
            );
            tokio::spawn(run_udp(
                udp,
                method,
                psks.clone(),
                self.udp_tx,
                tag.clone(),
            ));
        }

        // ── TCP 监听 ────────────────────────────────────────────────────────────
        if self.config.network.tcp() {
            let listener = bind_dual_stack_listener(bind).await?;

            // 传输栈：外层 TLS/REALITY + 传输层（tcp/ws/grpc/xhttp）
            let stack = Arc::new(InboundStack::build(
                &self.config.tls,
                self.config.transport.as_ref(),
            )?);
            info!(
                tag = %tag,
                addr = %bind,
                method = %self.config.method,
                users = psks.len(),
                stack = %stack.describe(),
                "shadowsocks inbound tcp listening"
            );

            let tcp_tx = self.tcp_tx;

            let handler: InboundConnHandler = {
                let tcp_tx = tcp_tx.clone();
                let tag = tag.clone();
                let psks = psks.clone();
                let salt_cache = salt_cache.clone();
                Arc::new(move |io, peer, raw_tcp| {
                    let psks = psks.clone();
                    let salt_cache = salt_cache.clone();
                    let tcp_tx = tcp_tx.clone();
                    let tag = tag.clone();
                    Box::pin(async move {
                        handle_tcp(io, raw_tcp, peer, method, &psks, &salt_cache, tcp_tx, tag).await
                    })
                })
            };

            crate::inbound::transport::serve_inbound(listener, stack, handler).await
        } else {
            // 仅 UDP：UDP 任务已 spawn，本协程保持存活
            std::future::pending::<()>().await;
            unreachable!("pending never resolves");
        }
    }
}

// ── Salt 重放缓存（2022 规范要求） ─────────────────────────────────────────────
//
// 2022-blake3 规范要求服务端缓存已见过的请求 salt，在时间窗口内拒绝重复 salt，
// 防止重放攻击。用 Mutex<HashMap> 做时间窗口缓存，插入时顺带清理过期条目，
// 无需后台清理任务。

/// Salt 重放保护缓存窗口（秒）。与时间戳校验窗口（30s）对齐，留 2x 余量。
const SALT_CACHE_WINDOW_SECS: u64 = 120;

struct SaltCache {
    entries: Mutex<HashMap<Vec<u8>, u64>>,
}

impl SaltCache {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 检查 salt 是否为重放。返回 `true` 表示通过（非重放），`false` 表示重放。
    /// 通过时自动插入缓存。
    fn check_and_insert(&self, salt: &[u8]) -> bool {
        let now = now_unix_secs();
        let mut entries = self.entries.lock().unwrap();

        entries.retain(|_, ts| now.saturating_sub(*ts) < SALT_CACHE_WINDOW_SECS);

        if entries.contains_key(salt) {
            return false;
        }
        entries.insert(salt.to_vec(), now);
        true
    }
}

// ── TCP 处理 ─────────────────────────────────────────────────────────────────

/// 处理一条 SS2022 TCP 连接：salt 读取 → 重放检查 → 多用户 PSK 逐个尝试解密
/// 请求头 → 解析目标地址 → 装箱解密流交给 dispatcher。
///
/// `io` 已由传输栈完成外层 TLS/REALITY + 传输层（tcp/ws/grpc/xhttp）握手。
#[allow(clippy::too_many_arguments)]
async fn handle_tcp(
    mut io: Box<dyn AsyncReadWrite>,
    raw_tcp: Option<TcpStream>,
    peer: SocketAddr,
    method: Method,
    psks: &[(Vec<u8>, String)],
    salt_cache: &SaltCache,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    let salt_len = method.salt_len();
    let key_len = method.key_len();

    // Step 1：读取客户端 salt（明文）
    let mut salt = vec![0u8; salt_len];
    io.read_exact(&mut salt).await?;

    // Step 2：salt 重放保护（2022 规范要求）
    if !salt_cache.check_and_insert(&salt) {
        warn!(
            peer = %display_sockaddr(peer),
            tag = %tag,
            "shadowsocks inbound: replay detected (duplicate salt)"
        );
        anyhow::bail!("shadowsocks 2022: replay detected (duplicate salt)");
    }

    // Step 3：读取 fixed header chunk（nonce=0，无外层长度前缀）
    let mut fixed_ct = vec![0u8; SS2022_TCP_FIXED_HEADER_LEN + TAG_LEN];
    io.read_exact(&mut fixed_ct).await?;

    // Step 4：多用户 PSK 逐个派生 subkey 尝试解密（首个成功者即认证通过）
    let mut matched: Option<(usize, AeadCipher, Vec<u8>)> = None;
    for (i, (psk, _)) in psks.iter().enumerate() {
        let subkey = ss2022_session_key(psk, &salt, key_len);
        let mut dec = AeadCipher::new(method, subkey);
        let mut buf = fixed_ct.clone();
        if dec.open(&mut buf).is_ok() {
            matched = Some((i, dec, buf));
            break;
        }
    }
    let Some((user_idx, mut dec, fixed_pt)) = matched else {
        anyhow::bail!("shadowsocks 2022: no user matched (auth failed)");
    };

    // Step 5：解析 fixed header：[type=0][timestamp 8B][variableHeaderLen 2B]
    anyhow::ensure!(
        fixed_pt[0] == SS2022_HEADER_TYPE_CLIENT,
        "shadowsocks 2022: wrong stream type {}, expected {}",
        fixed_pt[0],
        SS2022_HEADER_TYPE_CLIENT
    );
    let ts = u64::from_be_bytes(fixed_pt[1..9].try_into().unwrap());
    check_ss2022_timestamp(ts)?;
    let var_len = u16::from_be_bytes([fixed_pt[9], fixed_pt[10]]) as usize;

    // Step 6：读取 variable header chunk（nonce=1）：
    // [SOCKS_addr][paddingLen 2B][padding][可能的首包数据]
    anyhow::ensure!(
        var_len > 0,
        "shadowsocks 2022: empty variable header"
    );
    let mut var_ct = vec![0u8; var_len + TAG_LEN];
    io.read_exact(&mut var_ct).await?;
    dec.open(&mut var_ct)?; // counter → 2，此后为标准分帧

    let (addr_len, target) = parse_socks_addr(&var_ct)?;
    anyhow::ensure!(
        var_ct.len() >= addr_len + 2,
        "shadowsocks 2022: missing padding length"
    );
    let padding_len = u16::from_be_bytes([var_ct[addr_len], var_ct[addr_len + 1]]) as usize;
    let payload_start = addr_len + 2 + padding_len;
    anyhow::ensure!(
        var_ct.len() >= payload_start,
        "shadowsocks 2022: truncated padding"
    );
    // variable header 中 padding 之后若有剩余字节，视为首个上行 payload 前缀
    let first_payload = var_ct[payload_start..].to_vec();

    debug!(
        peer = %display_sockaddr(peer),
        user = %psks[user_idx].1,
        target = %target,
        tag = %tag,
        "shadowsocks request"
    );

    // Step 7：生成响应 salt、派生下行 subkey，构建解密/加密双工流
    let psk = psks[user_idx].0.clone();
    let mut resp_salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut resp_salt);
    let down_subkey = ss2022_session_key(&psk, &resp_salt, key_len);

    let io: Box<dyn AsyncReadWrite> = Box::new(Ss2022ServerStream {
        inner: io,
        dec, // counter 已到 2（fixed + variable header 各消耗一个 nonce）
        enc: AeadCipher::new(method, down_subkey),
        resp_salt,
        request_salt: salt,
        write_header_done: false,
        read_buf: Vec::new(),
        raw_buf: Vec::new(),
    });

    let mut sniffed = SniffedStream::from_encrypted(io, peer, raw_tcp);
    sniffed.prepend(Bytes::from(first_payload));

    tcp_tx
        .send(InboundTcpStream {
            stream: sniffed,
            target,
            inbound_tag: (*tag).clone(),
            sniffed_protocol: None,
            sniffed_domain: None,
        })
        .await
        .ok();

    Ok(())
}

// ── SS2022 服务端双工流 ───────────────────────────────────────────────────────

/// SS2022 服务端 TCP 流：读侧对客户端数据做标准分帧解密（counter 从 2 起续），
/// 写侧惰性发送响应 salt + 响应头（nonce=0/1），随后标准分帧加密（counter 从 2 起）。
struct Ss2022ServerStream<S> {
    inner: S,
    /// 上行解密器（fixed + variable header 已消耗 nonce 0/1）
    dec: AeadCipher,
    /// 下行加密器（响应头未发出前 counter=0）
    enc: AeadCipher,
    /// 响应 salt（首次 poll_write 时随响应头明文写出）
    resp_salt: Vec<u8>,
    /// 客户端请求 salt（响应头中回显，供客户端做 responseSalt 校验）
    request_salt: Vec<u8>,
    /// 响应 salt + 响应头 + padding 是否已随首个写出包发出
    write_header_done: bool,
    /// 已解密的明文缓冲
    read_buf: Vec<u8>,
    /// 底层流读取缓冲（积累密文帧）
    raw_buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Ss2022ServerStream<S> {
    /// 从底层流读取更多数据到 raw_buf。
    /// 返回 `Ok(true)` 表示读到了数据，`Ok(false)` 表示 EOF，`Pending` 表示需等待。
    fn poll_read_more(
        inner: &mut S,
        raw_buf: &mut Vec<u8>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<bool>> {
        use std::task::Poll;
        let mut tmp = [0u8; 4096];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match std::pin::Pin::new(inner).poll_read(cx, &mut tmp_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let filled = tmp_buf.filled();
                if filled.is_empty() {
                    Poll::Ready(Ok(false)) // EOF
                } else {
                    raw_buf.extend_from_slice(filled);
                    Poll::Ready(Ok(true))
                }
            }
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Ss2022ServerStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::io::ErrorKind;
        use std::task::Poll;
        let this = self.get_mut();

        // 先消费解密缓冲
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        loop {
            // 标准分帧：[enc(2B len)+tag][enc(payload)+tag]
            let len_chunk_size = 2 + TAG_LEN;
            if this.raw_buf.len() >= len_chunk_size {
                // 预解密 length（不递增 counter）以确定完整帧长度
                let nonce = this.dec.nonce();
                let mut len_peek = this.raw_buf[..len_chunk_size].to_vec();
                if this.dec.open_with_nonce(&mut len_peek, &nonce).is_err() {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "ss2022 server: length chunk decrypt failed",
                    )));
                }
                let payload_len = u16::from_be_bytes([len_peek[0], len_peek[1]]) as usize;
                let total_needed = len_chunk_size + payload_len + TAG_LEN;

                if this.raw_buf.len() >= total_needed {
                    // 真正执行两次 open（递增 counter）
                    let mut len_chunk = this.raw_buf[..len_chunk_size].to_vec();
                    if let Err(e) = this.dec.open(&mut len_chunk) {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("ss2022 server: len open: {e}"),
                        )));
                    }
                    let mut payload_chunk = this.raw_buf[len_chunk_size..total_needed].to_vec();
                    if let Err(e) = this.dec.open(&mut payload_chunk) {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("ss2022 server: payload open: {e}"),
                        )));
                    }
                    this.raw_buf.drain(..total_needed);
                    this.read_buf.extend_from_slice(&payload_chunk);

                    let n = buf.remaining().min(this.read_buf.len());
                    buf.put_slice(&this.read_buf[..n]);
                    this.read_buf.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                // payload 还不够，继续读
            }

            match Self::poll_read_more(&mut this.inner, &mut this.raw_buf, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                // EOF：raw_buf 无完整帧时视为对端正常关闭
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(true)) => continue,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Ss2022ServerStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::ErrorKind;
        use std::task::Poll;
        let this = self.get_mut();

        let io_err = |e: anyhow::Error| {
            std::io::Error::new(ErrorKind::InvalidData, format!("ss2022 server write: {e}"))
        };

        // 构建完整输出：[resp_salt 若未发送][响应头][padding][分帧 payload]
        let mut out = Vec::new();
        if !this.write_header_done {
            this.write_header_done = true;

            out.extend_from_slice(&this.resp_salt);

            // 响应头 chunk（nonce=0）：[type=1][timestamp 8B][requestSalt][paddingLen=0]
            let mut hdr = Vec::with_capacity(1 + 8 + this.request_salt.len() + 2 + TAG_LEN);
            hdr.push(SS2022_HEADER_TYPE_SERVER);
            hdr.extend_from_slice(&now_unix_secs().to_be_bytes());
            hdr.extend_from_slice(&this.request_salt);
            hdr.extend_from_slice(&0u16.to_be_bytes()); // paddingLen = 0
            this.enc.seal(&mut hdr).map_err(io_err)?;

            // padding chunk（nonce=1）：paddingLen=0 → 空 payload（仅 tag）
            let mut pad = Vec::new();
            this.enc.seal(&mut pad).map_err(io_err)?;

            out.extend_from_slice(&hdr);
            out.extend_from_slice(&pad);
        }

        // 分块，每块不超过 MAX_PAYLOAD
        let mut offset = 0;
        while offset < data.len() {
            let chunk_end = (offset + MAX_PAYLOAD).min(data.len());
            let chunk = &data[offset..chunk_end];

            let mut len_buf = (chunk.len() as u16).to_be_bytes().to_vec();
            this.enc.seal(&mut len_buf).map_err(io_err)?;

            let mut payload_buf = chunk.to_vec();
            this.enc.seal(&mut payload_buf).map_err(io_err)?;

            out.extend_from_slice(&len_buf);
            out.extend_from_slice(&payload_buf);
            offset = chunk_end;
        }

        if out.is_empty() {
            return Poll::Ready(Ok(data.len()));
        }

        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &out) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(data.len())),
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ── 原生 UDP 会话 ────────────────────────────────────────────────────────────

/// 单个客户端 socket（src 地址）的会话状态：回包时据此选择 PSK、
/// 回显 sessionId 并为响应帧递增 packetId。
struct UdpPeer {
    /// 该客户端最近一次成功解密所用 PSK
    psk: Vec<u8>,
    /// 客户端最近一次请求帧的 sessionId（响应 body 回显 + 响应帧 header 复用）
    session_id: u64,
    /// 响应帧 packetId（从 1 递增）
    packet_id: u64,
    /// 最近一次上行包的目标地址（回包 SOCKS_addr 优先级低于出站伪造源地址）
    last_target: Option<Target>,
}

/// 原生 UDP 会话主循环：单 socket recv_from → 解密 → 逐包投递 dispatcher；
/// 回包经统一 reply pump 按客户端地址 send_to 写回（多客户端共用一个 socket）。
async fn run_udp(
    socket: Arc<UdpSocket>,
    method: Method,
    psks: Arc<Vec<(Vec<u8>, String)>>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) {
    let peers: Arc<Mutex<HashMap<SocketAddr, UdpPeer>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(256);

    // ── 回包 pump：reply_rx → 构建 SS2022 响应帧 → send_to 客户端 ─────────────
    let pump_peers = peers.clone();
    let pump_socket = socket.clone();
    let pump_method = method;
    let pump_tag = tag.clone();
    tokio::spawn(async move {
        while let Some((data, client, spoofed)) = reply_rx.recv().await {
            // 取该客户端的会话状态，确定 PSK / sessionId / packetId / 回包源地址
            let (psk, session_id, packet_id, src_addr) = {
                let mut map = pump_peers.lock().unwrap();
                match map.get_mut(&client) {
                    Some(p) => {
                        p.packet_id = p.packet_id.wrapping_add(1);
                        (
                            p.psk.clone(),
                            p.session_id,
                            p.packet_id,
                            resolve_reply_addr(&p.last_target, spoofed),
                        )
                    }
                    None => {
                        debug!(
                            client = %display_sockaddr(client),
                            tag = %pump_tag,
                            "shadowsocks udp reply: unknown client, dropping"
                        );
                        continue;
                    }
                }
            };
            let Some(src_addr) = src_addr else {
                debug!(
                    client = %display_sockaddr(client),
                    tag = %pump_tag,
                    "shadowsocks udp reply: no address, dropping"
                );
                continue;
            };

            let socks_addr = encode_target(&Target::Socket(src_addr));
            let mut body = ss2022_udp_build_server_body(
                now_unix_secs(),
                session_id,
                &socks_addr,
                &data,
            );
            let wire = if ss2022_is_aes(pump_method) {
                match ss2022_udp_seal_aes(&psk, session_id, packet_id, &mut body) {
                    Ok(w) => w,
                    Err(e) => {
                        debug!(err = %e, tag = %pump_tag, "shadowsocks udp reply seal failed");
                        continue;
                    }
                }
            } else {
                let mut nonce_24 = [0u8; 24];
                rand::thread_rng().fill_bytes(&mut nonce_24);
                match ss2022_udp_seal_chacha(&psk, session_id, packet_id, &nonce_24, &mut body) {
                    Ok(w) => w,
                    Err(e) => {
                        debug!(err = %e, tag = %pump_tag, "shadowsocks udp reply seal failed");
                        continue;
                    }
                }
            };
            let _ = pump_socket.send_to(&wire, client).await;
        }
    });

    // ── 收包循环 ────────────────────────────────────────────────────────────────
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, src) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                warn!(err = %e, tag = %tag, "shadowsocks udp recv error");
                continue;
            }
        };

        // 多用户 PSK 逐个尝试解密
        let mut decoded: Option<(Vec<u8>, u64, Vec<u8>)> = None;
        for (psk, _) in psks.iter() {
            let result = if ss2022_is_aes(method) {
                ss2022_udp_open_aes_with_session(psk, &buf[..n])
            } else {
                ss2022_udp_open_chacha_with_session(psk, &buf[..n])
            };
            if let Ok((session_id, body)) = result {
                decoded = Some((psk.clone(), session_id, body));
                break;
            }
        }
        let Some((psk, session_id, body)) = decoded else {
            debug!(
                src = %display_sockaddr(src),
                tag = %tag,
                "shadowsocks udp: no user matched (drop)"
            );
            continue;
        };

        // 解析 body：[type=0][timestamp][paddingLen][padding][SOCKS_addr][payload]
        let Some((target, payload)) = ss2022_udp_parse_client_body(&body) else {
            debug!(
                src = %display_sockaddr(src),
                tag = %tag,
                "shadowsocks udp: bad request body (drop)"
            );
            continue;
        };

        // 更新会话状态（新客户端自动建档）
        {
            let mut map = peers.lock().unwrap();
            let p = map.entry(src).or_insert_with(|| UdpPeer {
                psk: psk.clone(),
                session_id,
                packet_id: 0,
                last_target: None,
            });
            p.psk = psk;
            p.session_id = session_id;
            p.last_target = Some(target.clone());
        }

        let packet = InboundUdpPacket {
            data: Bytes::copy_from_slice(payload),
            src,
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

    debug!(tag = %tag, "shadowsocks udp session loop exited");
}
