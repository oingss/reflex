//! AnyTLS 客户端出站（对齐 sing-box `protocol/anytls/outbound.go` 行为面）。
//!
//! 会话多路复用 + 空闲会话池；UDP 走 sing UoT v2（魔术地址
//! `sp.v2.udp-over-tcp.arpa`，见 [`crate::protocol::anytls`] 模块头）。
//!
//! 线格式原语（padding scheme、帧编解码、认证帧、SOCKS 地址、UoT v2、
//! 服务端会话多路复用）已下沉至 [`crate::protocol::anytls`]，本文件只保留
//! 客户端角色逻辑：会话状态机、写任务调度（缓冲/padding 触发）、空闲池。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};
use tracing::{debug, warn};

use crate::{
    config::outbound::AnyTlsOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{apply_mark_to_tcp, relay, set_tcp_opts, tls::build_client_config, Outbound},
    protocol::anytls::{
        apply_padding, build_auth_packet, build_frame, build_uot_packet, build_uot_request,
        encode_socks_addr, read_uot_packet, SharedPadding, CMD_ALERT, CMD_FIN,
        CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYN,
        CMD_SYNACK, CMD_UPDATE_PADDING, CMD_WASTE, FRAME_HEADER_SIZE, UOT_MAGIC_ADDRESS,
        UOT_MAGIC_PORT,
    },
};

// ── 向写任务发送的消息 ────────────────────────────────────────────────────────

enum WriteMsg {
    /// 控制帧字节（在缓冲模式下也直接写，不走 padding；如 FIN / HEART）
    Control(Vec<u8>),
    /// 数据帧字节（在缓冲模式下先缓冲）
    Frame(Vec<u8>),
    /// 停止缓冲，开始实际写出（附带触发帧，走 padding）
    Flush(Vec<u8>),
    /// 关闭连接
    Close,
}

// ── AnyTlsSession ─────────────────────────────────────────────────────────────

pub struct AnyTlsSession {
    /// 向写任务发送帧
    write_tx: mpsc::UnboundedSender<WriteMsg>,
    /// 活跃 Stream 数据通道表
    streams: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>>,
    /// 下一个 Stream ID（从 1 开始）
    next_stream_id: AtomicU32,
    /// 包计数器（用于 padding 逻辑，pkt 从 1 计数，见 protocol::anytls::apply_padding）
    pkt_counter: AtomicU32,
    /// 服务端协议版本
    peer_version: AtomicU8,
    /// 是否已关闭
    is_closed: AtomicBool,
    /// 关闭通知
    closed_notify: Arc<Notify>,
    /// 共享 padding scheme
    padding: Arc<SharedPadding>,
    /// 当前是否处于缓冲模式（cmdSettings 发出前缓冲）
    buffering: AtomicBool,
    /// Session 序号
    pub seq: u64,
    /// 进入空闲池的时间
    pub idle_since: Mutex<Option<Instant>>,
}

impl AnyTlsSession {
    /// 创建 Session 并启动收发任务
    pub(crate) fn new(
        conn: Box<dyn crate::outbound::AsyncReadWrite>,
        padding: Arc<SharedPadding>,
        seq: u64,
    ) -> Arc<Self> {
        let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteMsg>();
        let streams: Arc<tokio::sync::Mutex<HashMap<u32, mpsc::UnboundedSender<Bytes>>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let closed_notify = Arc::new(Notify::new());
        let (read_half, write_half) = tokio::io::split(conn);

        let session = Arc::new(AnyTlsSession {
            write_tx,
            streams: streams.clone(),
            next_stream_id: AtomicU32::new(0),
            pkt_counter: AtomicU32::new(0),
            peer_version: AtomicU8::new(1),
            is_closed: AtomicBool::new(false),
            closed_notify: closed_notify.clone(),
            padding,
            buffering: AtomicBool::new(true),
            seq,
            idle_since: Mutex::new(None),
        });

        // spawn 写任务
        tokio::spawn(write_task(write_half, write_rx, session.clone()));
        // spawn 接收循环
        tokio::spawn(recv_loop(read_half, session.clone()));

        session
    }

    pub fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        if !self.is_closed.swap(true, Ordering::AcqRel) {
            self.closed_notify.notify_waiters();
            let _ = self.write_tx.send(WriteMsg::Close);
        }
    }

    /// 发送控制帧（FIN / HEART_RESPONSE 等，不走 padding 路径）
    fn write_control(&self, cmd: u8, sid: u32, data: &[u8]) -> std::io::Result<()> {
        let frame = build_frame(cmd, sid, data);
        self.write_tx
            .send(WriteMsg::Control(frame))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    /// 发送数据帧（PSH）
    fn write_data(&self, sid: u32, data: &[u8]) -> std::io::Result<usize> {
        if self.is_closed() {
            return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        }
        let frame = build_frame(CMD_PSH, sid, data);
        let len = data.len();
        self.write_tx
            .send(WriteMsg::Flush(frame))
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::BrokenPipe))?;
        Ok(len)
    }

    /// 打开新 Stream
    pub async fn open_stream(self: &Arc<Self>) -> anyhow::Result<AnyTlsStream> {
        if self.is_closed() {
            anyhow::bail!("session is closed");
        }

        let sid = self.next_stream_id.fetch_add(1, Ordering::SeqCst) + 1;

        // 首个 Stream（sid==1）：先在缓冲模式下发 cmdSettings
        if sid == 1 {
            let md5 = self.padding.md5();
            let settings = format!("v=2\nclient=reflex/anytls\npadding-md5={}", md5);
            // buffering=true，Frame 消息被写任务缓冲
            let _ = self
                .write_tx
                .send(WriteMsg::Frame(build_frame(
                    CMD_SETTINGS,
                    0,
                    settings.as_bytes(),
                )));
        }

        // 注册 stream 数据通道
        let (data_tx, data_rx) = mpsc::unbounded_channel::<Bytes>();
        self.streams.lock().await.insert(sid, data_tx);

        // cmdSYN 也加入缓冲（与 cmdSettings 合批，等 addr 写入触发 Flush）
        // 这样首次 writeConn 会把 cmdSettings + cmdSYN + cmdPSH(addr) 合为一个 TLS 写调用，
        // 对应 anytls-go 的 pkt1（scheme "1=100-400"），与协议要求一致。
        let _ = self
            .write_tx
            .send(WriteMsg::Frame(build_frame(CMD_SYN, sid, &[])));
        // 标记 buffering=false：下一次 write_data（写代理目标地址）会触发 Flush
        self.buffering.store(false, Ordering::Release);

        Ok(AnyTlsStream {
            sid,
            session: self.clone(),
            data_rx,
            read_buf: Bytes::new(),
        })
    }

    /// 关闭 Stream（发 cmdFIN）
    fn close_stream_local(&self, sid: u32) {
        if !self.is_closed() {
            let _ = self.write_control(CMD_FIN, sid, &[]);
        }
        let streams = self.streams.clone();
        tokio::spawn(async move {
            streams.lock().await.remove(&sid);
        });
    }
}

// ── 写任务 ────────────────────────────────────────────────────────────────────

async fn write_task<W: AsyncWrite + Unpin + Send + 'static>(
    mut writer: W,
    mut rx: mpsc::UnboundedReceiver<WriteMsg>,
    session: Arc<AnyTlsSession>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buffering = true;

    while let Some(msg) = rx.recv().await {
        match msg {
            WriteMsg::Close => {
                let _ = writer.shutdown().await;
                return;
            }
            WriteMsg::Control(data) => {
                // 控制帧（FIN/HEART 等）直接写，不走 padding，不影响缓冲状态
                if writer.write_all(&data).await.is_err() {
                    session.close();
                    return;
                }
            }
            WriteMsg::Frame(data) => {
                if buffering {
                    pending.extend_from_slice(&data);
                } else {
                    let out = apply_padding(&session.pkt_counter, &session.padding.get(), data);
                    if writer.write_all(&out).await.is_err() {
                        session.close();
                        return;
                    }
                }
            }
            WriteMsg::Flush(data) => {
                // 停止缓冲，flush pending + current data 一起发出（走 padding）
                buffering = false;
                let combined = if !pending.is_empty() {
                    let mut c = std::mem::take(&mut pending);
                    c.extend_from_slice(&data);
                    c
                } else {
                    data
                };
                let out = apply_padding(&session.pkt_counter, &session.padding.get(), combined);
                if writer.write_all(&out).await.is_err() {
                    session.close();
                    return;
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

// ── 接收循环 ──────────────────────────────────────────────────────────────────

async fn recv_loop<R: AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
    session: Arc<AnyTlsSession>,
) {
    let mut hdr = [0u8; FRAME_HEADER_SIZE];

    loop {
        if session.is_closed() {
            return;
        }

        if reader.read_exact(&mut hdr).await.is_err() {
            session.close();
            return;
        }

        let cmd = hdr[0];
        let sid = u32::from_be_bytes(hdr[1..5].try_into().unwrap());
        let data_len = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;

        match cmd {
            CMD_PSH => {
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    let streams = session.streams.lock().await;
                    if let Some(tx) = streams.get(&sid) {
                        let _ = tx.send(Bytes::from(buf));
                    }
                }
            }
            CMD_FIN => {
                session.streams.lock().await.remove(&sid);
            }
            CMD_WASTE | CMD_SYN => {
                // CMD_WASTE: 丢弃数据；CMD_SYN: 客户端侧不应收到
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                }
            }
            CMD_ALERT => {
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    warn!(
                        seq = session.seq,
                        msg = %String::from_utf8_lossy(&buf),
                        "anytls server alert"
                    );
                }
                session.close();
                return;
            }
            CMD_UPDATE_PADDING => {
                if data_len > 0 {
                    let mut raw = vec![0u8; data_len];
                    if reader.read_exact(&mut raw).await.is_err() {
                        session.close();
                        return;
                    }
                    if session.padding.update(&raw) {
                        debug!(seq = session.seq, "anytls padding scheme updated");
                    } else {
                        warn!(
                            seq = session.seq,
                            "anytls padding scheme update failed (invalid)"
                        );
                    }
                }
            }
            CMD_SYNACK => {
                // v2：服务端确认 stream 打开
                // data_len == 0：正常确认，stream 已可用，无需额外处理
                // data_len >  0：服务端拒绝打开（携带错误信息），需关闭本地 stream
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    warn!(
                        seq = session.seq,
                        sid,
                        msg = %String::from_utf8_lossy(&buf),
                        "anytls server rejected stream (SYNACK with error)"
                    );
                    // 单次加锁移除 tx：tx 被 drop 后，AnyTlsStream::poll_read
                    // 收到 channel 关闭信号即返回 EOF/Reset，无需再发 CMD_FIN
                    // （服务端已知此 stream 失败，否则不会发错误 SYNACK）。
                    // 旧实现 `drop(tx.clone())` 是空操作（只 drop 了克隆），
                    // 且重复加锁存在 TOCTOU 窗口，这里一并修正。
                    session.streams.lock().await.remove(&sid);
                }
            }
            CMD_HEART_REQUEST => {
                let _ = session
                    .write_tx
                    .send(WriteMsg::Control(build_frame(
                        CMD_HEART_RESPONSE,
                        sid,
                        &[],
                    )));
            }
            CMD_HEART_RESPONSE => { /* 忽略 */ }
            CMD_SERVER_SETTINGS => {
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                    if let Ok(text) = std::str::from_utf8(&buf) {
                        for line in text.lines() {
                            if let Some(v) = line.strip_prefix("v=") {
                                if let Ok(ver) = v.trim().parse::<u8>() {
                                    session.peer_version.store(ver, Ordering::Release);
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // 未知命令，读出数据丢弃
                if data_len > 0 {
                    let mut buf = vec![0u8; data_len];
                    if reader.read_exact(&mut buf).await.is_err() {
                        session.close();
                        return;
                    }
                }
            }
        }
    }
}

// ── AnyTlsStream ─────────────────────────────────────────────────────────────

pub struct AnyTlsStream {
    sid: u32,
    session: Arc<AnyTlsSession>,
    data_rx: mpsc::UnboundedReceiver<Bytes>,
    read_buf: Bytes,
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        self.session.close_stream_local(self.sid);
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 先消费 read_buf
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf = self.read_buf.slice(n..);
            return std::task::Poll::Ready(Ok(()));
        }

        match self.data_rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data.slice(n..);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                // channel 关闭 → EOF 或 session 关闭
                if self.session.is_closed() {
                    std::task::Poll::Ready(Err(std::io::Error::from(
                        std::io::ErrorKind::ConnectionReset,
                    )))
                } else {
                    std::task::Poll::Ready(Ok(())) // 正常 EOF
                }
            }
            std::task::Poll::Pending => {
                if self.session.is_closed() {
                    std::task::Poll::Ready(Err(std::io::Error::from(
                        std::io::ErrorKind::ConnectionReset,
                    )))
                } else {
                    std::task::Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(self.session.write_data(self.sid, data))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.session.close_stream_local(self.sid);
        std::task::Poll::Ready(Ok(()))
    }
}

// ── AnyTlsClient ─────────────────────────────────────────────────────────────

struct ClientInner {
    /// 空闲会话池（按 seq 升序，pop 时取最后一个=最新的）
    idle_sessions: Vec<Arc<AnyTlsSession>>,
    /// 所有活跃会话
    all_sessions: HashMap<u64, Arc<AnyTlsSession>>,
    session_seq: u64,
}

pub struct AnyTlsClient {
    inner: Arc<tokio::sync::Mutex<ClientInner>>,
    padding: Arc<SharedPadding>,
    config: AnyTlsOutboundConfig,
    tls_config: Arc<rustls::ClientConfig>,
    routing_mark: u32,
    idle_timeout: Duration,
    min_idle_session: usize,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<crate::dns::DnsResolver>>,
}

impl AnyTlsClient {
    pub fn new(
        config: AnyTlsOutboundConfig,
        tls_config: Arc<rustls::ClientConfig>,
        routing_mark: u32,
        resolver: Option<Arc<crate::dns::DnsResolver>>,
    ) -> anyhow::Result<Arc<Self>> {
        let idle_check_interval = config
            .idle_session_check_interval
            .as_deref()
            .and_then(|s| crate::config::outbound::parse_duration(s).ok())
            .unwrap_or(Duration::from_secs(30));

        let idle_timeout = config
            .idle_session_timeout
            .as_deref()
            .and_then(|s| crate::config::outbound::parse_duration(s).ok())
            .unwrap_or(Duration::from_secs(60));

        let min_idle_session = config.min_idle_session as usize;

        let client = Arc::new(Self {
            inner: Arc::new(tokio::sync::Mutex::new(ClientInner {
                idle_sessions: Vec::new(),
                all_sessions: HashMap::new(),
                session_seq: 0,
            })),
            padding: Arc::new(SharedPadding::new_default()),
            config,
            tls_config,
            routing_mark,
            idle_timeout,
            min_idle_session,
            resolver,
        });

        // spawn 空闲清理任务
        let c = client.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(idle_check_interval).await;
                c.cleanup_idle().await;
            }
        });

        Ok(client)
    }

    /// 获取或创建可用 Session
    async fn get_or_create_session(&self) -> anyhow::Result<Arc<AnyTlsSession>> {
        // 尝试从空闲池获取最新的 session
        {
            let mut inner = self.inner.lock().await;
            while let Some(s) = inner.idle_sessions.pop() {
                if !s.is_closed() {
                    debug!(seq = s.seq, "anytls reuse idle session");
                    return Ok(s);
                }
            }
        }
        self.create_session().await
    }

    async fn create_session(&self) -> anyhow::Result<Arc<AnyTlsSession>> {
        let conn = self.dial_tls().await?;
        let seq = {
            let mut inner = self.inner.lock().await;
            inner.session_seq += 1;
            inner.session_seq
        };
        let session = AnyTlsSession::new(conn, self.padding.clone(), seq);

        {
            let mut inner = self.inner.lock().await;
            inner.all_sessions.insert(seq, session.clone());
        }

        // 注册清理 hook
        {
            let inner = self.inner.clone();
            let s = session.clone();
            tokio::spawn(async move {
                s.closed_notify.notified().await;
                let mut g = inner.lock().await;
                g.all_sessions.remove(&s.seq);
                g.idle_sessions.retain(|x| x.seq != s.seq);
            });
        }

        debug!(seq, "anytls new session created");
        Ok(session)
    }

    async fn dial_tls(&self) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let addr = crate::outbound::resolve_server_addr(
            &self.config.server,
            self.config.server_port,
            self.resolver.as_ref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("DNS failed for {}: {e}", self.config.server))?;

        let tcp = crate::outbound::connect_tcp_interface(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        let sni = self
            .config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server);
        let mut tls_stream =
            crate::outbound::tls::connect_tls(tcp, sni, self.tls_config.clone()).await?;

        // 认证帧：sha256(password)[32] + padding0_len[2] + padding0
        // （padding0 尺寸取 scheme 的 "0=..." 规则，见 protocol::anytls::build_auth_packet）
        let padding = self.padding.get();
        let auth = build_auth_packet(&self.config.password, &padding);

        tls_stream.write_all(&auth).await?;
        tls_stream.flush().await?;

        Ok(Box::new(tls_stream))
    }

    /// 创建代理 Stream（TCP）
    pub async fn create_proxy(&self, target: &Target) -> anyhow::Result<AnyTlsStream> {
        let session = self.get_or_create_session().await?;
        let mut stream = session.open_stream().await?;
        // 发送目标地址（SOCKS5 addr 格式）
        let addr = encode_socks_addr(target);
        stream.write_all(&addr).await?;
        Ok(stream)
    }

    /// Stream 关闭后将 Session 放回空闲池
    pub async fn return_idle(&self, session: Arc<AnyTlsSession>) {
        if session.is_closed() {
            return;
        }
        *session.idle_since.lock().unwrap() = Some(Instant::now());
        let mut inner = self.inner.lock().await;
        // 按 seq 升序插入（pop 时取最大 seq，即最新的）
        let pos = inner.idle_sessions.partition_point(|s| s.seq < session.seq);
        inner.idle_sessions.insert(pos, session);
    }

    /// 清理超时空闲会话
    async fn cleanup_idle(&self) {
        let timeout = self.idle_timeout;
        let min_idle = self.min_idle_session;

        let mut inner = self.inner.lock().await;
        let idle = &mut inner.idle_sessions;
        let total = idle.len();

        // 保留最新的 min_idle 个（索引最高的）
        let keep_from = total.saturating_sub(min_idle);

        let mut to_close: Vec<Arc<AnyTlsSession>> = Vec::new();
        for (i, s) in idle.iter().enumerate() {
            if i >= keep_from {
                break;
            }
            let expired = s
                .idle_since
                .lock()
                .unwrap()
                .map(|t| t.elapsed() > timeout)
                .unwrap_or(false);
            if expired {
                to_close.push(s.clone());
            }
        }
        idle.retain(|s| !to_close.iter().any(|c| c.seq == s.seq));
        drop(inner);

        for s in to_close {
            debug!(seq = s.seq, "anytls cleanup idle session");
            s.close();
        }
    }
}

// ── AnyTlsOutbound ────────────────────────────────────────────────────────────

pub struct AnyTlsOutbound {
    config: AnyTlsOutboundConfig,
    client: Arc<AnyTlsClient>,
    routing_mark: u32,
    resolver: Option<Arc<crate::dns::DnsResolver>>,
}

impl AnyTlsOutbound {
    pub fn new(config: AnyTlsOutboundConfig) -> anyhow::Result<Self> {
        let tls_config = build_client_config(&config.tls)?;
        let client = AnyTlsClient::new(config.clone(), tls_config, 0, None)?;
        Ok(Self {
            config,
            client,
            routing_mark: 0,
            resolver: None,
        })
    }

    pub fn with_resolver(self, resolver: Arc<crate::dns::DnsResolver>) -> Self {
        let tls_config = build_client_config(&self.config.tls).expect("TLS config rebuild failed");
        let client = AnyTlsClient::new(
            self.config.clone(),
            tls_config,
            self.routing_mark,
            Some(resolver.clone()),
        )
        .expect("client rebuild failed");
        Self {
            config: self.config,
            client,
            routing_mark: self.routing_mark,
            resolver: Some(resolver),
        }
    }

    pub fn with_mark(self, mark: u32) -> Self {
        let tls_config = build_client_config(&self.config.tls).expect("TLS config rebuild failed");
        let client =
            AnyTlsClient::new(self.config.clone(), tls_config, mark, self.resolver.clone())
                .expect("client rebuild failed");
        Self {
            config: self.config,
            client,
            routing_mark: mark,
            resolver: self.resolver,
        }
    }
}

#[async_trait::async_trait]
impl Outbound for AnyTlsOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let stream = self.client.create_proxy(&target).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            "anytls tcp connecting"
        );

        let stream = self.client.create_proxy(&conn.target).await?;
        let session_ref = stream.session.clone();
        let result = relay(conn.stream, stream).await;

        // 中继完成，Session 放回空闲池
        self.client.return_idle(session_ref).await;

        Ok(result)
    }

    /// UDP 使用 sing-box UDP-over-TCP v2 协议承载（见 protocol::anytls 模块头）。
    ///
    /// 流程：
    /// 1. 向服务端发起目标 = `sp.v2.udp-over-tcp.arpa:443` 的 TCP Stream
    /// 2. 写 UoT v2 请求头（包含真实目标地址）
    /// 3. 发送第一个 UDP 包
    /// 4. spawn task 持续写入后续上行包
    /// 5. 当前 task 持续读取下行 UDP 包并通过 reply_tx 回给入站
    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        debug!(
            tag = %self.config.tag,
            target = %packet.target,
            "anytls udp session (UoT v2)"
        );

        let uot_target = Target::Domain(UOT_MAGIC_ADDRESS.to_string(), UOT_MAGIC_PORT);
        let mut stream = self.client.create_proxy(&uot_target).await?;

        // 写 UoT v2 请求头
        let req_hdr = build_uot_request(&packet.target);
        stream.write_all(&req_hdr).await?;

        // 发送第一个 UDP 数据包
        let first = build_uot_packet(&packet.target, &packet.data);
        stream.write_all(&first).await?;

        let timeout = Duration::from_secs(30);
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());

        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // spawn 上行任务：持续将后续 UDP 包写入 Stream
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            tokio::spawn(async move {
                while let Some((target, data)) = upstream_rx.recv().await {
                    let frame = build_uot_packet(&target, &data);
                    if write_half.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 读取下行 UDP 包并回复给入站
        loop {
            match tokio::time::timeout(timeout, read_uot_packet(&mut read_half)).await {
                Ok(Ok((_target, data))) => {
                    let _ = reply_tx.send((data, src, spoofed_src)).await;
                }
                Ok(Err(e)) => {
                    let s = e.to_string();
                    if s.contains("eof")
                        || s.contains("EOF")
                        || s.contains("closed")
                        || s.contains("reset")
                    {
                        break;
                    }
                    return Err(e);
                }
                Err(_) => break, // timeout
            }
        }

        Ok(())
    }
}