use std::{
    collections::HashMap,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, Mutex, Notify},
};
use tracing::{debug, trace, warn};

use crate::config::outbound::MultiplexConfig;

// ── 协议常量 ──────────────────────────────────────────────────────────────────

const SMUX_V1: u8 = 1;
const SMUX_V2: u8 = 2;

const CMD_SYN: u8 = 0x00;
const CMD_FIN: u8 = 0x01;
const CMD_RST: u8 = 0x02;
const CMD_NOP: u8 = 0x03;
const CMD_PSH: u8 = 0xFF;

const HEADER_SIZE_V1: usize = 8; // ver(1)+cmd(1)+len(2)+sid(4)

const DEFAULT_MAX_FRAME: usize = 65535;
const KEEPALIVE_INTERVAL_SECS: u64 = 10;

// ── 公共配置 ──────────────────────────────────────────────────────────────────

/// SMux 会话配置（从 MultiplexConfig 转换而来）
#[derive(Debug, Clone)]
pub struct SmuxConfig {
    pub version: u8,
    pub max_frame_size: usize,
    pub keep_alive_interval: std::time::Duration,
    pub padding: bool,
}

impl Default for SmuxConfig {
    fn default() -> Self {
        Self {
            version: SMUX_V1,
            max_frame_size: DEFAULT_MAX_FRAME,
            keep_alive_interval: std::time::Duration::from_secs(KEEPALIVE_INTERVAL_SECS),
            padding: false,
        }
    }
}

impl From<&MultiplexConfig> for SmuxConfig {
    fn from(mc: &MultiplexConfig) -> Self {
        let version = SMUX_V1;
        Self {
            version,
            max_frame_size: DEFAULT_MAX_FRAME,
            keep_alive_interval: std::time::Duration::from_secs(KEEPALIVE_INTERVAL_SECS),
            padding: mc.padding,
        }
    }
}

// ── 帧 ────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Frame {
    version: u8,
    cmd: u8,
    stream_id: u32,
    data: Bytes,
    /// v2 消费窗口（仅 cmdPSH v2 有效）
    consumed: u32,
}

impl Frame {
    fn encode(&self) -> Bytes {
        let extra = if self.version == SMUX_V2 && self.cmd == CMD_PSH {
            4
        } else {
            0
        };
        let total = HEADER_SIZE_V1 + extra + self.data.len();
        let mut buf = BytesMut::with_capacity(total);
        buf.put_u8(self.version);
        buf.put_u8(self.cmd);
        buf.put_u16_le((self.data.len() + extra) as u16);
        buf.put_u32_le(self.stream_id);
        if extra > 0 {
            buf.put_u32_le(self.consumed);
        }
        buf.put_slice(&self.data);
        buf.freeze()
    }
}

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R, _version: u8) -> io::Result<Frame> {
    let mut hdr = [0u8; HEADER_SIZE_V1];
    r.read_exact(&mut hdr).await?;

    let ver = hdr[0];
    let cmd = hdr[1];
    let mut payload_len = u16::from_le_bytes([hdr[2], hdr[3]]) as usize;
    let stream_id = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);

    let consumed = if ver == SMUX_V2 && cmd == CMD_PSH && payload_len >= 4 {
        let mut c_buf = [0u8; 4];
        r.read_exact(&mut c_buf).await?;
        payload_len -= 4;
        u32::from_le_bytes(c_buf)
    } else {
        0
    };

    let mut data = vec![0u8; payload_len];
    if payload_len > 0 {
        r.read_exact(&mut data).await?;
    }
    Ok(Frame {
        version: ver,
        cmd,
        stream_id,
        data: Bytes::from(data),
        consumed,
    })
}

// ── 会话 ──────────────────────────────────────────────────────────────────────

/// 打开新流的请求（发给 session loop）
struct OpenRequest {
    /// session loop 把分配好的 SmuxStream 通过这里发回
    reply: tokio::sync::oneshot::Sender<anyhow::Result<SmuxStream>>,
}

/// SMux 会话，封装一条 TCP 连接，提供多路流功能。
pub struct SmuxSession {
    open_tx: mpsc::Sender<OpenRequest>,
    #[allow(dead_code)]
    closed: Arc<Notify>,
}

impl SmuxSession {
    /// 在已建立的双向流上创建 SMux 会话，启动后台读/写循环。
    pub fn new<T>(transport: T, cfg: SmuxConfig) -> Self
    where
        T: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (open_tx, open_rx) = mpsc::channel::<OpenRequest>(64);
        let closed = Arc::new(Notify::new());
        let closed2 = closed.clone();

        tokio::spawn(async move {
            let _ = session_loop(transport, cfg, open_rx, closed2).await;
        });

        Self { open_tx, closed }
    }

    /// 打开一条新的逻辑流。
    pub async fn open_stream(&self) -> anyhow::Result<SmuxStream> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.open_tx
            .send(OpenRequest { reply: reply_tx })
            .await
            .map_err(|_| anyhow::anyhow!("smux session closed"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("smux session loop dropped"))?
    }
}

// ── 流 ────────────────────────────────────────────────────────────────────────

/// SMux 逻辑流，实现 AsyncRead + AsyncWrite。
pub struct SmuxStream {
    #[allow(dead_code)]
    stream_id: u32,
    data_rx: Option<mpsc::Receiver<Bytes>>,
    /// 向 session 写队列投递 (sid, data)，session loop 串行编码并写出。
    /// 使用无界 channel 以避免 poll_write 在 channel 满时 busy-spin
    /// （旧实现 try_send + wake_by_ref 在 channel 满时会立即重新调度，浪费 CPU）。
    write_tx: mpsc::UnboundedSender<(u32, Bytes)>,
    closed: Arc<Notify>,
    read_buf: BytesMut,
}

impl AsyncRead for SmuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = buf.remaining().min(self.read_buf.len());
            buf.put_slice(&self.read_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }
        let rx = match self.data_rx.as_mut() {
            Some(r) => r,
            None => return Poll::Ready(Ok(())),
        };
        match rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = buf.remaining().min(data.len());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf.extend_from_slice(&data[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for SmuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 无界 channel：send 仅在 session 关闭时失败，永不阻塞，
        // 彻底消除旧实现 try_send + wake_by_ref 的 busy-spin。
        match self
            .write_tx
            .send((self.stream_id, Bytes::copy_from_slice(buf)))
        {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "smux stream closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ── 会话事件循环 ──────────────────────────────────────────────────────────────

struct StreamState {
    /// 向流投递入站数据
    data_tx: mpsc::Sender<Bytes>,
}

async fn session_loop<T>(
    transport: T,
    cfg: SmuxConfig,
    mut open_rx: mpsc::Receiver<OpenRequest>,
    closed: Arc<Notify>,
) -> anyhow::Result<()>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(transport);
    let version = cfg.version;

    // 流表：stream_id → state
    let streams: Arc<Mutex<HashMap<u32, StreamState>>> = Arc::new(Mutex::new(HashMap::new()));
    let next_id = Arc::new(AtomicU32::new(1)); // 客户端使用奇数 stream_id

    // ── 中央写队列 ────────────────────────────────────────────────────────────
    // 所有 SmuxStream 的 poll_write 把 (sid, data) 投递到这里，session loop 通过
    // recv().await 等待，彻底替代旧实现每 1ms 轮询 + 持锁 write_all 的反模式。
    let (write_queue_tx, mut write_queue_rx) = mpsc::unbounded_channel::<(u32, Bytes)>();

    // ── 读循环 ────────────────────────────────────────────────────────────────
    let streams_r = streams.clone();
    let read_task = tokio::spawn(async move {
        loop {
            match read_frame(&mut reader, version).await {
                Ok(frame) => {
                    trace!(
                        "smux rx: cmd={} sid={} len={}",
                        frame.cmd,
                        frame.stream_id,
                        frame.data.len()
                    );
                    let mut map = streams_r.lock().await;
                    match frame.cmd {
                        CMD_PSH => {
                            if let Some(state) = map.get(&frame.stream_id) {
                                let _ = state.data_tx.send(frame.data).await;
                            }
                        }
                        CMD_FIN | CMD_RST => {
                            map.remove(&frame.stream_id);
                        }
                        CMD_NOP => {}
                        CMD_SYN => {}
                        _ => warn!("smux: unknown cmd 0x{:02x}", frame.cmd),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!("smux: transport EOF");
                    break;
                }
                Err(e) => {
                    warn!("smux: read error: {e}");
                    break;
                }
            }
        }
    });

    // ── 写循环 + 新流注册 ─────────────────────────────────────────────────────
    let streams_w = streams.clone();
    let next_id_w = next_id.clone();
    let mut keepalive = tokio::time::interval(cfg.keep_alive_interval);

    loop {
        tokio::select! {
            // 新流请求
            Some(req) = open_rx.recv() => {
                let sid = next_id_w.fetch_add(2, Ordering::Relaxed);

                // SYN 帧
                let syn = Frame {
                    version,
                    cmd: CMD_SYN,
                    stream_id: sid,
                    data: Bytes::new(),
                    consumed: 0,
                };
                if let Err(e) = writer.write_all(&syn.encode()).await {
                    warn!("smux: SYN write error: {e}");
                    let _ = req.reply.send(Err(anyhow::anyhow!("smux SYN failed: {e}")));
                    break;
                }

                // 建立入站数据通道
                let (data_tx, data_rx) = mpsc::channel::<Bytes>(64);
                let stream_closed = Arc::new(Notify::new());

                let stream = SmuxStream {
                    stream_id: sid,
                    data_rx: Some(data_rx),
                    // 共享中央写队列：send 永不阻塞（除非 session 关闭）
                    write_tx: write_queue_tx.clone(),
                    closed: stream_closed.clone(),
                    read_buf: BytesMut::new(),
                };

                streams_w.lock().await.insert(sid, StreamState { data_tx });

                let _ = req.reply.send(Ok(stream));
                debug!("smux: opened stream sid={sid}");
            }

            // 出站数据：从中央写队列取一条编码写出。
            // 不持有 streams 锁，避免阻塞读循环；sid 已内嵌在消息中。
            Some((sid, data)) = write_queue_rx.recv() => {
                let frame = Frame {
                    version,
                    cmd: CMD_PSH,
                    stream_id: sid,
                    data,
                    consumed: 0,
                };
                if let Err(e) = writer.write_all(&frame.encode()).await {
                    warn!("smux: PSH write error sid={sid}: {e}");
                    streams_w.lock().await.remove(&sid);
                    // 写失败后继续运行；其它流仍可使用。
                }
            }

            // Keepalive NOP
            _ = keepalive.tick() => {
                let nop = Frame {
                    version,
                    cmd: CMD_NOP,
                    stream_id: 0,
                    data: Bytes::new(),
                    consumed: 0,
                };
                if let Err(e) = writer.write_all(&nop.encode()).await {
                    warn!("smux: NOP write error: {e}");
                    break;
                }
            }

            _ = closed.notified() => {
                debug!("smux: session closed by caller");
                break;
            }
        }
    }

    read_task.abort();
    Ok(())
}

// ── 连接池（MultiplexPool）────────────────────────────────────────────────────

/// 多路复用连接池：管理 N 条物理连接，每条连接上跑多个 SMux 流。
///
/// 与 sing-box 的 mux.Client 行为对齐：
/// - 优先复用现有连接（流数 < max_streams）
/// - 所有连接流满时新建连接（不超过 max_connections）
pub struct MultiplexPool {
    cfg: MultiplexConfig,
    /// (session, 当前流计数)
    sessions: Mutex<Vec<(Arc<SmuxSession>, usize)>>,
    /// 建立新物理连接的工厂函数
    #[allow(clippy::type_complexity)]
    dial: Box<
        dyn Fn() -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = anyhow::Result<Box<dyn AsyncReadWrite>>>
                        + Send,
                >,
            > + Send
            + Sync,
    >,
}

/// 辅助 trait，合并 AsyncRead + AsyncWrite + Send + Unpin
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

impl MultiplexPool {
    pub fn new<F, Fut>(cfg: MultiplexConfig, dial: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Box<dyn AsyncReadWrite>>> + Send + 'static,
    {
        Self {
            cfg,
            sessions: Mutex::new(Vec::new()),
            dial: Box::new(move || Box::pin(dial())),
        }
    }

    /// 获取或创建一个 SMux 流。
    pub async fn acquire(&self) -> anyhow::Result<SmuxStream> {
        let max_streams = if self.cfg.max_streams == 0 {
            usize::MAX
        } else {
            self.cfg.max_streams
        };
        let max_conns = if self.cfg.max_connections == 0 {
            usize::MAX
        } else {
            self.cfg.max_connections
        };

        let mut sessions = self.sessions.lock().await;

        // 找现有可用连接
        for (session, count) in sessions.iter_mut() {
            if *count < max_streams {
                let stream = session.open_stream().await?;
                *count += 1;
                return Ok(stream);
            }
        }

        // 新建连接
        if sessions.len() < max_conns {
            let transport = (self.dial)().await?;
            let smux_cfg = SmuxConfig::from(&self.cfg);
            let session = Arc::new(SmuxSession::new(transport, smux_cfg));
            let stream = session.open_stream().await?;
            sessions.push((session, 1));
            return Ok(stream);
        }

        anyhow::bail!("smux pool: all connections full (max_connections={max_conns})")
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encode_v1_syn() {
        let f = Frame {
            version: SMUX_V1,
            cmd: CMD_SYN,
            stream_id: 1,
            data: Bytes::new(),
            consumed: 0,
        };
        let enc = f.encode();
        assert_eq!(enc.len(), HEADER_SIZE_V1);
        assert_eq!(enc[0], SMUX_V1);
        assert_eq!(enc[1], CMD_SYN);
        assert_eq!(u16::from_le_bytes([enc[2], enc[3]]), 0); // payload len
        assert_eq!(u32::from_le_bytes([enc[4], enc[5], enc[6], enc[7]]), 1);
    }

    #[test]
    fn frame_encode_v1_psh_with_data() {
        let data = Bytes::from_static(b"hello");
        let f = Frame {
            version: SMUX_V1,
            cmd: CMD_PSH,
            stream_id: 3,
            data,
            consumed: 0,
        };
        let enc = f.encode();
        assert_eq!(enc.len(), HEADER_SIZE_V1 + 5);
        assert_eq!(u16::from_le_bytes([enc[2], enc[3]]), 5);
        assert_eq!(&enc[8..13], b"hello");
    }

    #[test]
    fn frame_encode_v2_psh_has_consumed() {
        let data = Bytes::from_static(b"hi");
        let f = Frame {
            version: SMUX_V2,
            cmd: CMD_PSH,
            stream_id: 5,
            data,
            consumed: 100,
        };
        let enc = f.encode();
        // length field in header = consumed(4) + data(2) = 6
        assert_eq!(u16::from_le_bytes([enc[2], enc[3]]), 6);
        // consumed at offset 8
        assert_eq!(u32::from_le_bytes([enc[8], enc[9], enc[10], enc[11]]), 100);
        // data at offset 12
        assert_eq!(&enc[12..14], b"hi");
    }

    #[test]
    fn smux_config_from_multiplex() {
        let mc = MultiplexConfig {
            enabled: true,
            protocol: "smux".into(),
            ..Default::default()
        };
        let sc = SmuxConfig::from(&mc);
        assert_eq!(sc.version, SMUX_V1);
    }

    #[test]
    fn smux_config_yamux_downgrades() {
        let mc = MultiplexConfig {
            enabled: true,
            protocol: "yamux".into(),
            ..Default::default()
        };
        let sc = SmuxConfig::from(&mc);
        assert_eq!(sc.version, SMUX_V1); // yamux → smux v1 compat
    }
}
