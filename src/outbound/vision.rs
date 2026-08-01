use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, BytesMut};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::trace;

use crate::outbound::tls::TlsStreamBox;

const TLS_13_SUPPORTED_VERSIONS: &[u8] = &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
const TLS_CLIENT_HANDSHAKE_START: &[u8] = &[0x16, 0x03];
const TLS_APPLICATION_DATA_START: &[u8] = &[0x17, 0x03, 0x03];

const COMMAND_PADDING_CONTINUE: u8 = 0x00;
const COMMAND_PADDING_END: u8 = 0x01;
const COMMAND_PADDING_DIRECT: u8 = 0x02;

const XRAY_CHUNK_SIZE: usize = 8192;
const BUFFER_LIMIT: usize = 8192 - 21;

fn is_tls13_aead_cipher(cipher: u16) -> bool {
    matches!(cipher, 0x1301..=0x1304)
}

pub struct VisionConn {
    /// 底层 TLS 流。direct 模式后仍持有（不消费），通过 get_mut() 访问裸 TCP。
    tls: TlsStreamBox,
    user_uuid: [u8; 16],

    // ── TLS 嗅探状态 ──
    is_tls: bool,
    number_of_packet_to_filter: i32,
    is_tls12_or_above: bool,
    remaining_server_hello: i32,
    cipher: u16,
    enable_xtls: bool,

    // ── 写状态 ──
    is_padding: bool,
    direct_write: bool,
    write_uuid: bool,

    // ── 读状态 ──
    within_padding_buffers: bool,
    remaining_content: i32,
    remaining_padding: i32,
    current_command: u8,
    direct_read: bool,

    /// direct 模式切换前从 TLS layer drain 出来的残留 plaintext。
    /// 与 sing-vmess vision.go:150-161 的 `io.ReadAll(c.input)` + `io.ReadAll(c.rawInput)` 对齐。
    drained_plaintext: BytesMut,

    /// 读侧缓冲：unPadding 解出的、尚未交给上层的内容。
    read_remainder: BytesMut,

    /// 写侧暂存：poll_write 返回 Pending 时保留未写完的 padding 帧。
    pending_write: Option<BytesMut>,
}

impl VisionConn {
    /// 创建 Vision 连接。`tls` 必须是已完成握手的 TLS 1.3 流。
    /// `user_uuid` 是 VLESS 用户 UUID，用于 padding 帧认证。
    pub fn new(tls: TlsStreamBox, user_uuid: [u8; 16]) -> Self {
        Self {
            tls,
            user_uuid,
            is_tls: false,
            number_of_packet_to_filter: 8,
            is_tls12_or_above: false,
            remaining_server_hello: -1,
            cipher: 0,
            enable_xtls: false,
            is_padding: true,
            direct_write: false,
            write_uuid: true,
            within_padding_buffers: true,
            remaining_content: -1,
            remaining_padding: -1,
            current_command: 0,
            direct_read: false,
            drained_plaintext: BytesMut::new(),
            read_remainder: BytesMut::new(),
            pending_write: None,
        }
    }

    // ── TLS 嗅探（移植自 vision.go:248-294 filterTLS）────────────────────────

    fn filter_tls(&mut self, buffers: &[&[u8]]) {
        for buffer in buffers {
            self.number_of_packet_to_filter -= 1;
            if buffer.len() > 6 {
                // TLS record: type(1B) + version(2B) + length(2B) + ...
                // type 22 = Handshake, version 3.3 = TLS 1.2 legacy
                if buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 {
                    self.is_tls = true;
                    if buffer[5] == 2 {
                        // ServerHello
                        self.is_tls12_or_above = true;
                        self.remaining_server_hello =
                            ((buffer[3] as i32) << 8 | (buffer[4] as i32)) + 5;
                        if buffer.len() >= 79 && self.remaining_server_hello >= 79 {
                            let session_id_len = buffer[43] as usize;
                            if 43 + session_id_len + 3 <= buffer.len() {
                                let cs = &buffer[43 + session_id_len + 1..43 + session_id_len + 3];
                                self.cipher = ((cs[0] as u16) << 8) | (cs[1] as u16);
                            }
                        }
                    }
                } else if buffer.len() >= 2
                    && &buffer[..2] == TLS_CLIENT_HANDSHAKE_START
                    && buffer[5] == 1
                {
                    // ClientHello
                    self.is_tls = true;
                }
            }
            if self.remaining_server_hello > 0 {
                let end = (self.remaining_server_hello as usize).min(buffer.len());
                self.remaining_server_hello -= end as i32;
                // 在 ServerHello 中搜索 supported_versions 扩展 (0x00,0x2b,0x00,0x02,0x03,0x04)
                // 0x03,0x04 = TLS 1.3
                if buffer[..end]
                    .windows(TLS_13_SUPPORTED_VERSIONS.len())
                    .any(|w| w == TLS_13_SUPPORTED_VERSIONS)
                {
                    if is_tls13_aead_cipher(self.cipher) {
                        self.enable_xtls = true;
                    }
                    self.number_of_packet_to_filter = 0;
                    return;
                } else if self.remaining_server_hello == 0 {
                    // TLS 1.2
                    self.number_of_packet_to_filter = 0;
                    return;
                }
            }
            if self.number_of_packet_to_filter == 0 {
                trace!("vision: filterTLS stop filtering");
                return;
            }
        }
    }

    // ── padding 编码（移植自 vision.go:296-331 padding）───────────────────────

    /// 构建 padding 帧。
    fn build_padding_frame(&mut self, content: &[u8], command: u8) -> BytesMut {
        let content_len = content.len();
        let padding_len = if content_len < 900 && self.is_tls {
            rand::thread_rng().gen_range(0..500) + 900 - content_len
        } else {
            rand::thread_rng().gen_range(0..256)
        };

        let mut total = 5 + content_len + padding_len;
        if self.write_uuid {
            total += 16;
        }

        let mut buf = BytesMut::with_capacity(total);
        if self.write_uuid {
            buf.put_slice(&self.user_uuid);
            self.write_uuid = false;
        }
        buf.put_u8(command);
        buf.put_u16(content_len as u16);
        buf.put_u16(padding_len as u16);
        if content_len > 0 {
            buf.put_slice(content);
        }
        // 随机 padding 字节
        buf.resize(buf.len() + padding_len, 0);
        // 填充随机字节（避免被流量分析识别为全零 padding）
        let pad_start = buf.len() - padding_len;
        rand::thread_rng().fill(&mut buf[pad_start..]);

        trace!(
            "vision padding: content={} padding={} cmd={}",
            content_len,
            padding_len,
            command
        );
        buf
    }

    // ── unPadding 解码（移植自 vision.go:333-381 unPadding）───────────────────

    /// 从一个读取块中解析 padding 帧，返回解出的内容。
    /// 返回值: (解出的内容列表, 是否需要继续处理剩余数据)
    fn unpadding(&mut self, buffer: &[u8]) -> Vec<BytesMut> {
        let mut buffers = Vec::new();
        let mut index = 0;

        // 首次：检查 UUID 前缀
        if self.remaining_content == -1 && self.remaining_padding == -1 {
            if buffer.len() >= 21 && buffer[..16] == self.user_uuid {
                index = 16;
                self.remaining_content = 0;
                self.remaining_padding = 0;
                self.current_command = 0;
            } else {
                // 无 UUID 前缀，直接作为内容返回
                buffers.push(BytesMut::from(buffer));
                return buffers;
            }
        }

        if self.remaining_content == -1 && self.remaining_padding == -1 {
            buffers.push(BytesMut::from(buffer));
            return buffers;
        }

        while index < buffer.len() {
            if self.remaining_content <= 0 && self.remaining_padding <= 0 {
                if self.current_command == COMMAND_PADDING_END {
                    // commandPaddingEnd：剩余字节直接作为内容
                    buffers.push(BytesMut::from(&buffer[index..]));
                    break;
                } else {
                    // 解析 padding 帧头 [cmd 1B][contentLen 2B][paddingLen 2B]
                    if index + 5 > buffer.len() {
                        break;
                    }
                    let hdr = &buffer[index..index + 5];
                    self.current_command = hdr[0];
                    self.remaining_content = ((hdr[1] as i32) << 8) | (hdr[2] as i32);
                    self.remaining_padding = ((hdr[3] as i32) << 8) | (hdr[4] as i32);
                    index += 5;
                }
            } else if self.remaining_content > 0 {
                let end = (self.remaining_content as usize).min(buffer.len() - index);
                buffers.push(BytesMut::from(&buffer[index..index + end]));
                self.remaining_content -= end as i32;
                index += end;
            } else {
                // remaining_padding > 0
                let end = (self.remaining_padding as usize).min(buffer.len() - index);
                self.remaining_padding -= end as i32;
                index += end;
            }
            if index == buffer.len() {
                break;
            }
        }
        buffers
    }

    // ── reshapeBuffer（移植自 constant.go:30-46）──────────────────────────────

    /// 将大 buffer 按 TLS ApplicationData 边界切分，确保 filterTLS 能正确识别 TLS record。
    fn reshape_buffer(buf: &[u8]) -> Vec<&[u8]> {
        if buf.len() < BUFFER_LIMIT {
            return vec![buf];
        }
        let mut result = Vec::new();
        let mut remaining = buf;
        while remaining.len() >= BUFFER_LIMIT {
            // 在前 BUFFER_LIMIT 字节中搜索最后一个 TLS ApplicationData 头 (0x17,0x03,0x03)
            let search_end = BUFFER_LIMIT.min(remaining.len());
            let mut index = remaining[..search_end]
                .windows(3)
                .rposition(|w| w == TLS_APPLICATION_DATA_START);
            match index {
                Some(i) if (32..=BUFFER_LIMIT).contains(&i) => {}
                _ => index = Some(8192 / 2),
            }
            let split = index.unwrap_or(8192 / 2);
            result.push(&remaining[..split]);
            remaining = &remaining[split..];
        }
        if !remaining.is_empty() {
            result.push(remaining);
        }
        result
    }

    fn drain_tls_plaintext(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let mut tmp = [0u8; 8192];
        loop {
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.tls).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        // EOF
                        break;
                    }
                    self.drained_plaintext.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => break, // 无更多数据可读
            }
        }
        Ok(())
    }
}

// ── AsyncRead 实现 ───────────────────────────────────────────────────────────

impl AsyncRead for VisionConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 1. 先消费 read_remainder（之前 unPadding 解出但没一次性给完的数据）
        if !self.read_remainder.is_empty() {
            let n = buf.remaining().min(self.read_remainder.len());
            buf.put_slice(&self.read_remainder[..n]);
            self.read_remainder.advance(n);
            return Poll::Ready(Ok(()));
        }

        // 2. direct_read 模式：先消费 drained_plaintext，再读裸 TCP
        if self.direct_read {
            // 先把 drain 出来的 TLS 残留 plaintext 给上层
            if !self.drained_plaintext.is_empty() {
                let n = buf.remaining().min(self.drained_plaintext.len());
                buf.put_slice(&self.drained_plaintext[..n]);
                self.drained_plaintext.advance(n);
                return Poll::Ready(Ok(()));
            }
            // 直接读裸 TCP（绕过 TLS AEAD）
            return match &mut self.tls {
                TlsStreamBox::Plain(s) => {
                    let (tcp, _) = s.get_mut();
                    Pin::new(tcp).poll_read(cx, buf)
                }
                TlsStreamBox::Utls(_) => {
                    // uTLS 不支持 Vision（与 sing-box 一致：uTLS + Vision 不兼容）
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "vision: uTLS does not support direct read",
                    )))
                }
            };
        }

        // 3. padding 阶段：从 TLS 读一个块，unPadding 后给上层
        let mut tmp = [0u8; XRAY_CHUNK_SIZE];
        let mut rb = ReadBuf::new(&mut tmp);
        match Pin::new(&mut self.tls).poll_read(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let filled = rb.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(())); // EOF
                }
                let data = filled;

                if self.within_padding_buffers || self.number_of_packet_to_filter > 0 {
                    let buffers = self.unpadding(data);
                    // 检查是否需要切换状态
                    if self.remaining_content == 0 && self.remaining_padding == 0 {
                        match self.current_command {
                            COMMAND_PADDING_END => {
                                self.within_padding_buffers = false;
                                self.remaining_content = -1;
                                self.remaining_padding = -1;
                            }
                            COMMAND_PADDING_DIRECT => {
                                self.within_padding_buffers = false;
                                self.direct_read = true;
                                // drain TLS plaintext buffer
                                if let Err(e) = self.drain_tls_plaintext(cx) {
                                    return Poll::Ready(Err(e));
                                }
                                trace!("vision: switched to direct read");
                            }
                            COMMAND_PADDING_CONTINUE => {
                                self.within_padding_buffers = true;
                            }
                            _ => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("vision: unknown command {}", self.current_command),
                                )));
                            }
                        }
                    } else {
                        self.within_padding_buffers =
                            self.remaining_content > 0 || self.remaining_padding > 0;
                    }

                    // 嗅探 TLS
                    if self.number_of_packet_to_filter > 0 {
                        let refs: Vec<&[u8]> = buffers.iter().map(|b| b.as_ref()).collect();
                        self.filter_tls(&refs);
                    }

                    // 把解出的内容存入 read_remainder
                    for b in buffers {
                        self.read_remainder.extend_from_slice(&b);
                    }

                    // 递归调用自己把 read_remainder 给上层
                    // （不用 cx.waker().wake_by_ref()，直接继续处理避免额外调度）
                    if !self.read_remainder.is_empty() {
                        let n = buf.remaining().min(self.read_remainder.len());
                        buf.put_slice(&self.read_remainder[..n]);
                        self.read_remainder.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    // read_remainder 为空（纯 padding），继续读下一个块
                    // 用 wake_by_ref 避免busy-loop
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    // 不在 padding 阶段，直接作为内容
                    if self.number_of_packet_to_filter > 0 {
                        self.filter_tls(&[data]);
                    }
                    let n = buf.remaining().min(data.len());
                    buf.put_slice(&data[..n]);
                    if n < data.len() {
                        self.read_remainder.extend_from_slice(&data[n..]);
                    }
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

// ── AsyncWrite 实现 ──────────────────────────────────────────────────────────

impl AsyncWrite for VisionConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        // 1. 优先完成上一次未写完的 padding 帧
        if let Some(mut pending) = self.pending_write.take() {
            return match Pin::new(&mut self.tls).poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    // 继续处理当前 data
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Ok(n)) => {
                    let rest = pending.split_off(n);
                    self.pending_write = Some(rest);
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. direct_write 模式：直接写裸 TCP（绕过 TLS AEAD）
        if self.direct_write {
            // 嗅探仍在进行时继续 filter
            if self.number_of_packet_to_filter > 0 {
                self.filter_tls(&[data]);
            }
            return match &mut self.tls {
                TlsStreamBox::Plain(s) => {
                    let (tcp, _) = s.get_mut();
                    Pin::new(tcp).poll_write(cx, data)
                }
                TlsStreamBox::Utls(_) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "vision: uTLS does not support direct write",
                ))),
            };
        }

        // 3. padding 阶段：嗅探 + 包装 padding 帧 + 写 TLS
        if self.number_of_packet_to_filter > 0 {
            self.filter_tls(&[data]);
        }

        if self.is_padding {
            let input_len = data.len();
            let chunks = Self::reshape_buffer(data);
            let mut frames: Vec<BytesMut> = Vec::with_capacity(chunks.len());
            let mut direct_switch_index: Option<usize> = None;

            for (i, chunk) in chunks.iter().enumerate() {
                if self.is_tls && chunk.len() > 6 && &chunk[..3] == TLS_APPLICATION_DATA_START {
                    // 检测到 TLS ApplicationData → 切换
                    let command = if self.enable_xtls {
                        self.direct_write = true;
                        direct_switch_index = Some(i);
                        COMMAND_PADDING_DIRECT
                    } else {
                        COMMAND_PADDING_END
                    };
                    self.is_padding = false;
                    frames.push(self.build_padding_frame(chunk, command));
                    break;
                } else if !self.is_tls12_or_above && self.number_of_packet_to_filter <= 1 {
                    // 非 TLS 或 TLS 1.2 以下 → 结束 padding
                    self.is_padding = false;
                    frames.push(self.build_padding_frame(chunk, COMMAND_PADDING_END));
                    break;
                } else {
                    frames.push(self.build_padding_frame(chunk, COMMAND_PADDING_CONTINUE));
                }
            }

            // 如果触发了 direct 切换，先写切换帧之前的加密数据到 TLS，
            // 然后切换 writer 到裸 TCP，写剩余帧。
            if let Some(switch_idx) = direct_switch_index {
                // 先 flush TLS 写缓冲，确保切换前的加密数据已发出
                match Pin::new(&mut self.tls).poll_flush(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        // 把 frames 放回 pending，下次继续
                        // （直接合并成一个 buffer）
                        let mut combined = BytesMut::new();
                        for f in &frames {
                            combined.extend_from_slice(f);
                        }
                        self.pending_write = Some(combined);
                        return Poll::Pending;
                    }
                }

                // 切换前的帧（含 direct 命令帧）通过 TLS 写出
                for f in &frames[..=switch_idx] {
                    match Pin::new(&mut self.tls).poll_write(cx, f) {
                        Poll::Ready(Ok(n)) if n >= f.len() => {}
                        Poll::Ready(Ok(n)) => {
                            // 部分写：暂存剩余
                            let rest = BytesMut::from(&f[n..]);
                            let mut combined = BytesMut::new();
                            combined.extend_from_slice(&rest);
                            for f2 in &frames[switch_idx + 1..] {
                                combined.extend_from_slice(f2);
                            }
                            self.pending_write = Some(combined);
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => {
                            let mut combined = BytesMut::new();
                            for f2 in &frames[switch_idx..] {
                                combined.extend_from_slice(f2);
                            }
                            self.pending_write = Some(combined);
                            return Poll::Pending;
                        }
                    }
                }

                // 切换后的帧直接写裸 TCP
                // 注意：sing-vmess vision.go:230 有 `time.Sleep(5ms)` 的 race workaround。
                // Rust 单线程 tokio 任务不存在该 race（无并发 writer），不需要 sleep。
                for f in &frames[switch_idx + 1..] {
                    match &mut self.tls {
                        TlsStreamBox::Plain(s) => {
                            let (tcp, _) = s.get_mut();
                            match Pin::new(tcp).poll_write(cx, f) {
                                Poll::Ready(Ok(n)) if n >= f.len() => {}
                                Poll::Ready(Ok(n)) => {
                                    let rest = BytesMut::from(&f[n..]);
                                    self.pending_write = Some(rest);
                                    cx.waker().wake_by_ref();
                                    return Poll::Pending;
                                }
                                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                                Poll::Pending => {
                                    self.pending_write = Some(f.clone());
                                    return Poll::Pending;
                                }
                            }
                        }
                        TlsStreamBox::Utls(_) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::Unsupported,
                                "vision: uTLS does not support direct write",
                            )))
                        }
                    }
                }
                return Poll::Ready(Ok(input_len));
            }

            // 未触发 direct 切换：所有帧通过 TLS 写出
            // 合并所有帧为一个 buffer，减少 write 系统调用
            let mut combined = BytesMut::new();
            for f in &frames {
                combined.extend_from_slice(f);
            }
            match Pin::new(&mut self.tls).poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) if n >= combined.len() => Poll::Ready(Ok(input_len)),
                Poll::Ready(Ok(n)) => {
                    self.pending_write = Some(combined.split_off(n));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.pending_write = Some(combined);
                    Poll::Pending
                }
            }
        } else {
            // 非 padding 阶段、非 direct：直接写 TLS
            Pin::new(&mut self.tls).poll_write(cx, data)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.tls).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.tls).poll_shutdown(cx)
    }
}
