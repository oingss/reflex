//! Hysteria2 协议原语：inbound 服务端与 outbound 客户端共享的编解码原语。
//!
//! ## 线路格式（对齐官方 hysteria2 / quic-go 实现）
//!
//! - 传输：QUIC（quinn 0.11 + rustls ring），ALPN 固定为 `h3`
//! - 认证：HTTP/3 `POST https://hysteria/auth`
//!   - 请求头：`hysteria-auth`（密码）、`hysteria-cc-rx`（客户端声明接收带宽，
//!     bytes/s，0=未配置）、`hysteria-padding`（256–2047 字节随机 ASCII）
//!   - 响应头：`:status 233` = 认证成功；`hysteria-udp: true`（允许 UDP 代理）；
//!     `hysteria-cc-rx`（服务端下行带宽 bytes/s，`0` = 不启用 Brutal / auto）；
//!     `hysteria-padding`
//! - HTTP/3 帧：`[type varint][len varint][payload]`
//!   （DATA=0x0 / HEADERS=0x1 / SETTINGS=0x4）
//! - QPACK 头块：`[Required Insert Count 1B][Delta Base 1B][header ...]`。
//!   本模块编码侧使用 Literal Without Name Reference（RFC 9204 §4.5.6，
//!   无 Huffman）；解码侧额外支持静态表 Indexed / Literal With Name
//!   Reference 与 Huffman 字符串（quic-go 服务端响应头的实际编码格式）
//! - TCP 代理：双向流首 varint = 帧类型 `0x401`，随后
//!   `[addr_len varint][addr "host:port"][padding_len varint][padding]`；
//!   服务端响应 `[status 1B][msg_len varint][msg][padding_len varint][padding]`
//!   （status=0 成功，非 0 失败，msg 为错误说明）
//! - UDP 代理：QUIC datagram，头
//!   `[session_id u32 BE][packet_id u16 BE][frag_id u8][frag_count u8]
//!   [addr_len varint][addr][payload]`；载荷超过 [`MAX_DATAGRAM_PAYLOAD`]
//!   （1197 B，sing-quic `udpMTU = 1200 - 3`）时按片分片，每片携带完整 addr
//! - H3 连接初始化：连接建立后双方各打开 3 条 uni 流
//!   （control=0x00 + SETTINGS / QPACK encoder=0x02 / QPACK decoder=0x03，
//!   RFC 9114 §6.2 + RFC 9204 §4.2），见 [`open_h3_control_streams`]
//!
//! ## 设计原则
//! 只放帧格式、编解码原语与常量；连接管理、认证状态机、UDP 会话调度、
//! 拥塞控制分别在 inbound / outbound 两侧实现（对齐 `protocol/mod.rs` 约定）。

use std::net::IpAddr;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncReadExt;

use crate::inbound::Target;

// ── 常量 ──────────────────────────────────────────────────────────────────────

/// QUIC ALPN（官方 hysteria2 使用 HTTP/3 的 ALPN `h3`）
pub const HY2_ALPN: &[u8] = b"h3";

/// Hysteria2 认证 URL host（固定值）
pub const AUTH_URL_HOST: &str = "hysteria";
/// Hysteria2 认证 URL path（固定值）
pub const AUTH_URL_PATH: &str = "/auth";
/// 认证成功状态码（233）
pub const STATUS_AUTH_OK: u16 = 233;

/// 认证响应头：是否启用 UDP
pub const RESP_HEADER_UDP: &str = "hysteria-udp";
/// 认证响应头：服务端允许的对端发送带宽（bytes/s 或 "auto"/"0"）
pub const RESP_HEADER_CC_RX: &str = "hysteria-cc-rx";

/// TCP 代理请求帧类型（QUIC varint 0x401）
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;

/// HTTP/3 DATA 帧类型（RFC 9114 §7.2.2）
pub const H3_FRAME_DATA: u64 = 0x0;
/// HTTP/3 HEADERS 帧类型（RFC 9114 §7.2.2）
pub const H3_FRAME_HEADERS: u64 = 0x1;
/// HTTP/3 SETTINGS 帧类型（RFC 9114 §7.2.3）
pub const H3_FRAME_SETTINGS: u64 = 0x4;

/// 消息最大长度（防 DoS）
pub const MAX_MESSAGE_LENGTH: u64 = 2048;
/// Padding 最大长度（防 DoS）
pub const MAX_PADDING_LENGTH: u64 = 4096;

/// 单个 QUIC datagram 中可携带的最大用户数据字节数。
/// 与 sing-box 对齐：`udpMTU = 1200 - 3 = 1197`（3 字节预留给 QUIC datagram 头开销）。
pub const MAX_DATAGRAM_PAYLOAD: usize = 1197;

/// QUIC 初始 stream 接收窗口（与 sing-box hysteria/protocol.go 对齐：8 MiB）
pub const QUIC_STREAM_RECEIVE_WINDOW: u64 = 8 * 1024 * 1024; // 8 MiB
/// QUIC 连接级别最大接收窗口（与 sing-box 对齐：20 MiB）
pub const QUIC_MAX_CONNECTION_RECEIVE_WINDOW: u64 = 20 * 1024 * 1024; // 20 MiB

// ── QUIC varint 编解码（RFC 9000 §16）────────────────────────────────────────

/// 写入 QUIC variable-length integer（RFC 9000 §16）
pub fn write_varint(buf: &mut BytesMut, i: u64) {
    if i <= 63 {
        buf.put_u8(i as u8);
    } else if i <= 16383 {
        buf.put_u16((i as u16) | 0x4000);
    } else if i <= 1_073_741_823 {
        buf.put_u32((i as u32) | 0x8000_0000);
    } else {
        buf.put_u64(i | 0xc000_0000_0000_0000);
    }
}

/// 计算一个 QUIC varint 编码后的字节数（1/2/4/8）。
/// 与 [`write_varint`] 的分支完全对应，用于在不分配 `BytesMut` 的前提下
/// 预估 header 长度。
#[inline]
pub fn varint_len(i: u64) -> usize {
    if i <= 63 {
        1
    } else if i <= 16383 {
        2
    } else if i <= 1_073_741_823 {
        4
    } else {
        8
    }
}

/// 从字节切片解码 QUIC varint，返回 (value, bytes_consumed)
pub fn decode_varint_slice(buf: &[u8]) -> anyhow::Result<(u64, usize)> {
    anyhow::ensure!(!buf.is_empty(), "varint: empty buffer");
    let tag = buf[0] >> 6;
    let val = match tag {
        0 => ((buf[0] & 0x3f) as u64, 1),
        1 => {
            anyhow::ensure!(buf.len() >= 2, "varint: truncated 2-byte");
            ((((buf[0] & 0x3f) as u64) << 8) | buf[1] as u64, 2)
        }
        2 => {
            anyhow::ensure!(buf.len() >= 4, "varint: truncated 4-byte");
            (
                (((buf[0] & 0x3f) as u64) << 24)
                    | ((buf[1] as u64) << 16)
                    | ((buf[2] as u64) << 8)
                    | (buf[3] as u64),
                4,
            )
        }
        3 => {
            anyhow::ensure!(buf.len() >= 8, "varint: truncated 8-byte");
            (
                (((buf[0] & 0x3f) as u64) << 56)
                    | ((buf[1] as u64) << 48)
                    | ((buf[2] as u64) << 40)
                    | ((buf[3] as u64) << 32)
                    | ((buf[4] as u64) << 24)
                    | ((buf[5] as u64) << 16)
                    | ((buf[6] as u64) << 8)
                    | (buf[7] as u64),
                8,
            )
        }
        _ => unreachable!(),
    };
    Ok(val)
}

/// 从 AsyncRead 读取 QUIC varint（quinn::RecvStream 实现 AsyncRead + Unpin，
/// 可直接传入）
pub async fn read_varint_async<R: AsyncReadExt + Unpin>(r: &mut R) -> anyhow::Result<u64> {
    let first = r.read_u8().await?;
    let tag = first >> 6;
    let val = match tag {
        0 => (first & 0x3f) as u64,
        1 => {
            let b1 = r.read_u8().await?;
            (((first & 0x3f) as u64) << 8) | (b1 as u64)
        }
        2 => {
            let mut rest = [0u8; 3];
            r.read_exact(&mut rest).await?;
            (((first & 0x3f) as u64) << 24)
                | ((rest[0] as u64) << 16)
                | ((rest[1] as u64) << 8)
                | (rest[2] as u64)
        }
        3 => {
            let mut rest = [0u8; 7];
            r.read_exact(&mut rest).await?;
            (((first & 0x3f) as u64) << 56)
                | ((rest[0] as u64) << 48)
                | ((rest[1] as u64) << 40)
                | ((rest[2] as u64) << 32)
                | ((rest[3] as u64) << 24)
                | ((rest[4] as u64) << 16)
                | ((rest[5] as u64) << 8)
                | (rest[6] as u64)
        }
        _ => unreachable!(),
    };
    Ok(val)
}

// ── HTTP/3 帧辅助 ─────────────────────────────────────────────────────────────

/// 写一个 HTTP/3 frame：`[type varint][len varint][payload]`
pub fn write_h3_frame(buf: &mut BytesMut, frame_type: u64, payload: &[u8]) {
    write_varint(buf, frame_type);
    write_varint(buf, payload.len() as u64);
    buf.put_slice(payload);
}

/// 从 quinn::RecvStream 读取一个 HTTP/3 frame，返回 (frame_type, payload)。
///
/// 注意：本函数会自行读取 frame type varint。如果调用方已经通过
/// [`read_varint_async`] 读过 frame type（例如为了 match 分发帧类型），
/// 请改用 [`read_h3_frame_payload`]，否则会把"长度 varint"错当成
/// "类型 varint"读，导致后续 QPACK payload 解析全部错位
///（典型症状：`qpack payload too short` / 认证阶段莫名失败）。
pub async fn read_h3_frame(recv: &mut quinn::RecvStream) -> anyhow::Result<(u64, Vec<u8>)> {
    let frame_type = read_varint_async(recv).await?;
    let payload = read_h3_frame_payload(recv).await?;
    Ok((frame_type, payload))
}

/// 读取 HTTP/3 frame 的 `[len varint][payload]` 部分，frame type 已由
/// 调用方读取并匹配过。用于 pre-auth 循环等"先读 type 做分支，再读剩余
/// 帧内容"的场景，避免与 [`read_h3_frame`] 重复消费 type varint。
pub async fn read_h3_frame_payload(recv: &mut quinn::RecvStream) -> anyhow::Result<Vec<u8>> {
    let payload_len = read_varint_async(recv).await?;
    // 放宽到 1MB，避免大 HEADERS 帧（含长 padding）被误拒
    anyhow::ensure!(
        payload_len <= 1024 * 1024,
        "h3 frame too large: {payload_len}"
    );
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        recv.read_exact(&mut payload).await?;
    }
    Ok(payload)
}

// ── QPACK 编解码 ──────────────────────────────────────────────────────────────

/// 写单个 literal header（RFC 9204 §4.5.6: Literal Header Field Without Name
/// Reference，不使用 Huffman / 动态表）。
///
/// 第一字节格式：`[0][0][1][N][H][name_len 3-bit prefix]`
///   - bits[7:5] = 0b001（instruction type）
///   - bit[4] = N（never-index flag，0）
///   - bit[3] = H（Huffman for name，0）
///   - bits[2:0] = name 长度的 3-bit prefix integer（RFC 7541 §5.1，prefix=3）
///     若 name_len < 7：直接编入低 3 位；若 >= 7：低 3 位全 1（0b111），
///     后跟 7-bit 前缀续字节（value = 7 + 续字节累加值）
///
/// 紧随其后：name 字节
/// 然后：value string literal `[H=0(bit7)][7-bit prefix length][value 字节]`
pub fn put_literal_header(buf: &mut BytesMut, name: &[u8], value: &[u8]) {
    let nlen = name.len();
    if nlen < 7 {
        buf.put_u8(0x20 | nlen as u8);
    } else {
        buf.put_u8(0x27); // 0x20 | 0x07：3-bit prefix 饱和
        let mut rem = nlen - 7;
        while rem >= 128 {
            buf.put_u8((rem as u8) | 0x80);
            rem >>= 7;
        }
        buf.put_u8(rem as u8);
    }
    buf.put_slice(name);
    // value string literal: H=0（bit7=0），7-bit prefix length
    let vlen = value.len();
    if vlen < 128 {
        buf.put_u8(vlen as u8);
    } else {
        buf.put_u8(0x7f);
        let mut rem = vlen - 127;
        while rem >= 128 {
            buf.put_u8((rem as u8) | 0x80);
            rem >>= 7;
        }
        buf.put_u8(rem as u8);
    }
    buf.put_slice(value);
}

/// QPACK integer 解码（RFC 7541 §5.1），返回 (value, bytes_consumed)
fn qpack_read_int(data: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }
    let mask = (1u8 << prefix_bits) - 1;
    let first = (data[0] & mask) as u64;
    if first < mask as u64 {
        return Some((first, 1));
    }
    // multi-byte
    let mut val = first;
    let mut m = 0u32;
    let mut i = 1usize;
    loop {
        if i >= data.len() {
            return None;
        }
        let b = data[i];
        val += ((b & 0x7f) as u64) << m;
        m += 7;
        i += 1;
        if b & 0x80 == 0 {
            break;
        }
    }
    Some((val, i))
}

/// QPACK 静态表条目（RFC 9204 Appendix A，仅列出认证响应可能出现的条目）
fn qpack_static_entry(idx: u64) -> Option<(&'static str, &'static str)> {
    match idx {
        0 => Some((":authority", "")),
        1 => Some((":path", "/")),
        2 => Some(("age", "0")),
        3 => Some(("content-disposition", "")),
        4 => Some(("content-length", "0")),
        5 => Some(("cookie", "")),
        6 => Some(("date", "")),
        7 => Some(("etag", "")),
        8 => Some(("if-modified-since", "")),
        9 => Some(("if-none-match", "")),
        10 => Some(("last-modified", "")),
        11 => Some(("link", "")),
        12 => Some(("location", "")),
        13 => Some(("referer", "")),
        14 => Some(("set-cookie", "")),
        15 => Some((":method", "CONNECT")),
        16 => Some((":method", "DELETE")),
        17 => Some((":method", "GET")),
        18 => Some((":method", "HEAD")),
        19 => Some((":method", "OPTIONS")),
        20 => Some((":method", "POST")),
        21 => Some((":method", "PUT")),
        22 => Some((":scheme", "http")),
        23 => Some((":scheme", "https")),
        24 => Some((":status", "103")),
        25 => Some((":status", "200")),
        26 => Some((":status", "304")),
        27 => Some((":status", "404")),
        28 => Some((":status", "503")),
        _ => None,
    }
}

/// 从静态表按 index 取 name（用于 Literal With Name Reference）
fn qpack_static_name(idx: u64) -> Option<&'static str> {
    qpack_static_entry(idx).map(|(name, _)| name)
}

/// 从 QPACK header block 中解析所有 header，返回 Vec<(name, value)>
///
/// 支持 quic-go/http3 实际发送的编码格式（RFC 9204）：
///
/// 1. Indexed Header Field（静态表）: 0b1xxxxxxx
/// 2. Literal Header Field With Name Reference（静态表）: 0b0101xxxx
/// 3. Literal Header Field Without Name Reference: 0b001x_xxxx
pub fn parse_headers_from_qpack(payload: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    if payload.len() < 2 {
        anyhow::bail!("qpack payload too short");
    }
    let mut headers = Vec::new();
    let mut i = 2usize; // 跳过 Required Insert Count + Delta Base

    while i < payload.len() {
        let b = payload[i];

        if b & 0x80 != 0 {
            // ── 1. Indexed Header Field（静态表）: 0b1xxxxxxx ─────────────────
            // [1][T][idx(N=6)]：T=1 → 静态表，T=0 → 动态表（认证场景不出现）
            let Some((idx, consumed)) = qpack_read_int(&payload[i..], 6) else {
                break;
            };
            i += consumed;
            if let Some((name, value)) = qpack_static_entry(idx) {
                if !name.is_empty() {
                    headers.push((name.to_string(), value.to_string()));
                }
            }
        } else if b & 0xc0 == 0x40 {
            // ── 2. Literal Field With Name Reference（静态表）────────────────
            // RFC 9204 §4.5.4 / §4.5.5：首字节 0b01xx_xxxx
            //   bit[6]=1, bit[5]=T(静态/动态表), bit[4]=N(never-index)
            //   bits[3:0] = name index 的 4-bit prefix integer（prefix=4）
            // 静态表 name reference: T=1 → 0x50~0x5F
            let Some((idx, consumed)) = qpack_read_int(&payload[i..], 4) else {
                break;
            };
            i += consumed;
            if i >= payload.len() {
                break;
            }
            let val_huffman = payload[i] & 0x80 != 0;
            let Some((val_len, vc)) = qpack_read_int(&payload[i..], 7) else {
                break;
            };
            i += vc;
            let val_len = val_len as usize;
            if i + val_len > payload.len() {
                break;
            }
            let val_bytes = &payload[i..i + val_len];
            i += val_len;
            let value = if val_huffman {
                huffman_decode(val_bytes)
            } else {
                String::from_utf8_lossy(val_bytes).into_owned()
            };
            let name = qpack_static_name(idx).unwrap_or("").to_string();
            headers.push((name, value));
        } else if b & 0xe0 == 0x20 {
            // ── 3. Literal Without Name Reference: 0b001x_xxxx ──────────────
            // RFC 9204 §4.5.6: [0][0][1][N][H][name_len 3-bit prefix]
            let name_huffman = b & 0x08 != 0;
            let Some((name_len, nc)) = qpack_read_int(&payload[i..], 3) else {
                break;
            };
            i += nc;
            let name_len = name_len as usize;
            if i + name_len > payload.len() {
                break;
            }
            let name = if name_huffman {
                huffman_decode(&payload[i..i + name_len])
            } else {
                String::from_utf8_lossy(&payload[i..i + name_len]).into_owned()
            };
            i += name_len;
            if i >= payload.len() {
                break;
            }
            // value string: H = bit7，len = 7-bit prefix integer
            let val_huffman = payload[i] & 0x80 != 0;
            let Some((val_len, vc)) = qpack_read_int(&payload[i..], 7) else {
                break;
            };
            i += vc;
            let val_len = val_len as usize;
            if i + val_len > payload.len() {
                break;
            }
            let val_bytes = &payload[i..i + val_len];
            i += val_len;
            let value = if val_huffman {
                huffman_decode(val_bytes)
            } else {
                String::from_utf8_lossy(val_bytes).into_owned()
            };
            headers.push((name, value));
        } else {
            // 其他格式（Literal With Post-Base Name Reference 等）暂不支持，跳过 1 字节
            i += 1;
        }
    }
    Ok(headers)
}

/// HTTP/2 / QPACK Huffman 解码（RFC 7541 Appendix B，与 RFC 9204 共用）
///
/// quic-go 对响应头 value（"233", "true" 等短 ASCII 字符串）可能启用 Huffman
///（H=1 flag），必须正确解码否则所有响应头 value 均为乱码。
///
/// 实现：按位处理，利用码字唯一前缀性质做贪心匹配。
/// 码字表：(code: u32, len: u8) 索引即为 symbol（0..=256，256=EOS）
fn huffman_decode(data: &[u8]) -> String {
    // RFC 7541 Appendix B Huffman 码字表
    // 每个元素：(码字 u32, 码字位长 u8)，索引 = 符号值
    #[rustfmt::skip]
    static TABLE: [(u32, u8); 257] = [
        (0x1ff8,13),(0x7fffd8,23),(0xfffffe2,28),(0xfffffe3,28),(0xfffffe4,28),
        (0xfffffe5,28),(0xfffffe6,28),(0xfffffe7,28),(0xfffffe8,28),(0xffffea,24),
        (0x3fffffff,30),(0xfffffe9,28),(0xfffffea,28),(0x3ffffffe,30),(0xfffffeb,28),
        (0xfffffec,28),(0xfffffed,28),(0xfffffee,28),(0xfffffef,28),(0xffffff0,28),
        (0xffffff1,28),(0xffffff2,28),(0x3ffffffe,30),(0xffffff3,28),(0xffffff4,28),
        (0xffffff5,28),(0xffffff6,28),(0xffffff7,28),(0xffffff8,28),(0xffffff9,28),
        (0xffffffa,28),(0xffffffb,28),(0x14,6),(0x3f8,10),(0x3f9,10),(0xffa,12),
        (0x1ff9,13),(0x15,6),(0xf8,8),(0x7fa,11),(0x3fa,10),(0x3fb,10),(0xf9,8),
        (0x7fb,11),(0xfa,8),(0x16,6),(0x17,6),(0x18,6),(0x0,5),(0x1,5),(0x2,5),
        (0x19,6),(0x1a,6),(0x1b,6),(0x1c,6),(0x1d,6),(0x1e,6),(0x1f,6),(0x5c,7),
        (0xfb,8),(0x7ffc,15),(0x20,6),(0xffb,12),(0x3fc,10),(0x1ffa,13),(0x21,6),
        (0x5d,7),(0x5e,7),(0x5f,7),(0x60,7),(0x61,7),(0x62,7),(0x63,7),(0x64,7),
        (0x65,7),(0x66,7),(0x67,7),(0x68,7),(0x69,7),(0x6a,7),(0x6b,7),(0x6c,7),
        (0x6d,7),(0x6e,7),(0x6f,7),(0x70,7),(0x71,7),(0x72,7),(0xfc,8),(0x73,7),
        (0xfd,8),(0x1ffb,13),(0x7fff0,19),(0x1ffc,13),(0x3ffc,14),(0x22,6),
        (0x7ffd,15),(0x3,5),(0x23,6),(0x4,5),(0x24,6),(0x5,5),(0x25,6),(0x26,6),
        (0x27,6),(0x6,5),(0x74,7),(0x75,7),(0x28,6),(0x29,6),(0x2a,6),(0x7,5),
        (0x2b,6),(0x76,7),(0x2c,6),(0x8,5),(0x9,5),(0x2d,6),(0x77,7),(0x78,7),
        (0x79,7),(0x7a,7),(0x7b,7),(0x7ffe,15),(0x7fc,11),(0x3ffd,14),(0x1ffd,13),
        (0xffffffc,28),(0xfffe6,20),(0x3fffd2,22),(0xfffe7,20),(0xfffe8,20),
        (0x3fffd3,22),(0x3fffd4,22),(0x3fffd5,22),(0x7fffd9,23),(0x3fffd6,22),
        (0x7fffda,23),(0x7fffdb,23),(0x7fffdc,23),(0x7fffdd,23),(0x7fffde,23),
        (0xffffeb,24),(0x7fffdf,23),(0xffffec,24),(0xffffed,24),(0x3fffd7,22),
        (0x7fffe0,23),(0xffffee,24),(0x7fffe1,23),(0x7fffe2,23),(0x7fffe3,23),
        (0x7fffe4,23),(0x1fffdc,21),(0x3fffd8,22),(0x7fffe5,23),(0x3fffd9,22),
        (0x7fffe6,23),(0x7fffe7,23),(0xffffef,24),(0x3fffda,22),(0x1fffdd,21),
        (0xfffe9,20),(0x3fffdb,22),(0x3fffdc,22),(0x7fffe8,23),(0x7fffe9,23),
        (0x1fffde,21),(0x7fffea,23),(0x3fffdd,22),(0x3fffde,22),(0xfffff0,24),
        (0x1fffdf,21),(0x3fffdf,22),(0x7fffeb,23),(0x7fffec,23),(0x1fffe0,21),
        (0x1fffe1,21),(0x3fffe0,22),(0x1fffe2,21),(0x7fffed,23),(0x3fffe1,22),
        (0x7fffee,23),(0x7fffef,23),(0xfffea,20),(0x3fffe2,22),(0x3fffe3,22),
        (0x3fffe4,22),(0x7ffff0,23),(0x3fffe5,22),(0x3fffe6,22),(0x7ffff1,23),
        (0x3ffffe0,26),(0x3ffffe1,26),(0xfffeb,20),(0x7fff1,19),(0x3fffe7,22),
        (0x7ffff2,23),(0x3fffe8,22),(0x1ffffec,25),(0x3ffffe2,26),(0x3ffffe3,26),
        (0x3ffffe4,26),(0x7ffffde,27),(0x7ffffdf,27),(0x3ffffe5,26),(0xfffff1,24),
        (0x1ffffed,25),(0x7fff2,19),(0x1fffe3,21),(0x3ffffe6,26),(0x7ffffe0,27),
        (0x7ffffe1,27),(0x3ffffe7,26),(0x7ffffe2,27),(0xfffff2,24),(0x1fffe4,21),
        (0x1fffe5,21),(0x3ffffe8,26),(0x3ffffe9,26),(0xffffffd,28),(0x7ffffe3,27),
        (0x7ffffe4,27),(0x7ffffe5,27),(0xfffec,20),(0xfffff3,24),(0xfffed,20),
        (0x1fffe6,21),(0x3fffe9,22),(0x1fffe7,21),(0x1fffe8,21),(0x7ffff3,23),
        (0x3fffea,22),(0x3fffeb,22),(0x1ffffee,25),(0x1ffffef,25),(0xfffff4,24),
        (0xfffff5,24),(0x3ffffea,26),(0x7ffff4,23),(0x3ffffeb,26),(0x7ffffe6,27),
        (0x3ffffec,26),(0x3ffffed,26),(0x7ffffe7,27),(0x7ffffe8,27),(0x7ffffe9,27),
        (0x7ffffea,27),(0x7ffffeb,27),(0xffffffe,28),(0x7ffffec,27),(0x7ffffed,27),
        (0x7ffffee,27),(0x7ffffef,27),(0x7fffff0,27),(0x3ffffee,26),(0x3fffffff,30),
    ];

    // 将输入字节展开成位流，高位在前
    let total_bits = data.len() * 8;
    let mut out = Vec::new();
    let mut bit_pos = 0usize; // 当前读取到第几位

    while bit_pos < total_bits {
        let remaining = total_bits - bit_pos;
        let try_bits = remaining.min(30); // 最长码字 30 位

        // 从 bit_pos 处取最多 try_bits 位（高位对齐）
        let mut window: u64 = 0;
        let mut fetched = 0u32;
        let mut bp = bit_pos;
        while fetched < try_bits as u32 && bp < total_bits {
            let byte_idx = bp / 8;
            let bit_idx = 7 - (bp % 8); // 高位在前
            let bit = ((data[byte_idx] >> bit_idx) & 1) as u64;
            window = (window << 1) | bit;
            fetched += 1;
            bp += 1;
        }

        // 在码字表中找匹配（按码长从短到长贪心；Huffman 码是前缀码，第一个匹配就是正确的）
        let mut matched = false;
        for len in 5u8..=30u8 {
            if len as usize > try_bits {
                break;
            }
            // 取 window 的高 len 位
            let shift = fetched - len as u32;
            let candidate = (window >> shift) as u32;

            // 线性扫描（257 项，认证频率低，可接受）
            for (sym, &(code, code_len)) in TABLE.iter().enumerate() {
                if code_len == len && code == candidate {
                    if sym == 256 {
                        // EOS
                        return String::from_utf8_lossy(&out).into_owned();
                    }
                    out.push(sym as u8);
                    bit_pos += len as usize;
                    matched = true;
                    break;
                }
            }
            if matched {
                break;
            }
        }

        if !matched {
            // 无法解码（填充位或损坏数据），停止
            break;
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

// ── H3 连接初始化（control / QPACK uni 流）───────────────────────────────────

/// 打开 HTTP/3 连接初始化所需的 3 条 uni 流（RFC 9114 §6.2 + RFC 9204 §4.2）：
///
/// 1. control stream（type=0x00）+ 空 SETTINGS 帧
/// 2. QPACK encoder stream（type=0x02）
/// 3. QPACK decoder stream（type=0x03）
///
/// quic-go 的 H3 实现要求对端存在这三条流（尤其 QPACK 两条是 MUST），
/// 否则会以 H3_QPACK_DECOMPRESSION_FAILED(0x200) 等错误拒绝请求。
/// stream 发送后不能 finish（control stream 协议上不可关闭），
/// 由持有 task 挂到连接关闭。
pub async fn open_h3_control_streams(conn: &quinn::Connection) -> anyhow::Result<()> {
    // control stream：type byte + SETTINGS 帧（空 settings，与 quic-go 默认一致）
    let mut ctrl = conn.open_uni().await?;
    ctrl.write_all(&[0x00]).await?;
    let mut settings = BytesMut::new();
    write_h3_frame(&mut settings, H3_FRAME_SETTINGS, &[]);
    ctrl.write_all(&settings).await?;
    let c = conn.clone();
    tokio::spawn(async move {
        c.closed().await;
        drop(ctrl);
    });

    // QPACK encoder stream（即使 table capacity=0 也必须存在）
    let mut enc = conn.open_uni().await?;
    enc.write_all(&[0x02]).await?;
    let c = conn.clone();
    tokio::spawn(async move {
        c.closed().await;
        drop(enc);
    });

    // QPACK decoder stream
    let mut dec = conn.open_uni().await?;
    dec.write_all(&[0x03]).await?;
    let c = conn.clone();
    tokio::spawn(async move {
        c.closed().await;
        drop(dec);
    });

    Ok(())
}

// ── 认证响应 ──────────────────────────────────────────────────────────────────

/// 构造并写出认证成功响应（`:status 233` + `hysteria-udp` + `hysteria-cc-rx`
/// + `hysteria-padding`）。仅写 HEADERS 帧，不 finish（由调用方决定）。
pub async fn write_auth_ok_response(
    send: &mut quinn::SendStream,
    cc_rx: &str,
) -> anyhow::Result<()> {
    let mut qpack = BytesMut::new();
    qpack.put_u8(0x00); // Required Insert Count = 0
    qpack.put_u8(0x00); // S=0, Delta Base = 0
    let status = STATUS_AUTH_OK.to_string();
    put_literal_header(&mut qpack, b":status", status.as_bytes());
    put_literal_header(&mut qpack, b"hysteria-udp", b"true");
    put_literal_header(&mut qpack, b"hysteria-cc-rx", cc_rx.as_bytes());
    put_literal_header(&mut qpack, b"hysteria-padding", random_padding(256, 2048).as_bytes());

    let mut frame = BytesMut::new();
    write_h3_frame(&mut frame, H3_FRAME_HEADERS, &qpack);
    send.write_all(&frame).await?;
    Ok(())
}

/// 构造并写出认证失败响应（`:status 403`）。
pub async fn write_auth_fail_response(send: &mut quinn::SendStream) -> anyhow::Result<()> {
    let mut qpack = BytesMut::new();
    qpack.put_u8(0x00);
    qpack.put_u8(0x00);
    put_literal_header(&mut qpack, b":status", b"403");
    put_literal_header(&mut qpack, b"hysteria-padding", random_padding(64, 256).as_bytes());

    let mut frame = BytesMut::new();
    write_h3_frame(&mut frame, H3_FRAME_HEADERS, &qpack);
    send.write_all(&frame).await?;
    Ok(())
}

/// 构造并写出 404 响应（对非认证的普通 H3 请求做极简 masquerade）。
pub async fn write_h3_not_found_response(send: &mut quinn::SendStream) -> anyhow::Result<()> {
    let mut qpack = BytesMut::new();
    qpack.put_u8(0x00);
    qpack.put_u8(0x00);
    put_literal_header(&mut qpack, b":status", b"404");
    put_literal_header(&mut qpack, b"content-type", b"text/plain");

    let mut frame = BytesMut::new();
    write_h3_frame(&mut frame, H3_FRAME_HEADERS, &qpack);
    send.write_all(&frame).await?;
    Ok(())
}

// ── Padding 生成 ──────────────────────────────────────────────────────────────

/// 生成指定长度范围 [min, max) 内的随机 padding 字符串。
///
/// 使用 `rand::thread_rng`（CSPRNG 种子）保证不可预测性，对抗流量特征分析。
/// 字符集与官方 hysteria `internal/protocol/padding.go` 一致（可打印 ASCII）。
pub fn random_padding(min: usize, max: usize) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: usize = rng.gen_range(min..max);
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..n)
        .map(|_| {
            let idx: usize = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}

// ── 目标地址编解码 ────────────────────────────────────────────────────────────

/// 将 Target 转为 "host:port" 字符串（官方协议地址格式；IPv6 自动带方括号）
pub fn target_to_addr_str(target: &Target) -> String {
    match target {
        Target::Domain(host, port) => format!("{host}:{port}"),
        Target::Socket(addr) => addr.to_string(),
    }
}

/// 将 "host:port"（IPv6 可带方括号）解析回 Target。
/// IP 字面量 → [`Target::Socket`]，域名 → [`Target::Domain`]。
pub fn parse_addr_to_target(s: &str) -> anyhow::Result<Target> {
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("hy2 addr missing port: {s}"))?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("hy2 addr invalid port: {s}"))?;
    anyhow::ensure!(!host.is_empty(), "hy2 addr empty host: {s}");
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(Target::Socket(std::net::SocketAddr::new(ip, port)))
    } else {
        Ok(Target::Domain(host.to_string(), port))
    }
}

// ── TCP 代理请求/响应（quinn 流级）───────────────────────────────────────────

/// 读取 TCP 代理请求（帧类型 0x401 已由调用方消费）：
/// `[addr_len varint][addr "host:port"][padding_len varint][padding]`
pub async fn read_tcp_request(recv: &mut quinn::RecvStream) -> anyhow::Result<String> {
    let addr_len = read_varint_async(recv).await?;
    anyhow::ensure!(
        addr_len > 0 && addr_len <= MAX_MESSAGE_LENGTH,
        "hy2 tcp request: invalid addr_len {addr_len}"
    );
    let mut addr_buf = vec![0u8; addr_len as usize];
    recv.read_exact(&mut addr_buf).await?;
    let addr = String::from_utf8(addr_buf)?;

    let pad_len = read_varint_async(recv).await?;
    anyhow::ensure!(
        pad_len <= MAX_PADDING_LENGTH,
        "hy2 tcp request: padding too long"
    );
    if pad_len > 0 {
        let mut discard = vec![0u8; pad_len as usize];
        let _ = recv.read_exact(&mut discard).await;
    }

    Ok(addr)
}

/// 写出 TCP 代理响应：
/// `[status 1B][msg_len varint][msg][padding_len varint][padding]`
/// （status=0 成功；非 0 失败，msg 为错误说明）。
///
/// 注意：不调用 flush，由调用方在需要立即发出时自行 flush
///（quinn 会缓冲，未 flush 前对端收不到响应字节）。
pub async fn write_tcp_response(
    send: &mut quinn::SendStream,
    ok: bool,
    message: &str,
) -> anyhow::Result<()> {
    let msg = message.as_bytes();
    let padding = random_padding(128, 1024).into_bytes();

    let mut buf = BytesMut::new();
    buf.put_u8(if ok { 0x00 } else { 0x01 });
    write_varint(&mut buf, msg.len() as u64);
    buf.put_slice(msg);
    write_varint(&mut buf, padding.len() as u64);
    buf.put_slice(&padding);

    send.write_all(&buf).await?;
    Ok(())
}

// ── UDP datagram 编解码 ───────────────────────────────────────────────────────

/// 解析 UDP datagram 帧头（跳过 addr），返回 (payload, frag_id, frag_count,
/// session_id, packet_id)。客户端回包接收路径使用（无需 addr 内容）。
pub fn parse_udp_frag_header(buf: &Bytes) -> anyhow::Result<(Bytes, u8, u8, u32, u16)> {
    anyhow::ensure!(buf.len() >= 9, "hy2 udp datagram too short");
    let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_id = buf[6];
    let frag_count = buf[7];
    let mut cur = 8usize;

    // 跳过 addr（addr_len varint + addr bytes）
    anyhow::ensure!(cur < buf.len(), "hy2 udp: missing addr_len");
    let (addr_len, varint_bytes) = decode_varint_slice(&buf[cur..])?;
    cur += varint_bytes;
    anyhow::ensure!(
        buf.len() >= cur + addr_len as usize,
        "hy2 udp: addr truncated in frag header"
    );
    cur += addr_len as usize;

    // 零拷贝切分：buf 是 quinn read_datagram 返回的 Bytes（引用计数底层分配），
    // `slice` 仅偏移+长度，不复制数据。
    let payload = buf.slice(cur..);
    Ok((payload, frag_id, frag_count, session_id, packet_id))
}

/// 解析后的 UDP datagram（服务端入站路径使用：需要 addr 内容）
#[derive(Debug)]
pub struct UdpDatagram {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    /// "host:port" 地址字符串（IPv6 带方括号）
    pub addr: String,
    /// 载荷（零拷贝切片）
    pub payload: Bytes,
}

/// 解析 UDP datagram（含 addr 解码），供服务端入站使用。
pub fn parse_udp_datagram(buf: &Bytes) -> anyhow::Result<UdpDatagram> {
    anyhow::ensure!(buf.len() >= 9, "hy2 udp datagram too short");
    let session_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let packet_id = u16::from_be_bytes([buf[4], buf[5]]);
    let frag_id = buf[6];
    let frag_count = buf[7];
    let mut cur = 8usize;

    anyhow::ensure!(cur < buf.len(), "hy2 udp: missing addr_len");
    let (addr_len, varint_bytes) = decode_varint_slice(&buf[cur..])?;
    cur += varint_bytes;
    anyhow::ensure!(
        addr_len > 0 && addr_len <= MAX_MESSAGE_LENGTH,
        "hy2 udp: invalid addr_len {addr_len}"
    );
    anyhow::ensure!(
        buf.len() >= cur + addr_len as usize,
        "hy2 udp: addr truncated"
    );
    let addr = String::from_utf8_lossy(&buf[cur..cur + addr_len as usize]).into_owned();
    cur += addr_len as usize;

    let payload = buf.slice(cur..);
    Ok(UdpDatagram {
        session_id,
        packet_id,
        frag_id,
        frag_count,
        addr,
        payload,
    })
}

/// 将 UDP payload 按 [`MAX_DATAGRAM_PAYLOAD`] 分片并逐个发送（QUIC datagram）。
///
/// 每个分片的头部格式：
///   [session_id u32 BE][packet_id u16 BE][frag_id u8][frag_count u8]
///   [addr_len varint][addr][data_chunk]
///
/// 与官方 UDPMessage.Serialize 逻辑一致：每片都携带完整 addr 字段。
/// 客户端上行与服务端下行复用同一格式。
pub fn send_udp_fragmented(
    conn: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    addr: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    // 栈上计算头部大小，避免分配 BytesMut
    let header_overhead = 8 + varint_len(addr.len() as u64) + addr.len();
    let chunk_size = MAX_DATAGRAM_PAYLOAD.saturating_sub(header_overhead).max(1);

    if data.len() <= chunk_size {
        // 单分片快路径：一次构造、一次发送，零中间分配
        let mut buf = BytesMut::with_capacity(header_overhead + data.len());
        buf.put_u32(session_id);
        buf.put_u16(packet_id);
        buf.put_u8(0); // frag_id
        buf.put_u8(1); // frag_count
        write_varint(&mut buf, addr.len() as u64);
        buf.put_slice(addr.as_bytes());
        buf.put_slice(data);
        conn.send_datagram(buf.freeze())?;
        return Ok(());
    }

    // 多分片路径：直接迭代 chunks，不 collect 成 Vec
    let frag_count = data.len().div_ceil(chunk_size);
    anyhow::ensure!(
        frag_count <= u8::MAX as usize,
        "hy2 udp: too many fragments ({frag_count})"
    );
    for (frag_id, chunk) in data.chunks(chunk_size).enumerate() {
        let mut hdr = BytesMut::with_capacity(header_overhead + chunk.len());
        hdr.put_u32(session_id);
        hdr.put_u16(packet_id);
        hdr.put_u8(frag_id as u8);
        hdr.put_u8(frag_count as u8);
        write_varint(&mut hdr, addr.len() as u64);
        hdr.put_slice(addr.as_bytes());
        hdr.put_slice(chunk);
        conn.send_datagram(hdr.freeze())?;
    }
    Ok(())
}

/// 构造一个 Hysteria2 UDP datagram 头部（8B 固定头 + addr_len varint + addr）。
/// 仅用于测试（roundtrip）；生产路径由 [`send_udp_fragmented`] 内联构造以减少分配。
#[cfg(test)]
pub(crate) fn build_udp_header(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u32(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_id);
    buf.put_u8(frag_count);
    write_varint(&mut buf, addr.len() as u64);
    buf.put_slice(addr.as_bytes());
    buf
}

// ── QUIC BiStream → AsyncRead + AsyncWrite 适配器 ─────────────────────────────

/// quinn 双向流适配器：把 [`quinn::SendStream`] + [`quinn::RecvStream`]
/// 组合成一个实现 tokio AsyncRead + AsyncWrite 的流（Send + Unpin + 'static），
/// 供 inbound/outbound 两侧装箱为 `Box<dyn AsyncReadWrite>`。
pub struct QuinnBiStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl tokio::io::AsyncRead for QuinnBiStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for QuinnBiStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.send)
            .poll_write(cx, data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for val in [0u64, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, val);
            let (decoded, _) = decode_varint_slice(&buf).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {val}");
        }
    }

    #[test]
    fn varint_len_matches_write_varint() {
        // varint_len 必须与 write_varint 实际写入字节数一致，
        // 否则 send_udp_fragmented 的 chunk_size 计算会出错。
        for val in [0u64, 1, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824] {
            let mut buf = BytesMut::new();
            write_varint(&mut buf, val);
            assert_eq!(varint_len(val), buf.len());
        }
    }

    #[test]
    fn target_addr_roundtrip() {
        let t = Target::Domain("example.com".into(), 443);
        let s = target_to_addr_str(&t);
        assert_eq!(s, "example.com:443");
        match parse_addr_to_target(&s).unwrap() {
            Target::Domain(h, p) => assert_eq!((h.as_str(), p), ("example.com", 443)),
            other => panic!("expected domain, got {other:?}"),
        }

        let t = Target::Socket("1.2.3.4:80".parse().unwrap());
        let s = target_to_addr_str(&t);
        assert_eq!(s, "1.2.3.4:80");
        match parse_addr_to_target(&s).unwrap() {
            Target::Socket(a) => assert_eq!(a.to_string(), "1.2.3.4:80"),
            other => panic!("expected socket, got {other:?}"),
        }

        // IPv6 带方括号
        let t = Target::Socket("[::1]:53".parse().unwrap());
        let s = target_to_addr_str(&t);
        assert_eq!(s, "[::1]:53");
        match parse_addr_to_target(&s).unwrap() {
            Target::Socket(a) => assert_eq!(a.to_string(), "[::1]:53"),
            other => panic!("expected socket, got {other:?}"),
        }

        assert!(parse_addr_to_target("no-port").is_err());
        assert!(parse_addr_to_target("host:bad").is_err());
    }

    #[test]
    fn udp_frag_header_roundtrip() {
        let addr = "example.com:443";
        let data = b"hello";
        let mut buf = build_udp_header(42, 7, 0, 1, addr);
        buf.put_slice(data);
        let frozen = buf.freeze();
        let (payload, frag_id, frag_count, session_id, packet_id) =
            parse_udp_frag_header(&frozen).unwrap();
        assert_eq!(&payload[..], data);
        assert_eq!((frag_id, frag_count, session_id, packet_id), (0, 1, 42, 7));

        let dgram = parse_udp_datagram(&frozen).unwrap();
        assert_eq!(dgram.addr, addr);
        assert_eq!(&dgram.payload[..], data);
        assert_eq!(
            (dgram.session_id, dgram.packet_id, dgram.frag_id, dgram.frag_count),
            (42, 7, 0, 1)
        );
    }

    #[test]
    fn udp_frag_header_multifragment() {
        // 多分片：每个分片头都携带完整 addr，payload 是该分片的数据。
        let addr = "1.2.3.4:80";
        let data = b"abcdefghij"; // 10 bytes
        let frag0 = {
            let mut b = build_udp_header(100, 9, 0, 2, addr);
            b.put_slice(&data[0..5]);
            b.freeze()
        };
        let frag1 = {
            let mut b = build_udp_header(100, 9, 1, 2, addr);
            b.put_slice(&data[5..10]);
            b.freeze()
        };
        let d0 = parse_udp_datagram(&frag0).unwrap();
        let d1 = parse_udp_datagram(&frag1).unwrap();
        assert_eq!(&d0.payload[..], b"abcde");
        assert_eq!(&d1.payload[..], b"fghij");
        assert_eq!((d0.frag_id, d0.frag_count, d0.session_id, d0.packet_id), (0, 2, 100, 9));
        assert_eq!((d1.frag_id, d1.frag_count, d1.session_id, d1.packet_id), (1, 2, 100, 9));
    }

    #[test]
    fn qpack_encode_parse_roundtrip() {
        // put_literal_header 编码的块必须能被 parse_headers_from_qpack 解析
        let mut payload = BytesMut::new();
        payload.put_u8(0x00); // Required Insert Count
        payload.put_u8(0x00); // Delta Base
        for (name, value) in &[
            (&b":status"[..], &b"233"[..]),
            (b"hysteria-udp", b"true"),
            (b"hysteria-cc-rx", b"50000000"),
            (b"hysteria-padding", b"x".repeat(200).as_slice()),
        ] {
            put_literal_header(&mut payload, name, value);
        }
        let headers = parse_headers_from_qpack(&payload).unwrap();
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0], (":status".into(), "233".into()));
        assert_eq!(headers[1], ("hysteria-udp".into(), "true".into()));
        assert_eq!(headers[2], ("hysteria-cc-rx".into(), "50000000".into()));
        assert_eq!(headers[3].0, "hysteria-padding");
        assert_eq!(headers[3].1.len(), 200);
    }

    #[test]
    fn random_padding_length() {
        let p = random_padding(64, 512);
        assert!(p.len() >= 64 && p.len() < 512);
    }
}
