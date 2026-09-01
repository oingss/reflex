//! TUIC v5 协议原语：inbound 服务端与 outbound 客户端共享。
//!
//! 帧格式（对齐 sing-tuic / flux `tuic/proto.rs`，**不是 SOCKS5**）：
//! - Authenticate（uni-stream）：`[Ver=0x05 1B][Cmd=0x00 1B][UUID 16B][Token 32B]`，
//!   Token = TLS `export_keying_material(label=uuid 原始 16B, context=password 字节, 32B)`
//!   （与 flux `connection.rs validate_token`、sing-tuic `clientHandshake` 一致）
//! - Connect（bi-stream，客户端首写时与用户数据合并）：
//!   `[Ver 1B][Cmd=0x01 1B][ADDR+PORT]`
//! - Packet（QUIC datagram 或 uni-stream）：
//!   `[Ver 1B][Cmd=0x02 1B][SessionID 2B BE][PacketID 2B BE][FragTotal 1B][FragID 1B]`
//!   `[DataLen 2B BE][ADDR+PORT][DATA]`；仅 frag_id=0 携带真实 ADDR，
//!   后续分片 ADDR 为 Empty(0xff)
//! - Dissociate（uni-stream）：`[Ver 1B][Cmd=0x03 1B][SessionID 2B BE]`
//! - Heartbeat（datagram）：`[Ver 1B][Cmd=0x04 1B]`
//!
//! 地址编码（sing-tuic AddressSerializer）：
//! - FQDN: `0x00 [len 1B][domain][port 2B BE]`
//! - IPv4: `0x01 [4B ip][port 2B BE]`
//! - IPv6: `0x02 [16B ip][port 2B BE]`
//! - Empty（仅分片占位）: `0xff`

use std::net::{IpAddr, SocketAddr};

use bytes::{BufMut, Bytes, BytesMut};

use crate::inbound::Target;

// ── 协议常量 ─────────────────────────────────────────────────────────────────

/// TUIC 协议版本（v5）
pub const VERSION: u8 = 0x05;

pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;

/// 地址类型：FQDN
pub const ATYP_FQDN: u8 = 0x00;
/// 地址类型：IPv4
pub const ATYP_IPV4: u8 = 0x01;
/// 地址类型：IPv6
pub const ATYP_IPV6: u8 = 0x02;
/// 地址类型：Empty（仅用于多分片 Packet 的后续分片占位）
pub const ATYP_EMPTY: u8 = 0xff;

/// 默认 ALPN（reflex 客户端缺省值；标准 TUIC v5 / flux 服务端用 "h3"，
/// 服务端两个都接受）
pub const TUIC_ALPN: &[u8] = b"tuic";
/// 标准 TUIC v5 ALPN（sing-box / flux 客户端使用）
pub const TUIC_ALPN_H3: &[u8] = b"h3";

/// QUIC 传输参数：单 stream 接收窗口
pub const QUIC_STREAM_WINDOW: u64 = 8 * 1024 * 1024; // 8 MiB
/// QUIC 传输参数：连接级接收窗口
pub const QUIC_CONN_WINDOW: u64 = 15 * 1024 * 1024; // 15 MiB
/// QUIC 空闲超时（毫秒）
pub const IDLE_TIMEOUT_MS: u32 = 30_000; // 30s
/// QUIC keep-alive 间隔（秒）
pub const KEEPALIVE_SECS: u64 = 10;

/// UDP 单个 datagram 中可携带的最大用户数据字节数（与 sing-box tuic/packet.go 对齐）。
/// `udpMTU = 1200 - 3 = 1197`（3 字节预留给 QUIC datagram 头开销）。
/// 超过此值的 UDP 包必须分片发送，否则 `send_datagram` 会返回 DatagramTooLarge。
pub const MAX_DATAGRAM_PAYLOAD: usize = 1197;

/// UDP 分片重组超时（与 sing-box tuic/packet.go 的 LRU 10s 对齐）。
/// 超时未到齐的分片组将被丢弃，防止内存泄漏。
pub const FRAG_REASSEMBLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// ── UUID ─────────────────────────────────────────────────────────────────────

/// 解析 UUID 字符串（容忍带/不带连字符）为 16 字节原始数组。
pub fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "tuic: invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

// ── 地址编解码 ───────────────────────────────────────────────────────────────

/// 解析后的 TUIC 地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedAddr {
    /// Empty(0xff)：多分片 Packet 后续分片的占位地址，不含路由信息
    Empty,
    /// 域名 + 端口
    Domain(String, u16),
    /// IP + 端口
    Socket(SocketAddr),
}

impl ParsedAddr {
    /// 转为路由层 [`Target`]；Empty 无路由信息返回 None。
    pub fn to_target(&self) -> Option<Target> {
        match self {
            Self::Empty => None,
            Self::Domain(d, p) => Some(Target::Domain(d.clone(), *p)),
            Self::Socket(a) => Some(Target::Socket(*a)),
        }
    }
}

/// 同步解析 TUIC 地址（sing-tuic AddressSerializer）。
///
/// 返回 `(地址, 消耗字节数)`。用于 datagram 定长缓冲解析；流式读取场景
/// 先按 ATYP 读定长片段再调用本函数校验。
pub fn parse_address(buf: &[u8]) -> anyhow::Result<(ParsedAddr, usize)> {
    anyhow::ensure!(!buf.is_empty(), "tuic address: empty buffer");
    let atyp = buf[0];
    match atyp {
        ATYP_EMPTY => Ok((ParsedAddr::Empty, 1)),
        ATYP_FQDN => {
            anyhow::ensure!(buf.len() >= 2, "tuic address: truncated FQDN length");
            let len = buf[1] as usize;
            let need = 2 + len + 2;
            anyhow::ensure!(
                buf.len() >= need,
                "tuic address: truncated FQDN (need {need}, got {})",
                buf.len()
            );
            let domain = std::str::from_utf8(&buf[2..2 + len])
                .map_err(|e| anyhow::anyhow!("tuic address: invalid domain utf8: {e}"))?
                .to_string();
            let port = u16::from_be_bytes([buf[2 + len], buf[3 + len]]);
            Ok((ParsedAddr::Domain(domain, port), need))
        }
        ATYP_IPV4 => {
            let need = 1 + 4 + 2;
            anyhow::ensure!(
                buf.len() >= need,
                "tuic address: truncated IPv4 (need {need}, got {})",
                buf.len()
            );
            let ip = std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok((
                ParsedAddr::Socket(SocketAddr::new(IpAddr::V4(ip), port)),
                need,
            ))
        }
        ATYP_IPV6 => {
            let need = 1 + 16 + 2;
            anyhow::ensure!(
                buf.len() >= need,
                "tuic address: truncated IPv6 (need {need}, got {})",
                buf.len()
            );
            let mut seg = [0u16; 8];
            for (i, s) in seg.iter_mut().enumerate() {
                *s = u16::from_be_bytes([buf[1 + i * 2], buf[2 + i * 2]]);
            }
            let ip = std::net::Ipv6Addr::new(
                seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
            );
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok((
                ParsedAddr::Socket(SocketAddr::new(IpAddr::V6(ip), port)),
                need,
            ))
        }
        t => anyhow::bail!("tuic address: unknown atyp 0x{t:02x}"),
    }
}

/// 编码 TUIC 地址（sing-tuic AddressSerializer，**非 SOCKS5**）。
///
/// - FQDN: `0x00 [len u8][domain][port u16 BE]`
/// - IPv4: `0x01 [4B ip][port u16 BE]`
/// - IPv6: `0x02 [16B ip][port u16 BE]`
pub fn write_target(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.put_u8(ATYP_FQDN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
            buf.put_u16(*port);
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(ATYP_IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(ATYP_IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
        },
    }
}

/// 计算 `write_target` 编码后的字节长度（用于分片预算）。
pub fn addr_serialize_len(target: &Target) -> usize {
    match target {
        Target::Domain(host, _) => 1 + 1 + host.len() + 2, // ATYP + len + domain + port
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(_) => 1 + 4 + 2,
            IpAddr::V6(_) => 1 + 16 + 2,
        },
    }
}

// ── 帧构建 ───────────────────────────────────────────────────────────────────

/// 构建 Authenticate 帧：`[Ver][Cmd=0x00][UUID 16B][Token 32B]`（50B）。
pub fn build_authenticate_frame(uuid: &[u8; 16], token: &[u8; 32]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 16 + 32);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_AUTHENTICATE);
    buf.put_slice(uuid);
    buf.put_slice(token);
    buf.freeze()
}

/// 构建 TCP Connect 帧头（不含用户数据；客户端在首次写入时与数据拼接）。
///
/// 与 sing-tuic `clientConn.Write` 一致：
/// `[Ver=0x05 1B][Cmd=0x01 1B][ADDR+PORT]`
pub fn build_connect_header(target: &Target) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 64);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_CONNECT);
    write_target(&mut buf, target);
    buf.freeze()
}

/// 构建 Dissociate 帧（uni-stream）：`[Ver][Cmd=0x03][SessionID 2B BE]`。
pub fn build_dissociate_frame(session_id: u16) -> Bytes {
    let mut buf = BytesMut::with_capacity(4);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_DISSOCIATE);
    buf.put_u16(session_id);
    buf.freeze()
}

/// 构建 Heartbeat datagram：`[Ver][Cmd=0x04]`。
pub fn build_heartbeat_frame() -> Bytes {
    Bytes::from_static(&[VERSION, CMD_HEARTBEAT])
}

/// 构建 UDP Packet datagram（sing-tuic `udpMessage.pack`）。
///
/// 布局：
/// `[Ver 1B][Cmd=0x02 1B][SessionID 2B BE][PacketID 2B BE]`
/// `[FragTotal 1B][FragID 1B][DataLen 2B BE][ADDR+PORT][DATA]`
///
/// 注意 FragTotal 在前、FragID 在后。datagram 中不携带 UUID 与 TOKEN
/// （认证信息已在 Authenticate 帧中发送）。本函数构造**单分片**
/// （frag_total=1, frag_id=0）的 datagram；大包请用 [`send_udp_fragmented`]。
pub fn build_udp_packet(
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    target: &Target,
    data: &[u8],
) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + 2 + 2 + 1 + 1 + 2 + 64 + data.len());
    buf.put_u8(VERSION);
    buf.put_u8(CMD_PACKET);
    buf.put_u16(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_total);
    buf.put_u8(frag_id);
    buf.put_u16(data.len() as u16);
    write_target(&mut buf, target);
    buf.put_slice(data);
    buf.freeze()
}

/// 构建 UDP Packet **帧头**（不含 DATA），供 uni-stream Packet 模式
/// （header + payload 分两次写入）使用。
pub fn build_udp_packet_header(
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    target: &Target,
    data_len: usize,
) -> Bytes {
    let mut buf = BytesMut::with_capacity(10 + 64);
    buf.put_u8(VERSION);
    buf.put_u8(CMD_PACKET);
    buf.put_u16(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_total);
    buf.put_u8(frag_id);
    buf.put_u16(data_len as u16);
    write_target(&mut buf, target);
    buf.freeze()
}

/// 计算单个分片可携带的最大 payload 长度（固定头 10B + ADDR + DataLen 2B 之外）。
fn udp_fragment_chunk_size(target: &Target) -> usize {
    let addr_len = addr_serialize_len(target);
    MAX_DATAGRAM_PAYLOAD.saturating_sub(10 + addr_len + 2).max(1)
}

/// 将一个 UDP 包按 [`MAX_DATAGRAM_PAYLOAD`] 分片并通过 QUIC datagram 发送。
///
/// 与 sing-box tuic/packet.go `fragUDPMessage` + `writePacket` 对齐：
/// - 仅 **frag_id=0** 携带真实目标 ADDR，后续分片 ADDR 置空（ATYP=0xff Empty）
/// - 每个分片的 DataLen = 该分片的数据块长度
/// - frag_total = 分片总数，frag_id 从 0 递增
///
/// 单分片快路径一次构造一次发送，多分片路径直接迭代 chunks。
pub fn send_udp_fragmented(
    conn: &quinn::Connection,
    session_id: u16,
    packet_id: u16,
    target: &Target,
    data: &[u8],
) -> anyhow::Result<()> {
    let chunk_size = udp_fragment_chunk_size(target);

    if data.len() <= chunk_size {
        // 单分片快路径：一次构造、一次发送，零中间分配
        let pkt = build_udp_packet(session_id, packet_id, 0, 1, target, data);
        conn.send_datagram(pkt)
            .map_err(|e| anyhow::anyhow!("tuic send datagram: {e}"))?;
        return Ok(());
    }

    // 多分片路径：直接迭代 chunks，不 collect 成 Vec
    let frag_total = data.len().div_ceil(chunk_size);
    anyhow::ensure!(
        frag_total <= u8::MAX as usize,
        "tuic udp: too many fragments ({frag_total})"
    );
    for (frag_id, chunk) in data.chunks(chunk_size).enumerate() {
        let addr_len = addr_serialize_len(target);
        let mut buf = BytesMut::with_capacity(10 + addr_len + 2 + chunk.len());
        buf.put_u8(VERSION);
        buf.put_u8(CMD_PACKET);
        buf.put_u16(session_id);
        buf.put_u16(packet_id);
        buf.put_u8(frag_total as u8);
        buf.put_u8(frag_id as u8);
        buf.put_u16(chunk.len() as u16);
        if frag_id == 0 {
            // 首片携带真实目标
            write_target(&mut buf, target);
        } else {
            // 后续分片 ADDR 置空（Empty 类型 = 0xff，与 sing-box AddressSerializer 一致）
            buf.put_u8(ATYP_EMPTY);
        }
        buf.put_slice(chunk);
        conn.send_datagram(buf.freeze())
            .map_err(|e| anyhow::anyhow!("tuic send datagram: {e}"))?;
    }
    Ok(())
}

// ── 帧解析 ───────────────────────────────────────────────────────────────────

/// 判断 2 字节前缀是否形如 TUIC 命令（对齐 flux `Command::is_tuic_prefix`）。
pub fn is_tuic_prefix(prefix: [u8; 2]) -> bool {
    prefix[0] == VERSION && prefix[1] <= CMD_HEARTBEAT
}

/// 从收到的 UDP Packet datagram 中解析出关键元信息（不含地址详情）。
///
/// 布局（与 `build_udp_packet` 对应）：
/// `[Ver 1B][Cmd 1B][SessionID 2B][PacketID 2B]`
/// `[FragTotal 1B][FragID 1B][DataLen 2B][ADDR ...][DATA]`
///
/// 返回 (session_id, packet_id, frag_total, frag_id, data_len, data_offset)。
/// data_offset 指向 DATA 起始位置；调用方据此切片。
pub fn parse_udp_packet_meta(data: &[u8]) -> Option<(u16, u16, u8, u8, usize, usize)> {
    const MIN_HDR: usize = 10;
    if data.len() < MIN_HDR {
        return None;
    }
    if data[0] != VERSION || data[1] != CMD_PACKET {
        return None;
    }
    let session_id = u16::from_be_bytes([data[2], data[3]]);
    let packet_id = u16::from_be_bytes([data[4], data[5]]);
    let frag_total = data[6];
    let frag_id = data[7];
    let data_len = u16::from_be_bytes([data[8], data[9]]) as usize;

    // 跳过 ADDR（可变长）定位 DATA 起始
    let mut cur = 10usize;
    if cur >= data.len() {
        return None;
    }
    let atyp = data[cur];
    cur += 1;
    match atyp {
        ATYP_FQDN => {
            // FQDN: [len 1B][domain][port 2B]
            if cur >= data.len() {
                return None;
            }
            let dlen = data[cur] as usize;
            cur += 1 + dlen + 2;
        }
        ATYP_IPV4 => {
            // IPv4: [4B ip][port 2B]
            cur += 4 + 2;
        }
        ATYP_IPV6 => {
            // IPv6: [16B ip][port 2B]
            cur += 16 + 2;
        }
        ATYP_EMPTY => {
            // Empty（后续分片的占位 ADDR）
        }
        _ => return None,
    }
    if cur + data_len > data.len() {
        return None;
    }
    Some((session_id, packet_id, frag_total, frag_id, data_len, cur))
}

/// 解析后的 UDP Packet datagram 完整元信息（服务端用）。
#[derive(Debug, Clone)]
pub struct UdpPacketMeta {
    pub session_id: u16,
    pub packet_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    /// frag_id=0 携带的目标地址；后续分片为 Empty
    pub addr: ParsedAddr,
    /// DATA 起始偏移（相对 datagram 起始）
    pub data_offset: usize,
    /// DATA 长度
    pub data_len: usize,
}

/// 解析一个完整的 UDP Packet datagram（服务端 datagram 路径用）。
///
/// 在 [`parse_udp_packet_meta`] 的基础上额外解析出 ADDR。
pub fn parse_udp_datagram(data: &[u8]) -> Option<UdpPacketMeta> {
    let (session_id, packet_id, frag_total, frag_id, data_len, data_offset) =
        parse_udp_packet_meta(data)?;
    let (addr, _) = parse_address(&data[10..]).ok()?;
    Some(UdpPacketMeta {
        session_id,
        packet_id,
        frag_total,
        frag_id,
        addr,
        data_offset,
        data_len,
    })
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u[0], 0xaa);
        assert_eq!(u[15], 0xee);
    }

    #[test]
    fn parse_uuid_no_dashes() {
        let u = parse_uuid("aabbccdd11223344aabbccdd11223344").unwrap();
        assert_eq!(u.len(), 16);
    }

    #[test]
    fn parse_uuid_invalid() {
        assert!(parse_uuid("zzzz").is_err());
    }

    #[test]
    fn address_fqdn_roundtrip() {
        let target = Target::Domain("example.com".into(), 443);
        let mut buf = BytesMut::new();
        write_target(&mut buf, &target);
        let (addr, used) = parse_address(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(
            addr,
            ParsedAddr::Domain("example.com".to_string(), 443)
        );
        assert_eq!(addr.to_target(), Some(target));
    }

    #[test]
    fn address_ipv4_roundtrip() {
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let mut buf = BytesMut::new();
        write_target(&mut buf, &target);
        assert_eq!(buf[0], ATYP_IPV4);
        let (addr, used) = parse_address(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(addr.to_target(), Some(target));
    }

    #[test]
    fn address_ipv6_roundtrip() {
        let target = Target::Socket("[2001:db8::1]:443".parse().unwrap());
        let mut buf = BytesMut::new();
        write_target(&mut buf, &target);
        assert_eq!(buf[0], ATYP_IPV6);
        let (addr, used) = parse_address(&buf).unwrap();
        assert_eq!(used, buf.len());
        assert_eq!(addr.to_target(), Some(target));
    }

    #[test]
    fn address_empty() {
        let (addr, used) = parse_address(&[0xff]).unwrap();
        assert_eq!(used, 1);
        assert_eq!(addr, ParsedAddr::Empty);
        assert!(addr.to_target().is_none());
    }

    #[test]
    fn address_truncated_rejected() {
        assert!(parse_address(&[0x00, 11, b'e']).is_err());
        assert!(parse_address(&[0x01, 1, 2, 3]).is_err());
        assert!(parse_address(&[0x09]).is_err());
    }

    #[test]
    fn authenticate_frame_layout() {
        let uuid = [0xAA; 16];
        let token = [0xBB; 32];
        let f = build_authenticate_frame(&uuid, &token);
        assert_eq!(f.len(), 50);
        assert_eq!(f[0], VERSION);
        assert_eq!(f[1], CMD_AUTHENTICATE);
        assert_eq!(&f[2..18], &uuid[..]);
        assert_eq!(&f[18..50], &token[..]);
    }

    #[test]
    fn dissociate_frame_layout() {
        let f = build_dissociate_frame(0x1234);
        assert_eq!(f.as_ref(), &[0x05, 0x03, 0x12, 0x34]);
    }

    #[test]
    fn heartbeat_frame_layout() {
        assert_eq!(build_heartbeat_frame().as_ref(), &[0x05, 0x04]);
    }

    #[test]
    fn is_tuic_prefix_ok() {
        assert!(is_tuic_prefix([0x05, 0x00]));
        assert!(is_tuic_prefix([0x05, 0x04]));
        assert!(!is_tuic_prefix([0x04, 0x00]));
        assert!(!is_tuic_prefix([0x05, 0x05]));
    }

    #[test]
    fn udp_datagram_roundtrip_with_address() {
        let target = Target::Domain("example.com".into(), 443);
        let pkt = build_udp_packet(0x1234, 0x5678, 0, 1, &target, b"hello");
        let meta = parse_udp_datagram(&pkt).expect("parse ok");
        assert_eq!(meta.session_id, 0x1234);
        assert_eq!(meta.packet_id, 0x5678);
        assert_eq!(meta.frag_total, 1);
        assert_eq!(meta.frag_id, 0);
        assert_eq!(meta.addr.to_target(), Some(target));
        assert_eq!(meta.data_len, 5);
        assert_eq!(&pkt[meta.data_offset..meta.data_offset + 5], b"hello");
    }

    #[test]
    fn udp_datagram_empty_addr_fragment() {
        // 模拟后续分片（ATYP=0xff Empty）
        let mut buf = BytesMut::new();
        buf.put_u8(VERSION);
        buf.put_u8(CMD_PACKET);
        buf.put_u16(0x1234u16); // session
        buf.put_u16(0x0001u16); // packet_id
        buf.put_u8(2); // frag_total
        buf.put_u8(1); // frag_id
        buf.put_u16(4u16); // data_len
        buf.put_u8(0xff); // Empty ADDR
        buf.put_slice(b"frag");
        let meta = parse_udp_datagram(&buf).expect("parse ok");
        assert_eq!(meta.addr, ParsedAddr::Empty);
        assert_eq!(meta.data_offset, 11);
        assert_eq!(meta.data_len, 4);
    }
}
