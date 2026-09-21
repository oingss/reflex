//! VLESS 协议原语：inbound 服务端与 outbound 客户端共享。
//!
//! 帧格式（对齐 v2ray VLESS 协议）：
//! - 请求头（TCP）：`[Ver 1B][UUID 16B][AddonLen 1B][Addon ...][Cmd 1B][Port 2B BE][ATYP+ADDR]`
//! - 请求头（UDP）：同上，Cmd=0x02
//! - 响应头：`[Ver 1B][AddonLen 1B][Addon ...]`
//! - UDP over WebSocket/TCP 分帧：`[LEN 2B BE][DATA]`
//!
//!Addon 格式（protobuf-like，用于携带 Vision flow）：
//!   `[field 1 tag=0x0a][varint len][Flow string bytes]`

use crate::inbound::Target;
use bytes::{BufMut, Bytes, BytesMut};
use std::net::IpAddr;

/// VLESS 协议版本
pub const VERSION: u8 = 0x00;

/// 命令类型
pub mod command {
    pub const TCP: u8 = 0x01;
    pub const UDP: u8 = 0x02;
}

/// 地址类型
pub mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x02;
    pub const IPV6: u8 = 0x03;
}

/// protobuf varint 编码（用于 addon 的 Flow 字段长度）
pub fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

/// 解析 UUID 字符串为 16 字节（与 v2ray `uuid.ParseStr` 对齐）。
pub fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

// ── 请求头构造（outbound 客户端用） ──────────────────────────────────────────

/// 构建 VLESS 请求头（支持 TCP/UDP，支持 Vision flow addon）。
///
/// `flow = Some("xtls-rprx-vision")` 时 addon 中携带 Flow 字段。
/// `cmd` 为 [`command::TCP`] 或 [`command::UDP`]。
pub fn build_request_header(
    uuid: &[u8; 16],
    target: &Target,
    cmd: u8,
    flow: Option<&str>,
) -> anyhow::Result<BytesMut> {
    let mut buf = BytesMut::with_capacity(64);

    // 构建 addon（protobuf-like，仅 flow 非空时携带）
    let addon_bytes = if let Some(flow) = flow {
        if !flow.is_empty() {
            // protobuf: field 1 (Flow), wire type 2 (length-delimited)
            // tag = (field_number << 3) | wire_type = (1 << 3) | 2 = 0x0a
            let mut addon = Vec::new();
            addon.push((0x01 << 3) | 0x02); // 0x0a
            let flow_bytes = flow.as_bytes();
            write_varint(&mut addon, flow_bytes.len() as u64);
            addon.extend_from_slice(flow_bytes);
            addon
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    buf.put_u8(VERSION);
    buf.put_slice(uuid);
    buf.put_u8(addon_bytes.len() as u8);
    buf.extend_from_slice(&addon_bytes);
    buf.put_u8(cmd);
    buf.put_u16(target.port());
    write_addr(&mut buf, target);
    Ok(buf)
}

/// 构建 TCP 请求头（cmd=0x01，便捷封装）。
pub fn build_tcp_request(uuid: &[u8; 16], target: &Target, flow: Option<&str>) -> anyhow::Result<Bytes> {
    Ok(build_request_header(uuid, target, command::TCP, flow)?.freeze())
}

/// 构建 UDP 请求头（cmd=0x02，便捷封装）。
pub fn build_udp_request(uuid: &[u8; 16], target: &Target) -> anyhow::Result<Bytes> {
    Ok(build_request_header(uuid, target, command::UDP, None)?.freeze())
}

// ── 请求头解析（inbound 服务端用） ────────────────────────────────────────────

/// 解析后的 VLESS 请求头。
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// 客户端 UUID（16 字节）
    pub uuid: [u8; 16],
    /// addon 原始字节（含 flow 等，可能为空）
    pub addon: Bytes,
    /// 命令类型（TCP=0x01 / UDP=0x02）
    pub command: u8,
    /// 目标地址
    pub target: Target,
    /// 消耗的字节数（含 addon）
    pub consumed: usize,
}

/// 从缓冲区解析 VLESS 请求头。
///
/// 返回 [`ParsedRequest`]，其中 `consumed` 指示请求头总长度，
/// 调用方据此分离请求头与后续 payload。
pub fn parse_request(buf: &[u8]) -> anyhow::Result<ParsedRequest> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    anyhow::ensure!(buf.len() >= 18, "vless request too short (need >=18 for ver+uuid+addonlen+cmd)");
    anyhow::ensure!(buf[0] == VERSION, "unsupported vless version: {}", buf[0]);

    let mut cur = 1usize;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&buf[cur..cur + 16]);
    cur += 16;

    let addon_len = buf[cur] as usize;
    cur += 1;
    anyhow::ensure!(buf.len() >= cur + addon_len + 3, "vless request: addon truncated");
    let addon = Bytes::copy_from_slice(&buf[cur..cur + addon_len]);
    cur += addon_len;

    let command = buf[cur];
    cur += 1;

    anyhow::ensure!(buf.len() >= cur + 2, "vless request: port truncated");
    let port = u16::from_be_bytes([buf[cur], buf[cur + 1]]);
    cur += 2;

    anyhow::ensure!(buf.len() > cur, "vless request: addr truncated (no atyp)");
    let atyp = buf[cur];
    cur += 1;

    let target = match atyp {
        atyp::IPV4 => {
            anyhow::ensure!(buf.len() >= cur + 4, "vless: ipv4 addr truncated");
            let ip = Ipv4Addr::new(buf[cur], buf[cur + 1], buf[cur + 2], buf[cur + 3]);
            cur += 4;
            Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        atyp::IPV6 => {
            anyhow::ensure!(buf.len() >= cur + 16, "vless: ipv6 addr truncated");
            let ip: [u8; 16] = buf[cur..cur + 16].try_into()?;
            cur += 16;
            Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        atyp::DOMAIN => {
            anyhow::ensure!(buf.len() > cur, "vless: domain len truncated");
            let dlen = buf[cur] as usize;
            cur += 1;
            anyhow::ensure!(buf.len() >= cur + dlen, "vless: domain truncated");
            let domain = String::from_utf8(buf[cur..cur + dlen].to_vec())?;
            cur += dlen;
            Target::Domain(domain, port)
        }
        other => anyhow::bail!("unknown vless atyp: 0x{other:02x}"),
    };

    Ok(ParsedRequest {
        uuid,
        addon,
        command,
        target,
        consumed: cur,
    })
}

// ── 响应头构造与解析 ──────────────────────────────────────────────────────────

/// 构建 VLESS 响应头（服务端→客户端）。标准响应：`[Ver 1B][AddonLen 1B=0]`。
pub fn build_response() -> Bytes {
    let mut buf = BytesMut::with_capacity(2);
    buf.put_u8(VERSION);
    buf.put_u8(0); // addon len = 0
    buf.freeze()
}

/// 解析 VLESS 响应头，返回响应头长度（客户端跳过用）。
pub fn parse_response(buf: &[u8]) -> anyhow::Result<usize> {
    anyhow::ensure!(buf.len() >= 2, "vless response too short");
    anyhow::ensure!(buf[0] == VERSION, "unsupported vless version: {}", buf[0]);
    let addon_len = buf[1] as usize;
    anyhow::ensure!(buf.len() >= 2 + addon_len, "vless response truncated");
    Ok(2 + addon_len)
}

// ── 地址编解码（请求头复用） ──────────────────────────────────────────────────

/// 将目标地址写入缓冲区（VLESS ATYP+ADDR+PORT 格式）。
pub fn write_addr(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, _) => {
            buf.put_u8(atyp::DOMAIN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(atyp::IPV4);
                buf.put_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(atyp::IPV6);
                buf.put_slice(&ip.octets());
            }
        },
    }
}

// ── UDP over WebSocket/TCP 分帧 ────────────────────────────────────────────────
//
// 每个 UDP 包在 WebSocket/TCP 流上用 2 字节大端长度前缀分帧：
//   [DATA_LEN 2B BE][DATA ...]
// 与 TCP 的区别：TCP 是纯透明转发；UDP 需要分帧以保持包边界。
// 发往服务端的第一帧同样包含 VLESS 请求头（Command=0x02 UDP）。

/// 将 UDP payload 封装为带长度前缀的帧
pub fn encode_udp_frame(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(2 + payload.len());
    buf.put_u16(payload.len() as u16);
    buf.put_slice(payload);
    buf.freeze()
}

/// 从字节流中解析出一个 UDP 帧的载荷长度，返回 (帧头占用字节数=2, 数据长度)
pub fn decode_udp_frame_len(buf: &[u8]) -> anyhow::Result<(usize, usize)> {
    anyhow::ensure!(
        buf.len() >= 2,
        "vless udp frame: need at least 2 bytes for length"
    );
    let data_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    Ok((2, data_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let uuid = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(uuid[0], 0xaa);
        assert_eq!(uuid[15], 0xee);
    }

    #[test]
    fn build_request_header_domain() {
        let uuid = [0xau8; 16];
        let target = Target::Domain("example.com".into(), 443);
        let hdr = build_request_header(&uuid, &target, command::TCP, None).unwrap();
        assert_eq!(hdr[0], 0x00);
        assert_eq!(&hdr[1..17], &uuid);
        assert_eq!(hdr[17], 0x00); // addon len
        assert_eq!(hdr[18], 0x01); // cmd TCP
        assert_eq!(u16::from_be_bytes([hdr[19], hdr[20]]), 443);
        assert_eq!(hdr[21], 0x02); // atyp domain
    }

    #[test]
    fn request_roundtrip_domain() {
        let uuid = [0xau8; 16];
        let target = Target::Domain("example.com".into(), 443);
        let hdr = build_tcp_request(&uuid, &target, None).unwrap();
        let parsed = parse_request(&hdr).unwrap();
        assert_eq!(parsed.uuid, uuid);
        assert_eq!(parsed.command, command::TCP);
        match parsed.target {
            Target::Domain(ref h, p) => {
                assert_eq!(h, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain"),
        }
        assert_eq!(parsed.consumed, hdr.len());
    }

    #[test]
    fn request_roundtrip_ipv4() {
        let uuid = [0u8; 16];
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let hdr = build_tcp_request(&uuid, &target, None).unwrap();
        let parsed = parse_request(&hdr).unwrap();
        match parsed.target {
            Target::Socket(a) => {
                assert_eq!(a.ip().to_string(), "1.2.3.4");
                assert_eq!(a.port(), 80);
            }
            _ => panic!("expected socket"),
        }
    }

    #[test]
    fn request_roundtrip_flow() {
        let uuid = [0xau8; 16];
        let target = Target::Domain("example.com".into(), 443);
        let hdr = build_tcp_request(&uuid, &target, Some("xtls-rprx-vision")).unwrap();
        // addon len 应非 0
        assert_ne!(hdr[17], 0);
        let parsed = parse_request(&hdr).unwrap();
        assert!(!parsed.addon.is_empty());
        assert_eq!(parsed.consumed, hdr.len());
    }

    #[test]
    fn response_roundtrip() {
        let resp = build_response();
        assert_eq!(resp.as_ref(), &[0x00, 0x00]);
        assert_eq!(parse_response(&resp).unwrap(), 2);
        assert!(parse_response(&[0x01, 0x00]).is_err());
    }

    #[test]
    fn udp_frame_roundtrip() {
        let data = b"hello dns";
        let frame = encode_udp_frame(data);
        assert_eq!(frame.len(), 2 + data.len());
        let (hdr, dlen) = decode_udp_frame_len(&frame).unwrap();
        assert_eq!(hdr, 2);
        assert_eq!(dlen, data.len());
        assert_eq!(&frame[hdr..hdr + dlen], data);
    }

    #[test]
    fn udp_frame_too_short() {
        assert!(decode_udp_frame_len(&[0x00]).is_err());
    }
}
