//! Trojan 协议原语：inbound 服务端与 outbound 客户端共享。
//!
//! 帧格式（对齐 trojan-go / sing-box protocol/trojan）：
//! - TCP 请求头：`[SHA224(password) hex 56B][CRLF][CMD 1B][SOCKS_addr][CRLF]`
//! - UDP over TCP 请求头：同上，CMD=0x03
//! - UDP 分帧：`[SOCKS_addr][LEN 2B BE][CRLF 2B][DATA]`
//! - 服务端无响应头（TLS 握手成功后直接透传）
//!
//! 覆盖：
//! - [`derive_key`]：SHA-224(password) → hex 56 字节
//! - 请求头构造：[`build_tcp_header`] / [`build_udp_handshake`]（客户端用）
//! - 请求头解析：[`parse_request`]（服务端用）
//! - UDP 帧构造与解析：[`build_udp_frame`] / [`read_udp_frame_addr`]
//! - SOCKS 地址编解码：[`write_addr`] / [`read_socks_addr`]

use crate::inbound::Target;
use bytes::{BufMut, Bytes, BytesMut};
use sha2::Digest;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

// ── 常量 ──────────────────────────────────────────────────────────────────────

/// SHA-224 输出后 hex 编码的长度（28 字节 × 2）
pub const KEY_LEN: usize = 56;

pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x03;

pub mod atyp {
    pub const IPV4: u8 = 0x01;
    pub const DOMAIN: u8 = 0x03;
    pub const IPV6: u8 = 0x04;
}

/// Trojan UDP 帧最大载荷（防 DoS）。
pub const MAX_UDP_PAYLOAD: usize = 65535;

pub const CRLF: &[u8] = b"\r\n";

// ── 密钥派生 ──────────────────────────────────────────────────────────────────

/// 计算 Trojan 密钥：SHA-224(password) → hex → 56 字节 ASCII。
///
/// 与 sing-box `protocol/trojan` 的 `Key()` 函数对齐。
pub fn derive_key(password: &str) -> [u8; KEY_LEN] {
    let hash = sha2::Sha224::digest(password.as_bytes());
    let hex = hex::encode(hash);
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(hex.as_bytes());
    key
}

// ── 请求头构造（outbound 客户端用） ──────────────────────────────────────────

/// 构建 Trojan TCP 请求头（不含 payload）。
///
/// `[key 56B][CRLF][CMD_TCP 1B][SOCKS_addr][CRLF]`
pub fn build_tcp_header(key: &[u8; KEY_LEN], target: &Target) -> BytesMut {
    let mut buf = BytesMut::with_capacity(KEY_LEN + 2 + 1 + 1 + 256 + 2 + 2);
    buf.put_slice(key);
    buf.put_slice(CRLF);
    buf.put_u8(CMD_TCP);
    write_addr(&mut buf, target);
    buf.put_slice(CRLF);
    buf
}

/// 构建 Trojan UDP 请求头（不含 UDP 分帧，仅握手部分）。
///
/// `[key 56B][CRLF][CMD_UDP 1B][SOCKS_addr][CRLF]`
pub fn build_udp_handshake(key: &[u8; KEY_LEN], target: &Target) -> BytesMut {
    let mut buf = BytesMut::with_capacity(KEY_LEN + 2 + 1 + 1 + 256 + 2 + 2);
    buf.put_slice(key);
    buf.put_slice(CRLF);
    buf.put_u8(CMD_UDP);
    write_addr(&mut buf, target);
    buf.put_slice(CRLF);
    buf
}

// ── 请求头解析（inbound 服务端用） ────────────────────────────────────────────

/// 解析后的 Trojan 请求头。
#[derive(Debug, Clone)]
pub struct ParsedRequest {
    /// SHA224(password) hex（56 字节，用于与配置的密码校验）
    pub key_hex: [u8; KEY_LEN],
    /// 命令类型（TCP=0x01 / UDP=0x03）
    pub command: u8,
    /// 目标地址
    pub target: Target,
    /// 消耗的字节数（key + CRLF + CMD + addr + CRLF）
    pub consumed: usize,
}

/// 从缓冲区解析 Trojan 请求头。
///
/// 调用方需先确保 buf 至少含 `KEY_LEN + 2`（key + CRLF）。
/// 解析后 `consumed` 指向请求头结尾，后续即 payload（TCP）或 UDP 分帧。
pub fn parse_request(buf: &[u8]) -> anyhow::Result<ParsedRequest> {
    // 最小长度：key(56) + CRLF(2) + cmd(1) + atyp(1) = 60
    anyhow::ensure!(buf.len() >= 60, "trojan request too short");

    let mut key_hex = [0u8; KEY_LEN];
    key_hex.copy_from_slice(&buf[..KEY_LEN]);

    // CRLF
    anyhow::ensure!(&buf[KEY_LEN..KEY_LEN + 2] == CRLF, "trojan: bad CRLF after key");
    let mut cur = KEY_LEN + 2;

    let command = buf[cur];
    cur += 1;
    anyhow::ensure!(
        command == CMD_TCP || command == CMD_UDP,
        "trojan: unsupported command 0x{command:02x}"
    );

    // 解析 SOCKS_addr（变长）
    let (addr_len, target) = read_socks_addr(&buf[cur..])?;
    cur += addr_len;

    // 尾部 CRLF
    anyhow::ensure!(buf.len() >= cur + 2, "trojan: trailing CRLF truncated");
    anyhow::ensure!(&buf[cur..cur + 2] == CRLF, "trojan: bad trailing CRLF");
    cur += 2;

    Ok(ParsedRequest {
        key_hex,
        command,
        target,
        consumed: cur,
    })
}

// ── UDP 帧构造与解析 ──────────────────────────────────────────────────────────

/// 构建 Trojan UDP 帧（握手后每个包的格式）。
///
/// `[SOCKS_addr][LEN 2B BE][CRLF 2B][DATA]`
pub fn build_udp_frame(target: &Target, data: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(256 + data.len());
    write_addr(&mut buf, target);
    buf.put_u16(data.len() as u16);
    buf.put_slice(CRLF);
    buf.put_slice(data);
    buf.freeze()
}

/// 读取 Trojan UDP 帧的地址部分，返回 (地址消耗字节数, 目标)。
///
/// 帧格式：`[SOCKS_addr][LEN 2B BE][CRLF 2B][DATA]`
/// 此函数只解析 SOCKS_addr 部分，调用方后续自行读 LEN+CRLF+DATA。
pub fn read_udp_frame_addr(addr_buf: &[u8]) -> anyhow::Result<(usize, Target)> {
    read_socks_addr(addr_buf)
}

// ── SOCKS 地址编解码 ──────────────────────────────────────────────────────────

/// 将目标地址写入缓冲区（SOCKS5 地址格式：ATYP + ADDR + PORT）。
///
/// Trojan 的 ATYP：IPv4=0x01, Domain=0x03, IPv6=0x04。
pub fn write_addr(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.put_u8(atyp::DOMAIN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
            buf.put_u16(*port);
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.put_u8(atyp::IPV4);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
            IpAddr::V6(ip) => {
                buf.put_u8(atyp::IPV6);
                buf.put_slice(&ip.octets());
                buf.put_u16(addr.port());
            }
        },
    }
}

/// 从字节流中读取一个 SOCKS5 地址，返回 (消耗字节数, 目标地址)。
///
/// 与 sing-box `M.SocksaddrSerializer.ReadAddrPort` 行为一致：
/// - IPv4: 0x01 + 4B ip + 2B port = 7B
/// - IPv6: 0x04 + 16B ip + 2B port = 19B
/// - Domain: 0x03 + 1B len + domain + 2B port = 4..259B
pub fn read_socks_addr(data: &[u8]) -> anyhow::Result<(usize, Target)> {
    anyhow::ensure!(!data.is_empty(), "truncated");
    let atyp = data[0];
    match atyp {
        atyp::IPV4 => {
            anyhow::ensure!(data.len() >= 7, "ipv4 truncated");
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((7, Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))))
        }
        atyp::IPV6 => {
            anyhow::ensure!(data.len() >= 19, "ipv6 truncated");
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                19,
                Target::Socket(SocketAddr::new(IpAddr::V6(ip.into()), port)),
            ))
        }
        atyp::DOMAIN => {
            anyhow::ensure!(data.len() >= 2, "domain truncated (no len)");
            let dlen = data[1] as usize;
            anyhow::ensure!(data.len() >= 4 + dlen, "domain truncated");
            let domain = String::from_utf8(data[2..2 + dlen].to_vec())?;
            let port = u16::from_be_bytes([data[2 + dlen], data[3 + dlen]]);
            Ok((4 + dlen, Target::Domain(domain, port)))
        }
        _ => anyhow::bail!("unknown address type: 0x{atyp:02x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_known_vector() {
        // SHA-224("password") = d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01
        let key = derive_key("password");
        let hex = std::str::from_utf8(&key).unwrap();
        assert!(hex.starts_with("d63dc919"), "unexpected key prefix: {hex}");
        assert_eq!(key.len(), 56);
    }

    #[test]
    fn build_tcp_header_domain() {
        let key = derive_key("password");
        let target = Target::Domain("example.com".into(), 443);
        let hdr = build_tcp_header(&key, &target);
        assert_eq!(&hdr[..56], &key);
        assert_eq!(&hdr[56..58], CRLF);
        assert_eq!(hdr[58], CMD_TCP);
        assert_eq!(hdr[59], atyp::DOMAIN);
        assert_eq!(hdr[60], "example.com".len() as u8);
    }

    #[test]
    fn request_roundtrip_tcp_domain() {
        let key = derive_key("mypassword");
        let target = Target::Domain("target.example".into(), 80);
        let hdr = build_tcp_header(&key, &target);
        let parsed = parse_request(&hdr).unwrap();
        assert_eq!(parsed.key_hex, key);
        assert_eq!(parsed.command, CMD_TCP);
        match parsed.target {
            Target::Domain(ref h, p) => {
                assert_eq!(h, "target.example");
                assert_eq!(p, 80);
            }
            _ => panic!("expected domain"),
        }
        assert_eq!(parsed.consumed, hdr.len());
    }

    #[test]
    fn request_roundtrip_udp_ipv4() {
        let key = derive_key("pass");
        let target = Target::Socket("1.2.3.4:443".parse().unwrap());
        let hdr = build_udp_handshake(&key, &target);
        let parsed = parse_request(&hdr).unwrap();
        assert_eq!(parsed.command, CMD_UDP);
        match parsed.target {
            Target::Socket(a) => {
                assert_eq!(a.ip().to_string(), "1.2.3.4");
                assert_eq!(a.port(), 443);
            }
            _ => panic!("expected socket"),
        }
    }

    #[test]
    fn udp_frame_roundtrip() {
        let target = Target::Domain("dns.google".into(), 53);
        let data = b"hello dns";
        let frame = build_udp_frame(&target, data);
        // 帧尾应是 data
        assert_eq!(&frame[frame.len() - data.len()..], data);
    }

    #[test]
    fn socks_addr_roundtrip_ipv6() {
        let target = Target::Socket("[2001:db8::1]:443".parse().unwrap());
        let mut buf = BytesMut::new();
        write_addr(&mut buf, &target);
        let (n, parsed) = read_socks_addr(&buf).unwrap();
        assert_eq!(n, buf.len());
        match parsed {
            Target::Socket(a) => {
                assert_eq!(a.to_string(), "[2001:db8::1]:443");
            }
            _ => panic!("expected socket"),
        }
    }
}
