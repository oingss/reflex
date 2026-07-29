use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use base64::{engine::general_purpose, Engine};
use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::MixedInboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession},
};

pub struct MixedInbound {
    config: MixedInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl MixedInbound {
    pub fn new(
        config: MixedInboundConfig,
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
        let bind: SocketAddr =
            crate::inbound::parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());
        let config = Arc::new(self.config);

        info!(tag = %tag, addr = %bind, "mixed inbound starting");

        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "mixed inbound accept error");
                    continue;
                }
            };

            let tcp_tx = self.tcp_tx.clone();
            let udp_tx = self.udp_tx.clone();
            let tag = tag.clone();
            let config = config.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, peer, config, tcp_tx, udp_tx, tag).await {
                    debug!(peer = %peer, err = %e, "mixed inbound conn error");
                }
            });
        }
    }
}

// ── 连接处理：协议嗅探 ────────────────────────────────────────────────────────

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<MixedInboundConfig>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // peek 第一个字节判断协议
    let mut first = [0u8; 1];
    stream.peek(&mut first).await?;

    match first[0] {
        // SOCKS5 握手起始字节
        0x05 => handle_socks5(stream, peer, config, tcp_tx, udp_tx, tag).await,
        // HTTP 方法首字母：C(ONNECT) G(ET) P(OST/UT) H(EAD) D(ELETE) O(PTIONS)
        b'C' | b'G' | b'P' | b'H' | b'D' | b'O' | b'T' => {
            handle_http(stream, peer, config, tcp_tx, tag).await
        }
        other => {
            anyhow::bail!("unknown protocol first byte: 0x{other:02x}")
        }
    }
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

// SOCKS5 命令
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

// SOCKS5 地址类型
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// 应答码
const REP_SUCCESS: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<MixedInboundConfig>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // ── 阶段一：方法协商 ──────────────────────────────────────────────────────
    // [VER=5][NMETHODS][METHOD...]
    let ver = stream.read_u8().await?;
    anyhow::ensure!(ver == 0x05, "not SOCKS5");

    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let need_auth = config.username.is_some();
    let method = if need_auth && methods.contains(&0x02) {
        0x02 // USERNAME/PASSWORD
    } else if !need_auth && methods.contains(&0x00) {
        0x00 // NO AUTH
    } else {
        // 没有可接受的方法
        stream.write_all(&[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable SOCKS5 auth method");
    };

    stream.write_all(&[0x05, method]).await?;

    // ── 阶段二：鉴权（USERNAME/PASSWORD，RFC 1929）─────────────────────────
    if method == 0x02 {
        // [VER=1][ULEN][UNAME][PLEN][PASSWD]
        let _ver = stream.read_u8().await?;
        let ulen = stream.read_u8().await? as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await?;
        let plen = stream.read_u8().await? as usize;
        let mut passwd = vec![0u8; plen];
        stream.read_exact(&mut passwd).await?;

        let ok = config.username.as_deref() == Some(std::str::from_utf8(&uname).unwrap_or(""))
            && config.password.as_deref() == Some(std::str::from_utf8(&passwd).unwrap_or(""));

        if ok {
            stream.write_all(&[0x01, 0x00]).await?; // 成功
        } else {
            stream.write_all(&[0x01, 0x01]).await?; // 失败
            anyhow::bail!("SOCKS5 auth failed");
        }
    }

    // ── 阶段三：请求 ─────────────────────────────────────────────────────────
    // [VER=5][CMD][RSV=0][ATYP][DST.ADDR][DST.PORT]
    let _ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved
    let atyp = stream.read_u8().await?;

    let target = read_socks5_addr(&mut stream, atyp).await?;

    match cmd {
        CMD_CONNECT => {
            // 回复成功，BND.ADDR/PORT 填 0（TProxy 场景不关心）
            write_socks5_reply(&mut stream, REP_SUCCESS, peer).await?;

            debug!(peer = %peer, target = %target, "socks5 CONNECT");

            tcp_tx
                .send(InboundTcpStream {
                    stream: SniffedStream::new(stream),
                    target,
                    inbound_tag: (*tag).clone(),
                    sniffed_protocol: None,
                    sniffed_domain: None,
                })
                .await
                .ok();
        }

        CMD_UDP_ASSOCIATE => {
            if !config.network.udp() {
                write_socks5_reply_code(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
                anyhow::bail!("UDP ASSOCIATE disabled");
            }
            handle_socks5_udp_associate(stream, peer, udp_tx, tag).await?;
        }

        other => {
            write_socks5_reply_code(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
            anyhow::bail!("unsupported SOCKS5 cmd: 0x{other:02x}");
        }
    }

    Ok(())
}

async fn read_socks5_addr(stream: &mut TcpStream, atyp: u8) -> anyhow::Result<Target> {
    match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            Ok(Target::Socket(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(ip)),
                port,
            )))
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            Ok(Target::Socket(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            let port = stream.read_u16().await?;
            let domain = String::from_utf8(domain)?;
            Ok(Target::Domain(domain, port))
        }
        other => anyhow::bail!("unknown SOCKS5 atyp: 0x{other:02x}"),
    }
}

async fn write_socks5_reply(
    stream: &mut TcpStream,
    rep: u8,
    bind_addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut buf = BytesMut::with_capacity(16);
    buf.put_u8(0x05); // VER
    buf.put_u8(rep); // REP
    buf.put_u8(0x00); // RSV
    match bind_addr {
        SocketAddr::V4(a) => {
            buf.put_u8(ATYP_IPV4);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
        SocketAddr::V6(a) => {
            buf.put_u8(ATYP_IPV6);
            buf.put_slice(&a.ip().octets());
            buf.put_u16(a.port());
        }
    }
    stream.write_all(&buf).await?;
    Ok(())
}

async fn write_socks5_reply_code(stream: &mut TcpStream, rep: u8) -> anyhow::Result<()> {
    // BND.ADDR = 0.0.0.0:0
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

// ── SOCKS5 UDP ASSOCIATE ──────────────────────────────────────────────────────
//
// 流程：
// 1. 客户端发 UDP ASSOCIATE 请求
// 2. 服务端在随机端口绑定一个 UDP socket，回复该端口给客户端
// 3. 客户端向该端口发 SOCKS5 UDP 封装的数据包
// 4. 本端解包后转发；回包时重新封装发回客户端
// 5. 控制 TCP 连接断开时，UDP 会话也结束

async fn handle_socks5_udp_associate(
    mut ctrl: TcpStream,
    peer: SocketAddr,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // 在随机端口绑定 UDP socket
    let udp_bind: SocketAddr = if peer.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let udp_sock = Arc::new(UdpSocket::bind(udp_bind).await?);
    let udp_local = udp_sock.local_addr()?;
    // RFC 1928 §6: BND.ADDR 应为客户端可用的目的地址。
    // 用 TCP 控制连接的本端 IP（客户端实际连接到的服务器地址）+ UDP socket 的端口，
    // 而非 0.0.0.0（不可路由）。
    let ctrl_local = ctrl.local_addr().unwrap_or(udp_local);
    let bnd_addr = SocketAddr::new(ctrl_local.ip(), udp_local.port());

    // 告知客户端 UDP 端口
    write_socks5_reply(&mut ctrl, REP_SUCCESS, bnd_addr).await?;

    debug!(peer = %peer, udp_port = %udp_local.port(), "socks5 UDP ASSOCIATE");

    // 回包通道
    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);

    // 回包发送任务
    let reply_task = {
        let sock = udp_sock.clone();
        tokio::spawn(async move {
            while let Some((data, dst, _spoofed_src)) = reply_rx.recv().await {
                // 封装成 SOCKS5 UDP 格式再发回（SOCKS5 不需要伪造源地址）
                let wrapped = wrap_socks5_udp(&data, dst);
                if let Err(e) = sock.send_to(&wrapped, dst).await {
                    warn!(err = %e, "socks5 udp reply error");
                }
            }
        })
    };

    // UDP 接收任务
    let sock2 = udp_sock.clone();
    let tag2 = tag.clone();
    let tx2 = udp_tx.clone();
    let rtx2 = reply_tx.clone();

    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, src) = match sock2.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "socks5 udp recv error");
                    break;
                }
            };

            // 来源过滤：仅接受来自 TCP 控制连接对端 IP 的 UDP 包，
            // 防止任意主机绕过鉴权使用 UDP 转发（RFC 1928 §6 安全要求）
            if src.ip() != peer.ip() {
                debug!(src = %src, expected = %peer.ip(), "socks5 udp packet from unexpected source, dropping");
                continue;
            }

            // 解析 SOCKS5 UDP 封装
            let (data, target) = match parse_socks5_udp(&buf[..n]) {
                Ok(v) => v,
                Err(e) => {
                    debug!(err = %e, "invalid socks5 udp packet");
                    continue;
                }
            };

            let packet = InboundUdpPacket {
                data,
                src,
                target,
                inbound_tag: (*tag2).clone(),
                session: UdpSession {
                    reply_tx: rtx2.clone(),
                },
                sniffed_protocol: None,
                sniffed_domain: None,
                origin_destination: None,
                upstream_rx: None,
                lifetime_guards: vec![],
            };

            if tx2.send(packet).await.is_err() {
                break;
            }
        }
    });

    // 等待控制连接断开（客户端断开 = UDP 会话结束）。
    // 旧实现仅做 ctrl.read()，存在两个问题：
    // 1. 未启用 TCP keepalive：网络分区时 read 永久阻塞，UDP 会话泄漏。
    // 2. reply_task 未被 abort：即使控制连接断开，reply_task 仍持有 udp_sock
    //    的 Arc 引用，导致 socket 无法及时释放。
    // 修复：设置 keepalive 探测 + 断开后 abort reply_task。
    let _ = ctrl.set_nodelay(true);
    // SockRef::from 返回 SockRef 直接值（非 Result），因为 tokio::net::TcpStream
    // 实现了 AsFd trait。
    {
        let sock_ref = socket2::SockRef::from(&ctrl);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(std::time::Duration::from_secs(60))
            .with_interval(std::time::Duration::from_secs(15));
        let _ = sock_ref.set_tcp_keepalive(&keepalive);
    }

    let mut dummy = [0u8; 1];
    let _ = ctrl.read(&mut dummy).await;

    udp_task.abort();
    reply_task.abort();
    debug!(peer = %peer, "socks5 UDP ASSOCIATE ended");
    Ok(())
}

/// 解析 SOCKS5 UDP 封装的数据包
/// 格式: [RSV 2][FRAG 1][ATYP 1][ADDR][PORT 2][DATA]
fn parse_socks5_udp(buf: &[u8]) -> anyhow::Result<(Bytes, Target)> {
    anyhow::ensure!(buf.len() >= 4, "udp packet too short");
    // RSV(2) + FRAG(1)
    let frag = buf[2];
    anyhow::ensure!(frag == 0, "fragmented UDP not supported");

    let atyp = buf[3];
    let mut cur = 4usize;

    let target = match atyp {
        ATYP_IPV4 => {
            anyhow::ensure!(buf.len() >= cur + 6, "truncated ipv4");
            let ip = Ipv4Addr::new(buf[cur], buf[cur + 1], buf[cur + 2], buf[cur + 3]);
            cur += 4;
            let port = u16::from_be_bytes([buf[cur], buf[cur + 1]]);
            cur += 2;
            Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        ATYP_IPV6 => {
            anyhow::ensure!(buf.len() >= cur + 18, "truncated ipv6");
            let ip: [u8; 16] = buf[cur..cur + 16].try_into()?;
            cur += 16;
            let port = u16::from_be_bytes([buf[cur], buf[cur + 1]]);
            cur += 2;
            Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        ATYP_DOMAIN => {
            anyhow::ensure!(buf.len() > cur, "truncated domain len");
            let dlen = buf[cur] as usize;
            cur += 1;
            anyhow::ensure!(buf.len() >= cur + dlen + 2, "truncated domain");
            let domain = String::from_utf8(buf[cur..cur + dlen].to_vec())?;
            cur += dlen;
            let port = u16::from_be_bytes([buf[cur], buf[cur + 1]]);
            cur += 2;
            Target::Domain(domain, port)
        }
        other => anyhow::bail!("unknown atyp 0x{other:02x}"),
    };

    let data = Bytes::copy_from_slice(&buf[cur..]);
    Ok((data, target))
}

/// 将回包封装成 SOCKS5 UDP 格式
fn wrap_socks5_udp(data: &[u8], dst: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG
    match dst {
        SocketAddr::V4(a) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&a.ip().octets());
            buf.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    buf.extend_from_slice(data);
    buf
}

// ── HTTP CONNECT ──────────────────────────────────────────────────────────────

async fn handle_http(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<MixedInboundConfig>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // 读取请求行和头部（以 \r\n\r\n 结尾）。
    // 直接从 stream 读取到 Vec，避免 BufReader 丢弃超读的 body 字节。
    use tokio::io::AsyncWriteExt;

    const MAX_HEADER_TOTAL: usize = 65536;
    const MAX_LINE_LEN: usize = 8192;

    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("HTTP client closed before sending complete headers");
        }
        buf.extend_from_slice(&tmp[..n]);
        // 单行长度上限（防止恶意超大单行）
        if let Some(last_nl) = buf.iter().rposition(|&b| b == b'\n') {
            let last_line = &buf[last_nl + 1..];
            anyhow::ensure!(
                last_line.len() <= MAX_LINE_LEN,
                "HTTP header line too long (>{MAX_LINE_LEN})"
            );
        }
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        anyhow::ensure!(
            buf.len() <= MAX_HEADER_TOTAL,
            "HTTP headers too large (>{MAX_HEADER_TOTAL})"
        );
    }

    let request = std::str::from_utf8(&buf[..header_end])?;
    let target = parse_http_connect(request)?;

    // ── 认证检查（与 http.rs 对齐）──────────────────────────────────────────────
    if config.username.is_some() {
        let auth_ok = check_http_auth(&config, request);
        if !auth_ok {
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
                .await?;
            anyhow::bail!("HTTP proxy auth required/failed");
        }
    }

    debug!(peer = %peer, target = %target, "http CONNECT");

    // 回复 200 Connection Established
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let mut sniffed = SniffedStream::new(stream);
    // 保留 header 之后的字节（可能是 CONNECT 后的 early data，或转发请求的 body）
    if buf.len() > header_end {
        sniffed.prepend(bytes::Bytes::copy_from_slice(&buf[header_end..]));
    }
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

/// 解析 HTTP CONNECT 请求行，提取目标 host:port
/// 支持：`CONNECT example.com:443 HTTP/1.1`
/// 也支持普通 GET 等（将目标改写为 Host 头的目的地，port=80）
fn parse_http_connect(request: &str) -> anyhow::Result<Target> {
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    anyhow::ensure!(parts.len() >= 2, "malformed HTTP request line");

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // host:port
        if let Some((host, port_str)) = target.rsplit_once(':') {
            let port: u16 = port_str.parse().unwrap_or(443);
            return Ok(Target::Domain(host.to_string(), port));
        }
        return Ok(Target::Domain(target.to_string(), 443));
    }

    // 非 CONNECT：从 Host 头提取目标，端口默认 80
    for line in request.lines().skip(1) {
        if let Some(rest) = line.strip_prefix("Host:") {
            let host = rest.trim();
            if let Some((h, p)) = host.rsplit_once(':') {
                let port: u16 = p.parse().unwrap_or(80);
                return Ok(Target::Domain(h.to_string(), port));
            }
            return Ok(Target::Domain(host.to_string(), 80));
        }
    }

    anyhow::bail!("no Host header in HTTP request")
}

/// 检查 HTTP Proxy-Authorization: Basic 头（大小写不敏感匹配 scheme）
fn check_http_auth(config: &MixedInboundConfig, request: &str) -> bool {
    // 未配置用户名 → 不校验
    let (cfg_user, cfg_pass) = match (&config.username, &config.password) {
        (Some(u), Some(p)) => (u, p),
        _ => return true,
    };
    // 查找 Proxy-Authorization 头（大小写不敏感）
    for line in request.lines().skip(1) {
        if let Some(colon) = line.find(':') {
            if line[..colon].eq_ignore_ascii_case("proxy-authorization") {
                let value = line[colon + 1..].trim();
                // scheme 大小写不敏感
                let (scheme, rest) = match value.split_once(' ') {
                    Some((s, r)) => (s, r.trim()),
                    None => return false,
                };
                if !scheme.eq_ignore_ascii_case("Basic") {
                    return false;
                }
                let decoded = match general_purpose::STANDARD.decode(rest) {
                    Ok(d) => d,
                    Err(_) => return false,
                };
                let creds = match std::str::from_utf8(&decoded) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let (user, pass) = match creds.split_once(':') {
                    Some((u, p)) => (u, p),
                    None => return false,
                };
                return user == cfg_user && pass == cfg_pass;
            }
        }
    }
    false
}

/// 在 buf 中查找 `\r\n\r\n` 的结束位置（返回 header 总长度，含终止 CRLF CRLF）
fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for i in 0..=buf.len() - 4 {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_connect() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let t = parse_http_connect(req).unwrap();
        assert!(matches!(t, Target::Domain(ref h, 443) if h == "example.com"));
    }

    #[test]
    fn parse_http_get() {
        let req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let t = parse_http_connect(req).unwrap();
        assert!(matches!(t, Target::Domain(ref h, 80) if h == "example.com"));
    }

    #[test]
    fn socks5_udp_roundtrip() {
        let data = b"hello";
        let dst: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let wrapped = wrap_socks5_udp(data, dst);
        let (parsed_data, parsed_target) = parse_socks5_udp(&wrapped).unwrap();
        assert_eq!(&parsed_data[..], data);
        assert!(matches!(parsed_target, Target::Socket(a) if a == dst));
    }

    #[test]
    fn socks5_udp_ipv6() {
        let data = b"world";
        let dst: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let wrapped = wrap_socks5_udp(data, dst);
        let (parsed_data, parsed_target) = parse_socks5_udp(&wrapped).unwrap();
        assert_eq!(&parsed_data[..], data);
        assert!(matches!(parsed_target, Target::Socket(a) if a == dst));
    }
}
