//! SOCKS5 入站：纯 SOCKS5 代理，支持 CONNECT + UDP ASSOCIATE。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::inbound::{AuthUser, SocksInboundConfig},
    inbound::{InboundTcpStream, InboundUdpPacket, SniffedStream, Target, UdpSession},
};

pub struct SocksInbound {
    config: SocksInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
}

impl SocksInbound {
    pub fn new(
        config: SocksInboundConfig,
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

        info!(tag = %tag, addr = %bind, "socks inbound starting");

        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "socks inbound accept error");
                    continue;
                }
            };

            let tcp_tx = self.tcp_tx.clone();
            let udp_tx = self.udp_tx.clone();
            let tag = tag.clone();
            let config = config.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_socks5(stream, peer, config, tcp_tx, udp_tx, tag).await {
                    debug!(peer = %peer, err = %e, "socks inbound conn error");
                }
            });
        }
    }
}

// ── SOCKS5 协议常量 ──────────────────────────────────────────────────────────

const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_SUCCESS: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

async fn handle_socks5(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<SocksInboundConfig>,
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

    let need_auth = !config.users.is_empty();
    let method = if need_auth && methods.contains(&0x02) {
        0x02 // USERNAME/PASSWORD
    } else if !need_auth && methods.contains(&0x00) {
        0x00 // NO AUTH
    } else {
        stream.write_all(&[0x05, 0xFF]).await?;
        anyhow::bail!("no acceptable SOCKS5 auth method");
    };

    stream.write_all(&[0x05, method]).await?;

    // ── 阶段二：鉴权（USERNAME/PASSWORD，RFC 1929）─────────────────────────
    if method == 0x02 {
        // [VER=1][ULEN][UNAME][PLEN][PASSWD]
        let ver = stream.read_u8().await?;
        anyhow::ensure!(ver == 0x01, "invalid SOCKS5 auth version: 0x{ver:02x}");
        let ulen = stream.read_u8().await? as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await?;
        let plen = stream.read_u8().await? as usize;
        let mut passwd = vec![0u8; plen];
        stream.read_exact(&mut passwd).await?;

        let user_str = std::str::from_utf8(&uname).unwrap_or("");
        let pass_str = std::str::from_utf8(&passwd).unwrap_or("");
        let ok = check_auth(&config.users, user_str, pass_str);

        if ok {
            stream.write_all(&[0x01, 0x00]).await?;
        } else {
            stream.write_all(&[0x01, 0x01]).await?;
            anyhow::bail!("SOCKS5 auth failed");
        }
    }

    // ── 阶段三：请求 ─────────────────────────────────────────────────────────
    // [VER=5][CMD][RSV=0][ATYP][DST.ADDR][DST.PORT]
    let _ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    let target = match read_socks5_addr(&mut stream, atyp).await {
        Ok(t) => t,
        Err(e) => {
            // 0x08 = Command reply code: Address type not supported
            let rep = if e.to_string().contains("unknown SOCKS5 atyp") {
                0x08
            } else {
                0x01
            };
            let _ = write_socks5_reply_code(&mut stream, rep).await;
            anyhow::bail!("SOCKS5 read target failed: {e}");
        }
    };

    match cmd {
        CMD_CONNECT => {
            let local = stream.local_addr().unwrap_or(peer);
            write_socks5_reply(&mut stream, REP_SUCCESS, local).await?;
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
            handle_socks5_udp_associate(stream, peer, udp_tx, tag).await?;
        }

        other => {
            write_socks5_reply_code(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
            anyhow::bail!("unsupported SOCKS5 cmd: 0x{other:02x}");
        }
    }

    Ok(())
}

/// 校验用户名/密码是否在 users 列表中
fn check_auth(users: &[AuthUser], username: &str, password: &str) -> bool {
    users
        .iter()
        .any(|u| u.username == username && u.password == password)
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
    buf.put_u8(0x05);
    buf.put_u8(rep);
    buf.put_u8(0x00);
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
    stream
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

// ── SOCKS5 UDP ASSOCIATE ──────────────────────────────────────────────────────

async fn handle_socks5_udp_associate(
    mut ctrl: TcpStream,
    peer: SocketAddr,
    udp_tx: mpsc::Sender<InboundUdpPacket>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    let udp_bind: SocketAddr = if peer.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let udp_sock = Arc::new(UdpSocket::bind(udp_bind).await?);
    let udp_local = udp_sock.local_addr()?;
    // RFC 1928 §6: BND.ADDR 应为客户端可用的目的地址。
    // 用 TCP 控制连接的本端 IP（客户端实际连接到的服务器地址）+ UDP socket 的端口
    let ctrl_local = ctrl.local_addr().unwrap_or(udp_local);
    let bnd_addr = SocketAddr::new(ctrl_local.ip(), udp_local.port());

    write_socks5_reply(&mut ctrl, REP_SUCCESS, bnd_addr).await?;

    debug!(peer = %peer, udp_port = %udp_local.port(), "socks5 UDP ASSOCIATE");

    let (reply_tx, mut reply_rx) = mpsc::channel::<(Bytes, SocketAddr, SocketAddr)>(64);

    let reply_task = {
        let sock = udp_sock.clone();
        tokio::spawn(async move {
            while let Some((data, dst, _spoofed_src)) = reply_rx.recv().await {
                let wrapped = wrap_socks5_udp(&data, dst);
                if let Err(e) = sock.send_to(&wrapped, dst).await {
                    warn!(err = %e, "socks5 udp reply error");
                }
            }
        })
    };

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

            // 来源过滤：仅接受来自 TCP 控制连接对端 IP 的 UDP 包
            if src.ip() != peer.ip() {
                debug!(src = %src, expected = %peer.ip(), "socks5 udp packet from unexpected source, dropping");
                continue;
            }

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

    let _ = ctrl.set_nodelay(true);
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
    // RSV 必须为 0x0000（RFC 1928 §7）
    anyhow::ensure!(
        buf[0] == 0 && buf[1] == 0,
        "non-zero RSV in SOCKS5 UDP packet"
    );
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
    buf.extend_from_slice(&[0x00, 0x00, 0x00]);
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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn auth_check() {
        let users = vec![
            AuthUser {
                username: "admin".into(),
                password: "secret".into(),
            },
            AuthUser {
                username: "guest".into(),
                password: "pass".into(),
            },
        ];
        assert!(check_auth(&users, "admin", "secret"));
        assert!(check_auth(&users, "guest", "pass"));
        assert!(!check_auth(&users, "admin", "wrong"));
        assert!(!check_auth(&users, "unknown", "secret"));
    }
}
