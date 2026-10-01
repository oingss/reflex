//! SOCKS5 服务端入站（移植自 flux，纯服务端 CONNECT 代理）。
//!
//! 与客户端本地用途的 [`crate::inbound::socks`] 的区别：面向公网服务端场景，
//! **仅支持 CONNECT 命令**，不支持 UDP ASSOCIATE（与 flux 行为一致）。
//! 鉴权方式：SOCKS5 用户名/密码子协商（RFC 1929），未配置 users 时不鉴权。
//!
//! 与 flux 的差异：reflex 架构下入站不直接拨号，解析出目标后交给
//! dispatcher 按路由规则选择出站；拨号失败由 dispatcher 侧回 RST。

use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};
use tracing::{debug, error, info};

use crate::{
    config::inbound::SocksServerInboundConfig,
    inbound::{display_sockaddr, InboundTcpStream, SniffedStream, Target},
};

// ── SOCKS5 协议常量（RFC 1928）────────────────────────────────────────────────

const VER: u8 = 0x05;

// Auth methods
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

// Commands
const CMD_CONNECT: u8 = 0x01;

// Address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

pub struct SocksServerInbound {
    config: SocksServerInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl SocksServerInbound {
    pub fn new(config: SocksServerInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            crate::inbound::parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());
        let config = Arc::new(self.config);

        info!(
            tag = %tag,
            addr = %bind,
            auth = if config.users.is_empty() { "none" } else { "password" },
            "socks-server inbound starting"
        );

        let listener = TcpListener::bind(bind).await?;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(err = %e, "socks-server inbound accept error");
                    continue;
                }
            };

            let tcp_tx = self.tcp_tx.clone();
            let tag = tag.clone();
            let config = config.clone();

            tokio::spawn(async move {
                if let Err(e) = handle(stream, peer, config, tcp_tx, tag).await {
                    debug!(peer = %display_sockaddr(peer), err = %e, "socks-server conn error");
                }
            });
        }
    }
}

// ── Per-connection handler ────────────────────────────────────────────────────

async fn handle(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<SocksServerInboundConfig>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // ── Greeting ──────────────────────────────────────────────────────────────
    // [VER=5][NMETHODS][METHOD...]
    let ver = stream.read_u8().await?;
    anyhow::ensure!(ver == VER, "bad SOCKS version: 0x{ver:02x}");

    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let use_password = !config.users.is_empty();

    if use_password && methods.contains(&METHOD_PASSWORD) {
        stream.write_all(&[VER, METHOD_PASSWORD]).await?;
        // Sub-negotiation: username/password (RFC 1929)
        // [VER=1][ULEN][UNAME][PLEN][PASSWD]
        let sub_ver = stream.read_u8().await?;
        anyhow::ensure!(sub_ver == 0x01, "bad subneg version: 0x{sub_ver:02x}");
        let ulen = stream.read_u8().await? as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await?;
        let plen = stream.read_u8().await? as usize;
        let mut passwd = vec![0u8; plen];
        stream.read_exact(&mut passwd).await?;

        let uname_str = String::from_utf8_lossy(&uname);
        let passwd_str = String::from_utf8_lossy(&passwd);

        let ok = config
            .users
            .iter()
            .any(|u| u.username == uname_str.as_ref() && u.password == passwd_str.as_ref());

        if ok {
            stream.write_all(&[0x01, 0x00]).await?; // success
        } else {
            stream.write_all(&[0x01, 0x01]).await?; // failure
            anyhow::bail!("authentication failed for user '{uname_str}'");
        }
    } else if !use_password && methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
    } else {
        stream.write_all(&[VER, METHOD_NO_ACCEPTABLE]).await?;
        anyhow::bail!("no acceptable auth method");
    }

    // ── Request ───────────────────────────────────────────────────────────────
    // [VER=5][CMD][RSV=0][ATYP][DST.ADDR][DST.PORT]
    let ver2 = stream.read_u8().await?;
    anyhow::ensure!(ver2 == VER, "bad SOCKS version in request: 0x{ver2:02x}");
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved, must be 0x00
    let atyp = stream.read_u8().await?;

    if !matches!(atyp, ATYP_IPV4 | ATYP_DOMAIN | ATYP_IPV6) {
        send_reply(&mut stream, REP_ATYP_NOT_SUPPORTED).await?;
        anyhow::bail!("unsupported address type: 0x{atyp:02x}");
    }

    let (target_host, target) = match read_target(&mut stream, atyp).await {
        Ok(v) => v,
        Err(e) => {
            // 地址数据残缺/截断等：按 flux 语义回 General Failure
            let _ = send_reply(&mut stream, REP_GENERAL_FAILURE).await;
            anyhow::bail!("read SOCKS5 target failed: {e}");
        }
    };

    if cmd != CMD_CONNECT {
        send_reply(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
        anyhow::bail!("unsupported command: 0x{cmd:02x} (only CONNECT is supported)");
    }

    // ── 交给 dispatcher 路由 ─────────────────────────────────────────────────
    // 与 flux 的差异：不在入站内直接拨号（flux 在拨号失败时回
    // REP_GENERAL_FAILURE），reflex 先回成功、由 dispatcher 完成拨号，
    // 拨号失败通过 SniffedStream 的 Drop-RST 语义通知客户端。
    send_reply(&mut stream, REP_SUCCESS).await?;
    info!(
        peer = %display_sockaddr(peer),
        target = %target_host,
        tag = %tag,
        "socks-server CONNECT"
    );
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

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// 读取 DST.ADDR + DST.PORT。返回 (显示用目标字符串, Target)。
async fn read_target(stream: &mut TcpStream, atyp: u8) -> anyhow::Result<(String, Target)> {
    let (host, port) = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            let port = stream.read_u16().await?;
            let ip = std::net::Ipv4Addr::from(b);
            (ip.to_string(), Target::Socket(SocketAddr::new(ip.into(), port)))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            stream.read_exact(&mut b).await?;
            let domain = String::from_utf8(b)?;
            let port = stream.read_u16().await?;
            (format!("{domain}:{port}"), Target::Domain(domain, port))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            let port = stream.read_u16().await?;
            let ip = std::net::Ipv6Addr::from(b);
            (format!("[{ip}]:{port}"), Target::Socket(SocketAddr::new(ip.into(), port)))
        }
        other => anyhow::bail!("unsupported address type: 0x{other:02x}"),
    };
    Ok((host, port))
}

/// Send a minimal SOCKS5 reply with the given reply code.
/// BND.ADDR = 0.0.0.0, BND.PORT = 0 (acceptable for CONNECT，与 flux 一致).
async fn send_reply<W: AsyncWrite + Unpin>(w: &mut W, rep: u8) -> anyhow::Result<()> {
    // VER REP RSV ATYP  BND.ADDR(4)  BND.PORT(2)
    w.write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reply_bytes() {
        let (mut client, mut server) = tokio::io::duplex(64);
        send_reply(&mut server, REP_SUCCESS).await.unwrap();
        let mut buf = vec![0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

        let (mut client, mut server) = tokio::io::duplex(64);
        send_reply(&mut server, REP_GENERAL_FAILURE).await.unwrap();
        let mut buf = vec![0u8; 10];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[1], 0x01);
    }
}
