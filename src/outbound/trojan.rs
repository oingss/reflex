use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    config::outbound::{TrojanOutboundConfig, TrojanTransportConfig},
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{apply_mark_to_tcp, relay, resolve_server_addr, set_tcp_opts, Outbound},
    protocol::trojan,
};

// ── 结构体 ────────────────────────────────────────────────────────────────────

pub struct TrojanOutbound {
    config: TrojanOutboundConfig,
    /// 预计算的 56 字节 hex key（密码的 SHA-224）
    key: [u8; trojan::KEY_LEN],
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<DnsResolver>>,
}

impl TrojanOutbound {
    pub fn new(config: TrojanOutboundConfig) -> anyhow::Result<Self> {
        let key = trojan::derive_key(&config.password);
        // WS 与 TCP+TLS 路径都通过 connect_tls_or_utls 动态构建 TLS 配置，
        // 不再在 new() 时提前压成 rustls::ClientConfig（避免丢失 uTLS/certificate 字段）。
        Ok(Self {
            config,
            key,
            routing_mark: 0,
            resolver: None,
        })
    }

    pub fn with_resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 连接建立 ──────────────────────────────────────────────────────────────

    /// 建立裸 TCP 连接（不含 TLS）
    async fn connect_raw_tcp(&self) -> anyhow::Result<TcpStream> {
        let addr = self.resolve_server().await?;
        let tcp = crate::outbound::connect_tcp_interface(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;
        Ok(tcp)
    }

    /// 建立 TCP + TLS 连接（自动选择普通 TLS 或 uTLS）
    async fn connect_tls(&self) -> anyhow::Result<crate::outbound::tls::TlsStreamBox> {
        let tcp = self.connect_raw_tcp().await?;
        let sni = self.tls_sni();
        crate::outbound::tls::connect_tls_or_utls(tcp, sni, &self.config.tls).await
    }

    // ── 握手头构造 ────────────────────────────────────────────────────────────

    /// 构建 Trojan TCP 请求头（不含 payload）
    fn build_tcp_header(&self, target: &Target) -> BytesMut {
        trojan::build_tcp_header(&self.key, target)
    }

    /// 构建 Trojan UDP 请求头（不含 UDP 分帧，仅握手部分）
    ///
    /// Trojan UDP over TCP：握手后每个 UDP 包格式：
    /// `[ATYP 1B][ADDR ...][PORT 2B][LEN 2B][CRLF][DATA]`
    fn build_udp_handshake(&self, target: &Target) -> BytesMut {
        trojan::build_udp_handshake(&self.key, target)
    }

    // ── dial：返回通用 AsyncReadWrite ─────────────────────────────────────────

    async fn dial(
        &self,
        header: Bytes,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        match self.config.transport.as_ref() {
            None | Some(TrojanTransportConfig::Tcp(_)) => {
                if self.config.tls.enabled {
                    let stream = self.connect_tls().await?;
                    Ok(Box::new(TrojanTcpStream::new(stream, header)))
                } else {
                    let stream = self.connect_raw_tcp().await?;
                    Ok(Box::new(TrojanTcpStream::new(stream, header)))
                }
            }
            Some(TrojanTransportConfig::Ws(ws_cfg)) => {
                let sni = self.tls_sni();
                let tls_opt = if self.config.tls.enabled {
                    Some(&self.config.tls)
                } else {
                    None
                };
                let ws = crate::outbound::transport::websocket::connect(
                    &self.config.server,
                    self.config.server_port,
                    sni,
                    tls_opt,
                    ws_cfg,
                    self.routing_mark,
                    self.resolver.clone(),
                )
                .await?;
                Ok(Box::new(
                    crate::outbound::transport::websocket::WsStream::with_header(ws, header),
                ))
            }
            Some(TrojanTransportConfig::Xhttp(xhttp_cfg)) => {
                use crate::outbound::transport::xhttp;
                use std::collections::HashMap;
                let stream = xhttp::connect(
                    &self.config.server,
                    self.config.server_port,
                    xhttp_cfg,
                    if self.config.tls.enabled {
                        Some(&self.config.tls)
                    } else {
                        None
                    },
                    &HashMap::new(),
                    self.routing_mark,
                    self.resolver.clone(),
                )
                .await?;
                Ok(Box::new(TrojanTcpStream::new(stream, header)))
            }
            Some(TrojanTransportConfig::Grpc(grpc_cfg)) => {
                let sni = self.tls_sni();
                let tls_opt = if self.config.tls.enabled {
                    Some(&self.config.tls)
                } else {
                    None
                };
                let stream = crate::outbound::transport::grpc::connect(
                    &self.config.server,
                    self.config.server_port,
                    sni,
                    tls_opt,
                    grpc_cfg,
                    self.routing_mark,
                    self.resolver.clone(),
                )
                .await?;
                Ok(Box::new(TrojanTcpStream::new(stream, header)))
            }
        }
    }

    // ── 辅助 ──────────────────────────────────────────────────────────────────

    async fn resolve_server(&self) -> anyhow::Result<SocketAddr> {
        resolve_server_addr(
            &self.config.server,
            self.config.server_port,
            self.resolver.as_ref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("DNS failed for {}: {e}", self.config.server))
    }

    fn tls_sni(&self) -> &str {
        self.config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server)
    }
}

// ── Outbound trait ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for TrojanOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let header = self.build_tcp_header(&target).freeze();
        self.dial(header).await
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let transport_type = match &self.config.transport {
            None | Some(TrojanTransportConfig::Tcp(_)) => "tcp",
            Some(TrojanTransportConfig::Ws(_)) => "ws",
            Some(TrojanTransportConfig::Xhttp(_)) => "xhttp",
            Some(TrojanTransportConfig::Grpc(_)) => "grpc",
        };
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            transport = transport_type,
            tls = self.config.tls.enabled,
            "trojan tcp connecting"
        );

        let header = self.build_tcp_header(&conn.target).freeze();
        let io = self.dial(header).await?;
        Ok(relay(conn.stream, io).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        debug!(
            tag = %self.config.tag,
            target = %packet.target,
            "trojan udp session"
        );

        // Trojan UDP over TCP：握手头 + UDP 分帧
        let header = self.build_udp_handshake(&packet.target).freeze();
        let io = self.dial(header).await?;
        let (mut reader, mut writer) = tokio::io::split(io);

        // 发送第一个 UDP 帧：[ATYP][ADDR][PORT][LEN 2B][CRLF][DATA]
        let udp_frame = trojan::build_udp_frame(&packet.target, &packet.data);
        writer.write_all(&udp_frame).await?;
        writer.flush().await?;

        let timeout = std::time::Duration::from_secs(60); // 对齐 sing-box 默认
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());

        // 若有后续上行包通道，spawn task 持续将上行包写入 TCP 隧道
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            tokio::spawn(async move {
                while let Some((target, data)) = upstream_rx.recv().await {
                    let frame = trojan::build_udp_frame(&target, &data);
                    if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
                        break;
                    }
                }
            });
        }

        // ── 接收循环：解析 Trojan UDP 帧 ─────────────────────────────────────
        // 帧格式：[ATYP 1B][ADDR 变长][PORT 2B][LEN 2B BE][CRLF 2B][DATA len B]
        // 旧实现手动跳字节，对于 Domain 地址无法正确确定长度。改用 read_socks_addr
        // 精确解析变长地址，与 sing-box `M.SocksaddrSerializer.ReadAddrPort` 一致。
        loop {
            // 读取 ATYP 字节
            let mut atyp_buf = [0u8; 1];
            match tokio::time::timeout(timeout, reader.read_exact(&mut atyp_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }

            // 从 stream 中读取完整地址（需要二次 read，因为 ATYP 之后 ADDR 长度不定）
            let mut addr_buf = vec![0u8; 256]; // 最大 FQDN = 1 + 255 + 2 = 258B
            addr_buf[0] = atyp_buf[0];
            let (_consumed, _target) = match atyp_buf[0] {
                trojan::atyp::IPV4 => {
                    reader.read_exact(&mut addr_buf[1..7]).await?;
                    trojan::read_socks_addr(&addr_buf[..7])?
                }
                trojan::atyp::IPV6 => {
                    reader.read_exact(&mut addr_buf[1..19]).await?;
                    trojan::read_socks_addr(&addr_buf[..19])?
                }
                trojan::atyp::DOMAIN => {
                    let mut domain_len_buf = [0u8; 1];
                    reader.read_exact(&mut domain_len_buf).await?;
                    let dlen = domain_len_buf[0] as usize;
                    addr_buf[1] = dlen as u8;
                    reader.read_exact(&mut addr_buf[2..2 + dlen + 2]).await?; // domain + port
                    let total = 4 + dlen; // ATYP(1) + len(1) + domain(N) + port(2)
                    trojan::read_socks_addr(&addr_buf[..total])?
                }
                _ => break,
            };

            // 读取 [LEN 2B][CRLF 2B] = 4 字节
            let mut len_crlf = [0u8; 4];
            reader.read_exact(&mut len_crlf).await?;
            let data_len = u16::from_be_bytes([len_crlf[0], len_crlf[1]]) as usize;

            // 防 DoS：拒绝超大载荷
            if data_len == 0 {
                break;
            }
            if data_len > trojan::MAX_UDP_PAYLOAD {
                return Err(anyhow::anyhow!(
                    "trojan udp: payload too large ({data_len} > {})",
                    trojan::MAX_UDP_PAYLOAD
                ));
            }

            let mut data = vec![0u8; data_len];
            match tokio::time::timeout(timeout, reader.read_exact(&mut data)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => break,
            }

            let _ = reply_tx
                .send((bytes::Bytes::from(data), src, spoofed_src))
                .await;
        }

        Ok(())
    }
}

// ── TrojanTcpStream：TCP/TLS 传输适配器 ──────────────────────────────────────
//
// 首次写入时在数据前拼接 Trojan 握手头；无需跳过服务端响应头（Trojan 无响应头）。

use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project! {
    struct TrojanTcpStream<S> {
        #[pin]
        inner: S,
        pending_header: Option<Bytes>,
        // 部分写出后剩余的合并缓冲（header 残余 + 用户数据），需在下次 poll_write 优先冲刷
        pending_write: Option<Bytes>,
        // pending_write 全部冲刷后应回报给调用方的字节数（即触发部分写的原始 data.len()）
        pending_reported: usize,
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TrojanTcpStream<S> {
    fn new(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            pending_write: None,
            pending_reported: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TrojanTcpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Trojan 服务端无响应头，直接透传
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TrojanTcpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();

        // 1. 优先冲刷上次部分写出遗留的合并缓冲。
        //    旧实现在 n < header.len() 时返回 Ok(0)（违反 AsyncWrite 契约：
        //    Ok(0) 表示连接不可写）并丢弃未发送的 header 残余，导致后续裸数据
        //    写出 → 协议损坏。这里改为保存剩余并返回 Pending，下次重试。
        if let Some(pending) = this.pending_write.take() {
            return match this.inner.poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = *this.pending_reported;
                    *this.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    *this.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    *this.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. 首次写入：握手头 + data 合并发送
        if let Some(header) = this.pending_header.take() {
            let mut combined = BytesMut::with_capacity(header.len() + data.len());
            combined.put_slice(&header);
            combined.put_slice(data);
            let combined = combined.freeze();
            return match this.inner.poll_write(cx, &combined) {
                Poll::Ready(Ok(n)) if n >= combined.len() => Poll::Ready(Ok(data.len())),
                Poll::Ready(Ok(n)) => {
                    *this.pending_write = Some(combined.slice(n..));
                    *this.pending_reported = data.len();
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => {
                    *this.pending_header = Some(header);
                    Poll::Pending
                }
            };
        }

        // 3. 无 header，直接写
        this.inner.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 在测试中安装 rustls ring CryptoProvider（rustls 0.23 要求）。
    /// 多次调用安全：已安装时 install_default 返回 Err，此处忽略。
    fn ensure_rustls_provider() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn derive_key_known_vector() {
        // 与 sing-box transport/trojan/protocol.go 的 Key() 函数对齐：
        // Trojan 密钥 = hex(SHA-224(password))，长度 56 字节 ASCII。
        // SHA-224("password") = d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01
        let key = trojan::derive_key("password");
        let hex = std::str::from_utf8(&key).unwrap();
        assert!(hex.starts_with("d63dc919"), "unexpected key prefix: {hex}");
        assert_eq!(key.len(), 56);
    }

    #[test]
    fn build_tcp_header_domain() {
        ensure_rustls_provider();
        use crate::config::outbound::{TlsConfig, TrojanTcpConfig, TrojanTransportConfig};
        let cfg = TrojanOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            password: "password".into(),
            transport: Some(TrojanTransportConfig::Tcp(TrojanTcpConfig::default())),
            tls: TlsConfig::default(),
            multiplex: None,
            detour: None,
        };
        let ob = TrojanOutbound::new(cfg).unwrap();
        let target = Target::Domain("target.example".into(), 80);
        let hdr = ob.build_tcp_header(&target);

        // 前 56 字节是 key
        assert_eq!(&hdr[..56], &ob.key);
        // CRLF
        assert_eq!(&hdr[56..58], b"\r\n");
        // CMD_TCP
        assert_eq!(hdr[58], trojan::CMD_TCP);
        // ATYP_DOMAIN
        assert_eq!(hdr[59], trojan::atyp::DOMAIN);
        // domain length
        assert_eq!(hdr[60], "target.example".len() as u8);
    }

    #[test]
    fn build_tcp_header_ipv4() {
        ensure_rustls_provider();
        use crate::config::outbound::{TlsConfig, TrojanTcpConfig, TrojanTransportConfig};
        use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
        let cfg = TrojanOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            password: "pass".into(),
            transport: Some(TrojanTransportConfig::Tcp(TrojanTcpConfig::default())),
            tls: TlsConfig::default(),
            multiplex: None,
            detour: None,
        };
        let ob = TrojanOutbound::new(cfg).unwrap();
        let target = Target::Socket(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(1, 2, 3, 4),
            443,
        )));
        let hdr = ob.build_tcp_header(&target);
        // ATYP_IPV4 在索引 59
        assert_eq!(hdr[59], trojan::atyp::IPV4);
        // IPv4 octets
        assert_eq!(&hdr[60..64], &[1, 2, 3, 4]);
        // port big-endian
        assert_eq!(u16::from_be_bytes([hdr[64], hdr[65]]), 443);
    }
}
