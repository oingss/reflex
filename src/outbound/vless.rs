use std::{net::IpAddr, sync::Arc};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    config::outbound::{VlessOutboundConfig, VlessTransportConfig},
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, relay, resolve_server_addr, resolve_target_with_dns, set_tcp_opts,
        Outbound,
    },
};

use crate::outbound::tls::reality::reality_connect;
use crate::outbound::vmess::{build_packetaddr_frame, PacketAddrReader};

/// 编码 protobuf varint
fn write_varint(buf: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buf.push((value as u8) | 0x80);
        value >>= 7;
    }
    buf.push(value as u8);
}

pub struct VlessOutbound {
    config: VlessOutboundConfig,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<DnsResolver>>,
}

impl VlessOutbound {
    pub fn new(config: VlessOutboundConfig) -> anyhow::Result<Self> {
        // WS 与 TCP+TLS 路径都通过 connect_tls_or_utls 动态构建 TLS 配置，
        // 不再在 new() 时提前压成 rustls::ClientConfig（避免丢失 uTLS/certificate 字段）。
        Ok(Self {
            config,
            routing_mark: 0,
            resolver: None,
        })
    }

    /// 将 `VlessTlsConfig`（vless 专用，缺 certificate 字段）转换为通用 `TlsConfig`。
    /// 供 websocket::connect 等 TLS 统一入口使用。
    fn build_tls_config(
        tls: &crate::config::outbound::VlessTlsConfig,
    ) -> crate::config::outbound::TlsConfig {
        crate::config::outbound::TlsConfig {
            enabled: tls.enabled,
            server_name: tls.server_name.clone(),
            insecure: tls.insecure,
            ca_path: tls.ca_path.clone(),
            certificate: vec![],
            certificate_path: None,
            alpn: tls.alpn.clone(),
            min_version: None,
            max_version: None,
            utls: tls.utls.clone(),
            ech: tls.ech.clone(),
        }
    }

    pub fn with_resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 解析 UUID 字符串为 16 字节
    fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        anyhow::ensure!(hex.len() == 32, "invalid UUID: {s}");
        let mut out = [0u8; 16];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
        }
        Ok(out)
    }

    /// 构建 VLESS 请求头（TCP 命令）
    ///
    /// 当 flow = "xtls-rprx-vision" 时，addon 中携带 Flow 字段。
    /// addon 格式（protobuf-like）：
    ///   [Flow field tag=1][varint len][Flow string bytes]
    fn build_request_header(
        uuid: &[u8; 16],
        target: &Target,
        flow: Option<&str>,
    ) -> anyhow::Result<BytesMut> {
        let mut buf = BytesMut::with_capacity(64);

        // 构建 addon
        let addon_bytes = if let Some(flow) = flow {
            if !flow.is_empty() {
                // protobuf: field 1 (Flow), wire type 2 (length-delimited)
                // tag = (field_number << 3) | wire_type = (1 << 3) | 2 = 0x0a
                let mut addon = Vec::new();
                addon.push((0x01 << 3) | 0x02); // 0x0a
                let flow_bytes = flow.as_bytes();
                // varint length
                write_varint(&mut addon, flow_bytes.len() as u64);
                addon.extend_from_slice(flow_bytes);
                addon
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        buf.put_u8(0x00); // Version
        buf.put_slice(uuid); // UUID 16B
        buf.put_u8(addon_bytes.len() as u8); // Addon length
        buf.extend_from_slice(&addon_bytes);
        buf.put_u8(0x01); // Command: TCP CONNECT
        buf.put_u16(target.port());
        match target {
            Target::Domain(host, _) => {
                buf.put_u8(0x02);
                buf.put_u8(host.len() as u8);
                buf.put_slice(host.as_bytes());
            }
            Target::Socket(addr) => match addr.ip() {
                IpAddr::V4(ip) => {
                    buf.put_u8(0x01);
                    buf.put_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.put_u8(0x03);
                    buf.put_slice(&ip.octets());
                }
            },
        }
        Ok(buf)
    }

    /// 建立 TCP+TLS 连接（自动选择普通 TLS 或 uTLS）
    async fn connect_tcp_tls(&self) -> anyhow::Result<crate::outbound::tls::TlsStreamBox> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let sni = self.tls_sni();

        let addr = resolve_server_addr(server, port, self.resolver.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;

        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        // 从 VlessTlsConfig 组装通用 TlsConfig
        let tls_base = match &self.config.tls {
            Some(vtls) => Self::build_tls_config(vtls),
            None => crate::config::outbound::TlsConfig::default(),
        };
        crate::outbound::tls::connect_tls_or_utls(tcp, sni, &tls_base).await
    }

    /// 建立 TCP+REALITY 连接
    async fn connect_tcp_reality(
        &self,
        tls: &crate::config::outbound::VlessTlsConfig,
        reality: &crate::config::outbound::RealityConfig,
    ) -> anyhow::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> {
        let server = &self.config.server;
        let port = self.config.server_port;

        let addr = resolve_server_addr(server, port, self.resolver.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;

        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        let cfg = crate::config::outbound::RealityDialConfig {
            public_key: reality.public_key.clone(),
            short_id: reality.short_id.clone(),
            server_name: tls.server_name.clone(),
            server: server.clone(),
            alpn: tls.alpn.clone(),
            fingerprint: "chrome".to_string(),
        };

        debug!(
            tag = %self.config.tag,
            server = %server,
            sni = cfg.server_name.as_deref().unwrap_or(server),
            "REALITY: connecting"
        );

        let stream = reality_connect(tcp, &cfg).await?;
        Ok(stream)
    }

    /// 获取 TLS SNI
    fn tls_sni(&self) -> &str {
        self.config
            .tls
            .as_ref()
            .and_then(|t| t.server_name.as_deref())
            .unwrap_or(&self.config.server)
    }

    /// 连接并返回通用的 AsyncRead+AsyncWrite box
    async fn dial(
        &self,
        header: Bytes,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        // ── XHTTP 传输 ────────────────────────────────────────────────────────
        if let Some(VlessTransportConfig::Xhttp(xhttp_cfg)) = &self.config.transport {
            use crate::outbound::transport::xhttp;
            use std::collections::HashMap;
            let tls_cfg = self
                .config
                .tls
                .as_ref()
                .map(|t| crate::config::outbound::TlsConfig {
                    enabled: t.enabled,
                    server_name: t.server_name.clone(),
                    insecure: t.insecure,
                    ca_path: t.ca_path.clone(),
                    certificate: vec![],
                    certificate_path: None,
                    alpn: t.alpn.clone(),
                    min_version: None,
                    max_version: None,
                    utls: t.utls.clone(),
                    ech: t.ech.clone(),
                });
            let stream = xhttp::connect(
                &self.config.server,
                self.config.server_port,
                xhttp_cfg,
                tls_cfg.as_ref(),
                &HashMap::new(),
                self.routing_mark,
                self.resolver.clone(),
            )
            .await?;
            return Ok(Box::new(VlessTcpStream::new(stream, header)));
        }

        // ── gRPC 传输 ──────────────────────────────────────────────────────────
        if let Some(VlessTransportConfig::Grpc(grpc_cfg)) = &self.config.transport {
            let sni = self.tls_sni();
            let tls_opt = self.config.tls.as_ref().map(Self::build_tls_config);
            let stream = crate::outbound::transport::grpc::connect(
                &self.config.server,
                self.config.server_port,
                sni,
                tls_opt.as_ref(),
                grpc_cfg,
                self.routing_mark,
                self.resolver.clone(),
            )
            .await?;
            return Ok(Box::new(VlessTcpStream::new(stream, header)));
        }

        // transport 为 None 或 Tcp 时都走 TCP 路径
        let is_ws = matches!(&self.config.transport, Some(VlessTransportConfig::Ws(_)));

        if is_ws {
            let ws_cfg = match &self.config.transport {
                Some(VlessTransportConfig::Ws(w)) => w,
                _ => unreachable!(),
            };
            let sni = self.tls_sni();
            // 将 VlessTlsConfig 转为通用 TlsConfig，让 websocket::connect 走
            // connect_tls_or_utls 统一入口（支持 uTLS、自签证书、ALPN）。
            let tls_opt = self.config.tls.as_ref().map(Self::build_tls_config);
            let ws = crate::outbound::transport::websocket::connect(
                &self.config.server,
                self.config.server_port,
                sni,
                tls_opt.as_ref(),
                ws_cfg,
                self.routing_mark,
                self.resolver.clone(),
            )
            .await?;
            return Ok(Box::new(
                crate::outbound::transport::websocket::WsStream::with_header(ws, header)
                    .skip_vless_response(),
            ));
        }

        // TCP 路径：根据 tls 配置决定用普通 TLS、REALITY 还是明文
        match &self.config.tls {
            Some(tls) if tls.enabled => {
                if let Some(reality) = &tls.reality {
                    if reality.enabled || !reality.public_key.is_empty() {
                        let stream = self.connect_tcp_reality(tls, reality).await?;
                        return Ok(Box::new(VlessTcpStream::new(stream, header)));
                    }
                }
                let stream = self.connect_tcp_tls().await?;
                Ok(Box::new(VlessTcpStream::new(stream, header)))
            }
            _ => {
                // 明文 TCP（tls 为 None 或 enabled=false）
                let server = &self.config.server;
                let port = self.config.server_port;
                let addr = resolve_server_addr(server, port, self.resolver.as_ref())
                    .await
                    .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;
                let tcp = TcpStream::connect(addr).await?;
                set_tcp_opts(&tcp)?;
                apply_mark_to_tcp(&tcp, self.routing_mark)?;
                Ok(Box::new(VlessTcpStream::new(tcp, header)))
            }
        }
    }
}

#[async_trait::async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let uuid = Self::parse_uuid(&self.config.uuid)?;
        let target = Target::Domain(host.to_string(), port);
        let header = Self::build_request_header(&uuid, &target, None)?.freeze();
        self.dial(header).await
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let uuid = Self::parse_uuid(&self.config.uuid)?;
        let header = Self::build_request_header(&uuid, &conn.target, None)?.freeze();

        let transport_type = match &self.config.transport {
            Some(VlessTransportConfig::Ws(_)) => "ws",
            Some(VlessTransportConfig::Xhttp(_)) => "xhttp",
            Some(VlessTransportConfig::Grpc(_)) => "grpc",
            _ => "tcp",
        };
        debug!(tag = %self.config.tag, target = %conn.target, transport = transport_type, "vless tcp connecting");

        let io = self.dial(header).await?;
        Ok(relay(conn.stream, io).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        use crate::outbound::common::proto::vless_build_udp_request;
        use crate::outbound::vmess::{PACKETADDR_MAGIC, PACKETADDR_MAGIC_PORT};
        use tokio::io::AsyncWriteExt;

        let uuid = Self::parse_uuid(&self.config.uuid)?;
        // packetaddr 模式：请求头中使用魔术地址，服务端据此进入 packetaddr 模式。
        // 真实目标地址通过后续分帧的 [ATYP][ADDR][PORT][DATA] 携带。
        let magic_target = Target::Domain(PACKETADDR_MAGIC.to_string(), PACKETADDR_MAGIC_PORT);
        let header = vless_build_udp_request(&uuid, &magic_target)?;

        debug!(tag=%self.config.tag, target=%packet.target, "vless udp session opened (packetaddr)");

        // packetaddr 不支持 FQDN（sing-vmess packetaddr.ErrFqdnUnsupported），
        // 必须先将域名目标解析为 IP，再构建 packetaddr 帧。
        // 与 sing-box protocol/vless/outbound.go:171 对齐：
        //   "packetaddr: domain destination is not supported"
        let first_dst_addr =
            resolve_target_with_dns(&packet.target, self.resolver.as_ref()).await?;

        let io = self.dial(header).await?;
        let (reader, mut writer) = tokio::io::split(io);

        // VLESS UDP 使用 packetaddr 分帧（与 VMess 一致，与 sing-vmess packetaddr.AddressSerializer 对齐）：
        //   [ATYP 1B][ADDR 4/16B][PORT u16 BE][DATA]
        // 无长度前缀，帧边界由底层流的消息边界提供。
        // 旧实现使用 [ATYP][ADDR][PORT][LEN][DATA] 格式（带长度前缀）且支持域名，
        // 与 sing-vmess packetaddr 格式不兼容 → 服务端解析失败。
        let frame = build_packetaddr_frame(first_dst_addr, &packet.data);
        writer.write_all(&frame).await?;
        writer.flush().await?;

        let timeout = std::time::Duration::from_secs(5);
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());

        // 若有后续上行包，spawn task 持续将上行包写入 VLESS 隧道（每包带 packetaddr 帧）
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let resolver = self.resolver.clone();
            // 会话按 (src, outbound) 聚合后每包目标可能不同；packetaddr
            // 不支持 FQDN，需按每包 target 解析为 SocketAddr。用 HashMap 缓存
            // 避免同一目标每包都走 DNS。
            let first_target = packet.target.clone();
            tokio::spawn(async move {
                let mut dst_cache: std::collections::HashMap<Target, std::net::SocketAddr> =
                    std::collections::HashMap::new();
                dst_cache.insert(first_target, first_dst_addr);
                while let Some((target, data)) = upstream_rx.recv().await {
                    let dst_addr = match dst_cache.get(&target).copied() {
                        Some(d) => d,
                        None => match resolve_target_with_dns(&target, resolver.as_ref()).await {
                            Ok(d) => {
                                dst_cache.insert(target, d);
                                d
                            }
                            Err(e) => {
                                debug!(target=%target, err=%e, "vless udp: dns resolve error");
                                continue;
                            }
                        },
                    };
                    let frame = build_packetaddr_frame(dst_addr, &data);
                    if writer.write_all(&frame).await.is_err() || writer.flush().await.is_err() {
                        break;
                    }
                }
            });
        }

        // 接收侧：从流中按 packetaddr 帧解析回包
        let mut pa_reader = PacketAddrReader::new(reader);
        let mut buf = vec![0u8; 65535];
        loop {
            match tokio::time::timeout(timeout, pa_reader.read_packet(&mut buf)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(n)) => {
                    let _ = reply_tx
                        .send((bytes::Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                        .await;
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

// ── TCP Stream 适配器（VLESS over TCP/REALITY）────────────────────────────────

use pin_project_lite::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// 在 TCP/TLS 流上实现 VLESS 帧：首次写入拼接请求头，首次读取跳过响应头。
pin_project! {
    pub struct VlessTcpStream<S> {
        #[pin]
        inner: S,
        pending_header: Option<Bytes>,
        read_buf: Bytes,
        response_header_skipped: bool,
        // 暂存已读但未处理的字节（用于跳过 VLESS 响应头）
        raw_buf: Vec<u8>,
        // 待发送的合并缓冲区（header + data），用于处理部分写或 Pending
        // 旧实现：Pending 时把 header 放回 pending_header，data 直接丢弃 → 数据丢失
        pending_write: Option<Bytes>,
        // pending_write 完整发出后应上报的"已写字节数"（即原始 data.len()）
        pending_reported: usize,
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessTcpStream<S> {
    pub fn new(inner: S, header: Bytes) -> Self {
        Self {
            inner,
            pending_header: Some(header),
            read_buf: Bytes::new(),
            response_header_skipped: false,
            raw_buf: Vec::new(),
            pending_write: None,
            pending_reported: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VlessTcpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();

        // 先消费 read_buf（之前读出但未一次性给完的数据）
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            *this.read_buf = this.read_buf.slice(n..);
            return Poll::Ready(Ok(()));
        }

        if !*this.response_header_skipped {
            // 需要先读取并跳过 VLESS 响应头 [Ver 1B][Addon Len 1B][Addon ...]
            // 旧实现：读一次后若不够 2+addon_len 字节，直接返回 Ok(())（空 buf），
            // 调用者会误判为 EOF；且没有重新注册 waker，等同 busy-loop。
            // 修正：循环读取直到凑够头部、或返回 Pending（waker 已由 inner 注册）、或 EOF。
            loop {
                if this.raw_buf.len() >= 2 {
                    let addon_len = this.raw_buf[1] as usize;
                    let hdr_len = 2 + addon_len;
                    if this.raw_buf.len() >= hdr_len {
                        *this.response_header_skipped = true;
                        let payload = Bytes::copy_from_slice(&this.raw_buf[hdr_len..]);
                        this.raw_buf.clear();
                        if !payload.is_empty() {
                            *this.read_buf = payload;
                            let n = buf.remaining().min(this.read_buf.len());
                            buf.put_slice(&this.read_buf[..n]);
                            *this.read_buf = this.read_buf.slice(n..);
                            return Poll::Ready(Ok(()));
                        }
                        // header 后无附带 payload，跳出循环继续读 inner
                        break;
                    }
                }
                // 数据不够，从 inner 读更多
                let mut temp_storage = [0u8; 512];
                let mut temp_buf = ReadBuf::new(&mut temp_storage);
                match this.inner.as_mut().poll_read(cx, &mut temp_buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let filled = temp_buf.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Ok(())); // 真正的 EOF
                        }
                        this.raw_buf.extend_from_slice(filled);
                    }
                }
            }
        }

        // 响应头已跳过，直接读 inner
        this.inner.as_mut().poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VlessTcpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();

        // 1. 优先完成上一次未写完的合并缓冲区
        if let Some(pending) = this.pending_write.take() {
            return match this.inner.poll_write(cx, &pending) {
                Poll::Ready(Ok(n)) if n >= pending.len() => {
                    let reported = *this.pending_reported;
                    *this.pending_reported = 0;
                    Poll::Ready(Ok(reported))
                }
                Poll::Ready(Ok(n)) => {
                    // 部分写：保留剩余，下次继续
                    *this.pending_write = Some(pending.slice(n..));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    *this.pending_reported = 0;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => {
                    *this.pending_write = Some(pending);
                    Poll::Pending
                }
            };
        }

        // 2. 首次写：合并 header + data
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
                    // 旧实现：把 header 放回 pending_header，data 丢弃 → 数据丢失
                    // 修正：保存合并缓冲区，下次 poll_write 时优先完成它
                    *this.pending_write = Some(combined);
                    *this.pending_reported = data.len();
                    Poll::Pending
                }
            };
        }

        // 3. 无 header，直接透传
        this.inner.poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uuid_ok() {
        let uuid = VlessOutbound::parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(uuid[0], 0xaa);
        assert_eq!(uuid[15], 0xee);
    }

    #[test]
    fn build_request_header_domain() {
        let uuid = [0xau8; 16];
        let target = Target::Domain("example.com".into(), 443);
        let hdr = VlessOutbound::build_request_header(&uuid, &target, None).unwrap();
        assert_eq!(hdr[0], 0x00);
        assert_eq!(&hdr[1..17], &uuid);
        assert_eq!(hdr[17], 0x00);
        assert_eq!(hdr[18], 0x01);
        assert_eq!(u16::from_be_bytes([hdr[19], hdr[20]]), 443);
        assert_eq!(hdr[21], 0x02);
    }
}
