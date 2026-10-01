use std::net::{SocketAddr};
use std::sync::Arc;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::io::AsyncReadExt;
use tracing::debug;

// 协议原语已上移到 protocol/vmess.rs（inbound 服务端与 outbound 客户端共享），
// 此处 re-export 保持旧路径 `crate::outbound::vmess::*` 的兼容性
//（如 outbound/vless.rs 引用 PACKETADDR_MAGIC）。
pub use crate::protocol::vmess::*;

use crate::{
    config::outbound::{VmessOutboundConfig, VmessTransportConfig},
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, relay, resolve_server_addr, resolve_target_with_dns, set_tcp_opts,
        AsyncReadWrite, Outbound, OutboundStatus,
    },
};

// ════════════════════════════════════════════════════════════════════════════
// 主结构与 Outbound 实现（协议原语见 protocol/vmess.rs）
// ════════════════════════════════════════════════════════════════════════════

pub struct VmessOutbound {
    config: VmessOutboundConfig,
    user_key: [u8; 16],
    security: u8,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<DnsResolver>>,
}

impl VmessOutbound {
    pub fn new(config: VmessOutboundConfig) -> anyhow::Result<Self> {
        let uuid = parse_uuid(&config.uuid)?;
        let user_key = user_key(&uuid);
        // 与 sing-box protocol/vmess/outbound.go:93-99 对齐：
        // security 为空时默认 "auto"；"auto" + TLS 启用时降级为 "zero"（明文），
        // 因为外层 TLS 已提供机密性，内层再加密是冗余。
        let normalized = if config.security.is_empty() {
            "auto"
        } else {
            config.security.as_str()
        };
        let effective_security = match (normalized, config.tls.enabled) {
            ("auto", true) => "zero",
            (s, _) => s,
        };
        let security = resolve_security(effective_security)?;
        Ok(Self {
            config,
            user_key,
            security,
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

    // ── 建立底层连接 ────────────────────────────────────────────────────────

    async fn connect_raw(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        match &self.config.transport {
            VmessTransportConfig::Ws(ws_cfg) => {
                let sni = self
                    .config
                    .tls
                    .server_name
                    .as_deref()
                    .unwrap_or(self.config.server.as_str());
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
                    crate::outbound::transport::websocket::WsStream::new(ws),
                ))
            }
            VmessTransportConfig::Xhttp(xhttp_cfg) => {
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
                Ok(Box::new(stream))
            }
            VmessTransportConfig::Grpc(grpc_cfg) => {
                let sni = self
                    .config
                    .tls
                    .server_name
                    .as_deref()
                    .unwrap_or(self.config.server.as_str());
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
                Ok(Box::new(stream))
            }
            VmessTransportConfig::Tcp => self.connect_tcp_raw().await,
        }
    }

    async fn connect_tcp_raw(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let addr = resolve_server_addr(server, port, self.resolver.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;
        let tcp = crate::outbound::connect_tcp_interface(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;
        if self.config.tls.enabled {
            let sni = self
                .config
                .tls
                .server_name
                .as_deref()
                .unwrap_or(server.as_str());
            let stream =
                crate::outbound::tls::connect_tls_or_utls(tcp, sni, &self.config.tls).await?;
            Ok(Box::new(stream))
        } else {
            Ok(Box::new(tcp))
        }
    }

    // ── VMess 握手 ───────────────────────────────────────────────────────────

    async fn handshake(
        &self,
        mut raw: Box<dyn AsyncReadWrite>,
        target: &Target,
        command: u8,
    ) -> anyhow::Result<VmessStream<Box<dyn AsyncReadWrite>>> {
        let req_hdr = RequestHeader::new(self.security, command);

        // 1. 发送握手帧（AuthID + EncLen + ConnNonce + EncHeader）
        let handshake_bytes = build_handshake(&self.user_key, &req_hdr, target);
        use tokio::io::AsyncWriteExt;
        raw.write_all(&handshake_bytes).await?;
        raw.flush().await?;

        // 2. 读取响应头
        // AEAD 响应：[EncLen 2+16B][EncHeader 4+16B] = 38 字节
        const RESP_TOTAL: usize = (2 + 16) + (4 + 16);
        let mut resp_buf = vec![0u8; RESP_TOTAL];
        raw.read_exact(&mut resp_buf).await?;

        let (token, _) = parse_response_header(&resp_buf, &req_hdr.req_key, &req_hdr.req_nonce)?;
        anyhow::ensure!(
            token == req_hdr.resp_header,
            "vmess: response token mismatch (got {token:#04x}, expected {:#04x})",
            req_hdr.resp_header
        );

        debug!(tag = %self.config.tag, target = %target, "vmess handshake ok");

        // 3. 包装为 VmessStream
        Ok(VmessStream::new(
            raw,
            self.security,
            req_hdr.option,
            &req_hdr.req_key,
            &req_hdr.req_nonce,
        ))
    }
}

// ── Outbound impl ─────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "VMess".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let raw = self.connect_raw().await?;
        let stream = self.handshake(raw, &target, CMD_TCP).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let raw = self.connect_raw().await?;
        let vmess = self.handshake(raw, &conn.target, CMD_TCP).await?;
        debug!(tag = %self.config.tag, target = %conn.target, "vmess tcp relay");
        Ok(relay(conn.stream, vmess).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let raw = self.connect_raw().await?;
        // packetaddr 模式：请求头中使用魔术地址，服务端据此进入 packetaddr 模式。
        // 真实目标地址通过后续分帧的 [ATYP][ADDR][PORT][DATA] 携带。
        // 旧实现将实际目标写入请求头，服务端不进入 packetaddr 模式 → UDP 不可用。
        let magic_target = Target::Domain(PACKETADDR_MAGIC.to_string(), PACKETADDR_MAGIC_PORT);
        let mut vmess = self.handshake(raw, &magic_target, CMD_UDP).await?;
        debug!(tag = %self.config.tag, target = %packet.target, "vmess udp relay (packetaddr)");

        // packetaddr 不支持 FQDN（sing-vmess packetaddr.ErrFqdnUnsupported），
        // 必须先将域名目标解析为 IP，再构建 packetaddr 帧。
        // 与 sing-box protocol/vmess/outbound.go:198 对齐：
        //   "packetaddr: domain destination is not supported"
        let first_dst_addr =
            resolve_target_with_dns(&packet.target, self.resolver.as_ref()).await?;

        // VMess UDP 使用 packetaddr 分帧（与 sing-vmess packetaddr.AddressSerializer 一致）：
        //   [ATYP 1B][ADDR 4/16B][PORT u16 BE][DATA]
        // 无长度前缀，帧边界由 VMess AEAD chunk stream 的 chunk 边界提供。
        // 旧实现直接 write_all(&packet.data)，将裸 payload 写入流隧道，
        // 服务端无法区分包边界，也无法将回包关联到正确目标地址，
        // 导致 UDP 实质不可用。

        // 发送第一个包（带 packetaddr 帧）
        use tokio::io::AsyncWriteExt;
        let frame = build_packetaddr_frame(first_dst_addr, &packet.data);
        vmess.write_all(&frame).await?;
        vmess.flush().await?;

        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());
        let timeout = std::time::Duration::from_secs(10);

        // 若有后续上行包，spawn task 持续写入 vmess 隧道（每包带 packetaddr 帧）
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let (vmess_rd, mut vmess_wr) = tokio::io::split(vmess);
            let resolver = self.resolver.clone();
            // 会话按 (src, outbound) 聚合后每包目标可能不同；packetaddr
            // 不支持 FQDN，需按每包 target 解析为 SocketAddr。用 HashMap 缓存
            // 避免同一目标每包都走 DNS。
            let first_target = packet.target.clone();

            tokio::spawn(async move {
                let mut dst_cache: std::collections::HashMap<Target, SocketAddr> =
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
                                debug!(target=%target, err=%e, "vmess udp: dns resolve error");
                                continue;
                            }
                        },
                    };
                    let frame = build_packetaddr_frame(dst_addr, &data);
                    if vmess_wr.write_all(&frame).await.is_err() || vmess_wr.flush().await.is_err()
                    {
                        break;
                    }
                }
            });

            // 接收侧：从流中按 packetaddr 帧解析回包
            let mut reader = PacketAddrReader::new(vmess_rd);
            let mut buf = vec![0u8; 65535];
            loop {
                match tokio::time::timeout(timeout, reader.read_packet(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        let _ = reply_tx
                            .send((Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                            .await;
                    }
                    Ok(Err(_)) => break,
                }
            }
        } else {
            let mut reader = PacketAddrReader::new(vmess);
            let mut buf = vec![0u8; 65535];
            loop {
                match tokio::time::timeout(timeout, reader.read_packet(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        let _ = reply_tx
                            .send((Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                            .await;
                    }
                    Ok(Err(_)) => break,
                }
            }
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// VMess UDP packetaddr 分帧（帧格式原语见 protocol/vmess.rs 常量；
// 此处的读取器依赖"一个 chunk = 一个帧"的流语义，属于 outbound 角色逻辑）
// ════════════════════════════════════════════════════════════════════════════
//
// VMess CMD_UDP 模式下，所有 UDP 数据包通过一条 TCP 流隧道传输。
// 为区分包边界并携带目标地址，每个包使用 packetaddr 帧格式：
//
//   [ATYP 1B][ADDR 4/16B][PORT u16 BE][DATA]
//
// 与 sing-vmess packetaddr.AddressSerializer 一致：
//   - ATYP 0x01 = IPv4 (4 字节地址)
//   - ATYP 0x02 = IPv6 (16 字节地址)
//   - 不支持域名（FQDN），调用方必须先解析域名
//
// **无长度前缀**：帧边界由 VMess AEAD chunk stream 的 chunk 边界提供。
// 每次 write_all 写入一个 chunk = 一个 packetaddr 帧；
// 每次 read 返回一个 chunk = 一个完整帧。
// 这与 sing-vmess packetconn.ReadPacket 的行为一致（底层 NetPacketConn.ReadPacket
// 读取一个 chunk 到 buffer，再从 buffer 头部解析 AddrPort，剩余即为 payload）。

/// 构建 packetaddr 帧：[ATYP][ADDR][PORT u16 BE][DATA]
///
/// 调用方必须传入已解析的 `SocketAddr`，因为 packetaddr 不支持 FQDN。
pub(crate) fn build_packetaddr_frame(addr: SocketAddr, data: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(32 + data.len());
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            buf.put_u8(PACKETADDR_ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            buf.put_u8(PACKETADDR_ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
    }
    buf.put_u16(addr.port());
    buf.put_slice(data);
    buf
}

/// 从 VMess UDP 流中按 packetaddr 帧逐包读取。
///
/// 每帧格式：[ATYP 1B][ADDR 4/16B][PORT u16 BE][DATA]
///
/// **无长度前缀**：VMess AEAD chunk stream 每次 `read` 返回一个 chunk 的数据，
/// 一个 chunk = 一个完整的 packetaddr 帧。因此一次 `read` 即可获得完整帧，
/// 从帧头解析 ATYP/ADDR/PORT 后，剩余字节即为 payload。
///
/// 这与 sing-vmess packetconn.ReadPacket 的行为一致：
/// ```go
/// func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
///     _, err = c.NetPacketConn.ReadPacket(buffer)  // 读取一个 chunk
///     destination, err = AddressSerializer.ReadAddrPort(buffer)  // 解析帧头
///     return destination.Unwrap(), nil  // buffer 剩余字节 = payload
/// }
/// ```
pub(crate) struct PacketAddrReader<R> {
    inner: R,
    /// 内部读取缓冲区（一次 read 返回一个 chunk = 一个 packetaddr 帧）
    /// 大于 VMess MAX_CHUNK=15000，确保单次 read 能容纳整个 chunk
    chunk_buf: Vec<u8>,
}

impl<R: tokio::io::AsyncRead + Unpin> PacketAddrReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            chunk_buf: vec![0u8; 17000],
        }
    }

    /// 读取一个完整的 packetaddr 帧，将 payload 写入 out，返回 payload 长度。
    /// 返回 0 表示流结束。
    pub(crate) async fn read_packet(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        // VMess chunk stream 每次 poll_read 返回一个 chunk 的数据。
        // 一个 chunk = 一个 packetaddr 帧 = [ATYP][ADDR][PORT u16 BE][DATA]
        // 因此一次 read 即可获得完整帧，无需长度前缀。
        let n = self.inner.read(&mut self.chunk_buf).await?;
        if n == 0 {
            return Ok(0);
        }

        if n < 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vmess packetaddr: frame too short for ATYP",
            ));
        }
        let atyp = self.chunk_buf[0];

        // 根据 ATYP 计算地址长度（与 sing-vmess packetaddr.AddressSerializer 一致）
        let addr_len = match atyp {
            PACKETADDR_ATYP_IPV4 => 4,
            PACKETADDR_ATYP_IPV6 => 16,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("vmess packetaddr: unknown ATYP {atyp:#04x}"),
                ))
            }
        };

        // 帧头 = ATYP(1) + ADDR(addr_len) + PORT(2)
        let header_len = 1 + addr_len + 2;
        if n < header_len {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("vmess packetaddr: frame {n} bytes shorter than header {header_len}"),
            ));
        }

        // 剩余字节即为 payload（无长度前缀，chunk 边界提供帧边界）
        let payload_len = n - header_len;
        if payload_len > out.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "vmess packetaddr: payload {payload_len} exceeds buffer {}",
                    out.len()
                ),
            ));
        }

        out[..payload_len].copy_from_slice(&self.chunk_buf[header_len..n]);
        Ok(payload_len)
    }
}
