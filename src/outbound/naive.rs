use std::sync::Arc;

use http::{Method, Request, StatusCode, Uri};
use rustls::ClientConfig;
use tokio::io::AsyncWriteExt;
use tracing::debug;

use crate::config::outbound::NaiveOutboundConfig;
use crate::inbound::{InboundTcpStream, InboundUdpPacket, Target};
use crate::outbound::{
    apply_mark_to_tcp, relay, resolve_server_addr, set_tcp_opts, tls::build_client_config,
    Outbound,
};

// UOT（UDP-over-TCP）帧原语与 anytls 共用（已上移至 protocol/anytls）
use crate::protocol::anytls::{
    build_uot_packet, build_uot_request, read_uot_packet, UOT_MAGIC_ADDRESS, UOT_MAGIC_PORT,
};

// 兼容再导出：Naive wire-format 原语已上移至 `protocol/naive`，
// 保留原有 `crate::outbound::naive::*` 路径可用（pub use 同时把名字
// 引入本模块作用域，dial() 与测试直接使用）。
pub use crate::protocol::naive::{
    generate_padding_header, NaiveStream, MAX_PADDING_CHUNK, PADDING_COUNT, PADDING_HEADER_CHARSET,
};

use crate::protocol::naive::build_basic_auth_value;

// ── NaiveOutbound ─────────────────────────────────────────────────────────────

pub struct NaiveOutbound {
    config: NaiveOutboundConfig,
    tls_config: Arc<ClientConfig>,
    routing_mark: u32,
    resolver: Option<Arc<crate::dns::DnsResolver>>,
}

impl NaiveOutbound {
    pub fn new(config: NaiveOutboundConfig) -> anyhow::Result<Self> {
        validate(&config)?;
        let tls_config = build_client_config(&config.tls)?;
        Ok(Self {
            config,
            tls_config,
            routing_mark: 0,
            resolver: None,
        })
    }

    pub fn with_resolver(mut self, resolver: Arc<crate::dns::DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 建立到目标的 NaiveProxy 隧道
    async fn dial(&self, target: &Target) -> anyhow::Result<NaiveStream> {
        // 1. TCP 连接到 naive 服务器
        let addr = resolve_server_addr(
            &self.config.server,
            self.config.server_port,
            self.resolver.as_ref(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("naive: resolve server {} failed: {e}", self.config.server))?;

        let tcp = crate::outbound::connect_tcp_interface(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;

        // 2. TLS 握手（使用 ALPN 协商 h2）
        let sni = self
            .config
            .tls
            .server_name
            .as_deref()
            .unwrap_or(&self.config.server);
        let tls_stream =
            crate::outbound::tls::connect_tls(tcp, sni, self.tls_config.clone()).await?;

        // 3. h2 握手
        let (send_req, connection) = h2::client::handshake(tls_stream)
            .await
            .map_err(|e| anyhow::anyhow!("naive: h2 handshake failed: {e}"))?;

        // 4. 后台驱动 h2 连接
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                debug!("naive: h2 connection ended: {e}");
            }
        });

        // 5. 构建 CONNECT 请求
        let authority = format!("{}:{}", target.host(), target.port());
        let uri = Uri::builder()
            .scheme("https")
            .authority(authority.as_str())
            .build()
            .map_err(|e| anyhow::anyhow!("naive: invalid authority '{authority}': {e}"))?;

        let auth = build_basic_auth_value(&self.config.username, &self.config.password);

        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(uri)
            .header("Proxy-Authorization", auth)
            .header("Padding", generate_padding_header());

        for (k, v) in &self.config.extra_headers {
            builder = builder.header(k.as_str(), v.as_str());
        }

        let request = builder
            .body(())
            .map_err(|e| anyhow::anyhow!("naive: build CONNECT request failed: {e}"))?;

        // 6. 发送 CONNECT 请求
        let mut h2_ready = send_req
            .ready()
            .await
            .map_err(|e| anyhow::anyhow!("naive: h2 ready failed: {e}"))?;
        let (response, send_stream) = h2_ready
            .send_request(request, false)
            .map_err(|e| anyhow::anyhow!("naive: send CONNECT failed: {e}"))?;

        // 7. 等待 200 响应
        let response = response
            .await
            .map_err(|e| anyhow::anyhow!("naive: CONNECT response failed: {e}"))?;
        if response.status() != StatusCode::OK {
            anyhow::bail!("naive: CONNECT failed with status {}", response.status());
        }

        let recv_stream = response.into_body();

        debug!(
            tag = %self.config.tag,
            target = %target,
            "naive: CONNECT tunnel established"
        );

        Ok(NaiveStream::new(send_stream, recv_stream))
    }
}

// ── 配置校验 ──────────────────────────────────────────────────────────────────

fn validate(config: &NaiveOutboundConfig) -> anyhow::Result<()> {
    // TLS 必须启用
    if !config.tls.enabled {
        anyhow::bail!("naive outbound requires TLS to be enabled");
    }

    // QUIC 模式暂不支持
    if config.quic {
        anyhow::bail!("naive outbound: QUIC (HTTP/3) mode is not yet supported in reflex");
    }

    // 校验 quic_congestion_control 值
    match config.quic_congestion_control.as_str() {
        "" | "bbr" | "bbr2" | "cubic" | "reno" => {}
        other => anyhow::bail!("naive outbound: invalid quic_congestion_control '{other}'"),
    }

    Ok(())
}

// ── Outbound trait ────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for NaiveOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let stream = self.dial(&target).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            "naive tcp connecting"
        );
        let stream = self.dial(&conn.target).await?;
        Ok(relay(conn.stream, stream).await)
    }

    /// UDP 使用 sing-box UDP-over-TCP v2 协议承载（复用 anytls 的 UoT v2 实现）。
    ///
    /// 流程与 anytls `handle_udp` 一致：
    /// 1. 向 naive 服务端发起目标 = `sp.v2.udp-over-tcp.arpa:443` 的 CONNECT
    /// 2. 写 UoT v2 请求头（包含真实目标地址）
    /// 3. 发送第一个 UDP 包
    /// 4. spawn task 持续写入后续上行包
    /// 5. 当前 task 持续读取下行 UDP 包并回给入站
    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let uot_enabled = self
            .config
            .udp_over_tcp
            .as_ref()
            .map(|u| u.enabled)
            .unwrap_or(false);

        if !uot_enabled {
            anyhow::bail!("naive outbound: UDP requires udp_over_tcp enabled");
        }

        debug!(
            tag = %self.config.tag,
            target = %packet.target,
            "naive udp session (UoT v2)"
        );

        let uot_target = Target::Domain(UOT_MAGIC_ADDRESS.to_string(), UOT_MAGIC_PORT);
        let mut stream = self.dial(&uot_target).await?;

        // 写 UoT v2 请求头
        let req_hdr = build_uot_request(&packet.target);
        stream.write_all(&req_hdr).await?;

        // 发送第一个 UDP 数据包
        let first = build_uot_packet(&packet.target, &packet.data);
        stream.write_all(&first).await?;

        let timeout = std::time::Duration::from_secs(30);
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());

        let (mut read_half, mut write_half) = tokio::io::split(stream);

        // 上行任务：持续将后续 UDP 包写入隧道
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            tokio::spawn(async move {
                while let Some((target, data)) = upstream_rx.recv().await {
                    let frame = build_uot_packet(&target, &data);
                    if write_half.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 下行：读取 UoT v2 封装的 UDP 包并回给入站
        loop {
            match tokio::time::timeout(timeout, read_uot_packet(&mut read_half)).await {
                Ok(Ok((_target, data))) => {
                    let _ = reply_tx.send((data, src, spoofed_src)).await;
                }
                Ok(Err(e)) => {
                    let s = e.to_string();
                    if s.contains("eof")
                        || s.contains("EOF")
                        || s.contains("closed")
                        || s.contains("reset")
                    {
                        break;
                    }
                    return Err(e);
                }
                Err(_) => break, // timeout
            }
        }

        Ok(())
    }
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn padding_header_format() {
        let hdr = generate_padding_header();
        // 长度在 30..=61
        assert!(hdr.len() >= 30 && hdr.len() <= 61);
        // 前 16 字符在字符集内
        for b in hdr.bytes().take(16) {
            assert!(
                PADDING_HEADER_CHARSET.contains(&b),
                "char {} not in charset",
                b
            );
        }
        // 其余为 ~
        for b in hdr.bytes().skip(16) {
            assert_eq!(b, b'~');
        }
    }

    #[test]
    fn validate_rejects_no_tls() {
        let mut cfg = NaiveOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            username: String::new(),
            password: String::new(),
            insecure_concurrency: 0,
            extra_headers: Default::default(),
            stream_receive_window: Default::default(),
            udp_over_tcp: None,
            quic: false,
            quic_congestion_control: String::new(),
            quic_session_receive_window: Default::default(),
            tls: crate::config::outbound::TlsConfig {
                enabled: false,
                ..Default::default()
            },
        };
        assert!(validate(&cfg).is_err());

        // 启用 TLS 后校验通过（TLS 配置本身不在此处检查）
        cfg.tls.enabled = true;
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn validate_rejects_quic_mode() {
        let cfg = NaiveOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            username: String::new(),
            password: String::new(),
            insecure_concurrency: 0,
            extra_headers: Default::default(),
            stream_receive_window: Default::default(),
            udp_over_tcp: None,
            quic: true,
            quic_congestion_control: String::new(),
            quic_session_receive_window: Default::default(),
            tls: crate::config::outbound::TlsConfig {
                enabled: true,
                ..Default::default()
            },
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_quic_congestion_control_values() {
        let valid = ["", "bbr", "bbr2", "cubic", "reno"];
        for cc in &valid {
            let cfg = NaiveOutboundConfig {
                tag: "test".into(),
                server: "example.com".into(),
                server_port: 443,
                username: String::new(),
                password: String::new(),
                insecure_concurrency: 0,
                extra_headers: Default::default(),
                stream_receive_window: Default::default(),
                udp_over_tcp: None,
                quic: false,
                quic_congestion_control: cc.to_string(),
                quic_session_receive_window: Default::default(),
                tls: crate::config::outbound::TlsConfig {
                    enabled: true,
                    ..Default::default()
                },
            };
            assert!(validate(&cfg).is_ok(), "should accept cc='{cc}'");
        }

        let cfg = NaiveOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            username: String::new(),
            password: String::new(),
            insecure_concurrency: 0,
            extra_headers: Default::default(),
            stream_receive_window: Default::default(),
            udp_over_tcp: None,
            quic: false,
            quic_congestion_control: "invalid".into(),
            quic_session_receive_window: Default::default(),
            tls: crate::config::outbound::TlsConfig {
                enabled: true,
                ..Default::default()
            },
        };
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn base64_auth_encoding() {
        let auth = base64::engine::general_purpose::STANDARD.encode("user:pass");
        assert_eq!(auth, "dXNlcjpwYXNz");
    }
}
