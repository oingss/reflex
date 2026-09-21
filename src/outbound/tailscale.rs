use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use crate::{
    config::outbound::TailscaleOutboundConfig,
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{resolve_target_with_dns, Outbound, OutboundStatus},
};

/// Tailscale 状态文件名（与 clash-rs 一致）。
const TAILSCALE_STATE_FILE_NAME: &str = "tailscale_state.json";

/// Tailscale 默认 client 名称。
const TAILSCALE_DEFAULT_CLIENT_NAME: &str = "reflex";

// ── TailscaleOutbound ────────────────────────────────────────────────────────

pub struct TailscaleOutbound {
    config: TailscaleOutboundConfig,
    /// 懒加载的 Tailscale Device（首次连接时初始化，之后复用）
    device: tokio::sync::Mutex<Option<Arc<tailscale::Device>>>,
    /// 用于把域名目标解析为 IP（Tailscale netstack 只接受 IP）
    resolver: Option<Arc<DnsResolver>>,
}

impl TailscaleOutbound {
    pub fn new(config: TailscaleOutboundConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            device: tokio::sync::Mutex::new(None),
            resolver: None,
        })
    }

    pub fn with_resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// 懒加载 Tailscale Device：首次调用时根据配置初始化，之后直接返回缓存。
    ///
    /// - `ephemeral = true` 时不加载状态文件（每次启动都是新身份）
    /// - `state_dir` 提供时从中加载 `tailscale_state.json`（持久身份）
    /// - 否则使用内存中的临时状态
    async fn get_device(&self) -> io::Result<Arc<tailscale::Device>> {
        let mut guard = self.device.lock().await;
        if let Some(device) = guard.as_ref() {
            return Ok(Arc::clone(device));
        }

        // 上游 crate 要求显式确认实验性软件身份。
        // SAFETY: 仅在 lazy-init 路径执行一次，且不影响其他系统进程。
        // 与 clash-rs 行为一致。
        unsafe {
            std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");
        }

        // 加载持久身份（若配置了 state_dir 且非 ephemeral）
        let key_state = if self.config.ephemeral {
            Default::default()
        } else if let Some(state_dir) = self.config.state_dir.as_ref() {
            let state_file = std::path::PathBuf::from(state_dir).join(TAILSCALE_STATE_FILE_NAME);
            match tailscale::config::load_key_file(
                state_file.clone(),
                tailscale::config::BadFormatBehavior::Overwrite,
            )
            .await
            {
                Ok(ks) => ks,
                Err(e) => {
                    // 文件不存在或格式错误时不阻塞启动：fallback 到空状态，
                    // 触发新一轮认证（用户会拿到新的 auth URL）。
                    warn!(path = %state_file.display(), err = %e, "tailscale: load key state failed, falling back to fresh identity");
                    Default::default()
                }
            }
        } else {
            Default::default()
        };

        let mut ts_config = tailscale::Config {
            key_state,
            ..Default::default()
        };
        ts_config.client_name = Some(
            self.config
                .client_name
                .clone()
                .unwrap_or_else(|| TAILSCALE_DEFAULT_CLIENT_NAME.to_string()),
        );
        ts_config.requested_hostname = self.config.hostname.clone();

        if let Some(control_url) = self.config.control_url.as_ref() {
            ts_config.control_server_url = control_url.parse().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid control_url: {e}"),
                )
            })?;
        }

        let device = tailscale::Device::new(&ts_config, self.config.auth_key.clone())
            .await
            .map_err(|e| io::Error::other(format!("failed to initialize tailscale device: {e}")))?;
        let device = Arc::new(device);
        *guard = Some(Arc::clone(&device));
        Ok(device)
    }

    /// 解析目标地址为 IP（Tailscale netstack 只接受 IP，不接受域名）。
    async fn resolve_target_ip(&self, target: &Target) -> io::Result<IpAddr> {
        match target {
            Target::Socket(addr) => Ok(addr.ip()),
            Target::Domain(host, _) => {
                let ip = resolve_target_with_dns(target, self.resolver.as_ref())
                    .await
                    .map_err(|e| io::Error::other(format!("dns resolve '{host}' failed: {e}")))?;
                Ok(ip.ip())
            }
        }
    }
}

#[async_trait]
impl Outbound for TailscaleOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Tailscale".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let target = &conn.target;
        let port = target.port();
        let ip = self.resolve_target_ip(target).await?;

        debug!(
            tag = %self.config.tag,
            target = %target,
            ip = %ip,
            port = port,
            "tailscale: tcp connect"
        );

        let device = self.get_device().await?;
        let stream = device
            .tcp_connect((ip, port).into())
            .await
            .map_err(|e| anyhow::anyhow!("tailscale: tcp_connect to {ip}:{port} failed: {e}"))?;

        // 把 device 保留在 stream 包装层中，避免 device 在 stream 还在使用时被释放。
        // 实际上 device 是 Arc<Device>，只要 stream 内部持有它即可。
        let stream = TailscaleTcpStream::new(stream, device);
        Ok(crate::outbound::relay(conn.stream, stream).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let target = &packet.target;
        let port = target.port();
        let dst_ip = self.resolve_target_ip(target).await?;

        let device = self.get_device().await?;

        // 选一个本机在 Tailscale 网络中的地址作为源（按目标 IP 协议族匹配）
        let local_ip: IpAddr = match dst_ip {
            IpAddr::V4(_) => device
                .ipv4_addr()
                .await
                .map(IpAddr::V4)
                .map_err(|e| anyhow::anyhow!("tailscale: get ipv4_addr failed: {e}"))?,
            IpAddr::V6(_) => device
                .ipv6_addr()
                .await
                .map(IpAddr::V6)
                .map_err(|e| anyhow::anyhow!("tailscale: get ipv6_addr failed: {e}"))?,
        };

        // 选一个临时源端口（49152..=u16::MAX）
        let local_port: u16 = rand::thread_rng().gen_range(49152u16..=u16::MAX);
        let udp = device
            .udp_bind(std::net::SocketAddr::new(local_ip, local_port))
            .await
            .map_err(|e| {
                anyhow::anyhow!("tailscale: udp_bind on {local_ip}:{local_port} failed: {e}")
            })?;

        let dst_addr = std::net::SocketAddr::new(dst_ip, port);
        debug!(
            tag = %self.config.tag,
            target = %target,
            local = %local_ip,
            local_port = local_port,
            "tailscale: udp session"
        );

        // 发送首包
        let udp = Arc::new(tokio::sync::Mutex::new(udp));
        {
            let sock = udp.lock().await;
            sock.send_to(dst_addr, &packet.data).await?;
        }

        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());

        // 上行：后续包通过 upstream_rx 收到，写入 UDP socket
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let udp_up = udp.clone();
            tokio::spawn(async move {
                while let Some((target, data)) = upstream_rx.recv().await {
                    // 每个包的目标可能不同，需重新解析
                    let dst = match target {
                        Target::Socket(a) => a,
                        Target::Domain(_, _) => {
                            match resolve_target_with_dns(&target, None).await {
                                Ok(a) => a,
                                Err(_) => continue,
                            }
                        }
                    };
                    let sock = udp_up.lock().await;
                    if sock.send_to(dst, &data).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 下行：循环读取 UDP 回包，发回给客户端
        // 注意：必须持有 udp 锁直到 recv_from 完成；锁与等待是同步发生的，
        // 与 clash-rs 行为一致。
        let timeout = std::time::Duration::from_secs(5);
        let mut buf = vec![0u8; 65535];
        loop {
            let sock = udp.lock().await;
            match tokio::time::timeout(timeout, sock.recv_from(&mut buf)).await {
                Ok(Ok((_, n))) => {
                    drop(sock);
                    if n == 0 {
                        break;
                    }
                    let _ = reply_tx
                        .send((bytes::Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                        .await;
                }
                Ok(Err(_)) => break,
                Err(_) => break, // 超时
            }
        }
        Ok(())
    }

    /// 通过 Tailscale 网络建立到 (host, port) 的 TCP 连接，供 DNS-over-TCP detour 使用。
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let ip = self.resolve_target_ip(&target).await?;
        let device = self.get_device().await?;
        let stream = device
            .tcp_connect((ip, port).into())
            .await
            .map_err(|e| anyhow::anyhow!("tailscale: tcp_connect to {ip}:{port} failed: {e}"))?;
        Ok(Box::new(TailscaleTcpStream::new(stream, device)))
    }
}

// ── TailscaleTcpStream ───────────────────────────────────────────────────────

/// 包装 `tailscale::netstack::TcpStream` 为 `AsyncRead + AsyncWrite`。
///
/// 同时持有 `Arc<tailscale::Device>` 守卫，确保 stream 在使用期间 Device 不会被释放。
pub struct TailscaleTcpStream {
    inner: tailscale::netstack::TcpStream,
    /// 持有 Device 防止提前释放
    _device: Arc<tailscale::Device>,
}

impl TailscaleTcpStream {
    pub fn new(inner: tailscale::netstack::TcpStream, device: Arc<tailscale::Device>) -> Self {
        Self {
            inner,
            _device: device,
        }
    }
}

impl AsyncRead for TailscaleTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TailscaleTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
