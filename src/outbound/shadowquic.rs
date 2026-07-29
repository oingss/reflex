use std::sync::Arc;
use std::time::Duration;

use shadowquic::{
    config::{BrutalParams, CongestionControl, ShadowQuicClientCfg, SocketOpt},
    msgs::socks5::SocksAddr,
    shadowquic::outbound::{ShadowQuicClient, ShadowQuicConn},
    squic::outbound,
};
use tokio::sync::{Mutex, OnceCell};
use tracing::debug;

use crate::{
    config::outbound::ShadowQuicOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{relay, AsyncReadWrite, Outbound, OutboundStatus},
};

/// UDP 会话空闲超时（秒）。超过此时间无下行包则关闭会话。
const UDP_IDLE_TIMEOUT_SECS: u64 = 10;

pub struct ShadowQuicOutbound {
    config: ShadowQuicOutboundConfig,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<crate::dns::DnsResolver>>,
    /// 懒初始化的 ShadowQuicClient（首次使用时创建，含 DNS 解析）
    client: OnceCell<ShadowQuicClient>,
    /// 缓存的 QUIC 连接（连接池）
    cached: Mutex<Option<ShadowQuicConn>>,
}

impl ShadowQuicOutbound {
    pub fn new(config: ShadowQuicOutboundConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            routing_mark: 0,
            resolver: None,
            client: OnceCell::new(),
            cached: Mutex::new(None),
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

    // ── 连接管理 ─────────────────────────────────────────────────────────────

    /// 懒初始化 ShadowQuicClient，解析服务器域名并构建配置。
    ///
    /// shadowquic 内部 `get_conn()` 会调用 `cfg.addr.to_socket_addrs()` 解析地址，
    /// 此处预先用 reflex 的 DNS resolver 解析为 IP:port 字符串写入 `cfg.addr`，
    /// 避免 shadowquic 走系统 DNS（与 TUIC/Hy2 等出站行为一致）。
    async fn prepare_endpoint(&self) -> anyhow::Result<&ShadowQuicClient> {
        self.client
            .get_or_try_init(|| async {
                let addr = crate::outbound::resolve_server_addr(
                    &self.config.server,
                    self.config.server_port,
                    self.resolver.as_ref(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!("shadowquic DNS failed for {}: {e}", self.config.server)
                })?;

                let cfg = build_sq_config(&self.config, addr, self.routing_mark);
                Ok(ShadowQuicClient::new(cfg)) as anyhow::Result<ShadowQuicClient>
            })
            .await
    }

    /// 获取或创建 QUIC 连接（带连接池）。
    ///
    /// 与 clash-rs `Handler::prepare_conn` 一致：
    /// 1. 读锁检查缓存连接是否存活（`close_reason().is_none()`）
    /// 2. 若已关闭，获取写锁后 double-check，调用 `get_conn()` 重建
    async fn prepare_conn(&self) -> anyhow::Result<ShadowQuicConn> {
        // Fast path：读锁检查缓存连接
        {
            let guard = self.cached.lock().await;
            if let Some(ref c) = *guard {
                if c.close_reason().is_none() {
                    return Ok(c.clone());
                }
            }
        }

        // Slow path：写锁创建新连接
        let mut guard = self.cached.lock().await;
        // Double-check：防止多个任务同时进入 slow path 重复创建
        if let Some(ref c) = *guard {
            if c.close_reason().is_none() {
                return Ok(c.clone());
            }
            debug!(tag = %self.config.tag, "shadowquic cached conn closed, reconnecting");
        }

        let client = self.prepare_endpoint().await?;
        let conn = client
            .get_conn()
            .await
            .map_err(|e| anyhow::anyhow!("shadowquic get_conn: {e}"))?;
        *guard = Some(conn.clone());
        debug!(tag = %self.config.tag, "shadowquic QUIC connected");
        Ok(conn)
    }
}

// ── Outbound impl ─────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for ShadowQuicOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "ShadowQuic".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let conn = self.prepare_conn().await?;
        let dst = host_to_socks_addr(host, port);
        let stream = outbound::connect_tcp(&conn, dst)
            .await
            .map_err(|e| anyhow::anyhow!("shadowquic connect_tcp: {e}"))?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let sq_conn = self.prepare_conn().await?;
        let dst = target_to_socks_addr(&conn.target);
        debug!(tag = %self.config.tag, target = %conn.target, "shadowquic tcp relay");
        let proxy_stream = outbound::connect_tcp(&sq_conn, dst)
            .await
            .map_err(|e| anyhow::anyhow!("shadowquic connect_tcp: {e}"))?;
        Ok(relay(conn.stream, proxy_stream).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let sq_conn = self.prepare_conn().await?;

        // associate_udp 的 dst 是 bind_addr（服务端绑定地址），
        // 与 clash-rs 一致使用 0.0.0.0:0（或 [::]:0），让服务端自行选择。
        // 每个数据包的实际目标地址通过 udp_send 的 SocksAddr 单独指定。
        let bind_addr: SocksAddr = if packet.src.is_ipv4() {
            "0.0.0.0:0".parse::<std::net::SocketAddr>().unwrap().into()
        } else {
            "[::]:0".parse::<std::net::SocketAddr>().unwrap().into()
        };
        let (udp_send, mut udp_recv) =
            outbound::associate_udp(&sq_conn, bind_addr, self.config.over_stream)
                .await
                .map_err(|e| anyhow::anyhow!("shadowquic associate_udp: {e}"))?;

        // 发送首个 UDP 包（reflex 的 InboundUdpPacket 已携带首包数据）
        let first_dst = target_to_socks_addr(&packet.target);
        udp_send
            .send((packet.data.clone(), first_dst))
            .await
            .map_err(|e| anyhow::anyhow!("shadowquic send first udp packet: {e}"))?;
        debug!(tag = %self.config.tag, target = %packet.target, "shadowquic udp associated");

        // 后续上行包转发 task：从 inbound upstream_rx 读取，发往 shadowquic 服务端
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let udp_send = udp_send.clone();
            tokio::spawn(async move {
                while let Some((target, data)) = upstream_rx.recv().await {
                    let dst = target_to_socks_addr(&target);
                    if udp_send.send((data, dst)).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 下行回包转发 task：从 shadowquic udp_recv 读取，发回 inbound reply_tx
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());
        let timeout = Duration::from_secs(UDP_IDLE_TIMEOUT_SECS);
        let guards = packet.lifetime_guards;

        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(timeout, udp_recv.recv()).await {
                    Ok(Some((data, _from))) => {
                        // spoofed_src 将回包源地址伪装为目标地址，
                        // 使客户端 NAT 能正确匹配（与 TUIC/Hy2 行为一致）
                        if reply_tx.send((data, src, spoofed_src)).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => break, // channel 关闭（QUIC 连接断开）
                    Err(_) => break,   // idle timeout
                }
            }
            drop(guards);
        });

        Ok(())
    }
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

/// 将 reflex `Target` 转换为 shadowquic `SocksAddr`。
fn target_to_socks_addr(target: &Target) -> SocksAddr {
    match target {
        Target::Domain(host, port) => SocksAddr::from_domain(host.clone(), *port),
        Target::Socket(addr) => (*addr).into(),
    }
}

/// 将 `host:port` 转换为 shadowquic `SocksAddr`（IP 优先，避免服务端二次 DNS）。
fn host_to_socks_addr(host: &str, port: u16) -> SocksAddr {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        std::net::SocketAddr::new(ip, port).into()
    } else {
        SocksAddr::from_domain(host.to_string(), port)
    }
}

/// 将 reflex `ShadowQuicOutboundConfig` 转换为 shadowquic `ShadowQuicClientCfg`。
///
/// - `addr` 使用已解析的 IP:port 字符串（避免 shadowquic 内部走系统 DNS）
/// - `congestion_control` 字符串转 enum，`"brutal"` 时使用 `brutal_bandwidth`
/// - `socket_opt.fw_mark` 来自 `routing_mark`（Linux SO_MARK）
fn build_sq_config(
    config: &ShadowQuicOutboundConfig,
    addr: std::net::SocketAddr,
    routing_mark: u32,
) -> ShadowQuicClientCfg {
    let congestion_control = match config.congestion_control.as_str() {
        "cubic" => CongestionControl::Cubic,
        "new-reno" => CongestionControl::NewReno,
        "brutal" => CongestionControl::Brutal(BrutalParams {
            bandwidth: config.brutal_bandwidth,
            ..Default::default()
        }),
        // 默认 BBR（与 shadowquic 默认一致）
        _ => CongestionControl::Bbr,
    };

    ShadowQuicClientCfg {
        username: config.username.clone(),
        password: config.password.clone(),
        addr: addr.to_string(),
        server_name: config.server_name.clone(),
        alpn: config.alpn.clone(),
        initial_mtu: config.initial_mtu,
        congestion_control,
        zero_rtt: config.zero_rtt,
        over_stream: config.over_stream,
        min_mtu: config.min_mtu,
        keep_alive_interval: config.keep_alive_interval,
        gso: config.gso,
        mtu_discovery: config.mtu_discovery,
        blackhole_detection: config.blackhole_detection,
        cipher_suite_preference: None,
        protect_path: None,
        socket_opt: SocketOpt {
            fw_mark: if routing_mark != 0 {
                Some(routing_mark)
            } else {
                None
            },
            bind_interface: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_to_socks_addr_domain() {
        let target = Target::Domain("example.com".into(), 443);
        let addr = target_to_socks_addr(&target);
        assert_eq!(addr.port, 443);
        match addr.addr {
            shadowquic::msgs::socks5::AddrOrDomain::Domain(v) => {
                assert_eq!(v.contents, b"example.com");
            }
            _ => panic!("expected domain"),
        }
    }

    #[test]
    fn target_to_socks_addr_ipv4() {
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let addr = target_to_socks_addr(&target);
        assert_eq!(addr.port, 80);
        match addr.addr {
            shadowquic::msgs::socks5::AddrOrDomain::V4(octets) => {
                assert_eq!(octets, [1, 2, 3, 4]);
            }
            _ => panic!("expected ipv4"),
        }
    }

    #[test]
    fn host_to_socks_addr_ip() {
        let addr = host_to_socks_addr("10.0.0.1", 8080);
        assert_eq!(addr.port, 8080);
        assert!(matches!(
            addr.addr,
            shadowquic::msgs::socks5::AddrOrDomain::V4(_)
        ));
    }

    #[test]
    fn host_to_socks_addr_domain() {
        let addr = host_to_socks_addr("example.com", 443);
        assert_eq!(addr.port, 443);
        assert!(matches!(
            addr.addr,
            shadowquic::msgs::socks5::AddrOrDomain::Domain(_)
        ));
    }

    #[test]
    fn build_sq_config_defaults() {
        let cfg = ShadowQuicOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            password: "pass".into(),
            username: "user".into(),
            server_name: "camo.example.com".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1400,
            congestion_control: "bbr".into(),
            brutal_bandwidth: 10_000_000,
            zero_rtt: true,
            over_stream: false,
            min_mtu: 1290,
            keep_alive_interval: 0,
            gso: true,
            mtu_discovery: true,
            blackhole_detection: false,
            detour: None,
        };
        let addr: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();
        let sq = build_sq_config(&cfg, addr, 0);
        assert_eq!(sq.username, "user");
        assert_eq!(sq.password, "pass");
        assert_eq!(sq.addr, "1.2.3.4:443");
        assert_eq!(sq.server_name, "camo.example.com");
        assert_eq!(sq.alpn, vec!["h3".to_string()]);
        assert_eq!(sq.initial_mtu, 1400);
        assert!(matches!(sq.congestion_control, CongestionControl::Bbr));
        assert!(sq.zero_rtt);
        assert!(!sq.over_stream);
        assert_eq!(sq.socket_opt.fw_mark, None);
    }

    #[test]
    fn build_sq_config_brutal() {
        let cfg = ShadowQuicOutboundConfig {
            tag: "test".into(),
            server: "example.com".into(),
            server_port: 443,
            password: "pass".into(),
            username: "user".into(),
            server_name: "camo.example.com".into(),
            alpn: vec!["h3".into()],
            initial_mtu: 1400,
            congestion_control: "brutal".into(),
            brutal_bandwidth: 50_000_000,
            zero_rtt: true,
            over_stream: false,
            min_mtu: 1290,
            keep_alive_interval: 0,
            gso: true,
            mtu_discovery: true,
            blackhole_detection: false,
            detour: None,
        };
        let addr: std::net::SocketAddr = "1.2.3.4:443".parse().unwrap();
        let sq = build_sq_config(&cfg, addr, 256);
        match sq.congestion_control {
            CongestionControl::Brutal(p) => {
                assert_eq!(p.bandwidth, 50_000_000);
            }
            _ => panic!("expected brutal"),
        }
        assert_eq!(sq.socket_opt.fw_mark, Some(256));
    }
}
