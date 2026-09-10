mod doh;
mod doq;
mod dot;
mod fakeip;
mod h3;
mod hosts;
mod local;
mod rcode;
mod tcp;
mod udp;
mod util;

use doh::*;
use doq::*;
use dot::*;
pub use fakeip::*;
use h3::*;
pub use hosts::*;
pub use local::*;
use rcode::*;
use tcp::*;
pub use udp::*;
use util::*;

// 供 dns/rule.rs 编译 per-rule `client_subnet` 字符串复用（与 server 级同一解析器）。
pub(crate) use util::parse_client_subnet;

use util::extract_sni_host;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::time::Duration;

use crate::experimental::CacheFile;
use bytes::Bytes;
use tokio::time::timeout;
use tracing::debug;

use crate::config::dns::{DnsProtocol, DnsServerConfig, RcodeAction};
use crate::outbound::Outbound;

// ── 主结构 ────────────────────────────────────────────────────────────────────

pub struct DnsUpstream {
    pub tag: String,
    pub kind: UpstreamKind,
    pub timeout: Duration,
    /// 发出查询所走的出站通道；None 表示直连。
    pub detour: Option<Arc<dyn Outbound>>,
    /// 用于解析本 upstream 域名的 bootstrap DNS（仅当 address 为域名形式时有意义）。
    pub domain_resolver: Option<Arc<DnsUpstream>>,
    /// 直连 UDP 上游的复用收发状态（IPv4）：包含 socket + 后台 recv_loop + callbacks map
    pub(super) udp_state_v4: Arc<Mutex<Option<Arc<UdpState>>>>,
    /// 直连 UDP 上游的复用收发状态（IPv6）
    pub(super) udp_state_v6: Arc<Mutex<Option<Arc<UdpState>>>>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    pub routing_mark: u32,
    /// EDNS Client Subnet（RFC 7871）：查询前注入到 OPT EDNS0_SUBNET 选项。
    /// 对齐 sing-box dns.DNSClientOptions.ClientSubnet / per-server client_subnet。
    /// None 表示不注入。
    pub client_subnet: Option<(std::net::IpAddr, u8)>,
}

pub enum UpstreamKind {
    Udp {
        addr: SocketAddr,
    },
    /// DNS-over-TCP：每次查询建立新 TCP 连接，2 字节长度前缀帧
    Tcp {
        addr: SocketAddr,
    },
    /// DNS-over-HTTPS：HTTP/2（优先）→ 回退 HTTP/1.1，Content-Type: application/dns-message
    /// 直连时走 rustls；经 detour 时走隧道 TCP + rustls
    Doh {
        host: String,
        port: u16,
        path: String,
        /// 若 host 是域名，此字段缓存已解析的 IP（由 domain_resolver 懒初始化）
        resolved_addr: std::sync::Mutex<Option<std::net::IpAddr>>,
        /// rustls 配置（含系统根证书 + SNI）
        tls_cfg: std::sync::Arc<rustls::ClientConfig>,
        /// insecure 标记，用于 non-outbound-net 分支提示
        insecure: bool,
        /// 复用的 h2 连接（对齐 sing-box http2.Transport 自动池化）。
        /// `SendRequest` 可并发发送多个请求（HTTP/2 多路复用），用 Mutex 保护。
        /// Box 装箱以缩小 enum 变体大小（避免 large_enum_variant）。
        h2_pool: Box<tokio::sync::Mutex<Option<h2::client::SendRequest<Bytes>>>>,
    },
    /// DNS-over-TLS：TCP + TLS 握手，2 字节长度前缀帧
    Dot {
        addr: SocketAddr,
        sni: String,
        tls_cfg: std::sync::Arc<rustls::ClientConfig>,
        /// 有限并发的 TLS 连接池（对齐 sing-box `dns/transport/tls.go` 的
        /// `ConnPool`，`MaxInflight: 8`）。
        ///
        /// DNS-over-TCP framing 本身不支持在一条连接上并发复用（一发一收，
        /// 串行），但这不意味着只能维护一条连接——旧实现用
        /// `Mutex<Option<TlsStream>>` 做"取用-归还"，并发查询下池子实际
        /// 容量恒为 1，后来者新建的连接用完后会和先来者互相覆盖同一个槽位，
        /// 被覆盖的连接直接丢弃关闭。现在换成 `DotConnPool`：多条连接 +
        /// 信号量限流，从根本上解决"同时只有一条连接"的瓶颈。
        /// Box 装箱以缩小 enum 变体大小（避免 large_enum_variant）。
        conn_pool: Box<dot::DotConnPool>,
    },
    /// DNS-over-QUIC（RFC 9250）：QUIC 流，2 字节长度前缀帧
    Doq {
        addr: SocketAddr,
        sni: String,
        quic_cfg: std::sync::Arc<quinn::ClientConfig>,
        /// 复用的 DoQ 连接（对齐 sing-box ConnPoolSingle）。
        /// 同时持有 endpoint 和 connection，避免 endpoint drop 致连接失效。
        /// Box 装箱以缩小 enum 变体大小（避免 large_enum_variant）。
        conn_pool: Box<tokio::sync::Mutex<Option<DoqConn>>>,
    },
    /// DNS-over-HTTP/3（RFC 9464）：QUIC + HTTP/3，POST application/dns-message
    /// 与 DoQ 一样依赖 QUIC，detour 存在时忽略并直连
    H3 {
        addr: SocketAddr,
        sni: String,
        path: String,
        quic_cfg: std::sync::Arc<quinn::ClientConfig>,
        /// 复用的 DoH3 连接（对齐 sing-box http3.go + ConnPoolSingle）。
        /// 同时持有 endpoint、quinn::Connection、h3 SendRequest。
        /// Box 装箱以缩小 enum 变体大小（避免 large_enum_variant）。
        conn_pool: Box<tokio::sync::Mutex<Option<H3Conn>>>,
    },
    /// hosts 文件 DNS（对齐 sing-box `hosts.Transport`）：
    /// 仅响应 A/AAAA，predefined 优先 → 文件顺序 → NXDOMAIN 回退
    Hosts {
        upstream: Arc<HostsUpstream>,
    },
    /// 本地系统 DNS（对齐 sing-box `local.Transport`）：
    /// hosts 优先 → 系统 DNS（读 /etc/resolv.conf + UDP/TCP）
    Local {
        upstream: Arc<LocalUpstream>,
    },
    Rcode {
        action: RcodeAction,
    },
    /// FakeIP：从内存地址池按需分配假 IP
    FakeIp {
        store: Arc<FakeIpStore>,
    },
}

impl DnsUpstream {
    /// detour 出站的 tag（未配置 detour 时为 None）。
    /// 供 `DnsResolver::resolve_domain_for_outbound` 的防环过滤使用：
    /// 解析某出站自身服务器域名时，必须排除 detour 指向该出站的上游，
    /// 否则会形成「建连需要解析 → 解析需要建连」的互斥锁死锁。
    pub fn detour_tag(&self) -> Option<&str> {
        self.detour.as_ref().map(|d| d.tag())
    }

    /// 不带 detour 的构造（向后兼容）。
    pub fn from_config(cfg: &DnsServerConfig) -> anyhow::Result<Self> {
        Self::from_config_with_detour(cfg, None)
    }

    /// 带 detour 的构造。
    pub fn from_config_with_detour(
        cfg: &DnsServerConfig,
        detour: Option<Arc<dyn Outbound>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full(cfg, detour, None, None)
    }

    /// 完整构造：支持 detour + CacheFile。
    pub fn from_config_full(
        cfg: &DnsServerConfig,
        detour: Option<Arc<dyn Outbound>>,
        cache_file: Option<Arc<CacheFile>>,
        domain_resolver: Option<Arc<DnsUpstream>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full_with_reader(cfg, detour, cache_file, None, domain_resolver)
    }

    /// 同上，额外接受 cache_reader 用于 fakeip 恢复。
    pub fn from_config_full_with_reader(
        cfg: &DnsServerConfig,
        detour: Option<Arc<dyn Outbound>>,
        cache_file: Option<Arc<CacheFile>>,
        cache_reader: Option<Arc<crate::experimental::CacheFileReader>>,
        domain_resolver: Option<Arc<DnsUpstream>>,
    ) -> anyhow::Result<Self> {
        let t = Duration::from_secs(cfg.timeout);
        let kind = match cfg.protocol() {
            DnsProtocol::Rcode => UpstreamKind::Rcode {
                action: cfg
                    .rcode()
                    .ok_or_else(|| anyhow::anyhow!("invalid rcode in '{}'", cfg.tag))?,
            },

            DnsProtocol::Doh => {
                let (host, port, path) = parse_doh_url(&cfg.address)?;
                let pre_resolved = host.parse::<std::net::IpAddr>().ok();

                {
                    let tls_cfg = build_rustls_client_config(cfg)?;
                    UpstreamKind::Doh {
                        host,
                        port,
                        path,
                        resolved_addr: std::sync::Mutex::new(pre_resolved),
                        tls_cfg,
                        insecure: cfg.insecure,
                        h2_pool: Box::new(tokio::sync::Mutex::new(None)),
                    }
                }
            }

            DnsProtocol::Tcp => UpstreamKind::Tcp {
                addr: parse_addr(
                    cfg.address.strip_prefix("tcp://").unwrap_or(&cfg.address),
                    53,
                )?,
            },

            DnsProtocol::Udp => UpstreamKind::Udp {
                addr: parse_addr(
                    cfg.address.strip_prefix("udp://").unwrap_or(&cfg.address),
                    53,
                )?,
            },

            DnsProtocol::Dot => {
                {
                    let raw = cfg.address.strip_prefix("tls://").unwrap_or(&cfg.address);
                    let addr = parse_addr(raw, 853)?;
                    // SNI 默认值用原始服务器字符串（可能是域名），而非 IP。
                    // 对齐 sing-box：DoT/DoH 默认 SNI = server domain。
                    // 当 raw 是 IP 字符串时回退到 addr.ip()（行为不变）。
                    let sni = cfg.sni.clone().unwrap_or_else(|| extract_sni_host(raw));
                    let tls_cfg = build_rustls_client_config(cfg)?;
                    UpstreamKind::Dot {
                        addr,
                        sni,
                        tls_cfg,
                        conn_pool: Box::new(dot::DotConnPool::new()),
                    }
                }
            }

            DnsProtocol::Doq => {
                {
                    let raw = cfg.address.strip_prefix("quic://").unwrap_or(&cfg.address);
                    let addr = parse_addr(raw, 853)?;
                    // SNI 默认值用原始服务器字符串（可能是域名），而非 IP。
                    let sni = cfg.sni.clone().unwrap_or_else(|| extract_sni_host(raw));
                    let quic_cfg = build_doq_quic_config(cfg)?;
                    UpstreamKind::Doq {
                        addr,
                        sni,
                        quic_cfg,
                        conn_pool: Box::new(tokio::sync::Mutex::new(None)),
                    }
                }
            }

            DnsProtocol::H3 => {
                {
                    // h3:// URL 与 DoH 的 https:// URL 结构相同，复用 parse_doh_url 解析
                    let https_url = cfg
                        .address
                        .strip_prefix("h3://")
                        .map(|rest| format!("https://{rest}"))
                        .unwrap_or_else(|| cfg.address.clone());
                    let (host, port, path) = parse_doh_url(&https_url)?;
                    // 与 DoQ 一致：QUIC dial 需要 SocketAddr，配置时必须为 IP 字面量；
                    // 域名形式不支持（用户应通过 IP 配置 + sni 字段指定 SNI）
                    let addr = parse_addr(&host, port)?;
                    // SNI 默认值用 host（可能是 IP 字符串或域名）
                    let sni = cfg.sni.clone().unwrap_or_else(|| host.clone());
                    let quic_cfg = build_h3_quic_config(cfg)?;
                    UpstreamKind::H3 {
                        addr,
                        sni,
                        path,
                        quic_cfg,
                        conn_pool: Box::new(tokio::sync::Mutex::new(None)),
                    }
                }
            }

            DnsProtocol::Hosts => {
                // hosts://[path1,path2,...] —— 可选自定义 hosts 文件路径列表
                // 路径为空时使用默认 /etc/hosts
                let paths_arg = cfg.address.strip_prefix("hosts://").unwrap_or("");
                let paths: Vec<std::path::PathBuf> = if paths_arg.is_empty() {
                    Vec::new()
                } else {
                    paths_arg
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .map(std::path::PathBuf::from)
                        .collect()
                };
                let upstream = HostsUpstream::new(std::collections::HashMap::new(), paths);
                UpstreamKind::Hosts {
                    upstream: Arc::new(upstream),
                }
            }

            DnsProtocol::Local => {
                // local:// —— 无参数，使用默认 /etc/hosts + /etc/resolv.conf
                // 对齐 sing-box `local.Transport`：不接受配置参数，完全跟随系统
                let upstream = LocalUpstream::new();
                UpstreamKind::Local {
                    upstream: Arc::new(upstream),
                }
            }

            DnsProtocol::FakeIp => {
                let fi_cfg = cfg.fakeip.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "dns server '{}': address is 'fakeip://' but 'fakeip' config is missing",
                        cfg.tag
                    )
                })?;
                let store = FakeIpStore::new_with_cache(fi_cfg, cache_file, cache_reader)
                    .map_err(|e| anyhow::anyhow!("dns server '{}' fakeip store: {e}", cfg.tag))?;
                UpstreamKind::FakeIp {
                    store: Arc::new(store),
                }
            }
        };

        if detour.is_some() {
            let detour_tag = detour.as_ref().map(|d| d.tag()).unwrap_or("?");
            debug!(
                upstream = %cfg.tag,
                detour = %detour_tag,
                "dns upstream will route queries via detour"
            );
        }

        // 解析 EDNS Client Subnet（如 "1.2.3.0/24"）
        // 对齐 sing-box per-server client_subnet + DNSClientOptions.ClientSubnet
        let client_subnet = cfg.client_subnet.as_deref().and_then(parse_client_subnet);

        Ok(Self {
            tag: cfg.tag.clone(),
            kind,
            timeout: t,
            detour,
            domain_resolver,
            udp_state_v4: Arc::new(Mutex::new(None)),
            udp_state_v6: Arc::new(Mutex::new(None)),
            routing_mark: 0,
            client_subnet,
        })
    }

    /// 设置 SO_MARK，返回 Self（用于链式调用）。
    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 设置解析策略（同步到内部 fakeip store，如果有的话）。
    pub fn with_strategy(self, s: crate::config::dns::ResolveStrategy) -> Self {
        if let UpstreamKind::FakeIp { ref store } = self.kind {
            store.set_strategy(s);
        }
        self
    }

    /// 获取或创建 UDP 收发状态。对齐 sing-box `connection.AcquireShared`：
    /// - 首次调用创建 socket 并启动后台 recv_loop
    /// - 后续调用复用 socket 与 recv_loop
    ///
    /// 当 `require_size` 超过当前 state 的 `udp_size` 时触发重建（对齐 sing-box
    /// 在 EDNS OPT UDPSize 增大时的 `t.Reset()`）：旧 state 置 None 释放 socket，
    /// 旧 recv_loop 因 socket drop 而退出；新 state 用更大的 udp_size 创建。
    async fn get_or_create_udp_state(
        &self,
        addr: SocketAddr,
        require_size: i32,
    ) -> anyhow::Result<Arc<UdpState>> {
        let slot = if addr.is_ipv6() {
            &self.udp_state_v6
        } else {
            &self.udp_state_v4
        };
        // 快速路径：已有 state 且 udp_size 足够，直接复用
        {
            let mut guard = slot.lock().unwrap();
            if let Some(s) = guard.as_ref() {
                if s.udp_size.load(Ordering::Relaxed) >= require_size {
                    return Ok(s.clone());
                }
                // udp_size 不够：标记 invalidate 让旧 recv_loop 退出
                debug!(
                    addr = %addr,
                    old = s.udp_size.load(Ordering::Relaxed),
                    new = require_size,
                    "dns udp: EDNS UDPSize increased, rebuilding socket"
                );
                s.invalidate();
                // 清空 slot，让旧 socket 被 drop（recv_loop 退出后释放）
                *guard = None;
            }
        }
        // 慢路径：创建新 state。注意不持有 MutexGuard 跨 await（非 Send）
        let new_state = UdpState::new(addr, self.routing_mark).await?;
        // 初始化时就反映 EDNS 需求（如要求大于默认值则采用要求值）
        if require_size > UdpState::DEFAULT_UDP_SIZE {
            new_state.udp_size.store(require_size, Ordering::Relaxed);
        }
        {
            let mut guard = slot.lock().unwrap();
            // 双重检查：其他并发调用可能已先创建满足条件的 state
            if let Some(s) = guard.as_ref() {
                if s.udp_size.load(Ordering::Relaxed) >= require_size {
                    let s = s.clone();
                    drop(guard);
                    s.ensure_recv_loop();
                    return Ok(s);
                }
            }
            *guard = Some(new_state.clone());
        }
        new_state.ensure_recv_loop();
        Ok(new_state)
    }

    /// 用本 upstream 解析一个主机名，返回第一个 IP（供 DoH/DoT domain_resolver 使用）。
    pub(super) fn resolve_host<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<std::net::IpAddr>> + Send + 'a>> {
        Box::pin(async move {
            use crate::dns::{build_query_bytes, extract_first_ip_from_resp};
            let q = build_query_bytes(host, 1u16);
            if let Ok(resp) = self.query(q.into()).await {
                if let Some(ip) = extract_first_ip_from_resp(&resp, 1) {
                    return Ok(ip);
                }
            }
            let q = build_query_bytes(host, 28u16);
            if let Ok(resp) = self.query(q.into()).await {
                if let Some(ip) = extract_first_ip_from_resp(&resp, 28) {
                    return Ok(ip);
                }
            }
            anyhow::bail!("domain_resolver failed to resolve host '{host}'")
        })
    }

    pub fn query(
        &self,
        msg: Bytes,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Bytes>> + Send + '_>> {
        // 无 per-rule 覆盖：沿用 server 级 self.client_subnet（既有行为）。
        // 供 resolve_host / resolve_domain_with_strategy 等 bootstrap 解析路径使用。
        self.query_inner(msg, None)
    }

    /// 带 per-rule ECS 覆盖的查询入口。
    ///
    /// `ecs_override`：对齐 sing-box `option.DNSRouteActionOptions.ClientSubnet` 的
    /// per-rule 覆盖优先级 —— Some 时覆盖 server 级 `self.client_subnet`；
    /// None 时回退到 server 级（与 `query` 行为一致）。
    ///
    /// 多上游 race 场景下，所有上游共享同一 per-rule 覆盖（sing-box 中 per-rule
    /// 优先于 transport/server 级），符合 sing-box dns/router.go:166-168 的语义。
    pub fn query_with_ecs(
        &self,
        msg: Bytes,
        ecs_override: Option<(std::net::IpAddr, u8)>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Bytes>> + Send + '_>> {
        self.query_inner(msg, ecs_override)
    }

    fn query_inner(
        &self,
        msg: Bytes,
        ecs_override: Option<(std::net::IpAddr, u8)>,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Bytes>> + Send + '_>> {
        Box::pin(async move {
            // 注入 EDNS Client Subnet（如配置）。
            // 对齐 sing-box client.go:135-141：per-rule ClientSubnet 优先，
            // 缺省时回退到 client（server）级 clientSubnet。
            // Rcode / FakeIp / Hosts / Local 是本地内置上游，不注入（避免无意义的 OPT 包装）。
            let msg = if let Some((subnet, prefix_len)) = ecs_override.or(self.client_subnet) {
                let is_local = matches!(
                    &self.kind,
                    UpstreamKind::Rcode { .. }
                        | UpstreamKind::FakeIp { .. }
                        | UpstreamKind::Hosts { .. }
                        | UpstreamKind::Local { .. }
                );
                if is_local {
                    msg
                } else {
                    crate::dns::wire::set_client_subnet(msg, subnet, prefix_len)
                }
            } else {
                msg
            };
            match &self.kind {
                UpstreamKind::Rcode { action } => Ok(rcode_reply(&msg, *action)),

                UpstreamKind::FakeIp { store } => store.reply(&msg),

                // ── Hosts ─────────────────────────────────────────────────────
                UpstreamKind::Hosts { upstream } => Ok(upstream.reply(&msg)),

                // ── Local ────────────────────────────────────────────────────
                UpstreamKind::Local { upstream } => {
                    Ok(timeout(self.timeout, upstream.reply(&msg)).await?)
                }

                // ── UDP ───────────────────────────────────────────────────────
                UpstreamKind::Udp { addr } => {
                    if let Some(ob) = &self.detour {
                        // 对齐 sing-box：优先尝试 UDP-over-detour（如 SOCKS5 UDP ASSOCIATE），
                        // 出站不支持 UDP 时降级为 TCP（保留原有行为）。
                        match ob.connect_udp().await {
                            Ok(Some(relay)) => {
                                debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                                    "dns udp query via detour (udp relay)");
                                // 修复 TC bit 未重试 TCP bug：旧实现直接返回截断响应，
                                // 对齐 sing-box udp.go:121-125 的 response.Truncated → exchangeTCP。
                                // Bytes clone 是 refcount 增减，开销极小。
                                let resp = timeout(
                                    self.timeout,
                                    udp_query_via_detour_udp(relay, *addr, msg.clone()),
                                )
                                .await??;
                                if resp.len() >= 3 && (resp[2] & 0x02) != 0 {
                                    debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                                        "dns udp (via detour) TC bit set, retrying over TCP");
                                    timeout(
                                        self.timeout,
                                        tcp_query_via_detour(
                                            ob.as_ref(),
                                            addr.ip().to_string(),
                                            addr.port(),
                                            msg,
                                        ),
                                    )
                                    .await?
                                } else {
                                    Ok(resp)
                                }
                            }
                            Ok(None) => {
                                debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                                    "dns udp query: detour does not support udp, falling back to TCP");
                                timeout(
                                    self.timeout,
                                    tcp_query_via_detour(
                                        ob.as_ref(),
                                        addr.ip().to_string(),
                                        addr.port(),
                                        msg,
                                    ),
                                )
                                .await?
                            }
                            Err(e) => {
                                debug!(upstream=%self.tag, detour=%ob.tag(), err=%e,
                                    "dns udp query: detour connect_udp failed, falling back to TCP");
                                timeout(
                                    self.timeout,
                                    tcp_query_via_detour(
                                        ob.as_ref(),
                                        addr.ip().to_string(),
                                        addr.port(),
                                        msg,
                                    ),
                                )
                                .await?
                            }
                        }
                    } else {
                        // 解析 EDNS OPT UDPSize（如有），用于动态调整 socket 缓冲区
                        // 对齐 sing-box dns/transport/udp.go:147-159
                        let edns_udp_size = extract_edns_udp_size(&msg);
                        let require_size = edns_udp_size.max(UdpState::DEFAULT_UDP_SIZE);
                        let state = self.get_or_create_udp_state(*addr, require_size).await?;
                        // get_or_create_udp_state 已根据 require_size 反映到 state.udp_size
                        // 这里再做一次 CAS 以防 state 被其他调用复用而 udp_size 较小（极少见）
                        if require_size > state.udp_size.load(Ordering::Relaxed) {
                            state.udp_size.store(require_size, Ordering::Relaxed);
                        }
                        timeout(
                            self.timeout,
                            udp_query_with_state(state, *addr, msg, self.routing_mark),
                        )
                        .await?
                    }
                }

                // ── TCP ───────────────────────────────────────────────────────
                UpstreamKind::Tcp { addr } => {
                    if let Some(ob) = &self.detour {
                        debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                            "dns tcp query routed via detour");
                        timeout(
                            self.timeout,
                            tcp_query_via_detour(
                                ob.as_ref(),
                                addr.ip().to_string(),
                                addr.port(),
                                msg,
                            ),
                        )
                        .await?
                    } else {
                        timeout(self.timeout, tcp_query(*addr, msg, self.routing_mark)).await?
                    }
                }

                // ── DoH ───────────────────────────────────────────────────────
                UpstreamKind::Doh {
                    host,
                    port,
                    path,
                    resolved_addr,
                    tls_cfg,
                    h2_pool,
                    ..
                } => {
                    let ip = resolve_or_cached(
                        resolved_addr,
                        host,
                        *port,
                        self.domain_resolver.as_ref(),
                        &self.tag,
                    )
                    .await?;

                    if let Some(ob) = &self.detour {
                        debug!(upstream=%self.tag, detour=%ob.tag(), host=%host,
                            "dns doh query routed via detour");
                        timeout(
                            self.timeout,
                            doh_query_via_detour(
                                ob.as_ref(),
                                host,
                                *port,
                                path,
                                tls_cfg.clone(),
                                msg,
                            ),
                        )
                        .await?
                    } else {
                        // 复用 h2 连接（对齐 sing-box http2.Transport 自动池化）。
                        // 外层 timeout 触发时主动 reset pool（对齐 sing-box https.go:158-168
                        // DeadlineExceeded → CloseIdleConnections + Clone transport）：
                        // 否则 pool 中残留的 SendRequest clone 可能指向已坏的 h2 连接，
                        // 后续查询会继续超时，直到失败重试路径才被清掉，造成连续超时。
                        match timeout(
                            self.timeout,
                            doh_query_pooled_direct(
                                ip,
                                host,
                                *port,
                                path,
                                tls_cfg.clone(),
                                msg,
                                h2_pool,
                                self.routing_mark,
                            ),
                        )
                        .await
                        {
                            Ok(r) => r,
                            Err(_elapsed) => {
                                debug!(upstream=%self.tag, "DoH query timeout, resetting h2 pool");
                                *h2_pool.lock().await = None;
                                Err(anyhow::anyhow!(
                                    "DoH query timeout after {:?}",
                                    self.timeout
                                ))
                            }
                        }
                    }
                }

                // ── DoT ───────────────────────────────────────────────────────
                UpstreamKind::Dot {
                    addr,
                    sni,
                    tls_cfg,
                    conn_pool,
                } => {
                    if let Some(ob) = &self.detour {
                        debug!(upstream=%self.tag, detour=%ob.tag(), addr=%addr,
                            "dns dot query routed via detour");
                        timeout(
                            self.timeout,
                            dot_query_via_detour(
                                ob.as_ref(),
                                addr.ip().to_string(),
                                addr.port(),
                                sni,
                                tls_cfg.clone(),
                                msg,
                            ),
                        )
                        .await?
                    } else {
                        // 复用 TLS 连接（对齐 sing-box ConnPoolOrdered）。
                        // DNS-over-TCP framing 不支持多路复用，用「取用-归还」模式。
                        // 外层 timeout 触发时主动 reset pool（对齐 sing-box tls.go
                        // 在 DeadlineExceeded 时 Release(conn, false) 丢弃连接）：
                        // dot_query_pooled 内部 take 后归还可能在 await 点被 timeout
                        // 打断，残留连接状态不明，统一丢弃更安全。
                        match timeout(
                            self.timeout,
                            dot_query_pooled(
                                *addr,
                                sni,
                                tls_cfg.clone(),
                                msg,
                                self.routing_mark,
                                conn_pool,
                            ),
                        )
                        .await
                        {
                            Ok(r) => r,
                            Err(_elapsed) => {
                                debug!(upstream=%self.tag, "DoT query timeout, resetting pool");
                                conn_pool.reset().await;
                                Err(anyhow::anyhow!(
                                    "DoT query timeout after {:?}",
                                    self.timeout
                                ))
                            }
                        }
                    }
                }

                // ── DoQ ───────────────────────────────────────────────────────
                UpstreamKind::Doq {
                    addr,
                    sni,
                    quic_cfg,
                    conn_pool,
                } => {
                    if self.detour.is_some() {
                        debug!(upstream=%self.tag,
                            "dns doq does not support TCP detour, falling back to direct");
                    }
                    // 复用 QUIC 连接（对齐 sing-box ConnPoolSingle）。
                    // QUIC 支持多 stream 复用，一个连接可并发开多个 bi-stream。
                    // 外层 timeout 触发时主动 reset pool 并发送 CONNECTION_CLOSE
                    // （对齐 sing-box quic.go 在连接级错误时 t.Reset()）：DoQ 的
                    // conn.clone() 模式让 pool 持有的连接不会被 future drop 自动释放，
                    // 必须显式关闭，否则旧连接的 idle timeout 可能还没到，下次查询
                    // 继续复用坏连接。
                    match timeout(
                        self.timeout,
                        doq_query_pooled(
                            *addr,
                            sni,
                            quic_cfg.clone(),
                            msg,
                            self.routing_mark,
                            conn_pool,
                        ),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_elapsed) => {
                            debug!(upstream=%self.tag, "DoQ query timeout, resetting pool");
                            let mut guard = conn_pool.lock().await;
                            if let Some(old) = guard.take() {
                                old.conn.close(0u32.into(), b"");
                            }
                            Err(anyhow::anyhow!(
                                "DoQ query timeout after {:?}",
                                self.timeout
                            ))
                        }
                    }
                }

                // ── DoH3 ──────────────────────────────────────────────────────
                UpstreamKind::H3 {
                    addr,
                    sni,
                    path,
                    quic_cfg,
                    conn_pool,
                } => {
                    if self.detour.is_some() {
                        debug!(upstream=%self.tag,
                            "dns h3 does not support TCP detour, falling back to direct");
                    }
                    // 复用 QUIC + HTTP/3 连接（对齐 sing-box http3.go + ConnPoolSingle）。
                    // QUIC 多 stream 复用，h3 SendRequest Clone 后并发发送多个请求。
                    // 外层 timeout 触发时主动 reset pool 并 close QUIC 连接
                    // （对齐 sing-box http3.go 在连接级错误时 t.Reset()）。
                    match timeout(
                        self.timeout,
                        h3_query_pooled(
                            *addr,
                            sni,
                            path,
                            quic_cfg.clone(),
                            msg,
                            self.routing_mark,
                            conn_pool,
                        ),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(_elapsed) => {
                            debug!(upstream=%self.tag, "DoH3 query timeout, resetting pool");
                            let mut guard = conn_pool.lock().await;
                            if let Some(old) = guard.take() {
                                old.quic_conn.close(0u32.into(), b"");
                            }
                            Err(anyhow::anyhow!(
                                "DoH3 query timeout after {:?}",
                                self.timeout
                            ))
                        }
                    }
                }
            }
        })
    }
}
