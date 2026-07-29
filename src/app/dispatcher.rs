use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::{
    dns::DnsResolver,
    inbound::{
        dns::{DnsQuery, DnsQueryTx},
        InboundTcpStream, InboundUdpPacket, Target,
    },
    router::{RouteAction, RouteOptions, Router},
};

use super::{
    clash_api::{ConnInfo, ConnectionTracker, RuleInfo},
    outbound_mgr::OutboundManager,
    sniff::{is_dns_wire, sniff},
    stats::{Stats, TcpGuard, UdpGuard},
};

// ── UDP 会话超时（参照 sing-box constant/timeout.go）─────────────────────────

/// 默认 UDP 会话空闲超时：60 秒（对齐 mihomo tunnel.go 的 udpTimeout）
// TODO: plumb per-inbound udp_timeout from SocksInboundConfig/MixedInboundConfig
const UDP_TIMEOUT: Duration = Duration::from_secs(60);

/// 用于 peer_addr() 失败时的占位地址。原实现每次都 "0.0.0.0:0".parse().unwrap()
/// 在错误路径上重新 parse；改为 const 在编译期构造一次。
/// `SocketAddr::new` 不是 const fn，但 `SocketAddrV4::new` 是 const fn，
/// 可在 const 上下文构造。
const ZERO_ADDR: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::new(0, 0, 0, 0),
    0,
));

/// 协议专属短超时，端口 → 超时时长
fn udp_timeout_for_port(port: u16) -> Duration {
    match port {
        53 => Duration::from_secs(10),   // DNS
        123 => Duration::from_secs(10),  // NTP
        3478 => Duration::from_secs(10), // STUN
        443 => Duration::from_secs(30),  // QUIC
        _ => UDP_TIMEOUT,
    }
}

/// 应用规则命中后的 `override_address` / `override_port`（对齐 sing-box
/// 同名规则动作选项）。在所有 sniff/resolve 重新路由都完成、即将真正建立
/// 连接之前调用一次；不影响已经记录下来的 rule_payload（Clash API 展示的
/// 仍是原始匹配条件，只有实际转发目标被改写）。
fn apply_route_overrides(target: &mut Target, opts: &RouteOptions) {
    if opts.override_address.is_none() && opts.override_port.is_none() {
        return;
    }
    let new_host = opts
        .override_address
        .clone()
        .unwrap_or_else(|| target.host());
    let new_port = opts.override_port.unwrap_or_else(|| target.port());
    debug!(
        original = %*target,
        new_host = %new_host,
        new_port = new_port,
        "route: override_address/override_port applied"
    );
    *target = if let Ok(ip) = new_host.parse::<std::net::IpAddr>() {
        Target::Socket(std::net::SocketAddr::new(ip, new_port))
    } else {
        Target::Domain(new_host, new_port)
    };
}

/// 计算连接展示用的 `(host, destination_ip)`，对齐 sing-box `trafficontrol` tracker
/// 的行为（`host = metadata.Domain ?? Destination.Fqdn`，`destinationIP = Destination.Addr`）：
///
/// - `host`：优先取 sniff 命中域名（`override_destination=false` 时存于 `sniffed_domain`，
///   对应 sing-box 的 `metadata.Domain`）；否则取原始域名目标（`Target::Domain`，
///   对应 `Destination.Fqdn`，含 fakeip 反查 / override 改写后的域名）；都没有则为空。
/// - `destination_ip`：取 `Target::Socket` 的 IP（对应 `Destination.Addr`，
///   tproxy/tun 入站的原始 IP）；目标为域名时为空。
///
/// 二者独立：tproxy + sniff 命中时 host=域名、destination_ip=IP 同时有值；
/// 目标本身就是域名时 host=域名、destination_ip 为空。
/// resolve 动作不修改 target（与 sing-box 一致，只填 DestinationAddresses 供拨号），
/// 故对展示无影响。
fn host_and_dest_ip(sniffed: Option<&str>, target: &Target) -> (String, String) {
    let host = sniffed
        .map(str::to_string)
        .or_else(|| match target {
            Target::Domain(d, _) => Some(d.clone()),
            Target::Socket(_) => None,
        })
        .unwrap_or_default();
    let destination_ip = match target {
        Target::Socket(addr) => addr.ip().to_string(),
        Target::Domain(..) => String::new(),
    };
    (host, destination_ip)
}

// ── UDP 会话表 ────────────────────────────────────────────────────────────────

/// 会话 key：(入站源地址, 目标, 出站 tag)
/// 同一 (src, dst) 走不同出站时各自独立（规则切换场景）
///
/// 优化：
/// - outbound_tag 用 Arc<str> 避免 clone 时复制字符串内容
/// - target 用 Target（已派生 Hash/Eq）而非 to_string() 后的 Box<str>，
///   避免每个 UDP 包都做格式化分配。Target::clone 对 Socket 变体是 Copy（0 malloc），
///   对 Domain 变体是 1 次 String clone（比 to_string 省去 ':' 和 port 的格式化）。
// 会话按 (src, outbound) 聚合：同一客户端 socket 访问多个目标时复用一条出站连接，
// 对齐 mihomo `natTable` 按 `packet.LocalAddr()`（即客户端源地址）聚合的语义。
// FakeIP 场景因回包源地址伪装需要 per-target 的 origin_destination，不走聚合
// （见 run_udp 里的 fakeip 分流）。
type UdpSessionKey = (SocketAddr, Arc<str>); // (src, outbound_tag)

/// 向已存在会话的入站方向投递数据
struct UdpSessionHandle {
    /// 向会话 task 投递新包载荷 `(Target, Bytes)`：每包携带目标地址，
    /// 出站实现据此构建协议帧，支持同会话多目标复用（对齐 mihomo natTable）。
    data_tx: mpsc::Sender<(Target, bytes::Bytes)>,
    last_seen: Instant,
}

/// Dispatcher 持有的 UDP 会话表（每个 run_udp 实例独占，无需 Arc<Mutex>）
struct UdpSessionTable {
    sessions: HashMap<UdpSessionKey, UdpSessionHandle>,
}

impl UdpSessionTable {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// 检查会话是否存活（Sender 未关闭）
    fn get_live(&mut self, key: &UdpSessionKey) -> Option<&mut UdpSessionHandle> {
        let alive = self
            .sessions
            .get(key)
            .is_some_and(|h| !h.data_tx.is_closed());
        if alive {
            return self.sessions.get_mut(key);
        }
        // Sender 已关闭说明会话 task 已退出，移除
        self.sessions.remove(key);
        None
    }

    fn insert(&mut self, key: UdpSessionKey, handle: UdpSessionHandle) {
        self.sessions.insert(key, handle);
    }

    /// 定期清理已关闭的会话（Sender closed 或超时），避免 HashMap 无限增长
    fn gc(&mut self) {
        self.sessions
            .retain(|_, h| !h.data_tx.is_closed() && h.last_seen.elapsed() < UDP_TIMEOUT * 2);
    }
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

pub struct Dispatcher {
    router: Arc<Router>,
    outbound_mgr: Arc<OutboundManager>,
    dns_tx: DnsQueryTx,
    dns_resolver: Arc<DnsResolver>,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
}

impl Dispatcher {
    pub fn new(
        router: Arc<Router>,
        outbound_mgr: Arc<OutboundManager>,
        dns_tx: DnsQueryTx,
        dns_resolver: Arc<DnsResolver>,
        stats: Arc<Stats>,
        conn_tracker: Arc<ConnectionTracker>,
    ) -> Self {
        Self {
            router,
            outbound_mgr,
            dns_tx,
            dns_resolver,
            stats,
            conn_tracker,
        }
    }

    pub async fn run_tcp(self, mut rx: mpsc::Receiver<InboundTcpStream>) {
        while let Some(mut conn) = rx.recv().await {
            // ── FakeIP 反向查找（参照 sing-box route.go routeConnection）──────────
            // 若目标 IP 落在 FakeIP 段内，立即还原为域名目标，再进入路由匹配。
            // 参照 sing-box：IP 在段内但 store 无记录时，视为致命错误断连，
            // 并建议用户开启 experimental.cache_file.store_fakeip。
            if let Target::Socket(addr) = &conn.target {
                let ip = addr.ip();
                let port = addr.port();
                use crate::dns::FakeIpLookup;
                match self.dns_resolver.lookup_fakeip(ip) {
                    FakeIpLookup::Found(domain) => {
                        debug!(
                            fakeip = %ip,
                            domain = %domain,
                            "fakeip reverse lookup: restoring domain target"
                        );
                        conn.target = Target::Domain(domain, port);
                    }
                    FakeIpLookup::Missing => {
                        tracing::warn!(
                            fakeip = %ip,
                            "fakeip reverse lookup: missing record, dropping connection; \
                             enable experimental.cache_file.store_fakeip to persist mappings"
                        );
                        continue;
                    }
                    FakeIpLookup::NotFakeIp => {}
                }
            }

            // 先做第一次路由，检查是否需要嗅探
            // 进程查找：仅当存在 process_name/process_path 规则时才做（短路优化）。
            // 查找需要 src + dst + proto，src 用 peer_addr（客户端真实地址）。
            // 拿不到 peer_addr 时（极少见，Unix socket 入站等）直接跳过进程匹配。
            let proc_info = if self.router.has_process_rules() {
                let src = conn.stream.peer_addr().unwrap_or(ZERO_ADDR);
                let dst = conn.target.to_socket_addr_lossy();
                self.router
                    .process_resolver()
                    .lookup(src, dst, crate::app::process::NetProtocol::Tcp)
                    .await
            } else {
                None
            };

            // 全局 hijack_dns 短路：route.hijack_dns=true 时，端口 53 流量
            // 直接交给 DNS 模块，跳过整张路由表与 sniff/resolve 链路。
            // 与 sing-box `route.hijack_dns: true` 行为对齐。
            if self.router.hijack_dns_global() && conn.target.port() == 53 {
                debug!(target = %conn.target, "global hijack_dns: short-circuit to DnsOut");
                self.stats.dns().record_hijack(true);
                let rule_info = RuleInfo {
                    rule_type: "HIJACK-DNS".into(),
                    rule_payload: "".into(),
                };
                let mgr = self.outbound_mgr.clone();
                let dns_tx = self.dns_tx.clone();
                let stats = self.stats.clone();
                let conn_tracker = self.conn_tracker.clone();
                let action = RouteAction::DnsOut;
                tokio::spawn(async move {
                    if let Err(e) =
                        dispatch_tcp(conn, action, rule_info, mgr, dns_tx, stats, conn_tracker)
                            .await
                    {
                        debug!(err = %e, "tcp dispatch error (hijack_dns)");
                    }
                });
                continue;
            }
            let (action_ref, rule_type, rule_payload, options_ref) =
                self.router.route_tcp(&conn, proc_info.as_ref());
            let action = action_ref.clone();
            let mut route_options = options_ref.clone();
            // 优化：延迟 RuleInfo 构造到路由最终确定后，避免 sniff/resolve 重路由
            // 分支里重复分配 Arc<str>。原实现每次重路由都构造一次 RuleInfo（2 个
            // Arc<str> 分配），最多构造 3 次，但只有最后一次被使用。
            // 改为用 (&str, &str) 累积最终结果，最后一次性 .into() 构造。
            // router 返回的 &str 借用 self.router（Arc<Router>），在整个循环里存活。
            let mut rule_display: (&str, &str) = (rule_type, rule_payload);
            let action = if let RouteAction::Sniff {
                timeout_ms,
                override_destination,
                sniff_types,
                force_domain,
                skip_domain,
                skip_src_address,
            } = action
            {
                // 嗅探过滤器：根据 force_domain / skip_domain / skip_src_address
                // 决定是否对当前连接执行嗅探。被过滤掉的连接直接进入下一阶段
                // 路由（与未命中 sniff 规则一致），避免对内网/特定来源做无谓嗅探。
                let filter = crate::app::sniff::SniffFilter::from_config(
                    force_domain,
                    skip_domain,
                    skip_src_address,
                );
                let target_host = match &conn.target {
                    Target::Domain(h, _) => Some(h.as_str()),
                    Target::Socket(_) => None,
                };
                let src_ip = conn.stream.peer_addr().ok().map(|a| a.ip());
                let should_sniff = filter.should_sniff(target_host, src_ip);

                // 嗅探：非破坏性读取头部，识别域名后按配置决定是否覆盖目标地址
                let sniff_result = if should_sniff {
                    sniff(&mut conn.stream, timeout_ms, &sniff_types).await
                } else {
                    debug!(
                        target = %conn.target,
                        "sniff skipped by filter (force_domain/skip_domain/skip_src_address)"
                    );
                    None
                };
                if let Some(result) = sniff_result {
                    let port = conn.target.port();
                    // 将协议写入 sniffed_protocol，供路由规则匹配
                    if conn.sniffed_protocol.is_none() {
                        conn.sniffed_protocol = Some(result.protocol.to_string());
                    }
                    if let Some(domain) = result.domain {
                        if override_destination {
                            debug!(
                                original = %conn.target,
                                sniffed = %domain,
                                protocol = result.protocol,
                                "sniff updated target domain"
                            );
                            conn.target = crate::inbound::Target::Domain(domain, port);
                        } else {
                            debug!(
                                original = %conn.target,
                                sniffed = %domain,
                                protocol = result.protocol,
                                "sniff identified domain (override_destination=false, target unchanged)"
                            );
                            conn.sniffed_domain = Some(domain);
                        }
                    } else {
                        debug!(
                            original = %conn.target,
                            protocol = result.protocol,
                            "sniff identified protocol (no domain)"
                        );
                    }
                }
                // 无条件检测 TCP DNS（端口 53 上的 DNS over TCP）。
                // 原实现仅在 Sniff 嗅探未识别协议时才做兜底检测，导致用户没配
                // sniff 规则时 TCP DNS 流量无法被 hijack_dns 捕获。
                // 改为：只要端口=53 且 prefix 足够长，就尝试 is_dns_wire 检测，
                // 命中则把 sniffed_protocol 设为 "dns"，后续 hijack_dns 规则可命中。
                if conn.target.port() == 53
                    && conn.sniffed_protocol.is_none()
                    && conn.stream.prefix.len() >= 14
                {
                    let dns_buf = &conn.stream.prefix[2..];
                    if is_dns_wire(dns_buf) {
                        conn.sniffed_protocol = Some("dns".to_string());
                    }
                }
                // 重新路由（跳过所有 Sniff 规则，避免死循环）
                // 多候选语义：override_destination=false 时 conn.target 保留原始值
                // （IP 或 Domain），conn.sniffed_domain 存嗅探域名，两者都参与匹配。
                // override_destination=true 时 conn.target 已被覆盖为 Domain，sniffed_domain 为 None。
                {
                    let (a, rt, rp, ro) =
                        self.router.route_tcp_after_sniff(&conn, proc_info.as_ref());
                    rule_display = (rt, rp);
                    route_options = ro.clone();
                    a.clone()
                }
            } else {
                // 未命中 Sniff 规则，但若目标是 TCP 53 端口，仍需做一次
                // 轻量 DNS 协议检测：用户可能没配 sniff 规则，但配了
                // hijack_dns + protocol=["dns"]，此时需要嗅探出协议为 "dns"。
                // 这里的轻量检测复用 sniff() 函数，仅启用 DNS 嗅探类型，
                // 默认 300ms 超时；嗅探到的字节会被 prepend 归还，不影响后续转发。
                if conn.target.port() == 53 && conn.sniffed_protocol.is_none() {
                    let dns_only = vec![crate::app::sniff::SniffType::Dns];
                    if let Some(result) = sniff(&mut conn.stream, 0, &dns_only).await {
                        if conn.sniffed_protocol.is_none() {
                            conn.sniffed_protocol = Some(result.protocol.to_string());
                        }
                        // DNS 协议嗅探不携带域名，result.domain 必为 None，无需处理
                        let _ = result.domain;
                        // 命中 DNS 后重新路由，让 hijack_dns 规则能匹配
                        let (a, rt, rp, ro) =
                            self.router.route_tcp_after_sniff(&conn, proc_info.as_ref());
                        rule_display = (rt, rp);
                        route_options = ro.clone();
                        a.clone()
                    } else {
                        action
                    }
                } else {
                    action
                }
            };

            // 处理 Resolve 动作：将域名解析为 IP，resolved_ip 作为新候选加入后续匹配。
            // 解析优先级：sniffed_domain → target.Domain
            // resolve 后保留所有候选：sniffed_domain + target（原始）+ resolved_ip
            let action = if let RouteAction::Resolve { server } = &action {
                // 确定要解析的域名：优先 sniffed_domain，其次 target.Domain
                let domain_to_resolve =
                    conn.sniffed_domain.clone().or_else(|| match &conn.target {
                        Target::Domain(h, _) => Some(h.clone()),
                        Target::Socket(_) => None,
                    });

                if let Some(host) = domain_to_resolve {
                    let resolve_result = match server.as_ref() {
                        Some(tags) => {
                            self.dns_resolver
                                .resolve_domain_via(&host, tags.as_slice())
                                .await
                        }
                        None => self.dns_resolver.resolve_domain(&host).await,
                    };
                    match resolve_result {
                        Ok(ip) => {
                            debug!(
                                domain = %host,
                                ip = %ip,
                                "resolve: domain resolved, re-routing with resolved IP as candidate"
                            );
                            let (a, rt, rp, ro) = self.router.route_tcp_after_resolve(
                                &conn,
                                Some(ip),
                                proc_info.as_ref(),
                            );
                            rule_display = (rt, rp);
                            route_options = ro.clone();
                            a.clone()
                        }
                        Err(e) => {
                            debug!(domain = %host, err = %e, "resolve: DNS lookup failed, falling through");
                            let (a, rt, rp, ro) = self.router.route_tcp_after_resolve(
                                &conn,
                                None,
                                proc_info.as_ref(),
                            );
                            rule_display = (rt, rp);
                            route_options = ro.clone();
                            a.clone()
                        }
                    }
                } else {
                    // 没有域名可解析（target 是 IP 且无 sniffed_domain），直接跳过
                    let (a, rt, rp, ro) =
                        self.router
                            .route_tcp_after_resolve(&conn, None, proc_info.as_ref());
                    rule_display = (rt, rp);
                    route_options = ro.clone();
                    a.clone()
                }
            } else {
                action
            };

            // 应用 override_address / override_port（在所有 sniff/resolve 重路由
            // 完成后、实际派发给出站之前生效）。
            apply_route_overrides(&mut conn.target, &route_options);

            // 优化：路由最终确定后才构造 RuleInfo，避免中间分支重复分配 Arc<str>。
            let rule_info = RuleInfo {
                rule_type: rule_display.0.into(),
                rule_payload: rule_display.1.into(),
            };

            let mgr = self.outbound_mgr.clone();
            let dns_tx = self.dns_tx.clone();
            let stats = self.stats.clone();
            let conn_tracker = self.conn_tracker.clone();

            // 规则级 hijack_dns 统计：action 为 DnsOut 但未走全局短路时，
            // 说明是规则匹配命中 hijack_dns，记录一次劫持（TCP）。
            if matches!(action, RouteAction::DnsOut) {
                self.stats.dns().record_hijack(true);
            }

            tokio::spawn(async move {
                if let Err(e) =
                    dispatch_tcp(conn, action, rule_info, mgr, dns_tx, stats, conn_tracker).await
                {
                    debug!(err=%e, "tcp dispatch error");
                    debug!("tcp dispatch error chain: {:#}", e);
                }
            });
        }
    }

    pub async fn run_udp(self, mut rx: mpsc::Receiver<InboundUdpPacket>) {
        let mut session_table = UdpSessionTable::new();
        // GC 定时器：每 30 秒清理一次死会话
        let mut gc_ticker = tokio::time::interval(Duration::from_secs(30));
        gc_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                maybe_packet = rx.recv() => {
                    let Some(mut packet) = maybe_packet else { break };

                    // ── FakeIP 反向查找 ──────────────────────────────────────
                    if let Target::Socket(addr) = &packet.target {
                        let ip = addr.ip();
                        let port = addr.port();
                        use crate::dns::FakeIpLookup;
                        match self.dns_resolver.lookup_fakeip(ip) {
                            FakeIpLookup::Found(domain) => {
                                debug!(
                                    fakeip = %ip,
                                    domain = %domain,
                                    "fakeip reverse lookup (udp): restoring domain target"
                                );
                                // 参照 sing-box route.go routePacketConnection：
                                // 保存原 fakeip SocketAddr 到 origin_destination，
                                // 供 UDP 出站回包时把源地址伪装回 fakeip
                                // （对应 sing-box 的 bufio.NewNATPacketConn 包装）。
                                packet.origin_destination = Some(*addr);
                                packet.target = Target::Domain(domain, port);
                            }
                            FakeIpLookup::Missing => {
                                tracing::warn!(
                                    fakeip = %ip,
                                    "fakeip reverse lookup (udp): missing record, dropping packet; \
                                     enable experimental.cache_file.store_fakeip to persist mappings"
                                );
                                continue;
                            }
                            FakeIpLookup::NotFakeIp => {}
                        }
                    }

                    // UDP DNS 协议检测
                    if packet.sniffed_protocol.is_none() && is_dns_wire(&packet.data) {
                        packet.sniffed_protocol = Some("dns".to_string());
                    }

                    // 全局 hijack_dns 短路（与 TCP 对称）：route.hijack_dns=true 时，
                    // 端口 53 的 UDP 包直接交给 DNS 模块，跳过路由表与 sniff/resolve。
                    // 与 FakeIP 路径一致，走 dispatch_udp 单包转发，不做 session 聚合
                    // （DNS 请求一次性问答，聚合意义不大）。
                    if self.router.hijack_dns_global() && packet.target.port() == 53 {
                        debug!(target = %packet.target, "global hijack_dns(udp): short-circuit to DnsOut");
                        self.stats.dns().record_hijack(false);
                        let mgr = self.outbound_mgr.clone();
                        let dns_tx = self.dns_tx.clone();
                        let stats = self.stats.clone();
                        let conn_tracker = self.conn_tracker.clone();
                        tokio::spawn(async move {
                            if let Err(e) = dispatch_udp(
                                packet,
                                RouteAction::DnsOut,
                                RuleInfo {
                                    rule_type: "HIJACK-DNS".into(),
                                    rule_payload: "".into(),
                                },
                                mgr,
                                dns_tx,
                                stats,
                                conn_tracker,
                            )
                            .await
                            {
                                debug!(err = %e, "udp dispatch error (hijack_dns)");
                            }
                        });
                        continue;
                    }

                    // 进程查找：仅当存在 process_name/process_path 规则时才做（短路优化）。
                    // UDP 包带 src（客户端真实地址），dst 取 target.to_socket_addr_lossy()。
                    let proc_info = if self.router.has_process_rules() {
                        let dst = packet.target.to_socket_addr_lossy();
                        self.router
                            .process_resolver()
                            .lookup(packet.src, dst, crate::app::process::NetProtocol::Udp)
                            .await
                    } else {
                        None
                    };

                    let (action_ref, rule_type, rule_payload, options_ref) =
                        self.router.route_udp(&packet, proc_info.as_ref());
                    let action = action_ref.clone();
                    // 优化：延迟 RuleInfo 构造（与 TCP 路径对称），避免 sniff/resolve
                    // 重路由分支里重复分配 Arc<str>。
                    let mut rule_display: (&str, &str) = (rule_type, rule_payload);
                    let mut route_options = options_ref.clone();

                    // UDP 嗅探：对单包做协议识别（QUIC/DTLS/STUN/NTP/BitTorrent-uTP/DNS）。
                    // 与 TCP 不同的是：UDP 无连接，每个包独立嗅探；但嗅探开销极低
                    // （只读已有 packet.data，不阻塞 IO），所以无条件执行。
                    // 嗅探到域名时按 override_destination 决定是否覆盖 target，
                    // 并把结果存入 sniffed_domain 供后续路由多候选匹配。
                    let action = if let RouteAction::Sniff {
                        override_destination,
                        sniff_types,
                        force_domain,
                        skip_domain,
                        skip_src_address,
                        ..
                    } = &action
                    {
                        // 嗅探过滤器：UDP 路径与 TCP 对称。
                        let filter = crate::app::sniff::SniffFilter::from_config(
                            force_domain.clone(),
                            skip_domain.clone(),
                            skip_src_address.clone(),
                        );
                        let target_host = match &packet.target {
                            Target::Domain(h, _) => Some(h.as_str()),
                            Target::Socket(_) => None,
                        };
                        let src_ip = Some(packet.src.ip());
                        let should_sniff = filter.should_sniff(target_host, src_ip);

                        if should_sniff {
                            if let Some(result) =
                                crate::app::sniff::sniff_packet(&packet.data, sniff_types)
                            {
                                if packet.sniffed_protocol.is_none() {
                                    packet.sniffed_protocol = Some(result.protocol.to_string());
                                }
                                if let Some(domain) = result.domain {
                                    let port = packet.target.port();
                                    if *override_destination {
                                        debug!(
                                            original = %packet.target,
                                            sniffed = %domain,
                                            protocol = result.protocol,
                                            "sniff(udp) updated target domain"
                                        );
                                        packet.target = Target::Domain(domain, port);
                                    } else {
                                        debug!(
                                            original = %packet.target,
                                            sniffed = %domain,
                                            protocol = result.protocol,
                                            "sniff(udp) identified domain (override_destination=false)"
                                        );
                                        packet.sniffed_domain = Some(domain);
                                    }
                                }
                            }
                        } else {
                            debug!(
                                target = %packet.target,
                                "sniff(udp) skipped by filter (force_domain/skip_domain/skip_src_address)"
                            );
                        }
                        // 重新路由（跳过所有 Sniff 规则，避免死循环）
                        let (a, rt, rp, ro) =
                            self.router.route_udp_after_sniff(&packet, proc_info.as_ref());
                        rule_display = (rt, rp);
                        route_options = ro.clone();
                        a.clone()
                    } else {
                        action
                    };

                    // 处理 Resolve 动作（与 TCP 对称）
                    // 解析优先级：sniffed_domain → target.Domain
                    let action = if let RouteAction::Resolve { server } = &action {
                        let domain_to_resolve = packet
                            .sniffed_domain
                            .clone()
                            .or_else(|| match &packet.target {
                                Target::Domain(h, _) => Some(h.clone()),
                                Target::Socket(_) => None,
                            });

                        if let Some(host) = domain_to_resolve {
                            let resolve_result = match server.as_ref() {
                                Some(tags) => {
                                    self.dns_resolver
                                        .resolve_domain_via(&host, tags.as_slice())
                                        .await
                                }
                                None => self.dns_resolver.resolve_domain(&host).await,
                            };
                            match resolve_result {
                                Ok(ip) => {
                                    debug!(
                                        domain = %host,
                                        ip = %ip,
                                        "resolve(udp): domain resolved, re-routing with resolved IP as candidate"
                                    );
                                    let (a, rt, rp, ro) = self
                                        .router
                                        .route_udp_after_resolve(&packet, Some(ip), proc_info.as_ref());
                                    rule_display = (rt, rp);
                                    route_options = ro.clone();
                                    a.clone()
                                }
                                Err(e) => {
                                    debug!(domain = %host, err = %e, "resolve(udp): DNS lookup failed, falling through");
                                    let (a, rt, rp, ro) =
                                        self.router.route_udp_after_resolve(&packet, None, proc_info.as_ref());
                                    rule_display = (rt, rp);
                                    route_options = ro.clone();
                                    a.clone()
                                }
                            }
                        } else {
                            let (a, rt, rp, ro) =
                                self.router.route_udp_after_resolve(&packet, None, proc_info.as_ref());
                            rule_display = (rt, rp);
                            route_options = ro.clone();
                            a.clone()
                        }
                    } else {
                        action
                    };

                    // 优化：路由最终确定后才构造 RuleInfo。
                    let rule_info = RuleInfo {
                        rule_type: rule_display.0.into(),
                        rule_payload: rule_display.1.into(),
                    };

                    // DNS 直接走原有逻辑，不需要会话复用
                    if matches!(action, RouteAction::DnsOut) {
                        // 规则级 hijack_dns 统计（UDP）
                        self.stats.dns().record_hijack(false);
                        let mgr = self.outbound_mgr.clone();
                        let dns_tx = self.dns_tx.clone();
                        let stats = self.stats.clone();
                        let conn_tracker = self.conn_tracker.clone();
                        tokio::spawn(async move {
                            if let Err(e) = dispatch_udp(packet, action, rule_info, mgr, dns_tx, stats, conn_tracker).await {
                                debug!(err=%e, "udp dns dispatch error");
                            }
                        });
                        continue;
                    }

                    // 对于真正的出站，使用会话复用
                    // 优化：outbound_tag 转 Arc<str>，session_key clone 时只原子 +1
                    let outbound_tag: Arc<str> = match &action {
                        RouteAction::Outbound(tag) => tag.as_str().into(),
                        _ => {
                            // Block / 其他 action，直接 dispatch
                            let mgr = self.outbound_mgr.clone();
                            let dns_tx = self.dns_tx.clone();
                            let stats = self.stats.clone();
                            let conn_tracker = self.conn_tracker.clone();
                            tokio::spawn(async move {
                                if let Err(e) = dispatch_udp(packet, action, rule_info, mgr, dns_tx, stats, conn_tracker).await {
                                    debug!(err=%e, "udp dispatch error");
                                }
                            });
                            continue;
                        }
                    };

                    // FakeIP 场景不走 session 聚合：回包源地址需要伪装回原 fakeip
                    // （packet.origin_destination），不同目标的 fakeip 不同，聚合会导致
                    // 回包源地址伪装错误，客户端 NAT 不匹配而丢包。走 dispatch_udp
                    // 保持每包独立出站，与原行为一致。
                    if packet.origin_destination.is_some() {
                        let mgr = self.outbound_mgr.clone();
                        let dns_tx = self.dns_tx.clone();
                        let stats = self.stats.clone();
                        let conn_tracker = self.conn_tracker.clone();
                        tokio::spawn(async move {
                            if let Err(e) = dispatch_udp(packet, action, rule_info, mgr, dns_tx, stats, conn_tracker).await {
                                debug!(err=%e, "udp (fakeip) dispatch error");
                            }
                        });
                        continue;
                    }

                    // 会话去重 key：按 (src, outbound) 聚合，同一客户端 socket 访问
                    // 多个目标时复用一条出站连接（对齐 mihomo natTable 按 src 聚合）。
                    let session_key: UdpSessionKey = (packet.src, outbound_tag.clone());

                    // 实际拨号目标：应用 override_address/override_port。
                    let mut dial_target = packet.target.clone();
                    apply_route_overrides(&mut dial_target, &route_options);

                    // udp_timeout 规则级覆盖，对齐 sing-box `udp_timeout`。
                    let timeout = route_options
                        .udp_timeout
                        .map(Duration::from_secs)
                        .unwrap_or_else(|| udp_timeout_for_port(dial_target.port()));

                    if let Some(handle) = session_table.get_live(&session_key) {
                        // 会话存活，投递 (target, data)：每包携带自己的目标地址，
                        // 出站实现据此构建协议帧，支持同会话多目标。
                        if let Err(mpsc::error::TrySendError::Full(_)) =
                            handle.data_tx.try_send((dial_target, packet.data))
                        {
                            warn!(
                                src=%packet.src,
                                dst=%packet.target,
                                "udp: session channel full, packet dropped"
                            );
                        }
                        handle.last_seen = Instant::now();
                        debug!(src=%packet.src, dst=%packet.target, "udp: reuse session");
                    } else {
                        // 新会话：启动一个长期 task 持有出站连接
                        debug!(src=%packet.src, dst=%packet.target, outbound=%outbound_tag, "udp: new session");
                        // 投递通道：inbound → session task，容量 64。元素为 (Target, Bytes)，
                        // 每包携带目标地址以支持同会话多目标复用。
                        let (data_tx, data_rx) = mpsc::channel::<(Target, bytes::Bytes)>(64);

                        // 先把第一个包发进去再启动 task
                        if let Err(mpsc::error::TrySendError::Full(_)) =
                            data_tx.try_send((dial_target.clone(), packet.data.clone()))
                        {
                            warn!(
                                src=%packet.src,
                                dst=%packet.target,
                                "udp: new session channel unexpectedly full, packet dropped"
                            );
                        }

                        let mgr = self.outbound_mgr.clone();
                        let stats = self.stats.clone();
                        let conn_tracker = self.conn_tracker.clone();
                        let dns_tx = self.dns_tx.clone();
                        let reply_tx = packet.session.reply_tx.clone();
                        let src = packet.src;
                        let inbound_tag = packet.inbound_tag.clone();
                        let rule_info_clone = rule_info.clone();
                        // Arc<str> clone 只是原子 +1
                        let ob_tag_str = outbound_tag.clone();

                        tokio::spawn(async move {
                            run_udp_session(
                                src,
                                inbound_tag,
                                ob_tag_str,
                                data_rx,
                                reply_tx,
                                rule_info_clone,
                                mgr,
                                dns_tx,
                                stats,
                                conn_tracker,
                                timeout,
                            )
                            .await;
                        });

                        session_table.insert(
                            session_key,
                            UdpSessionHandle {
                                data_tx,
                                last_seen: Instant::now(),
                            },
                        );
                    }
                }
                _ = gc_ticker.tick() => {
                    session_table.gc();
                }
            }
        }
    }
}

// ── UDP 会话 task ─────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn run_udp_session(
    src: SocketAddr,
    inbound_tag: String,
    outbound_tag: Arc<str>,
    mut data_rx: mpsc::Receiver<(Target, bytes::Bytes)>,
    reply_tx: mpsc::Sender<(bytes::Bytes, SocketAddr, SocketAddr)>,
    rule_info: RuleInfo,
    mgr: Arc<OutboundManager>,
    _dns_tx: DnsQueryTx,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
    timeout: Duration,
) {
    use crate::inbound::UdpSession;

    let ob = match mgr.get(&outbound_tag) {
        Some(o) => o,
        None => {
            debug!(tag=%outbound_tag, "udp session: outbound not found");
            return;
        }
    };

    let _guard = UdpGuard::new(stats.tag(&outbound_tag));

    // 等第一个包，获取目标地址（用于 conn_tracker 注册和 outbound 拨号）。
    // 会话按 (src, outbound) 聚合后，首包的目标即为本会话在 clash-ui 中展示的
    // host/destination（对齐 mihomo：一个 src 一个 sender，显示首包目标）。
    let (first_target, first_data) = match tokio::time::timeout(timeout, data_rx.recv()).await {
        Ok(Some((target, data))) => (target, data),
        Ok(None) => {
            debug!(src=%src, outbound=%outbound_tag, "udp session: data_rx closed before first packet");
            return;
        }
        Err(_) => {
            debug!(src=%src, outbound=%outbound_tag, timeout=?timeout, "udp session: idle timeout before first packet");
            return;
        }
    };

    let dest_port = first_target.port();
    // UDP 不做域名 sniff（packet.sniffed_domain 恒为 None），host/destination_ip
    // 直接基于首包目标计算。
    let (host, destination_ip) = host_and_dest_ip(None, &first_target);
    let conn_guard = conn_tracker.register(
        ConnInfo {
            network: "udp",
            host: &host,
            destination_ip: &destination_ip,
            source: src,
            dest_port,
            inbound: &inbound_tag,
            outbound: &outbound_tag,
        },
        &rule_info,
    );

    // 取消句柄必须在 conn_guard 被移入下面的 lifetime_guards（从而被 Box 包装
    // 移交给 packet）之前取出，否则 conn_guard 已被移动，无法再调用其方法。
    let cancel_handle = conn_guard.cancel_handle();

    // 获取实时计数器，用于 UDP 字节统计
    let (live_up, live_down) = conn_guard.live_counters().unwrap_or_else(|| {
        (
            std::sync::Arc::new(portable_atomic::AtomicI64::new(0)),
            std::sync::Arc::new(portable_atomic::AtomicI64::new(0)),
        )
    });

    let up_bytes = first_data.len() as i64;
    let live_down_clone = live_down.clone();
    let (counting_tx, mut counting_rx) =
        mpsc::channel::<(bytes::Bytes, SocketAddr, SocketAddr)>(64);
    let real_reply_tx = reply_tx.clone();
    tokio::spawn(async move {
        use std::sync::atomic::Ordering;
        while let Some((data, addr, spoofed_src)) = counting_rx.recv().await {
            let down_bytes = data.len() as i64;
            live_down_clone.fetch_add(down_bytes, Ordering::Relaxed);
            let _ = real_reply_tx.send((data, addr, spoofed_src)).await;
        }
    });
    let packet = InboundUdpPacket {
        data: first_data,
        src,
        target: first_target.clone(),
        inbound_tag: inbound_tag.clone(),
        session: UdpSession {
            reply_tx: counting_tx,
        },
        sniffed_protocol: None,
        sniffed_domain: None,
        // FakeIP 场景已在前置分流走 dispatch_udp，此处恒为 None。
        origin_destination: None,
        upstream_rx: Some(data_rx),
        lifetime_guards: vec![Box::new(conn_guard), Box::new(_guard)],
    };
    let handle_fut = ob.handle_udp(packet);
    match cancel_handle {
        Some((cancelled, notify)) => {
            tokio::select! {
                res = handle_fut => {
                    if let Err(e) = res {
                        debug!(err=%e, outbound=%outbound_tag, "udp session: handle_udp error");
                    }
                }
                _ = super::clash_api::wait_cancelled(&cancelled, &notify) => {
                    debug!(src=%src, dst=%first_target, outbound=%outbound_tag, "udp session terminated via clash api");
                }
            }
        }
        None => {
            if let Err(e) = handle_fut.await {
                debug!(err=%e, outbound=%outbound_tag, "udp session: handle_udp error");
            }
        }
    }
    use std::sync::atomic::Ordering;
    live_up.fetch_add(up_bytes, Ordering::Relaxed);
}

// ── TCP 分发 ──────────────────────────────────────────────────────────────────

async fn dispatch_tcp(
    conn: InboundTcpStream,
    action: RouteAction,
    rule_info: RuleInfo,
    mgr: Arc<OutboundManager>,
    dns_tx: DnsQueryTx,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
) -> anyhow::Result<()> {
    match action {
        RouteAction::DnsOut => {
            let guard = TcpGuard::new(stats.tag("dns-out"));
            let res = handle_dns_tcp(conn, dns_tx).await;
            if res.is_err() {
                guard.record_error();
            }
            res
        }
        RouteAction::Outbound(tag) => {
            let ob = mgr
                .get(&tag)
                .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))?;
            debug!(tag=%tag, target=%conn.target, "tcp → outbound");
            let guard = TcpGuard::new(stats.tag(&tag));
            let dest_port = conn.target.port();
            let (host, destination_ip) =
                host_and_dest_ip(conn.sniffed_domain.as_deref(), &conn.target);
            let source = conn.stream.peer_addr().unwrap_or(ZERO_ADDR);
            let conn_guard = conn_tracker.register(
                ConnInfo {
                    network: "tcp",
                    host: &host,
                    destination_ip: &destination_ip,
                    source,
                    dest_port,
                    inbound: &conn.inbound_tag,
                    outbound: &tag,
                },
                &rule_info,
            );
            let (live_up, live_down) = conn_guard.live_counters().unwrap_or_else(|| {
                (
                    std::sync::Arc::new(portable_atomic::AtomicI64::new(0)),
                    std::sync::Arc::new(portable_atomic::AtomicI64::new(0)),
                )
            });
            // 取消句柄需在 conn_guard 仍存于 tracker 中时获取（select! 期间
            // conn_guard 本身保持存活，直到下面这个代码块结束才 Drop）。
            let cancel_handle = conn_guard.cancel_handle();
            let result = match cancel_handle {
                Some((cancelled, notify)) => {
                    tokio::select! {
                        res = ob.handle_tcp_live(conn, live_up, live_down) => res,
                        _ = super::clash_api::wait_cancelled(&cancelled, &notify) => {
                            debug!(tag=%tag, "tcp connection terminated via clash api");
                            Ok((0, 0))
                        }
                    }
                }
                None => ob.handle_tcp_live(conn, live_up, live_down).await,
            };
            match result {
                Ok((up, down)) => {
                    guard.add_bytes(up, down);
                    Ok(())
                }
                Err(e) => {
                    guard.record_error();
                    Err(e)
                }
            }
        }
        RouteAction::Sniff { .. } => {
            unreachable!("Sniff action must not reach dispatch_tcp")
        }
        RouteAction::Resolve { .. } => {
            unreachable!("Resolve action must not reach dispatch_tcp")
        }
    }
}

// ── UDP 分发（仅用于 DNS-out 和非 Outbound action）───────────────────────────

async fn dispatch_udp(
    packet: InboundUdpPacket,
    action: RouteAction,
    rule_info: RuleInfo,
    mgr: Arc<OutboundManager>,
    dns_tx: DnsQueryTx,
    stats: Arc<Stats>,
    conn_tracker: Arc<ConnectionTracker>,
) -> anyhow::Result<()> {
    match action {
        RouteAction::DnsOut => {
            let _guard = UdpGuard::new(stats.tag("dns-out"));
            handle_dns_udp(packet, dns_tx).await
        }
        RouteAction::Outbound(tag) => {
            let ob = mgr
                .get(&tag)
                .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))?;
            debug!(tag=%tag, target=%packet.target, "udp → outbound (direct)");
            let _guard = UdpGuard::new(stats.tag(&tag));
            let dest_port = packet.target.port();
            let (host, destination_ip) =
                host_and_dest_ip(packet.sniffed_domain.as_deref(), &packet.target);
            let conn_guard = conn_tracker.register(
                ConnInfo {
                    network: "udp",
                    host: &host,
                    destination_ip: &destination_ip,
                    source: packet.src,
                    dest_port,
                    inbound: &packet.inbound_tag,
                    outbound: &tag,
                },
                &rule_info,
            );
            let cancel_handle = conn_guard.cancel_handle();
            let result = match cancel_handle {
                Some((cancelled, notify)) => {
                    tokio::select! {
                        res = ob.handle_udp(packet) => res,
                        _ = super::clash_api::wait_cancelled(&cancelled, &notify) => {
                            debug!(tag=%tag, "udp packet dispatch terminated via clash api");
                            Ok(())
                        }
                    }
                }
                None => ob.handle_udp(packet).await,
            };
            drop(conn_guard);
            result
        }
        RouteAction::Sniff { .. } => {
            debug!("Sniff action reached dispatch_udp unexpectedly, dropping packet");
            Ok(())
        }
        RouteAction::Resolve { .. } => {
            debug!("Resolve action reached dispatch_udp unexpectedly, dropping packet");
            Ok(())
        }
    }
}

// ── DNS over TCP（来自 tproxy/mixed 路由到 dns-out）──────────────────────────

async fn handle_dns_tcp(mut conn: InboundTcpStream, dns_tx: DnsQueryTx) -> anyhow::Result<()> {
    use bytes::Bytes;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };

    loop {
        let len = match conn.stream.read_u16().await {
            Ok(v) => v as usize,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        };
        anyhow::ensure!(len <= 65535, "DNS TCP message too large: {len}");

        let mut buf = vec![0u8; len];
        conn.stream.read_exact(&mut buf).await?;

        let (reply_tx, reply_rx) = oneshot::channel::<Bytes>();
        dns_tx
            .send(DnsQuery {
                message: Bytes::from(buf),
                from: conn.stream.peer_addr().unwrap_or(ZERO_ADDR),
                inbound_tag: conn.inbound_tag.clone(),
                source: crate::inbound::dns::DnsQuerySource::Hijacked,
                reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("dns resolver closed"))?;

        let resp = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("dns reply dropped"))?;

        conn.stream
            .write_all(&(resp.len() as u16).to_be_bytes())
            .await?;
        conn.stream.write_all(&resp).await?;
    }
    Ok(())
}

// ── DNS over UDP（来自 tproxy/mixed 路由到 dns-out）──────────────────────────

async fn handle_dns_udp(packet: InboundUdpPacket, dns_tx: DnsQueryTx) -> anyhow::Result<()> {
    use tokio::sync::oneshot;

    let (reply_tx, reply_rx) = oneshot::channel();
    dns_tx
        .send(DnsQuery {
            message: packet.data,
            from: packet.src,
            inbound_tag: packet.inbound_tag,
            source: crate::inbound::dns::DnsQuerySource::Hijacked,
            reply_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("dns resolver closed"))?;

    let resp = reply_rx
        .await
        .map_err(|_| anyhow::anyhow!("dns reply dropped"))?;

    let _ = packet
        .session
        .reply_tx
        .send((resp, packet.src, packet.target.to_socket_addr_lossy()))
        .await;
    Ok(())
}
