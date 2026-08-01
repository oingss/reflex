pub mod clash_api;
pub mod dispatcher;
pub mod outbound_mgr;
pub mod process;
pub mod ruleset_registry;
pub mod sniff;
pub mod stats;

use std::sync::Arc;

use tokio::{sync::mpsc, task::JoinSet};
use tracing::{error, info};

use crate::{
    clash_mode::ClashMode,
    config::{dns::ResolveStrategy, inbound::InboundConfig, Config},
    dns::DnsResolver,
    experimental::{open_cache_file, CacheFile, CacheFileReader},
    inbound::{
        dns::DnsInbound, http::HttpInbound, mixed::MixedInbound, socks::SocksInbound,
        tun::TunInbound, InboundTcpStream, InboundUdpPacket,
    },
    router::Router,
};

use clash_api::ClashApi;
use dispatcher::Dispatcher;
use outbound_mgr::{OutboundManager, OutboundManagerConfig};
use ruleset_registry::RuleSetRegistry;
use stats::Stats;

#[cfg(target_os = "linux")]
use crate::inbound::{redir::RedirInbound, tproxy::TProxyInbound};

pub struct App {
    tasks: JoinSet<anyhow::Result<()>>,
    /// 对外暴露统计，供监控接口查询
    pub stats: Arc<Stats>,
}

impl App {
    pub async fn start(config_path: &str) -> anyhow::Result<Self> {
        Self::start_with_config_path(Config::from_file(config_path)?, Some(config_path)).await
    }

    pub async fn start_with_config(config: Config) -> anyhow::Result<Self> {
        Self::start_with_config_path(config, None).await
    }

    pub async fn start_with_config_path(
        config: Config,
        config_path: Option<&str>,
    ) -> anyhow::Result<Self> {
        let stats = Stats::new();

        // ── 0. 实验性功能：cache_file ────────────────────────────────────────
        let (cache_writer, cache_reader): (Option<Arc<CacheFile>>, Option<Arc<CacheFileReader>>) =
            if let Some(cf_cfg) = config.experimental.cache_file.as_ref() {
                if cf_cfg.enabled {
                    let (writer, reader) = open_cache_file(
                        &cf_cfg.path,
                        cf_cfg.store_fakeip,
                        cf_cfg.fakeip_ttl_days,
                        cf_cfg.store_dns,
                        cf_cfg.dns_cleanup_interval_secs,
                    )?;
                    info!(
                        path=%cf_cfg.path,
                        store_fakeip=%cf_cfg.store_fakeip,
                        store_dns=%cf_cfg.store_dns,
                        "cache file opened"
                    );
                    (Some(writer), Some(reader))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            };

        // ── 0.5 Clash API 模式共享状态 ──────────────────────────────────────
        // 必须在 Router / DnsResolver 之前创建：三者要共享同一个 Arc<ClashMode>
        // 实例，这样 PATCH /configs 写入的模式变化才能被 `clash_mode` 规则条件
        // 实时感知（对齐 sing-box clash_mode 规则项的语义）。
        let initial_mode = config
            .experimental
            .clash_api
            .as_ref()
            .map(|c| c.default_mode.clone())
            .unwrap_or_else(|| "rule".to_string());
        let clash_mode = Arc::new(ClashMode::new(initial_mode));

        // ── 1. 路由器（先建，因为 DNS resolver 需要共享规则集）────────────────
        let router = Arc::new(Router::from_config(
            &config.route,
            cache_reader.as_ref().map(|r| r.as_ref()),
            cache_writer.as_ref().map(|w| w.as_ref()),
            clash_mode.clone(),
        )?);
        info!("router: {} rules loaded", config.route.rules.len());

        // ── 2. DNS 解析器（先于 OutboundManager 构建，传入 outbound 前需要它）──
        // 注意：此时 outbounds 还未构建，detour 字段暂时无法解析；
        // 先用无 outbounds 的版本初始化，待 OutboundManager 建好后再注入。
        // 为了解决循环依赖（DNS需要outbound，outbound需要DNS），
        // 使用两阶段初始化：先用 Arc<OnceLock> 延迟注入。
        let (dns_tx, dns_rx) = mpsc::channel::<crate::inbound::dns::DnsQuery>(256);

        // DNS 缺失（dns.servers 为空）时使用 disabled resolver：
        // 无 upstream、无缓存，resolve_domain 返回错误（dispatcher 优雅降级）。
        // 不启动 DNS 处理循环（下方 dns_enabled 控制不 spawn run task）。
        let dns_enabled = !config.dns.servers.is_empty();

        // 第一阶段：不带 outbounds 构建 DNS resolver（detour 暂时为直连）
        let dns_resolver = Arc::new(if dns_enabled {
            let mut r = DnsResolver::from_config_full(
                &config.dns,
                &router.rulesets,
                None, // outbounds 还未就绪
                cache_writer.clone(),
                cache_reader.clone(),
                config.route.default_mark.unwrap_or(0),
                clash_mode.clone(),
            )?;
            if !config.route.ipv6 {
                // route.ipv6=false 强制 Ipv4Only，覆盖 dns.strategy 的任何设置
                r.strategy = ResolveStrategy::Ipv4Only;
                // 同步更新所有 fakeip upstream 的 strategy
                r.set_fakeip_strategy(ResolveStrategy::Ipv4Only);
            }
            r
        } else {
            info!("dns: no servers configured, DNS module disabled (domain resolution will fail)");
            DnsResolver::disabled(clash_mode.clone())
        });

        // ── 3. Provider Manager（先于 OutboundManager，节点需要在 outbound 构建前加载）
        let provider_manager = if config.providers.is_empty() {
            None
        } else {
            let config_dir = std::path::PathBuf::from(
                config_path
                    .as_ref()
                    .and_then(|p| std::path::Path::new(p).parent())
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| ".".to_string()),
            );
            let mgr = Arc::new(crate::provider::ProviderManager::new(&config.providers));
            for provider_cfg in &config.providers {
                match provider_cfg {
                    crate::config::ProviderConfig::Remote(c) => {
                        crate::provider::remote::start_remote_provider(
                            c.clone(),
                            mgr.clone(),
                            config_dir.clone(),
                        )
                        .await;
                    }
                    crate::config::ProviderConfig::Local(c) => {
                        crate::provider::remote::start_local_provider(
                            c.clone(),
                            mgr.clone(),
                            config_dir.clone(),
                        );
                    }
                }
            }
            Some(mgr)
        };

        // ── 4. 出站注册表（注入 DNS resolver 和 ProviderManager）────────────
        let outbound_mgr = Arc::new(OutboundManager::from_config_full(
            &config.outbounds,
            OutboundManagerConfig {
                resolver: Some(dns_resolver.clone()),
                cache_writer: cache_writer.clone(),
                cache_reader: cache_reader.clone(),
                provider_manager: provider_manager.clone(),
                routing_mark: config.route.default_mark.unwrap_or(0),
                auto_detect_interface: config.route.auto_detect_interface,
                default_interface: config.route.default_interface.clone(),
            },
        )?);
        info!(
            "outbound manager: {} outbounds registered",
            outbound_mgr.len()
        );

        // ── 校验：路由规则引用的 outbound tag 必须已注册 ──────────────────────
        // sniff/resolve/hijack_dns/private_ip 规则不依赖 outbound tag，跳过。
        // final 字段也需要检查。
        {
            for (i, rule) in config.route.rules.iter().enumerate() {
                if rule.sniff || rule.resolve || rule.hijack_dns || rule.private_ip {
                    continue;
                }
                let tag = &rule.outbound;
                if !tag.is_empty() && tag != "dns-out" && outbound_mgr.get(tag).is_none() {
                    anyhow::bail!(
                        "route rule[{i}]: outbound tag \"{tag}\" is not defined in outbounds"
                    );
                }
            }
            let final_tag = &config.route.r#final;
            if final_tag != "dns-out" && outbound_mgr.get(final_tag).is_none() {
                anyhow::bail!(
                    "route.final: outbound tag \"{final_tag}\" is not defined in outbounds"
                );
            }
        }

        // ── provider 节点变更监听 + health_check ─────────────────────────────
        if let Some(ref pmgr) = provider_manager {
            // 为每个 selector/urltest outbound 启动 provider 变更监听
            for ob_cfg in &config.outbounds {
                let pref = match ob_cfg {
                    crate::config::OutboundConfig::Selector(c) => c.providers.clone(),
                    crate::config::OutboundConfig::UrlTest(c) => c.providers.clone(),
                    _ => None,
                };
                if let Some(pref) = pref {
                    if pref.tags.is_empty() {
                        continue;
                    }
                    let ob_tag = ob_cfg.tag().to_string();
                    let outbound_mgr_ref = outbound_mgr.clone();
                    let pmgr_ref = pmgr.clone();
                    let pref_clone = pref.clone();
                    // 对每个引用的 provider 订阅更新
                    for ptag in &pref.tags {
                        let mut rx = match pmgr.subscribe(ptag) {
                            Some(r) => r,
                            None => continue,
                        };
                        let ob_tag2 = ob_tag.clone();
                        let pmgr2 = pmgr_ref.clone();
                        let pref2 = pref_clone.clone();
                        let mgr2 = outbound_mgr_ref.clone();
                        tokio::spawn(async move {
                            loop {
                                if rx.changed().await.is_err() {
                                    break;
                                }
                                // 重新展开所有 provider 节点
                                let nodes = pmgr2.expand(&pref2);
                                let tags: Vec<String> = nodes.into_iter().map(|(t, _)| t).collect();
                                if let Some(ob) = mgr2.get(&ob_tag2) {
                                    if let Some(sel) = ob
                                        .as_any()
                                        .downcast_ref::<crate::outbound::common::group::SelectorOutbound>(
                                    ) {
                                        sel.refresh_provider_nodes(tags);
                                    } else if let Some(ut) = ob
                                        .as_any()
                                        .downcast_ref::<crate::outbound::common::group::UrlTestOutbound>(
                                    ) {
                                        ut.refresh_provider_nodes(tags);
                                    }
                                }
                            }
                        });
                    }
                    // 初始展开
                    let nodes = pmgr.expand(&pref);
                    let tags: Vec<String> = nodes.into_iter().map(|(t, _)| t).collect();
                    if let Some(ob) = outbound_mgr.get(&ob_tag) {
                        if let Some(sel) =
                            ob.as_any()
                                .downcast_ref::<crate::outbound::common::group::SelectorOutbound>()
                        {
                            sel.refresh_provider_nodes(tags);
                        } else if let Some(ut) =
                            ob.as_any()
                                .downcast_ref::<crate::outbound::common::group::UrlTestOutbound>()
                        {
                            ut.refresh_provider_nodes(tags);
                        }
                    }
                }
            }

            // health_check
            let hc_history = Arc::new(crate::app::clash_api::DelayHistory::default());
            let ob_registry = outbound_mgr.as_registry();
            for provider_cfg in &config.providers {
                let (ptag, hc) = match provider_cfg {
                    crate::config::ProviderConfig::Remote(c) => (&c.tag, c.health_check.as_ref()),
                    crate::config::ProviderConfig::Local(c) => (&c.tag, c.health_check.as_ref()),
                };
                if let Some(hc) = hc {
                    crate::provider::health::start_health_check(
                        ptag.clone(),
                        hc.clone(),
                        pmgr.clone(),
                        ob_registry.clone(),
                        hc_history.clone(),
                    );
                }
            }
        }

        // 第二阶段：用完整的 outbounds 重建 DNS resolver（解析 detour 字段）
        // DNS 禁用时跳过重建，继续使用第一阶段的 disabled resolver。
        let dns_resolver = if dns_enabled {
            Arc::new({
                let mut r = DnsResolver::from_config_full(
                    &config.dns,
                    &router.rulesets,
                    Some(outbound_mgr.as_map()),
                    cache_writer,
                    cache_reader,
                    config.route.default_mark.unwrap_or(0),
                    clash_mode.clone(),
                )?;
                if !config.route.ipv6 {
                    // route.ipv6=false 强制 Ipv4Only，覆盖 dns.strategy 的任何设置
                    r.strategy = ResolveStrategy::Ipv4Only;
                    // 同步更新所有 fakeip upstream 的 strategy
                    r.set_fakeip_strategy(ResolveStrategy::Ipv4Only);
                }
                r
            })
        } else {
            dns_resolver
        };
        if dns_enabled {
            info!(
                "dns resolver: {} servers, {} rules",
                config.dns.servers.len(),
                config.dns.rules.len()
            );
        }

        // ── 4. 入站 → Dispatcher 通道 ────────────────────────────────────────
        let (tcp_tx, tcp_rx) = mpsc::channel::<InboundTcpStream>(1024);
        let (udp_tx, udp_rx) = mpsc::channel::<InboundUdpPacket>(1024);

        let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();

        // ── 5. 启动各 Inbound ────────────────────────────────────────────────
        // inbounds 为空时自动补一个 127.0.0.1:7890 的 mixed 入站，
        // 实现"零配置即可启动"（配合自动补的 direct 出站）。
        let default_inbounds: Vec<InboundConfig>;
        let inbounds_iter: &Vec<InboundConfig> = if config.inbounds.is_empty() {
            info!("inbounds: empty, auto-creating default mixed inbound at 127.0.0.1:7890");
            default_inbounds = vec![InboundConfig::Mixed(
                crate::config::inbound::MixedInboundConfig {
                    tag: "mixed-in".to_string(),
                    listen: "127.0.0.1".to_string(),
                    listen_port: 7890,
                    network: crate::config::inbound::Network::TcpUdp,
                    username: None,
                    password: None,
                    udp_timeout: None,
                },
            )];
            &default_inbounds
        } else {
            &config.inbounds
        };

        for ib_config in inbounds_iter {
            match ib_config {
                InboundConfig::TProxy(c) => {
                    #[cfg(target_os = "linux")]
                    {
                        info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting tproxy inbound");
                        let mut c = c.clone();
                        if c.routing_mark == 0 {
                            c.routing_mark = config.route.default_mark.unwrap_or(0);
                        }
                        let inbound = TProxyInbound::new(c, tcp_tx.clone(), udp_tx.clone());
                        tasks.spawn(async move { inbound.run().await });
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        anyhow::bail!("tproxy inbound '{}' is only supported on Linux", c.tag);
                    }
                }
                InboundConfig::Redir(c) => {
                    #[cfg(target_os = "linux")]
                    {
                        info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting redir inbound");
                        let inbound = RedirInbound::new(c.clone(), tcp_tx.clone());
                        tasks.spawn(async move { inbound.run().await });
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        anyhow::bail!("redir inbound '{}' is only supported on Linux", c.tag);
                    }
                }
                InboundConfig::Mixed(c) => {
                    info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting mixed inbound");
                    let inbound = MixedInbound::new(c.clone(), tcp_tx.clone(), udp_tx.clone());
                    tasks.spawn(async move { inbound.run().await });
                }
                InboundConfig::Http(c) => {
                    info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting http inbound");
                    let inbound = HttpInbound::new(c.clone(), tcp_tx.clone());
                    tasks.spawn(async move { inbound.run().await });
                }
                InboundConfig::Socks(c) => {
                    info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting socks inbound");
                    let inbound = SocksInbound::new(c.clone(), tcp_tx.clone(), udp_tx.clone());
                    tasks.spawn(async move { inbound.run().await });
                }
                InboundConfig::Dns(c) => {
                    info!(tag=%c.tag, listen=%c.listen, port=%c.listen_port, "starting dns inbound");
                    let inbound = DnsInbound::new(c.clone(), dns_tx.clone());
                    tasks.spawn(async move { inbound.run().await });
                }
                InboundConfig::Tun(c) => {
                    info!(
                        tag = %c.tag,
                        interface = ?c.interface_name,
                        mtu = c.mtu,
                        auto_route = c.auto_route,
                        stack = %c.stack,
                        dns_hijack = config.route.hijack_dns,
                        "starting tun inbound"
                    );
                    let inbound =
                        TunInbound::new((*c).as_ref().clone(), tcp_tx.clone(), udp_tx.clone())
                            .with_dns_hijack(dns_tx.clone(), config.route.hijack_dns);
                    tasks.spawn(async move { inbound.run().await });
                }
            }
        }

        // ── 6. DNS 处理循环（仅 DNS 启用时启动）──────────────────────────────
        if dns_enabled {
            let resolver = dns_resolver.clone();
            tasks.spawn(async move {
                resolver.run(dns_rx).await;
                Ok(())
            });
        }

        // ── 连接追踪器（Dispatcher 和 ClashApi 共享）────────────────────────
        let conn_tracker = crate::app::clash_api::ConnectionTracker::new();

        // ── 应用层 idle 探活 sweeper（应用层双保险，补内核 TCP keepalive 的盲区）
        // 每 30s 扫描一次连接表，连续 5min 无流量变化的连接视为"静默死亡"，
        // 复用现有 cancel 链路主动终止。判定依据是流量计数器变化（而非 read 超时），
        // 因此带应用层心跳的 WebSocket / SSH 等合法长连接不会被误杀。
        // 详见 ConnectionTracker::spawn_idle_sweeper 的设计说明。
        {
            let sweeper = conn_tracker.spawn_idle_sweeper(
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(300),
            );
            tasks.spawn(async move {
                let _ = sweeper.await;
                Ok(())
            });
        }

        // ── 7. TCP Dispatcher ────────────────────────────────────────────────
        {
            let dispatcher = Dispatcher::new(
                router.clone(),
                outbound_mgr.clone(),
                dns_tx.clone(),
                dns_resolver.clone(),
                stats.clone(),
                conn_tracker.clone(),
            );
            tasks.spawn(async move {
                dispatcher.run_tcp(tcp_rx).await;
                Ok(())
            });
        }

        // ── 8. UDP Dispatcher ────────────────────────────────────────────────
        {
            let dispatcher = Dispatcher::new(
                router.clone(),
                outbound_mgr.clone(),
                dns_tx.clone(),
                dns_resolver.clone(),
                stats.clone(),
                conn_tracker.clone(),
            );
            tasks.spawn(async move {
                dispatcher.run_udp(udp_rx).await;
                Ok(())
            });
        }

        // ── 9. 规则集注册表（统一实例，供 Clash API 和热更新共享）──────────────
        // 始终创建：即使 Clash API 未启用，也需要供 start_watchers() 使用，
        // 让本地文件变更和远程定时刷新能即时更新元数据。
        let rs_registry =
            RuleSetRegistry::from_router_meta(config.route.clone(), router.ruleset_meta.clone());

        // ── 10. Clash API（可选）───────────────────────────────────────────────
        if let Some(clash_api_config) = config.experimental.clash_api.clone() {
            if clash_api_config.enabled {
                let route_cfg = Arc::new(config.route.clone());

                // ── UI 自动下载（external_ui 目录不存在或为空时）────────────
                if let Some(ref ui_dir) = clash_api_config.external_ui {
                    let ui_dir = ui_dir.clone();
                    let download_url = clash_api_config.external_ui_download_url.clone();
                    let needs_download = std::fs::read_dir(&ui_dir)
                        .map(|mut d| d.next().is_none())
                        .unwrap_or(true); // 目录不存在也触发下载
                    if needs_download {
                        let ui_dir2 = ui_dir.clone();
                        tasks.spawn(async move {
                            if let Err(e) = crate::app::clash_api::download_external_ui(
                                &ui_dir2,
                                download_url.as_deref(),
                            )
                            .await
                            {
                                tracing::warn!("external ui download failed: {e}");
                            }
                            Ok(())
                        });
                    }
                }

                let clash_api = ClashApi::new(
                    clash_api_config,
                    outbound_mgr.clone(),
                    stats.clone(),
                    route_cfg,
                    inbounds_iter.clone(),
                    config.log.level,
                    conn_tracker.clone(),
                    rs_registry.clone(),
                    Some(dns_resolver.clone()),
                    clash_mode.clone(),
                );
                tasks.spawn(async move { clash_api.run().await });
            }
        }

        // ── 11. 规则集热更新（本地文件 notify + 远程 update_interval 定时）─────
        // start_watchers 内部会：
        // - 为每个 type=local 的规则集启动 notify 文件监听（去抖动 200ms）
        // - 为每个 type=remote 且配置了 update_interval 的规则集启动周期定时器
        // 任一规则集变更时刷新 Registry 元数据（rule_count / updated_at），
        // Clash API 的 /rules 等接口能立即反映最新状态。
        for handle in rs_registry.start_watchers() {
            tasks.spawn(async move {
                let _ = handle.await;
                Ok(())
            });
        }

        Ok(Self { tasks, stats })
    }

    pub async fn wait(mut self) -> anyhow::Result<()> {
        while let Some(res) = self.tasks.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error!(err=%e, "task exited with error, shutting down");
                    self.tasks.abort_all();
                    return Err(e);
                }
                Err(e) => {
                    error!(err=%e, "task panicked, shutting down");
                    self.tasks.abort_all();
                    return Err(anyhow::anyhow!("task panicked: {}", e));
                }
            }
        }
        Ok(())
    }
}
