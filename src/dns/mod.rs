pub mod cache;
pub mod rcode;
pub mod resolver_helpers;
pub mod rule;
pub mod upstream;
pub mod wire;

pub use rcode::*;
pub use wire::*;

use std::{collections::HashMap, sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::ruleset::RuleSet;

use crate::{
    clash_mode::ClashMode,
    config::dns::{DnsConfig, DnsRuleConfig, ProxyDomainResolverConfig, ResolveStrategy},
    experimental::{CacheFile, CacheFileReader},
    inbound::dns::DnsQuery,
    outbound::Outbound,
};

use cache::{CacheResult, DnsCache, InflightResult};
use futures_util::stream::{FuturesUnordered, StreamExt};
use resolver_helpers::{extract_all_ips, lookup_ip_cache, store_ip_cache, toposort_servers};
use rule::{compose_transport_tag, CompiledDnsRule};
use upstream::DnsUpstream;
use wire::{
    build_query, extract_first_ip, extract_min_ttl_or_negative, is_cacheable_or_negative, patch_id,
};

// ── FakeIP 反向查找结果 ───────────────────────────────────────────────────────

/// 参照 sing-box route.go routeConnection 的三路分支：
/// - IP 不在任何 fakeip 段   → NotFakeIp（正常路由）
/// - IP 在段内且有 store 记录 → Found(domain)（恢复域名后路由）
/// - IP 在段内但 store 无记录 → Missing（应断连，建议开启 store_fakeip）
#[derive(Debug)]
pub enum FakeIpLookup {
    NotFakeIp,
    Found(String),
    Missing,
}

// ── DNS 解析器 ────────────────────────────────────────────────────────────────

pub struct DnsResolver {
    rules: Vec<CompiledDnsRule>,
    /// 原始 DNS 规则配置（未编译），用于 clash-api /dns/rules 展示。
    rule_configs: Vec<DnsRuleConfig>,
    /// 默认上游列表（对应 `dns.final`，单元素时走快速路径，多元素时并发 race）。
    default: Vec<Arc<DnsUpstream>>,
    cache: Option<Arc<DnsCache>>,
    /// 全部已注册的 DNS 上游，key 为 server tag，供 resolve_server 指定时使用
    upstreams: HashMap<String, Arc<DnsUpstream>>,
    /// 生效的解析策略（由 global.ipv6 + dns.strategy 合并决定）
    pub strategy: ResolveStrategy,
    /// `dns.proxy_domain_resolver` 配置，用于解析代理出站节点的服务器域名。
    /// 构造时已校验每个 server tag 都存在于 upstreams 中，且符合并发约束。
    /// 对齐 sing-box `route.default_domain_resolver`（DomainResolveOptions）：
    /// - `server`：DNS server tag（s），支持单 tag 或多 tag 并发
    /// - `strategy`：None 时沿用全局 `self.strategy`（对齐 sing-box AsIS）
    /// - `disable_cache`：是否跳过缓存
    proxy_domain_resolver: Option<ProxyDomainResolverConfig>,
    /// Clash API 当前模式的共享只读引用，供 DNS 规则的 `clash_mode` 条件匹配使用。
    clash_mode: Arc<ClashMode>,
}

impl DnsResolver {
    /// 构造一个"禁用"的 DNS 解析器：无 upstream、无规则、无缓存。
    ///
    /// 用于配置中未声明 `dns` 字段（或 `dns.servers` 为空）的场景。
    /// 此时：
    /// - `resolve_domain` / `resolve_domain_all` 返回 `"no upstream"` 错误
    ///   （dispatcher 会优雅降级：跳过 IP 重路由，仍按域名路由）。
    /// - `lookup_fakeip` 返回 `NotFakeIp`（无 fakeip store）。
    /// - `handle`（DNS 查询处理）返回错误，调用方收到 SERVFAIL。
    /// - `run` 循环不启动（由 app/mod.rs 跳过）。
    ///
    /// 占用内存极小（几个空 Vec/HashMap），不启动任何后台任务。
    pub fn disabled(clash_mode: Arc<ClashMode>) -> Self {
        DnsResolver {
            rules: Vec::new(),
            rule_configs: Vec::new(),
            default: Vec::new(),
            cache: None,
            upstreams: HashMap::new(),
            strategy: ResolveStrategy::PreferIpv4,
            proxy_domain_resolver: None,
            clash_mode,
        }
    }

    pub fn from_config(config: &DnsConfig) -> anyhow::Result<Self> {
        Self::from_config_full(
            config,
            &HashMap::new(),
            None,
            None,
            None,
            0,
            Arc::new(ClashMode::new("rule")),
        )
    }

    pub fn from_config_with_rulesets(
        config: &DnsConfig,
        rulesets: &HashMap<String, Arc<RuleSet>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full(
            config,
            rulesets,
            None,
            None,
            None,
            0,
            Arc::new(ClashMode::new("rule")),
        )
    }

    pub fn from_config_with_rulesets_and_outbounds(
        config: &DnsConfig,
        rulesets: &HashMap<String, Arc<RuleSet>>,
        outbounds: Option<&HashMap<String, Arc<dyn Outbound>>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full(
            config,
            rulesets,
            outbounds,
            None,
            None,
            0,
            Arc::new(ClashMode::new("rule")),
        )
    }

    /// 最完整构造：支持 CacheFile 注入（fakeip 持久化 + DNS 缓存持久化）。
    ///
    /// `clash_mode`：Clash API 当前模式的共享状态，用于 DNS 规则的 `clash_mode`
    /// 条件。生产环境（`app/mod.rs`）应传入与 `Router`/`ClashApi` 共享的同一个
    /// `Arc<ClashMode>` 实例；其余 wrapper 构造函数（测试/简化场景）各自创建
    /// 一个独立实例，互不影响。
    pub fn from_config_full(
        config: &DnsConfig,
        rulesets: &HashMap<String, Arc<RuleSet>>,
        outbounds: Option<&HashMap<String, Arc<dyn Outbound>>>,
        cache_writer: Option<Arc<CacheFile>>,
        cache_reader: Option<Arc<CacheFileReader>>,
        routing_mark: u32,
        clash_mode: Arc<ClashMode>,
    ) -> anyhow::Result<Self> {
        // 验证 optimistic 和 disable_cache 不能同时开
        if config.optimistic_timeout > 0 && config.disable_cache {
            anyhow::bail!("`optimistic_timeout` cannot be used with `disable_cache: true`");
        }

        // ── 拓扑排序 & 构建 upstreams ────────────────────────────────────────
        let order = toposort_servers(&config.servers)?;
        let mut upstreams: HashMap<String, Arc<DnsUpstream>> = HashMap::new();

        for idx in order {
            let srv = &config.servers[idx];

            let detour = match (&srv.detour, outbounds) {
                (Some(tag), Some(obs)) => match obs.get(tag) {
                    Some(ob) => {
                        tracing::info!(dns_server=%srv.tag, detour=%tag, "dns server detour resolved");
                        Some(ob.clone())
                    }
                    None => anyhow::bail!(
                        "dns server '{}' references unknown detour '{}'",
                        srv.tag,
                        tag
                    ),
                },
                (Some(tag), None) => {
                    tracing::warn!(dns_server=%srv.tag, detour=%tag,
                        "detour configured but no outbounds map; queries will be sent directly");
                    None
                }
                (None, _) => None,
            };

            let domain_resolver = match &srv.domain_resolver {
                Some(tag) => match upstreams.get(tag) {
                    Some(up) => {
                        tracing::info!(dns_server=%srv.tag, domain_resolver=%tag, "resolved");
                        Some(up.clone())
                    }
                    None => anyhow::bail!(
                        "dns server '{}' references unknown domain_resolver '{}'",
                        srv.tag,
                        tag
                    ),
                },
                None => None,
            };

            // fakeip upstream 才注入 cache_file/reader，其他忽略
            let (cf, cr) = if srv.protocol() == crate::config::dns::DnsProtocol::FakeIp {
                (cache_writer.clone(), cache_reader.clone())
            } else {
                (None, None)
            };

            upstreams.insert(
                srv.tag.clone(),
                Arc::new(
                    DnsUpstream::from_config_full_with_reader(
                        srv,
                        detour,
                        cf,
                        cr,
                        domain_resolver,
                    )?
                    .with_mark(routing_mark)
                    .with_strategy(config.strategy),
                ),
            );
        }

        // ── 编译规则 ──────────────────────────────────────────────────────────
        let rules = config
            .rules
            .iter()
            .map(|r| CompiledDnsRule::compile(r, &upstreams, rulesets))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let default = rule::resolve_server_ref(config.r#final.as_slice(), &upstreams, "dns.final")?;

        // ── FakeIP 单例与默认服务器校验（参照 sing-box dns/transport_manager.go）────
        // sing-box 在 transport_manager.Create 中强制：
        //   1. 全局最多一个 fakeip upstream（`multiple fakeip server are not supported`）
        //   2. default（即 dns.final）不能是 fakeip（`default server cannot be fakeip`）
        // reflex 的 lookup_fakeip/reset_fakeip/set_fakeip_strategy 都假设 fakeip
        // upstream 至多一个（含 default），多实例会导致反向查找命中错误的 store。
        {
            let fakeip_tags: Vec<&String> = upstreams
                .iter()
                .filter_map(|(tag, u)| {
                    matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }).then_some(tag)
                })
                .collect();
            if fakeip_tags.len() > 1 {
                anyhow::bail!(
                    "multiple fakeip server are not supported (found {}: {})",
                    fakeip_tags.len(),
                    fakeip_tags
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            // default 可能是多个上游（并发场景），逐一检查不能含 fakeip。
            // 注意：resolve_server_ref 已经保证并发场景下不会包含 fakeip，
            // 但单 tag 形式的 fakeip 仍可能成为 default，这里二次校验以输出
            // 与 sing-box 一致的错误消息。
            for d in &default {
                if matches!(d.kind, upstream::UpstreamKind::FakeIp { .. }) {
                    anyhow::bail!(
                        "default server (dns.final='{}') cannot be fakeip; \
                         set dns.final to a non-fakeip server and route fakeip via dns.rules",
                        config.r#final.join(",")
                    );
                }
            }
        }

        // `proxy_domain_resolver` 必须引用已存在的 server tag（s），并符合并发约束
        if let Some(cfg) = &config.proxy_domain_resolver {
            rule::resolve_server_ref(
                cfg.server.as_slice(),
                &upstreams,
                "dns.proxy_domain_resolver.server",
            )?;
        }

        // ── 构建缓存 ──────────────────────────────────────────────────────────
        let cache = if config.disable_cache {
            None
        } else {
            let ttl_cap = if config.cache_ttl_max > 0 {
                config.cache_ttl_max
            } else {
                3600
            };
            let optimistic_ttl = if config.optimistic_timeout > 0 {
                Some(Duration::from_secs(config.optimistic_timeout))
            } else {
                None
            };
            // 只有 store_dns=true 时才有持久化句柄
            let (pr, pw) = if cache_reader.as_ref().is_some_and(|r| r.store_dns) {
                (cache_reader, cache_writer)
            } else {
                (None, None)
            };

            Some(Arc::new(DnsCache::with_options(
                config.cache_capacity,
                ttl_cap,
                optimistic_ttl,
                pr,
                pw,
            )))
        };

        Ok(Self {
            rules,
            rule_configs: config.rules.clone(),
            default,
            cache,
            upstreams,
            strategy: config.strategy,
            proxy_domain_resolver: config.proxy_domain_resolver.clone(),
            clash_mode,
        })
    }

    /// 返回原始 DNS 规则配置列表（未编译），供 clash-api `/dns/rules` 展示。
    pub fn rule_configs(&self) -> &[DnsRuleConfig] {
        &self.rule_configs
    }

    /// 返回默认 DNS 上游的 server tag 列表（对应 `dns.final`），供 clash-api 展示。
    pub fn final_servers(&self) -> Vec<String> {
        self.default.iter().map(|u| u.tag.clone()).collect()
    }

    /// 查询 FakeIP 地址是否落在已知的 FakeIP 段内，若是则反向查找对应的域名。
    /// 参照 sing-box route.go routeConnection：
    ///   - IP 不在任何 fakeip 段 → `FakeIpLookup::NotFakeIp`
    ///   - IP 在段内且有记录    → `FakeIpLookup::Found(domain)`
    ///   - IP 在段内但无记录   → `FakeIpLookup::Missing`（应断连，建议开启 cache_file）
    pub fn lookup_fakeip(&self, addr: std::net::IpAddr) -> FakeIpLookup {
        for upstream in self.upstreams.values() {
            if let upstream::UpstreamKind::FakeIp { store } = &upstream.kind {
                if store.contains(addr) {
                    return match store.lookup(addr) {
                        Some(domain) => FakeIpLookup::Found(domain),
                        None => FakeIpLookup::Missing,
                    };
                }
            }
        }
        FakeIpLookup::NotFakeIp
    }

    /// 同步更新所有 fakeip upstream 的 strategy。
    /// 在 global.ipv6=false 时调用，强制覆盖为 Ipv4Only。
    pub fn set_fakeip_strategy(&self, s: crate::config::dns::ResolveStrategy) {
        // default 即 upstreams 中的一个（按 config.r#final 取出），迭代覆盖即可；
        // 且 from_config_full 已校验 default 不能是 fakeip，无需重复检查。
        for upstream in self.upstreams.values() {
            if let upstream::UpstreamKind::FakeIp { store } = &upstream.kind {
                store.set_strategy(s);
            }
        }
    }

    /// 重置所有 FakeIP 存储（参照 sing-box `cacheFile.FakeIPReset()`）。
    ///
    /// 遍历所有 fakeip upstream（含 default，default 即 upstreams 中的一个），
    /// 调用 `FakeIpStore::reset()` 清空内存映射 + 持久化表，
    /// 并把分配指针回退到 range 起点。
    /// 用于 Clash API `POST /cache/fakeip/flush`。
    pub fn reset_fakeip(&self) {
        let mut count = 0;
        for upstream in self.upstreams.values() {
            if let upstream::UpstreamKind::FakeIp { store } = &upstream.kind {
                store.reset();
                count += 1;
            }
        }
        if count == 0 {
            tracing::debug!("reset_fakeip: no fakeip upstream configured");
        }
    }

    pub async fn resolve_domain(&self, host: &str) -> anyhow::Result<std::net::IpAddr> {
        // 按域名匹配规则，选出正确的上游；跳过 fakeip；无匹配则用 default
        // inbound_tag 传空串：dispatcher 内部调用不属于任何入站
        let upstreams = self.select_resolve_upstreams(host);
        // 对齐 sing-box Lookup：路由路径解析域名也要走缓存，避免每次转发都打上游。
        // resolve_domain_with_strategy_multi 内部不做缓存（仅做并发 race），
        // 缓存由本方法显式处理：先查缓存（key = transport_tag + host + strategy），
        // 未命中则查询 upstream 并写回缓存。
        let transport_tag = compose_transport_tag(&upstreams);
        if let Some(ref cache) = self.cache {
            if let Some(ip) = lookup_ip_cache(cache, &transport_tag, host, self.strategy) {
                return Ok(ip);
            }
        }
        let ip = self
            .resolve_domain_with_strategy_multi(host, self.strategy, &upstreams)
            .await?;
        if let Some(ref cache) = self.cache {
            if !upstreams.is_empty() {
                store_ip_cache(
                    cache,
                    &transport_tag,
                    host,
                    self.strategy,
                    ip,
                    &upstreams[0],
                );
            }
        }
        Ok(ip)
    }

    /// 解析域名的**全部**候选地址（A + AAAA），按 `strategy` 排序，供 Happy
    /// Eyeballs 多候选拨号使用（对齐 sing-box `network_strategy` 的候选地址
    /// 来源）。upstream 选择逻辑和 `resolve_domain` 完全一致，区别只是不止取
    /// 第一个 IP。
    pub async fn resolve_domain_all(&self, host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        let upstreams = self.select_resolve_upstreams(host);
        self.resolve_domain_all_with_cache(host, &upstreams, self.strategy)
            .await
    }

    /// 选择用于域名解析的上游列表（跳过含 fakeip 的规则，无匹配回退 default 中非 fakeip 部分）。
    /// 对齐 mihomo 并发 DNS：返回的列表可能含多个上游，调用方并发查询。
    fn select_resolve_upstreams(&self, host: &str) -> Vec<Arc<DnsUpstream>> {
        // 找到第一个匹配且不含 fakeip 上游的规则
        // （resolve_server_ref 已保证并发场景下不会含 fakeip，所以这里只需检查
        // 单元素 fakeip 规则——用 .any() 统一处理两种情况）
        // 一次性归一化 host，所有规则复用同一结果，避免重复 trim/lower。
        let host_norm = crate::router::normalize_domain(host);
        let current_mode = self.clash_mode.get();
        if let Some(r) = self.rules.iter().find(|r| {
            r.matches_normalized("", &host_norm, 1 /* A */, &current_mode)
                && r.upstreams
                    .iter()
                    .all(|u| !matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
        }) {
            return r.upstreams.clone();
        }
        // 无匹配规则：使用 default，但过滤掉 fakeip 上游
        let filtered: Vec<Arc<DnsUpstream>> = self
            .default
            .iter()
            .filter(|u| !matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            return filtered;
        }
        // default 全是 fakeip：回退到 upstreams map 中第一个非 fakeip upstream
        if let Some(u) = self
            .upstreams
            .values()
            .find(|u| !matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
        {
            return vec![u.clone()];
        }
        // 整个配置只有 fakeip upstream（极端配置）：返回 default，让查询失败时报错
        self.default.clone()
    }

    /// `resolve_domain_all` 的缓存版：先查缓存，未命中查询 upstream 并写缓存。
    /// 对齐 sing-box Lookup 的缓存行为。多上游时并发查询所有上游，首个成功响应即返回
    /// （取其全部候选地址）。缓存键使用组合 transport_tag。
    async fn resolve_domain_all_with_cache(
        &self,
        host: &str,
        upstreams: &[Arc<DnsUpstream>],
        strategy: ResolveStrategy,
    ) -> anyhow::Result<Vec<std::net::IpAddr>> {
        use std::net::IpAddr;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        if upstreams.is_empty() {
            anyhow::bail!("resolve_domain_all_with_cache: no upstream");
        }

        let transport_tag = compose_transport_tag(upstreams);

        // 查缓存：复用 lookup_ip_cache（返回单个 IP），命中则返回单元素 vec。
        // 这是简化处理——缓存只存首个 IP，多 IP 场景仍需查询上游。
        // 对于 Happy Eyeballs 场景，首个 IP 命中已足够启动连接，完整列表
        // 可在缓存 miss 时从上游获取。
        if let Some(ref cache) = self.cache {
            if let Some(ip) = lookup_ip_cache(cache, &transport_tag, host, strategy) {
                return Ok(vec![ip]);
            }
        }

        // 未命中缓存：查询 upstream（多上游时并发 race，取首个成功的全部候选地址）
        let ips = self
            .resolve_domain_all_with_strategy_multi(host, strategy, upstreams)
            .await?;

        // 写入缓存（仅存首个 IP，与 resolve_domain_with_upstreams 的缓存格式一致）
        if let Some(ref cache) = self.cache {
            if let Some(first) = ips.first() {
                store_ip_cache(cache, &transport_tag, host, strategy, *first, &upstreams[0]);
            }
        }

        Ok(ips)
    }

    /// 多上游版本的 `resolve_domain_all_with_strategy`：单上游时走快速路径，
    /// 多上游时并发查询所有上游，首个成功响应即返回其全部候选地址。
    async fn resolve_domain_all_with_strategy_multi(
        &self,
        host: &str,
        strategy: ResolveStrategy,
        upstreams: &[Arc<DnsUpstream>],
    ) -> anyhow::Result<Vec<std::net::IpAddr>> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(vec![ip]);
        }
        if upstreams.is_empty() {
            anyhow::bail!("resolve_domain_all_with_strategy_multi: no upstream");
        }
        if upstreams.len() == 1 {
            return self
                .resolve_domain_all_with_strategy(host, strategy, &upstreams[0])
                .await;
        }
        let mut futures: FuturesUnordered<_> = upstreams
            .iter()
            .map(|up| self.resolve_domain_all_with_strategy(host, strategy, up))
            .collect();
        let mut last_err: Option<anyhow::Error> = None;
        while let Some(res) = futures.next().await {
            match res {
                Ok(ips) => return Ok(ips),
                Err(e) => {
                    debug!(err=%e, host, "dns multi-resolve-all: one upstream failed, waiting for others");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("resolve_domain_all_with_strategy_multi: all upstreams failed")
        }))
    }

    /// 内部：用指定上游和指定策略解析域名的全部候选地址，按策略排序。
    /// 与 `resolve_domain_with_strategy` 结构保持一致，便于对照维护。
    async fn resolve_domain_all_with_strategy(
        &self,
        host: &str,
        strategy: ResolveStrategy,
        upstream: &Arc<DnsUpstream>,
    ) -> anyhow::Result<Vec<std::net::IpAddr>> {
        use std::net::IpAddr;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        match strategy {
            ResolveStrategy::Ipv4Only => {
                let query_a = build_query(host, 1u16);
                let resp = upstream.query(query_a.into()).await;
                let v4 = resp
                    .ok()
                    .as_deref()
                    .map(|r| extract_all_ips(r, 1))
                    .unwrap_or_default();
                if v4.is_empty() {
                    anyhow::bail!("dns resolve failed for '{host}': no A answer");
                }
                Ok(v4)
            }
            ResolveStrategy::Ipv6Only => {
                let query_aaaa = build_query(host, 28u16);
                let resp = upstream.query(query_aaaa.into()).await;
                let v6 = resp
                    .ok()
                    .as_deref()
                    .map(|r| extract_all_ips(r, 28))
                    .unwrap_or_default();
                if v6.is_empty() {
                    anyhow::bail!("dns resolve failed for '{host}': no AAAA answer");
                }
                Ok(v6)
            }
            ResolveStrategy::PreferIpv4 | ResolveStrategy::PreferIpv6 => {
                let query_a = build_query(host, 1u16);
                let query_aaaa = build_query(host, 28u16);
                let (resp_a, resp_aaaa) = tokio::join!(
                    upstream.query(query_a.into()),
                    upstream.query(query_aaaa.into()),
                );
                let v4 = resp_a
                    .ok()
                    .as_deref()
                    .map(|r| extract_all_ips(r, 1))
                    .unwrap_or_default();
                let v6 = resp_aaaa
                    .ok()
                    .as_deref()
                    .map(|r| extract_all_ips(r, 28))
                    .unwrap_or_default();
                let mut out = Vec::with_capacity(v4.len() + v6.len());
                if matches!(strategy, ResolveStrategy::PreferIpv6) {
                    out.extend(v6);
                    out.extend(v4);
                } else {
                    out.extend(v4);
                    out.extend(v6);
                }
                if out.is_empty() {
                    anyhow::bail!("dns resolve failed for '{host}': no answer");
                }
                Ok(out)
            }
        }
    }
    /// 若配置了 `dns.proxy_domain_resolver`，走该 server tag（s）解析代理节点域名；
    /// 否则回退到 `resolve_domain`（按规则 + dns.final 默认上游解析）。
    ///
    /// 对齐 sing-box `default_domain_resolver` 行为：
    /// - 若 `proxy_domain_resolver.strategy` 为 None，沿用全局 `dns.strategy`
    ///   （对齐 sing-box `DomainStrategyAsIS` 使用 transport 默认策略）
    /// - 若 `proxy_domain_resolver.disable_cache = false`（默认），启用缓存
    /// - `server` 支持单 tag 或多 tag（mihomo 风格并发）
    pub async fn resolve_proxy_domain(&self, host: &str) -> anyhow::Result<std::net::IpAddr> {
        match &self.proxy_domain_resolver {
            Some(cfg) => {
                self.resolve_domain_with_options(
                    host,
                    cfg.server.as_slice(),
                    cfg.strategy.unwrap_or(self.strategy),
                    cfg.disable_cache,
                )
                .await
            }
            None => self.resolve_domain(host).await,
        }
    }

    /// 使用指定 server tag（s）的 DNS 上游解析域名（沿用全局 `strategy`，启用缓存）。
    /// 供 dispatcher 的 `resolve` 路由动作使用。
    /// 多 tag 时并发查询所有上游，首个成功响应即返回（对齐 mihomo 并发 DNS）。
    /// 若所有 tag 都不存在则回退到默认上游并记录 warn 日志。
    pub async fn resolve_domain_via(
        &self,
        host: &str,
        server_tags: &[String],
    ) -> anyhow::Result<std::net::IpAddr> {
        self.resolve_domain_with_options(host, server_tags, self.strategy, false)
            .await
    }

    /// 内部统一入口：用指定 server tag（s）、strategy 和 cache 开关解析域名。
    ///
    /// 对齐 sing-box `resolveDialer` + `Router.Lookup` + mihomo 并发 DNS：
    /// - 查找指定 server tag（s）的 upstream（全部不存在则回退默认上游 + warn）
    /// - 应用指定的 strategy（覆盖全局）
    /// - 多 tag 时并发查询所有上游，首个成功响应即返回
    /// - 若启用缓存且 cache 存在，先查缓存；未命中则查询并写入缓存
    ///   缓存 key 使用组合 transport_tag（单 tag 直接，多 tag 用 "local,remote" 形式）
    async fn resolve_domain_with_options(
        &self,
        host: &str,
        server_tags: &[String],
        strategy: ResolveStrategy,
        disable_cache: bool,
    ) -> anyhow::Result<std::net::IpAddr> {
        // 解析 tag 列表为 upstream 列表，过滤掉不存在的 tag
        let upstreams: Vec<Arc<DnsUpstream>> = server_tags
            .iter()
            .filter_map(|tag| self.upstreams.get(tag).cloned())
            .collect();
        let upstreams = if upstreams.is_empty() {
            tracing::warn!(
                ?server_tags,
                host,
                "resolve_domain_with_options: no valid server tags, falling back to default"
            );
            self.default.clone()
        } else {
            upstreams
        };

        // 组合缓存键（与 handle() 一致）
        let transport_tag = compose_transport_tag(&upstreams);

        // 缓存查询（对齐 sing-box client.Lookup 的缓存逻辑）
        // 缓存 key 使用 transport_tag + host + strategy 派生的 qtype，
        // 避免不同 strategy / 不同上游组合的查询互相污染。
        if !disable_cache {
            if let Some(ref cache) = self.cache {
                if let Some(ip) = lookup_ip_cache(cache, &transport_tag, host, strategy) {
                    return Ok(ip);
                }
            }
        }

        // 未命中缓存：查询 upstream（多上游时并发 race）
        let ip = self
            .resolve_domain_with_strategy_multi(host, strategy, &upstreams)
            .await?;

        // 写入缓存
        if !disable_cache {
            if let Some(ref cache) = self.cache {
                store_ip_cache(cache, &transport_tag, host, strategy, ip, &upstreams[0]);
            }
        }

        Ok(ip)
    }

    /// 多上游版本的 `resolve_domain_with_strategy`：单上游时直接走快速路径，
    /// 多上游时并发查询所有上游，首个成功响应即返回（对齐 mihomo 并发 DNS）。
    /// 全部失败时返回最后一个错误。
    async fn resolve_domain_with_strategy_multi(
        &self,
        host: &str,
        strategy: ResolveStrategy,
        upstreams: &[Arc<DnsUpstream>],
    ) -> anyhow::Result<std::net::IpAddr> {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(ip);
        }
        if upstreams.is_empty() {
            anyhow::bail!("resolve_domain_with_strategy_multi: no upstream");
        }
        // 快速路径：单上游
        if upstreams.len() == 1 {
            return self
                .resolve_domain_with_strategy(host, strategy, &upstreams[0])
                .await;
        }
        // 并发路径：所有上游同时查，首个 Ok 返回，其余 drop 取消
        let mut futures: FuturesUnordered<_> = upstreams
            .iter()
            .map(|up| self.resolve_domain_with_strategy(host, strategy, up))
            .collect();
        let mut last_err: Option<anyhow::Error> = None;
        while let Some(res) = futures.next().await {
            match res {
                Ok(ip) => {
                    return Ok(ip);
                }
                Err(e) => {
                    debug!(err=%e, host, "dns multi-resolve: one upstream failed, waiting for others");
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            anyhow::anyhow!("resolve_domain_with_strategy_multi: all upstreams failed")
        }))
    }

    /// 内部：用指定上游和指定策略解析域名。
    async fn resolve_domain_with_strategy(
        &self,
        host: &str,
        strategy: ResolveStrategy,
        upstream: &Arc<DnsUpstream>,
    ) -> anyhow::Result<std::net::IpAddr> {
        use std::net::IpAddr;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }

        match strategy {
            ResolveStrategy::Ipv4Only => {
                // 只查 A 记录
                let query_a = build_query(host, 1u16);
                let resp = upstream.query(query_a.into()).await;
                resp.ok()
                    .as_deref()
                    .and_then(|r| extract_first_ip(r, 1))
                    .ok_or_else(|| anyhow::anyhow!("dns resolve failed for '{host}': no A answer"))
            }
            ResolveStrategy::Ipv6Only => {
                // 只查 AAAA 记录
                let query_aaaa = build_query(host, 28u16);
                let resp = upstream.query(query_aaaa.into()).await;
                resp.ok()
                    .as_deref()
                    .and_then(|r| extract_first_ip(r, 28))
                    .ok_or_else(|| {
                        anyhow::anyhow!("dns resolve failed for '{host}': no AAAA answer")
                    })
            }
            ResolveStrategy::PreferIpv4 | ResolveStrategy::PreferIpv6 => {
                // 并发查 A + AAAA，按优先级选择（tokio::join! 避免串行等待两次 RTT）
                let query_a = build_query(host, 1u16);
                let query_aaaa = build_query(host, 28u16);
                let (resp_a, resp_aaaa) = tokio::join!(
                    upstream.query(query_a.into()),
                    upstream.query(query_aaaa.into()),
                );
                let ipv4 = resp_a.ok().as_deref().and_then(|r| extract_first_ip(r, 1));
                let ipv6 = resp_aaaa
                    .ok()
                    .as_deref()
                    .and_then(|r| extract_first_ip(r, 28));
                match (strategy, ipv4, ipv6) {
                    (ResolveStrategy::PreferIpv6, _, Some(v6)) => Ok(v6),
                    (ResolveStrategy::PreferIpv6, Some(v4), None) => Ok(v4),
                    (_, Some(v4), _) => Ok(v4),
                    (_, None, Some(v6)) => Ok(v6),
                    _ => anyhow::bail!("dns resolve failed for '{host}': no answer"),
                }
            }
        }
    }

    /// 启动 DNS 处理循环
    /// 返回内存诊断数据，供定期日志使用：
    /// - `cache_len`    : DNS LRU 缓存条目数
    /// - `inflight_len` : inflight 去重表条目数（正常应趋近于 0）
    /// - `fakeip_sizes` : FakeIpStore 三张表的条目数 (addr_to_domain, domain_to_v4, domain_to_v6)
    pub fn diag(&self) -> (usize, usize, Option<(usize, usize, usize)>) {
        let cache_len = self.cache.as_ref().map_or(0, |c| c.len());
        let inflight_len = self.cache.as_ref().map_or(0, |c| c.inflight_len());
        let fakeip_sizes = self.upstreams.values().find_map(|u| {
            if let crate::dns::upstream::UpstreamKind::FakeIp { store, .. } = &u.kind {
                Some(store.diag_sizes())
            } else {
                None
            }
        });
        (cache_len, inflight_len, fakeip_sizes)
    }

    /// 清空内存 DNS 缓存（对应 Clash API `POST /cache/dns/flush`）。
    pub fn clear_cache(&self) {
        if let Some(ref cache) = self.cache {
            cache.clear();
            tracing::info!("dns cache flushed");
        }
    }

    /// 对指定域名和类型进行一次 DNS 查询，返回原始 DNS 报文。
    /// 用于 Clash API `GET /dns/query?name=...&type=A`。
    ///
    /// 用 default upstreams 直接查询（不走路由规则，不影响 fake-ip 分配）。
    /// 多 default 时并发 race，首个成功响应即返回（对齐 mihomo 并发 DNS）。
    pub async fn resolve_raw(&self, name: &str, qtype: u16) -> anyhow::Result<Vec<u8>> {
        let query = build_query_bytes(name, qtype);
        let msg = bytes::Bytes::from(query);
        let resp = race_upstreams(&self.default, &msg)
            .await
            .map_err(|e| anyhow::anyhow!("dns query failed: {e}"))?;
        Ok(resp.to_vec())
    }

    pub async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<DnsQuery>) {
        while let Some(query) = rx.recv().await {
            let resolver = self.clone();
            tokio::spawn(async move {
                let source = query.source;
                let resp = match resolver
                    .handle(query.message.clone(), &query.inbound_tag)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        warn!(err=%e, from=%query.from, source=?source, "dns resolve error");
                        make_servfail(&query.message)
                    }
                };
                let _ = query.reply_tx.send(resp);
            });
        }
    }

    /// 处理一条 DNS 查询报文，走完整规则管线（含 fakeip、缓存、并发去重）。
    ///
    /// 这是 DNS 解析器的主入口，inbound listener、TUN 劫持、Clash API `/dns/query`
    /// 都通过此方法处理查询。与 sing-box `router.Exchange` 对齐——所有调用方走同一管线。
    pub async fn handle(&self, msg: Bytes, inbound_tag: &str) -> anyhow::Result<Bytes> {
        let qname = extract_qname(&msg).unwrap_or_default();
        let qtype = extract_qtype(&msg).unwrap_or(1);
        debug!(qname=%qname, qtype=qtype, inbound=%inbound_tag, "dns query");

        // ── 应用 strategy 拒绝规则（对齐 sing-box client.go:117） ─────────────
        // strategy=Ipv6Only + A 查询     → 返回空 NOERROR（拒绝 A）
        // strategy=Ipv4Only + AAAA 查询  → 返回空 NOERROR（拒绝 AAAA）
        //
        // 这避免将「按策略不该返回的记录类型」的查询转发到上游，
        // 既减少上游负载，又防止应用拿到与 strategy 矛盾的地址。
        if (qtype == 1 && matches!(self.strategy, ResolveStrategy::Ipv6Only))
            || (qtype == 28 && matches!(self.strategy, ResolveStrategy::Ipv4Only))
        {
            debug!(
                qname=%qname,
                qtype=qtype,
                strategy=?self.strategy,
                "strategy rejected: returning empty NOERROR"
            );
            return Ok(make_noerror_empty(&msg));
        }

        // ── 规则匹配，选择上游 ────────────────────────────────────────────────
        // 对齐 mihomo 并发 DNS：规则或 default 可指定多个 server tag，
        // 此时同时向所有上游发起查询，首个成功响应即返回。
        let current_mode = self.clash_mode.get();
        // 一次性归一化 qname（trim 末尾 '.' + ASCII 小写），所有规则复用，
        // 避免每条规则 / 每个 ruleset 在 RuleSet::match_domain 内重复归一化。
        let qname_norm = crate::router::normalize_domain(&qname);
        let (upstreams, disable_cache) = self
            .rules
            .iter()
            .find(|r| r.matches_normalized(inbound_tag, &qname_norm, qtype, &current_mode))
            .map(|r| (r.upstreams.clone(), r.disable_cache))
            .unwrap_or_else(|| (self.default.clone(), false));

        // 组合缓存键：单上游时为该 tag，多上游时为 "local,remote" 形式。
        // 同一组上游始终映射到同一缓存键，避免不同组合的缓存互相污染。
        let transport_tag = compose_transport_tag(&upstreams);

        // ── 查缓存 ────────────────────────────────────────────────────────────
        if let (Some(cache), false) = (&self.cache, disable_cache) {
            match cache.get(&transport_tag, &qname, qtype) {
                CacheResult::Hit(cached) => {
                    debug!(qname=%qname, transport=%transport_tag, "dns cache hit");
                    return Ok(patch_id(cached, &msg));
                }
                CacheResult::Stale(cached) => {
                    debug!(qname=%qname, transport=%transport_tag, "dns cache stale, refreshing in background");
                    // 后台异步刷新——走 inflight 去重，避免多个并发 stale 触发多个上游请求。
                    // 对齐 sing-box：stale 返回后只刷新一次，并发调用复用同一个 leader。
                    let cache2 = cache.clone();
                    let upstreams2 = upstreams.clone();
                    let msg2 = msg.clone();
                    let qname2 = qname.clone();
                    let transport_tag2 = transport_tag.clone();
                    tokio::spawn(async move {
                        // 先尝试成为 inflight leader：若已有 leader 在刷新则直接退出
                        match cache2.try_lead_inflight(&transport_tag2, &qname2, qtype) {
                            InflightResult::Waiter(_) => {
                                // 已有 leader 在刷新，本后台任务无需再查
                                debug!(qname=%qname2, "optimistic refresh: inflight leader exists, skip");
                            }
                            InflightResult::Leader => {
                                match race_upstreams(&upstreams2, &msg2).await {
                                    Ok(resp) => {
                                        if is_cacheable_or_negative(&resp) {
                                            let ttl =
                                                extract_min_ttl_or_negative(&resp).unwrap_or(60);
                                            cache2.set(
                                                &transport_tag2,
                                                &qname2,
                                                qtype,
                                                resp.clone(),
                                                ttl,
                                            );
                                        }
                                        cache2.complete_inflight(
                                            &transport_tag2,
                                            &qname2,
                                            qtype,
                                            Some(&resp),
                                        );
                                    }
                                    Err(e) => {
                                        debug!(err=%e, qname=%qname2, "optimistic refresh failed");
                                        cache2.complete_inflight(
                                            &transport_tag2,
                                            &qname2,
                                            qtype,
                                            None,
                                        );
                                    }
                                }
                            }
                        }
                    });
                    return Ok(patch_id(cached, &msg));
                }
                CacheResult::Miss => {}
            }

            // ── 并发请求去重（参照 sing-box client.go cacheLock）───────────────
            // 同一 (transport, qname, qtype) 若已有 leader 在查询，本请求作为 waiter 等待广播结果。
            //
            // 对齐 sing-box client.go:142-176 的 cond channel 模型：
            // - waiter 等待 cond 关闭（leader 完成）
            // - 唤醒后 waiter 独立 loadResponse 查缓存
            //   * 命中（leader 成功并写入缓存）→ 返回缓存
            //   * 未命中（leader 失败）→ fall-through 到下方 race_upstreams 路径，
            //     即 waiter 自行查询上游
            //
            // 这避免了「leader 瞬时失败导致 N 个 waiter 全部报错」的问题：
            // waiter 有自己的 ctx 超时，若上游持续故障，waiter 会因 timeout 失败，
            // 不会无限放大；若上游瞬时抖动恢复，waiter 可拿到结果。
            let waiter_cached: Option<Bytes> = match cache.try_lead_inflight(
                &transport_tag,
                &qname,
                qtype,
            ) {
                InflightResult::Waiter(mut rx) => {
                    debug!(qname=%qname, transport=%transport_tag, "dns inflight dedup: waiting for leader");
                    match rx.recv().await {
                        Ok(cached) => Some(cached),
                        Err(_) => {
                            // leader 查询失败：缓存未写入。对齐 sing-box：fall-through
                            // 到下方 race_upstreams 路径，由 waiter 自行查询上游。
                            debug!(qname=%qname, "dns inflight leader failed, waiter falls through to upstream");
                            None
                        }
                    }
                }
                InflightResult::Leader => {
                    // 本请求作为 leader，查询上游，然后广播结果
                    let resp = race_upstreams(&upstreams, &msg).await;
                    match resp {
                        Ok(resp) => {
                            if is_cacheable_or_negative(&resp) {
                                let ttl = extract_min_ttl_or_negative(&resp).unwrap_or(60);
                                cache.set(&transport_tag, &qname, qtype, resp.clone(), ttl);
                            }
                            cache.complete_inflight(&transport_tag, &qname, qtype, Some(&resp));
                            return Ok(resp);
                        }
                        Err(e) => {
                            cache.complete_inflight(&transport_tag, &qname, qtype, None);
                            return Err(e);
                        }
                    }
                }
            };
            if let Some(cached) = waiter_cached {
                return Ok(patch_id(cached, &msg));
            }
            // waiter fall-through：继续走下方 race_upstreams 路径
        }

        // ── 无缓存路径：直接查询上游（多上游时并发 race）──────────────────────
        let resp = race_upstreams(&upstreams, &msg).await?;
        Ok(resp)
    }
}

// ── 并发查询辅助 ──────────────────────────────────────────────────────────────
//
// 对齐 mihomo 的并发 DNS 解析：当一组上游被配置为并发查询时，同时向所有上游
// 发起相同查询，首个返回 Ok 的上游结果即被采用，其余查询在 drop 时被取消。
// 全部失败时返回最后一个错误（保留 anyhow::Error 链）。
//
// 单上游时走快速路径，直接调用 `upstream.query`，避免 FuturesUnordered 开销。

async fn race_upstreams(upstreams: &[Arc<DnsUpstream>], msg: &Bytes) -> anyhow::Result<Bytes> {
    if upstreams.is_empty() {
        anyhow::bail!("race_upstreams: no upstream configured");
    }
    // 快速路径：单上游直接查询
    if upstreams.len() == 1 {
        return upstreams[0].query(msg.clone()).await;
    }
    // 并发路径：FuturesUnordered + 首个 Ok 返回，其余 drop 取消
    let mut futures: FuturesUnordered<_> =
        upstreams.iter().map(|up| up.query(msg.clone())).collect();
    let mut last_err: Option<anyhow::Error> = None;
    while let Some(res) = futures.next().await {
        match res {
            Ok(resp) => {
                // 首个成功响应：drop FuturesUnordered 取消其余查询
                if let Some(e) = last_err.as_ref() {
                    debug!(err=%e, "dns race: an upstream failed before winner returned");
                }
                return Ok(resp);
            }
            Err(e) => {
                debug!(err=%e, "dns race: one upstream failed, waiting for others");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("race_upstreams: all upstreams failed")))
}

/// 重写 DNS 响应中所有 RR 的 TTL 字段为指定值。
///
/// 用于缓存命中时根据剩余时间动态递减 TTL，对齐 sing-box client.go loadResponse
/// 的行为：返回给客户端的 TTL 应反映真实剩余秒数，而非写入时的原始值。
///
/// 遍历 Answer / Authority / Additional 三个区段，逐条把 RR 的 TTL 字段
/// （4 字节，大端）改写为 `new_ttl`。NAME 中的压缩指针会被正确跳过。
/// 原始 `resp` 不可变，返回一个新的 `Bytes`。
pub(crate) fn rewrite_response_ttls(resp: &[u8], new_ttl: u32) -> Bytes {
    if resp.len() < 12 {
        return Bytes::copy_from_slice(resp);
    }
    let mut buf = resp.to_vec();
    let ttl_bytes = new_ttl.to_be_bytes();

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    // 跳过 Question section
    let mut pos = 12usize;
    for _ in 0..qdcount {
        // 跳过 QNAME
        loop {
            if pos >= buf.len() {
                return Bytes::from(buf);
            }
            let l = buf[pos] as usize;
            if l == 0 {
                pos += 1;
                break;
            }
            if l & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + l;
        }
        pos += 4; // QTYPE + QCLASS
    }

    // 依次遍历 Answer / Authority / Additional
    let total_rr = ancount + nscount + arcount;
    for _ in 0..total_rr {
        // 跳过 NAME（含压缩指针）
        loop {
            if pos >= buf.len() {
                return Bytes::from(buf);
            }
            let l = buf[pos] as usize;
            if l == 0 {
                pos += 1;
                break;
            }
            if l & 0xC0 == 0xC0 {
                pos += 2;
                break;
            }
            pos += 1 + l;
        }
        // RR fixed fields: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes
        if pos + 10 > buf.len() {
            return Bytes::from(buf);
        }
        // 重写 TTL
        buf[pos + 4..pos + 8].copy_from_slice(&ttl_bytes);
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }

    Bytes::from(buf)
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use resolver_helpers::build_minimal_dns_response;
    use wire::{extract_min_ttl, is_cacheable};

    fn make_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut msg = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0x00);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]);
        msg
    }

    /// 构造一个最小可用的 DNS 响应报文：1 条问题 + 任意条答案记录
    /// （NAME 用指针压缩指向 offset 12 处的问题段，和真实 DNS 报文一致）。
    fn make_response_with_records(
        qname: &str,
        qtype_for_question: u16,
        records: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0x00, 0x01]); // ID
        msg.extend_from_slice(&[0x81, 0x80]); // flags: response, RD+RA
        msg.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        msg.extend_from_slice(&(records.len() as u16).to_be_bytes()); // ANCOUNT
        msg.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        msg.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

        for label in qname.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0x00);
        msg.extend_from_slice(&qtype_for_question.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

        for (rtype, rdata) in records {
            msg.extend_from_slice(&[0xC0, 0x0C]); // NAME：指针压缩，指向 offset 12
            msg.extend_from_slice(&rtype.to_be_bytes());
            msg.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
            msg.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // TTL=3600
            msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            msg.extend_from_slice(rdata);
        }
        msg
    }

    #[test]
    fn extract_all_ips_collects_multiple_a_records() {
        let resp = make_response_with_records(
            "example.com",
            1,
            &[(1, vec![1, 2, 3, 4]), (1, vec![5, 6, 7, 8])],
        );
        let ips = extract_all_ips(&resp, 1);
        assert_eq!(
            ips,
            vec![
                "1.2.3.4".parse::<std::net::IpAddr>().unwrap(),
                "5.6.7.8".parse::<std::net::IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn extract_all_ips_empty_when_qtype_not_present() {
        let resp = make_response_with_records("example.com", 1, &[(1, vec![1, 2, 3, 4])]);
        // 响应里只有 A 记录，找 AAAA 应该返回空，而不是 panic 或返回错误类型的值
        assert!(extract_all_ips(&resp, 28).is_empty());
    }

    #[test]
    fn extract_all_ips_filters_by_qtype_in_mixed_response() {
        let v6_bytes = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)
            .octets()
            .to_vec();
        let resp =
            make_response_with_records("example.com", 1, &[(1, vec![9, 9, 9, 9]), (28, v6_bytes)]);
        assert_eq!(
            extract_all_ips(&resp, 1),
            vec!["9.9.9.9".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(
            extract_all_ips(&resp, 28),
            vec!["2001:db8::1".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn extract_qname_basic() {
        assert_eq!(
            extract_qname(&make_query("www.google.com", 1)),
            Some("www.google.com".into())
        );
    }

    #[test]
    fn extract_qtype_a() {
        assert_eq!(extract_qtype(&make_query("x.com", 1)), Some(1));
    }

    #[test]
    fn extract_qtype_aaaa() {
        assert_eq!(extract_qtype(&make_query("x.com", 28)), Some(28));
    }

    #[test]
    fn patch_id_works() {
        let query = make_query("x.com", 1);
        let mut resp = query.clone();
        resp[0] = 0xFF;
        resp[1] = 0xFF;
        let patched = patch_id(Bytes::from(resp), &query);
        assert_eq!(patched[0], query[0]);
        assert_eq!(patched[1], query[1]);
    }

    #[test]
    fn rcode_values() {
        let q = &make_query("a.com", 1);
        assert_eq!(make_refused(q)[3] & 0x0F, 5);
        assert_eq!(make_noerror_empty(q)[3] & 0x0F, 0);
        assert_eq!(make_nxdomain(q)[3] & 0x0F, 3);
    }

    #[test]
    fn is_cacheable_false_no_answer() {
        assert!(!is_cacheable(&make_query("a.com", 1)));
    }

    #[test]
    fn negative_ttl_nxdomain_without_soa_not_cached() {
        // NXDOMAIN 无 SOA → 不缓存
        let mut resp = make_query("nx.com", 1);
        resp[3] = 0x83; // QR=1 RCODE=NXDOMAIN
        assert!(!is_cacheable_or_negative(&resp));
    }

    // ── proxy_domain_resolver 缓存辅助函数测试 ────────────────────────────────
    //
    // 验证 build_minimal_dns_response 构造的报文能被 extract_first_ip 正确解析，
    // 以及 store_ip_cache / lookup_ip_cache 的 round-trip 行为对齐 sing-box
    // client.Lookup 的缓存逻辑。

    #[test]
    fn build_minimal_dns_response_v4_parseable() {
        // 构造的 A 记录响应必须能被 extract_first_ip 解析出正确的 IPv4
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resp = build_minimal_dns_response("example.com", 1, ip);
        let parsed = extract_first_ip(&resp, 1).expect("should parse v4");
        assert_eq!(parsed, ip);
    }

    #[test]
    fn build_minimal_dns_response_v6_parseable() {
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        let resp = build_minimal_dns_response("example.com", 28, ip);
        let parsed = extract_first_ip(&resp, 28).expect("should parse v6");
        assert_eq!(parsed, ip);
    }

    #[test]
    fn build_minimal_dns_response_wrong_qtype_returns_none() {
        // A 响应里查 AAAA 应返回 None，反之亦然（qtype 不匹配）
        let v4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let resp = build_minimal_dns_response("example.com", 1, v4);
        assert!(extract_first_ip(&resp, 28).is_none());
    }

    #[test]
    fn store_and_lookup_ip_cache_ipv4_only() {
        // Ipv4Only 策略：写入 A 记录缓存，lookup 应命中
        let cache = DnsCache::new(16, 300);
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv4Only,
            ip,
            &dummy_upstream(),
        );
        let got = lookup_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv4Only,
        );
        assert_eq!(got, Some(ip));
    }

    #[test]
    fn store_and_lookup_ip_cache_ipv6_only() {
        let cache = DnsCache::new(16, 300);
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv6Only,
            ip,
            &dummy_upstream(),
        );
        let got = lookup_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv6Only,
        );
        assert_eq!(got, Some(ip));
    }

    #[test]
    fn store_and_lookup_ip_cache_prefer_ipv4_falls_back_to_aaaa() {
        // PreferIpv4：先查 A，未命中再查 AAAA。这里只写 AAAA，应回退命中。
        let cache = DnsCache::new(16, 300);
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::PreferIpv4,
            ip,
            &dummy_upstream(),
        );
        let got = lookup_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::PreferIpv4,
        );
        assert_eq!(got, Some(ip));
    }

    #[test]
    fn store_and_lookup_ip_cache_prefer_ipv4_prefers_a() {
        // PreferIpv4：同时写 A 和 AAAA 时（两次 store），lookup 应优先返回 A
        let cache = DnsCache::new(16, 300);
        let v4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::PreferIpv4,
            v4,
            &dummy_upstream(),
        );
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::PreferIpv4,
            v6,
            &dummy_upstream(),
        );
        let got = lookup_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::PreferIpv4,
        );
        assert_eq!(got, Some(v4));
    }

    #[test]
    fn lookup_ip_cache_miss_when_empty() {
        let cache = DnsCache::new(16, 300);
        assert!(lookup_ip_cache(
            &cache,
            "local",
            "missing.example.com",
            ResolveStrategy::PreferIpv4
        )
        .is_none());
    }

    #[test]
    fn store_ip_cache_skips_wrong_qtype_for_ipv4_only() {
        // Ipv4Only 策略 + IPv6 结果：不应写入缓存（避免污染）
        let cache = DnsCache::new(16, 300);
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv4Only,
            v6,
            &dummy_upstream(),
        );
        assert!(lookup_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv4Only
        )
        .is_none());
    }

    #[test]
    fn store_ip_cache_skips_wrong_qtype_for_ipv6_only() {
        // Ipv6Only 策略 + IPv4 结果：不应写入缓存
        let cache = DnsCache::new(16, 300);
        let v4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv6Only,
            v4,
            &dummy_upstream(),
        );
        assert!(lookup_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv6Only
        )
        .is_none());
    }

    #[test]
    fn cache_isolated_per_server_tag() {
        // 不同 server tag 的缓存互不干扰（对齐 sing-box transport 隔离）
        let cache = DnsCache::new(16, 300);
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        store_ip_cache(
            &cache,
            "local",
            "node.example.com",
            ResolveStrategy::Ipv4Only,
            ip,
            &dummy_upstream(),
        );
        // 用另一个 tag 查询应 Miss
        assert!(lookup_ip_cache(
            &cache,
            "remote",
            "node.example.com",
            ResolveStrategy::Ipv4Only
        )
        .is_none());
        // 原 tag 仍命中
        assert_eq!(
            lookup_ip_cache(
                &cache,
                "local",
                "node.example.com",
                ResolveStrategy::Ipv4Only
            ),
            Some(ip)
        );
    }

    /// 构造一个仅用于满足 store_ip_cache 签名的 dummy upstream（不会被实际使用）。
    fn dummy_upstream() -> Arc<DnsUpstream> {
        use crate::config::dns::{DnsProtocol, DnsServerConfig};
        // 用 rcode://success 构造一个无需网络的上游
        let cfg = DnsServerConfig {
            tag: "dummy".into(),
            address: "rcode://success".into(),
            detour: None,
            domain_resolver: None,
            client_subnet: None,
            timeout: 5,
            strategy: None,
            fakeip: None,
            sni: None,
            insecure: false,
        };
        let _ = DnsProtocol::Rcode; // 触发 import
        Arc::new(
            DnsUpstream::from_config_full_with_reader(&cfg, None, None, None, None)
                .expect("dummy upstream should construct")
                .with_strategy(ResolveStrategy::PreferIpv4),
        )
    }

    // ── rewrite_response_ttls 测试（对齐 sing-box loadResponse TTL 递减）──────

    #[test]
    fn rewrite_response_ttls_rewrites_answer_ttl() {
        // 构造一个有 2 条 A 记录的响应，TTL=3600
        let resp = make_response_with_records(
            "example.com",
            1,
            &[(1, vec![1, 2, 3, 4]), (1, vec![5, 6, 7, 8])],
        );
        // 原始 min TTL 应为 3600
        assert_eq!(extract_min_ttl(&resp), Some(3600));

        // 重写为 100
        let rewritten = rewrite_response_ttls(&resp, 100);
        // 重写后 min TTL 应为 100
        assert_eq!(extract_min_ttl(&rewritten), Some(100));
    }

    #[test]
    fn rewrite_response_ttls_preserves_non_ttl_fields() {
        // 重写 TTL 不应影响 RDATA、TYPE、CLASS 等字段
        let resp = make_response_with_records("example.com", 1, &[(1, vec![1, 2, 3, 4])]);
        let rewritten = rewrite_response_ttls(&resp, 50);
        // 重写后仍应能正确提取 IP（RDATA 未被破坏）
        let ip = extract_first_ip(&rewritten, 1).expect("should extract IP after TTL rewrite");
        assert_eq!(ip, "1.2.3.4".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn rewrite_response_ttls_handles_short_response() {
        // 异常短的响应不应 panic，原样返回
        let short = [0u8; 5];
        let rewritten = rewrite_response_ttls(&short, 100);
        assert_eq!(rewritten.len(), 5);
    }

    #[test]
    fn rewrite_response_ttls_handles_no_answer() {
        // ANCOUNT=0 的响应不应 panic
        let mut resp = vec![0u8; 12];
        resp[4] = 0;
        resp[5] = 1; // QDCOUNT=1
        resp[6] = 0;
        resp[7] = 0; // ANCOUNT=0
                     // 补一个 Question
        resp.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
        resp.extend_from_slice(&[0, 1]); // QTYPE=A
        resp.extend_from_slice(&[0, 1]); // QCLASS=IN
        let rewritten = rewrite_response_ttls(&resp, 100);
        // 不应 panic，结构保持
        assert_eq!(rewritten[6], 0); // ANCOUNT 仍为 0
    }

    // ── 负向 TTL 修复验证（对齐 sing-box extractNegativeTTL）──────────────────

    #[test]
    fn negative_ttl_uses_soa_minimum_not_hardcoded_300() {
        // 构造一个 NXDOMAIN + SOA 响应，SOA TTL=600, minimum=1800
        // 修复前：会被截断为 300；修复后：应使用 min(600, 1800) = 600
        let mut msg = Vec::new();
        msg.extend_from_slice(&[
            0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ]);
        // Question: example.com A IN
        for label in ["example", "com"] {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        // Authority SOA RR
        msg.extend_from_slice(&[0xC0, 0x0C, 0, 6, 0, 1]); // NAME ptr + TYPE=SOA + CLASS=IN
        msg.extend_from_slice(&600u32.to_be_bytes()); // TTL=600
        msg.extend_from_slice(&[0, 0]); // RDLENGTH 占位（后面回填）
                                        // RDATA: MNAME + RNAME + 5×uint32
        let rdata_start = msg.len();
        msg.extend_from_slice(&[4, b'r', b'o', b'o', b't']); // MNAME
        msg.push(0);
        msg.extend_from_slice(&[4, b'n', b's', b't', b'l']); // RNAME
        msg.push(0);
        msg.extend_from_slice(&1u32.to_be_bytes()); // serial
        msg.extend_from_slice(&7200u32.to_be_bytes()); // refresh
        msg.extend_from_slice(&3600u32.to_be_bytes()); // retry
        msg.extend_from_slice(&1209600u32.to_be_bytes()); // expire
        msg.extend_from_slice(&1800u32.to_be_bytes()); // minimum=1800
        let rdata_len = msg.len() - rdata_start;
        // 回填 RDLENGTH（在 RDATA 前 2 字节）
        let rdlength_pos = rdata_start - 2;
        msg[rdlength_pos..rdlength_pos + 2].copy_from_slice(&(rdata_len as u16).to_be_bytes());

        let ttl = extract_min_ttl_or_negative(&msg).expect("should extract TTL");
        // min(soaTTL=600, soaMinimum=1800) = 600
        assert_eq!(
            ttl, 600,
            "negative TTL should use min(soaTTL, soaMinimum), not hardcoded 300"
        );
    }

    #[test]
    fn negative_ttl_fallback_60_when_no_soa() {
        // NXDOMAIN 无 SOA → 回退 60s（修复前是 300）
        let mut resp = make_query("nx.com", 1);
        resp[3] = 0x83; // QR=1 RCODE=NXDOMAIN
        let ttl = extract_min_ttl_or_negative(&resp).expect("should have fallback TTL");
        assert_eq!(
            ttl, 60,
            "negative TTL without SOA should fallback to 60s, not 300"
        );
    }

    // ── strategy 拒绝规则测试（对齐 sing-box client.go:117） ───────────────────
    //
    // sing-box 在 client.go:117 处：
    //   qtype=A && strategy=Ipv6Only  → 返回空 NOERROR（拒绝 A）
    //   qtype=AAAA && strategy=Ipv4Only → 返回空 NOERROR（拒绝 AAAA）
    // 这避免将「按策略不该返回的记录类型」的查询转发到上游。

    fn build_strategy_test_resolver(strategy: ResolveStrategy) -> DnsResolver {
        use crate::config::dns::{DnsServerConfig, DnsServerRef};
        let cfg = DnsConfig {
            servers: vec![DnsServerConfig {
                tag: "default".into(),
                address: "rcode://success".into(),
                detour: None,
                domain_resolver: None,
                client_subnet: None,
                timeout: 5,
                strategy: None,
                fakeip: None,
                sni: None,
                insecure: false,
            }],
            rules: vec![],
            r#final: DnsServerRef::single("default"),
            strategy,
            proxy_domain_resolver: None,
            disable_hosts: false,
            disable_cache: true, // 关闭缓存以避免缓存影响测试断言
            cache_ttl_max: 0,
            cache_capacity: 16,
            optimistic_timeout: 0,
        };
        DnsResolver::from_config(&cfg).expect("resolver should construct")
    }

    #[tokio::test]
    async fn strategy_ipv6_only_rejects_a_query() {
        // strategy=Ipv6Only + A 查询 → 返回空 NOERROR，不转发到上游
        let resolver = build_strategy_test_resolver(ResolveStrategy::Ipv6Only);
        let q = make_query("example.com", 1); // A
        let resp = resolver
            .handle(Bytes::from(q), "test")
            .await
            .expect("handle should succeed");
        // flags byte2 = 0x85 (QR + AA + RD)
        assert_eq!(resp[2], 0x85);
        // flags byte3 = 0x80 (RA + RCODE=0/NOERROR)
        assert_eq!(resp[3], 0x80);
        // QDCOUNT=1（回显 Question 段）
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        // ANCOUNT=0（空答案）
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[tokio::test]
    async fn strategy_ipv4_only_rejects_aaaa_query() {
        // strategy=Ipv4Only + AAAA 查询 → 返回空 NOERROR
        let resolver = build_strategy_test_resolver(ResolveStrategy::Ipv4Only);
        let q = make_query("example.com", 28); // AAAA
        let resp = resolver
            .handle(Bytes::from(q), "test")
            .await
            .expect("handle should succeed");
        assert_eq!(resp[2], 0x85);
        assert_eq!(resp[3], 0x80);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[tokio::test]
    async fn strategy_ipv6_only_allows_aaaa_query() {
        // strategy=Ipv6Only + AAAA 查询 → 不应被拒绝（rcode://success 也返回 NOERROR）
        let resolver = build_strategy_test_resolver(ResolveStrategy::Ipv6Only);
        let q = make_query("example.com", 28); // AAAA
        let resp = resolver
            .handle(Bytes::from(q), "test")
            .await
            .expect("handle should succeed");
        // rcode://success 返回 NOERROR，未被 strategy 拦截
        assert_eq!(resp[3] & 0x0F, 0);
    }

    #[tokio::test]
    async fn strategy_ipv4_only_allows_a_query() {
        // strategy=Ipv4Only + A 查询 → 不应被拒绝
        let resolver = build_strategy_test_resolver(ResolveStrategy::Ipv4Only);
        let q = make_query("example.com", 1); // A
        let resp = resolver
            .handle(Bytes::from(q), "test")
            .await
            .expect("handle should succeed");
        assert_eq!(resp[3] & 0x0F, 0);
    }

    #[tokio::test]
    async fn strategy_prefer_ipv4_does_not_reject_anything() {
        // strategy=PreferIpv4 → 不应拒绝任何类型的查询
        let resolver = build_strategy_test_resolver(ResolveStrategy::PreferIpv4);
        let q = make_query("example.com", 1); // A
        let resp = resolver
            .handle(Bytes::from(q), "test")
            .await
            .expect("handle should succeed");
        assert_eq!(resp[3] & 0x0F, 0);
    }
}
