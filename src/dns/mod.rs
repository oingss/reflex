//! DNS 解析器：接收查询，按规则分流到不同上游，内置 LRU 缓存。
//!
//! 优化（参照 sing-box）：
//! - transport 隔离：不同上游的缓存条目互不干扰
//! - Optimistic 模式：过期缓存在窗口期内仍返回，后台异步刷新
//! - 持久化：store_dns=true 时写入 redb，重启后自动恢复
//! - **并发请求去重**（新增）：同一 (transport, qname, qtype) 的并发查询只发出一次上游请求，
//!   参照 sing-box dns/client.go 的 cacheLock 机制，消除 DNS 请求风暴。
//! - **负 TTL / SOA 缓存**（新增）：NXDOMAIN/NOERROR-empty 应答按 SOA minimum 缓存，
//!   避免对不存在域名反复查询上游（对应 sing-box extractNegativeTTL）。

pub mod cache;
pub mod upstream;

use std::{collections::HashMap, sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::ruleset::{MatchTarget, RuleSet};

use crate::{
    clash_mode::ClashMode,
    config::dns::{DnsConfig, DnsQueryType, DnsRuleConfig, ProxyDomainResolverConfig, ResolveStrategy},
    experimental::{CacheFile, CacheFileReader},
    inbound::dns::DnsQuery,
    outbound::Outbound,
};

use cache::{CacheResult, DnsCache, InflightResult};
use upstream::DnsUpstream;

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
    default: Arc<DnsUpstream>,
    cache: Option<Arc<DnsCache>>,
    /// 全部已注册的 DNS 上游，key 为 server tag，供 resolve_server 指定时使用
    upstreams: HashMap<String, Arc<DnsUpstream>>,
    /// 生效的解析策略（由 global.ipv6 + dns.strategy 合并决定）
    pub strategy: ResolveStrategy,
    /// `dns.proxy_domain_resolver` 配置，用于解析代理出站节点的服务器域名。
    /// 构造时已校验 server tag 存在于 upstreams 中。
    /// 对齐 sing-box `route.default_domain_resolver`（DomainResolveOptions）：
    /// - `server`：DNS server tag
    /// - `strategy`：None 时沿用全局 `self.strategy`（对齐 sing-box AsIS）
    /// - `disable_cache`：是否跳过缓存
    proxy_domain_resolver: Option<ProxyDomainResolverConfig>,
    /// Clash API 当前模式的共享只读引用，供 DNS 规则的 `clash_mode` 条件匹配使用。
    clash_mode: Arc<ClashMode>,
}

impl DnsResolver {
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

        let default = upstreams
            .get(&config.r#final)
            .ok_or_else(|| anyhow::anyhow!("dns.final '{}' not found", config.r#final))?
            .clone();

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
                    fakeip_tags.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                );
            }
            if matches!(default.kind, upstream::UpstreamKind::FakeIp { .. }) {
                anyhow::bail!(
                    "default server (dns.final='{}') cannot be fakeip; \
                     set dns.final to a non-fakeip server and route fakeip via dns.rules",
                    config.r#final
                );
            }
        }

        // `proxy_domain_resolver` 必须引用一个已存在的 server tag
        if let Some(cfg) = &config.proxy_domain_resolver {
            if !upstreams.contains_key(&cfg.server) {
                anyhow::bail!(
                    "dns.proxy_domain_resolver '{}' not found in dns.servers",
                    cfg.server
                );
            }
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
            default,
            cache,
            upstreams,
            strategy: config.strategy,
            proxy_domain_resolver: config.proxy_domain_resolver.clone(),
            clash_mode,
        })
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
        for upstream in self.upstreams.values() {
            if let upstream::UpstreamKind::FakeIp { store } = &upstream.kind {
                store.set_strategy(s);
            }
        }
        // default upstream 也可能是 fakeip
        if let upstream::UpstreamKind::FakeIp { store } = &self.default.kind {
            store.set_strategy(s);
        }
    }

    /// 重置所有 FakeIP 存储（参照 sing-box `cacheFile.FakeIPReset()`）。
    ///
    /// 遍历所有 fakeip upstream（含 default），调用 `FakeIpStore::reset()`
    /// 清空内存映射 + 持久化表，并把分配指针回退到 range 起点。
    /// 用于 Clash API `POST /cache/fakeip/flush`。
    pub fn reset_fakeip(&self) {
        let mut count = 0;
        for upstream in self.upstreams.values() {
            if let upstream::UpstreamKind::FakeIp { store } = &upstream.kind {
                store.reset();
                count += 1;
            }
        }
        // default upstream 也可能是 fakeip
        if let upstream::UpstreamKind::FakeIp { store } = &self.default.kind {
            store.reset();
            count += 1;
        }
        if count == 0 {
            tracing::debug!("reset_fakeip: no fakeip upstream configured");
        }
    }

    pub async fn resolve_domain(&self, host: &str) -> anyhow::Result<std::net::IpAddr> {
        // 按域名匹配规则，选出正确的上游；跳过 fakeip；无匹配则用 default
        // inbound_tag 传空串：dispatcher 内部调用不属于任何入站
        let upstream = self.select_resolve_upstream(host);
        // 对齐 sing-box Lookup：路由路径解析域名也要走缓存，避免每次转发都打上游。
        // resolve_domain_with_options 内部会先查缓存（key = upstream.tag + host + qtype），
        // 未命中才查询 upstream 并写回缓存。
        self.resolve_domain_with_options(host, &upstream.tag, self.strategy, false)
            .await
    }

    /// 解析域名的**全部**候选地址（A + AAAA），按 `strategy` 排序，供 Happy
    /// Eyeballs 多候选拨号使用（对齐 sing-box `network_strategy` 的候选地址
    /// 来源）。upstream 选择逻辑和 `resolve_domain` 完全一致，区别只是不止取
    /// 第一个 IP。
    pub async fn resolve_domain_all(&self, host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        let upstream = self.select_resolve_upstream(host);
        self.resolve_domain_all_with_cache(host, &upstream.tag, self.strategy)
            .await
    }

    /// 选择用于域名解析的上游（跳过 fakeip，无匹配回退 default 或第一个非 fakeip）。
    fn select_resolve_upstream(&self, host: &str) -> Arc<DnsUpstream> {
        self.rules
            .iter()
            .find(|r| {
                r.matches("", host, 1 /* A */, &self.clash_mode.get())
                    && !matches!(r.upstream.kind, upstream::UpstreamKind::FakeIp { .. })
            })
            .map(|r| r.upstream.clone())
            .unwrap_or_else(|| {
                // default 本身也可能是 fakeip，此时回退到第一个非 fakeip upstream
                if matches!(self.default.kind, upstream::UpstreamKind::FakeIp { .. }) {
                    self.upstreams
                        .values()
                        .find(|u| !matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
                        .cloned()
                        .unwrap_or_else(|| self.default.clone())
                } else {
                    self.default.clone()
                }
            })
    }

    /// `resolve_domain_all` 的缓存版：先查缓存，未命中查询 upstream 并写缓存。
    /// 对齐 sing-box Lookup 的缓存行为。
    async fn resolve_domain_all_with_cache(
        &self,
        host: &str,
        server_tag: &str,
        strategy: ResolveStrategy,
    ) -> anyhow::Result<Vec<std::net::IpAddr>> {
        use std::net::IpAddr;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let upstream = match self.upstreams.get(server_tag) {
            Some(up) => up.clone(),
            None => self.default.clone(),
        };

        // 查缓存：复用 lookup_ip_cache（返回单个 IP），命中则返回单元素 vec。
        // 这是简化处理——缓存只存首个 IP，多 IP 场景仍需查询上游。
        // 对于 Happy Eyeballs 场景，首个 IP 命中已足够启动连接，完整列表
        // 可在缓存 miss 时从上游获取。
        if let Some(ref cache) = self.cache {
            if let Some(ip) = lookup_ip_cache(cache, server_tag, host, strategy) {
                return Ok(vec![ip]);
            }
        }

        // 未命中缓存：查询 upstream
        let ips = self
            .resolve_domain_all_with_strategy(host, strategy, &upstream)
            .await?;

        // 写入缓存（仅存首个 IP，与 resolve_domain_with_options 的缓存格式一致）
        if let Some(ref cache) = self.cache {
            if let Some(first) = ips.first() {
                store_ip_cache(cache, server_tag, host, strategy, *first, &upstream);
            }
        }

        Ok(ips)
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
    /// 若配置了 `dns.proxy_domain_resolver`，走该 server tag 解析代理节点域名；
    /// 否则回退到 `resolve_domain`（按规则 + dns.final 默认上游解析）。
    ///
    /// 对齐 sing-box `default_domain_resolver` 行为：
    /// - 若 `proxy_domain_resolver.strategy` 为 None，沿用全局 `dns.strategy`
    ///   （对齐 sing-box `DomainStrategyAsIS` 使用 transport 默认策略）
    /// - 若 `proxy_domain_resolver.disable_cache = false`（默认），启用缓存
    pub async fn resolve_proxy_domain(&self, host: &str) -> anyhow::Result<std::net::IpAddr> {
        match &self.proxy_domain_resolver {
            Some(cfg) => {
                self.resolve_domain_with_options(
                    host,
                    &cfg.server,
                    cfg.strategy.unwrap_or(self.strategy),
                    cfg.disable_cache,
                )
                .await
            }
            None => self.resolve_domain(host).await,
        }
    }

    /// 使用指定 server tag 的 DNS 上游解析域名（沿用全局 `strategy`，启用缓存）。
    /// 供 dispatcher 的 `resolve` 路由动作使用。
    /// 若 tag 不存在则回退到默认上游并记录 warn 日志。
    pub async fn resolve_domain_via(
        &self,
        host: &str,
        server_tag: &str,
    ) -> anyhow::Result<std::net::IpAddr> {
        self.resolve_domain_with_options(host, server_tag, self.strategy, false)
            .await
    }

    /// 内部统一入口：用指定 server tag、strategy 和 cache 开关解析域名。
    ///
    /// 对齐 sing-box `resolveDialer` + `Router.Lookup`：
    /// - 查找指定 server tag 的 upstream（不存在则回退默认上游 + warn）
    /// - 应用指定的 strategy（覆盖全局）
    /// - 若启用缓存且 cache 存在，先查缓存；未命中则查询 upstream 并写入缓存
    async fn resolve_domain_with_options(
        &self,
        host: &str,
        server_tag: &str,
        strategy: ResolveStrategy,
        disable_cache: bool,
    ) -> anyhow::Result<std::net::IpAddr> {
        let upstream = match self.upstreams.get(server_tag) {
            Some(up) => up.clone(),
            None => {
                tracing::warn!(
                    server_tag,
                    host,
                    "resolve_domain_via: server tag not found, falling back to default"
                );
                self.default.clone()
            }
        };

        // 缓存查询（对齐 sing-box client.Lookup 的缓存逻辑）
        // 缓存 key 使用 server_tag + host + strategy 派生的 qtype，
        // 避免不同 strategy 的查询互相污染。
        if !disable_cache {
            if let Some(ref cache) = self.cache {
                if let Some(ip) = lookup_ip_cache(cache, server_tag, host, strategy) {
                    return Ok(ip);
                }
            }
        }

        // 未命中缓存：查询 upstream
        let ip = self
            .resolve_domain_with_strategy(host, strategy, &upstream)
            .await?;

        // 写入缓存
        if !disable_cache {
            if let Some(ref cache) = self.cache {
                store_ip_cache(cache, server_tag, host, strategy, ip, &upstream);
            }
        }

        Ok(ip)
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
    pub async fn resolve_raw(&self, name: &str, qtype: u16) -> anyhow::Result<Vec<u8>> {
        let query = build_query_bytes(name, qtype);
        // 用 default upstream 直接查询（不走路由规则，不影响 fake-ip 分配）
        let resp = self
            .default
            .query(bytes::Bytes::from(query))
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

    async fn handle(&self, msg: Bytes, inbound_tag: &str) -> anyhow::Result<Bytes> {
        let qname = extract_qname(&msg).unwrap_or_default();
        let qtype = extract_qtype(&msg).unwrap_or(1);
        debug!(qname=%qname, qtype=qtype, inbound=%inbound_tag, "dns query");

        // ── 规则匹配，选择上游 ────────────────────────────────────────────────
        let current_mode = self.clash_mode.get();
        let (upstream, disable_cache) = self
            .rules
            .iter()
            .find(|r| r.matches(inbound_tag, &qname, qtype, &current_mode))
            .map(|r| (r.upstream.clone(), r.disable_cache))
            .unwrap_or_else(|| (self.default.clone(), false));

        let transport_tag = upstream.tag.clone();

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
                    let upstream2 = upstream.clone();
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
                                match upstream2.query(msg2).await {
                                    Ok(resp) => {
                                        if is_cacheable_or_negative(&resp) {
                                            let ttl = extract_min_ttl_or_negative(&resp).unwrap_or(60);
                                            cache2.set(&transport_tag2, &qname2, qtype, resp.clone(), ttl);
                                        }
                                        cache2.complete_inflight(&transport_tag2, &qname2, qtype, Some(&resp));
                                    }
                                    Err(e) => {
                                        debug!(err=%e, qname=%qname2, "optimistic refresh failed");
                                        cache2.complete_inflight(&transport_tag2, &qname2, qtype, None);
                                    }
                                }
                            }
                        }
                    });
                    return Ok(patch_id(cached, &msg));
                }
                CacheResult::Miss => {}
            }

            // ── 并发请求去重（参照 sing-box cacheLock）────────────────────────
            // 同一 (transport, qname, qtype) 若已有 leader 在查询，本请求作为 waiter 等待广播结果。
            match cache.try_lead_inflight(&transport_tag, &qname, qtype) {
                InflightResult::Waiter(mut rx) => {
                    debug!(qname=%qname, transport=%transport_tag, "dns inflight dedup: waiting for leader");
                    match rx.recv().await {
                        Ok(cached) => return Ok(patch_id(cached, &msg)),
                        Err(_) => {
                            // leader 查询失败。对齐 sing-box：waiter 不自行重试上游，
                            // 直接返回错误，避免 N 个 waiter 放大成 N 次上游请求。
                            // （sing-box waiter 唤醒后只查 cache，不重试。）
                            debug!(qname=%qname, "dns inflight leader failed, waiter returns error");
                            return Err(anyhow::anyhow!("dns upstream query failed (inflight leader error)"));
                        }
                    }
                }
                InflightResult::Leader => {
                    // 本请求作为 leader，查询上游，然后广播结果
                    let resp = upstream.query(msg.clone()).await;
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
            }
        }

        // ── 无缓存路径：直接查询上游 ──────────────────────────────────────────
        let resp = upstream.query(msg).await?;
        Ok(resp)
    }
}

// ── 编译后的 DNS 规则 ─────────────────────────────────────────────────────────

struct CompiledDnsRule {
    inbound_tags: Vec<String>,
    query_types: Vec<u16>,
    inline_rs: Option<Arc<RuleSet>>,
    file_rulesets: Vec<Arc<RuleSet>>,
    upstream: Arc<DnsUpstream>,
    disable_cache: bool,
    /// 仅当 Clash API 当前模式等于该值时才命中（对应 `clash_mode`），
    /// 大小写不敏感比较；None 表示不限制模式。与主路由规则的 `clash_mode`
    /// 语义一致，见 `router::CompiledRule`。
    clash_mode_filter: Option<String>,
}

impl CompiledDnsRule {
    fn compile(
        rule: &DnsRuleConfig,
        upstreams: &HashMap<String, Arc<DnsUpstream>>,
        preloaded: &HashMap<String, Arc<RuleSet>>,
    ) -> anyhow::Result<Self> {
        let upstream = upstreams
            .get(&rule.server)
            .ok_or_else(|| anyhow::anyhow!("dns server '{}' not found", rule.server))?
            .clone();

        let mut lines = Vec::new();
        for d in &rule.domain {
            lines.push(format!("domain: {d}"));
        }
        for d in &rule.domain_suffix {
            lines.push(format!("domain-suffix: {d}"));
        }
        for d in &rule.domain_keyword {
            lines.push(format!("domain-keyword: {d}"));
        }

        let inline_rs = if lines.is_empty() {
            None
        } else {
            Some(Arc::new(RuleSet::from_text(&lines.join("\n"))?))
        };

        let mut file_rulesets = Vec::new();
        for tag in &rule.ruleset {
            match preloaded.get(tag) {
                Some(rs) => file_rulesets.push(rs.clone()),
                None => {
                    // 对齐 sing-box rule_item_rule_set.go:35 —— 未找到 tag 时
                    // 直接初始化失败，而不是静默跳过（否则用户配错 tag 不会发现）。
                    anyhow::bail!(
                        "dns rule references unloaded ruleset '{}': tag not found",
                        tag
                    );
                }
            }
        }

        Ok(Self {
            inbound_tags: rule.inbound.clone(),
            query_types: rule
                .query_type
                .iter()
                .map(|qt| match qt {
                    DnsQueryType::A => 1u16,
                    DnsQueryType::Aaaa => 28,
                    DnsQueryType::Cname => 5,
                    DnsQueryType::Mx => 15,
                    DnsQueryType::Txt => 16,
                    DnsQueryType::Ns => 2,
                    DnsQueryType::Ptr => 12,
                    DnsQueryType::Srv => 33,
                    DnsQueryType::Https => 65,
                })
                .collect(),
            inline_rs,
            file_rulesets,
            upstream,
            disable_cache: rule.disable_cache,
            clash_mode_filter: rule.clash_mode.clone(),
        })
    }

    fn matches(&self, inbound_tag: &str, qname: &str, qtype: u16, current_mode: &str) -> bool {
        // Clash API 模式过滤（不受其他条件影响的硬性前置过滤）。
        if let Some(mode) = &self.clash_mode_filter {
            if !mode.eq_ignore_ascii_case(current_mode) {
                return false;
            }
        }
        if !self.inbound_tags.is_empty() && !self.inbound_tags.iter().any(|t| t == inbound_tag) {
            return false;
        }
        if !self.query_types.is_empty() && !self.query_types.contains(&qtype) {
            return false;
        }
        let has_cond = self.inline_rs.is_some() || !self.file_rulesets.is_empty();
        if has_cond {
            let mt = MatchTarget::Domain(qname);
            let hit = self.inline_rs.as_ref().is_some_and(|rs| rs.matches(&mt))
                || self.file_rulesets.iter().any(|rs| rs.matches(&mt));
            if !hit {
                return false;
            }
        }
        true
    }
}

// ── DNS wire-format 辅助 ──────────────────────────────────────────────────────

pub fn extract_qname(msg: &[u8]) -> Option<String> {
    if msg.len() < 13 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            break;
        }
        pos += 1;
        if pos + len > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[pos..pos + len]).into_owned());
        pos += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

pub fn extract_qtype(msg: &[u8]) -> Option<u16> {
    if msg.len() < 13 {
        return None;
    }
    let mut pos = 12;
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    if pos + 2 > msg.len() {
        return None;
    }
    Some(u16::from_be_bytes([msg[pos], msg[pos + 1]]))
}

fn patch_id(resp: Bytes, query: &[u8]) -> Bytes {
    if resp.len() >= 2 && query.len() >= 2 {
        let mut v = resp.to_vec();
        v[0] = query[0];
        v[1] = query[1];
        Bytes::from(v)
    } else {
        resp
    }
}

/// 原 is_cacheable：只缓存 NOERROR + ANCOUNT>0
#[allow(dead_code)]
fn is_cacheable(resp: &[u8]) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    rcode == 0 && ancount > 0
}

/// 扩展版：同时缓存负应答（NXDOMAIN / NOERROR-empty），以 SOA minimum TTL 为准。
/// 参照 sing-box extractNegativeTTL，避免对不存在域名反复查询上游。
fn is_cacheable_or_negative(resp: &[u8]) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    // NOERROR(0) + ANCOUNT>0 → 正向缓存
    if rcode == 0 && u16::from_be_bytes([resp[6], resp[7]]) > 0 {
        return true;
    }
    // NXDOMAIN(3) 或 NOERROR + 无 answer → 负向缓存（若有 SOA TTL）
    if rcode == 0 || rcode == 3 {
        return extract_soa_ttl(resp).is_some();
    }
    false
}

/// 提取 min TTL（正向应答用），或 SOA minimum（负向应答用）。
fn extract_min_ttl_or_negative(resp: &[u8]) -> Option<u32> {
    if resp.len() < 12 {
        return None;
    }
    let rcode = resp[3] & 0x0F;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);

    if (rcode == 0 || rcode == 3) && ancount == 0 {
        // 负应答：用 SOA 的 min(soaTTL, soaMinimum)。
        // 对齐 sing-box extractNegativeTTL —— 不硬编码 300s 上限，使用 SOA 真实值。
        // 无 SOA 时回退到 60s（避免对不存在域名反复查询上游），上限 3600s 防止极端值。
        return Some(extract_soa_ttl(resp).unwrap_or(60).min(3600));
    }
    extract_min_ttl(resp)
}

/// 从 Authority 区提取 SOA minimum TTL（负应答缓存 TTL 依据）。
/// 参照 sing-box extractNegativeTTL：min(soaTTL, soaMinimum)。
fn extract_soa_ttl(resp: &[u8]) -> Option<u32> {
    // 简单扫描 Authority section：NSCOUNT 个 RR，寻找 TYPE=SOA(6)
    if resp.len() < 12 {
        return None;
    }
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    if nscount == 0 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    // 跳过 Question section
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return None;
        }
        let l = resp[pos] as usize;
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
              // 跳过 Answer section
    for _ in 0..ancount {
        pos = skip_rr(resp, pos)?;
    }
    // 扫描 Authority section 找 SOA
    for _ in 0..nscount {
        let rr_start = pos;
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rr_ttl =
            u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let _rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if rr_type == 6 {
            // SOA: MNAME + RNAME + serial(4) + refresh(4) + retry(4) + expire(4) + minimum(4)
            // 跳过 MNAME 和 RNAME 两个域名，定位 minimum 字段
            let mut soa_pos = pos;
            soa_pos = skip_name(resp, soa_pos)?;
            soa_pos = skip_name(resp, soa_pos)?;
            if soa_pos + 20 > resp.len() {
                return None;
            }
            let minimum = u32::from_be_bytes([
                resp[soa_pos + 16],
                resp[soa_pos + 17],
                resp[soa_pos + 18],
                resp[soa_pos + 19],
            ]);
            return Some(rr_ttl.min(minimum));
        }
        pos = rr_start;
        pos = skip_rr(resp, pos)?;
    }
    None
}

fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let l = msg[pos] as usize;
        if l == 0 {
            return Some(pos + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + l;
    }
}

fn skip_rr(msg: &[u8], pos: usize) -> Option<usize> {
    let pos = skip_name(msg, pos)?;
    if pos + 10 > msg.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
    Some(pos + 10 + rdlength)
}

fn extract_min_ttl(resp: &[u8]) -> Option<u32> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return None;
        }
        let len = msg_label_len(resp, pos)?;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    pos += 4; // QTYPE + QCLASS
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        if resp[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            loop {
                if pos >= resp.len() {
                    return None;
                }
                let l = resp[pos] as usize;
                if l == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + l;
            }
        }
        if pos + 10 > resp.len() {
            break;
        }
        let ttl = u32::from_be_bytes(resp[pos + 4..pos + 8].try_into().ok()?);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if ttl < min_ttl {
            min_ttl = ttl;
        }
    }
    if min_ttl == u32::MAX {
        None
    } else {
        Some(min_ttl)
    }
}

fn msg_label_len(msg: &[u8], pos: usize) -> Option<usize> {
    msg.get(pos).map(|&b| b as usize)
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

pub fn make_servfail(query: &[u8]) -> Bytes {
    let mut resp = [0u8; 12];
    if query.len() >= 2 {
        resp[0] = query[0];
        resp[1] = query[1];
    }
    resp[2] = 0x80;
    resp[3] = 0x02;
    Bytes::copy_from_slice(&resp)
}

pub fn make_refused(query: &[u8]) -> Bytes {
    let mut v = make_servfail(query).to_vec();
    v[3] = 0x05;
    Bytes::from(v)
}

pub fn make_noerror_empty(query: &[u8]) -> Bytes {
    let mut v = make_servfail(query).to_vec();
    v[3] = 0x00;
    Bytes::from(v)
}

pub fn make_nxdomain(query: &[u8]) -> Bytes {
    let mut v = make_servfail(query).to_vec();
    v[3] = 0x03;
    Bytes::from(v)
}

pub fn build_query_bytes(name: &str, qtype: u16) -> Vec<u8> {
    build_query(name, qtype)
}

pub fn extract_first_ip_from_resp(resp: &[u8], qtype: u16) -> Option<std::net::IpAddr> {
    extract_first_ip(resp, qtype)
}

fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut msg = vec![
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x01]);
    msg
}

fn extract_first_ip(resp: &[u8], qtype: u16) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return None;
        }
        let len = resp[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    pos += 4;
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        if resp[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            loop {
                if pos >= resp.len() {
                    return None;
                }
                let l = resp[pos] as usize;
                if l == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + l;
            }
        }
        if pos + 10 > resp.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            break;
        }
        if rr_type == qtype {
            match qtype {
                1 if rdlength == 4 => {
                    return Some(IpAddr::V4(Ipv4Addr::new(
                        resp[pos],
                        resp[pos + 1],
                        resp[pos + 2],
                        resp[pos + 3],
                    )))
                }
                28 if rdlength == 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&resp[pos..pos + 16]);
                    return Some(IpAddr::V6(Ipv6Addr::from(o)));
                }
                _ => {}
            }
        }
        pos += rdlength;
    }
    None
}

// ── proxy_domain_resolver 缓存辅助 ───────────────────────────────────────────
//
// 对齐 sing-box client.Lookup 的缓存逻辑：将解析结果（原始 DNS 响应）缓存，
// 避免对代理节点 server 域名的重复 DNS 查询。
// 缓存 key = (server_tag, host, qtype)，与全局 DNS 查询缓存共用同一个 DnsCache。

/// 从 DNS 缓存中查找代理节点域名对应的 IP。
/// 根据 strategy 选择查询 A/AAAA 或两者，返回首个匹配的 IP。
fn lookup_ip_cache(
    cache: &DnsCache,
    server_tag: &str,
    host: &str,
    strategy: ResolveStrategy,
) -> Option<std::net::IpAddr> {
    match strategy {
        ResolveStrategy::Ipv4Only => {
            let cached = cache.get(server_tag, host, 1);
            ip_from_cache_result(cached, 1)
        }
        ResolveStrategy::Ipv6Only => {
            let cached = cache.get(server_tag, host, 28);
            ip_from_cache_result(cached, 28)
        }
        ResolveStrategy::PreferIpv4 => {
            let v4 = ip_from_cache_result(cache.get(server_tag, host, 1), 1);
            if v4.is_some() {
                return v4;
            }
            ip_from_cache_result(cache.get(server_tag, host, 28), 28)
        }
        ResolveStrategy::PreferIpv6 => {
            let v6 = ip_from_cache_result(cache.get(server_tag, host, 28), 28);
            if v6.is_some() {
                return v6;
            }
            ip_from_cache_result(cache.get(server_tag, host, 1), 1)
        }
    }
}

/// 从 CacheResult 中提取首个 IP（Hit 或 Stale 均视为有效）。
fn ip_from_cache_result(result: CacheResult, qtype: u16) -> Option<std::net::IpAddr> {
    match result {
        CacheResult::Hit(resp) | CacheResult::Stale(resp) => extract_first_ip(&resp, qtype),
        CacheResult::Miss => None,
    }
}

/// 将代理节点域名解析结果写入 DNS 缓存。
///
/// 由于 `resolve_domain_with_strategy` 直接查询 upstream 返回 IP（不返回原始报文），
/// 这里无法直接缓存 IP。改为构造一个最小 DNS 响应报文写入缓存，保持与全局
/// DNS 缓存格式一致，后续 lookup_ip_cache 可正确读取。
fn store_ip_cache(
    cache: &DnsCache,
    server_tag: &str,
    host: &str,
    strategy: ResolveStrategy,
    ip: std::net::IpAddr,
    _upstream: &Arc<DnsUpstream>,
) {
    // 根据 strategy 和实际返回的 IP 类型决定写入哪个 qtype 的缓存
    let qtype = match ip {
        std::net::IpAddr::V4(_) => 1u16,  // A
        std::net::IpAddr::V6(_) => 28u16, // AAAA
    };

    // 仅当该 strategy 会查询此 qtype 时才写入，避免缓存污染
    let should_store = match strategy {
        ResolveStrategy::Ipv4Only => qtype == 1,
        ResolveStrategy::Ipv6Only => qtype == 28,
        ResolveStrategy::PreferIpv4 | ResolveStrategy::PreferIpv6 => true,
    };
    if !should_store {
        return;
    }

    let resp = build_minimal_dns_response(host, qtype, ip);
    cache.set(server_tag, host, qtype, resp.into(), 300);
}

/// 构造一个仅包含单条 Answer 记录的最小 DNS 响应报文，用于缓存写入。
fn build_minimal_dns_response(host: &str, qtype: u16, ip: std::net::IpAddr) -> Vec<u8> {
    // DNS header: ID=0, QR=1(query response), QDCOUNT=1, ANCOUNT=1
    let mut msg = vec![
        0x00, 0x00, // ID
        0x81, 0x00, // flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x01, // ANCOUNT=1
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
    ];

    // Question section: QNAME + QTYPE + QCLASS
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    // Answer section: NAME(pointer to offset 12) + TYPE + CLASS + TTL + RDLENGTH + RDATA
    msg.push(0xc0); // 压缩指针指向 offset 12 (Question 的 QNAME)
    msg.push(0x0c);
    msg.extend_from_slice(&qtype.to_be_bytes()); // TYPE
    msg.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
    msg.extend_from_slice(&300u32.to_be_bytes()); // TTL=300
    match ip {
        std::net::IpAddr::V4(v4) => {
            msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH=4
            msg.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            msg.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH=16
            msg.extend_from_slice(&v6.octets());
        }
    }

    msg
}

/// 与 `extract_first_ip` 平行的实现：不是命中第一条就返回，而是收集**全部**
/// 匹配 `qtype` 的记录。供 `resolve_domain_all`（Happy Eyeballs 多候选拨号）
/// 使用。刻意不复用 `extract_first_ip` 内部逻辑（哪怕有重复），是为了不去碰
/// 已经过充分测试的原函数，降低改动风险。
fn extract_all_ips(resp: &[u8], qtype: u16) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut out = Vec::new();
    if resp.len() < 12 {
        return out;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return out;
    }
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return out;
        }
        let len = resp[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    pos += 4;
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        if resp[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            loop {
                if pos >= resp.len() {
                    return out;
                }
                let l = resp[pos] as usize;
                if l == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + l;
            }
        }
        if pos + 10 > resp.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            break;
        }
        if rr_type == qtype {
            match qtype {
                1 if rdlength == 4 => {
                    out.push(IpAddr::V4(Ipv4Addr::new(
                        resp[pos],
                        resp[pos + 1],
                        resp[pos + 2],
                        resp[pos + 3],
                    )));
                }
                28 if rdlength == 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&resp[pos..pos + 16]);
                    out.push(IpAddr::V6(Ipv6Addr::from(o)));
                }
                _ => {}
            }
        }
        pos += rdlength;
    }
    out
}

// ── 拓扑排序 ──────────────────────────────────────────────────────────────────

fn toposort_servers(servers: &[crate::config::dns::DnsServerConfig]) -> anyhow::Result<Vec<usize>> {
    let n = servers.len();
    let tag_to_idx: HashMap<&str, usize> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| (s.tag.as_str(), i))
        .collect();
    let mut in_degree = vec![0usize; n];
    let mut deps: Vec<Option<usize>> = vec![None; n];
    for (i, srv) in servers.iter().enumerate() {
        if let Some(ref tag) = srv.domain_resolver {
            let j = *tag_to_idx.get(tag.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "dns server '{}' domain_resolver '{}' not found",
                    srv.tag,
                    tag
                )
            })?;
            deps[i] = Some(j);
            in_degree[i] += 1;
            if let Some(k) = deps[j] {
                if k == i {
                    anyhow::bail!(
                        "dns server domain_resolver cycle between '{}' and '{}'",
                        servers[i].tag,
                        servers[j].tag
                    );
                }
            }
        }
    }
    let mut queue: std::collections::VecDeque<usize> =
        (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    while let Some(node) = queue.pop_front() {
        order.push(node);
        for i in 0..n {
            if deps[i] == Some(node) {
                in_degree[i] -= 1;
                if in_degree[i] == 0 {
                    queue.push_back(i);
                }
            }
        }
    }
    if order.len() != n {
        anyhow::bail!("dns server domain_resolver has a cycle");
    }
    Ok(order)
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        let resp = make_response_with_records(
            "example.com",
            1,
            &[(1, vec![9, 9, 9, 9]), (28, v6_bytes)],
        );
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
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv4Only, ip, &dummy_upstream());
        let got = lookup_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv4Only);
        assert_eq!(got, Some(ip));
    }

    #[test]
    fn store_and_lookup_ip_cache_ipv6_only() {
        let cache = DnsCache::new(16, 300);
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv6Only, ip, &dummy_upstream());
        let got = lookup_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv6Only);
        assert_eq!(got, Some(ip));
    }

    #[test]
    fn store_and_lookup_ip_cache_prefer_ipv4_falls_back_to_aaaa() {
        // PreferIpv4：先查 A，未命中再查 AAAA。这里只写 AAAA，应回退命中。
        let cache = DnsCache::new(16, 300);
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::PreferIpv4, ip, &dummy_upstream());
        let got = lookup_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::PreferIpv4);
        assert_eq!(got, Some(ip));
    }

    #[test]
    fn store_and_lookup_ip_cache_prefer_ipv4_prefers_a() {
        // PreferIpv4：同时写 A 和 AAAA 时（两次 store），lookup 应优先返回 A
        let cache = DnsCache::new(16, 300);
        let v4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::PreferIpv4, v4, &dummy_upstream());
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::PreferIpv4, v6, &dummy_upstream());
        let got = lookup_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::PreferIpv4);
        assert_eq!(got, Some(v4));
    }

    #[test]
    fn lookup_ip_cache_miss_when_empty() {
        let cache = DnsCache::new(16, 300);
        assert!(lookup_ip_cache(&cache, "local", "missing.example.com", ResolveStrategy::PreferIpv4).is_none());
    }

    #[test]
    fn store_ip_cache_skips_wrong_qtype_for_ipv4_only() {
        // Ipv4Only 策略 + IPv6 结果：不应写入缓存（避免污染）
        let cache = DnsCache::new(16, 300);
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv4Only, v6, &dummy_upstream());
        assert!(lookup_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv4Only).is_none());
    }

    #[test]
    fn store_ip_cache_skips_wrong_qtype_for_ipv6_only() {
        // Ipv6Only 策略 + IPv4 结果：不应写入缓存
        let cache = DnsCache::new(16, 300);
        let v4: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv6Only, v4, &dummy_upstream());
        assert!(lookup_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv6Only).is_none());
    }

    #[test]
    fn cache_isolated_per_server_tag() {
        // 不同 server tag 的缓存互不干扰（对齐 sing-box transport 隔离）
        let cache = DnsCache::new(16, 300);
        let ip: std::net::IpAddr = "1.2.3.4".parse().unwrap();
        store_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv4Only, ip, &dummy_upstream());
        // 用另一个 tag 查询应 Miss
        assert!(lookup_ip_cache(&cache, "remote", "node.example.com", ResolveStrategy::Ipv4Only).is_none());
        // 原 tag 仍命中
        assert_eq!(
            lookup_ip_cache(&cache, "local", "node.example.com", ResolveStrategy::Ipv4Only),
            Some(ip)
        );
    }

    /// 构造一个仅用于满足 store_ip_cache 签名的 dummy upstream（不会被实际使用）。
    fn dummy_upstream() -> Arc<DnsUpstream> {
        use crate::config::dns::{DnsServerConfig, DnsProtocol};
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
        resp[4] = 0; resp[5] = 1; // QDCOUNT=1
        resp[6] = 0; resp[7] = 0; // ANCOUNT=0
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
        msg.extend_from_slice(&[0x00, 0x01, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
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
        assert_eq!(ttl, 600, "negative TTL should use min(soaTTL, soaMinimum), not hardcoded 300");
    }

    #[test]
    fn negative_ttl_fallback_60_when_no_soa() {
        // NXDOMAIN 无 SOA → 回退 60s（修复前是 300）
        let mut resp = make_query("nx.com", 1);
        resp[3] = 0x83; // QR=1 RCODE=NXDOMAIN
        let ttl = extract_min_ttl_or_negative(&resp).expect("should have fallback TTL");
        assert_eq!(ttl, 60, "negative TTL without SOA should fallback to 60s, not 300");
    }
}
