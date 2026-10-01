pub mod cache;
pub mod rcode;
pub mod resolver_helpers;
pub mod rule;
pub mod upstream;
pub mod wire;

pub use rcode::*;
pub use wire::*;

use std::{collections::HashMap, num::NonZeroUsize, sync::Arc, sync::Mutex, time::Duration};

use bytes::Bytes;
use lru::LruCache;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::{
    clash_mode::ClashMode,
    config::dns::{DnsConfig, DnsRuleConfig, ProxyDomainResolverConfig, ResolveStrategy},
    experimental::{CacheFile, CacheFileReader},
    inbound::dns::DnsQuery,
    outbound::Outbound,
    ruleset::RuleSet,
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

// ── DNS Drop 错误（对齐 sing-box `tun.ErrDrop`）─────────────────────────────

/// `block` 规则的 `drop` 方法返回的特殊错误，对齐 sing-box
/// `RuleActionRejectMethodDrop` → `return nil, tun.ErrDrop`：
/// 调用方应静默丢弃查询，不返回任何 DNS 响应（不写 SERVFAIL）。
///
/// 调用方通过 `err.is::<DnsDropError>()` 或 `err.downcast_ref::<DnsDropError>()`
/// 识别并跳过响应；其他错误仍按 SERVFAIL 处理。
#[derive(Debug, Clone, Copy)]
pub struct DnsDropError;

impl std::fmt::Display for DnsDropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("dns query dropped (block method=drop)")
    }
}

impl std::error::Error for DnsDropError {}

// ── DNS 解析器 ────────────────────────────────────────────────────────────────

pub struct DnsResolver {
    rules: Vec<CompiledDnsRule>,
    /// 无 inbound 条件的规则索引（全局规则），匹配时必须检查。
    global_dns_indices: Vec<usize>,
    /// 按 inbound tag 分桶的规则索引，匹配时只需检查当前 inbound 的子集。
    dns_inbound_buckets: HashMap<String, Vec<usize>>,
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
    /// ���齐 sing-box `route.default_domain_resolver`（DomainResolveOptions）：
    /// - `server`：DNS server tag（s），支持单 tag 或多 tag 并发
    /// - `strategy`：None 时沿用全局 `self.strategy`（对齐 sing-box AsIS）
    /// - `disable_cache`：是否跳过缓存
    proxy_domain_resolver: Option<ProxyDomainResolverConfig>,
    /// Clash API 当前模式的共享只读引用，供 DNS 规则的 `clash_mode` 条件匹配使用。
    clash_mode: Arc<ClashMode>,
    /// 域名→上游选择结果的小型 LRU 缓存，避免对同一域名重复扫描全部 DNS 规则。
    upstream_cache: Mutex<LruCache<String, Vec<Arc<DnsUpstream>>>>,
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
            global_dns_indices: Vec::new(),
            dns_inbound_buckets: HashMap::new(),
            rule_configs: Vec::new(),
            default: Vec::new(),
            cache: None,
            upstreams: HashMap::new(),
            strategy: ResolveStrategy::PreferIpv4,
            proxy_domain_resolver: None,
            clash_mode,
            upstream_cache: Mutex::new(LruCache::new(NonZeroUsize::new(256).unwrap())),
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

        // ── 构建 inbound 分桶索引（对齐主路由 Router 的 bucketing 策略） ───────
        // 无 inbound 条件的规则 → global_dns_indices（每次匹配都必须检查）
        // 有 inbound 条件的规则 → dns_inbound_buckets[tag]（仅匹配 inbound tag 时检查）
        let mut global_dns_indices = Vec::new();
        let mut dns_inbound_buckets: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, r) in rules.iter().enumerate() {
            if r.inbound_tags.is_empty() {
                global_dns_indices.push(idx);
            } else {
                for tag in &r.inbound_tags {
                    dns_inbound_buckets.entry(tag.clone()).or_default().push(idx);
                }
            }
        }

        Ok(Self {
            rules,
            global_dns_indices,
            dns_inbound_buckets,
            rule_configs: config.rules.clone(),
            default,
            cache,
            upstreams,
            strategy: config.strategy,
            proxy_domain_resolver: config.proxy_domain_resolver.clone(),
            clash_mode,
            upstream_cache: Mutex::new(LruCache::new(NonZeroUsize::new(256).unwrap())),
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
        // 对齐 mihomo resolver.Lookup：按 strategy 决定查询类型，规则匹配时
        // 传入实际 qtype，使 query_type 过滤的规则能正确命中（见 select_resolve_upstreams）。
        let qtype = match self.strategy {
            ResolveStrategy::Ipv6Only => 28, // AAAA
            _ => 1,                          // A（Ipv4Only / PreferIpv4 / PreferIpv6 / AsIS）
        };
        let upstreams = self.select_resolve_upstreams(host, qtype);
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

    /// 防环版本：供各 proxy 出站解析**自身服务器域名**时使用。
    ///
    /// 与 `resolve_domain` 的唯一区别：会过滤掉 detour 指向 `self_outbound_tag`
    /// 自身的上游。否则在 TUN/默认路由场景下会出现致命死锁：
    /// 建立代理连接 → 需要先解析代理服务器域名 → 该域名按规则路由到带
    /// `detour=同一代理` 的 DNS 上游 → 查询又需要建立同一代理的连接 →
    /// 而 `get_or_create_connection` 的连接缓存锁正被外层持有 → 永久互等。
    /// 日志表现为：所有 DNS 查询超时（deadline has elapsed），且**没有任何**
    /// 代理连接错误日志（连接根本没发起）。
    ///
    /// 对齐 sing-box 语义：sing-box 要求解析代理服务器域名的
    /// `domain_resolver` 不能 detour 到该代理自身（配置检查会警告 loop）。
    pub async fn resolve_domain_for_outbound(
        &self,
        host: &str,
        self_outbound_tag: &str,
    ) -> anyhow::Result<std::net::IpAddr> {
        let qtype = match self.strategy {
            ResolveStrategy::Ipv6Only => 28,
            _ => 1,
        };
        let mut upstreams = self.select_resolve_upstreams(host, qtype);
        if !self_outbound_tag.is_empty() {
            let self_tag = self_outbound_tag;
            upstreams.retain(|u| u.detour_tag() != Some(self_tag));
        }
        if upstreams.is_empty() {
            anyhow::bail!(
                "dns anti-loop: resolving proxy server domain '{host}' would require \
                 outbound '{self_outbound_tag}' itself (all candidate DNS servers detour \
                 via it); configure dns.proxy_domain_resolver to a server that is not \
                 detoured through '{self_outbound_tag}'"
            );
        }
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
        // 对齐 mihomo resolver.Lookup：按 strategy 决定查询类型（见 resolve_domain 注释）。
        // PreferIpv4 / PreferIpv6 同时查 A + AAAA，但规则匹配用 A（qtype=1）作为
        // 代表类型——这与 mihomo 行为一致：规则 query_type 过滤通常针对单类型，
        // Prefer 策略下两条记录都查，规则匹配只走一次（A 路径）。
        let qtype = match self.strategy {
            ResolveStrategy::Ipv6Only => 28, // AAAA
            _ => 1,                         // A
        };
        let upstreams = self.select_resolve_upstreams(host, qtype);
        self.resolve_domain_all_with_cache(host, &upstreams, self.strategy)
            .await
    }

    /// 归并遍历 global_dns_indices 和 dns_inbound_buckets[inbound_tag]，
    /// 返回第一个匹配的规则索引。对齐主路由 Router 的 merge-iterate 策略：
    /// 两条索引序列都已按全局规则顺序排列，归并遍历保持全局顺序。
    fn match_dns_rule(
        &self,
        inbound_tag: &str,
        qname_norm: &str,
        qtype: u16,
        current_mode: &str,
    ) -> Option<usize> {
        let tagged = self.dns_inbound_buckets.get(inbound_tag);
        let mut gi = 0usize;
        let mut ti = 0usize;
        loop {
            let g = self.global_dns_indices.get(gi).copied();
            let t = tagged.and_then(|v| v.get(ti)).copied();
            let idx = match (g, t) {
                (Some(a), Some(b)) if b < a => {
                    ti += 1;
                    b
                }
                (Some(a), Some(_)) => {
                    gi += 1;
                    a
                }
                (Some(a), None) => {
                    gi += 1;
                    a
                }
                (None, Some(b)) => {
                    ti += 1;
                    b
                }
                (None, None) => break,
            };
            if self.rules[idx].matches_normalized(inbound_tag, qname_norm, qtype, current_mode) {
                return Some(idx);
            }
        }
        None
    }

    /// 选择用于域名解析的上游列表（跳过含 fakeip 的规则，无匹配回退 default 中非 fakeip 部分）。
    /// 对齐 mihomo 并发 DNS：返回的列表可能含多个上游，调用方并发查询。
    ///
    /// `qtype`：按 strategy 决定的查询类型（A=1 / AAAA=28）。旧实现硬编码 qtype=1，
    /// 导致 strategy=Ipv6Only 时 AAAA 查询无法命中带 `query_type: [AAAA]` 过滤的
    /// DNS 规则——规则匹配用的 qtype 与实际查询的 qtype 不一致。对齐 mihomo
    /// `resolver.Lookup`：规则匹配传入实际查询类型。
    /// 缓存键也包含 qtype，避免 A / AAAA 规则分流的域名共享同一缓存条目。
    fn select_resolve_upstreams(&self, host: &str, qtype: u16) -> Vec<Arc<DnsUpstream>> {
        // 一次性归一化 host，所有规则复用同一结果，避免重复 trim/lower。
        let host_norm = crate::router::normalize_domain(host);
        // 缓存键包含 qtype：同一域名的 A / AAAA 查询可能命中不同规则
        // （query_type 过滤的规则），不能共享缓存条目。
        let host_key = format!("{host_norm}\x00{qtype}");

        // 查 upstream LRU 缓存：同一域名+qtype 多次解析时跳过规则匹配
        if let Some(cached) = self.upstream_cache.lock().unwrap().get(&host_key) {
            return cached.clone();
        }

        let current_mode = self.clash_mode.get();
        // 使用入站分桶归并遍历，inbound_tag 传空（解析场景无特定入站）
        if let Some(idx) = self.match_dns_rule("", &host_norm, qtype, &current_mode) {
            let r = &self.rules[idx];
            if r.upstreams
                .iter()
                .all(|u| !matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
            {
                let result = r.upstreams.clone();
                self.upstream_cache
                    .lock()
                    .unwrap()
                    .put(host_key, result.clone());
                return result;
            }
        }
        // 无匹配规则：使用 default，但过滤掉 fakeip 上游
        let filtered: Vec<Arc<DnsUpstream>> = self
            .default
            .iter()
            .filter(|u| !matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            self.upstream_cache
                .lock()
                .unwrap()
                .put(host_key, filtered.clone());
            return filtered;
        }
        // default 全是 fakeip：回退到 upstreams map 中第一个非 fakeip upstream
        if let Some(u) = self
            .upstreams
            .values()
            .find(|u| !matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
        {
            let result = vec![u.clone()];
            self.upstream_cache
                .lock()
                .unwrap()
                .put(host_key, result.clone());
            return result;
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

    /// `resolve_proxy_domain` 的防环版本：`self_outbound_tag` 为正在建立连接的
    /// 出站 tag。若配置了 `proxy_domain_resolver`，会过滤掉其中 detour 指向
    /// 该出站自身的 server tag；未配置时走 `resolve_domain_for_outbound`
    /// （按规则选择上游并做同样的防环过滤）。
    ///
    /// 详见 `resolve_domain_for_outbound` 的注释：不过滤时，「建立代理连接 →
    /// 解析代理服务器域名 → DNS 查询又 detour 到同一代理」会形成永久死锁。
    pub async fn resolve_proxy_domain_for_outbound(
        &self,
        host: &str,
        self_outbound_tag: &str,
    ) -> anyhow::Result<std::net::IpAddr> {
        match &self.proxy_domain_resolver {
            Some(cfg) => {
                let strategy = cfg.strategy.unwrap_or(self.strategy);
                // 防环：过滤掉 detour 指向自身的 server tag
                let server_tags = cfg.server.as_slice();
                let mut tags: Vec<String> = Vec::with_capacity(server_tags.len());
                for t in server_tags {
                    let loops = self
                        .upstreams
                        .get(t)
                        .and_then(|u| u.detour_tag())
                        .map(|d| d == self_outbound_tag)
                        .unwrap_or(false);
                    if loops {
                        tracing::warn!(
                            server_tag = %t,
                            outbound = %self_outbound_tag,
                            "dns: proxy_domain_resolver tag detours via the outbound \
                             being dialed, excluded to break the resolution loop"
                        );
                        continue;
                    }
                    tags.push(t.clone());
                }
                if tags.is_empty() {
                    anyhow::bail!(
                        "dns anti-loop: all proxy_domain_resolver servers detour via \
                         outbound '{self_outbound_tag}' itself; cannot resolve '{host}'"
                    );
                }
                self.resolve_domain_with_options(host, &tags, strategy, cfg.disable_cache)
                    .await
            }
            None => self.resolve_domain_for_outbound(host, self_outbound_tag).await,
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
        // Clash API 直查：不走路由规则，沿用各 default upstream 的 server 级 ECS。
        let resp = race_upstreams(&self.default, &msg, None)
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
                    // block 规则的 drop 方法：静默丢弃查询，不返回任何响应。
                    // 对齐 sing-box `RuleActionRejectMethodDrop` → `tun.ErrDrop`。
                    Err(e) if e.downcast_ref::<DnsDropError>().is_some() => {
                        debug!(from=%query.from, source=?source, "dns query dropped (block method=drop)");
                        // drop query.reply_tx 而不发送，inbound 端收到 Err 后
                        // 输出 "dns query dropped (no reply)" 日志，不返回任何 DNS 响应。
                        return;
                    }
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

        // ── 规则匹配，选择上游 ────────────────────────────────────────────────
        // 对齐 mihomo 并发 DNS：规则或 default 可指定多个 server tag，
        // 此时同时向所有上游发起查询，首个成功响应即返回。
        let current_mode = self.clash_mode.get();
        // 一次性归一化 qname（trim 末尾 '.' + ASCII 小写），所有规则复用，
        // 避免每条规则 / 每个 ruleset 在 RuleSet::match_domain 内重复归一化。
        let qname_norm = crate::router::normalize_domain(&qname);
        let matched = if self.rules.is_empty() {
            None
        } else {
            self.match_dns_rule(inbound_tag, &qname_norm, qtype, &current_mode)
                .map(|idx| &self.rules[idx])
        };

        // 提取匹配规则的 (upstreams, disable_cache, block, predefined, per_rule_strategy,
        //   rewrite_ttl, per_rule_client_subnet)。
        // 对齐 sing-box dns/router.go matchDNS：未匹配时使用 default 上游、
        // 不禁用缓存、无动作、无 per-rule 覆盖。
        let (
            upstreams,
            mut disable_cache,
            block,
            predefined,
            per_rule_strategy,
            rewrite_ttl,
            per_rule_client_subnet,
        ) = matched.map(|r| {
            (
                r.upstreams.clone(),
                r.disable_cache,
                r.block,
                r.predefined,
                r.strategy,
                r.rewrite_ttl,
                r.client_subnet,
            )
        }).unwrap_or_else(|| (self.default.clone(), false, None, None, None, None, None));

        // ── 应用 strategy 拒绝规则（对齐 sing-box client.go:117） ─────────────
        // strategy=Ipv6Only + A 查询     → 返回空 NOERROR（拒绝 A）
        // strategy=Ipv4Only + AAAA 查询  → 返回空 NOERROR（拒绝 AAAA）
        //
        // 这避免将「按策略不该返回的记录类型」的查询转发到上游，
        // 既减少上游负载，又防止应用拿到与 strategy 矛盾的地址。
        //
        // per_rule_strategy（对齐 sing-box `DNSRouteActionOptions.Strategy`）：
        // 命中规则时若声明了 strategy，覆盖全局 self.strategy。
        // None 表示沿用全局策略（对齐 sing-box `DomainStrategyAsIS`）。
        let effective_strategy = per_rule_strategy.unwrap_or(self.strategy);
        if (qtype == 1 && matches!(effective_strategy, ResolveStrategy::Ipv6Only))
            || (qtype == 28 && matches!(effective_strategy, ResolveStrategy::Ipv4Only))
        {
            debug!(
                qname=%qname,
                qtype=qtype,
                strategy=?effective_strategy,
                per_rule=?per_rule_strategy,
                "strategy rejected: returning empty NOERROR"
            );
            return Ok(make_noerror_empty(&msg));
        }

        // ── block 动作：直接返回固定 rcode，跳过上游查询与缓存 ────────────
        // 对齐 sing-box dns.rule `action: "block"`：用于广告/追踪域名屏蔽，
        // 无需单独声明 rcode:// block server。
        // `drop` 方法静默丢弃查询（对齐 sing-box `RuleActionRejectMethodDrop`）：
        // 返回 DnsDropError，由 run() / clash_api 识别后跳过响应。
        if let Some(action) = block {
            debug!(qname=%qname, qtype=qtype, rcode=?action, "dns rule block");
            return match action {
                crate::config::dns::RcodeAction::Refused => Ok(make_refused(&msg)),
                crate::config::dns::RcodeAction::Success => Ok(make_noerror_empty(&msg)),
                crate::config::dns::RcodeAction::NxDomain => Ok(make_nxdomain(&msg)),
                crate::config::dns::RcodeAction::Drop => {
                    Err(anyhow::Error::from(DnsDropError))
                }
            };
        }

        // ── predefined 动作：直接返回指定 rcode 的响应 ────────────────────
        // 对齐 sing-box `option.DNSRouteActionPredefined`：返回指定 rcode 的
        // DNS 响应，不查询上游、不查缓存。仅支持 rcode 字段（success/refused/nxdomain/drop）。
        if let Some(rcode) = predefined {
            debug!(qname=%qname, qtype=qtype, rcode=?rcode, "dns rule predefined");
            return match rcode {
                crate::config::dns::RcodeAction::Refused => Ok(make_refused(&msg)),
                crate::config::dns::RcodeAction::Success => Ok(make_noerror_empty(&msg)),
                crate::config::dns::RcodeAction::NxDomain => Ok(make_nxdomain(&msg)),
                // predefined drop 与 block drop 等价：静默丢弃查询。
                crate::config::dns::RcodeAction::Drop => {
                    Err(anyhow::Error::from(DnsDropError))
                }
            };
        }

        // ── D-1: FakeIP 上游强制禁用缓存（对齐 sing-box dns/router.go:160）───
        // sing-box 在 matchDNS 中：`if isFakeIP || action.DisableCache { ... }`
        // FakeIP upstream 的"响应"由本机生成，不依赖上游网络，且每次查询
        // 可能分配新的假 IP。若启用缓存，多次查询同一域名会复用同一假 IP，
        // 失去 FakeIP 的"每连接独立 IP"语义，且缓存过期后假 IP 仍可能被引用，
        // 导致 fakeip store 反查时找不到记录。
        if !disable_cache
            && upstreams
                .iter()
                .any(|u| matches!(u.kind, upstream::UpstreamKind::FakeIp { .. }))
        {
            debug!(
                qname=%qname,
                transport=%compose_transport_tag(&upstreams),
                "dns cache force-disabled: matched upstream is fakeip"
            );
            disable_cache = true;
        }

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
                    // per-rule 覆盖随后台刷新任务一起捕获（均为 Copy），
                    // 确保后台刷新与前台查询行为一致（ECS / rewrite_ttl）。
                    let ecs2 = per_rule_client_subnet;
                    let rewrite_ttl2 = rewrite_ttl;
                    tokio::spawn(async move {
                        // 先尝试成为 inflight leader：若已有 leader 在刷新则直接退出
                        match cache2.try_lead_inflight(&transport_tag2, &qname2, qtype) {
                            InflightResult::Waiter(_) => {
                                // 已有 leader 在刷新，本后台任务无需再查
                                debug!(qname=%qname2, "optimistic refresh: inflight leader exists, skip");
                            }
                            InflightResult::Leader => {
                                match race_upstreams(&upstreams2, &msg2, ecs2).await {
                                    Ok(resp) => {
                                        // 对齐 sing-box client.go:307-319：rewrite_ttl 设定时
                                        // 重写 RR TTL 并以此作为缓存 TTL；否则取 min/SOA TTL。
                                        let (resp, ttl) =
                                            finalize_resp_ttl(resp, rewrite_ttl2);
                                        if is_cacheable_or_negative(&resp) {
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
                    let resp =
                        race_upstreams(&upstreams, &msg, per_rule_client_subnet).await;
                    match resp {
                        Ok(resp) => {
                            // 对齐 sing-box client.go:307-319：rewrite_ttl 设定时
                            // 重写 RR TTL 并以此作为缓存 TTL；否则取 min/SOA TTL。
                            let (resp, ttl) = finalize_resp_ttl(resp, rewrite_ttl);
                            if is_cacheable_or_negative(&resp) {
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
        let resp = race_upstreams(&upstreams, &msg, per_rule_client_subnet).await?;
        // 对齐 sing-box client.go:307-319：rewrite_ttl 设定时重写 RR TTL。
        // 无缓存路径不写入缓存，但仍需把重写后的 resp 返回给客户端。
        let (resp, _ttl) = finalize_resp_ttl(resp, rewrite_ttl);
        Ok(resp)
    }
}

// ── 并发查询辅助 ──────────────────────────────────────────────────────────────
//
// 对齐 mihomo 的并发 DNS 解析：当一组上游被配置为并发查询时，同时向所有上游
// 发起相同查询，首个返回 Ok 的上游结果即被采用，其余查询在 drop 时被取消。
// 全部失败时返回最后一个错误（保留 anyhow::Error 链）。
//
// 单上游时走快速路径，直接调用 `upstream.query_with_ecs`，避免 FuturesUnordered 开销。

/// `ecs_override`：per-rule EDNS Client Subnet 覆盖（对齐 sing-box
/// `option.DNSRouteActionOptions.ClientSubnet`）。
/// Some 时注入到查询并覆盖 server 级 client_subnet；None 时沿用 server 级。
async fn race_upstreams(
    upstreams: &[Arc<DnsUpstream>],
    msg: &Bytes,
    ecs_override: Option<(std::net::IpAddr, u8)>,
) -> anyhow::Result<Bytes> {
    if upstreams.is_empty() {
        anyhow::bail!("race_upstreams: no upstream configured");
    }
    // 快速路径：单上游直接查询
    if upstreams.len() == 1 {
        return upstreams[0].query_with_ecs(msg.clone(), ecs_override).await;
    }
    // 并发路径：FuturesUnordered + 首个 Ok 返回，其余 drop 取消
    let mut futures: FuturesUnordered<_> = upstreams
        .iter()
        .map(|up| up.query_with_ecs(msg.clone(), ecs_override))
        .collect();
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
///
/// OPT（EDNS0, TYPE=41）记录的"TTL"字段实际是 extended-RCODE + version + DO + z
/// （RFC 6891），并非 TTL，必须跳过 —— 对齐 sing-box client.go:312-314
/// `if record.Header().Rrtype == dns.TypeOPT { continue }`。
/// 旧实现未跳过 OPT，会把 OPT 的 extended-RCODE/flags 当作 TTL 改写，破坏 EDNS0 协商。
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
        // OPT（EDNS0, TYPE=41）的 TTL 字段是 extended-RCODE/flags，不可当 TTL 改写。
        // 对齐 sing-box client.go:312-314 跳过 TypeOPT。
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        if rtype != 41 {
            // 重写 TTL
            buf[pos + 4..pos + 8].copy_from_slice(&ttl_bytes);
        }
        let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10 + rdlength;
    }

    Bytes::from(buf)
}

/// 对齐 sing-box client.go:289-319：计算缓存存储 / 返回客户端用的 TTL，
/// 并在 `rewrite_ttl` 设定时把响应中所有 RR 的 TTL 重写为该值（跳过 OPT）。
///
/// - `rewrite_ttl = Some(t)`：ttl = t，重写 resp 的 RR TTL 为 t（缓存命中时由
///   `rewrite_response_ttls` 按 remaining 递减，与存储值 t 一致）。
/// - `rewrite_ttl = None`：ttl = `extract_min_ttl_or_negative(resp).unwrap_or(60)`，
///   不重写 resp（沿用上游原始 TTL 返回；缓存命中时仍由 cache.rs 递减）。
///
/// 返回 `(可能重写后的 resp, 缓存存储 ttl)`。调用方用前者返回客户端、存入缓存，
/// 用后者作为 `DnsCache::set` 的 ttl 参数。
fn finalize_resp_ttl(resp: Bytes, rewrite_ttl: Option<u32>) -> (Bytes, u32) {
    match rewrite_ttl {
        Some(t) => (rewrite_response_ttls(&resp, t), t),
        None => {
            // 先取 TTL 再移动 resp，避免 borrow-after-move。
            let ttl = extract_min_ttl_or_negative(&resp).unwrap_or(60);
            (resp, ttl)
        }
    }
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

    #[test]
    fn rewrite_response_ttls_skips_opt_record() {
        // OPT（EDNS0, TYPE=41）的"TTL"字段是 extended-RCODE + version + DO + flags
        // （RFC 6891），不可当作 TTL 改写。对齐 sing-box client.go:312-314 跳过 TypeOPT。
        //
        // 构造：1 条 A 记录（TTL=3600）+ 1 条 OPT 记录（Additional 段，
        // ext-rcode=0, version=0, DO=1 → flags 字节 = 0x80）。
        let mut resp = make_response_with_records("example.com", 1, &[(1, vec![1, 2, 3, 4])]);
        // ARCOUNT: 0 → 1
        resp[10] = 0x00;
        resp[11] = 0x01;
        // 追加 OPT RR：NAME=root, TYPE=41, CLASS=4096(UDPsize), TTL=0x00000080(DO),
        // RDLENGTH=0
        resp.extend_from_slice(&[
            0x00,             // NAME: root
            0x00, 0x29,       // TYPE: OPT (41)
            0x10, 0x00,       // CLASS: UDP payload size 4096
            0x00, 0x00, 0x00, 0x80, // "TTL": ext-rcode=0, version=0, flags=0x80 (DO bit)
            0x00, 0x00,       // RDLENGTH: 0
        ]);

        // 直接搜索 OPT "TTL" 字节序列（00 00 00 80）定位，避免手算偏移易错。
        let opt_ttl_pos = resp
            .windows(4)
            .position(|w| w == [0x00, 0x00, 0x00, 0x80])
            .expect("OPT TTL bytes should be present before rewrite");

        let rewritten = rewrite_response_ttls(&resp, 100);

        // A 记录 TTL 被重写为 100
        assert_eq!(extract_min_ttl(&rewritten), Some(100));
        // OPT 的 extended-RCODE/flags 字节保持不变（未被当作 TTL 改写）
        assert_eq!(
            &rewritten[opt_ttl_pos..opt_ttl_pos + 4],
            &[0x00, 0x00, 0x00, 0x80],
            "OPT extended-RCODE/flags must not be rewritten as TTL"
        );
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
