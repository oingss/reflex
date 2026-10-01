use std::collections::HashMap;
use std::sync::Arc;

use ahash::AHashSet;
use smallvec::SmallVec;

use crate::config::dns::{DnsQueryType, DnsRuleAction, DnsRuleConfig, RcodeAction, ResolveStrategy};
use crate::dns::upstream::{DnsUpstream, UpstreamKind};
use crate::ruleset::RuleSet;

pub(super) struct CompiledDnsRule {
    pub(super) inbound_tags: AHashSet<String>,
    pub(super) query_types: SmallVec<[u16; 4]>,
    pub(super) inline_rs: Option<Arc<RuleSet>>,
    pub(super) file_rulesets: Vec<Arc<RuleSet>>,
    /// 命中规则后并发查询的上游列表（对齐 mihomo 并发 DNS）。
    /// 单元素时走快速路径，多元素时 race 返回首个成功响应。
    /// block / predefined 动作时为空。
    pub(super) upstreams: Vec<Arc<DnsUpstream>>,
    pub(super) disable_cache: bool,
    /// block 动作：命中后直接返回固定 rcode（不查询上游、不查缓存）。
    /// 含 `Drop` 变体：静默丢弃查询，不返回任何响应（对齐 sing-box
    /// `RuleActionRejectMethodDrop`）。None 表示非 block 规则。
    pub(super) block: Option<RcodeAction>,
    /// predefined 动作：命中后直接返回指定 rcode 的响应（不查询上游、不查缓存）。
    /// 对齐 sing-box `option.DNSRouteActionPredefined`：与 block 行为相似但语义独立。
    /// None 表示非 predefined 规则。
    pub(super) predefined: Option<RcodeAction>,
    /// 该规则的解析策略（覆盖全局 `dns.strategy`）。
    /// None 表示沿用全局策略（对齐 sing-box `DomainStrategyAsIS`）。
    /// 对齐 sing-box `option.DNSRouteActionOptions.Strategy`：影响 A/AAAA 拒绝规则。
    pub(super) strategy: Option<ResolveStrategy>,
    /// 重写响应中所有 RR 的 TTL 为该值（秒），跳过 OPT 记录。
    /// 对齐 sing-box `option.DNSRouteActionOptions.RewriteTTL`（client.go:307-316）：
    /// Some 时上游返回 TTL 被统一覆盖，并作为缓存存储 TTL；None 时不重写。
    pub(super) rewrite_ttl: Option<u32>,
    /// EDNS Client Subnet per-rule 覆盖（RFC 7871）。
    /// 对齐 sing-box `option.DNSRouteActionOptions.ClientSubnet`：Some 时
    /// 查询前注入 EDNS0_SUBNET，优先级高于 server 级 `DnsUpstream::client_subnet`；
    /// None 时沿用 server 级。block / predefined 动作时无意义（不查询上游）。
    pub(super) client_subnet: Option<(std::net::IpAddr, u8)>,
    /// 仅当 Clash API 当前模式等于该值时才命中（对应 `clash_mode`），
    /// 大小写不敏感比较；None 表示不限制模式。与主路由规则的 `clash_mode`
    /// 语义一致，见 `router::CompiledRule`。
    pub(super) clash_mode_filter: Option<String>,
}

impl CompiledDnsRule {
    pub(super) fn compile(
        rule: &DnsRuleConfig,
        upstreams: &HashMap<String, Arc<DnsUpstream>>,
        preloaded: &HashMap<String, Arc<RuleSet>>,
    ) -> anyhow::Result<Self> {
        // ── 动作解析：action 唯一决定（反序列化后恒为 Some）──────────────
        let (compiled_upstreams, block, predefined, strategy, rewrite_ttl, client_subnet) =
            match rule.action.as_ref() {
                Some(DnsRuleAction::Route {
                    server,
                    strategy,
                    rewrite_ttl,
                    client_subnet,
                }) => {
                    // per-rule client_subnet：解析 CIDR 字符串，复用 server 级解析器。
                    // 解析失败（None）时 warn 并降级为"不覆盖"（沿用 server 级），
                    // 与 DnsUpstream 构造时 parse_client_subnet 失败的语义一致。
                    let cs = client_subnet
                        .as_deref()
                        .and_then(crate::dns::upstream::parse_client_subnet);
                    (
                        resolve_server_ref(server.as_slice(), upstreams, "dns.rules[].server")?,
                        None,
                        None,
                        *strategy,
                        *rewrite_ttl,
                        cs,
                    )
                }
                Some(DnsRuleAction::Block { method }) => {
                    // 对齐项目既有 block-dns server（rcode://refused）的默认语义
                    (
                        Vec::new(),
                        Some(method.unwrap_or(RcodeAction::Refused)),
                        None,
                        None,
                        None,
                        None,
                    )
                }
                Some(DnsRuleAction::Predefined { rcode }) => {
                    // 对齐 sing-box `PredefinedOptions.Rcode`：缺省 NOERROR（success）
                    (
                        Vec::new(),
                        None,
                        Some(rcode.unwrap_or(RcodeAction::Success)),
                        None,
                        None,
                        None,
                    )
                }
                None => {
                    anyhow::bail!(
                        "dns rule: missing `action` (defaults to route with required server)"
                    )
                }
            };

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
            inbound_tags: rule.inbound.iter().cloned().collect(),
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
            upstreams: compiled_upstreams,
            disable_cache: rule.disable_cache,
            block,
            predefined,
            strategy,
            rewrite_ttl,
            client_subnet,
            clash_mode_filter: rule.clash_mode.clone(),
        })
    }

    /// DNS 规则匹配：检查 inbound_tag / qtype / clash_mode 等过滤条件，
    /// 以及 inline_rs / file_rulesets 的域名匹配。
    ///
    /// 调用方负责对 qname 做一次性归一化（trim 末尾 '.' + ASCII 小写），
    /// 复用同一结果给所有 rules，避免每条规则 / 每个 ruleset 重复 trim/lower。
    /// 对齐 router/mod.rs 的 match_rulesets 优化思路。
    pub(super) fn matches_normalized(
        &self,
        inbound_tag: &str,
        qname_norm: &str,
        qtype: u16,
        current_mode: &str,
    ) -> bool {
        // Clash API 模式过滤（不受其他条件影响的硬性前置过滤）。
        if let Some(mode) = &self.clash_mode_filter {
            if !mode.eq_ignore_ascii_case(current_mode) {
                return false;
            }
        }
        if !self.inbound_tags.is_empty() && !self.inbound_tags.contains(inbound_tag) {
            return false;
        }
        if !self.query_types.is_empty() && !self.query_types.contains(&qtype) {
            return false;
        }
        let has_cond = self.inline_rs.is_some() || !self.file_rulesets.is_empty();
        if has_cond {
            // 直接调用 match_domain_normalized，复用调用方已归一化的 qname，
            // 避免每条规则 / 每个 ruleset 重复 trim/lower。
            let hit = self
                .inline_rs
                .as_ref()
                .is_some_and(|rs| rs.match_domain_normalized(qname_norm))
                || self
                    .file_rulesets
                    .iter()
                    .any(|rs| rs.match_domain_normalized(qname_norm));
            if !hit {
                return false;
            }
        }
        true
    }
}

// ── server tag 引用解析与校验 ─────────────────────────────────────────────────
//
// 将 `DnsServerRef`（字符串或数组形式）解析为 `Vec<Arc<DnsUpstream>>`，并校验：
// 1. 每个 tag 必须在 `upstreams` 中存在
// 2. 多 tag（并发场景）时，任一 tag 不能是 `fakeip://` 或 `rcode://` 类型
//    （这两种类型无真正"查询"语义；fakeip 还有单例不变量，并发会破坏）
//
// `context` 用于错误消息中指明是哪个字段出错，例如 "dns.final" / "dns.rules[].server"。
pub(super) fn resolve_server_ref(
    tags: &[String],
    upstreams: &HashMap<String, Arc<DnsUpstream>>,
    context: &str,
) -> anyhow::Result<Vec<Arc<DnsUpstream>>> {
    if tags.is_empty() {
        anyhow::bail!("{}: server list cannot be empty", context);
    }
    let is_concurrent = tags.len() > 1;
    let mut result = Vec::with_capacity(tags.len());
    for tag in tags {
        let up = upstreams
            .get(tag)
            .ok_or_else(|| anyhow::anyhow!("{}: dns server '{}' not found", context, tag))?
            .clone();
        if is_concurrent
            && matches!(
                up.kind,
                UpstreamKind::Rcode { .. } | UpstreamKind::FakeIp { .. }
            )
        {
            anyhow::bail!(
                "{}: dns server '{}' has protocol rcode:// or fakeip:// which \
                 cannot be used in a concurrent server list (use single-string form only)",
                context,
                tag
            );
        }
        result.push(up);
    }
    Ok(result)
}

/// 由多个上游 tag 组合出缓存键（对齐 mihomo 并发场景的缓存隔离）。
/// 单元素时直接返回该 tag；多元素时按用户给定顺序拼接为 "local,remote"。
/// 顺序保持用户配置，确保同一组上游始终映射到同一缓存键。
pub(super) fn compose_transport_tag(upstreams: &[Arc<DnsUpstream>]) -> String {
    if upstreams.len() == 1 {
        upstreams[0].tag.clone()
    } else {
        upstreams
            .iter()
            .map(|u| u.tag.as_str())
            .collect::<Vec<_>>()
            .join(",")
    }
}
