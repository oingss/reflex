use std::{collections::HashMap, net::IpAddr, sync::Arc};

use regex::Regex;
use tracing::{debug, trace};

use crate::ruleset::{LoadedRuleSet, MatchTarget, RuleSet};

use crate::{
    app::process::{ProcessInfo, ProcessResolver},
    clash_mode::ClashMode,
    config::route::{NetworkFilter, RouteConfig, RouteRuleConfig, RuleSetType},
    experimental::{CacheFile, CacheFileReader},
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
};

// ── 路由决策 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Outbound(String),
    DnsOut,
    Sniff {
        timeout_ms: u64,
        override_destination: bool,
        sniff_types: Vec<crate::app::sniff::SniffType>,
        force_domain: Vec<String>,
        skip_domain: Vec<String>,
        skip_src_address: Vec<String>,
    },
    Resolve {
        server: Option<crate::config::dns::DnsServerRef>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteOptions {
    /// 命中后改写目标地址（IP 或域名），对齐 sing-box `override_address`。
    pub override_address: Option<String>,
    /// 命中后改写目标端口，对齐 sing-box `override_port`。
    pub override_port: Option<u16>,
    /// 命中后覆盖 UDP 会话空闲超时（秒），对齐 sing-box `udp_timeout`。
    pub udp_timeout: Option<u64>,
}

impl RouteOptions {
    /// 是否带有任何需要在转发前处理的覆盖项。
    pub fn is_empty(&self) -> bool {
        self.override_address.is_none()
            && self.override_port.is_none()
            && self.udp_timeout.is_none()
    }
}

// ── 规则集元数据（规则数量 + 加载时间）────────────────────────────────────────

#[derive(Clone)]
pub struct RuleSetMeta {
    /// 规则条目总数
    pub rule_count: usize,
    /// 最后加载/更新的 Unix 毫秒时间戳
    pub updated_at_ms: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── 网络出口配置（来自 route 顶层字段）────────────────────────────────────────

/// 路由层出口网络配置，暴露给 direct outbound 使用。
#[derive(Debug, Clone, Default)]
pub struct NetworkEgressConfig {
    /// 是否自动检测并绑定默认出口网络接口（对应 `route.auto_detect_interface`）
    pub auto_detect_interface: bool,
    /// 强制指定的出口接口名称（对应 `route.default_interface`）
    pub default_interface: Option<String>,
    /// 路由标记，用于 Linux 策略路由（对应 `route.default_mark`）
    pub default_mark: Option<u32>,
}

// ── 路由器 ────────────────────────────────────────────────────────────────────

pub struct Router {
    rules: Vec<CompiledRule>,
    /// 预计算：去掉 Sniff 动作的规则索引列表（供 route_skip_sniff 使用）
    idx_no_sniff: Vec<usize>,
    /// 预计算：去掉 Sniff+Resolve 动作的规则索引列表（供 route_skip_resolve 使用）
    idx_no_sniff_resolve: Vec<usize>,
    default: RouteAction,
    /// 已加载的规则集，供 DNS 模块共享
    pub rulesets: std::collections::HashMap<String, std::sync::Arc<RuleSet>>,
    /// 每个规则集的元数据（数量、更新时间）
    pub ruleset_meta: std::collections::HashMap<String, RuleSetMeta>,
    /// 原始配置，供刷新 remote 规则集时使用
    route_config: RouteConfig,
    /// 出口网络配置（auto_detect_interface / default_interface / default_mark）
    pub egress: NetworkEgressConfig,
    /// Clash API 当前模式的共享只读引用，供 `clash_mode` 规则条件匹配使用。
    clash_mode: Arc<ClashMode>,
    /// 进程查找器：用于 `process_name` / `process_path` 规则匹配。
    /// 仅当 `has_process_rules = true` 时 dispatcher 才会调用查找。
    process_resolver: Arc<ProcessResolver>,
    /// 是否存在任意 `process_name` / `process_path` 规则。
    /// 用于在 dispatcher 热路径上短路进程查找（无规则时直接跳过）。
    has_process_rules: bool,
    /// 全局 DNS 劫持开关（对应 `route.hijack_dns`）。
    /// 为 true 时 dispatcher 在调用 route_* 之前检查目标端口是否为 53，
    /// 命中则直接派发为 `RouteAction::DnsOut`，跳过整个路由表查找。
    hijack_dns_global: bool,
}

impl Router {
    pub fn from_config(
        config: &RouteConfig,
        cache_reader: Option<&CacheFileReader>,
        cache_writer: Option<&CacheFile>,
        clash_mode: Arc<ClashMode>,
    ) -> anyhow::Result<Self> {
        let mut rulesets: HashMap<String, Arc<RuleSet>> = HashMap::new();
        let mut ruleset_meta: HashMap<String, RuleSetMeta> = HashMap::new();
        for rs_ref in &config.rule_set {
            let rs = load_ruleset_ref(rs_ref, cache_reader, cache_writer)?;
            let rc = rs.rule_count();
            ruleset_meta.insert(
                rs_ref.tag.clone(),
                RuleSetMeta {
                    rule_count: rc,
                    updated_at_ms: now_ms(),
                },
            );
            rulesets.insert(rs_ref.tag.clone(), Arc::new(rs));
        }

        // 验证：hijack_dns=true 必须配合至少一个匹配条件
        for (i, r) in config.rules.iter().enumerate() {
            if r.hijack_dns && !r.has_conditions() {
                anyhow::bail!(
                    "route rule[{i}]: `hijack_dns: true` must be used with at least one \
                     matching condition (e.g. `protocol`, `inbound`, `network`, `port`). \
                     A bare `hijack_dns: true` with no conditions is not allowed."
                );
            }
        }

        let rules = config
            .rules
            .iter()
            .map(|r| CompiledRule::compile(r, &rulesets))
            .collect::<anyhow::Result<Vec<_>>>()?;

        // ── 预计算过滤索引 ──────────────────────────────────────────────────
        let idx_no_sniff: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(r.action, RouteAction::Sniff { .. }) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();

        let idx_no_sniff_resolve: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(
                    r.action,
                    RouteAction::Sniff { .. } | RouteAction::Resolve { .. }
                ) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();

        let default = to_action(&config.r#final);

        let egress = NetworkEgressConfig {
            auto_detect_interface: config.auto_detect_interface,
            default_interface: config.default_interface.clone(),
            default_mark: config.default_mark,
        };

        // 是否存在任意进程规则：若全无则 dispatcher 热路径上短路进程查找。
        let has_process_rules = config
            .rules
            .iter()
            .any(|r| !r.process_name.is_empty() || !r.process_path.is_empty());

        Ok(Self {
            rules,
            idx_no_sniff,
            idx_no_sniff_resolve,
            default,
            rulesets,
            ruleset_meta,
            route_config: config.clone(),
            egress,
            clash_mode,
            process_resolver: Arc::new(ProcessResolver::default()),
            has_process_rules,
            hijack_dns_global: config.hijack_dns,
        })
    }

    /// 返回进程查找器（供 dispatcher 在 `has_process_rules = true` 时调用）
    pub fn process_resolver(&self) -> &Arc<ProcessResolver> {
        &self.process_resolver
    }

    /// 是否配置了任意 `process_name` / `process_path` 规则。
    /// 用于在 dispatcher 热路径上短路进程查找。
    pub fn has_process_rules(&self) -> bool {
        self.has_process_rules
    }

    /// 是否启用了全局 DNS 劫持（`route.hijack_dns: true`）。
    /// 为 true 时 dispatcher 应在调用 route_* 之前对端口 53 流量短路到 DnsOut。
    pub fn hijack_dns_global(&self) -> bool {
        self.hijack_dns_global
    }

    /// 返回默认路由动作（用于 UDP 嗅探降级）
    pub fn default_action(&self) -> &RouteAction {
        &self.default
    }

    /// 重新下载并替换指定 remote 规则集。仅对 type=remote 的规则集有效。
    /// 成功后更新 rulesets 和 ruleset_meta。
    /// 注意：此方法会阻塞当前线程做网络下载，应在 tokio::task::spawn_blocking 里调用。
    pub fn reload_remote_ruleset(&mut self, tag: &str) -> anyhow::Result<()> {
        let rs_ref = self
            .route_config
            .rule_set
            .iter()
            .find(|r| r.tag == tag)
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}' not found"))?
            .clone();

        use crate::config::route::{RuleSetFormat, RuleSetType};
        if rs_ref.r#type != RuleSetType::Remote {
            anyhow::bail!("rule_set '{tag}' is not remote, cannot update");
        }

        let url = rs_ref
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}': missing url"))?;

        // 强制从网络重新下载（忽略磁盘缓存）
        let data = download_bytes(url, tag)?;

        let rs = if rs_ref.format == RuleSetFormat::Source {
            // source 格式：编译后更新，缓存原始文本
            let src = String::from_utf8(data).map_err(|e| {
                anyhow::anyhow!("rule_set '{tag}': downloaded source is not UTF-8: {e}")
            })?;
            if let Some(path) = &rs_ref.path {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(path, src.as_bytes()).ok();
                tracing::debug!(tag, path, "rule_set: refreshed source disk cache");
            }
            compile_source_to_ruleset(&src, tag)?
        } else {
            // binary 格式：覆盖磁盘缓存
            if let Some(path) = &rs_ref.path {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(path, &data).ok();
                tracing::debug!(tag, path, "rule_set: refreshed disk cache");
            }
            let loaded = crate::ruleset::LoadedRuleSet::from_bytes(&data)
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': parse error: {e}"))?;
            RuleSet::from_loaded(loaded)
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': load error: {e}"))?
        };

        let rc = rs.rule_count();
        self.rulesets.insert(tag.to_string(), Arc::new(rs));
        self.ruleset_meta.insert(
            tag.to_string(),
            RuleSetMeta {
                rule_count: rc,
                updated_at_ms: now_ms(),
            },
        );
        tracing::info!(tag, rule_count = rc, "rule_set: refreshed");
        Ok(())
    }

    pub fn route_tcp(
        &self,
        conn: &InboundTcpStream,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        self.route(
            &conn.inbound_tag,
            Some(NetworkKind::Tcp),
            &conn.target,
            conn.sniffed_protocol.as_deref(),
            conn.sniffed_domain.as_deref(),
            conn.stream.peer_addr().ok().map(|a| a.ip()),
            None,
            process_info,
        )
    }

    /// sniff 后重路由：使用 conn 自身的 target + sniffed_domain 多候选匹配。
    /// 不再需要外部传 target —— override_destination=false 时 target 保留原始值，
    /// override_destination=true 时 target 已被覆盖为 Domain，都从 conn 读。
    pub fn route_tcp_after_sniff(
        &self,
        conn: &InboundTcpStream,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        self.route_indexed(
            &self.idx_no_sniff,
            &conn.inbound_tag,
            Some(NetworkKind::Tcp),
            &conn.target,
            conn.sniffed_protocol.as_deref(),
            conn.sniffed_domain.as_deref(),
            conn.stream.peer_addr().ok().map(|a| a.ip()),
            None,
            process_info,
            "post-sniff",
        )
    }

    /// resolve 后重路由：保留 sniffed_domain + target + resolved_ip 全部候选。
    /// resolved_ip 来自 DNS 解析，与 target.Socket.ip（如果有）共同参与 IP 规则匹配。
    pub fn route_tcp_after_resolve(
        &self,
        conn: &InboundTcpStream,
        resolved_ip: Option<IpAddr>,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        self.route_indexed(
            &self.idx_no_sniff_resolve,
            &conn.inbound_tag,
            Some(NetworkKind::Tcp),
            &conn.target,
            conn.sniffed_protocol.as_deref(),
            conn.sniffed_domain.as_deref(),
            conn.stream.peer_addr().ok().map(|a| a.ip()),
            resolved_ip,
            process_info,
            "post-resolve",
        )
    }

    pub fn route_udp_after_resolve(
        &self,
        packet: &InboundUdpPacket,
        resolved_ip: Option<IpAddr>,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        self.route_indexed(
            &self.idx_no_sniff_resolve,
            &packet.inbound_tag,
            Some(NetworkKind::Udp),
            &packet.target,
            packet.sniffed_protocol.as_deref(),
            packet.sniffed_domain.as_deref(),
            Some(packet.src.ip()),
            resolved_ip,
            process_info,
            "post-resolve",
        )
    }

    /// UDP 命中 Sniff 规则后重新路由：跳过所有 Sniff 规则，继续匹配后续规则。
    /// 与 TCP 的 route_tcp_after_sniff 对称，使用 conn 自身的多候选匹配。
    pub fn route_udp_after_sniff(
        &self,
        packet: &InboundUdpPacket,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        self.route_indexed(
            &self.idx_no_sniff,
            &packet.inbound_tag,
            Some(NetworkKind::Udp),
            &packet.target,
            packet.sniffed_protocol.as_deref(),
            packet.sniffed_domain.as_deref(),
            Some(packet.src.ip()),
            None,
            process_info,
            "post-sniff(udp)",
        )
    }

    pub fn route_udp(
        &self,
        packet: &InboundUdpPacket,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        self.route(
            &packet.inbound_tag,
            Some(NetworkKind::Udp),
            &packet.target,
            packet.sniffed_protocol.as_deref(),
            packet.sniffed_domain.as_deref(),
            Some(packet.src.ip()),
            None,
            process_info,
        )
    }

    /// 全量规则遍历（普通路由）
    #[allow(clippy::too_many_arguments)]
    fn route(
        &self,
        inbound_tag: &str,
        network: Option<NetworkKind>,
        target: &Target,
        sniffed_protocol: Option<&str>,
        sniffed_domain: Option<&str>,
        src_ip: Option<IpAddr>,
        resolved_ip: Option<IpAddr>,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        // 只读一次当前 Clash API 模式，避免在循环里反复加读锁。
        let current_mode = self.clash_mode.get();
        for rule in &self.rules {
            if rule.matches(
                inbound_tag,
                network,
                target,
                sniffed_protocol,
                sniffed_domain,
                src_ip,
                resolved_ip,
                process_info,
                &current_mode,
            ) {
                trace!(inbound=%inbound_tag, target=%target, action=?rule.action, "route hit");
                return (
                    &rule.action,
                    &rule.rule_display.0,
                    &rule.rule_display.1,
                    &rule.options,
                );
            }
        }
        debug!(inbound=%inbound_tag, target=%target, action=?self.default, "route default");
        (&self.default, "final", "", &EMPTY_ROUTE_OPTIONS)
    }

    /// 按预计算索引遍历（跳过特定 action 规则，零分支判断）
    #[allow(clippy::too_many_arguments)]
    fn route_indexed(
        &self,
        indices: &[usize],
        inbound_tag: &str,
        network: Option<NetworkKind>,
        target: &Target,
        sniffed_protocol: Option<&str>,
        sniffed_domain: Option<&str>,
        src_ip: Option<IpAddr>,
        resolved_ip: Option<IpAddr>,
        process_info: Option<&ProcessInfo>,
        label: &str,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        let current_mode = self.clash_mode.get();
        for &i in indices {
            let rule = &self.rules[i];
            if rule.matches(
                inbound_tag,
                network,
                target,
                sniffed_protocol,
                sniffed_domain,
                src_ip,
                resolved_ip,
                process_info,
                &current_mode,
            ) {
                trace!(inbound=%inbound_tag, target=%target, action=?rule.action, label, "route hit");
                return (
                    &rule.action,
                    &rule.rule_display.0,
                    &rule.rule_display.1,
                    &rule.options,
                );
            }
        }
        debug!(inbound=%inbound_tag, target=%target, action=?self.default, label, "route default");
        (&self.default, "final", "", &EMPTY_ROUTE_OPTIONS)
    }
}

/// `final` 兜底动作没有对应的规则配置，因此没有 options；用一个静态空值
/// 避免每次调用都构造一个临时 `RouteOptions`。
static EMPTY_ROUTE_OPTIONS: RouteOptions = RouteOptions {
    override_address: None,
    override_port: None,
    udp_timeout: None,
};

// ── 编译后的单条规则 ──────────────────────────────────────────────────────────

struct CompiledRule {
    inbound_tags: Vec<String>,
    network: Option<NetworkFilter>,
    protocols: Vec<String>,
    rulesets: Vec<Arc<RuleSet>>,
    addr_rs: Option<Arc<RuleSet>>,
    port_rs: Option<Arc<RuleSet>>,
    /// 来源 IP CIDR 规则集（对应 `source_ip_cidr`）
    source_rs: Option<Arc<RuleSet>>,
    /// 预编译的域名正则列表（对应 `domain_regex`，大小写不敏感）
    domain_regex: Vec<Regex>,
    /// 是否启用私有 IP 直连匹配
    private_ip: bool,
    /// 进程名匹配列表（对应 `process_name`，OR 语义，大小写敏感完整匹配）
    process_names: Vec<String>,
    /// 进程路径匹配列表（对应 `process_path`，OR 语义，子串包含匹配）
    process_paths: Vec<String>,
    /// 反转所有匹配条件（对应 `invert`）
    invert: bool,
    /// 仅当 Clash API 当前模式等于该值时才命中（对应 `clash_mode`），
    /// 大小写不敏感比较；None 表示不限制模式。
    clash_mode_filter: Option<String>,
    action: RouteAction,
    /// 命中后的动作精细化选项（override_address/override_port/udp_timeout）
    options: RouteOptions,
    rule_display: (String, String),
}

impl CompiledRule {
    fn compile(
        rule: &RouteRuleConfig,
        rulesets: &HashMap<String, Arc<RuleSet>>,
    ) -> anyhow::Result<Self> {
        let mut compiled_rulesets = Vec::new();
        for tag in &rule.ruleset {
            let rs = rulesets
                .get(tag)
                .ok_or_else(|| anyhow::anyhow!("ruleset '{tag}' not found"))?;
            compiled_rulesets.push(rs.clone());
        }

        // 地址类内联规则（目标地址）
        let addr_rs = {
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
            for c in &rule.ip_cidr {
                if c.contains(':') {
                    lines.push(format!("ip-cidr6: {c}"));
                } else {
                    lines.push(format!("ip-cidr: {c}"));
                }
            }
            if lines.is_empty() {
                None
            } else {
                Some(Arc::new(RuleSet::from_text(&lines.join("\n"))?))
            }
        };

        // 来源 IP CIDR 规则集（source_ip_cidr）
        let source_rs = {
            let mut lines = Vec::new();
            for c in &rule.source_ip_cidr {
                if c.contains(':') {
                    lines.push(format!("ip-cidr6: {c}"));
                } else {
                    lines.push(format!("ip-cidr: {c}"));
                }
            }
            if lines.is_empty() {
                None
            } else {
                Some(Arc::new(RuleSet::from_text(&lines.join("\n"))?))
            }
        };

        // 域名正则预编译（domain_regex，大小写不敏感）
        let domain_regex = rule
            .domain_regex
            .iter()
            .enumerate()
            .map(|(i, pattern)| {
                // 在 pattern 前加 (?i) 使其大小写不敏感，与 sing-box 行为对齐
                Regex::new(&format!("(?i){pattern}"))
                    .map_err(|e| anyhow::anyhow!("domain_regex[{i}] '{pattern}': {e}"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        // 端口类内联规则
        let port_rs = {
            let mut lines = Vec::new();
            for p in &rule.port {
                if p.0 == p.1 {
                    lines.push(format!("port: {}", p.0));
                } else {
                    lines.push(format!("port: {}-{}", p.0, p.1));
                }
            }
            for p in &rule.port_range {
                lines.push(format!("port: {p}"));
            }
            if lines.is_empty() {
                None
            } else {
                Some(Arc::new(RuleSet::from_text(&lines.join("\n"))?))
            }
        };

        let action = if rule.sniff {
            let sniff_types = rule
                .sniff_type
                .iter()
                .filter_map(|s| crate::app::sniff::SniffType::parse(s))
                .collect();
            RouteAction::Sniff {
                timeout_ms: rule.sniff_timeout_ms,
                override_destination: rule.sniff_override_destination,
                sniff_types,
                force_domain: rule.sniff_force_domain.clone(),
                skip_domain: rule.sniff_skip_domain.clone(),
                skip_src_address: rule.sniff_skip_src_address.clone(),
            }
        } else if rule.resolve {
            RouteAction::Resolve {
                server: rule.resolve_server.clone(),
            }
        } else if rule.hijack_dns {
            RouteAction::DnsOut
        } else if rule.private_ip && !rule.invert {
            // private_ip=true 时动作固定为直连，忽略 outbound 字段
            // 注意：invert=true 时语义被反转（"非私有 IP"才命中），
            // 此时不应强制走 direct，而应使用规则自身的 outbound 字段。
            RouteAction::Outbound("direct".to_string())
        } else {
            to_action(&rule.outbound)
        };

        let rule_display = if rule.private_ip
            && rule.ruleset.is_empty()
            && rule.domain.is_empty()
            && rule.domain_suffix.is_empty()
            && rule.domain_keyword.is_empty()
            && rule.domain_regex.is_empty()
            && rule.ip_cidr.is_empty()
            && rule.source_ip_cidr.is_empty()
        {
            ("PRIVATE-IP".to_string(), String::new())
        } else if !rule.ruleset.is_empty() {
            ("rule-set".to_string(), rule.ruleset.join(","))
        } else if !rule.domain.is_empty() {
            ("DOMAIN".to_string(), rule.domain.join(","))
        } else if !rule.domain_suffix.is_empty() {
            ("DOMAIN-SUFFIX".to_string(), rule.domain_suffix.join(","))
        } else if !rule.domain_keyword.is_empty() {
            ("DOMAIN-KEYWORD".to_string(), rule.domain_keyword.join(","))
        } else if !rule.domain_regex.is_empty() {
            ("DOMAIN-REGEX".to_string(), rule.domain_regex.join(","))
        } else if !rule.ip_cidr.is_empty() {
            ("IP-CIDR".to_string(), rule.ip_cidr.join(","))
        } else if !rule.source_ip_cidr.is_empty() {
            ("SRC-IP-CIDR".to_string(), rule.source_ip_cidr.join(","))
        } else if !rule.process_name.is_empty() {
            ("PROCESS-NAME".to_string(), rule.process_name.join(","))
        } else if !rule.process_path.is_empty() {
            ("PROCESS-PATH".to_string(), rule.process_path.join(","))
        } else if let Some(nf) = rule.network {
            (
                "NETWORK".to_string(),
                format!("{nf:?}").to_ascii_lowercase(),
            )
        } else if !rule.protocol.is_empty() {
            ("PROTOCOL".to_string(), rule.protocol.join(","))
        } else if !rule.inbound.is_empty() {
            ("IN-NAME".to_string(), rule.inbound.join(","))
        } else if rule.sniff {
            ("SNIFF".to_string(), String::new())
        } else if rule.resolve {
            ("RESOLVE".to_string(), String::new())
        } else if rule.hijack_dns {
            ("HIJACK-DNS".to_string(), String::new())
        } else if let Some(mode) = &rule.clash_mode {
            ("CLASH-MODE".to_string(), mode.clone())
        } else {
            ("MATCH".to_string(), String::new())
        };

        Ok(Self {
            inbound_tags: rule.inbound.clone(),
            network: rule.network,
            protocols: rule.protocol.iter().map(|s| s.to_lowercase()).collect(),
            rulesets: compiled_rulesets,
            addr_rs,
            port_rs,
            source_rs,
            domain_regex,
            private_ip: rule.private_ip,
            process_names: rule.process_name.clone(),
            process_paths: rule.process_path.clone(),
            invert: rule.invert,
            clash_mode_filter: rule.clash_mode.clone(),
            action,
            options: RouteOptions {
                override_address: rule.override_address.clone(),
                override_port: rule.override_port,
                udp_timeout: rule.udp_timeout,
            },
            rule_display,
        })
    }

    #[inline]
    #[allow(clippy::too_many_arguments)]
    fn matches(
        &self,
        inbound_tag: &str,
        network: Option<NetworkKind>,
        target: &Target,
        sniffed_protocol: Option<&str>,
        sniffed_domain: Option<&str>,
        src_ip: Option<IpAddr>,
        resolved_ip: Option<IpAddr>,
        process_info: Option<&ProcessInfo>,
        current_mode: &str,
    ) -> bool {
        // 0. Clash API 模式过滤（对应 `clash_mode`，不受 invert 影响）。
        //    和 sing-box route/rule/rule_item_clash_mode.go 一样，作为硬性
        //    前置条件处理：大小写不敏感比较，未配置时不限制。
        if let Some(mode) = &self.clash_mode_filter {
            if !mode.eq_ignore_ascii_case(current_mode) {
                return false;
            }
        }

        // 1. 入站 tag 过滤（不受 invert 影响）
        if !self.inbound_tags.is_empty() && !self.inbound_tags.iter().any(|t| t == inbound_tag) {
            return false;
        }

        // 2. 网络类型过滤（不受 invert 影响）
        if let Some(nf) = &self.network {
            match (nf, network) {
                (NetworkFilter::Tcp, Some(NetworkKind::Tcp)) => {}
                (NetworkFilter::Udp, Some(NetworkKind::Udp)) => {}
                _ => return false,
            }
        }

        // 3. 协议过滤（不受 invert 影响）
        // 优化：原实现 proto.to_lowercase() 每次匹配都分配新 String，
        // 改用 eq_ignore_ascii_case 逐个比较，零分配。
        // self.protocols 在编译期已 to_lowercase，比较时大小写不敏感即可。
        if !self.protocols.is_empty() {
            match sniffed_protocol {
                Some(proto) => {
                    if !self.protocols.iter().any(|p| p.eq_ignore_ascii_case(proto)) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // 4. 来源 IP CIDR 过滤（source_ip_cidr，不受 invert 影响）
        //    来源条件作为独立的 AND 约束，与目标条件互相独立。
        if let Some(src_rs) = &self.source_rs {
            match src_ip {
                Some(ip) => {
                    if !src_rs.matches(&MatchTarget::Ip(ip)) {
                        return false;
                    }
                }
                None => return false,
            }
        }

        // 5. 进程名/路径过滤（process_name / process_path，不受 invert 影响）。
        //    进程查找是 syscall 密集型操作，dispatcher 已根据
        //    `Router::has_process_rules()` 短路：无任何进程规则时不会做查找，
        //    本字段也必为空，本段直接跳过。
        //    匹配语义：
        //    - process_names 列表内 OR（任一完整相等即命中）
        //    - process_paths 列表内 OR（任一子串包含即命中）
        //    - 两者同时配置时 AND
        //    - 配置了但 process_info = None（不支持平台/未找到）→ 不命中
        if !self.process_names.is_empty() || !self.process_paths.is_empty() {
            let Some(info) = process_info else {
                return false;
            };
            if !self.process_names.is_empty() && !self.process_names.contains(&info.name) {
                return false;
            }
            if !self.process_paths.is_empty() {
                let path_str = info.path.as_deref().unwrap_or("");
                if !self.process_paths.iter().any(|p| path_str.contains(p)) {
                    return false;
                }
            }
        }

        // 6. 目标条件：多候选 OR 匹配（对齐 sing-box 的 Destination.Addr + Domain
        //    并存语义）。规则内不同类型的地址条件之间仍是 AND，但同一类型内
        //    多个候选之间是 OR。
        //    域名候选：sniffed_domain（优先）→ target.Domain
        //    IP 候选：target.Socket.ip → resolved_ip
        //    （FakeIP 反查后 target 已被改成 Domain，FakeIP 不会进入 IP 候选）
        //    各类条件"未配置"时自动视为满足，只有"已配置"的类别才必须命中。
        let has_ruleset = !self.rulesets.is_empty();
        let has_addr_rs = self.addr_rs.is_some();
        let has_port_rs = self.port_rs.is_some();
        let has_domain_regex = !self.domain_regex.is_empty();
        let has_private_ip = self.private_ip;

        let has_addr_rules = has_ruleset || has_addr_rs || has_port_rs || has_domain_regex;

        if has_addr_rules || has_private_ip {
            let port_val = target.port();

            let ruleset_ok =
                !has_ruleset || self.match_rulesets(sniffed_domain, target, resolved_ip, port_val);
            let addr_rs_ok = !has_addr_rs
                || self
                    .addr_rs
                    .as_ref()
                    .is_some_and(|rs| match_addr_rs(rs, sniffed_domain, target, resolved_ip));
            let port_rs_ok = !has_port_rs
                || self
                    .port_rs
                    .as_ref()
                    .is_some_and(|rs| rs.matches(&MatchTarget::Port(port_val)));
            let domain_regex_ok =
                !has_domain_regex || match_domain_regex(&self.domain_regex, sniffed_domain, target);
            let private_ip_ok = !has_private_ip || match_private_ip(target, resolved_ip);

            let matched =
                ruleset_ok && addr_rs_ok && port_rs_ok && domain_regex_ok && private_ip_ok;

            // 应用 invert
            if self.invert {
                if matched {
                    return false;
                }
            } else if !matched {
                return false;
            }
        } else if self.invert {
            // 无目标条件但 invert=true：视为"无条件命中后取反 = 永不命中"
            // 这与 sing-box 的语义一致，invert 在无条件时没有实际意义，
            // 但不应崩溃，直接返回 false 保持安全。
            return false;
        }

        true
    }

    /// ruleset 列表匹配：列表内多个 tag 之间是 OR；单个 ruleset 内部
    /// domain/ip 与 port 条目之间也按 OR 处理（任一命中即算该 ruleset 命中）。
    /// 多候选语义：域名候选（sniffed_domain → target.Domain）和 IP 候选
    /// （target.Socket.ip → resolved_ip）任一命中即算命中。
    ///
    /// 性能优化：
    /// 1. 域名候选在循环外一次性归一化（trim 末尾 '.' + ASCII 小写），
    ///    所有 rulesets 复用同一归一化结果，避免每个 ruleset 在
    ///    RuleSet::match_domain 内重复归一化同一域名。
    /// 2. 利用 RuleSet::has_domain_matchers / has_ip_matchers /
    ///    has_port_matchers 跳过不含对应匹配器的 ruleset，避免 MatchTarget
    ///    构造和无效 match_domain/match_ip 调用。
    /// 3. 域名匹配直接走 RuleSet::match_domain_normalized，避免 MatchTarget
    ///    enum 构造和 match dispatch。
    fn match_rulesets(
        &self,
        sniffed_domain: Option<&str>,
        target: &Target,
        resolved_ip: Option<IpAddr>,
        port_val: u16,
    ) -> bool {
        // 预归一化域名候选
        let sniffed_norm = sniffed_domain.map(normalize_domain);
        let target_domain_norm = match target {
            Target::Domain(h, _) => Some(normalize_domain(h)),
            _ => None,
        };
        // target.Socket.ip 提前取出一次，避免每次循环 match 重复提取
        let target_socket_ip = match target {
            Target::Socket(addr) => Some(addr.ip()),
            _ => None,
        };

        for rs in &self.rulesets {
            // 域名候选：sniffed_domain 优先，然后 target.Domain
            if rs.has_domain_matchers() {
                if let Some(d) = sniffed_norm.as_deref() {
                    if rs.match_domain_normalized(d) {
                        return true;
                    }
                }
                if let Some(d) = target_domain_norm.as_deref() {
                    if rs.match_domain_normalized(d) {
                        return true;
                    }
                }
            }

            // IP 候选：target.Socket.ip，然后 resolved_ip
            if rs.has_ip_matchers() {
                if let Some(ip) = target_socket_ip {
                    if rs.matches(&MatchTarget::Ip(ip)) {
                        return true;
                    }
                }
                if let Some(ip) = resolved_ip {
                    if rs.matches(&MatchTarget::Ip(ip)) {
                        return true;
                    }
                }
            }

            // 端口
            if rs.has_port_matchers() && rs.matches(&MatchTarget::Port(port_val)) {
                return true;
            }
        }
        false
    }
}

// ── 多候选匹配辅助函数 ──────────────────────────────────────────────────────

/// 将域名归一化：trim 末尾 '.' + ASCII 小写。
/// 仅在含有大写字母或末尾 '.' 时分配；多数情况（已是规范小写无 FQDN 点）
/// 直接返回 Cow::Borrowed，零分配。
#[inline]
pub(crate) fn normalize_domain(d: &str) -> std::borrow::Cow<'_, str> {
    let trimmed = d.trim_end_matches('.');
    if trimmed.bytes().any(|b| b.is_ascii_uppercase()) {
        std::borrow::Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        std::borrow::Cow::Borrowed(trimmed)
    }
}

/// 内联 addr_rs（domain/ip_cidr）多候选匹配：域名候选和 IP 候选任一命中即算命中。
///
/// 性能优化与 match_rulesets 同源：
/// 1. 域名候选先归一化再交给 RuleSet::match_domain_normalized，
///    避免每个 ruleset 重复 trim/lower。
/// 2. 利用 RuleSet::has_domain_matchers / has_ip_matchers 跳过空匹配器。
fn match_addr_rs(
    rs: &RuleSet,
    sniffed_domain: Option<&str>,
    target: &Target,
    resolved_ip: Option<IpAddr>,
) -> bool {
    // 域名候选
    if rs.has_domain_matchers() {
        if let Some(d) = sniffed_domain {
            let d_norm = normalize_domain(d);
            if rs.match_domain_normalized(&d_norm) {
                return true;
            }
        }
        if let Target::Domain(h, _) = target {
            let d_norm = normalize_domain(h);
            if rs.match_domain_normalized(&d_norm) {
                return true;
            }
        }
    }

    // IP 候选
    if rs.has_ip_matchers() {
        if let Target::Socket(addr) = target {
            if rs.matches(&MatchTarget::Ip(addr.ip())) {
                return true;
            }
        }
        if let Some(ip) = resolved_ip {
            if rs.matches(&MatchTarget::Ip(ip)) {
                return true;
            }
        }
    }

    false
}

/// domain_regex 列表匹配（大小写不敏感），列表内多个正则之间是 OR。
/// 多候选：sniffed_domain 和 target.Domain 都会被检查，任一命中即算命中。
fn match_domain_regex(regexes: &[Regex], sniffed_domain: Option<&str>, target: &Target) -> bool {
    // sniffed_domain 优先
    if let Some(d) = sniffed_domain {
        for re in regexes {
            if re.is_match(d) {
                return true;
            }
        }
    }
    // 然后检查 target.Domain
    if let Target::Domain(h, _) = target {
        for re in regexes {
            if re.is_match(h) {
                return true;
            }
        }
    }
    false
}

/// private_ip 多候选匹配：target.Socket.ip 和 resolved_ip 任一属于私有地址即算命中。
fn match_private_ip(target: &Target, resolved_ip: Option<IpAddr>) -> bool {
    if let Target::Socket(addr) = target {
        if is_private_ip(addr.ip()) {
            return true;
        }
    }
    if let Some(ip) = resolved_ip {
        if is_private_ip(ip) {
            return true;
        }
    }
    false
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn to_action(outbound: &str) -> RouteAction {
    if outbound == "dns-out" {
        RouteAction::DnsOut
    } else {
        RouteAction::Outbound(outbound.to_string())
    }
}

/// 判断一个 IP 地址是否属于私有/保留地址空间。
///
/// 覆盖范围（与 sing-box `ip_is_private` 对齐）：
/// - 回环：`127.0.0.0/8`，`::1/128`
/// - RFC 1918：`10.0.0.0/8`，`172.16.0.0/12`，`192.168.0.0/16`
/// - 链路本地：`169.254.0.0/16`，`fe80::/10`
/// - IPv6 ULA：`fc00::/7`
/// - 共享地址空间（RFC 6598）：`100.64.0.0/10`
/// - 本机网络：`0.0.0.0/8`
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            // 0.0.0.0/8
            o[0] == 0
            // 10.0.0.0/8
            || o[0] == 10
            // 100.64.0.0/10
            || (o[0] == 100 && (o[1] & 0xc0) == 64)
            // 127.0.0.0/8
            || o[0] == 127
            // 169.254.0.0/16
            || (o[0] == 169 && o[1] == 254)
            // 172.16.0.0/12
            || (o[0] == 172 && (o[1] & 0xf0) == 16)
            // 192.168.0.0/16
            || (o[0] == 192 && o[1] == 168)
        }
        std::net::IpAddr::V6(v6) => {
            let segs = v6.segments();
            // ::1/128
            v6.is_loopback()
            // fe80::/10（链路本地）
            || (segs[0] & 0xffc0) == 0xfe80
            // fc00::/7（ULA）
            || (segs[0] & 0xfe00) == 0xfc00
        }
    }
}

fn load_ruleset_ref(
    rs_ref: &crate::config::route::RuleSetRef,
    cache_reader: Option<&CacheFileReader>,
    cache_writer: Option<&CacheFile>,
) -> anyhow::Result<RuleSet> {
    match rs_ref.r#type {
        RuleSetType::Local => {
            let path = rs_ref.path.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "rule_set '{}': `path` is required when type = \"local\"",
                    rs_ref.tag
                )
            })?;
            load_ruleset_from_path(path, &rs_ref.tag, &rs_ref.format)
        }
        RuleSetType::Remote => {
            let url = rs_ref.url.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "rule_set '{}': `url` is required when type = \"remote\"",
                    rs_ref.tag
                )
            })?;
            load_ruleset_remote(
                url,
                rs_ref.path.as_deref(),
                rs_ref.download_detour.as_deref(),
                &rs_ref.tag,
                &rs_ref.format,
                cache_reader,
                cache_writer,
            )
        }
    }
}

/// 从本地文件加载规则集，支持 binary（.rrs）和 source（.json/.txt）格式。
fn load_ruleset_from_path(
    path: &str,
    tag: &str,
    format: &crate::config::route::RuleSetFormat,
) -> anyhow::Result<RuleSet> {
    use crate::config::route::RuleSetFormat;
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': failed to read file '{path}': {e}"))?;
    match format {
        RuleSetFormat::Binary => {
            let loaded = LoadedRuleSet::from_bytes(&data)?;
            Ok(RuleSet::from_loaded(loaded)?)
        }
        RuleSetFormat::Source => {
            let src = String::from_utf8(data).map_err(|e| {
                anyhow::anyhow!("rule_set '{tag}': source file is not valid UTF-8: {e}")
            })?;
            compile_source_to_ruleset(&src, tag)
        }
    }
}

/// 将文本、sing-box JSON 或 mihomo yaml Source Rule Set 编译为 RuleSet。
/// 自动检测格式：
/// - 以 `{` 开头 → sing-box JSON
/// - 首行以 `payload:` 开头 → mihomo / Clash yaml 规则集
/// - 其他 → Reflex 文本格式
fn compile_source_to_ruleset(src: &str, tag: &str) -> anyhow::Result<RuleSet> {
    use crate::ruleset::compiler::CompiledRuleSet;
    let trimmed = src.trim_start();
    let compiled = if trimmed.starts_with('{') {
        CompiledRuleSet::from_singbox_json(trimmed).map_err(|e| {
            anyhow::anyhow!("rule_set '{tag}': failed to parse sing-box JSON source: {e}")
        })?
    } else if looks_like_mihomo_yaml(trimmed) {
        CompiledRuleSet::from_mihomo_yaml(trimmed, None).map_err(|e| {
            anyhow::anyhow!("rule_set '{tag}': failed to parse mihomo yaml source: {e}")
        })?
    } else {
        CompiledRuleSet::from_text(trimmed)
            .map_err(|e| anyhow::anyhow!("rule_set '{tag}': failed to parse text source: {e}"))?
    };
    let mut buf = Vec::new();
    compiled.serialize(&mut buf).map_err(|e| {
        anyhow::anyhow!("rule_set '{tag}': failed to serialize compiled ruleset: {e}")
    })?;
    let loaded = LoadedRuleSet::from_bytes(&buf)
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': internal compile error: {e}"))?;
    Ok(RuleSet::from_loaded(loaded)?)
}

/// 探测给定文本是否是 mihomo / Clash 风格的 yaml 规则集。
///
/// 判别规则：trim 后首行以 `payload:` 或 `payload :` 开头（忽略大小写）。
/// 这种启发式足够覆盖 Loyalsoldier、Hackl0us 等主流规则仓库的发布格式。
fn looks_like_mihomo_yaml(src: &str) -> bool {
    let first_line = src.lines().next().unwrap_or("").trim_start();
    let lower = first_line.to_ascii_lowercase();
    lower.starts_with("payload:") || lower.starts_with("payload :")
}

/// 加载远程规则集，按以下优先级依次尝试：
///
/// 1. **`path` 磁盘缓存**
/// 2. **cache_file 持久化缓存**
/// 3. **网络下载**
fn load_ruleset_remote(
    url: &str,
    cache_path: Option<&str>,
    download_detour: Option<&str>,
    tag: &str,
    format: &crate::config::route::RuleSetFormat,
    cache_reader: Option<&CacheFileReader>,
    cache_writer: Option<&CacheFile>,
) -> anyhow::Result<RuleSet> {
    use crate::config::route::RuleSetFormat;
    // ── 1. path 磁盘缓存 ──────────────────────────────────────────────────
    if let Some(path) = cache_path {
        if std::path::Path::new(path).exists() {
            tracing::debug!(tag, path, "rule_set: loading from disk cache (path)");
            return load_ruleset_from_path(path, tag, format);
        }
    }

    // ── 2. cache_file 持久化缓存（仅 binary 格式；source 格式不缓存原始字节）──
    if cache_path.is_none() && *format == RuleSetFormat::Binary {
        if let Some(reader) = cache_reader {
            if let Some(data) = reader.load_ruleset_cache(tag) {
                tracing::debug!(tag, "rule_set: loading from cache_file (redb)");
                let loaded = LoadedRuleSet::from_bytes(&data).map_err(|e| {
                    anyhow::anyhow!(
                        "rule_set '{tag}': failed to parse cached data from cache_file: {e}"
                    )
                })?;
                return Ok(RuleSet::from_loaded(loaded)?);
            }
        }
    }

    // ── 3. 网络下载 ───────────────────────────────────────────────────────
    if let Some(detour) = download_detour {
        tracing::info!(tag, url, detour, "rule_set: downloading via detour");
    } else {
        tracing::info!(tag, url, "rule_set: downloading directly");
    }

    let data = download_bytes(url, tag)?;

    // source 格式：先编译，缓存原始 source 文本到磁盘（下次 load_ruleset_from_path 重新编译）
    if *format == RuleSetFormat::Source {
        let src = String::from_utf8(data).map_err(|e| {
            anyhow::anyhow!("rule_set '{tag}': downloaded source is not valid UTF-8: {e}")
        })?;
        // 写磁盘缓存（存 source 文本）
        if let Some(path) = cache_path {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent).ok();
            }
            std::fs::write(path, src.as_bytes()).ok();
            tracing::debug!(tag, path, "rule_set: saved source to disk cache");
        }
        return compile_source_to_ruleset(&src, tag);
    }

    // binary 格式：写缓存
    if let Some(path) = cache_path {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "rule_set '{tag}': failed to create cache dir '{}': {e}",
                    parent.display()
                )
            })?;
        }
        std::fs::write(path, &data).map_err(|e| {
            anyhow::anyhow!("rule_set '{tag}': failed to write disk cache to '{path}': {e}")
        })?;
        tracing::debug!(tag, path, "rule_set: saved to disk cache (path)");
    } else if let Some(writer) = cache_writer {
        writer.store_ruleset_entry(tag, data.clone());
        tracing::debug!(tag, "rule_set: saved to cache_file (redb)");
    } else {
        tracing::warn!(
            tag,
            url,
            "rule_set: no `path` and no cache_file configured; \
             ruleset is memory-only and will be re-downloaded on next startup"
        );
    }

    let loaded = LoadedRuleSet::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': failed to parse downloaded data: {e}"))?;
    Ok(RuleSet::from_loaded(loaded)?)
}

fn download_bytes(url: &str, tag: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    use std::time::Duration;
    // 旧实现无超时：慢速/挂起的服务器会无限阻塞调用线程。
    // 设置 30s 总超时（含连接阶段），与 sing-box downloadZIP 行为对齐。
    let resp = ureq::get(url)
        .timeout(Duration::from_secs(30))
        .call()
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': download failed from '{url}': {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf).map_err(|e| {
        anyhow::anyhow!("rule_set '{tag}': failed to read response body from '{url}': {e}")
    })?;
    Ok(buf)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkKind {
    Tcp,
    Udp,
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::route::{PortFilter, RouteRuleConfig};

    fn make_router(rules: Vec<RouteRuleConfig>, default: &str) -> Router {
        let rules_compiled: Vec<CompiledRule> = rules
            .iter()
            .map(|r| CompiledRule::compile(r, &HashMap::new()).unwrap())
            .collect();

        let idx_no_sniff: Vec<usize> = rules_compiled
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(r.action, RouteAction::Sniff { .. }) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();
        let idx_no_sniff_resolve: Vec<usize> = rules_compiled
            .iter()
            .enumerate()
            .filter_map(|(i, r)| {
                if matches!(
                    r.action,
                    RouteAction::Sniff { .. } | RouteAction::Resolve { .. }
                ) {
                    None
                } else {
                    Some(i)
                }
            })
            .collect();

        Router {
            rules: rules_compiled,
            idx_no_sniff,
            idx_no_sniff_resolve,
            default: RouteAction::Outbound(default.into()),
            rulesets: HashMap::new(),
            ruleset_meta: HashMap::new(),
            route_config: crate::config::route::RouteConfig {
                rules: vec![],
                r#final: String::new(),
                rule_set: vec![],
                resolve_dns: false,
                ipv6: true,
                auto_detect_interface: false,
                default_interface: None,
                default_mark: None,
                hijack_dns: false,
            },
            egress: NetworkEgressConfig::default(),
            clash_mode: Arc::new(ClashMode::new("rule")),
            process_resolver: Arc::new(ProcessResolver::default()),
            has_process_rules: false,
            hijack_dns_global: false,
        }
    }

    fn empty_rule(outbound: &str) -> RouteRuleConfig {
        RouteRuleConfig {
            inbound: vec![],
            network: None,
            protocol: vec![],
            ruleset: vec![],
            domain: vec![],
            domain_suffix: vec![],
            domain_keyword: vec![],
            domain_regex: vec![],
            ip_cidr: vec![],
            source_ip_cidr: vec![],
            port: vec![],
            port_range: vec![],
            sniff: false,
            sniff_timeout_ms: 0,
            sniff_type: vec![],
            sniff_override_destination: false,
            resolve: false,
            resolve_server: None,
            private_ip: false,
            hijack_dns: false,
            invert: false,
            outbound: outbound.into(),
            ..Default::default()
        }
    }

    fn route<'a>(
        r: &'a Router,
        inbound: &str,
        net: NetworkKind,
        target: &Target,
    ) -> &'a RouteAction {
        r.route(inbound, Some(net), target, None, None, None, None, None)
            .0
    }

    #[test]
    fn default_route() {
        let r = make_router(vec![], "proxy");
        let t = Target::Domain("example.com".into(), 443);
        assert_eq!(
            route(&r, "in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inbound_tag_filter() {
        let mut rule = empty_rule("direct");
        rule.inbound = vec!["tproxy-in".into()];
        let r = make_router(vec![rule], "proxy");
        let t = Target::Domain("example.com".into(), 80);
        assert_eq!(
            route(&r, "tproxy-in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            route(&r, "mixed-in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn network_filter() {
        let mut rule = empty_rule("direct");
        rule.network = Some(NetworkFilter::Udp);
        let r = make_router(vec![rule], "proxy");
        let t = Target::Socket("8.8.8.8:53".parse().unwrap());
        assert_eq!(
            route(&r, "in", NetworkKind::Udp, &t),
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            route(&r, "in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_domain_suffix() {
        let mut rule = empty_rule("direct");
        rule.domain_suffix = vec!["cn".into()];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("baidu.com.cn".into(), 80)
            ),
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("google.com".into(), 443)
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_domain_exact() {
        let mut rule = empty_rule("direct");
        rule.domain = vec!["example.com".into()];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("example.com".into(), 80)
            ),
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("sub.example.com".into(), 80)
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_ip_cidr() {
        let mut rule = empty_rule("direct");
        rule.ip_cidr = vec!["192.168.0.0/16".into()];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("192.168.1.1:80".parse().unwrap())
            ),
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("8.8.8.8:53".parse().unwrap())
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    // ── domain_regex 测试 ─────────────────────────────────────────────────

    #[test]
    fn domain_regex_basic() {
        let mut rule = empty_rule("proxy");
        rule.domain_regex = vec!["^.*\\.google\\.com$".into()];
        let r = make_router(vec![rule], "direct");
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("www.google.com".into(), 443)
            ),
            &RouteAction::Outbound("proxy".into())
        );
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("baidu.com".into(), 80)
            ),
            &RouteAction::Outbound("direct".into())
        );
    }

    #[test]
    fn domain_regex_case_insensitive() {
        let mut rule = empty_rule("proxy");
        rule.domain_regex = vec!["^.*\\.Google\\.COM$".into()];
        let r = make_router(vec![rule], "direct");
        // 大小写不敏感：WWW.GOOGLE.COM 也应命中
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("WWW.GOOGLE.COM".into(), 443)
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn domain_regex_no_match_for_ip_target() {
        let mut rule = empty_rule("proxy");
        rule.domain_regex = vec![".*".into()]; // 匹配任意域名
        let r = make_router(vec![rule], "direct");
        // IP 目标不触发 domain_regex
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("1.2.3.4:80".parse().unwrap())
            ),
            &RouteAction::Outbound("direct".into())
        );
    }

    // ── source_ip_cidr 测试 ───────────────────────────────────────────────

    #[test]
    fn source_ip_cidr_match() {
        let mut rule = empty_rule("direct");
        rule.source_ip_cidr = vec!["192.168.0.0/16".into()];
        let r = make_router(vec![rule], "proxy");
        let t = Target::Domain("example.com".into(), 80);
        // 来自 192.168.x.x 的连接命中
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                Some("192.168.1.100".parse::<IpAddr>().unwrap()),
                None,
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        // 来自公网 IP 的连接不命中
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                Some("8.8.8.8".parse::<IpAddr>().unwrap()),
                None,
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
        // 无来源 IP 的连接不命中
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn source_ip_cidr_combined_with_domain() {
        // source_ip_cidr AND domain_suffix：两者都需满足
        let mut rule = empty_rule("direct");
        rule.source_ip_cidr = vec!["10.0.0.0/8".into()];
        rule.domain_suffix = vec!["cn".into()];
        let r = make_router(vec![rule], "proxy");

        let cn_target = Target::Domain("baidu.cn".into(), 80);
        let non_cn = Target::Domain("google.com".into(), 80);

        // 来自内网 + 国内域名 → 命中
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &cn_target,
                None,
                None,
                Some("10.1.2.3".parse::<IpAddr>().unwrap()),
                None,
                None
            )
            .0,
            &RouteAction::Outbound("direct".into())
        );
        // 来自内网 + 非国内域名 → 不命中
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &non_cn,
                None,
                None,
                Some("10.1.2.3".parse::<IpAddr>().unwrap()),
                None,
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
        // 来自外网 + 国内域名 → 不命中（source_ip_cidr 不匹配）
        assert_eq!(
            r.route(
                "in",
                Some(NetworkKind::Tcp),
                &cn_target,
                None,
                None,
                Some("8.8.8.8".parse::<IpAddr>().unwrap()),
                None,
                None
            )
            .0,
            &RouteAction::Outbound("proxy".into())
        );
    }

    // ── invert 测试 ───────────────────────────────────────────────────────

    #[test]
    fn invert_domain_suffix() {
        // 非国内域名走代理
        let mut rule = empty_rule("proxy");
        rule.domain_suffix = vec!["cn".into()];
        rule.invert = true;
        let r = make_router(vec![rule], "direct");
        // 国内域名：正常命中后被 invert → 不命中 → 走 direct
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("baidu.cn".into(), 80)
            ),
            &RouteAction::Outbound("direct".into())
        );
        // 非国内域名：正常不命中后被 invert → 命中 → 走 proxy
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("google.com".into(), 443)
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn invert_with_ruleset_logic() {
        // invert=true 对 private_ip 也生效
        let mut rule = empty_rule("proxy");
        rule.private_ip = true;
        rule.invert = true;
        let r = make_router(vec![rule], "direct");
        // 私有 IP → 取反 → 不命中
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("192.168.1.1:80".parse().unwrap())
            ),
            &RouteAction::Outbound("direct".into())
        );
        // 公网 IP → 取反 → 命中
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("8.8.8.8:53".parse().unwrap())
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    // ── 原有测试保持不变 ──────────────────────────────────────────────────

    #[test]
    fn inline_port_only() {
        let mut rule = empty_rule("direct");
        rule.port = vec![PortFilter(80, 80), PortFilter(443, 443)];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("1.1.1.1:80".parse().unwrap())
            ),
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("1.1.1.1:22".parse().unwrap())
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inline_port_range() {
        let mut rule = empty_rule("direct");
        rule.port = vec![PortFilter(8000, 9000)];
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("1.1.1.1:8500".parse().unwrap())
            ),
            &RouteAction::Outbound("direct".into())
        );
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("1.1.1.1:7999".parse().unwrap())
            ),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn dns_out_action() {
        let mut rule = empty_rule("dns-out");
        rule.inbound = vec!["dns-in".into()];
        let r = make_router(vec![rule], "proxy");
        let t = Target::Domain("example.com".into(), 53);
        assert_eq!(
            r.route(
                "dns-in",
                Some(NetworkKind::Udp),
                &t,
                None,
                None,
                None,
                None,
                None
            )
            .0,
            &RouteAction::DnsOut
        );
    }

    #[test]
    fn rule_order_first_wins() {
        let mut r1 = empty_rule("direct");
        r1.domain_suffix = vec!["google.com".into()];
        let mut r2 = empty_rule("block");
        r2.domain_suffix = vec!["google.com".into()];
        let r = make_router(vec![r1, r2], "proxy");
        let t = Target::Domain("www.google.com".into(), 443);
        assert_eq!(
            route(&r, "in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("direct".into())
        );
    }

    #[test]
    fn no_condition_rule_matches_all() {
        let rule = empty_rule("direct");
        let r = make_router(vec![rule], "proxy");
        assert_eq!(
            route(
                &r,
                "any-in",
                NetworkKind::Tcp,
                &Target::Domain("anything.example".into(), 1234)
            ),
            &RouteAction::Outbound("direct".into())
        );
    }

    #[test]
    fn precomputed_idx_skips_sniff() {
        let sniff_rule = RouteRuleConfig {
            sniff: true,
            sniff_timeout_ms: 300,
            sniff_override_destination: true,
            inbound: vec!["mixed-in".into()],
            ..Default::default()
        };
        let mut direct_rule = empty_rule("direct");
        direct_rule.domain_suffix = vec!["cn".into()];

        let r = make_router(vec![sniff_rule, direct_rule], "proxy");
        assert_eq!(r.rules.len(), 2);
        assert_eq!(r.idx_no_sniff, vec![1]);
        let t = Target::Domain("baidu.cn".into(), 80);
        let (action, _, _, _) = r.route_indexed(
            &r.idx_no_sniff,
            "mixed-in",
            Some(NetworkKind::Tcp),
            &t,
            None,
            None,
            None,
            None,
            None,
            "test",
        );
        assert_eq!(action, &RouteAction::Outbound("direct".into()));
    }

    #[test]
    fn private_ip_matches_rfc1918() {
        let rule = RouteRuleConfig {
            private_ip: true,
            ..Default::default()
        };
        let r = make_router(vec![rule], "proxy");

        for ip in ["10.0.0.1:80", "172.16.0.1:80", "192.168.1.1:80"] {
            assert_eq!(
                route(
                    &r,
                    "in",
                    NetworkKind::Tcp,
                    &Target::Socket(ip.parse().unwrap())
                ),
                &RouteAction::Outbound("direct".into()),
                "should match private IP: {ip}"
            );
        }

        for ip in ["8.8.8.8:53", "1.1.1.1:443"] {
            assert_eq!(
                route(
                    &r,
                    "in",
                    NetworkKind::Tcp,
                    &Target::Socket(ip.parse().unwrap())
                ),
                &RouteAction::Outbound("proxy".into()),
                "should not match public IP: {ip}"
            );
        }
    }

    // ── clash_mode 规则条件 ──────────────────────────────────────────────

    #[test]
    fn clash_mode_only_matches_when_mode_equal() {
        let mut global_rule = empty_rule("global-selector");
        global_rule.clash_mode = Some("global".to_string());
        let r = make_router(vec![global_rule], "proxy");

        let t = Target::Domain("example.com".into(), 443);

        // 默认 mode = "rule"（make_router 内部用 ClashMode::new("rule")），
        // clash_mode=global 的规则不应命中，落到 final。
        assert_eq!(
            route(&r, "in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("proxy".into())
        );

        // 切到 global 模式后，规则应该命中。
        r.clash_mode.set("global");
        assert_eq!(
            route(&r, "in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("global-selector".into())
        );

        // 大小写不敏感比较，对齐 sing-box strings.EqualFold。
        r.clash_mode.set("GLOBAL");
        assert_eq!(
            route(&r, "in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("global-selector".into())
        );

        // 切回 rule 模式后规则不再命中。
        r.clash_mode.set("rule");
        assert_eq!(
            route(&r, "in", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn clash_mode_not_set_in_has_conditions_alone() {
        // 单独一个 clash_mode 字段也应该被 has_conditions() 认为是有效条件
        // （否则会被规则校验逻辑当成空规则报错）。
        let rule = RouteRuleConfig {
            clash_mode: Some("global".to_string()),
            outbound: "proxy".into(),
            ..Default::default()
        };
        assert!(rule.has_conditions());
    }

    // ── override_address / override_port / udp_timeout（RouteOptions）─────

    #[test]
    fn override_address_and_port_carried_in_route_options() {
        let mut rule = empty_rule("direct");
        rule.domain = vec!["printer.local".into()];
        rule.override_address = Some("192.168.1.50".to_string());
        rule.override_port = Some(9100);
        let r = make_router(vec![rule], "proxy");

        let t = Target::Domain("printer.local".into(), 80);
        let (action, _rt, _rp, opts) = r.route(
            "in",
            Some(NetworkKind::Tcp),
            &t,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(action, &RouteAction::Outbound("direct".into()));
        assert_eq!(opts.override_address.as_deref(), Some("192.168.1.50"));
        assert_eq!(opts.override_port, Some(9100));
    }

    #[test]
    fn udp_timeout_carried_in_route_options() {
        let mut rule = empty_rule("direct");
        rule.network = Some(NetworkFilter::Udp);
        rule.domain_suffix = vec![".game.example.com".into()];
        rule.udp_timeout = Some(300);
        let r = make_router(vec![rule], "proxy");

        let t = Target::Domain("a.game.example.com".into(), 12345);
        let (_action, _rt, _rp, opts) = r.route(
            "in",
            Some(NetworkKind::Udp),
            &t,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(opts.udp_timeout, Some(300));
    }

    #[test]
    fn final_action_has_empty_route_options() {
        // 没有任何规则命中、落到 final 的情况，options 应该是空的。
        let r = make_router(vec![], "proxy");
        let t = Target::Domain("nowhere.example.com".into(), 443);
        let (_action, rt, _rp, opts) = r.route(
            "in",
            Some(NetworkKind::Tcp),
            &t,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(rt, "final");
        assert!(opts.is_empty());
    }
}

#[cfg(test)]
mod hijack_dns_tests {
    use super::*;
    use crate::config::route::{RouteConfig, RouteRuleConfig};

    fn make_config(rules: Vec<RouteRuleConfig>) -> RouteConfig {
        RouteConfig {
            rules,
            r#final: "proxy".to_string(),
            rule_set: vec![],
            resolve_dns: false,
            ipv6: true,
            auto_detect_interface: false,
            default_interface: None,
            default_mark: None,
            hijack_dns: false,
        }
    }

    fn dns_protocol_rule() -> RouteRuleConfig {
        RouteRuleConfig {
            hijack_dns: true,
            protocol: vec!["dns".to_string()],
            ..Default::default()
        }
    }

    fn dns_inbound_rule() -> RouteRuleConfig {
        RouteRuleConfig {
            hijack_dns: true,
            inbound: vec!["dns-in".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn hijack_dns_with_protocol_dns_action() {
        let config = make_config(vec![dns_protocol_rule()]);
        let router =
            Router::from_config(&config, None, None, Arc::new(ClashMode::new("rule"))).unwrap();
        let t = Target::Socket("8.8.8.8:53".parse().unwrap());
        assert_eq!(
            router
                .route(
                    "any-in",
                    Some(NetworkKind::Udp),
                    &t,
                    Some("dns"),
                    None,
                    None,
                    None,
                    None
                )
                .0,
            &RouteAction::DnsOut
        );
    }

    #[test]
    fn hijack_dns_with_inbound_action() {
        let config = make_config(vec![dns_inbound_rule()]);
        let router =
            Router::from_config(&config, None, None, Arc::new(ClashMode::new("rule"))).unwrap();
        let t = Target::Domain("example.com".into(), 53);
        assert_eq!(
            router
                .route(
                    "dns-in",
                    Some(NetworkKind::Udp),
                    &t,
                    None,
                    None,
                    None,
                    None,
                    None
                )
                .0,
            &RouteAction::DnsOut
        );
    }

    #[test]
    fn bare_hijack_dns_is_error() {
        let rule = RouteRuleConfig {
            hijack_dns: true,
            ..Default::default()
        };
        let config = make_config(vec![rule]);
        let result = Router::from_config(&config, None, None, Arc::new(ClashMode::new("rule")));
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(msg.contains("hijack_dns"));
    }
}
