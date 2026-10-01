use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use ahash::AHashSet;
use regex::Regex;
use tracing::{debug, trace};

use crate::ruleset::{LoadedRuleSet, MatchTarget, RuleSet};

use crate::{
    app::process::{ProcessInfo, ProcessResolver},
    clash_mode::ClashMode,
    config::route::{
        NetworkFilter, RejectMethod, RouteActionConfig, RouteConfig, RouteRuleConfig, RuleSetType,
    },
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
    /// 拒绝连接（可配置拒绝方式，对齐 sing-box `reject` action）
    Reject {
        method: crate::config::route::RejectMethod,
    },
    /// 静默阻断（等价于 `Reject { method: Drop }`，对齐 sing-box `block` action）
    Block,
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

/// 单遍路由状态：记录已执行的非最终动作（sniff/resolve）与匹配游标。
///
/// 由 dispatcher 在一条连接的整个路由决策期间持有：
/// - `cursor`：下次匹配的起始规则索引（命中规则的下一条）
/// - `sniff_done` / `resolve_done`：已执行过对应非最终动作；此后再次命中
///   同类动作规则时直接跳过（避免重复嗅探/重复解析）
///
/// 语义对齐 sing-box：`sniff` / `resolve` 是非最终动作，命中执行后**继续匹配
/// 下一条规则**（不回退到规则表开头）。因此嗅探/解析规则应置于规则链最前，
/// 让嗅探结果供其后所有规则使用。
#[derive(Debug, Default, Clone)]
pub struct RouteState {
    /// 下次匹配的起始规则索引（命中规则的下一条）
    pub cursor: usize,
    /// 已执行过嗅探：后续 Sniff 规则跳过（避免重复嗅探）
    pub sniff_done: bool,
    /// 已执行过解析：后续 Resolve 规则跳过
    pub resolve_done: bool,
}

pub struct Router {
    rules: Vec<CompiledRule>,
    /// 无 `inbound` 条件规则的索引（对所有入站生效，升序）。
    /// 分桶遍历时与 `inbound_buckets` 归并，保证全局规则顺序。
    global_indices: Vec<usize>,
    /// 按入站 tag 分桶：tag → 该入站相关规则索引（升序，不含无 inbound 条件的规则）。
    /// 把「每连接遍历全部规则」降为「遍历该入站子集 + 全局规则」。
    inbound_buckets: HashMap<String, Vec<usize>>,
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

        // 验证：hijack_dns=true（含显式 `action: "hijack-dns"`）必须配合至少一个匹配条件
        for (i, r) in config.rules.iter().enumerate() {
            if r.is_hijack_dns() && !r.has_conditions() {
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

        // ── 入站分桶 ──────────────────────────────────────────────────────
        // 无 `inbound` 条件的规则对所有入站生效，放入 global_indices；
        // 有 `inbound` 条件的规则按 tag 入桶（一条规则可入多个桶）。
        // 两类索引都保持升序（按规则顺序插入），匹配时归并遍历即可保持
        // 全局规则顺序，与 RouteState 的单遍语义完全兼容。
        let mut global_indices: Vec<usize> = Vec::new();
        let mut inbound_buckets: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, rule) in rules.iter().enumerate() {
            if rule.inbound_tags.is_empty() {
                global_indices.push(i);
            } else {
                for tag in &rule.inbound_tags {
                    inbound_buckets.entry(tag.clone()).or_default().push(i);
                }
            }
        }

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
            global_indices,
            inbound_buckets,
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
        let mut state = RouteState::default();
        self.route_with_state(
            &mut state,
            &conn.inbound_tag,
            Some(NetworkKind::Tcp),
            &conn.target,
            conn.sniffed_protocol.as_deref(),
            conn.sniffed_domain.as_deref(),
            conn.stream.peer_addr().ok().map(|a| a.ip()),
            None,
            process_info,
        )
        .unwrap_or_else(|| self.default_result())
    }

    /// 无规则命中时的兜底结果（default 动作 + final 显示）。
    fn default_result(&self) -> (&RouteAction, &str, &str, &RouteOptions) {
        debug!(action=?self.default, "route default");
        (&self.default, "final", "", &EMPTY_ROUTE_OPTIONS)
    }

    pub fn route_udp(
        &self,
        packet: &InboundUdpPacket,
        process_info: Option<&ProcessInfo>,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        let mut state = RouteState::default();
        self.route_with_state(
            &mut state,
            &packet.inbound_tag,
            Some(NetworkKind::Udp),
            &packet.target,
            packet.sniffed_protocol.as_deref(),
            packet.sniffed_domain.as_deref(),
            Some(packet.src.ip()),
            None,
            process_info,
        )
        .unwrap_or_else(|| self.default_result())
    }

    /// 对 TUN 入站的 ICMP 回显（ping）请求做路由决策。
    ///
    /// 对齐 sing-box 1.13.0 的 `Router.PreMatch(network=NetworkICMP)` 语义
    /// （route/route.go:292-401）：ICMP 目标恒为 IP（无端口、无域名），
    /// `sniff` / `resolve` 这类非最终动作对 ICMP 无意义，按 sing-box 的
    /// `preMatch` 语义直接跳过（`matchRule` 中 `NetworkICMP` 时 sniff 规则
    /// 不被选中、resolve 对已是 IP 的目标为 no-op）。
    ///
    /// 返回值与其他 `route_*` 一致：`(action, rule_display, ruleset_display, options)`，
    /// 无规则命中时返回 `final` 兜底动作。
    pub fn route_icmp(
        &self,
        inbound_tag: &str,
        src_ip: Option<IpAddr>,
        dst_ip: IpAddr,
    ) -> (&RouteAction, &str, &str, &RouteOptions) {
        // 目标用端口 0 的 SocketAddr 占位（ICMP 无端口概念）。
        // 端口类规则对 ICMP 恒不命中（port=0），与 sing-box 一致。
        let target = Target::Socket(SocketAddr::new(dst_ip, 0));
        let mut state = RouteState::default();
        loop {
            match self.route_with_state(
                &mut state,
                inbound_tag,
                Some(NetworkKind::Icmp),
                &target,
                None,
                None,
                src_ip,
                None,
                None,
            ) {
                // sniff / resolve 对 ICMP 无意义：标记已执行后继续匹配下一条，
                // 复用 RouteState 的"已执行跳过"机制避免无限循环。
                Some((RouteAction::Sniff { .. }, _, _, _)) => {
                    state.sniff_done = true;
                    continue;
                }
                Some((RouteAction::Resolve { .. }, _, _, _)) => {
                    state.resolve_done = true;
                    continue;
                }
                Some(other) => return other,
                None => return self.default_result(),
            }
        }
    }

    /// 裸参数版路由（测试用）：等价 `route_tcp` / `route_udp`，
    /// 但直接接受匹配参数而非连接对象。一次性路由（默认 RouteState）。
    #[cfg(test)]
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
        let mut state = RouteState::default();
        self.route_with_state(
            &mut state,
            inbound_tag,
            network,
            target,
            sniffed_protocol,
            sniffed_domain,
            src_ip,
            resolved_ip,
            process_info,
        )
        .unwrap_or_else(|| self.default_result())
    }

    /// 单遍路由：从 `state.cursor` 开始匹配，命中非最终动作（sniff/resolve）
    /// 时由调用方执行动作后**继续调用**（`state` 相应置位）；命中最终动作或
    /// 越过规则表末尾返回 `None`（应使用 default 动作）。
    ///
    /// 语义对齐 sing-box route rule：
    /// - `sniff` / `resolve` 是非最终动作：命中执行后继续匹配**下一条规则**
    ///   （不回退到表头）；已执行过的动作类型其规则被跳过，避免重复执行
    /// - `route` / `reject` / `block` / `hijack-dns` 是最终动作：命中即终止
    ///
    /// 因此嗅探/解析规则应置于规则链最前，让嗅探结果供其后所有规则使用。
    #[allow(clippy::too_many_arguments)]
    pub fn route_with_state(
        &self,
        state: &mut RouteState,
        inbound_tag: &str,
        network: Option<NetworkKind>,
        target: &Target,
        sniffed_protocol: Option<&str>,
        sniffed_domain: Option<&str>,
        src_ip: Option<IpAddr>,
        resolved_ip: Option<IpAddr>,
        process_info: Option<&ProcessInfo>,
    ) -> Option<(&RouteAction, &str, &str, &RouteOptions)> {
        // 只读一次当前 Clash API 模式，避免在循环里反复加读锁。
        let current_mode = self.clash_mode.get();

        // 空规则快路径：无任何规则时直接走 default，省去归并初始化。
        if self.rules.is_empty() {
            return None;
        }

        // 分桶归并遍历：候选 = 无 `inbound` 条件的全局规则 ∪ 当前入站桶。
        // 两路索引均升序，从 `cursor` 处二分定位起点后归并，保持全局规则
        // 顺序，与 RouteState 单遍语义完全一致（嗅探/解析后 cursor 前进继续）。
        let tagged = self.inbound_buckets.get(inbound_tag);
        let mut gi = self.global_indices.partition_point(|&i| i < state.cursor);
        let mut ti = tagged
            .map(|v| v.partition_point(|&i| i < state.cursor))
            .unwrap_or(0);
        loop {
            let g = self.global_indices.get(gi).copied();
            let t = tagged.and_then(|v| v.get(ti)).copied();
            let next = match (g, t) {
                (Some(a), Some(b)) => {
                    if b < a {
                        ti += 1;
                        b
                    } else {
                        gi += 1;
                        a
                    }
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
            let rule = &self.rules[next];
            // 已执行过的非最终动作类型：跳过对应规则（避免重复嗅探/解析）
            if matches!(rule.action, RouteAction::Sniff { .. }) && state.sniff_done {
                continue;
            }
            if matches!(rule.action, RouteAction::Resolve { .. }) && state.resolve_done {
                continue;
            }
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
                state.cursor = next + 1;
                return Some((
                    &rule.action,
                    &rule.rule_display.0,
                    &rule.rule_display.1,
                    &rule.options,
                ));
            }
        }
        None
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
    inbound_tags: AHashSet<String>,
    network: Option<NetworkFilter>,
    protocols: Vec<String>,
    rulesets: Vec<Arc<RuleSet>>,
    addr_rs: Option<Arc<RuleSet>>,
    port_rs: Option<Arc<RuleSet>>,
    /// 来源 IP CIDR 规则集（对应 `source_ip_cidr`）
    source_rs: Option<Arc<RuleSet>>,
    /// 预编译的域名正则列表（对应 `domain_regex`，大小写不敏感）
    domain_regex: Vec<Regex>,
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

        // ── 动作构建：action 唯一决定（反序列化后恒为 Some）───────────────
        let action = match &rule.action {
            Some(ac) => config_action_to_route(ac)?,
            None => anyhow::bail!("route rule: missing `action` (defaults to route with required outbound)"),
        };

        let rule_display = if !rule.ruleset.is_empty() {
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
        } else if matches!(action, RouteAction::Sniff { .. }) {
            ("SNIFF".to_string(), String::new())
        } else if matches!(action, RouteAction::Resolve { .. }) {
            ("RESOLVE".to_string(), String::new())
        } else if matches!(action, RouteAction::DnsOut) {
            ("HIJACK-DNS".to_string(), String::new())
        } else if matches!(action, RouteAction::Reject { .. }) {
            ("REJECT".to_string(), String::new())
        } else if matches!(action, RouteAction::Block) {
            ("BLOCK".to_string(), String::new())
        } else if let Some(mode) = &rule.clash_mode {
            ("CLASH-MODE".to_string(), mode.clone())
        } else {
            ("MATCH".to_string(), String::new())
        };

        // 动作精细化选项：仅显式 `route` 动作携带
        let options = match &rule.action {
            Some(RouteActionConfig::Route {
                override_address,
                override_port,
                udp_timeout,
                ..
            }) => RouteOptions {
                override_address: override_address.clone(),
                override_port: *override_port,
                udp_timeout: *udp_timeout,
            },
            _ => RouteOptions::default(),
        };

        Ok(Self {
            inbound_tags: rule.inbound.iter().cloned().collect(),
            network: rule.network,
            protocols: rule.protocol.iter().map(|s| s.to_lowercase()).collect(),
            rulesets: compiled_rulesets,
            addr_rs,
            port_rs,
            source_rs,
            domain_regex,
            process_names: rule.process_name.clone(),
            process_paths: rule.process_path.clone(),
            invert: rule.invert,
            clash_mode_filter: rule.clash_mode.clone(),
            action,
            options,
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
        if !self.inbound_tags.is_empty() && !self.inbound_tags.contains(inbound_tag) {
            return false;
        }

        // 2. 网络类型过滤（不受 invert 影响）
        if let Some(nf) = &self.network {
            match (nf, network) {
                (NetworkFilter::Tcp, Some(NetworkKind::Tcp)) => {}
                (NetworkFilter::Udp, Some(NetworkKind::Udp)) => {}
                (NetworkFilter::Icmp, Some(NetworkKind::Icmp)) => {}
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
        //    匹配语义（对齐 sing-box route/rule/rule_item_process_{name,path}.go）：
        //    - process_names 列表内 OR（任一完整相等即命中）；
        //      ProcessInfo.name 已是 exe 路径 basename（见 app/process.rs）
        //    - process_paths 列表内 OR（任一**完整相等**即命中，精确 map 匹配）
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
                if !self.process_paths.iter().any(|p| p == path_str) {
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

        let has_addr_rules = has_ruleset || has_addr_rs || has_port_rs || has_domain_regex;

        if has_addr_rules {
            let port_val = target.port();

            // 域名候选一次性归一化（trim 末尾 '.' + ASCII 小写），供 rulesets /
            // addr_rs / domain_regex 三类地址条件共享，避免各匹配器对同一域名
            // 重复归一化；并保证 domain_regex 与 DOMAIN-SUFFIX 等匹配器对 FQDN
            // （带末尾 '.'）行为一致：'example.com.' 归一化为 'example.com' 后
            // 才能匹配 `^example\.com$`。mihomo RuleHost() 不做归一化，但 reflex
            // 在域名匹配上已统一归一化，此处将其收敛到 rule 层保持一致。
            let sniffed_norm = sniffed_domain.map(normalize_domain);
            let target_domain_norm = match target {
                Target::Domain(h, _) => Some(normalize_domain(h)),
                _ => None,
            };

            let ruleset_ok = !has_ruleset
                || self.match_rulesets(
                    sniffed_norm.as_deref(),
                    target_domain_norm.as_deref(),
                    target,
                    resolved_ip,
                    port_val,
                );
            let addr_rs_ok = !has_addr_rs
                || self
                    .addr_rs
                    .as_ref()
                    .is_some_and(|rs| {
                        match_addr_rs(
                            rs,
                            sniffed_norm.as_deref(),
                            target_domain_norm.as_deref(),
                            target,
                            resolved_ip,
                        )
                    });
            let port_rs_ok = !has_port_rs
                || self
                    .port_rs
                    .as_ref()
                    .is_some_and(|rs| rs.matches(&MatchTarget::Port(port_val)));
            let domain_regex_ok = !has_domain_regex
                || match_domain_regex(
                    &self.domain_regex,
                    sniffed_norm.as_deref(),
                    target_domain_norm.as_deref(),
                );

            let matched = ruleset_ok && addr_rs_ok && port_rs_ok && domain_regex_ok;

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
    /// 1. 域名候选由调用方在 rule 层一次性归一化（trim 末尾 '.' + ASCII 小写），
    ///    所有 rulesets 复用同一归一化结果，避免每个 ruleset 在
    ///    RuleSet::match_domain 内重复归一化同一域名，也避免与 addr_rs /
    ///    domain_regex 重复归一化。
    /// 2. 利用 RuleSet::has_domain_matchers / has_ip_matchers /
    ///    has_port_matchers 跳过不含对应匹配器的 ruleset，避免 MatchTarget
    ///    构造和无效 match_domain/match_ip 调用。
    /// 3. 域名匹配直接走 RuleSet::match_domain_normalized，避免 MatchTarget
    ///    enum 构造和 match dispatch。
    fn match_rulesets(
        &self,
        sniffed_domain_norm: Option<&str>,
        target_domain_norm: Option<&str>,
        target: &Target,
        resolved_ip: Option<IpAddr>,
        port_val: u16,
    ) -> bool {
        // target.Socket.ip 提前取出一次，避免每次循环 match 重复提取
        let target_socket_ip = match target {
            Target::Socket(addr) => Some(addr.ip()),
            _ => None,
        };

        for rs in &self.rulesets {
            // 域名候选：sniffed_domain 优先，然后 target.Domain（均已归一化）
            if rs.has_domain_matchers() {
                if let Some(d) = sniffed_domain_norm {
                    if rs.match_domain_normalized(d) {
                        return true;
                    }
                }
                if let Some(d) = target_domain_norm {
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
/// 1. 域名候选由调用方在 rule 层归一化后传入，避免本函数重复 trim/lower。
/// 2. 利用 RuleSet::has_domain_matchers / has_ip_matchers 跳过空匹配器。
fn match_addr_rs(
    rs: &RuleSet,
    sniffed_domain_norm: Option<&str>,
    target_domain_norm: Option<&str>,
    target: &Target,
    resolved_ip: Option<IpAddr>,
) -> bool {
    // 域名候选（已归一化）
    if rs.has_domain_matchers() {
        if let Some(d) = sniffed_domain_norm {
            if rs.match_domain_normalized(d) {
                return true;
            }
        }
        if let Some(d) = target_domain_norm {
            if rs.match_domain_normalized(d) {
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
///
/// 域名候选由调用方归一化（trim 末尾 '.' + ASCII 小写）后传入，保证 DOMAIN-REGEX
/// 与 DOMAIN-SUFFIX / DOMAIN 等匹配器对 FQDN（带末尾 '.'）行为一致：
/// 'example.com.' 归一化为 'example.com' 后才能匹配 `^example\.com$`。
/// 正则仍带 (?i) 前缀（编译期注入）使模式本身大小写不敏感。
fn match_domain_regex(
    regexes: &[Regex],
    sniffed_domain_norm: Option<&str>,
    target_domain_norm: Option<&str>,
) -> bool {
    // sniffed_domain 优先
    if let Some(d) = sniffed_domain_norm {
        for re in regexes {
            if re.is_match(d) {
                return true;
            }
        }
    }
    // 然后检查 target.Domain
    if let Some(d) = target_domain_norm {
        for re in regexes {
            if re.is_match(d) {
                return true;
            }
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

/// 将显式 `RouteActionConfig` 编译为内部 `RouteAction`。
fn config_action_to_route(ac: &RouteActionConfig) -> anyhow::Result<RouteAction> {
    Ok(match ac {
        RouteActionConfig::Route { outbound, .. } => to_action(outbound),
        RouteActionConfig::Reject { method } => RouteAction::Reject {
            method: method.unwrap_or(RejectMethod::Default),
        },
        RouteActionConfig::Block => RouteAction::Block,
        RouteActionConfig::HijackDns => RouteAction::DnsOut,
        RouteActionConfig::Sniff {
            timeout_ms,
            override_destination,
            sniff_type,
            force_domain,
            skip_domain,
            skip_src_address,
        } => RouteAction::Sniff {
            timeout_ms: *timeout_ms,
            override_destination: *override_destination,
            sniff_types: sniff_type
                .iter()
                .filter_map(|s| crate::app::sniff::SniffType::parse(s))
                .collect(),
            force_domain: force_domain.clone(),
            skip_domain: skip_domain.clone(),
            skip_src_address: skip_src_address.clone(),
        },
        RouteActionConfig::Resolve { server } => RouteAction::Resolve {
            server: server.clone(),
        },
    })
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
///
/// Binary 格式走 mmap 零拷贝：FST 字节直接借用文件映射，不读入堆，
/// 对 geosite 这类大规则集常驻内存显著下降。Source 格式仍读入内存后编译。
fn load_ruleset_from_path(
    path: &str,
    tag: &str,
    format: &crate::config::route::RuleSetFormat,
) -> anyhow::Result<RuleSet> {
    use crate::config::route::RuleSetFormat;
    match format {
        RuleSetFormat::Binary => {
            // mmap 只读映射本地 .rrs 文件，FST section 直接借用映射字节。
            let file = std::fs::File::open(path).map_err(|e| {
                anyhow::anyhow!("rule_set '{tag}': failed to open file '{path}': {e}")
            })?;
            let file_meta = file
                .metadata()
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': stat '{path}' failed: {e}"))?;
            if file_meta.len() == 0 {
                anyhow::bail!("rule_set '{tag}': file '{path}' is empty");
            }
            let mmap = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| {
                anyhow::anyhow!("rule_set '{tag}': failed to mmap '{path}': {e}")
            })?;
            let mmap = std::sync::Arc::new(mmap);
            let loaded = crate::ruleset::LoadedRuleSet::from_mmap(mmap)
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': parse error: {e}"))?;
            Ok(RuleSet::from_loaded(loaded)?)
        }
        RuleSetFormat::Source => {
            let data = std::fs::read(path).map_err(|e| {
                anyhow::anyhow!("rule_set '{tag}': failed to read file '{path}': {e}")
            })?;
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
///
/// 直接走 `LoadedRuleSet::from_compiled`，跳过 `serialize → from_bytes` 往返，
/// 避免为大型 source 规则集临时多分配一份 RRS 二进制 + section 重解析的内存。
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
    let loaded = crate::ruleset::LoadedRuleSet::from_compiled(compiled)
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
    /// ICMP 回显（ping）请求。对齐 sing-box 1.13.0 的 `N.NetworkICMP`，
    /// 仅由 TUN 入站的 ICMP 转发器产生，用于 `network: "icmp"` 规则匹配。
    Icmp,
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

        // 与 from_config 相同的分桶构建逻辑
        let mut global_indices: Vec<usize> = Vec::new();
        let mut inbound_buckets: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, rule) in rules_compiled.iter().enumerate() {
            if rule.inbound_tags.is_empty() {
                global_indices.push(i);
            } else {
                for tag in &rule.inbound_tags {
                    inbound_buckets.entry(tag.clone()).or_default().push(i);
                }
            }
        }

        Router {
            rules: rules_compiled,
            global_indices,
            inbound_buckets,
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
            action: Some(RouteActionConfig::Route {
                outbound: outbound.into(),
                override_address: None,
                override_port: None,
                udp_timeout: None,
            }),
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

    #[test]
    fn domain_regex_fqdn_trailing_dot() {
        // FQDN 带末尾 '.'（DNS 查询常见）应被归一化后匹配 DOMAIN-REGEX，
        // 与 DOMAIN-SUFFIX / DOMAIN 等匹配器行为一致：
        // 'example.com.' 归一化为 'example.com'，从而命中 `^example\.com$`。
        let mut rule = empty_rule("proxy");
        rule.domain_regex = vec!["^example\\.com$".into()];
        let r = make_router(vec![rule], "direct");
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Domain("example.com.".into(), 443)
            ),
            &RouteAction::Outbound("proxy".into())
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
        // invert=true 对 IP 条件也生效（私有段改用 ip_cidr 显式表达）
        let mut rule = empty_rule("proxy");
        rule.ip_cidr = vec!["192.168.0.0/16".into()];
        rule.invert = true;
        let r = make_router(vec![rule], "direct");
        // 192.168.1.1 命中 ip_cidr → 取反 → 不命中
        assert_eq!(
            route(
                &r,
                "in",
                NetworkKind::Tcp,
                &Target::Socket("192.168.1.1:80".parse().unwrap())
            ),
            &RouteAction::Outbound("direct".into())
        );
        // 公网 IP 不命中 ip_cidr → 取反 → 命中
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
    fn route_state_skips_sniff_after_executed() {
        // sniff 规则执行后（sniff_done=true），继续匹配时跳过 Sniff 规则，
        // 命中其后的规则——单遍语义下由 RouteState 跳过已执行类型实现。
        let sniff_rule = RouteRuleConfig {
            action: Some(RouteActionConfig::Sniff {
                timeout_ms: 300,
                override_destination: true,
                sniff_type: vec![],
                force_domain: vec![],
                skip_domain: vec![],
                skip_src_address: vec![],
            }),
            inbound: vec!["mixed-in".into()],
            ..Default::default()
        };
        let mut direct_rule = empty_rule("direct");
        direct_rule.domain_suffix = vec!["cn".into()];

        let r = make_router(vec![sniff_rule, direct_rule], "proxy");
        assert_eq!(r.rules.len(), 2);
        let t = Target::Domain("baidu.cn".into(), 80);

        // 首轮：命中 sniff 规则（sniff_done=false）
        let mut state = RouteState::default();
        let (action, rt, _, _) = r
            .route_with_state(
                &mut state,
                "mixed-in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("sniff rule should hit first");
        assert!(matches!(action, RouteAction::Sniff { .. }));
        // sniff 规则带 inbound 条件，显示按条件字段优先为 IN-NAME
        assert_eq!(rt, "IN-NAME");
        assert_eq!(state.cursor, 1);

        // 执行嗅探后置位，再次匹配跳过 Sniff 规则，命中 direct 规则
        state.sniff_done = true;
        let (action, _, _, _) = r
            .route_with_state(
                &mut state,
                "mixed-in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("direct rule should hit after sniff");
        assert_eq!(action, &RouteAction::Outbound("direct".into()));
    }

    #[test]
    fn route_state_skips_resolve_after_executed() {
        // sniff 后命中 resolve 规则，执行后（resolve_done=true）再次匹配时
        // Sniff 与 Resolve 规则都被跳过，命中最终规则。
        let sniff_rule = RouteRuleConfig {
            action: Some(RouteActionConfig::Sniff {
                timeout_ms: 0,
                override_destination: false,
                sniff_type: vec![],
                force_domain: vec![],
                skip_domain: vec![],
                skip_src_address: vec![],
            }),
            ..Default::default()
        };
        let resolve_rule = RouteRuleConfig {
            action: Some(RouteActionConfig::Resolve { server: None }),
            ..Default::default()
        };
        let mut direct_rule = empty_rule("direct");
        direct_rule.domain_suffix = vec!["cn".into()];

        let r = make_router(vec![sniff_rule, resolve_rule, direct_rule], "proxy");
        let t = Target::Domain("baidu.cn".into(), 80);

        let mut state = RouteState::default();
        let (action, _, _, _) = r
            .route_with_state(
                &mut state,
                "in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("sniff first");
        assert!(matches!(action, RouteAction::Sniff { .. }));
        state.sniff_done = true;

        let (action, _, _, _) = r
            .route_with_state(
                &mut state,
                "in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("resolve after sniff");
        assert!(matches!(action, RouteAction::Resolve { .. }));
        state.resolve_done = true;

        let (action, _, _, _) = r
            .route_with_state(
                &mut state,
                "in",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("direct after both");
        assert_eq!(action, &RouteAction::Outbound("direct".into()));
    }

    #[test]
    fn route_state_none_when_no_rule_matches() {
        let mut direct_rule = empty_rule("direct");
        direct_rule.domain_suffix = vec!["cn".into()];
        let r = make_router(vec![direct_rule], "proxy");
        let t = Target::Domain("example.com".into(), 443);
        let mut state = RouteState::default();
        let result = r.route_with_state(
            &mut state,
            "in",
            Some(NetworkKind::Tcp),
            &t,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_none());
    }

    // ── 入站分桶 ─────────────────────────────────────────────────────────

    #[test]
    fn inbound_buckets_built_correctly() {
        // 规则 0：无 inbound 条件（全局）
        let g0 = empty_rule("direct");
        // 规则 1：inbound = ["a"]
        let mut a1 = empty_rule("proxy");
        a1.inbound = vec!["a".into()];
        // 规则 2：inbound = ["a", "b"]（入两个桶）
        let mut ab2 = empty_rule("proxy");
        ab2.inbound = vec!["a".into(), "b".into()];

        let r = make_router(vec![g0, a1, ab2], "final");
        assert_eq!(r.global_indices, vec![0]);
        assert_eq!(r.inbound_buckets.get("a").unwrap(), &vec![1, 2]);
        assert_eq!(r.inbound_buckets.get("b").unwrap(), &vec![2]);
        // 未声明的入站 tag：无桶（只剩全局规则）
        assert!(!r.inbound_buckets.contains_key("unknown"));
    }

    #[test]
    fn inbound_bucket_isolates_rules_per_inbound() {
        // 入站 a 的规则不应命中入站 b 的连接
        let mut a_rule = empty_rule("direct");
        a_rule.inbound = vec!["a".into()];
        let r = make_router(vec![a_rule], "proxy");

        let t = Target::Domain("example.com".into(), 443);
        // 入站 a → 命中 direct
        assert_eq!(
            route(&r, "a", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("direct".into())
        );
        // 入站 b → 无桶内规则，走 default proxy
        assert_eq!(
            route(&r, "b", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("proxy".into())
        );
    }

    #[test]
    fn inbound_bucket_global_rule_applies_to_all() {
        // 无 inbound 条件的规则对所有入站生效，且与桶内规则按顺序归并
        let mut g0 = empty_rule("global-ob");
        g0.domain_suffix = vec!["cn".into()];
        let mut a1 = empty_rule("proxy");
        a1.inbound = vec!["a".into()];
        a1.domain_suffix = vec!["com".into()];
        let r = make_router(vec![g0, a1], "final");

        let t = Target::Domain("baidu.cn".into(), 443);
        // 入站 a：全局规则(0)在桶内规则(1)之前，.cn 命中全局规则
        assert_eq!(
            route(&r, "a", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("global-ob".into())
        );
        // 入站 b：只有全局规则，命中
        assert_eq!(
            route(&r, "b", NetworkKind::Tcp, &t),
            &RouteAction::Outbound("global-ob".into())
        );

        let t2 = Target::Domain("google.com".into(), 443);
        // 入站 a：全局规则不命中 .com，归并继续到桶内规则(1) → proxy
        assert_eq!(
            route(&r, "a", NetworkKind::Tcp, &t2),
            &RouteAction::Outbound("proxy".into())
        );
        // 入站 b：无桶内规则 → final
        assert_eq!(
            route(&r, "b", NetworkKind::Tcp, &t2),
            &RouteAction::Outbound("final".into())
        );
    }

    #[test]
    fn inbound_bucket_compatible_with_route_state_cursor() {
        // 单遍语义 + 分桶：sniff 命中执行后 cursor 前进，后续桶内规则继续可命中
        let mut sniff_rule = empty_rule("direct");
        sniff_rule.action = Some(RouteActionConfig::Sniff {
            timeout_ms: 0,
            override_destination: false,
            sniff_type: vec!["tls".into()],
            force_domain: vec![],
            skip_domain: vec![],
            skip_src_address: vec![],
        });
        let mut after_rule = empty_rule("proxy");
        after_rule.inbound = vec!["a".into()];
        after_rule.domain_suffix = vec!["com".into()];
        let r = make_router(vec![sniff_rule, after_rule], "final");

        let t = Target::Domain("google.com".into(), 443);
        let mut state = RouteState::default();
        // 第一轮：命中 sniff(0)，cursor → 1
        let (action, _, _, _) = r
            .route_with_state(
                &mut state,
                "a",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("sniff should hit");
        assert!(matches!(action, RouteAction::Sniff { .. }));
        assert_eq!(state.cursor, 1);
        state.sniff_done = true;
        // 第二轮：从 cursor=1 归并，桶内规则(1)命中 .com → proxy
        let (action, _, _, _) = r
            .route_with_state(
                &mut state,
                "a",
                Some(NetworkKind::Tcp),
                &t,
                None,
                None,
                None,
                None,
                None,
            )
            .expect("post-sniff rule should hit");
        assert_eq!(action, &RouteAction::Outbound("proxy".into()));
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
            action: Some(RouteActionConfig::Route {
                outbound: "proxy".into(),
                override_address: None,
                override_port: None,
                udp_timeout: None,
            }),
            ..Default::default()
        };
        assert!(rule.has_conditions());
    }

    // ── override_address / override_port / udp_timeout（RouteOptions）─────

    #[test]
    fn override_address_and_port_carried_in_route_options() {
        let mut rule = empty_rule("direct");
        rule.domain = vec!["printer.local".into()];
        rule.action = Some(RouteActionConfig::Route {
            outbound: "direct".into(),
            override_address: Some("192.168.1.50".to_string()),
            override_port: Some(9100),
            udp_timeout: None,
        });
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
        rule.action = Some(RouteActionConfig::Route {
            outbound: "direct".into(),
            override_address: None,
            override_port: None,
            udp_timeout: Some(300),
        });
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
            action: Some(RouteActionConfig::HijackDns),
            protocol: vec!["dns".to_string()],
            ..Default::default()
        }
    }

    fn dns_inbound_rule() -> RouteRuleConfig {
        RouteRuleConfig {
            action: Some(RouteActionConfig::HijackDns),
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
            action: Some(RouteActionConfig::HijackDns),
            ..Default::default()
        };
        let config = make_config(vec![rule]);
        let result = Router::from_config(&config, None, None, Arc::new(ClashMode::new("rule")));
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(msg.contains("hijack"));
    }
}
