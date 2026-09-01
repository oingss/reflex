use serde::{Deserialize, Serialize};

use crate::config::dns::DnsServerRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// 路由规则，顺序匹配，第一条命中生效
    #[serde(default)]
    pub rules: Vec<RouteRuleConfig>,

    /// 所有规则未命中时的默认出站 tag
    ///
    /// 缺省时为 `"direct"`——与未配置 outbounds 时自动补的 direct 出站自动关联，
    /// 实现"零配置即可启动"（仅 mixed 入站 + 直连出站）。
    #[serde(default = "default_route_final")]
    pub r#final: String,

    /// 规则集声明（local 或 remote）
    #[serde(default)]
    pub rule_set: Vec<RuleSetRef>,

    /// 是否对 DNS 响应中的 IP 也做路由（用于 fake-ip 或 IP 分流）
    #[serde(default)]
    pub resolve_dns: bool,

    /// 是否允许 IPv6 流量流经核心（默认 true）。
    ///
    /// - `true`：IPv6 正常处理，DNS 解析行为由 `dns.strategy` 控制。
    /// - `false`：完全屏蔽 IPv6，DNS 仅发 A 记录查询，`dns.strategy` 此时无效。
    #[serde(default = "default_true")]
    pub ipv6: bool,

    /// 自动检测并绑定默认出口网络接口（仅 Linux / macOS / Windows 支持）。
    ///
    /// 启用后，direct 出站会自动绑定到系统路由表中优先级最高的物理接口，
    /// 解决多网卡/VPN 环境下直连流量走错接口的问题。
    /// 与 sing-box `route.auto_detect_interface` 字段对齐。
    ///
    /// 典型用法：
    /// ```json
    /// "route": { "auto_detect_interface": true, "final": "🚀 节点选择" }
    /// ```
    #[serde(default)]
    pub auto_detect_interface: bool,

    /// 默认出口网络接口名称（覆盖自动检测结果）。
    ///
    /// 与 sing-box `route.default_interface` 对齐。
    /// 填写后强制所有 direct 连接绑定到该接口；与 `auto_detect_interface`
    /// 同时使用时本字段优先。
    #[serde(default)]
    pub default_interface: Option<String>,

    /// 默认路由标记（Linux fwmark，仅 Linux 支持）。
    ///
    /// 与 sing-box `route.default_mark` 对齐。
    /// 用于配合 iptables/nftables 策略路由，避免代理流量形成回环。
    #[serde(default)]
    pub default_mark: Option<u32>,

    /// 全局 DNS 劫持快捷开关：设为 true 时，所有目标端口为 53 的 TCP/UDP 流量
    /// 直接交给内部 DNS 模块处理，跳过整个路由匹配过程。
    ///
    /// 等价于在规则列表最前面加一条：
    /// ```json
    /// { "port": [53], "hijack_dns": true }
    /// ```
    /// 但更简洁，且省去路由表查找开销。典型用法（TUN 入站接管系统 DNS）：
    /// ```json
    /// { "route": { "hijack_dns": true, "final": "proxy" } }
    /// ```
    ///
    /// 注意：
    /// - 仅对目标端口 53 生效；DoH/DoT（853）等不会被劫持。
    /// - 与规则级 `hijack_dns: true` 共存时，全局开关优先（端口 53 流量不会
    ///   走规则匹配）。
    /// - 不影响 FakeIP 反查（仍然在路由前执行）。
    #[serde(default)]
    pub hijack_dns: bool,
}

// ── Rule ─────────────────────────────────────────────────────────────────────

/// 拒绝动作的方式，对齐 sing-box `reject` action 的 `method` 字段
/// （见 route/rule/rule_action.go:374-403 的 `RuleActionReject.Error()`）。
///
/// | 值       | TCP 行为                                     | UDP 行为                          | ICMP 行为（ping）                  |
/// |----------|----------------------------------------------|-----------------------------------|------------------------------------|
/// | default  | 发送 RST（SO_LINGER=0 后关闭）               | 丢弃包，不回任何数据              | 回复 ICMP 主机不可达（DstUnreachable）|
/// | drop     | 静默关闭（FIN/EOF），不主动发 RST            | 丢弃包，不回任何数据              | 丢弃包，不回任何数据                |
/// | reply    | 发送 RST（同 default）                      | 丢弃包（ICMP 未实现，需原始套接字）| 回复 ICMP 回显应答（Echo Reply）   |
///
/// 注意：
/// - sing-box 在 TCP/UDP 上拒绝 `reply` 方法（route/route.go:128-130），
///   reflex 保留为可用的 RST 语义。
/// - ICMP 的拒绝行为对齐 sing-box 1.13.0（docs/configuration/route/rule_action.md）：
///   `default` → 主机不可达，`reply` → 回显应答，`drop` → 静默丢弃。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RejectMethod {
    /// 默认：发送 RST（TCP）/ 丢弃包（UDP）/ 回复主机不可达（ICMP），
    /// 对应 sing-box `tun.ErrReset`
    Default,
    /// 静默丢弃，不回任何数据，对应 sing-box `tun.ErrDrop`
    Drop,
    /// 尽力发送 RST（TCP）；ICMP 上回复回显应答（对齐 sing-box 1.13.0）
    Reply,
}

/// 路由规则的动作，对齐 sing-box `route.rules[].action`。
///
/// 使用方式（`action` 为 tag 字段，动作专属参数平铺在同一对象里）：
/// ```json
/// { "action": "route", "outbound": "proxy" }
/// { "action": "reject", "method": "drop" }
/// { "action": "block" }
/// { "action": "hijack-dns", "protocol": ["dns"] }
/// { "action": "sniff", "sniff_type": ["tls", "http"] }
/// { "action": "resolve", "server": "local" }
/// ```
///
/// 动作分两类：
/// - **最终动作**（命中即终止匹配）：`route` / `reject` / `block` / `hijack-dns`
/// - **非最终动作**（执行后继续匹配后续规则）：`sniff` / `resolve`
///
/// 注意：显式 `action` 与旧式动作字段（`sniff` / `resolve` / `hijack_dns` /
/// `private_ip` / `outbound`）不能同时出现在同一条规则里，配置加载时报错。
/// 未填写 `action` 时自动从旧式字段推导（向后兼容）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum RouteActionConfig {
    /// 最终动作：转发到指定出站（默认动作）。
    Route {
        /// 目标 outbound tag，特殊值 `"dns-out"` 表示交给 DNS 模块。
        outbound: String,
        /// 改写连接的目标地址（对齐 sing-box `override_address`）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        override_address: Option<String>,
        /// 改写连接的目标端口（对齐 sing-box `override_port`）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        override_port: Option<u16>,
        /// 覆盖 UDP 会话空闲超时（秒）（对齐 sing-box `udp_timeout`）
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_timeout: Option<u64>,
    },
    /// 最终动作：拒绝连接（可配置拒绝方式）
    Reject {
        /// 拒绝方式，缺省为 `default`
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<RejectMethod>,
    },
    /// 最终动作：静默阻断，等价于 `reject` + `method: "drop"`
    Block,
    /// 最终动作：DNS 劫持，将流量交给内部 DNS 模块。
    ///
    /// 必须配合至少一个匹配条件（`inbound` / `protocol` / `network` / `port` 等），
    /// 否则配置加载时报错。
    HijackDns,
    /// 非最终动作：协议嗅探，用嗅探结果更新目标域名后**继续**匹配后续规则。
    ///
    /// 通常作为规则链第一条无条件规则使用。
    Sniff {
        /// 嗅探超时（毫秒），0 表示默认值（300 ms）
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        timeout_ms: u64,
        /// 嗅探到域名后是否覆盖目标地址（默认 false）
        #[serde(default, skip_serializing_if = "is_false")]
        override_destination: bool,
        /// 启用的嗅探协议列表（如 `["tls", "http", "quic"]`）
        #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "super::deserialize_one_or_many")]
        sniff_type: Vec<String>,
        /// 嗅探白名单（仅这些域名才嗅探）
        #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "super::deserialize_one_or_many")]
        force_domain: Vec<String>,
        /// 嗅探黑名单（跳过这些域名）
        #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "super::deserialize_one_or_many")]
        skip_domain: Vec<String>,
        /// 嗅探源 IP 黑名单（跳过这些 CIDR）
        #[serde(default, skip_serializing_if = "Vec::is_empty", deserialize_with = "super::deserialize_one_or_many")]
        skip_src_address: Vec<String>,
    },
    /// 非最终动作：将域名解析为 IP 后**继续**匹配后续规则。
    Resolve {
        /// 用于解析的 DNS server tag（s），不填使用默认 DNS 服务器。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<DnsServerRef>,
    },
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

/// 一条路由规则，所有非空条件之间是 AND 语义，
/// 同一条件内多个值是 OR 语义。
///
/// 反序列化兼容两种书写形式：
/// 1. 显式动作：`{ ..., "action": "route", "outbound": "direct" }`
/// 2. 旧式字段：`{ ..., "sniff": true, "outbound": "direct" }`（无 `action` 时
///    自动推导为对应 `RouteActionConfig`，`action` 字段始终为 `Some`）
///
/// 序列化时输出规范形式：条件字段 + `action` 展平字段（不再输出旧式动作字段）。
#[derive(Debug, Clone, Default)]
pub struct RouteRuleConfig {
    // ── 来源条件 ──────────────────────────────────────────────
    /// 来自指定入站 tag。支持单字符串或数组形式。
    pub inbound: Vec<String>,

    /// 网络类型过滤
    pub network: Option<NetworkFilter>,

    /// 来源 IP CIDR（OR），匹配连接的源地址。
    ///
    /// 与 sing-box `source_ip_cidr` 字段对齐。
    /// 支持 IPv4 和 IPv6 CIDR，例如 `["192.168.0.0/16", "10.0.0.0/8"]`。
    /// 也支持单字符串形式：`"source_ip_cidr": "192.168.0.0/16"`。
    ///
    /// 典型用法：限制只有局域网来源的流量走直连：
    /// ```json
    /// { "source_ip_cidr": ["192.168.0.0/16"], "outbound": "direct" }
    /// ```
    pub source_ip_cidr: Vec<String>,

    // ── 目标条件 ──────────────────────────────────────────────
    /// 命中的 ruleset tag（OR），同时支持域名和 IP 规则集。
    /// 配置形式支持单字符串或数组：`"ruleset": "geosite-cn"` 或
    /// `"ruleset": ["geosite-cn", "geoip-cn"]`。
    pub ruleset: Vec<String>,

    /// 内联精确域名（OR）。支持单字符串或数组形式。
    pub domain: Vec<String>,

    /// 内联域名后缀（OR）。支持单字符串或数组形式。
    pub domain_suffix: Vec<String>,

    /// 内联域名关键词（OR）。支持单字符串或数组形式。
    pub domain_keyword: Vec<String>,

    /// 内联域名正则表达式（OR）。
    ///
    /// 与 sing-box `domain_regex` 字段对齐。匹配目标域名（大小写不敏感）。
    /// 每个元素是一个 Rust/Go 兼容的正则表达式。支持单字符串或数组形式。
    ///
    /// 示例：匹配所有 Google 相关域名：
    /// ```json
    /// { "domain_regex": ["^.*\\.google\\.com$", "^.*\\.googleapis\\.com$"], "outbound": "proxy" }
    /// ```
    pub domain_regex: Vec<String>,

    /// 内联 IP CIDR（OR），支持 v4 和 v6。支持单字符串或数组形式。
    pub ip_cidr: Vec<String>,

    /// 目标端口过滤（OR），支持单端口和范围。
    /// 单值形式：`"port": 443` 或 `"port": "8000-9000"`；
    /// 数组形式：`"port": [80, 443, "8000-9000"]`。
    pub port: Vec<PortFilter>,

    /// 目标端口范围（备用写法，与 port 字段合并处理）。支持单字符串或数组形式。
    pub port_range: Vec<String>,

    // ── 进程匹配 ─────────────────────────────────────────────────────────
    /// 按进程名匹配（OR 语义）。仅在 Linux 上支持，其他平台规则不生效。
    /// 支持单字符串或数组形式。
    ///
    /// 进程名来自 `/proc/<pid>/comm`（如 `"chrome"`、`"Telegram"`），
    /// 大小写敏感完整匹配。
    ///
    /// 典型用法（让 Telegram 走代理）：
    /// ```json
    /// { "process_name": ["Telegram"], "outbound": "proxy" }
    /// ```
    ///
    /// 注意：进程查找需要读取 `/proc`，开销较高，规则匹配会带 5 秒 LRU 缓存。
    /// 仅对 TUN/TProxy 入站有效（能拿到真实源地址），SOCKS5/HTTP 入站拿到的
    /// 是客户端 socket 地址，可能匹配不到进程。
    pub process_name: Vec<String>,

    /// 按进程可执行文件路径匹配（OR 语义）。仅在 Linux 上支持。
    /// 支持单字符串或数组形式。
    ///
    /// 路径来自 `/proc/<pid>/exe`（如 `"/usr/bin/telegram-desktop"`），
    /// 大小写敏感的子串包含匹配（包含即命中，对齐 sing-box `process_path`）。
    ///
    /// 典型用法：
    /// ```json
    /// { "process_path": ["/usr/bin/telegram-desktop"], "outbound": "proxy" }
    /// ```
    pub process_path: Vec<String>,

    // ── 规则反转 ──────────────────────────────────────────────
    /// 反转所有匹配条件的结果（逻辑 NOT）。
    ///
    /// 与 sing-box `invert` 字段对齐。
    /// 设为 true 时，规则在所有其他条件**均不命中**时才触发。
    ///
    /// 示例：所有非国内流量走代理：
    /// ```json
    /// { "ruleset": ["geosite-cn"], "invert": true, "outbound": "proxy" }
    /// ```
    /// 等价于：未命中 geosite-cn 的流量 → proxy。
    ///
    /// 注意：`invert` 对 `sniff`、`resolve`、`hijack_dns` 等动作类字段无效，
    /// 只反转地址/协议/端口等匹配条件的聚合结果。
    pub invert: bool,

    // ── Clash API 模式 ────────────────────────────────────────────────────
    /// 仅当 Clash API 当前模式（`PATCH /configs` 设置的 `mode`）等于该值时才
    /// 命中本规则，大小写不敏感。与 sing-box `clash_mode` 规则条件对齐。
    ///
    /// 和 sing-box 一样，"global"/"direct" 这些模式名本身没有任何硬编码行为——
    /// 是否在某个模式下强制走某个 outbound，完全由你自己写规则决定：
    /// ```json
    /// { "clash_mode": "global", "outbound": "我的全局选择器" }
    /// { "clash_mode": "direct", "outbound": "direct" }
    /// ```
    /// 把这两条放在规则列表最前面，就能让 Dashboard 上的模式切换按钮真正生效。
    ///
    /// 该条件作为硬性前置过滤（类似 `inbound`/`network`/`protocol`），不受
    /// `invert` 影响。
    pub clash_mode: Option<String>,

    /// 嗅探到的应用层协议过滤（OR），如 `["dns"]`。
    /// 匹配由 DNS inbound 进入或嗅探识别出的协议名称。
    /// 目前支持的值：`"dns"`。支持单字符串或数组形式。
    pub protocol: Vec<String>,

    // ── 显式动作（sing-box 风格）────────────────────────────────────────
    /// 显式动作声明（`"action": "route" | "reject" | "block" | "hijack-dns" |
    /// "sniff" | "resolve"`）。
    ///
    /// 未填写时默认 `action: "route"`（此时 `outbound` 必填）。反序列化后恒为
    /// `Some`。动作参数（route 的 `outbound`、sniff 的 `sniff_type` 等）与
    /// 条件字段平铺在同一规则对象中；与动作无关的参数字段会报错。
    pub action: Option<RouteActionConfig>,
}

impl RouteRuleConfig {
    /// 显式动作是否等于某种类型（`f` 用于匹配 `RouteActionConfig`）。
    fn action_is(&self, f: impl FnOnce(&RouteActionConfig) -> bool) -> bool {
        self.action.as_ref().is_some_and(f)
    }

    /// 是否为 DNS 劫持规则（`action: "hijack-dns"`）。
    pub fn is_hijack_dns(&self) -> bool {
        self.action_is(|a| matches!(a, RouteActionConfig::HijackDns))
    }

    /// 是否为嗅探规则（`action: "sniff"`）。
    pub fn is_sniff_rule(&self) -> bool {
        self.action_is(|a| matches!(a, RouteActionConfig::Sniff { .. }))
    }

    /// 是否为解析规则（`action: "resolve"`）。
    pub fn is_resolve_rule(&self) -> bool {
        self.action_is(|a| matches!(a, RouteActionConfig::Resolve { .. }))
    }

    /// 是否为拒绝/阻断规则（`action: "reject"` / `"block"`）。
    pub fn is_reject_rule(&self) -> bool {
        self.action_is(|a| {
            matches!(a, RouteActionConfig::Reject { .. } | RouteActionConfig::Block)
        })
    }

    /// 该规则实际使用的 outbound tag：
    /// - 动作是 `route` 时返回其 `outbound`（含 `"dns-out"`）
    /// - 其余动作返回空串
    pub fn outbound_tag(&self) -> &str {
        match self.action.as_ref() {
            Some(RouteActionConfig::Route { outbound, .. }) => outbound.as_str(),
            _ => "",
        }
    }

    /// 是否需要校验 outbound tag 已注册：
    /// 仅当动作是 `route`、outbound 非空且不是 `"dns-out"` 时返回 `true`。
    /// 供配置校验逻辑统一使用（sniff/resolve/hijack-dns/block/reject 自动跳过）。
    pub fn requires_outbound_tag(&self) -> bool {
        match self.action.as_ref() {
            Some(RouteActionConfig::Route { outbound, .. }) => {
                !outbound.is_empty() && outbound != "dns-out"
            }
            _ => false,
        }
    }
}

impl RouteRuleConfig {
    /// 是否有任何匹配条件（全空的规则无意义）
    pub fn has_conditions(&self) -> bool {
        !self.inbound.is_empty()
            || self.network.is_some()
            || !self.protocol.is_empty()
            || !self.ruleset.is_empty()
            || !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.ip_cidr.is_empty()
            || !self.source_ip_cidr.is_empty()
            || !self.port.is_empty()
            || !self.port_range.is_empty()
            || !self.process_name.is_empty()
            || !self.process_path.is_empty()
            || self.clash_mode.is_some()
    }
}

// ── RouteRuleConfig 反序列化：action 唯一决定动作，无 action 默认 route ─────

/// 反序列化中间表示：镜像 `RouteRuleConfig` 的全部条件字段。
/// 无 `action` 字段（动作由 `RouteActionConfig` 单独解析）。
#[derive(Deserialize)]
#[allow(dead_code)]
struct RouteRuleRaw {
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    inbound: Vec<String>,
    #[serde(default)]
    network: Option<NetworkFilter>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    ruleset: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    domain: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    domain_regex: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    ip_cidr: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    source_ip_cidr: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    port: Vec<PortFilter>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    port_range: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    process_name: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    process_path: Vec<String>,
    #[serde(default)]
    invert: bool,
    #[serde(default)]
    clash_mode: Option<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    protocol: Vec<String>,
}

/// 条件字段（所有 action 共有，反序列化时出现在规则对象中）。
const ROUTE_COMMON_FIELDS: &[&str] = &[
    "action",
    "inbound",
    "network",
    "ruleset",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "source_ip_cidr",
    "port",
    "port_range",
    "process_name",
    "process_path",
    "invert",
    "clash_mode",
    "protocol",
];

/// 各 action 允许的参数（除条件字段外）。
fn route_action_params(action: &str) -> &'static [&'static str] {
    match action {
        "route" => &["outbound", "override_address", "override_port", "udp_timeout"],
        "reject" => &["method"],
        "block" => &[],
        "hijack-dns" => &[],
        "sniff" => &[
            "timeout_ms",
            "override_destination",
            "sniff_type",
            "force_domain",
            "skip_domain",
            "skip_src_address",
        ],
        "resolve" => &["server"],
        _ => &[],
    }
}

/// 校验规则对象的字段归属：条件字段或当前 action 的参数，其余报错。
/// 由此实现「动作参数严格归属」：`action: "route"` 不能带 sniff/resolve 参数，
/// `action: "sniff"` 不能带 outbound 等。
fn validate_route_action_fields(action: &str, obj: &serde_json::Map<String, serde_json::Value>) -> anyhow::Result<()> {
    let params = route_action_params(action);
    for key in obj.keys() {
        if !ROUTE_COMMON_FIELDS.contains(&key.as_str()) && !params.contains(&key.as_str()) {
            anyhow::bail!(
                "route rule: field '{key}' is not valid for action '{action}' \
                 (allowed action params: {})",
                params.join(", ")
            );
        }
    }
    Ok(())
}

impl RouteRuleConfig {
    /// 从 JSON Value 组装规则：`action` 决定动作；无 `action` 默认 `route`（outbound 必填）。
    fn from_value(value: serde_json::Value) -> anyhow::Result<Self> {
        use serde::Deserialize as _;
        let raw = RouteRuleRaw::deserialize(value.clone())?;

        let action = match value.get("action").and_then(|v| v.as_str()) {
            Some(action_name) => {
                let obj = value
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("route rule must be an object"))?;
                validate_route_action_fields(action_name, obj)?;
                // 显式解析（internally tagged，需要整个 map 才能读到 `action` tag）
                RouteActionConfig::deserialize(value)?
            }
            None => {
                // 无 action：默认 route，outbound 必填
                let obj = value
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("route rule must be an object"))?;
                validate_route_action_fields("route", obj)?;
                let outbound = obj
                    .get("outbound")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "route rule: missing required field `outbound` \
                             (no `action` specified, defaults to `route`)"
                        )
                    })?
                    .to_string();
                RouteActionConfig::Route {
                    outbound,
                    override_address: obj
                        .get("override_address")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    override_port: obj.get("override_port").and_then(|v| v.as_u64()).map(|p| p as u16),
                    udp_timeout: obj.get("udp_timeout").and_then(|v| v.as_u64()),
                }
            }
        };

        Ok(RouteRuleConfig {
            inbound: raw.inbound,
            network: raw.network,
            ruleset: raw.ruleset,
            domain: raw.domain,
            domain_suffix: raw.domain_suffix,
            domain_keyword: raw.domain_keyword,
            domain_regex: raw.domain_regex,
            ip_cidr: raw.ip_cidr,
            source_ip_cidr: raw.source_ip_cidr,
            port: raw.port,
            port_range: raw.port_range,
            process_name: raw.process_name,
            process_path: raw.process_path,
            invert: raw.invert,
            clash_mode: raw.clash_mode,
            protocol: raw.protocol,
            action: Some(action),
        })
    }
}

impl<'de> Deserialize<'de> for RouteRuleConfig {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(de)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

impl Serialize for RouteRuleConfig {
    /// 序列化为规范形式：条件字段 + `action` 展平字段（不再输出旧式动作字段）。
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Ser<'a> {
            inbound: &'a [String],
            network: &'a Option<NetworkFilter>,
            ruleset: &'a [String],
            domain: &'a [String],
            domain_suffix: &'a [String],
            domain_keyword: &'a [String],
            domain_regex: &'a [String],
            ip_cidr: &'a [String],
            source_ip_cidr: &'a [String],
            port: &'a [PortFilter],
            port_range: &'a [String],
            process_name: &'a [String],
            process_path: &'a [String],
            invert: bool,
            clash_mode: &'a Option<String>,
            protocol: &'a [String],
            #[serde(flatten)]
            action: &'a RouteActionConfig,
        }
        // 反序列化后 `action` 恒为 Some；Default 构造的兜底值
        let fallback = RouteActionConfig::Route {
            outbound: String::new(),
            override_address: None,
            override_port: None,
            udp_timeout: None,
        };
        let ser = Ser {
            inbound: &self.inbound,
            network: &self.network,
            ruleset: &self.ruleset,
            domain: &self.domain,
            domain_suffix: &self.domain_suffix,
            domain_keyword: &self.domain_keyword,
            domain_regex: &self.domain_regex,
            ip_cidr: &self.ip_cidr,
            source_ip_cidr: &self.source_ip_cidr,
            port: &self.port,
            port_range: &self.port_range,
            process_name: &self.process_name,
            process_path: &self.process_path,
            invert: self.invert,
            clash_mode: &self.clash_mode,
            protocol: &self.protocol,
            action: self.action.as_ref().unwrap_or(&fallback),
        };
        ser.serialize(s)
    }
}

// ── RuleSet 引用 ──────────────────────────────────────────────────────────────

/// 规则集来源类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetType {
    /// 本地文件，必须配合 `path` 字段使用
    Local,
    /// 远程 URL，必须配合 `url` 字段使用；可选填 `path` 作为本地缓存路径
    Remote,
}

/// 规则集文件格式，与 sing-box `format` 字段对齐。
///
/// | 值          | 含义                                                        |
/// |-------------|-------------------------------------------------------------|
/// | `"binary"`  | 预编译的 `.rrs` 二进制格式（默认）                          |
/// | `"source"`  | 文本或 sing-box JSON Source Rule Set，运行时自动编译        |
///
/// `"source"` 格式支持两种内容：
/// - sing-box JSON（`{"version":2,"rules":[...]}` 格式，`.json`/`.srs` 文件）
/// - Reflex 文本格式（每行 `key: value`，`.txt`/`.list` 文件）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetFormat {
    /// 预编译二进制（`.rrs`），默认值
    #[default]
    Binary,
    /// 文本或 sing-box JSON Source Rule Set，启动时实时编译
    Source,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetRef {
    /// 在 rules 中引用的名字
    pub tag: String,

    /// 来源类型：`"local"` 或 `"remote"`
    pub r#type: RuleSetType,

    /// 规则集文件格式，与 sing-box `format` 字段对齐。
    /// - `"binary"`（默认）：预编译的 `.rrs` 二进制
    /// - `"source"`：sing-box JSON 或 Reflex 文本格式，运行时自动编译
    #[serde(default)]
    pub format: RuleSetFormat,

    /// 本地文件路径。
    /// - `type = "local"` 时**必填**，指定规则集文件位置。
    /// - `type = "remote"` 时**选填**，作为下载后的本地缓存路径；
    ///   不填则缓存到 cache_file（若未启用则仅驻留内存）。
    #[serde(default)]
    pub path: Option<String>,

    /// 远程规则集 URL（`type = "remote"` 时**必填**）。
    #[serde(default)]
    pub url: Option<String>,

    /// 用于下载远程规则集的出站 tag（选填）。
    /// 填写时通过该出站下载，无法下载则报错；不填则直连下载。
    #[serde(default)]
    pub download_detour: Option<String>,

    /// 定时更新间隔（仅 `type = "remote"` 有效），与 sing-box `update_interval` 对齐。
    ///
    /// 格式同 provider 的 `update_interval`：`"1h"`、`"30m"`、`"1d"` 等。
    /// 不填则不自动更新（只在启动时下载一次）。
    #[serde(default)]
    pub update_interval: Option<String>,
}

// ── 辅助类型 ──────────────────────────────────────────────────────────────────

/// 路由规则的网络类型过滤，对齐 sing-box `route.rules[].network`。
///
/// 取值：
/// - `"tcp"`：仅匹配 TCP 连接
/// - `"udp"`：仅匹配 UDP 会话
/// - `"icmp"`：仅匹配 ICMP 回显（ping）请求（对齐 sing-box 1.13.0 的 `icmp` 网络类型）
///
/// 仅对 TUN 入站（能拿到原始 IP 包）的 ICMP 流量生效；其他入站类型
/// 不会产生 `NetworkKind::Icmp` 的路由请求，`icmp` 规则对它们恒不命中。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFilter {
    Tcp,
    Udp,
    Icmp,
}

/// 端口过滤：可以是数字或 "start-end" 字符串，用自定义反序列化处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortFilter(pub u16, pub u16); // (start, end)，单端口则 start == end

impl PortFilter {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.0 && port <= self.1
    }
}

impl<'de> Deserialize<'de> for PortFilter {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PortFilter;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a port number or a range string like \"8000-9000\"")
            }
            // JSON 数字
            fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
                if v > 65535 {
                    return Err(E::custom(format!("port {v} out of range")));
                }
                Ok(PortFilter(v as u16, v as u16))
            }
            // JSON 字符串 "8000-9000"
            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                if let Some((s, e)) = v.split_once('-') {
                    let start: u16 = s.trim().parse().map_err(E::custom)?;
                    let end: u16 = e.trim().parse().map_err(E::custom)?;
                    if start > end {
                        return Err(E::custom(format!("invalid range: {v}")));
                    }
                    Ok(PortFilter(start, end))
                } else {
                    let p: u16 = v.trim().parse().map_err(E::custom)?;
                    Ok(PortFilter(p, p))
                }
            }
        }
        de.deserialize_any(Visitor)
    }
}

impl Serialize for PortFilter {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0 == self.1 {
            s.serialize_u16(self.0)
        } else {
            s.serialize_str(&format!("{}-{}", self.0, self.1))
        }
    }
}

fn default_true() -> bool {
    true
}

/// `route.final` 的默认值：`"direct"`。
///
/// 与 OutboundManager 自动补的 direct 出站自动关联，实现零配置启动。
fn default_route_final() -> String {
    "direct".to_string()
}

impl Default for RouteConfig {
    fn default() -> Self {
        RouteConfig {
            rules: Vec::new(),
            r#final: default_route_final(),
            rule_set: Vec::new(),
            resolve_dns: false,
            ipv6: default_true(),
            auto_detect_interface: false,
            default_interface: None,
            default_mark: None,
            hijack_dns: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_route_config() {
        let v = json!({
            "rules": [
                {
                    "inbound": ["dns-in"],
                    "outbound": "dns-out"
                },
                {
                    "ruleset": ["geoip-cn", "geosite-cn"],
                    "outbound": "direct"
                },
                {
                    "network": "udp",
                    "port": [53],
                    "outbound": "dns-out"
                },
                {
                    "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
                    "outbound": "direct"
                },
                {
                    "domain_suffix": [".cn"],
                    "port": [80, 443, "8000-9000"],
                    "outbound": "direct"
                }
            ],
            "final": "proxy",
            "rule_set": [
                { "tag": "geosite-cn", "type": "local", "path": "/etc/proxy/rules/geosite-cn.rrs" },
                { "tag": "geoip-cn",   "type": "local", "path": "/etc/proxy/rules/geoip-cn.rrs"   }
            ]
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules.len(), 5);
        assert_eq!(route.r#final, "proxy");
        assert_eq!(route.rule_set.len(), 2);
    }

    #[test]
    fn parse_domain_regex() {
        let v = json!({
            "rules": [
                {
                    "domain_regex": ["^.*\\.google\\.com$", "^.*\\.googleapis\\.com$"],
                    "outbound": "proxy"
                }
            ],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].domain_regex.len(), 2);
        assert_eq!(route.rules[0].domain_regex[0], "^.*\\.google\\.com$");
    }

    #[test]
    fn parse_source_ip_cidr() {
        let v = json!({
            "rules": [
                {
                    "source_ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
                    "outbound": "direct"
                }
            ],
            "final": "proxy"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].source_ip_cidr.len(), 2);
    }

    #[test]
    fn parse_invert() {
        let v = json!({
            "rules": [
                {
                    "ruleset": ["geosite-cn"],
                    "invert": true,
                    "outbound": "proxy"
                }
            ],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert!(route.rules[0].invert);
    }

    #[test]
    fn parse_string_or_array_fields() {
        // ruleset：单字符串 vs 数组 vs 缺省
        let v = json!({
            "rules": [{ "ruleset": "geosite-cn", "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].ruleset, vec!["geosite-cn"]);

        let v = json!({
            "rules": [{ "ruleset": ["geosite-cn", "geoip-cn"], "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].ruleset, vec!["geosite-cn", "geoip-cn"]);

        let v = json!({
            "rules": [{ "domain_suffix": [".cn"], "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert!(route.rules[0].ruleset.is_empty());

        // domain / domain_suffix / domain_keyword：单字符串形式
        let v = json!({
            "rules": [{
                "domain": "example.com",
                "domain_suffix": ".cn",
                "domain_keyword": "google",
                "domain_regex": "^.*\\.google\\.com$",
                "outbound": "direct"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].domain, vec!["example.com"]);
        assert_eq!(route.rules[0].domain_suffix, vec![".cn"]);
        assert_eq!(route.rules[0].domain_keyword, vec!["google"]);
        assert_eq!(route.rules[0].domain_regex, vec!["^.*\\.google\\.com$"]);

        // ip_cidr / source_ip_cidr：单字符串形式
        let v = json!({
            "rules": [{
                "ip_cidr": "192.168.0.0/16",
                "source_ip_cidr": "10.0.0.0/8",
                "outbound": "direct"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].ip_cidr, vec!["192.168.0.0/16"]);
        assert_eq!(route.rules[0].source_ip_cidr, vec!["10.0.0.0/8"]);

        // port：单值 u16 / 单值字符串范围 / 数组
        let v = json!({
            "rules": [{ "port": 443, "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].port, vec![PortFilter(443, 443)]);

        let v = json!({
            "rules": [{ "port": "8000-9000", "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].port, vec![PortFilter(8000, 9000)]);

        let v = json!({
            "rules": [{ "port": [80, 443, "8000-9000"], "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            route.rules[0].port,
            vec![
                PortFilter(80, 80),
                PortFilter(443, 443),
                PortFilter(8000, 9000)
            ]
        );

        // port_range：单字符串 vs 数组
        let v = json!({
            "rules": [{ "port_range": "8000-9000", "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].port_range, vec!["8000-9000"]);

        // inbound / process_name / process_path：单字符串形式
        let v = json!({
            "rules": [{
                "inbound": "tun-in",
                "process_name": "Telegram",
                "process_path": "/usr/bin/telegram-desktop",
                "outbound": "proxy"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].inbound, vec!["tun-in"]);
        assert_eq!(route.rules[0].process_name, vec!["Telegram"]);
        assert_eq!(
            route.rules[0].process_path,
            vec!["/usr/bin/telegram-desktop"]
        );

        // sniff 相关字段：单字符串形式（action: sniff 的参数）
        let v = json!({
            "rules": [{
                "action": "sniff",
                "sniff_type": "tls",
                "force_domain": ".cn",
                "skip_domain": ".local",
                "skip_src_address": "127.0.0.0/8",
                "protocol": "dns"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        match &route.rules[0].action {
            Some(RouteActionConfig::Sniff {
                sniff_type,
                force_domain,
                skip_domain,
                skip_src_address,
                ..
            }) => {
                assert_eq!(sniff_type, &vec!["tls"]);
                assert_eq!(force_domain, &vec![".cn"]);
                assert_eq!(skip_domain, &vec![".local"]);
                assert_eq!(skip_src_address, &vec!["127.0.0.0/8"]);
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(route.rules[0].protocol, vec!["dns"]);
    }

    #[test]
    fn parse_auto_detect_interface() {
        let v = json!({
            "rules": [],
            "final": "proxy",
            "auto_detect_interface": true,
            "default_interface": "eth0",
            "default_mark": 100
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert!(route.auto_detect_interface);
        assert_eq!(route.default_interface.as_deref(), Some("eth0"));
        assert_eq!(route.default_mark, Some(100));
    }

    #[test]
    fn has_conditions_with_new_fields() {
        let base = RouteRuleConfig::default();

        let with_regex = RouteRuleConfig {
            domain_regex: vec![".*\\.google\\.com".into()],
            ..base.clone()
        };
        assert!(with_regex.has_conditions());

        let with_src_cidr = RouteRuleConfig {
            source_ip_cidr: vec!["192.168.0.0/16".into()],
            ..base.clone()
        };
        assert!(with_src_cidr.has_conditions());

        // invert 单独不算条件
        let invert_only = RouteRuleConfig {
            invert: true,
            ..base.clone()
        };
        assert!(!invert_only.has_conditions());
    }

    #[test]
    fn parse_ruleset_format_and_update_interval() {
        let v = json!({
            "rules": [],
            "final": "direct",
            "rule_set": [
                // binary（默认，省略 format 字段）
                {
                    "tag": "geosite-cn",
                    "type": "local",
                    "path": "/tmp/geosite-cn.rrs"
                },
                // source 格式 + update_interval
                {
                    "tag": "geosite-ads",
                    "type": "remote",
                    "format": "source",
                    "url": "https://example.com/geosite-ads.json",
                    "path": "/tmp/geosite-ads.json",
                    "update_interval": "24h"
                },
                // source 格式本地文件
                {
                    "tag": "custom-list",
                    "type": "local",
                    "format": "source",
                    "path": "/etc/reflex/custom.txt"
                }
            ]
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rule_set.len(), 3);

        // 默认 binary
        assert_eq!(route.rule_set[0].format, RuleSetFormat::Binary);
        assert!(route.rule_set[0].update_interval.is_none());

        // source + update_interval
        assert_eq!(route.rule_set[1].format, RuleSetFormat::Source);
        assert_eq!(route.rule_set[1].update_interval.as_deref(), Some("24h"));
        assert_eq!(
            route.rule_set[1].url.as_deref(),
            Some("https://example.com/geosite-ads.json")
        );

        // source 本地
        assert_eq!(route.rule_set[2].format, RuleSetFormat::Source);
        assert_eq!(route.rule_set[2].r#type, RuleSetType::Local);
    }

    #[test]
    fn port_filter_number() {
        let pf: PortFilter = serde_json::from_value(json!(443)).unwrap();
        assert_eq!(pf, PortFilter(443, 443));
        assert!(pf.contains(443));
        assert!(!pf.contains(80));
    }

    #[test]
    fn port_filter_range_str() {
        let pf: PortFilter = serde_json::from_value(json!("8000-9000")).unwrap();
        assert_eq!(pf, PortFilter(8000, 9000));
        assert!(pf.contains(8000));
        assert!(pf.contains(8500));
        assert!(pf.contains(9000));
        assert!(!pf.contains(7999));
    }

    #[test]
    fn port_filter_invalid_range() {
        let r: Result<PortFilter, _> = serde_json::from_value(json!("9000-8000"));
        assert!(r.is_err());
    }

    #[test]
    fn rule_has_conditions() {
        let empty = RouteRuleConfig::default();
        assert!(!empty.has_conditions());

        // 无条件规则（如 action: sniff 的 catch-all）has_conditions 为 false
        let with_ruleset = RouteRuleConfig {
            ruleset: vec!["geosite-cn".into()],
            ..empty.clone()
        };
        assert!(with_ruleset.has_conditions());

        let with_protocol = RouteRuleConfig {
            protocol: vec!["dns".into()],
            ..empty
        };
        assert!(with_protocol.has_conditions());
    }

    #[test]
    fn port_filter_serialize() {
        let single = PortFilter(443, 443);
        assert_eq!(serde_json::to_string(&single).unwrap(), "443");

        let range = PortFilter(8000, 9000);
        assert_eq!(serde_json::to_string(&range).unwrap(), "\"8000-9000\"");
    }

    // ── 显式 action 解析（sing-box 风格）──────────────────────────────────

    #[test]
    fn parse_explicit_action_route() {
        let v = json!({
            "rules": [
                { "domain_suffix": [".cn"], "action": "route", "outbound": "direct" },
                { "ip_cidr": ["1.1.1.0/24"], "action": "route", "outbound": "proxy",
                  "override_address": "10.0.0.1", "override_port": 8443, "udp_timeout": 300 }
            ],
            "final": "proxy"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        let r0 = &route.rules[0];
        assert_eq!(
            r0.action,
            Some(RouteActionConfig::Route {
                outbound: "direct".into(),
                override_address: None,
                override_port: None,
                udp_timeout: None,
            })
        );
        assert_eq!(r0.outbound_tag(), "direct");
        assert!(r0.requires_outbound_tag());

        let r1 = &route.rules[1];
        match &r1.action {
            Some(RouteActionConfig::Route {
                outbound,
                override_address,
                override_port,
                udp_timeout,
            }) => {
                assert_eq!(outbound, "proxy");
                assert_eq!(override_address.as_deref(), Some("10.0.0.1"));
                assert_eq!(*override_port, Some(8443));
                assert_eq!(*udp_timeout, Some(300));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn parse_explicit_action_reject_and_block() {
        let v = json!({
            "rules": [
                { "port": 853, "action": "reject" },
                { "ruleset": ["geosite-ads"], "action": "reject", "method": "drop" },
                { "ruleset": ["geosite-ads2"], "action": "block" },
                { "network": "udp", "port": [443], "action": "block" }
            ],
            "final": "proxy"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            route.rules[0].action,
            Some(RouteActionConfig::Reject { method: None })
        );
        assert_eq!(
            route.rules[1].action,
            Some(RouteActionConfig::Reject {
                method: Some(RejectMethod::Drop)
            })
        );
        assert_eq!(route.rules[2].action, Some(RouteActionConfig::Block));
        assert_eq!(route.rules[3].action, Some(RouteActionConfig::Block));
        // 非 route 动作不依赖 outbound tag
        assert!(!route.rules[0].requires_outbound_tag());
        assert!(route.rules[0].is_reject_rule());
        assert!(route.rules[2].is_reject_rule());
    }

    #[test]
    fn parse_explicit_action_sniff_resolve_hijack() {
        let v = json!({
            "rules": [
                { "action": "sniff", "sniff_type": ["tls", "http"], "timeout_ms": 500 },
                { "action": "resolve", "server": "local" },
                { "protocol": ["dns"], "action": "hijack-dns" }
            ],
            "final": "proxy"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        match &route.rules[0].action {
            Some(RouteActionConfig::Sniff {
                timeout_ms,
                override_destination,
                sniff_type,
                force_domain,
                skip_domain,
                skip_src_address,
            }) => {
                assert_eq!(*timeout_ms, 500);
                assert!(!*override_destination);
                assert_eq!(sniff_type, &vec!["tls".to_string(), "http".to_string()]);
                assert!(force_domain.is_empty());
                assert!(skip_domain.is_empty());
                assert!(skip_src_address.is_empty());
            }
            other => panic!("unexpected action: {other:?}"),
        }
        assert_eq!(
            route.rules[1].action,
            Some(RouteActionConfig::Resolve {
                server: Some(DnsServerRef::single("local"))
            })
        );
        assert_eq!(route.rules[2].action, Some(RouteActionConfig::HijackDns));
        assert!(route.rules[0].is_sniff_rule());
        assert!(route.rules[1].is_resolve_rule());
        assert!(route.rules[2].is_hijack_dns());
    }

    #[test]
    fn parse_reject_method_reply() {
        let v = json!({
            "rules": [{ "port": 853, "action": "reject", "method": "reply" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            route.rules[0].action,
            Some(RouteActionConfig::Reject {
                method: Some(RejectMethod::Reply)
            })
        );
    }

    // ── 默认动作：无 action 时默认 route ─────────────────────────────────

    #[test]
    fn no_action_defaults_to_route() {
        // 无 action + outbound → 默认 route
        let v = json!({
            "rules": [{ "domain_suffix": [".cn"], "outbound": "direct", "udp_timeout": 120 }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        let r = &route.rules[0];
        assert_eq!(r.outbound_tag(), "direct");
        assert!(r.requires_outbound_tag());
        assert_eq!(
            r.action,
            Some(RouteActionConfig::Route {
                outbound: "direct".into(),
                override_address: None,
                override_port: None,
                udp_timeout: Some(120),
            })
        );

        // outbound dns-out → route(dns-out)（编译层映射为 DnsOut）
        let v = json!({
            "rules": [{ "inbound": ["dns-in"], "outbound": "dns-out" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].outbound_tag(), "dns-out");
        assert!(!route.rules[0].requires_outbound_tag());
        assert!(!route.rules[0].is_hijack_dns());
        match &route.rules[0].action {
            Some(RouteActionConfig::Route { outbound, .. }) => assert_eq!(outbound, "dns-out"),
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn no_action_missing_outbound_rejected() {
        // 无 action 且无 outbound → 报错（默认 route 需要 outbound）
        let v = json!({
            "rules": [{ "domain_suffix": [".cn"] }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());
    }

    // ── 动作参数严格归属 ────────────────────────────────────────────────

    #[test]
    fn action_params_strictly_validated() {
        // action=route 不能带 sniff 参数
        let v = json!({
            "rules": [{ "action": "route", "outbound": "proxy", "sniff_type": ["tls"] }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        // action=sniff 不能带 outbound
        let v = json!({
            "rules": [{ "action": "sniff", "outbound": "proxy" }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        // action=block 不能带 method 之外的参数
        let v = json!({
            "rules": [{ "action": "block", "server": "local" }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        // action=reject 不能带 outbound
        let v = json!({
            "rules": [{ "action": "reject", "outbound": "proxy" }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        // action=hijack-dns 不能带 outbound
        let v = json!({
            "rules": [{ "action": "hijack-dns", "protocol": ["dns"], "outbound": "proxy" }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());
    }

    // ── 冲突与错误场景 ────────────────────────────────────────────────────

    #[test]
    fn explicit_action_conflict_rejected() {
        // action + sniff 开关同时出现
        let v = json!({
            "rules": [{ "action": "sniff", "sniff": true }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        // action + resolve 开关同时出现
        let v = json!({
            "rules": [{ "action": "resolve", "resolve": true }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        // action + hijack_dns 开关同时出现
        let v = json!({
            "rules": [{ "protocol": ["dns"], "action": "hijack-dns", "hijack_dns": true }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        // action + private_ip 开关同时出现
        let v = json!({
            "rules": [{ "action": "route", "outbound": "direct", "private_ip": true }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());
    }

    #[test]
    fn legacy_switch_fields_rejected() {
        // 旧式动作开关字段（sniff: true 等）已完全移除，配置加载报错
        let v = json!({
            "rules": [{ "sniff": true }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        let v = json!({
            "rules": [{ "resolve": true, "server": "local" }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        let v = json!({
            "rules": [{ "hijack_dns": true, "protocol": ["dns"] }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());

        let v = json!({
            "rules": [{ "private_ip": true }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());
    }

    #[test]
    fn explicit_action_route_with_outbound_is_valid() {
        // 显式 route + outbound 是 Route 变体的合法字段，不是冲突
        let v = json!({
            "rules": [{ "domain": "x.com", "action": "route", "outbound": "proxy" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].outbound_tag(), "proxy");
        assert!(route.rules[0].requires_outbound_tag());
        assert_eq!(
            route.rules[0].action,
            Some(RouteActionConfig::Route {
                outbound: "proxy".into(),
                override_address: None,
                override_port: None,
                udp_timeout: None,
            })
        );
    }

    #[test]
    fn explicit_action_unknown_value_rejected() {
        let v = json!({
            "rules": [{ "action": "not-a-real-action" }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());
    }

    #[test]
    fn explicit_action_route_missing_outbound_rejected() {
        let v = json!({
            "rules": [{ "domain": "x.com", "action": "route" }],
            "final": "direct"
        });
        assert!(serde_json::from_value::<RouteConfig>(v).is_err());
    }

    // ── 序列化 round-trip（规范形式）──────────────────────────────────────

    #[test]
    fn explicit_action_serialize_roundtrip() {
        let v = json!({
            "rules": [
                { "domain_suffix": [".cn"], "action": "route", "outbound": "direct", "udp_timeout": 120 },
                { "port": 853, "action": "reject", "method": "reply" },
                { "ruleset": ["geosite-ads"], "action": "block" }
            ],
            "final": "proxy"
        });
        let route: RouteConfig = serde_json::from_value(v.clone()).unwrap();
        // 序列化→反序列化应等价
        let s = serde_json::to_string(&route).unwrap();
        let route2: RouteConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(route.rules.len(), route2.rules.len());
        for (a, b) in route.rules.iter().zip(route2.rules.iter()) {
            assert_eq!(a.action, b.action);
            assert_eq!(a.domain_suffix, b.domain_suffix);
            assert_eq!(a.port, b.port);
        }
        // 序列化输出规范形式：包含 action tag，不再有旧式动作字段
        let rule_json = &s;
        assert!(rule_json.contains("\"action\":\"route\"") || rule_json.contains("\"action\": \"route\""));
        assert!(rule_json.contains("\"action\":\"reject\"") || rule_json.contains("\"action\": \"reject\""));
        assert!(rule_json.contains("\"action\":\"block\"") || rule_json.contains("\"action\": \"block\""));
    }

    #[test]
    fn default_route_serialize_roundtrip() {
        // 无 action（默认 route）配置序列化为规范 action 形式，仍可反序列化
        let v = json!({
            "rules": [{ "domain_suffix": [".cn"], "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        let s = serde_json::to_string(&route).unwrap();
        let route2: RouteConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(route.rules[0].action, route2.rules[0].action);
        assert_eq!(route.rules[0].domain_suffix, route2.rules[0].domain_suffix);
        assert_eq!(route.rules[0].outbound_tag(), "direct");
    }

    #[test]
    fn action_helper_methods() {
        let mk = |action: Option<RouteActionConfig>| RouteRuleConfig {
            action,
            ..Default::default()
        };
        assert!(mk(Some(RouteActionConfig::Block)).is_reject_rule());
        assert!(mk(Some(RouteActionConfig::Reject { method: None })).is_reject_rule());
        assert!(!mk(Some(RouteActionConfig::Route {
            outbound: "proxy".into(),
            override_address: None,
            override_port: None,
            udp_timeout: None,
        }))
        .is_reject_rule());

        let r = mk(Some(RouteActionConfig::Route {
            outbound: "dns-out".into(),
            override_address: None,
            override_port: None,
            udp_timeout: None,
        }));
        assert_eq!(r.outbound_tag(), "dns-out");
        assert!(!r.requires_outbound_tag());

        let r = mk(Some(RouteActionConfig::Route {
            outbound: "".into(),
            override_address: None,
            override_port: None,
            udp_timeout: None,
        }));
        assert!(!r.requires_outbound_tag());
    }
}
