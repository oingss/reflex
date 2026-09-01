use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsServerRef(pub Vec<String>);

impl DnsServerRef {
    /// 构造单元素引用（用于默认值和测试）。
    pub fn single(tag: impl Into<String>) -> Self {
        Self(vec![tag.into()])
    }

    /// 返回所有 tag 的切片。
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// 是否为单元素（决定序列化形式与是否走快速路径）。
    pub fn is_single(&self) -> bool {
        self.0.len() == 1
    }

    /// 用分隔符拼接所有 tag（用于组合缓存键）。
    pub fn join(&self, sep: &str) -> String {
        self.0
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(sep)
    }
}

/// `DnsConfig` 派生 `Default` 时 `r#final` 会取本 impl 的值。
/// 这里返回 `single("default")` 与 serde 的 `default_dns_final()` 保持一致，
/// 确保 `DnsConfig::default()`（即配置中缺省 `dns` 段时）能正确序列化→反序列化往返
/// （空 `Vec` 会序列化为 `[]`，而 `deserialize` 拒绝空数组）。
impl Default for DnsServerRef {
    fn default() -> Self {
        Self::single("default")
    }
}

impl<'de> Deserialize<'de> for DnsServerRef {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            One(String),
            Many(Vec<String>),
        }
        match Repr::deserialize(deserializer)? {
            Repr::One(s) => Ok(Self(vec![s])),
            Repr::Many(v) => {
                if v.is_empty() {
                    return Err(serde::de::Error::custom("dns server list cannot be empty"));
                }
                Ok(Self(v))
            }
        }
    }
}

impl Serialize for DnsServerRef {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.len() == 1 {
            serializer.serialize_str(&self.0[0])
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl From<String> for DnsServerRef {
    fn from(s: String) -> Self {
        Self(vec![s])
    }
}

impl std::fmt::Display for DnsServerRef {
    /// 单元素直接输出，多元素用逗号拼接（用于错误消息）。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.join(","))
    }
}

// ── FakeIP 配置 ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpConfig {
    /// IPv4 假地址段，如 "198.18.0.0/15"
    #[serde(default)]
    pub inet4_range: Option<String>,
    /// IPv6 假地址段，如 "fc00::/18"
    #[serde(default)]
    pub inet6_range: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    /// DNS 服务器列表
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,

    /// DNS 分流规则
    #[serde(default)]
    pub rules: Vec<DnsRuleConfig>,

    /// 没有规则命中时使用的 server tag（s）
    ///
    /// 支持单字符串（向后兼容）或数组形式（mihomo 风格并发）：
    /// - `"final": "remote"`
    /// - `"final": ["local", "remote"]`
    ///
    /// 数组形式时解析器同时向所有上游发起查询，首个成功响应即返回。
    /// `fakeip://` / `rcode://` 类型的 server 不能出现在数组里。
    #[serde(default = "default_dns_final")]
    pub r#final: DnsServerRef,

    /// IP 版本偏好策略
    #[serde(default)]
    pub strategy: ResolveStrategy,

    /// 用于解析「代理出站节点服务器域名」的 DNS 解析器配置。
    /// 即当 outbound（如 vmess/trojan/vless/hysteria2 等）的 `server` 字段是域名而非 IP 时，
    /// 用哪个 DNS server 来解析它。
    ///
    /// 对齐 sing-box `route.default_domain_resolver`（DomainResolveOptions）：
    /// - 简写形式：`"proxy_domain_resolver": "local"` —— 只指定 server tag，
    ///   strategy 沿用全局 `dns.strategy`，启用缓存。
    /// - 完整形式：`"proxy_domain_resolver": { "server": "local", "strategy": "prefer_ipv4", "disable_cache": false }`
    ///
    /// 不填则回退到 dns.final 对应的默认上游解析（按 dns.rules 路由 + 全局 strategy）。
    #[serde(default)]
    pub proxy_domain_resolver: Option<ProxyDomainResolverConfig>,

    /// 是否禁用系统 hosts 文件
    #[serde(default)]
    pub disable_hosts: bool,

    /// 禁用系统内置 DNS 缓存（让本程序自己管理）
    #[serde(default)]
    pub disable_cache: bool,

    /// DNS 缓存 TTL 上限（秒），0 表示跟随响应 TTL（上限 3600）
    #[serde(default)]
    pub cache_ttl_max: u32,

    /// 内存缓存最大条目数，默认 4096
    #[serde(default = "default_cache_capacity")]
    pub cache_capacity: usize,

    /// Optimistic（stale-while-revalidate）容忍时长（秒）。
    /// > 0 时：缓存过期后仍在此时长内，继续返回 stale 值并后台异步刷新；
    /// > = 0（默认）= 禁用 optimistic 模式，过期即 Miss。
    /// > 不能与 `disable_cache: true` 同时使用。
    #[serde(default)]
    pub optimistic_timeout: u64,
}

// ── Server ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsServerConfig {
    pub tag: String,

    /// 服务器地址，支持多种格式：
    /// - `1.2.3.4` / `1.2.3.4:53`          → UDP DNS（默认端口 53）
    /// - `udp://1.2.3.4:53`                 → UDP DNS（显式前缀）
    /// - `tcp://1.2.3.4:53`                 → TCP DNS
    /// - `tls://1.2.3.4:853`                → DNS-over-TLS
    /// - `https://1.1.1.1/dns-query`        → DNS-over-HTTPS
    /// - `quic://dns.adguard.com`           → DNS-over-QUIC
    /// - `h3://1.1.1.1/dns-query`           → DNS-over-HTTP/3（QUIC + HTTP/3）
    /// - `hosts://` / `hosts:///etc/hosts`  → 本地 hosts 文件 DNS
    /// - `local://`                          → 本地系统 DNS（resolv.conf + hosts）
    /// - `rcode://refused`                  → 内置：返回 REFUSED
    /// - `rcode://success`                  → 内置：返回空成功（用于屏蔽）
    /// - `rcode://nxdomain`                 → 内置：返回 NXDOMAIN
    pub address: String,

    /// 走哪个 outbound tag 发出查询，不填则走 direct
    #[serde(default)]
    pub detour: Option<String>,

    /// FakeIP 配置（仅 address 为 "fakeip://" 时使用）
    #[serde(default)]
    pub fakeip: Option<FakeIpConfig>,

    /// 当 address 为域名形式的 DoH/DoT 时，用哪个 server tag 来解析该域名。
    /// 被指向的 server 必须是纯 IP 地址（或自身也有 domain_resolver），以避免循环依赖。
    /// 若 address 已是 IP 形式则此字段忽略。
    #[serde(default)]
    pub domain_resolver: Option<String>,

    /// 客户端子网（EDNS Client Subnet），如 "1.2.3.0/24"
    #[serde(default)]
    pub client_subnet: Option<String>,

    /// 查询超时（秒），默认 5
    #[serde(default = "default_dns_timeout")]
    pub timeout: u64,

    /// 该 server 解析出的地址，优先使用哪个 IP 版本
    #[serde(default)]
    pub strategy: Option<ResolveStrategy>,

    /// TLS SNI（仅 DoT/DoQ 使用）。不填时用服务器 IP 字符串作为 SNI。
    /// 当服务器地址是域名时建议显式填写。
    #[serde(default)]
    pub sni: Option<String>,

    /// 跳过 TLS 证书验证（仅 DoH/DoT/DoQ，调试用）
    #[serde(default)]
    pub insecure: bool,
}

impl DnsServerConfig {
    /// 解析 address 字段，返回协议类型
    pub fn protocol(&self) -> DnsProtocol {
        let addr = &self.address;
        if addr.starts_with("https://") {
            DnsProtocol::Doh
        } else if addr.starts_with("tls://") {
            DnsProtocol::Dot
        } else if addr.starts_with("quic://") {
            DnsProtocol::Doq
        } else if addr.starts_with("h3://") {
            DnsProtocol::H3
        } else if addr.starts_with("tcp://") {
            DnsProtocol::Tcp
        } else if addr.starts_with("udp://") {
            DnsProtocol::Udp
        } else if addr.starts_with("hosts://") {
            DnsProtocol::Hosts
        } else if addr.starts_with("local://") {
            DnsProtocol::Local
        } else if addr.starts_with("rcode://") {
            DnsProtocol::Rcode
        } else if addr.starts_with("fakeip://") {
            DnsProtocol::FakeIp
        } else {
            DnsProtocol::Udp
        }
    }

    /// 提取 rcode 值（仅对 rcode:// 地址有效）
    pub fn rcode(&self) -> Option<RcodeAction> {
        let code = self.address.strip_prefix("rcode://")?;
        match code {
            "refused" => Some(RcodeAction::Refused),
            "success" => Some(RcodeAction::Success),
            "nxdomain" => Some(RcodeAction::NxDomain),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    Udp,
    Tcp,
    Dot,
    Doh,
    Doq,
    /// DNS-over-HTTP/3（RFC 9464）：QUIC + HTTP/3
    H3,
    /// 本地 hosts 文件 DNS（对齐 sing-box `hosts.Transport`）
    Hosts,
    /// 本地系统 DNS（对齐 sing-box `local.Transport`，读 /etc/resolv.conf + /etc/hosts）
    Local,
    Rcode,
    FakeIp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RcodeAction {
    Refused,
    Success,
    NxDomain,
    /// 静默丢弃查询：不返回任何 DNS 响应（对齐 sing-box
    /// `RuleActionRejectMethodDrop`，返回 `tun.ErrDrop`）。
    /// 仅在 `DnsRuleAction::Block::method` 中合法。
    Drop,
}

// ── Rule ─────────────────────────────────────────────────────────────────────

/// DNS 规则动作，对齐 sing-box `dns.rules[].action`。
///
/// 使用方式（`action` 为 tag 字段）：
/// ```json
/// { "ruleset": ["geosite-cn"], "action": "route", "server": "local" }
/// { "ruleset": ["geosite-ads"], "action": "block", "method": "nxdomain" }
/// { "domain": ["ads.example.com"], "action": "predefined", "rcode": "nxdomain" }
/// ```
///
/// 未填写 `action` 时自动从旧式 `server` 字段推导为 `route`（向后兼容）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum DnsRuleAction {
    /// 转发到指定 server（默认动作）
    Route {
        /// 目标 DNS server tag（s），支持单字符串或数组（mihomo 风格并发）
        server: DnsServerRef,
        /// 该规则的解析策略（覆盖全局 `dns.strategy`）。
        /// None 表示沿用全局策略（对齐 sing-box `DomainStrategyAsIS`）。
        /// 对齐 sing-box `option.DNSRouteActionOptions.Strategy`：
        /// - `Ipv4Only` + A 查询正常，AAAA 查询返回空 NOERROR
        /// - `Ipv6Only` + AAAA 查询正常，A 查询返回空 NOERROR
        #[serde(default, skip_serializing_if = "Option::is_none")]
        strategy: Option<ResolveStrategy>,
        /// 重写响应中所有 RR 的 TTL 为该值（秒），跳过 OPT 记录。
        /// 对齐 sing-box `option.DNSRouteActionOptions.RewriteTTL`（client.go:307-316）：
        /// 设定后，上游返回的 TTL 被统一覆盖为该值，同时作为缓存存储 TTL。
        /// None 表示不重写（沿用上游原始 TTL，缓存 TTL 取 min TTL / SOA minimum）。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rewrite_ttl: Option<u32>,
        /// EDNS Client Subnet（RFC 7871），如 "1.2.3.0/24" 或 "2001:db8::/32"。
        /// 对齐 sing-box `option.DNSRouteActionOptions.ClientSubnet`：设定后，
        /// 查询前向 OPT 注入 EDNS0_SUBNET，优先级高于 server 级 `client_subnet`
        /// 与 client 全局默认。None 表示沿用 server 级配置。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_subnet: Option<String>,
    },
    /// 直接返回指定 rcode，不查询上游、不查缓存。
    ///
    /// 等价于把 `rcode://` server 单独抽出为动作，无需再单独声明 block server。
    /// `method` 缺省为 `refused`（与项目既有 block-dns server 默认一致）。
    /// `drop` 方法静默丢弃查询，不返回任何响应（对齐 sing-box
    /// `RuleActionRejectMethodDrop`）。
    Block {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        method: Option<RcodeAction>,
    },
    /// 预定义响应：直接返回指定 rcode 的 DNS 响应，不查询上游、不查缓存。
    ///
    /// 对齐 sing-box `option.DNSRouteActionPredefined`：仅支持 `rcode` 字段
    /// （`success`/`refused`/`nxdomain`），暂不支持自定义 Answer/Ns/Extra 记录
    /// （那需要 DNS RR 文本解析器）。`rcode` 缺省为 `success`（NOERROR，空答案）。
    /// 行为上与 `block` 等价，但语义更清晰，与 sing-box 配置兼容。
    Predefined {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rcode: Option<RcodeAction>,
    },
}

/// 一条 DNS 规则，所有非空条件之间是 AND 语义，
/// 同一条件内多个值是 OR 语义。
///
/// `action` 唯一决定动作：`"route"`（默认，`server` 必填）或 `"block"`。
/// 动作参数（route 的 `server`、block 的 `method`）与条件字段平铺在同一
/// 规则对象中；与动作无关的参数字段会报错。
///
/// 序列化时输出规范形式：条件字段 + `action` 展平字段。
#[derive(Debug, Clone)]
pub struct DnsRuleConfig {
    /// 匹配指定入站 tag（如来自 dns-in 的查询）。支持单字符串或数组形式。
    pub inbound: Vec<String>,

    /// 命中的 ruleset tag 列表（OR 语义）。
    /// 配置形式支持单字符串或数组：`"ruleset": "geosite-cn"` 或
    /// `"ruleset": ["geosite-cn", "geoip-cn"]`。
    pub ruleset: Vec<String>,

    /// 内联精确域名（OR）。支持单字符串或数组形式。
    pub domain: Vec<String>,

    /// 内联后缀（OR）。支持单字符串或数组形式。
    pub domain_suffix: Vec<String>,

    /// 内联关键词（OR）。支持单字符串或数组形式。
    pub domain_keyword: Vec<String>,

    /// 按 DNS 查询类型过滤。支持单值或数组形式：
    /// - `"query_type": "A"`
    /// - `"query_type": ["A", "AAAA"]`
    ///
    /// 空表示所有类型。
    pub query_type: Vec<DnsQueryType>,

    /// 命中后是否禁用缓存
    pub disable_cache: bool,

    /// 仅当 Clash API 当前模式等于该值时才命中本规则，大小写不敏感。
    /// 与主路由规则的 `clash_mode` 字段语义一致（见 `RouteRuleConfig::clash_mode`），
    /// 对齐 sing-box DNS 规则同样支持的 `clash_mode` 条件。
    pub clash_mode: Option<String>,

    /// 显式动作声明（`"action": "route" | "block"`）。
    /// 未填写时默认 `action: "route"`（此时 `server` 必填）。反序列化后恒为 `Some`。
    pub action: Option<DnsRuleAction>,
}

impl DnsRuleConfig {
    /// 该规则实际使用的 server tag 列表（action=route 时；block/predefined 时为空）。
    pub fn server_tags(&self) -> Vec<String> {
        match self.action.as_ref() {
            Some(DnsRuleAction::Route { server, .. }) => server.as_slice().to_vec(),
            _ => Vec::new(),
        }
    }

    /// 是否为 block 动作（`action: "block"`）。
    pub fn is_block_rule(&self) -> bool {
        matches!(self.action.as_ref(), Some(DnsRuleAction::Block { .. }))
    }

    /// 是否为 predefined 动作（`action: "predefined"`）。
    pub fn is_predefined_rule(&self) -> bool {
        matches!(
            self.action.as_ref(),
            Some(DnsRuleAction::Predefined { .. })
        )
    }
}

// ── DnsRuleConfig 反序列化：action 唯一决定动作，无 action 默认 route ──────

/// 反序列化中间表示：镜像 `DnsRuleConfig` 的全部条件字段。
/// 无 `action` 字段（动作由 `DnsRuleAction` 单独解析）。
#[derive(Deserialize)]
#[allow(dead_code)]
struct DnsRuleRaw {
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    inbound: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    ruleset: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    domain: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    query_type: Vec<DnsQueryType>,
    #[serde(default)]
    disable_cache: bool,
    #[serde(default)]
    clash_mode: Option<String>,
}

/// 条件字段（所有 action 共有）。
const DNS_COMMON_FIELDS: &[&str] = &[
    "action",
    "inbound",
    "ruleset",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "query_type",
    "disable_cache",
    "clash_mode",
];

/// 各 action 允许的参数（除条件字段外）。
fn dns_action_params(action: &str) -> &'static [&'static str] {
    match action {
        "route" => &["server", "strategy", "rewrite_ttl", "client_subnet"],
        "block" => &["method"],
        "predefined" => &["rcode"],
        _ => &[],
    }
}

/// 校验 DNS 规则对象的字段归属：条件字段或当前 action 的参数，其余报错。
fn validate_dns_action_fields(action: &str, obj: &serde_json::Map<String, serde_json::Value>) -> anyhow::Result<()> {
    let params = dns_action_params(action);
    for key in obj.keys() {
        if !DNS_COMMON_FIELDS.contains(&key.as_str()) && !params.contains(&key.as_str()) {
            anyhow::bail!(
                "dns rule: field '{key}' is not valid for action '{action}' \
                 (allowed action params: {})",
                params.join(", ")
            );
        }
    }
    Ok(())
}

impl DnsRuleConfig {
    /// 从 JSON Value 组装规则：`action` 决定动作；无 `action` 默认 `route`（server 必填）。
    fn from_value(value: serde_json::Value) -> anyhow::Result<Self> {
        use serde::Deserialize as _;
        let raw = DnsRuleRaw::deserialize(value.clone())?;

        let action = match value.get("action").and_then(|v| v.as_str()) {
            Some(action_name) => {
                let obj = value
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("dns rule must be an object"))?;
                validate_dns_action_fields(action_name, obj)?;
                // 显式解析（internally tagged，需要整个 map 才能读到 `action` tag）
                DnsRuleAction::deserialize(value)?
            }
            None => {
                // 无 action：默认 route，server 必填，strategy/rewrite_ttl/client_subnet 可选
                let obj = value
                    .as_object()
                    .ok_or_else(|| anyhow::anyhow!("dns rule must be an object"))?;
                validate_dns_action_fields("route", obj)?;
                let server = serde_json::from_value(
                    obj.get("server")
                        .cloned()
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "dns rule: missing required field `server` \
                                 (no `action` specified, defaults to `route`)"
                            )
                        })?,
                )?;
                let strategy = obj
                    .get("strategy")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?;
                let rewrite_ttl = obj
                    .get("rewrite_ttl")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?;
                let client_subnet = obj
                    .get("client_subnet")
                    .cloned()
                    .map(serde_json::from_value)
                    .transpose()?;
                DnsRuleAction::Route {
                    server,
                    strategy,
                    rewrite_ttl,
                    client_subnet,
                }
            }
        };

        Ok(DnsRuleConfig {
            inbound: raw.inbound,
            ruleset: raw.ruleset,
            domain: raw.domain,
            domain_suffix: raw.domain_suffix,
            domain_keyword: raw.domain_keyword,
            query_type: raw.query_type,
            disable_cache: raw.disable_cache,
            clash_mode: raw.clash_mode,
            action: Some(action),
        })
    }
}

impl<'de> Deserialize<'de> for DnsRuleConfig {
    fn deserialize<D>(de: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(de)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

impl Serialize for DnsRuleConfig {
    /// 序列化为规范形式：条件字段 + `action` 展平字段。
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct Ser<'a> {
            inbound: &'a [String],
            ruleset: &'a [String],
            domain: &'a [String],
            domain_suffix: &'a [String],
            domain_keyword: &'a [String],
            query_type: &'a [DnsQueryType],
            disable_cache: bool,
            clash_mode: &'a Option<String>,
            #[serde(flatten)]
            action: &'a DnsRuleAction,
        }
        // 反序列化后 `action` 恒为 Some；Default 构造的兜底值
        let fallback = DnsRuleAction::Route {
            server: DnsServerRef::single(""),
            strategy: None,
            rewrite_ttl: None,
            client_subnet: None,
        };
        let ser = Ser {
            inbound: &self.inbound,
            ruleset: &self.ruleset,
            domain: &self.domain,
            domain_suffix: &self.domain_suffix,
            domain_keyword: &self.domain_keyword,
            query_type: &self.query_type,
            disable_cache: self.disable_cache,
            clash_mode: &self.clash_mode,
            action: self.action.as_ref().unwrap_or(&fallback),
        };
        ser.serialize(s)
    }
}

/// DNS 查询类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Srv,
    Https,
}

// ── Strategy ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResolveStrategy {
    /// 优先返回 IPv4（默认）
    #[default]
    PreferIpv4,
    /// 优先返回 IPv6
    PreferIpv6,
    /// 仅返回 IPv4
    Ipv4Only,
    /// 仅返回 IPv6
    Ipv6Only,
}

// ── proxy_domain_resolver 配置 ───────────────────────────────────────────────
//
// 对齐 sing-box `option.DomainResolveOptions`：既支持简写字符串 `"local"`，
// 也支持完整对象 `{ "server": "local", "strategy": "prefer_ipv4", "disable_cache": false }`。
// 反序列化时若为字符串则填充 `server` 字段，其余保持默认。

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(from = "ProxyDomainResolverConfigDeser")]
pub struct ProxyDomainResolverConfig {
    /// DNS server tag（s）（必须引用 dns.servers 中已存在的项）
    ///
    /// 支持单字符串或数组形式（mihomo 风格并发）。简写形式 `"local"` 和
    /// `"local"`/`["local","remote"]` 都被接受；完整对象形式下 `server`
    /// 字段同样支持两种形式。
    pub server: DnsServerRef,
    /// 解析策略；None 表示沿用全局 `dns.strategy`（对齐 sing-box AsIS）
    pub strategy: Option<ResolveStrategy>,
    /// 是否禁用缓存；默认 false（启用缓存）
    pub disable_cache: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ProxyDomainResolverConfigDeser {
    /// 简写形式：`"local"` 或 `["local", "remote"]`
    Short(DnsServerRef),
    /// 完整对象形式
    Full {
        server: DnsServerRef,
        #[serde(default)]
        strategy: Option<ResolveStrategy>,
        #[serde(default)]
        disable_cache: bool,
    },
}

impl From<ProxyDomainResolverConfigDeser> for ProxyDomainResolverConfig {
    fn from(value: ProxyDomainResolverConfigDeser) -> Self {
        match value {
            ProxyDomainResolverConfigDeser::Short(server) => Self {
                server,
                strategy: None,
                disable_cache: false,
            },
            ProxyDomainResolverConfigDeser::Full {
                server,
                strategy,
                disable_cache,
            } => Self {
                server,
                strategy,
                disable_cache,
            },
        }
    }
}

fn default_dns_final() -> DnsServerRef {
    DnsServerRef::single("default")
}
fn default_dns_timeout() -> u64 {
    5
}
fn default_cache_capacity() -> usize {
    4096
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_full_dns_config() {
        let v = json!({
            "servers": [
                {
                    "tag": "local",
                    "address": "223.5.5.5",
                    "detour": "direct"
                },
                {
                    "tag": "remote",
                    "address": "https://1.1.1.1/dns-query",
                    "detour": "proxy"
                },
                {
                    "tag": "block",
                    "address": "rcode://refused"
                }
            ],
            "rules": [
                {
                    "ruleset": ["geosite-cn"],
                    "server": "local"
                },
                {
                    "domain_suffix": [".cn"],
                    "query_type": ["A", "AAAA"],
                    "server": "local"
                },
                {
                    "ruleset": ["geosite-ads"],
                    "server": "block"
                }
            ],
            "final": "remote",
            "strategy": "prefer_ipv4"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(dns.servers.len(), 3);
        assert_eq!(dns.rules.len(), 3);
        assert_eq!(dns.r#final.as_slice(), &["remote".to_string()]);
    }

    #[test]
    fn parse_dns_string_or_array_fields() {
        // ruleset：单字符串 vs 数组 vs 缺省
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "ruleset": "geosite-cn", "server": "local" }],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(dns.rules[0].ruleset, vec!["geosite-cn"]);

        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "ruleset": ["geosite-cn", "geoip-cn"], "server": "local" }],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(dns.rules[0].ruleset, vec!["geosite-cn", "geoip-cn"]);

        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "domain_suffix": [".cn"], "server": "local" }],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert!(dns.rules[0].ruleset.is_empty());

        // inbound / domain / domain_suffix / domain_keyword：单字符串形式
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{
                "inbound": "dns-in",
                "domain": "example.com",
                "domain_suffix": ".cn",
                "domain_keyword": "google",
                "server": "local"
            }],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(dns.rules[0].inbound, vec!["dns-in"]);
        assert_eq!(dns.rules[0].domain, vec!["example.com"]);
        assert_eq!(dns.rules[0].domain_suffix, vec![".cn"]);
        assert_eq!(dns.rules[0].domain_keyword, vec!["google"]);

        // query_type：单值 vs 数组
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "query_type": "A", "server": "local" }],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(dns.rules[0].query_type, vec![DnsQueryType::A]);

        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "query_type": ["A", "AAAA"], "server": "local" }],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            dns.rules[0].query_type,
            vec![DnsQueryType::A, DnsQueryType::Aaaa]
        );
    }

    #[test]
    fn server_protocol_detection() {
        let make = |addr: &str| DnsServerConfig {
            tag: "t".into(),
            address: addr.into(),
            detour: None,
            domain_resolver: None,
            client_subnet: None,
            timeout: 5,
            strategy: None,
            fakeip: None,
            sni: None,
            insecure: false,
        };
        assert_eq!(make("1.1.1.1").protocol(), DnsProtocol::Udp);
        assert_eq!(make("udp://1.1.1.1:53").protocol(), DnsProtocol::Udp);
        assert_eq!(make("tcp://1.1.1.1:53").protocol(), DnsProtocol::Tcp);
        assert_eq!(make("tls://1.1.1.1:853").protocol(), DnsProtocol::Dot);
        assert_eq!(
            make("https://1.1.1.1/dns-query").protocol(),
            DnsProtocol::Doh
        );
        assert_eq!(make("quic://1.1.1.1").protocol(), DnsProtocol::Doq);
        assert_eq!(make("h3://1.1.1.1/dns-query").protocol(), DnsProtocol::H3);
        assert_eq!(make("hosts://").protocol(), DnsProtocol::Hosts);
        assert_eq!(make("hosts:///etc/hosts").protocol(), DnsProtocol::Hosts);
        assert_eq!(make("local://").protocol(), DnsProtocol::Local);
        assert_eq!(make("rcode://refused").protocol(), DnsProtocol::Rcode);
        assert_eq!(make("rcode://refused").rcode(), Some(RcodeAction::Refused));
        assert_eq!(
            make("rcode://nxdomain").rcode(),
            Some(RcodeAction::NxDomain)
        );
    }

    #[test]
    fn strategy_default() {
        let dns = DnsConfig::default();
        assert_eq!(dns.strategy, ResolveStrategy::PreferIpv4);
    }

    // ── ProxyDomainResolverConfig 反序列化（对齐 sing-box DomainResolveOptions）──

    #[test]
    fn proxy_domain_resolver_short_form() {
        // 简写形式：`"proxy_domain_resolver": "local"`
        // 对齐 sing-box `default_domain_resolver: "local"`
        let v = json!({"proxy_domain_resolver": "local"});
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        let cfg = dns.proxy_domain_resolver.expect("should be Some");
        assert_eq!(cfg.server.as_slice(), &["local".to_string()]);
        assert_eq!(cfg.strategy, None); // None = 沿用全局 strategy（对齐 AsIS）
        assert!(!cfg.disable_cache); // 默认启用缓存
    }

    #[test]
    fn proxy_domain_resolver_short_form_array() {
        // 简写形式 + 数组：`"proxy_domain_resolver": ["local", "remote"]`
        // 对齐 mihomo 并发解析
        let v = json!({"proxy_domain_resolver": ["local", "remote"]});
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        let cfg = dns.proxy_domain_resolver.expect("should be Some");
        assert_eq!(
            cfg.server.as_slice(),
            &["local".to_string(), "remote".to_string()]
        );
        assert_eq!(cfg.strategy, None);
        assert!(!cfg.disable_cache);
    }

    #[test]
    fn proxy_domain_resolver_full_form() {
        // 完整对象形式：显式指定 strategy 和 disable_cache
        let v = json!({
            "proxy_domain_resolver": {
                "server": "remote",
                "strategy": "prefer_ipv6",
                "disable_cache": true
            }
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        let cfg = dns.proxy_domain_resolver.expect("should be Some");
        assert_eq!(cfg.server.as_slice(), &["remote".to_string()]);
        assert_eq!(cfg.strategy, Some(ResolveStrategy::PreferIpv6));
        assert!(cfg.disable_cache);
    }

    #[test]
    fn proxy_domain_resolver_full_form_array_server() {
        // 完整对象形式 + server 为数组
        let v = json!({
            "proxy_domain_resolver": {
                "server": ["local", "remote"],
                "strategy": "prefer_ipv6",
                "disable_cache": true
            }
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        let cfg = dns.proxy_domain_resolver.expect("should be Some");
        assert_eq!(
            cfg.server.as_slice(),
            &["local".to_string(), "remote".to_string()]
        );
        assert_eq!(cfg.strategy, Some(ResolveStrategy::PreferIpv6));
        assert!(cfg.disable_cache);
    }

    #[test]
    fn proxy_domain_resolver_full_form_defaults() {
        // 对象形式只给 server，strategy 和 disable_cache 取默认值
        let v = json!({"proxy_domain_resolver": {"server": "local"}});
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        let cfg = dns.proxy_domain_resolver.expect("should be Some");
        assert_eq!(cfg.server.as_slice(), &["local".to_string()]);
        assert_eq!(cfg.strategy, None);
        assert!(!cfg.disable_cache);
    }

    #[test]
    fn proxy_domain_resolver_absent() {
        // 不填 → None，回退到 dns.final 默认上游 + dns.rules 路由
        let v = json!({"final": "default"});
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert!(dns.proxy_domain_resolver.is_none());
    }

    #[test]
    fn proxy_domain_resolver_serializes_back() {
        // 确保完整形式 round-trip 正确（序列化后再反序列化应等价）
        let original = ProxyDomainResolverConfig {
            server: DnsServerRef::single("local"),
            strategy: Some(ResolveStrategy::Ipv4Only),
            disable_cache: true,
        };
        let json_str = serde_json::to_string(&original).unwrap();
        let parsed: ProxyDomainResolverConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(original, parsed);
    }

    // ── DnsServerRef 反序列化与序列化 ───────────────────────────────────────

    #[test]
    fn dns_server_ref_single_string_form() {
        let v = json!("local");
        let r: DnsServerRef = serde_json::from_value(v).unwrap();
        assert_eq!(r.as_slice(), &["local".to_string()]);
        assert!(r.is_single());
        // 序列化回单字符串
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, "\"local\"");
    }

    #[test]
    fn dns_server_ref_array_form() {
        let v = json!(["local", "remote"]);
        let r: DnsServerRef = serde_json::from_value(v).unwrap();
        assert_eq!(r.as_slice(), &["local".to_string(), "remote".to_string()]);
        assert!(!r.is_single());
        // 序列化回数组
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, "[\"local\",\"remote\"]");
    }

    #[test]
    fn dns_server_ref_empty_array_rejected() {
        let v = json!([]);
        let err = serde_json::from_value::<DnsServerRef>(v);
        assert!(err.is_err(), "empty array should be rejected");
    }

    #[test]
    fn dns_rule_server_supports_array() {
        let v = json!({
            "servers": [
                {"tag": "local", "address": "1.1.1.1"},
                {"tag": "remote", "address": "8.8.8.8"}
            ],
            "rules": [
                {"domain": ["example.com"], "server": ["local", "remote"]}
            ],
            "final": ["local", "remote"]
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            dns.rules[0].server_tags(),
            vec!["local".to_string(), "remote".to_string()]
        );
        assert_eq!(
            dns.r#final.as_slice(),
            &["local".to_string(), "remote".to_string()]
        );
    }

    #[test]
    fn dns_server_ref_roundtrip_single() {
        // 单元素 round-trip：string → DnsServerRef → string
        let original = DnsServerRef::single("local");
        let s = serde_json::to_string(&original).unwrap();
        let parsed: DnsServerRef = serde_json::from_str(&s).unwrap();
        assert_eq!(original, parsed);
        // 确保仍是 string 形式
        assert_eq!(s, "\"local\"");
    }

    #[test]
    fn dns_server_ref_roundtrip_multi() {
        // 多元素 round-trip：array → DnsServerRef → array
        let original = DnsServerRef(vec!["local".into(), "remote".into()]);
        let s = serde_json::to_string(&original).unwrap();
        let parsed: DnsServerRef = serde_json::from_str(&s).unwrap();
        assert_eq!(original, parsed);
        assert_eq!(s, "[\"local\",\"remote\"]");
    }

    // ── DNS 规则显式 action 解析（sing-box 风格）─────────────────────────

    #[test]
    fn parse_dns_rule_explicit_action_route() {
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "ruleset": ["geosite-cn"], "action": "route", "server": "local" }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            dns.rules[0].action,
            Some(DnsRuleAction::Route {
                server: DnsServerRef::single("local"),
                strategy: None,
                rewrite_ttl: None,
                client_subnet: None,
            })
        );
        assert_eq!(dns.rules[0].server_tags(), vec!["local".to_string()]);
        assert!(!dns.rules[0].is_block_rule());
    }

    #[test]
    fn parse_dns_rule_route_with_strategy() {
        // route action 支持可选 strategy（覆盖全局 dns.strategy）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "domain": ["example.com"], "action": "route", "server": "local", "strategy": "ipv4_only" }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        match dns.rules[0].action {
            Some(DnsRuleAction::Route { ref strategy, .. }) => {
                assert_eq!(*strategy, Some(ResolveStrategy::Ipv4Only));
            }
            _ => panic!("expected Route action"),
        }
    }

    #[test]
    fn parse_dns_rule_route_with_rewrite_ttl_and_client_subnet() {
        // route action 支持可选 rewrite_ttl（对齐 sing-box DNSRouteActionOptions.RewriteTTL）
        // 与 client_subnet（对齐 sing-box DNSRouteActionOptions.ClientSubnet）。
        let v = json!({
            "servers": [{ "tag": "remote", "address": "8.8.8.8" }],
            "rules": [
                { "domain": ["example.com"], "action": "route", "server": "remote",
                  "rewrite_ttl": 60, "client_subnet": "1.2.3.0/24" }
            ],
            "final": "remote"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        match dns.rules[0].action {
            Some(DnsRuleAction::Route { ref rewrite_ttl, ref client_subnet, .. }) => {
                assert_eq!(*rewrite_ttl, Some(60));
                assert_eq!(client_subnet.as_deref(), Some("1.2.3.0/24"));
            }
            _ => panic!("expected Route action"),
        }
    }

    #[test]
    fn parse_dns_rule_route_rewrite_ttl_default_none() {
        // 未填写 rewrite_ttl / client_subnet 时为 None（向后兼容）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "domain": ["example.com"], "action": "route", "server": "local" }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        match dns.rules[0].action {
            Some(DnsRuleAction::Route { ref rewrite_ttl, ref client_subnet, .. }) => {
                assert_eq!(*rewrite_ttl, None);
                assert_eq!(*client_subnet, None);
            }
            _ => panic!("expected Route action"),
        }
    }

    #[test]
    fn parse_dns_rule_predefined_action() {
        // predefined action：返回指定 rcode，不查询上游
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "domain": ["ads.example.com"], "action": "predefined" },
                { "domain": ["ads2.example.com"], "action": "predefined", "rcode": "nxdomain" },
                { "domain": ["ads3.example.com"], "action": "predefined", "rcode": "refused" }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        // 默认 rcode = success
        assert_eq!(
            dns.rules[0].action,
            Some(DnsRuleAction::Predefined { rcode: None })
        );
        assert!(dns.rules[0].is_predefined_rule());
        assert!(dns.rules[0].server_tags().is_empty());
        assert_eq!(
            dns.rules[1].action,
            Some(DnsRuleAction::Predefined {
                rcode: Some(RcodeAction::NxDomain)
            })
        );
        assert_eq!(
            dns.rules[2].action,
            Some(DnsRuleAction::Predefined {
                rcode: Some(RcodeAction::Refused)
            })
        );
    }

    #[test]
    fn parse_dns_rule_block_drop_method() {
        // block action 的 drop method：静默丢弃查询
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "domain": ["drop.example.com"], "action": "block", "method": "drop" }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            dns.rules[0].action,
            Some(DnsRuleAction::Block {
                method: Some(RcodeAction::Drop)
            })
        );
    }

    #[test]
    fn parse_dns_rule_explicit_action_block() {
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "ruleset": ["geosite-ads"], "action": "block" },
                { "domain": ["ads.example.com"], "action": "block", "method": "nxdomain" },
                { "domain_suffix": [".tracker.com"], "action": "block", "method": "success" }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        // 默认 method = refused
        assert_eq!(
            dns.rules[0].action,
            Some(DnsRuleAction::Block { method: None })
        );
        assert!(dns.rules[0].is_block_rule());
        assert!(dns.rules[0].server_tags().is_empty());
        assert_eq!(
            dns.rules[1].action,
            Some(DnsRuleAction::Block {
                method: Some(RcodeAction::NxDomain)
            })
        );
        assert_eq!(
            dns.rules[2].action,
            Some(DnsRuleAction::Block {
                method: Some(RcodeAction::Success)
            })
        );
    }

    #[test]
    fn dns_rule_no_action_defaults_to_route() {
        // 无 action + server → 默认 route（server 是 route 动作参数）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "domain_suffix": [".cn"], "server": "local" },
                { "domain": ["x.com"], "server": ["local"] }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            dns.rules[0].action,
            Some(DnsRuleAction::Route {
                server: DnsServerRef::single("local"),
                strategy: None,
                rewrite_ttl: None,
                client_subnet: None,
            })
        );
        assert_eq!(dns.rules[0].server_tags(), vec!["local".to_string()]);
        // 数组形式
        assert_eq!(
            dns.rules[1].server_tags(),
            vec!["local".to_string()]
        );
    }

    #[test]
    fn dns_rule_missing_server_rejected() {
        // 无 action 且无 server → 报错（默认 route 需要 server）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "domain": ["x.com"] }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_err());
    }

    #[test]
    fn dns_rule_action_params_strictly_validated() {
        // action=block 不能带 server（route 专属参数）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "ruleset": ["geosite-ads"], "action": "block", "server": "local" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_err());

        // action=route 不能带 method（block 专属参数）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "action": "route", "server": "local", "method": "nxdomain" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_err());

        // action=predefined 不能带 server（route 专属参数）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "action": "predefined", "server": "local" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_err());

        // action=predefined 不能带 method（block 专属参数）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "action": "predefined", "method": "nxdomain" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_err());

        // action=block 不能带 rcode（predefined 专属参数）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "action": "block", "rcode": "nxdomain" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_err());

        // action=route 不能带 rcode（predefined 专属参数）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "action": "route", "server": "local", "rcode": "nxdomain" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_err());

        // 旧式 server 写法（无 action）默认 route，合法
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "domain_suffix": [".cn"], "server": "local" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_ok());

        // 无 action 但带 strategy（默认 route，strategy 合法）
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "domain_suffix": [".cn"], "server": "local", "strategy": "ipv4_only" }],
            "final": "local"
        });
        assert!(serde_json::from_value::<DnsConfig>(v).is_ok());
    }

    #[test]
    fn dns_rule_block_serialize_roundtrip() {
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [
                { "ruleset": ["geosite-ads"], "action": "block", "method": "nxdomain" },
                { "domain_suffix": [".cn"], "action": "route", "server": "local", "disable_cache": true, "strategy": "prefer_ipv4" },
                { "domain": ["ads.example.com"], "action": "predefined", "rcode": "nxdomain" }
            ],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v.clone()).unwrap();
        let s = serde_json::to_string(&dns).unwrap();
        let dns2: DnsConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(dns.rules.len(), dns2.rules.len());
        for (a, b) in dns.rules.iter().zip(dns2.rules.iter()) {
            assert_eq!(a.action, b.action);
            assert_eq!(a.ruleset, b.ruleset);
            assert_eq!(a.domain_suffix, b.domain_suffix);
            assert_eq!(a.disable_cache, b.disable_cache);
        }
        // 序列化包含 action tag
        assert!(s.contains("\"action\":\"block\"") || s.contains("\"action\": \"block\""));
        assert!(s.contains("\"action\":\"route\"") || s.contains("\"action\": \"route\""));
        assert!(s.contains("\"action\":\"predefined\"") || s.contains("\"action\": \"predefined\""));
    }

    #[test]
    fn dns_rule_default_route_serialize_roundtrip() {
        // 无 action（默认 route）配置序列化为规范 action 形式，仍可反序列化
        let v = json!({
            "servers": [{ "tag": "local", "address": "223.5.5.5" }],
            "rules": [{ "domain_suffix": [".cn"], "server": "local" }],
            "final": "local"
        });
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        let s = serde_json::to_string(&dns).unwrap();
        let dns2: DnsConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(dns.rules[0].action, dns2.rules[0].action);
        assert_eq!(dns.rules[0].server_tags(), dns2.rules[0].server_tags());
    }
}
