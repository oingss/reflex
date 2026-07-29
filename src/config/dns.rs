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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RcodeAction {
    Refused,
    Success,
    NxDomain,
}

// ── Rule ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRuleConfig {
    /// 匹配指定入站 tag（如来自 dns-in 的查询）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub inbound: Vec<String>,

    /// 命中的 ruleset tag 列表（OR 语义）。
    /// 配置形式支持单字符串或数组：`"ruleset": "geosite-cn"` 或
    /// `"ruleset": ["geosite-cn", "geoip-cn"]`。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub ruleset: Vec<String>,

    /// 内联精确域名（OR）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub domain: Vec<String>,

    /// 内联后缀（OR）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub domain_suffix: Vec<String>,

    /// 内联关键词（OR）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub domain_keyword: Vec<String>,

    /// 按 DNS 查询类型过滤。支持单值或数组形式：
    /// - `"query_type": "A"`
    /// - `"query_type": ["A", "AAAA"]`
    ///
    /// 空表示所有类型。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub query_type: Vec<DnsQueryType>,

    /// 目标 DNS server tag（s）
    ///
    /// 支持单字符串（向后兼容）或数组形式（mihomo 风格并发）：
    /// - `"server": "local"`
    /// - `"server": ["local", "remote"]`
    ///
    /// 数组形式时解析器同时向所有上游发起查询，首个成功响应即返回。
    /// `fakeip://` / `rcode://` 类型的 server 不能出现在数组里。
    pub server: DnsServerRef,

    /// 命中后是否禁用缓存
    #[serde(default)]
    pub disable_cache: bool,

    /// 仅当 Clash API 当前模式等于该值时才命中本规则，大小写不敏感。
    /// 与主路由规则的 `clash_mode` 字段语义一致（见 `RouteRuleConfig::clash_mode`），
    /// 对齐 sing-box DNS 规则同样支持的 `clash_mode` 条件。
    #[serde(default)]
    pub clash_mode: Option<String>,
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
            dns.rules[0].server.as_slice(),
            &["local".to_string(), "remote".to_string()]
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
}
