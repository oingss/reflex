use serde::{Deserialize, Serialize};

// ── FakeIP 配置 ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FakeIpConfig {
    /// IPv4 假地址段，如 "198.18.0.0/15"
    #[serde(default)]
    pub inet4_range: Option<String>,
    /// IPv6 假地址段，如 "fc00::/18"
    #[serde(default)]
    pub inet6_range: Option<String>,
    /// 不分配假 IP 的精确域名列表（直接返回 NXDOMAIN，让 DNS 规则降级到真实上游）
    #[serde(default)]
    pub exclude_domain: Vec<String>,
    /// 不分配假 IP 的域名后缀列表，如 ["lan", "local", "internal"]
    #[serde(default)]
    pub exclude_domain_suffix: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsConfig {
    /// DNS 服务器列表
    #[serde(default)]
    pub servers: Vec<DnsServerConfig>,

    /// DNS 分流规则
    #[serde(default)]
    pub rules: Vec<DnsRuleConfig>,

    /// 没有规则命中时使用的 server tag
    #[serde(default = "default_dns_final")]
    pub r#final: String,

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
    /// - `quic://dns.adguard.com`           → DNS-over-QUIC（预留）
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
        } else if addr.starts_with("tcp://") {
            DnsProtocol::Tcp
        } else if addr.starts_with("udp://") {
            DnsProtocol::Udp
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
    /// 匹配指定入站 tag（如来自 dns-in 的查询）
    #[serde(default)]
    pub inbound: Vec<String>,

    /// 命中的 ruleset tag 列表（OR 语义）
    #[serde(default)]
    pub ruleset: Vec<String>,

    /// 内联精确域名（OR）
    #[serde(default)]
    pub domain: Vec<String>,

    /// 内联后缀（OR）
    #[serde(default)]
    pub domain_suffix: Vec<String>,

    /// 内联关键词（OR）
    #[serde(default)]
    pub domain_keyword: Vec<String>,

    /// 按 DNS 查询类型过滤，如 ["A", "AAAA"]，空表示所有类型
    #[serde(default)]
    pub query_type: Vec<DnsQueryType>,

    /// 目标 DNS server tag
    pub server: String,

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
    /// DNS server tag（必须引用 dns.servers 中已存在的项）
    pub server: String,
    /// 解析策略；None 表示沿用全局 `dns.strategy`（对齐 sing-box AsIS）
    pub strategy: Option<ResolveStrategy>,
    /// 是否禁用缓存；默认 false（启用缓存）
    pub disable_cache: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ProxyDomainResolverConfigDeser {
    /// 简写形式：`"local"`
    Short(String),
    /// 完整对象形式
    Full {
        server: String,
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

fn default_dns_final() -> String {
    "default".into()
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
        assert_eq!(dns.r#final, "remote");
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
        assert_eq!(cfg.server, "local");
        assert_eq!(cfg.strategy, None); // None = 沿用全局 strategy（对齐 AsIS）
        assert!(!cfg.disable_cache); // 默认启用缓存
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
        assert_eq!(cfg.server, "remote");
        assert_eq!(cfg.strategy, Some(ResolveStrategy::PreferIpv6));
        assert!(cfg.disable_cache);
    }

    #[test]
    fn proxy_domain_resolver_full_form_defaults() {
        // 对象形式只给 server，strategy 和 disable_cache 取默认值
        let v = json!({"proxy_domain_resolver": {"server": "local"}});
        let dns: DnsConfig = serde_json::from_value(v).unwrap();
        let cfg = dns.proxy_domain_resolver.expect("should be Some");
        assert_eq!(cfg.server, "local");
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
            server: "local".into(),
            strategy: Some(ResolveStrategy::Ipv4Only),
            disable_cache: true,
        };
        let json_str = serde_json::to_string(&original).unwrap();
        let parsed: ProxyDomainResolverConfig = serde_json::from_str(&json_str).unwrap();
        assert_eq!(original, parsed);
    }
}
