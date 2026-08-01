pub mod dns;
pub mod experimental;
pub mod inbound;
pub mod log;
pub mod outbound;
pub mod provider;
pub mod route;

use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

pub use dns::DnsConfig;
pub use experimental::ExperimentalConfig;
pub use inbound::InboundConfig;
pub use log::LogConfig;
pub use outbound::OutboundConfig;
pub use provider::ProviderConfig;
pub use route::RouteConfig;

/// 顶层配置，对应整个 JSON 文件。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,

    #[serde(default)]
    pub dns: DnsConfig,

    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,

    /// 订阅 provider 列表（远端或本地节点来源）。
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,

    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,

    /// 路由配置。缺省时使用 `RouteConfig::default()`（final="direct"，无规则），
    /// 所有流量走自动补的 direct 出站。
    #[serde(default)]
    pub route: RouteConfig,

    #[serde(default)]
    pub experimental: ExperimentalConfig,
}

/// 配置文件格式。`from_file` 按文件扩展名自动选择。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Json,
    Yaml,
}

impl ConfigFormat {
    /// 根据文件扩展名推断格式；未识别的扩展名按 JSON 处理。
    pub fn from_path(path: &Path) -> Self {
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml") | Some("yml") => ConfigFormat::Yaml,
            _ => ConfigFormat::Json,
        }
    }
}

impl std::fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigFormat::Json => write!(f, "json"),
            ConfigFormat::Yaml => write!(f, "yaml"),
        }
    }
}

impl Config {
    /// 将配置中所有相对路径字段相对于 `base_dir` 展开为绝对路径。
    /// 已经是绝对路径的字段保持不变。
    pub fn resolve_paths(&mut self, base_dir: &Path) {
        let resolve = |p: &str| -> String {
            let path = std::path::Path::new(p);
            if path.is_absolute() {
                p.to_string()
            } else {
                base_dir.join(path).to_string_lossy().into_owned()
            }
        };

        // cache_file.path
        if let Some(ref mut cf) = self.experimental.cache_file {
            cf.path = resolve(&cf.path);
        }

        // route.rule_set[].path
        for rs in &mut self.route.rule_set {
            if let Some(ref mut p) = rs.path {
                *p = resolve(p);
            }
        }

        // providers: local.path 和 remote.path（本地缓存）
        for provider in &mut self.providers {
            match provider {
                crate::config::provider::ProviderConfig::Local(l) => {
                    l.path = resolve(&l.path);
                }
                crate::config::provider::ProviderConfig::Remote(r) => {
                    if let Some(ref mut p) = r.path {
                        *p = resolve(p);
                    }
                }
            }
        }
    }

    /// 从文件路径加载并解析配置，按文件扩展名自动选择解析器：
    /// `.json` → JSON（兼容 JSONC 注释）；`.yaml` / `.yml` → YAML。
    /// 其它扩展名按 JSON 处理。
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let fmt = ConfigFormat::from_path(path);
        Self::from_text_with_format(&raw, fmt)
            .with_context(|| format!("failed to parse config file ({fmt}): {}", path.display()))
    }

    /// 从 JSON 字符串解析配置（保留向后兼容，等价于
    /// `from_text_with_format(s, ConfigFormat::Json)`）。
    pub fn from_text(s: &str) -> anyhow::Result<Self> {
        Self::from_text_with_format(s, ConfigFormat::Json)
    }

    /// 按指定格式解析配置文本。
    pub fn from_text_with_format(s: &str, fmt: ConfigFormat) -> anyhow::Result<Self> {
        let config: Self = match fmt {
            ConfigFormat::Json => {
                // JSON 路径保留 // 和 # 注释剥离（兼容 JSONC 写法）。
                let stripped = strip_comments(s);
                serde_json::from_str(&stripped)
                    .map_err(|e| anyhow::anyhow!("JSON parse error: {e}"))?
            }
            ConfigFormat::Yaml => {
                // YAML 原生支持 # 注释；而 // 不是注释符号
                // （如 password: a//b 这种值不能被误判），所以不做预处理。
                serde_yaml::from_str(s).map_err(|e| anyhow::anyhow!("YAML parse error: {e}"))?
            }
        };
        config.validate()?;
        Ok(config)
    }

    /// 基础合法性校验
    fn validate(&self) -> anyhow::Result<()> {
        use std::collections::HashSet;

        // ── Provider ─────────────────────────────────────────────────────────
        let mut provider_tags = HashSet::new();
        for p in &self.providers {
            let tag = p.tag();
            if !provider_tags.insert(tag.to_string()) {
                anyhow::bail!("duplicate provider tag: '{tag}'");
            }
            // 验证时间格式
            match p {
                crate::config::provider::ProviderConfig::Remote(r) => {
                    r.update_interval_duration()
                        .with_context(|| format!("provider '{tag}': invalid update_interval"))?;
                    if let Some(hc) = &r.health_check {
                        hc.interval_duration().with_context(|| {
                            format!("provider '{tag}': invalid health_check.interval")
                        })?;
                        hc.timeout_duration().with_context(|| {
                            format!("provider '{tag}': invalid health_check.timeout")
                        })?;
                    }
                }
                crate::config::provider::ProviderConfig::Local(l) => {
                    if let Some(hc) = &l.health_check {
                        hc.interval_duration().with_context(|| {
                            format!("provider '{tag}': invalid health_check.interval")
                        })?;
                        hc.timeout_duration().with_context(|| {
                            format!("provider '{tag}': invalid health_check.timeout")
                        })?;
                    }
                }
            }
        }

        // ── Outbound ─────────────────────────────────────────────────────────
        let mut ob_tags = HashSet::new();
        for ob in &self.outbounds {
            let tag = ob.tag();
            if !ob_tags.insert(tag.to_string()) {
                anyhow::bail!("duplicate outbound tag: '{tag}'");
            }
            match ob {
                OutboundConfig::Vless(c) => validate_uuid(&c.uuid)
                    .with_context(|| format!("outbound '{}': invalid UUID", c.tag))?,
                OutboundConfig::Vmess(c) => validate_uuid(&c.uuid)
                    .with_context(|| format!("outbound '{}': invalid UUID", c.tag))?,
                OutboundConfig::Tuic(c) => validate_uuid(&c.uuid)
                    .with_context(|| format!("outbound '{}': invalid UUID", c.tag))?,
                _ => {}
            }
        }

        for ob in &self.outbounds {
            validate_outbound_group(ob, &ob_tags, &provider_tags)
                .with_context(|| format!("outbound '{}': invalid group", ob.tag()))?;
        }
        validate_outbound_group_cycles(&self.outbounds)?;

        // route.final 校验：
        // - 用户声明的 outbounds 非空时，final 必须匹配某个 outbound tag。
        // - outbounds 为空时，OutboundManager 会自动补一个 tag="direct" 的直连出站，
        //   因此 final="direct"（RouteConfig 默认值）是合法的；其他 tag 才报错。
        let final_tag = &self.route.r#final;
        if !ob_tags.is_empty() {
            if !ob_tags.contains(final_tag.as_str()) {
                anyhow::bail!("route.final '{final_tag}' does not match any outbound tag");
            }
        } else if final_tag != "direct" {
            anyhow::bail!(
                "route.final '{final_tag}' does not match any outbound tag \
                 (outbounds is empty, only 'direct' is auto-provided)"
            );
        }

        for (i, rule) in self.route.rules.iter().enumerate() {
            // hijack_dns 和 sniff=true 的规则 outbound 可以为空，跳过校验
            if rule.hijack_dns || rule.sniff || rule.resolve {
                continue;
            }
            if rule.outbound != "dns-out" && !ob_tags.contains(rule.outbound.as_str()) {
                anyhow::bail!(
                    "route.rules[{i}].outbound '{}' does not match any outbound tag",
                    rule.outbound
                );
            }
        }

        let rs_tags: HashSet<_> = self.route.rule_set.iter().map(|r| r.tag.as_str()).collect();
        if rs_tags.len() != self.route.rule_set.len() {
            anyhow::bail!("duplicate ruleset tag in route.rule_set");
        }
        for (i, rule) in self.route.rules.iter().enumerate() {
            for tag in &rule.ruleset {
                if !rs_tags.contains(tag.as_str()) {
                    anyhow::bail!(
                        "route.rules[{i}].ruleset '{tag}' is not declared in route.rule_set"
                    );
                }
            }
        }

        // ── Inbound ──────────────────────────────────────────────────────────
        let mut in_tags = HashSet::new();
        for ib in &self.inbounds {
            let tag = ib.tag();
            if !in_tags.insert(tag.to_string()) {
                anyhow::bail!("duplicate inbound tag: '{tag}'");
            }
            let (_, port) = ib.listen_addr();
            if port == 0 && !matches!(ib, InboundConfig::Tun(_)) {
                anyhow::bail!("inbound '{tag}': listen_port cannot be 0");
            }
        }

        for (i, rule) in self.route.rules.iter().enumerate() {
            for tag in &rule.inbound {
                if !in_tags.contains(tag.as_str()) {
                    anyhow::bail!(
                        "route.rules[{i}].inbound '{tag}' does not match any inbound tag"
                    );
                }
            }
        }

        // ── DNS ──────────────────────────────────────────────────────────────
        let mut dns_tags = HashSet::new();
        for srv in &self.dns.servers {
            if !dns_tags.insert(srv.tag.as_str()) {
                anyhow::bail!("duplicate dns server tag: '{}'", srv.tag);
            }
        }

        // 校验 dns.final 中所有 tag 都存在于 dns.servers（支持单 tag 或数组并发形式）
        if !self.dns.servers.is_empty() {
            for tag in self.dns.r#final.as_slice() {
                if !dns_tags.contains(tag.as_str()) {
                    anyhow::bail!(
                        "dns.final '{}' does not match any dns server tag",
                        self.dns.r#final
                    );
                }
            }
        }

        for (i, rule) in self.dns.rules.iter().enumerate() {
            // 校验 dns.rules[i].server 中所有 tag 都存在（支持单 tag 或数组并发形式）
            for tag in rule.server.as_slice() {
                if !dns_tags.contains(tag.as_str()) {
                    anyhow::bail!(
                        "dns.rules[{i}].server '{}' does not match any dns server tag",
                        rule.server
                    );
                }
            }
            for tag in &rule.inbound {
                if !in_tags.contains(tag.as_str()) {
                    anyhow::bail!("dns.rules[{i}].inbound '{tag}' does not match any inbound tag");
                }
            }
        }

        Ok(())
    }
}

fn validate_outbound_group(
    outbound: &OutboundConfig,
    tags: &std::collections::HashSet<String>,
    provider_tags: &std::collections::HashSet<String>,
) -> anyhow::Result<()> {
    if !outbound.is_group() {
        return Ok(());
    }

    let has_providers = outbound
        .group_providers()
        .is_some_and(|p| !p.tags.is_empty());

    // outbounds 和 providers 至少要有一个非空
    anyhow::ensure!(
        !outbound.child_outbounds().is_empty() || has_providers,
        "outbound '{}': both outbounds and providers are empty",
        outbound.tag()
    );

    for child in outbound.child_outbounds() {
        anyhow::ensure!(
            child != outbound.tag(),
            "outbound group cannot reference itself: '{child}'"
        );
        anyhow::ensure!(
            tags.contains(child),
            "outbound group references unknown outbound '{child}'"
        );
    }

    // 验证引用的 provider tag 都存在
    if let Some(pref) = outbound.group_providers() {
        for ptag in &pref.tags {
            anyhow::ensure!(
                provider_tags.contains(ptag.as_str()),
                "outbound '{}' references unknown provider '{ptag}'",
                outbound.tag()
            );
        }
    }

    if let Some(default) = outbound.group_default() {
        anyhow::ensure!(
            outbound
                .child_outbounds()
                .iter()
                .any(|child| child == default),
            "selector default '{default}' is not listed in outbounds"
        );
    }
    if let OutboundConfig::UrlTest(c) = outbound {
        c.interval_duration()?;
        c.idle_timeout_duration()?;
    }
    Ok(())
}

fn validate_outbound_group_cycles(outbounds: &[OutboundConfig]) -> anyhow::Result<()> {
    use std::collections::{HashMap, HashSet};

    fn visit<'a>(
        tag: &'a str,
        graph: &HashMap<&'a str, Vec<&'a str>>,
        visiting: &mut HashSet<&'a str>,
        visited: &mut HashSet<&'a str>,
    ) -> anyhow::Result<()> {
        if visited.contains(tag) {
            return Ok(());
        }
        if !visiting.insert(tag) {
            anyhow::bail!("outbound group cycle detected at '{tag}'");
        }
        if let Some(children) = graph.get(tag) {
            for child in children {
                if graph.contains_key(child) {
                    visit(child, graph, visiting, visited)?;
                }
            }
        }
        visiting.remove(tag);
        visited.insert(tag);
        Ok(())
    }

    let graph: HashMap<_, _> = outbounds
        .iter()
        .filter(|outbound| outbound.is_group())
        .map(|outbound| {
            (
                outbound.tag(),
                outbound
                    .child_outbounds()
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            )
        })
        .collect();

    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for tag in graph.keys() {
        visit(tag, &graph, &mut visiting, &mut visited)?;
    }
    Ok(())
}

/// 反序列化工具：同时接受单值或数组形式，统一返回 `Vec<T>`。
///
/// 用于路由规则和 DNS 规则中所有 OR 语义的多值字段（如 `domain`、`ip_cidr`、
/// `port`、`query_type`、`ruleset` 等），让用户在只有一个值时可以省略数组包装：
/// - `"domain": "example.com"`（单值，简洁）
/// - `"domain": ["a.com", "b.com"]`（数组，多值）
/// - `"port": 443`（单值）
/// - `"port": [80, 443]`（数组）
/// - `"query_type": "A"`（单值）
/// - `"query_type": ["A", "AAAA"]`（数组）
///
/// 序列化时统一输出数组形式（`Vec<T>` 的默认行为），单元素也是 `["x"]`，
/// 语义等价可往返解析。
///
/// 泛型参数 `T` 可以是 `String`、`PortFilter`、`DnsQueryType` 等任何实现
/// `Deserialize` 的类型。
pub(super) fn deserialize_one_or_many<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr<T> {
        One(T),
        Many(Vec<T>),
    }
    Ok(match Repr::<T>::deserialize(deserializer)? {
        Repr::One(s) => vec![s],
        Repr::Many(v) => v,
    })
}

/// 简易注释剥离：去掉行内 `//` 和 `#` 开头的注释。
/// 不处理字符串字面量内的注释符号（够用的简单实现）。
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('#') {
            out.push('\n');
            continue;
        }
        // 行内 // 注释：找第一个不在字符串里的 //
        if let Some(pos) = find_line_comment(line) {
            out.push_str(&line[..pos]);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn find_line_comment(line: &str) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut in_str = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => in_str = !in_str,
            b'\\' if in_str => i += 1, // 跳过转义字符
            b'/' if !in_str && i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn minimal_config() -> &'static str {
        r#"
        {
            "inbounds": [
                {
                    "type": "mixed",
                    "tag": "mixed-in",
                    "listen": "127.0.0.1",
                    "listen_port": 7890
                }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block",  "tag": "block"  }
            ],
            "route": {
                "final": "direct",
                "rules": [],
                "rule_set": []
            }
        }
        "#
    }

    #[test]
    fn parse_minimal() {
        Config::from_text(minimal_config()).unwrap();
    }

    #[test]
    fn duplicate_outbound_tag() {
        let s = r#"
        {
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "direct", "tag": "direct" }
            ],
            "route": { "final": "direct", "rules": [], "rule_set": [] }
        }
        "#;
        assert!(Config::from_text(s).is_err());
    }

    #[test]
    fn unknown_final_tag() {
        let s = r#"
        {
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "final": "nonexistent", "rules": [], "rule_set": [] }
        }
        "#;
        assert!(Config::from_text(s).is_err());
    }

    #[test]
    fn outbound_groups_validate_references() {
        let s = r#"{
            "inbounds": [{"type":"mixed","tag":"in","listen_port":7890}],
            "outbounds": [
                {"type":"direct","tag":"direct"},
                {"type":"block","tag":"香港节点 01"},
                {"type":"block","tag":"台湾节点 01"},
                {"type":"block","tag":"美国节点 01"},
                {
                    "type":"url-test",
                    "tag":"自动选择",
                    "outbounds":["香港节点 01","台湾节点 01","美国节点 01"],
                    "url":"https://www.gstatic.com/generate_204",
                    "interval":"3m",
                    "idle_timeout":"30m",
                    "tolerance":50
                },
                {
                    "type":"selector",
                    "tag":"🚀 节点选择",
                    "outbounds":["自动选择","香港节点 01","台湾节点 01","美国节点 01","direct"],
                    "default":"自动选择"
                }
            ],
            "route":{"final":"🚀 节点选择","rules":[],"rule_set":[]}
        }"#;
        Config::from_text(s).unwrap();
    }

    #[test]
    fn outbound_group_unknown_child_rejected() {
        let s = r#"{
            "outbounds": [
                {"type":"direct","tag":"direct"},
                {"type":"selector","tag":"select","outbounds":["missing"],"default":"missing"}
            ],
            "route":{"final":"select","rules":[],"rule_set":[]}
        }"#;
        assert!(Config::from_text(s).is_err());
    }

    #[test]
    fn outbound_group_cycle_rejected() {
        let s = r#"{
            "outbounds": [
                {"type":"selector","tag":"a","outbounds":["b"]},
                {"type":"selector","tag":"b","outbounds":["a"]}
            ],
            "route":{"final":"a","rules":[],"rule_set":[]}
        }"#;
        assert!(Config::from_text(s).is_err());
    }

    #[test]
    fn strip_comments_basic() {
        let src = r#"
        // top comment
        {
            "key": "value" // inline
            # hash comment
        }
        "#;
        let out = strip_comments(src);
        assert!(!out.contains("top comment"));
        assert!(!out.contains("inline"));
        assert!(!out.contains("hash comment"));
        assert!(out.contains("\"key\""));
    }
}

#[cfg(test)]
mod yaml_tests {
    use super::*;

    const MINIMAL_YAML: &str = r#"
inbounds:
  - type: mixed
    tag: mixed-in
    listen: 127.0.0.1
    listen_port: 7890

outbounds:
  - type: direct
    tag: direct
  - type: block
    tag: block

route:
  final: direct
  rules: []
  rule_set: []
"#;

    #[test]
    fn parse_minimal_yaml() {
        Config::from_text_with_format(MINIMAL_YAML, ConfigFormat::Yaml).unwrap();
    }

    /// YAML 中 `//` 不是注释符号，含 `//` 的字符串值必须原样保留
    /// （JSON 路径会先 strip_comments，YAML 路径不能这么干）。
    #[test]
    fn yaml_preserves_double_slash_in_value() {
        let s = r#"
inbounds:
  - type: dns
    tag: dns-in
    listen: 127.0.0.1
    listen_port: 5353
dns:
  servers:
    - tag: block
      address: "rcode://refused"
  final: block
  rules: []
outbounds:
  - type: direct
    tag: direct
route:
  final: direct
  rules: []
  rule_set: []
"#;
        let cfg = Config::from_text_with_format(s, ConfigFormat::Yaml).unwrap();
        assert_eq!(cfg.dns.servers[0].address, "rcode://refused");
    }

    /// YAML 原生支持 `#` 注释（行尾与整行）。
    #[test]
    fn yaml_supports_hash_comments() {
        let s = r#"
# top comment
inbounds:
  - type: mixed   # inline comment
    tag: in
    listen_port: 7890
outbounds:
  - type: direct
    tag: direct
route:
  final: direct
  rules: []
  rule_set: []
"#;
        Config::from_text_with_format(s, ConfigFormat::Yaml).unwrap();
    }

    /// 含 emoji / 中文 tag 的 YAML（验证 UTF-8 字符串处理）。
    #[test]
    fn yaml_unicode_tags() {
        let s = r#"
inbounds:
  - type: mixed
    tag: in
    listen_port: 7890
outbounds:
  - type: block
    tag: 香港节点 01
  - type: block
    tag: 🚀 节点选择
  - type: selector
    tag: 选择
    outbounds:
      - 香港节点 01
      - 🚀 节点选择
    default: 香港节点 01
route:
  final: 选择
  rules: []
  rule_set: []
"#;
        let cfg = Config::from_text_with_format(s, ConfigFormat::Yaml).unwrap();
        assert_eq!(cfg.outbounds.len(), 3);
    }

    #[test]
    fn format_from_path_extension() {
        use std::path::Path;
        assert_eq!(
            ConfigFormat::from_path(Path::new("a.json")),
            ConfigFormat::Json
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("a.yaml")),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("a.yml")),
            ConfigFormat::Yaml
        );
        // 未识别扩展名按 JSON 处理
        assert_eq!(ConfigFormat::from_path(Path::new("a")), ConfigFormat::Json);
        assert_eq!(
            ConfigFormat::from_path(Path::new("a.txt")),
            ConfigFormat::Json
        );
    }

    #[test]
    fn yaml_parse_error_message() {
        let bad = "inbounds: [ { : invalid\n";
        let err = Config::from_text_with_format(bad, ConfigFormat::Yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("YAML"), "expected 'YAML' in error: {msg}");
    }

    /// 同一份 minimal 配置的 JSON 与 YAML 等价解析结果应都通过校验。
    #[test]
    fn json_and_yaml_minimal_both_parse() {
        let minimal_json = r#"
        {
            "inbounds": [
                { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890 }
            ],
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "block",  "tag": "block"  }
            ],
            "route": { "final": "direct", "rules": [], "rule_set": [] }
        }
        "#;
        Config::from_text(minimal_json).unwrap();
        Config::from_text_with_format(MINIMAL_YAML, ConfigFormat::Yaml).unwrap();
    }
}

/// UUID v4 格式验证：xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
/// 接受带连字符或无连字符的 32 个十六进制字符
pub fn validate_uuid(s: &str) -> anyhow::Result<()> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(
        hex.len() == 32,
        "UUID must contain exactly 32 hex digits, got {}: '{s}'",
        hex.len()
    );
    // 带连字符时检查位置
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        anyhow::ensure!(
            parts.len() == 5
                && parts[0].len() == 8
                && parts[1].len() == 4
                && parts[2].len() == 4
                && parts[3].len() == 4
                && parts[4].len() == 12,
            "UUID must be in format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx: '{s}'"
        );
    }
    Ok(())
}

#[cfg(test)]
mod validate_tests {
    use super::*;

    fn base_config(extra: &str) -> String {
        format!(
            r#"{{
            "inbounds": [{{"type":"mixed","tag":"in","listen_port":7890}}],
            "outbounds": [{{"type":"direct","tag":"direct"}}],
            "route": {{"final":"direct","rules":[],"rule_set":[]}},
            {extra}
        }}"#
        )
    }

    // ── UUID ─────────────────────────────────────────────────────────────────

    #[test]
    fn valid_uuid_with_dashes() {
        validate_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
    }
    #[test]
    fn valid_uuid_no_dashes() {
        validate_uuid("aabbccdd11223344aabbccdd11223344").unwrap();
    }
    #[test]
    fn invalid_uuid_too_short() {
        assert!(validate_uuid("aabbccdd-1122-3344").is_err());
    }
    #[test]
    fn invalid_uuid_bad_chars() {
        assert!(validate_uuid("gggggggg-gggg-gggg-gggg-gggggggggggg").is_err());
    }
    #[test]
    fn invalid_uuid_wrong_dash_positions() {
        assert!(validate_uuid("aaaa-aaaabbbb-cccc-dddd-eeeeeeeeeeee").is_err());
    }

    // ── Inbound ───────────────────────────────────────────────────────────────

    #[test]
    fn port_zero_rejected() {
        let s = r#"{"inbounds":[{"type":"mixed","tag":"in","listen_port":0}],
                    "outbounds":[{"type":"direct","tag":"direct"}],
                    "route":{"final":"direct","rules":[],"rule_set":[]}}"#;
        assert!(Config::from_text(s).is_err());
    }

    #[test]
    fn duplicate_inbound_tag() {
        let s = r#"{"inbounds":[
                        {"type":"mixed","tag":"in","listen_port":7890},
                        {"type":"dns","tag":"in","listen_port":5353}
                    ],
                    "outbounds":[{"type":"direct","tag":"direct"}],
                    "route":{"final":"direct","rules":[],"rule_set":[]}}"#;
        assert!(Config::from_text(s).is_err());
    }

    // ── Route ruleset 引用 ────────────────────────────────────────────────────

    #[test]
    fn undeclared_ruleset_in_rules() {
        let s = r#"{"inbounds":[{"type":"mixed","tag":"in","listen_port":7890}],
                    "outbounds":[{"type":"direct","tag":"direct"}],
                    "route":{
                        "final":"direct",
                        "rules":[{"ruleset":["nonexistent"],"outbound":"direct"}],
                        "rule_set":[]
                    }}"#;
        assert!(Config::from_text(s).is_err());
    }

    #[test]
    fn declared_ruleset_passes() {
        // ruleset 文件不存在也能通过 config validate（文件在 router 加载时才检查）
        let s = r#"{"inbounds":[{"type":"mixed","tag":"in","listen_port":7890}],
                    "outbounds":[{"type":"direct","tag":"direct"}],
                    "route":{
                        "final":"direct",
                        "rules":[{"ruleset":["my-rules"],"outbound":"direct"}],
                        "rule_set":[{"tag":"my-rules","type":"local","path":"/tmp/rules.bin"}]
                    }}"#;
        Config::from_text(s).unwrap();
    }

    // ── Route inbound tag 引用 ────────────────────────────────────────────────

    #[test]
    fn route_rule_unknown_inbound() {
        let s = r#"{"inbounds":[{"type":"mixed","tag":"in","listen_port":7890}],
                    "outbounds":[{"type":"direct","tag":"direct"}],
                    "route":{
                        "final":"direct",
                        "rules":[{"inbound":["ghost-in"],"outbound":"direct"}],
                        "rule_set":[]
                    }}"#;
        assert!(Config::from_text(s).is_err());
    }

    // ── DNS ───────────────────────────────────────────────────────────────────

    #[test]
    fn dns_duplicate_server_tag() {
        let s = base_config(
            r#""dns":{"servers":[
            {"tag":"s","address":"1.1.1.1"},
            {"tag":"s","address":"8.8.8.8"}
        ],"final":"s","rules":[]}"#,
        );
        assert!(Config::from_text(&s).is_err());
    }

    #[test]
    fn dns_unknown_final() {
        let s = base_config(
            r#""dns":{"servers":[
            {"tag":"local","address":"1.1.1.1"}
        ],"final":"nonexistent","rules":[]}"#,
        );
        assert!(Config::from_text(&s).is_err());
    }

    #[test]
    fn dns_rule_unknown_server() {
        let s = base_config(
            r#""dns":{"servers":[
            {"tag":"local","address":"1.1.1.1"}
        ],"final":"local","rules":[
            {"domain_suffix":[".cn"],"server":"ghost"}
        ]}"#,
        );
        assert!(Config::from_text(&s).is_err());
    }

    #[test]
    fn dns_rule_unknown_inbound() {
        let s = base_config(
            r#""dns":{"servers":[
            {"tag":"local","address":"1.1.1.1"}
        ],"final":"local","rules":[
            {"inbound":["ghost-in"],"server":"local"}
        ]}"#,
        );
        assert!(Config::from_text(&s).is_err());
    }

    #[test]
    fn full_valid_config_passes() {
        let s = r#"{
            "log": {"level":"info"},
            "inbounds": [
                {"type":"tproxy","tag":"tp","listen_port":7893},
                {"type":"mixed","tag":"mixed","listen_port":7890},
                {"type":"dns","tag":"dns-in","listen_port":5353}
            ],
            "dns": {
                "servers": [
                    {"tag":"local","address":"223.5.5.5"},
                    {"tag":"remote","address":"https://1.1.1.1/dns-query"},
                    {"tag":"block","address":"rcode://refused"}
                ],
                "rules": [
                    {"inbound":["dns-in"],"domain_suffix":[".cn"],"server":"local"},
                    {"ruleset":["geosite-ads"],"server":"block"}
                ],
                "final": "remote"
            },
            "outbounds": [
                {"type":"direct","tag":"direct"},
                {"type":"block","tag":"block"}
            ],
            "route": {
                "final": "direct",
                "rules": [
                    {"inbound":["dns-in"],"outbound":"dns-out"},
                    {"ruleset":["geosite-ads"],"outbound":"block"}
                ],
                "rule_set": [
                    {"tag":"geosite-ads","type":"local","path":"/tmp/ads.bin"}
                ]
            }
        }"#;
        Config::from_text(s).unwrap();
    }
}
