//! 将 AdGuardHome / AdBlock 风格的 `.txt` 过滤规则文件转换为 [`CompiledRuleSet`]。
//!
//! 参考 sing-box 的 `rule-set convert -t adguard`（`common/convertor/adguard`）的思路，
//! 把 AdGuard 简化 AdBlock 语法尽力映射到 reflex `.rrs` 已有的几种原语
//! （精确域名 / 域名后缀 / 域名关键词 / 域名正则）上。
//!
//! reflex 的匹配引擎是「多类型并集匹配」，没有 sing-box 内部 succinct-trie
//! 那种支持任意位置通配符、反选（`@@`）、优先级（`$important`）的能力，
//! 因此本模块是**尽力而为的近似转换**，而非逐字节复刻 sing-box 的语义。
//! 关键差异已在下方各分支注释中说明。
//!
//! 支持的输入子集：
//! - 注释：以 `!` 或 `#` 开头的整行
//! - hosts 格式：`0.0.0.0 example.com` / `:: example.com`（仅未指定地址，
//!   与 AdGuardHome 自身约定一致）→ 精确域名
//! - `||example.com^` / `||example.com`              → 域名后缀（含自身）
//! - `|example.com^` / `|example.com`（单竖线）        → 精确域名
//! - 裸域名一行（无任何锚点）                          → 域名后缀（含自身）
//! - `.example.com`（前导点）                          → 域名后缀
//! - `/regex/`                                        → 域名正则
//! - 含 `*` 通配符的规则                                → 转换为等价域名正则
//! - `$important` / `$app=` / `$network=` / `$dnstype=` / `$dnsrewrite=0.0.0.0`
//!   等修饰符 → 忽略修饰符本身，继续解析域名部分
//!
//! 不支持、按行跳过并计入 `ignored_lines` 的内容：
//! - 例外规则 `@@...`（reflex 规则集没有反选/白名单语义）
//! - 带路径 / 查询参数 / 元素隐藏等「化妆品」过滤规则
//! - IP-CIDR 风格规则（AdGuard 文档中也不建议在 DNS 过滤里使用）
//! - 携带未识别修饰符（如 `$third-party`、`$script` 等）的规则

use regex::Regex;

use super::{compiler::CompiledRuleSet, error::Result};

/// 单行转换结果。
enum AdGuardEntry {
    /// 精确域名匹配
    Domain(String),
    /// 域名后缀匹配（含自身）
    Suffix(String),
    /// 已编译校验过的正则表达式（原始 pattern，未来按域名正则 section 存储）
    Regex(String),
}

/// 转换报告：除编译结果外附带统计信息，便于 CLI 输出。
#[derive(Debug)]
pub struct AdGuardConvertReport {
    pub ruleset: CompiledRuleSet,
    /// 非空、非注释的有效输入行数
    pub total_lines: usize,
    /// 因不支持的语法被跳过的行数
    pub ignored_lines: usize,
}

impl CompiledRuleSet {
    /// 从 AdGuardHome / AdBlock 风格文本编译（最佳努力转换，不因个别行失败而中止）。
    pub fn from_adguard_text(src: &str) -> Result<AdGuardConvertReport> {
        let mut out = CompiledRuleSet::default();
        let mut total_lines = 0usize;
        let mut ignored_lines = 0usize;

        for raw in src.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
                continue;
            }
            total_lines += 1;

            match parse_adguard_line(line) {
                Some(AdGuardEntry::Domain(d)) if d.len() <= 255 => out.domains.push(d),
                Some(AdGuardEntry::Suffix(d)) if d.len() <= 255 => out.domain_suffixes.push(d),
                Some(AdGuardEntry::Regex(r)) => out.domain_regexes.push(r),
                Some(_) | None => ignored_lines += 1,
            }
        }

        Ok(AdGuardConvertReport {
            ruleset: out,
            total_lines,
            ignored_lines,
        })
    }
}

/// 解析单行 AdGuard 规则，返回 `None` 表示该行不受支持（跳过）。
fn parse_adguard_line(line: &str) -> Option<AdGuardEntry> {
    // 1) hosts 格式："0.0.0.0 example.com" / ":: example.com"
    //    仅未指定地址（0.0.0.0 / ::）才视为屏蔽规则，与 AdGuardHome 约定一致；
    //    其他 IP（如 127.0.0.1 这类传统 hosts 拦截写法）不在 AdGuardHome 语义内，跳过。
    if let Some(entry) = try_parse_hosts_line(line) {
        return Some(entry);
    }

    let mut s = line.trim_end_matches('|').to_string();

    // 2) 修饰符 $xxx,yyy=zzz（正则规则 /.../ 内的 $ 不算修饰符分隔符）
    if !s.starts_with('/') {
        if let Some(idx) = s.find('$') {
            let modifiers = &s[idx + 1..];
            if !modifiers_supported(modifiers) {
                return None;
            }
            s.truncate(idx);
            s = s.trim_end_matches('|').to_string();
        }
    }

    // 3) 例外（白名单）规则：reflex 单一 .rrs 没有反选语义，无法表达，跳过
    if s.starts_with("@@") {
        return None;
    }

    // 4) 锚点：|| 后缀锚点 / | 起始锚点 / ^ 分隔符结尾
    let mut is_suffix = false;
    let mut has_start = false;
    if let Some(rest) = s.strip_prefix("||") {
        s = rest.to_string();
        is_suffix = true;
    } else if let Some(rest) = s.strip_prefix('|') {
        s = rest.to_string();
        has_start = true;
    }
    let has_end = if let Some(rest) = s.strip_suffix('^') {
        s = rest.to_string();
        true
    } else {
        false
    };

    // 5) 正则规则 /pattern/
    if s.len() >= 2 && s.starts_with('/') && s.ends_with('/') {
        let body = &s[1..s.len() - 1];
        if body.is_empty() || looks_like_ip_regex(body) {
            return None;
        }
        if Regex::new(body).is_err() {
            return None;
        }
        return Some(AdGuardEntry::Regex(body.to_string()));
    }

    // 6) URL scheme（http://、https:// 等）→ 去掉 scheme，按后缀处理
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
        is_suffix = true;
    }

    // 7) 不支持的内容：路径 / 查询参数 / 元素隐藏（化妆品过滤）/ 取反修饰符
    if s.is_empty()
        || s.contains('/')
        || s.contains('?')
        || s.contains('&')
        || s.contains('[')
        || s.contains(']')
        || s.contains('(')
        || s.contains(')')
        || s.contains('!')
        || s.contains('#')
        || s.contains('~')
    {
        return None;
    }

    // 8) 前导点：".example.com" 等价于后缀规则
    if let Some(rest) = s.strip_prefix('.') {
        s = rest.to_string();
        is_suffix = true;
    }

    // 9) 通配符 "*"：转换为等价正则
    if s.contains('*') {
        return build_wildcard_regex(&s, has_start, is_suffix, has_end).map(AdGuardEntry::Regex);
    }

    // 10) 校验剩余内容是否形如域名
    let lower = s.to_ascii_lowercase();
    if !looks_like_domain(&lower) {
        return None;
    }

    if is_suffix {
        // ||example.com^ → 域名及其所有子域名
        Some(AdGuardEntry::Suffix(lower))
    } else if has_start || has_end {
        // |example.com^ / |example.com / example.com^ → 仅精确域名
        Some(AdGuardEntry::Domain(lower))
    } else {
        // 裸域名一行，没有任何锚点：实践中绝大多数 AdGuardHome 域名列表
        // 都期望「该域名及其子域名」一并屏蔽，故按后缀处理（比 sing-box 内部
        // 严格的「无锚点 = 子串匹配」更贴近常见过滤列表的使用预期）。
        Some(AdGuardEntry::Suffix(lower))
    }
}

/// 解析 "<ip> <domain>" 形式的 hosts 行，仅接受未指定地址（0.0.0.0 / ::）。
fn try_parse_hosts_line(line: &str) -> Option<AdGuardEntry> {
    let mut parts = line.split_whitespace();
    let ip_str = parts.next()?;
    let domain = parts.next()?;
    if parts.next().is_some() {
        // 超过两列，不是简单 hosts 格式，交还给后续通用解析逻辑处理
        return None;
    }
    let ip: std::net::IpAddr = ip_str.parse().ok()?;
    if !ip.is_unspecified() {
        return None;
    }
    let lower = domain.to_ascii_lowercase();
    if !looks_like_domain(&lower) {
        return None;
    }
    Some(AdGuardEntry::Domain(lower))
}

/// 是否携带 reflex 能够处理的修饰符；遇到未识别的修饰符直接判定整行不支持。
fn modifiers_supported(modifiers: &str) -> bool {
    for param in modifiers.split(',') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        let mut it = param.splitn(2, '=');
        let key = it.next().unwrap_or("").trim();
        let val = it.next().map(str::trim);
        match key {
            // 这些修饰符与“域名是否命中”无关或 reflex 引擎不区分优先级，
            // 忽略修饰符本身、继续解析域名部分。
            "app" | "network" | "dnstype" | "important" => {}
            // dnsrewrite 仅当改写为「未指定地址」（等价于拦截）时才可安全忽略
            "dnsrewrite" => match val {
                Some("0.0.0.0") | Some("::") => {}
                _ => return false,
            },
            _ => return false,
        }
    }
    true
}

/// 粗略判断正则是否在匹配 IP 地址（而非域名），不支持则跳过。
/// 对应 sing-box `ignoreIPCIDRRegexp` 的简化版本。
fn looks_like_ip_regex(body: &str) -> bool {
    let mut b = body;
    if let Some(rest) = b.strip_prefix("(http?:\\/\\/)") {
        b = rest;
    } else if let Some(rest) = b.strip_prefix("(https?:\\/\\/)") {
        b = rest;
    } else if let Some(rest) = b.strip_prefix('^') {
        b = rest;
    }
    let head_escaped = b.split("\\.").next().unwrap_or("");
    let head_plain = b.split('.').next().unwrap_or("");
    head_escaped.parse::<u8>().is_ok() || head_plain.parse::<u8>().is_ok()
}

/// 将含 "*" 的域名片段转换为等价正则，按原有锚点决定首尾是否锚定。
fn build_wildcard_regex(body: &str, has_start: bool, is_suffix: bool, has_end: bool) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let mut pattern = String::new();
    if has_start {
        pattern.push('^');
    } else if is_suffix {
        // 后缀规则允许通配符前面还有任意层子域名
        pattern.push_str(r"(^|\.)");
    }
    for (i, part) in body.split('*').enumerate() {
        if i > 0 {
            pattern.push_str(".*");
        }
        pattern.push_str(&regex::escape(part));
    }
    if has_end {
        pattern.push('$');
    }
    if Regex::new(&pattern).is_err() {
        return None;
    }
    Some(pattern)
}

/// 宽松域名字符集校验：允许字母、数字、连字符、下划线、点；不允许首尾为点。
fn looks_like_domain(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_blank_lines_skipped() {
        let report = CompiledRuleSet::from_adguard_text("! comment\n# also comment\n\n").unwrap();
        assert_eq!(report.total_lines, 0);
        assert_eq!(report.ignored_lines, 0);
        assert_eq!(report.ruleset.total_entries(), 0);
    }

    #[test]
    fn double_pipe_suffix() {
        let report = CompiledRuleSet::from_adguard_text("||example.com^").unwrap();
        assert_eq!(report.ruleset.domain_suffixes, vec!["example.com"]);
        assert_eq!(report.ignored_lines, 0);
    }

    #[test]
    fn single_pipe_exact() {
        let report = CompiledRuleSet::from_adguard_text("|example.com^").unwrap();
        assert_eq!(report.ruleset.domains, vec!["example.com"]);
    }

    #[test]
    fn bare_domain_treated_as_suffix() {
        let report = CompiledRuleSet::from_adguard_text("example.com").unwrap();
        assert_eq!(report.ruleset.domain_suffixes, vec!["example.com"]);
    }

    #[test]
    fn leading_dot_is_suffix() {
        let report = CompiledRuleSet::from_adguard_text(".example.com").unwrap();
        assert_eq!(report.ruleset.domain_suffixes, vec!["example.com"]);
    }

    #[test]
    fn hosts_format_unspecified() {
        let report = CompiledRuleSet::from_adguard_text("0.0.0.0 ads.example.com\n:: t.example.com").unwrap();
        assert_eq!(
            report.ruleset.domains,
            vec!["ads.example.com", "t.example.com"]
        );
    }

    #[test]
    fn hosts_format_non_unspecified_ignored() {
        let report = CompiledRuleSet::from_adguard_text("127.0.0.1 ads.example.com").unwrap();
        assert_eq!(report.ruleset.total_entries(), 0);
        assert_eq!(report.ignored_lines, 1);
    }

    #[test]
    fn regex_rule() {
        let report = CompiledRuleSet::from_adguard_text(r"/^ad[0-9]+\.example\.com$/").unwrap();
        assert_eq!(report.ruleset.domain_regexes.len(), 1);
    }

    #[test]
    fn wildcard_rule_converted_to_regex() {
        let report = CompiledRuleSet::from_adguard_text("||*.ads.example.com^").unwrap();
        assert_eq!(report.ruleset.domain_regexes.len(), 1);
        assert_eq!(report.ignored_lines, 0);
    }

    #[test]
    fn important_modifier_kept() {
        let report = CompiledRuleSet::from_adguard_text("||example.com^$important").unwrap();
        assert_eq!(report.ruleset.domain_suffixes, vec!["example.com"]);
    }

    #[test]
    fn unsupported_modifier_ignored() {
        let report = CompiledRuleSet::from_adguard_text("||example.com^$third-party").unwrap();
        assert_eq!(report.ruleset.total_entries(), 0);
        assert_eq!(report.ignored_lines, 1);
    }

    #[test]
    fn exception_rule_ignored() {
        let report = CompiledRuleSet::from_adguard_text("@@||example.com^").unwrap();
        assert_eq!(report.ruleset.total_entries(), 0);
        assert_eq!(report.ignored_lines, 1);
    }

    #[test]
    fn cosmetic_filter_ignored() {
        let report = CompiledRuleSet::from_adguard_text("example.com##.ad-banner").unwrap();
        assert_eq!(report.ignored_lines, 1);
    }

    #[test]
    fn path_rule_ignored() {
        let report = CompiledRuleSet::from_adguard_text("||example.com/track^").unwrap();
        assert_eq!(report.ignored_lines, 1);
    }

    #[test]
    fn scheme_prefix_treated_as_suffix() {
        let report = CompiledRuleSet::from_adguard_text("https://example.com^").unwrap();
        assert_eq!(report.ruleset.domain_suffixes, vec!["example.com"]);
    }

    #[test]
    fn mixed_real_world_sample() {
        let sample = r#"
! Title: Sample
# another comment
0.0.0.0 host.example.com
||ads.example.net^
||tracker.example.org^$important
|exact.example.io^
.suffix.example.dev
@@||allow.example.com^
example.com/some/path
example.com##.banner
/^ad[0-9]+\.example\.com$/
||*.wild.example.app^
"#;
        let report = CompiledRuleSet::from_adguard_text(sample).unwrap();
        assert_eq!(report.total_lines, 10);
        assert_eq!(report.ignored_lines, 3); // @@, /path, ##banner
        assert!(
            report
                .ruleset
                .domains
                .contains(&"host.example.com".to_string())
        );
        assert!(
            report
                .ruleset
                .domains
                .contains(&"exact.example.io".to_string())
        );
        assert!(
            report
                .ruleset
                .domain_suffixes
                .contains(&"ads.example.net".to_string())
        );
        assert!(
            report
                .ruleset
                .domain_suffixes
                .contains(&"tracker.example.org".to_string())
        );
        assert!(
            report
                .ruleset
                .domain_suffixes
                .contains(&"suffix.example.dev".to_string())
        );
        assert_eq!(report.ruleset.domain_regexes.len(), 2);
    }
}
