use regex::Regex;

use super::{compiler::CompiledRuleSet, error::Result};

/// 单行转换结果。
#[derive(Debug)]
enum AdGuardEntry {
    /// 精确域名匹配
    Domain(String),
    /// 域名后缀匹配（含自身）
    Suffix(String),
    /// 已编译校验过的正则表达式（原始 pattern，未来按域名正则 section 存储）
    Regex(String),
    /// 例外（@@）规则的精确域名（暂跳过，预留扩展）
    #[allow(dead_code)]
    ExcludeDomain(String),
    /// 例外规则的后缀
    #[allow(dead_code)]
    ExcludeSuffix(String),
    /// 例外规则的正则
    #[allow(dead_code)]
    ExcludeRegex(String),
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
                Some(AdGuardEntry::ExcludeDomain(d)) if d.len() <= 255 => {
                    out.exclude_domains.push(d);
                }
                Some(AdGuardEntry::ExcludeSuffix(d)) if d.len() <= 255 => {
                    out.exclude_domain_suffixes.push(d);
                }
                Some(AdGuardEntry::ExcludeRegex(r)) => out.exclude_domain_regexes.push(r),
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

/// 解析单行 AdGuard 规则，对齐 sing-box convertor.go 语义。
///
/// 处理流程（与 sing-box 一致）：
/// 1. 整行是合法域名（`isRawDomain`）→ 精确匹配（`Domain`）
/// 2. hosts 格式 → 精确匹配（仅 0.0.0.0 / ::）
/// 3. 修饰符解析
/// 4. 锚点处理（\|/||/^）
/// 5. 正则规则
/// 6. URL scheme
/// 7. 非法字符检查
/// 8. 通配符转正则 / 域名校验
///
/// 返回 `None` 表示该行不受支持（跳过）。
fn parse_adguard_line(line: &str) -> Option<AdGuardEntry> {
    // ── 1) 整行是合法裸域名 → 精确匹配 ──────────────────────────────
    //    对齐 sing-box convertor.go:47 的 isRawDomain 快速路径。
    //    TestSimpleHosts：example.com 不匹配 www.example.com。
    if is_raw_domain_line(line) {
        return Some(AdGuardEntry::Domain(line.to_ascii_lowercase()));
    }

    // ── 2) hosts 格式 ────────────────────────────────────────────────
    if let Some(entry) = try_parse_hosts_line(line) {
        return Some(entry);
    }

    let mut s = line.trim_end_matches('|').to_string();

    // ── 3) 修饰符 $xxx（正则中 $ 不参与拆分） ──────────────────────────
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

    // ── 4) 例外 @@ ────────────────────────────────────────────────────
    let is_exclude = if let Some(rest) = s.strip_prefix("@@") {
        s = rest.to_string();
        true
    } else {
        false
    };

    // ── 5) 锚点 ───────────────────────────────────────────────────────
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

    // ── 6) 正则规则 /pattern/ ─────────────────────────────────────────
    if s.len() >= 2 && s.starts_with('/') && s.ends_with('/') {
        let body = &s[1..s.len() - 1];
        if body.is_empty() || looks_like_ip_regex(body) {
            return None;
        }
        if Regex::new(body).is_err() {
            return None;
        }
        return if is_exclude {
            Some(AdGuardEntry::ExcludeRegex(body.to_string()))
        } else {
            Some(AdGuardEntry::Regex(body.to_string()))
        };
    }

    // ── 7) URL scheme ─────────────────────────────────────────────────
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
        is_suffix = true;
    }

    // ── 8) 不支持的内容 ────────────────────────────────────────────────
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

    // ── 8b) 纯 IP / IP-CIDR 行跳过（对齐 sing-box parseADGuardIPCIDRLine）───
    //        如 1.2.3.4 / 10.0.0.0/8 / 1.2.3. 等不是域名，不应纳入规则集
    if looks_like_ipcidr(&s) {
        return None;
    }

    // ── 9) 前导点 ".example.com" → 等价于后缀规则 ─────────────────────
    if let Some(rest) = s.strip_prefix('.') {
        s = rest.to_string();
        is_suffix = true;
    }

    // ── 10) 通配符 "*" → 转换为等价正则 ────────────────────────────────
    if s.contains('*') {
        return build_wildcard_regex(&s, has_start, is_suffix, has_end).map(|p| {
            if is_exclude {
                AdGuardEntry::ExcludeRegex(p)
            } else {
                AdGuardEntry::Regex(p)
            }
        });
    }

    // ── 11) 校验剩余内容是否形如域名 ──────────────────────────────────
    let lower = s.to_ascii_lowercase();
    if !looks_like_domain(&lower) {
        return None;
    }

    // ── 12) 按锚点分类 ────────────────────────────────────────────────
    //    对齐 sing AdGuardMatcher 的四状态模型：
    //    - isSuffix + hasEnd → suffix（域+子域，label 边界）
    //    - isSuffix + !hasEnd → suffix（已知限制：不匹配任意后缀如 .cn 变体，
    //      但绝大多数列表用 ||x^ 规范写法）
    //    - hasStart + hasEnd → exact（精确匹配）
    //    - hasStart + !hasEnd → regex ^{x}（前缀匹配，如 x 匹配 x.cn）
    //    - !hasStart + hasEnd → regex {x}$（子串匹配结尾锚定）
    //    - !hasStart + !hasEnd → suffix（裸域名带修饰符后；sing-box 此处为子串，
    //      reflex 近似为后缀以覆盖最常见场景）
    let entry = if is_suffix {
        // ||xxx 后缀锚点：匹配自身及所有子域
        AdGuardEntry::Suffix(lower)
    } else if has_start && has_end {
        // |xxx^ 精确匹配
        AdGuardEntry::Domain(lower)
    } else if has_start {
        // |xxx（起始锚无 ^）→ 前缀匹配（对齐 sing-box TestAdGuardSyntaxVariants：
        // |example.gov 匹配 example.gov.cn）
        let pattern = format!("^{}", regex::escape(&lower));
        AdGuardEntry::Regex(pattern)
    } else if has_end {
        // xxx^（无前缀有 ^）→ 子串匹配结尾锚定（对齐 sing-box：
        // example.org^ 匹配 notexample.org、www.example.org）
        let pattern = format!("{}$", regex::escape(&lower));
        AdGuardEntry::Regex(pattern)
    } else {
        // 裸域名（修饰符剥离后的残留）：后缀匹配，覆盖最常见场景
        AdGuardEntry::Suffix(lower)
    };

    if is_exclude {
        match entry {
            AdGuardEntry::Domain(d) => Some(AdGuardEntry::ExcludeDomain(d)),
            AdGuardEntry::Suffix(d) => Some(AdGuardEntry::ExcludeSuffix(d)),
            AdGuardEntry::Regex(r) => Some(AdGuardEntry::ExcludeRegex(r)),
            e => Some(e),
        }
    } else {
        Some(entry)
    }
}

/// 检查整行是否是合法裸域名（不含锚点 / 修饰符 / scheme / 通配符 / 正则分隔符）。
///
/// 对齐 sing-box convertor.go 的 `M.IsDomainName(ruleLine)` isRawDomain 快速路径：
/// 如果整行本身就是一个合法域名，不走任何后续解析，直接作为精确匹配。
fn is_raw_domain_line(line: &str) -> bool {
    // 排除快速失败：含空格 / $ / | / ^ / * / / / : 的肯定不是裸域名
    for ch in line.chars() {
        match ch {
            ' ' | '$' | '|' | '^' | '*' | '/' | ':' | '!' | '#' | '?' | '&'
            | '[' | ']' | '(' | ')' | '~' | '@' => return false,
            _ => {}
        }
    }
    // 不能以 . 或 - 开头
    if line.starts_with('.') || line.starts_with('-') {
        return false;
    }
    // 排除纯 IPv4 地址（如 1.2.3.4）、IP 段（1.2.3.）、IP CIDR 等
    if looks_like_ipcidr(line) {
        return false;
    }
    looks_like_domain(&line.to_ascii_lowercase())
}

/// 解析 "<ip> <domain>" 形式的 hosts 行，仅接受未指定地址（0.0.0.0 / ::）。
fn try_parse_hosts_line(line: &str) -> Option<AdGuardEntry> {
    let mut parts = line.split_whitespace();
    let ip_str = parts.next()?;
    let domain = parts.next()?;
    if parts.next().is_some() {
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
            "app" | "network" | "dnstype" | "important" => {}
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
/// 对应 sing-box `ignoreIPCIDRRegexp`。
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
///
/// AdGuard 通配符语义（对齐 sing AdGuardMatcher anyLabel）：
/// - `*` 匹配**零或多个**任意字符（含 `.`，可为空）
/// - `||*.x^` 匹配 x 本身及所有子域（`*` 可为空）
///
/// 修复要点：
/// - 开头 `*` 紧接 `.` 时（如 `*.x`），使用 `(?:[^.]+\.)*(?:\.)?x`
///   表示"0 或多个 label. 序列，可选跟上 ."，确保 `*` 为空时也能匹配主域名
fn build_wildcard_regex(
    body: &str,
    has_start: bool,
    is_suffix: bool,
    has_end: bool,
) -> Option<String> {
    if body.is_empty() {
        return None;
    }
    let mut pattern = String::new();
    if has_start {
        pattern.push('^');
    } else if is_suffix {
        pattern.push_str(r"(^|\.)");
    }

    let parts: Vec<&str> = body.split('*').collect();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            // 紧跟前一个 `*` 的部分为空（即连续 `*` 或开头 `*`），
            // 且当前段以 `.` 开头 → 使用 subdomain-label 匹配以支持 `*` 匹配空
            if parts[i - 1].is_empty() && part.starts_with('.') {
                let rest = &part[1..]; // 去掉前导 `.`
                pattern.push_str(r"(?:[^.]+\.)*");
                if !rest.is_empty() {
                    pattern.push_str(r"(?:\.)?");
                    pattern.push_str(&regex::escape(rest));
                }
            } else {
                pattern.push_str(".*");
                pattern.push_str(&regex::escape(part));
            }
        } else {
            pattern.push_str(&regex::escape(part));
        }
    }
    if has_end {
        pattern.push('$');
    }
    if Regex::new(&pattern).is_err() {
        return None;
    }
    Some(pattern)
}

/// 检查字符串是否为纯 IP 地址或 IP-CIDR（如 1.2.3.4、10.0.0.0/8、1.2.3.）。
/// 对齐 sing-box `parseADGuardIPCIDRLine`：AdGuard 列表中的 IP 行应被跳过。
fn looks_like_ipcidr(s: &str) -> bool {
    let s = s.trim_end_matches('.');
    let parts: Vec<&str> = s.split('.').collect();
    // IPv4：3-4 段，每段是 0-255 的数字
    if (3..=4).contains(&parts.len())
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && p.parse::<u8>().is_ok()
        })
    {
        return true;
    }
    // IPv6：含 ::
    if s.contains("::") && s.split(':').count() <= 8 {
        if let Ok(addr) = s.parse::<std::net::Ipv6Addr>() {
            return !addr.is_unspecified();
        }
    }
    false
}

/// 宽松域名字符集校验：允许字母、数字、连字符、点；不允许首尾为点。
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

    // ── 基本功能 ────────────────────────────────────────────────────────

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

    /// 裸域名 → 精确匹配（对齐 sing-box isRawDomain 快速路径）
    #[test]
    fn bare_domain_is_exact() {
        let report = CompiledRuleSet::from_adguard_text("example.com").unwrap();
        assert_eq!(report.ruleset.domains, vec!["example.com"]);
        assert_eq!(report.ruleset.domain_suffixes.len(), 0);
    }

    #[test]
    fn leading_dot_is_suffix() {
        let report = CompiledRuleSet::from_adguard_text(".example.com").unwrap();
        assert_eq!(report.ruleset.domain_suffixes, vec!["example.com"]);
    }

    // ── hosts 格式 ─────────────────────────────────────────────────────

    #[test]
    fn hosts_format_unspecified() {
        let report =
            CompiledRuleSet::from_adguard_text("0.0.0.0 ads.example.com\n:: t.example.com")
                .unwrap();
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

    // ── 正则 ────────────────────────────────────────────────────────────

    #[test]
    fn regex_rule() {
        let report = CompiledRuleSet::from_adguard_text(r"/^ad[0-9]+\.example\.com$/").unwrap();
        assert_eq!(report.ruleset.domain_regexes.len(), 1);
    }

    // ── 通配符 ──────────────────────────────────────────────────────────

    #[test]
    fn wildcard_rule_converted_to_regex() {
        let report = CompiledRuleSet::from_adguard_text("||*.ads.example.com^").unwrap();
        assert_eq!(report.ruleset.domain_regexes.len(), 1);
        assert_eq!(report.ignored_lines, 0);
        // 验证生成的正则支持 `*` 匹配空（ads.example.com 本身）
        let rx = Regex::new(&report.ruleset.domain_regexes[0]).unwrap();
        assert!(rx.is_match("ads.example.com"), "* should match empty");
        assert!(rx.is_match("x.ads.example.com"));
        assert!(!rx.is_match("ads.example.com.cn"));
    }

    #[test]
    fn wildcard_double_star() {
        let report = CompiledRuleSet::from_adguard_text("||**.example.org^").unwrap();
        let rx = Regex::new(&report.ruleset.domain_regexes[0]).unwrap();
        assert!(rx.is_match("example.org"), "** should match empty");
        assert!(rx.is_match("sub.example.org"));
    }

    // ── 修饰符 ──────────────────────────────────────────────────────────

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

    // ── 例外规则 @@（现在保留到 exclude_* 字段） ────────────────────────

    #[test]
    fn exception_rule_preserved() {
        let report = CompiledRuleSet::from_adguard_text(
            "@@||allow.com^\n@@|exact.io^\n||block.com^\n",
        )
        .unwrap();
        // @@||xxx^ → exclude_suffix
        assert!(report
            .ruleset
            .exclude_domain_suffixes
            .contains(&"allow.com".to_string()));
        // @@|xxx^ → exclude_domain
        assert!(report
            .ruleset
            .exclude_domains
            .contains(&"exact.io".to_string()));
        // 正常规则不受影响
        assert!(report
            .ruleset
            .domain_suffixes
            .contains(&"block.com".to_string()));
        assert_eq!(report.ignored_lines, 0);
    }

    // ── 不支持的模式 ────────────────────────────────────────────────────

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

    // ── URL scheme ──────────────────────────────────────────────────────

    #[test]
    fn scheme_prefix_treated_as_suffix() {
        let report = CompiledRuleSet::from_adguard_text("https://example.com^").unwrap();
        assert_eq!(report.ruleset.domain_suffixes, vec!["example.com"]);
    }

    // ── 锚点语义（对齐 sing-box） ──────────────────────────────────────

    /// xxx^（无前缀有 ^）→ 子串匹配结尾锚定
    #[test]
    fn no_prefix_with_end() {
        let report = CompiledRuleSet::from_adguard_text("example.org^").unwrap();
        assert_eq!(report.ruleset.domains.len(), 0);
        assert_eq!(report.ruleset.domain_suffixes.len(), 0);
        assert!(!report.ruleset.domain_regexes.is_empty());
        let rx = Regex::new(&report.ruleset.domain_regexes[0]).unwrap();
        // 子串匹配：结尾为 example.org 即命中
        assert!(rx.is_match("example.org"));
        assert!(rx.is_match("notexample.org"), "substring match");
        assert!(rx.is_match("www.example.org"), "substring match");
        assert!(!rx.is_match("example.org.cn"));
    }

    /// |xxx（有前缀无 ^）→ 前缀匹配
    #[test]
    fn start_prefix_no_end() {
        let report = CompiledRuleSet::from_adguard_text("|example.gov").unwrap();
        assert_eq!(report.ruleset.domains.len(), 0);
        assert!(!report.ruleset.domain_regexes.is_empty());
        let rx = Regex::new(&report.ruleset.domain_regexes[0]).unwrap();
        assert!(rx.is_match("example.gov"));
        assert!(rx.is_match("example.gov.cn"), "prefix match");
        assert!(!rx.is_match("www.example.gov"));
    }

    // ── IP 行跳过 ────────────────────────────────────────────────────────

    #[test]
    fn raw_ip_skipped() {
        let report = CompiledRuleSet::from_adguard_text("1.2.3.4").unwrap();
        assert_eq!(report.ruleset.total_entries(), 0);
        assert_eq!(report.ignored_lines, 1);
    }

    #[test]
    fn ip_cidr_skipped() {
        let report = CompiledRuleSet::from_adguard_text("10.0.0.0/8").unwrap();
        // / 本身已被非法字符检查跳过
        assert_eq!(report.ruleset.total_entries(), 0);
    }

    // ── 更多通配符场景（对齐 sing-box TestAdGuardWildcardVariants） ───────

    #[test]
    fn wildcard_at_middle() {
        let report = CompiledRuleSet::from_adguard_text("||ex*le.org^").unwrap();
        let rx = Regex::new(&report.ruleset.domain_regexes[0]).unwrap();
        assert!(rx.is_match("example.org"));
        assert!(rx.is_match("exle.org")); // * 为空
        assert!(rx.is_match("exile.org"));
        assert!(rx.is_match("ex123le.org"));
        assert!(rx.is_match("www.example.org"));
        assert!(!rx.is_match("example.com"));
    }

    #[test]
    fn wildcard_at_end() {
        let report = CompiledRuleSet::from_adguard_text("||example.*^").unwrap();
        let rx = Regex::new(&report.ruleset.domain_regexes[0]).unwrap();
        assert!(rx.is_match("example.org"));
        assert!(rx.is_match("example.com"));
        assert!(rx.is_match("example.co.uk"));
        assert!(rx.is_match("www.example.org"));
        assert!(!rx.is_match("notexample.org"));
    }

    #[test]
    fn wildcard_matching_dots() {
        let report = CompiledRuleSet::from_adguard_text("||example*org^").unwrap();
        let rx = Regex::new(&report.ruleset.domain_regexes[0]).unwrap();
        assert!(rx.is_match("example.org")); // * 为空
        assert!(rx.is_match("example.test.org")); // * = ".test."
        assert!(!rx.is_match("example.org.cn"));
    }

    // ── 综合测试 ────────────────────────────────────────────────────────

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
example.com
"#;
        let report = CompiledRuleSet::from_adguard_text(sample).unwrap();
        assert_eq!(report.total_lines, 11);
        assert_eq!(report.ignored_lines, 2); // /path, ##banner（@@ 不再被跳过）
        // hosts → exact
        assert!(report
            .ruleset
            .domains
            .contains(&"host.example.com".to_string()));
        // |xxx^ → exact
        assert!(report
            .ruleset
            .domains
            .contains(&"exact.example.io".to_string()));
        // bare → exact (new: isRawDomain)
        assert!(report.ruleset.domains.contains(&"example.com".to_string()));
        // suffix
        assert!(report
            .ruleset
            .domain_suffixes
            .contains(&"ads.example.net".to_string()));
        assert!(report
            .ruleset
            .domain_suffixes
            .contains(&"tracker.example.org".to_string()));
        assert!(report
            .ruleset
            .domain_suffixes
            .contains(&"suffix.example.dev".to_string()));
        // regex: /pattern/ + ||*.wild.example.app^ = 2 regex
        assert_eq!(report.ruleset.domain_regexes.len(), 2);
    }
}
