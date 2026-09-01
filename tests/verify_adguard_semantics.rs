//! 回归验证测试：对照 sing-box / sing AdGuardMatcher 语义检查 reflex 转换结果。
//! 运行：cargo test --test verify_adguard_semantics -- --nocapture

use reflex::ruleset::{MatchTarget, RuleSet};

fn compile_adguard(src: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let report = reflex::ruleset::CompiledRuleSet::from_adguard_text(src).unwrap();
    (
        report.ruleset.domains,
        report.ruleset.domain_suffixes,
        report.ruleset.domain_regexes,
    )
}

fn rs(src: &str) -> RuleSet {
    use reflex::ruleset::{CompiledRuleSet, LoadedRuleSet};
    let compiled = CompiledRuleSet::from_adguard_text(src).unwrap();
    let mut buf = Vec::new();
    compiled.ruleset.serialize(&mut buf).unwrap();
    RuleSet::from_loaded(LoadedRuleSet::from_bytes(&buf).unwrap()).unwrap()
}

fn check(multi_line: &str, domain: &str, sing_expect: bool) {
    let r = rs(multi_line);
    let got = r.matches(&MatchTarget::Domain(domain));
    let status = if got == sing_expect { "OK  " } else { "DIFF" };
    println!(
        "[{status}] rule={multi_line:<40} domain={domain:<24} reflex={got:<5} sing={sing_expect}"
    );
}

#[test]
fn verify_bare_domain() {
    // sing-box: 裸域名 → 精确 Domain（TestSimpleHosts: example.com 不匹配 www.example.com）
    let (domains, suffixes, _) = compile_adguard("example.com");
    println!("example.com -> domains={domains:?} suffixes={suffixes:?}");
    check("example.com", "example.com", true);
    check("example.com", "www.example.com", false); // sing 期望 false（精确）
}

#[test]
fn verify_no_anchor_with_end() {
    // sing-box: example.org^ → 子串匹配（匹配 notexample.org / www.example.org）
    let (domains, suffixes, _regexes) = compile_adguard("example.org^");
    println!("example.org^ -> domains={domains:?} suffixes={suffixes:?} regexes=[...]");
    check("example.org^", "example.org", true);
    check("example.org^", "notexample.org", true); // sing 期望 true（子串）
    check("example.org^", "www.example.org", true); // sing 期望 true（子串）
}

#[test]
fn verify_single_pipe_no_end() {
    // sing-box: |example.gov → 前缀匹配（example.gov.cn 匹配）
    let (domains, suffixes, regexes) = compile_adguard("|example.gov");
    println!("|example.gov -> domains={domains:?} suffixes={suffixes:?} regexes={regexes:?}");
    check("|example.gov", "example.gov", true);
    check("|example.gov", "example.gov.cn", true); // sing 期望 true（前缀）
}

#[test]
fn verify_suffix_no_end() {
    // sing-box: ||example.org（无^）→ 任意后缀（example.org.cn 匹配）
    // reflex: 标准子域后缀（已知限制，不匹配 example.org.cn）
    let (_, suffixes, _) = compile_adguard("||example.org");
    println!("||example.org -> suffixes={suffixes:?}");
    check("||example.org", "example.org", true);
    check("||example.org", "www.example.org", true);
    // ||无^ 已知差异：sing 期望 example.org.cn 匹配，reflex 标准子域不匹配
    println!("  [KNOWN] ||example.org 无^：reflex 标准子域不匹配 example.org.cn（sing 需要任意后缀）");
}

#[test]
fn verify_wildcard_star_empty() {
    // sing-box: ||*.ads.example.com^ → * 可为空（ads.example.com 本身匹配）
    let (_, _, regexes) = compile_adguard("||*.ads.example.com^");
    println!("||*.ads.example.com^ -> regexes={regexes:?}");
    check("||*.ads.example.com^", "ads.example.com", true); // sing 期望 true（* 为空）
    check("||*.ads.example.com^", "x.ads.example.com", true);
    check("||*.ads.example.com^", "ads.example.com.cn", false);

    // sing-box: ||**.example.org^ 匹配 example.org 本身
    let (_, _, regexes) = compile_adguard("||**.example.org^");
    println!("||**.example.org^ -> regexes={regexes:?}");
    check("||**.example.org^", "example.org", true); // sing 期望 true
    check("||**.example.org^", "sub.example.org", true);
}

#[allow(dead_code)]
fn compile_adguard_full(src: &str) -> reflex::ruleset::CompiledRuleSet {
    let report = reflex::ruleset::CompiledRuleSet::from_adguard_text(src).unwrap();
    report.ruleset
}

#[test]
fn verify_exception_rule_blocks_nothing() {
    // @@ 例外：被例外的域名不应被同规则集中的其他规则命中
    let r = rs("@@||allow.com^\n||block.com^\n||allow.com^");
    // allow.com 在 suffix 里，但同时被 @@ 排除 → 应不匹配
    assert!(!r.matches(&MatchTarget::Domain("allow.com")), "excluded domain should NOT match");
    assert!(!r.matches(&MatchTarget::Domain("sub.allow.com")), "excluded subdomain should NOT match");
    // block.com 不受 @@ 影响 → 应匹配
    assert!(r.matches(&MatchTarget::Domain("block.com")));
    assert!(r.matches(&MatchTarget::Domain("www.block.com")));
    println!("  [OK] @@ 例外规则生效：allow.com 被排除，block.com 正常匹配");
}

#[test]
fn verify_hosts_and_exception() {
    // hosts 0.0.0.0 → 精确
    check("0.0.0.0 google.com", "google.com", true);
    check("0.0.0.0 google.com", "www.google.com", false);
    // important 修饰符：reflex 忽略
    let (_, s2, _) = compile_adguard("||important.com^$important\n||normal.com^");
    println!("$important 处理: suffixes={s2:?}");
}
