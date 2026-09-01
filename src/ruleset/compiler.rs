use std::{
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use fst::SetBuilder;
use regex::Regex;
use serde::Deserialize;

use super::{
    error::{Result, RuleSetError},
    format::*,
};

/// 编译后的中间表示，按 section 类型分组
#[derive(Debug, Default)]
pub struct CompiledRuleSet {
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ipv4_cidrs: Vec<(Ipv4Addr, u8)>,
    pub ipv6_cidrs: Vec<(Ipv6Addr, u8)>,
    /// 端口范围 (start, end)，单端口则 start == end
    pub ports: Vec<(u16, u16)>,
    /// 例外（@@）精确域名
    pub exclude_domains: Vec<String>,
    /// 例外（@@）域名后缀
    pub exclude_domain_suffixes: Vec<String>,
    /// 例外（@@）域名正则
    pub exclude_domain_regexes: Vec<String>,
}

impl CompiledRuleSet {
    /// 从文本内容编译
    pub fn from_text(src: &str) -> Result<Self> {
        let mut out = Self::default();

        for (lineno, raw) in src.lines().enumerate() {
            let line = lineno + 1;
            let trimmed = raw.trim();

            // 跳过空行和注释
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // 分割 key: value
            let (key, value) = trimmed
                .split_once(':')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| RuleSetError::ParseError {
                    line,
                    msg: format!("expected 'key: value', got '{trimmed}'"),
                })?;

            match key {
                "domain" => {
                    validate_domain_len(value, line)?;
                    out.domains.push(value.to_ascii_lowercase());
                }
                "domain-suffix" => {
                    // strip 前导点和末尾点：
                    //   - 前导 '.' 在 mihomo 语义中等价于无 '.' (suffix 本身就含自身)
                    //   - 末尾 '.' 是 FQDN 写法，与无 '.' 等价
                    // 这样 "google.com." 和 "google.com" 编码后产生相同的 FST key
                    let v = value.trim_matches('.');
                    validate_domain_len(v, line)?;
                    out.domain_suffixes.push(v.to_ascii_lowercase());
                }
                "domain-keyword" => {
                    out.domain_keywords.push(value.to_ascii_lowercase());
                }
                "domain-regex" => {
                    // 验证正则合法性
                    Regex::new(value).map_err(|e| {
                        RuleSetError::InvalidRegex(value.to_string(), e.to_string())
                    })?;
                    out.domain_regexes.push(value.to_string());
                }
                "ip-cidr" => {
                    let (addr, prefix) = parse_ipv4_cidr(value)?;
                    out.ipv4_cidrs.push((addr, prefix));
                }
                "ip-cidr6" => {
                    let (addr, prefix) = parse_ipv6_cidr(value)?;
                    out.ipv6_cidrs.push((addr, prefix));
                }
                "port" => {
                    let range = parse_port_range(value)?;
                    out.ports.push(range);
                }
                other => {
                    return Err(RuleSetError::ParseError {
                        line,
                        msg: format!("unknown rule type '{other}'"),
                    });
                }
            }
        }

        Ok(out)
    }

    /// 序列化为二进制格式，写入 writer（v2：domain/suffix 用 FST）
    pub fn serialize<W: Write>(&self, w: &mut W) -> Result<()> {
        // 构建 domain FST（精确匹配，key = 倒序 label，如 "com.google"）
        let domain_fst = build_domain_fst(&self.domains)?;
        // 构建 suffix FST（后缀匹配，key = 倒序 label + 尾部 "."，如 "com.google."）
        let suffix_fst = build_suffix_fst(&self.domain_suffixes)?;
        // 构建例外 domain FST
        let exclude_domain_fst = build_domain_fst(&self.exclude_domains)?;
        // 构建例外 suffix FST
        let exclude_suffix_fst = build_suffix_fst(&self.exclude_domain_suffixes)?;

        // 收集非空 sections
        let sections: Vec<(SectionType, Vec<u8>)> = [
            (SectionType::DomainFst, domain_fst),
            (SectionType::DomainSuffixFst, suffix_fst),
            (SectionType::ExcludeDomainFst, exclude_domain_fst),
            (SectionType::ExcludeSuffixFst, exclude_suffix_fst),
            (
                SectionType::DomainKeyword,
                encode_strings(&self.domain_keywords),
            ),
            (
                SectionType::DomainRegex,
                encode_strings(&self.domain_regexes),
            ),
            (
                SectionType::ExcludeDomainRegex,
                encode_strings(&self.exclude_domain_regexes),
            ),
            (SectionType::IpCidrV4, encode_ipv4_cidrs(&self.ipv4_cidrs)),
            (SectionType::IpCidrV6, encode_ipv6_cidrs(&self.ipv6_cidrs)),
            (SectionType::Port, encode_ports(&self.ports)),
        ]
        .into_iter()
        .filter(|(_, data)| !data.is_empty())
        .collect();

        // ── 文件头 ────────────────────────────────────────────
        w.write_all(&MAGIC)?; // 4
        w.write_all(&[VERSION])?; // 1
        w.write_all(&[0x00])?; // flags 1
        w.write_all(&(sections.len() as u32).to_le_bytes())?; // 4
        w.write_all(&[0x00; 4])?; // reserved 4

        // ── Sections ──────────────────────────────────────────
        for (sec_type, data) in &sections {
            let entry_count = entry_count_for(sec_type, data);
            w.write_all(&[*sec_type as u8])?; // type 1
            w.write_all(&(entry_count as u32).to_le_bytes())?; // count 4
            w.write_all(&(data.len() as u32).to_le_bytes())?; // byte_len 4
            w.write_all(data)?; // data N
        }

        Ok(())
    }

    pub fn total_entries(&self) -> usize {
        self.domains.len()
            + self.domain_suffixes.len()
            + self.domain_keywords.len()
            + self.domain_regexes.len()
            + self.ipv4_cidrs.len()
            + self.ipv6_cidrs.len()
            + self.ports.len()
            + self.exclude_domains.len()
            + self.exclude_domain_suffixes.len()
            + self.exclude_domain_regexes.len()
    }

    /// 从 sing-box Source Rule Set JSON 内容编译
    ///
    /// 支持 sing-box `rule_set` 的 JSON 格式（version 1 和 2），
    /// 自动将 sing-box 的字段名映射到本规则集格式：
    /// - `domain`         → domain（精确匹配）
    /// - `domain_suffix`  → domain-suffix（后缀匹配，去掉前导点）
    /// - `domain_keyword` → domain-keyword
    /// - `domain_regex`   → domain-regex
    /// - `ip_cidr`        → ip-cidr / ip-cidr6（自动识别 v4/v6）
    /// - `port`           → port（单端口）
    /// - `port_range`     → port（sing-box 用 "start:end" 格式，自动转换）
    ///
    /// # 内存优化
    ///
    /// 顶层先把 `rules` 数组解析为 `Vec<serde_json::Value>`（每条 rule 是一个
    /// JSON 值），然后逐条转换为 `SingBoxRule` 处理后立即 drop。
    /// 相比旧版全量反序列化为 `Vec<SingBoxRule>`，峰值内存减少约一半：
    /// 旧：JSON原文 + Vec\<SingBoxRule\>(全量) + CompiledRuleSet
    /// 新：JSON原文 + Vec\<Value\>(全量，但比SingBoxRule紧凑) + 单条SingBoxRule + CompiledRuleSet
    pub fn from_singbox_json(src: &str) -> Result<Self> {
        let envelope: SingBoxEnvelope =
            serde_json::from_str(src).map_err(|e| RuleSetError::ParseError {
                line: 0,
                msg: format!("sing-box JSON 解析失败: {e}"),
            })?;

        let mut out = Self::default();

        for raw_rule in envelope.rules {
            // 逐条从 Value 转换为 SingBoxRule，处理完即 drop
            let rule: SingBoxRule =
                serde_json::from_value(raw_rule).map_err(|e| RuleSetError::ParseError {
                    line: 0,
                    msg: format!("sing-box rule 解析失败: {e}"),
                })?;
            out.ingest_singbox_rule(rule)?;
            // rule dropped here
        }

        Ok(out)
    }

    /// 将一条 sing-box rule 的字段合并入 self（含嵌套子规则）
    fn ingest_singbox_rule(&mut self, rule: SingBoxRule) -> Result<()> {
        // logical_and / logical_or 嵌套子规则：逐条转换处理，立即 drop
        for raw_sub in rule.sub_rules {
            let sub: SingBoxRule =
                serde_json::from_value(raw_sub).map_err(|e| RuleSetError::ParseError {
                    line: 0,
                    msg: format!("sing-box sub-rule 解析失败: {e}"),
                })?;
            self.ingest_singbox_rule(sub)?;
            // sub dropped here
        }

        // domain（精确）
        for d in &rule.domain {
            let lower = d.trim().to_ascii_lowercase();
            validate_domain_len(&lower, 0)?;
            self.domains.push(lower);
        }

        // domain_suffix（strip 前导点和末尾点后存储，原因见 from_text）
        for d in &rule.domain_suffix {
            let v = d.trim().trim_matches('.').to_ascii_lowercase();
            validate_domain_len(&v, 0)?;
            self.domain_suffixes.push(v);
        }

        // domain_keyword
        for k in &rule.domain_keyword {
            self.domain_keywords.push(k.trim().to_ascii_lowercase());
        }

        // domain_regex
        for r in &rule.domain_regex {
            Regex::new(r).map_err(|e| RuleSetError::InvalidRegex(r.clone(), e.to_string()))?;
            self.domain_regexes.push(r.clone());
        }

        // ip_cidr（自动区分 v4 / v6）
        for cidr in &rule.ip_cidr {
            let cidr = cidr.trim();
            if cidr.contains(':') {
                let (addr, prefix) = parse_ipv6_cidr(cidr)?;
                self.ipv6_cidrs.push((addr, prefix));
            } else {
                let (addr, prefix) = parse_ipv4_cidr(cidr)?;
                self.ipv4_cidrs.push((addr, prefix));
            }
        }

        // port（单端口整数列表）
        for &p in &rule.port {
            self.ports.push((p, p));
        }

        // port_range（sing-box 格式："start:end"，冒号分隔）
        for pr in &rule.port_range {
            let range = parse_singbox_port_range(pr)?;
            self.ports.push(range);
        }

        Ok(())
    }

    /// 从 mihomo / Clash 规则集 yaml 文本编译。
    ///
    /// 输入为 mihomo `rule-providers` 中 `format: yaml` 的标准格式：
    /// ```yaml
    /// payload:
    ///   - '+.google.com'
    ///   - 'google.com'
    ///   - '.github.com'
    ///   - '*.example.com'
    ///   - '192.168.0.0/16'
    ///   - 'geosite:cn'      # 跳过
    ///   - 'geoip:cn'        # 跳过
    ///   - 'DOMAIN-SUFFIX,example.com'   # classical 行
    ///   - 'IP-CIDR,10.0.0.0/8,no-resolve'
    /// ```
    ///
    /// # behavior 参数
    ///
    /// 与 mihomo 一致，由调用方根据 `rule-providers` 配置项的 `behavior`
    /// 字段传入，决定如何解释每一条 payload：
    ///
    /// - `"domain"`：所有条目按域名处理，`+.foo.com` / `*.foo.com` / `.foo.com`
    ///   统一规约成"foo.com 自身 + 所有子域名"，写入 `domain_suffixes`。
    ///   纯字符串 `foo.com` 在 mihomo domain 行为下也匹配子域名，同样写入 suffix。
    /// - `"ipcidr"`：所有条目按 IP CIDR 处理。
    /// - `"classical"`：每条按完整 Clash 规则行解析，支持
    ///   `DOMAIN,foo.com` / `DOMAIN-SUFFIX,bar.com` / `IP-CIDR,1.2.3.0/24,no-resolve`
    ///   等格式（adapter 列忽略）。
    /// - `None`（推荐）：每条自动判别。无法判别的纯字符串默认当 domain-suffix，
    ///   与 mihomo `behavior: domain` 的实际行为一致。
    ///
    /// # 与 mihomo 的差异
    ///
    /// reflex 的 `CompiledRuleSet` 是"多类型并集匹配"，没有 `+.foo.com` 和
    /// `*.foo.com` 的严格区分（前者含自身，后者不含自身），这里统一近似为
    /// "含自身与所有子域名"，写入 `domain_suffixes`。如需精确区分，应在
    /// classical 模式下显式写出 `DOMAIN` / `DOMAIN-SUFFIX` 行。
    pub fn from_mihomo_yaml(src: &str, behavior: Option<&str>) -> Result<Self> {
        // 顶层 envelope：只解析 payload 字段，其余忽略。
        #[derive(Deserialize)]
        struct MihomoEnvelope {
            #[serde(default)]
            payload: Vec<serde_yaml::Value>,
        }

        let envelope: MihomoEnvelope =
            serde_yaml::from_str(src).map_err(|e| RuleSetError::ParseError {
                line: 0,
                msg: format!("mihomo yaml 解析失败: {e}"),
            })?;

        let mut out = Self::default();
        let bh = behavior.map(|s| s.to_ascii_lowercase());
        for (idx, raw) in envelope.payload.iter().enumerate() {
            // mihomo payload 元素允许是字符串或整数（端口/CIDR 写成裸数字）
            let entry = match raw.as_str() {
                Some(s) => s.trim().to_string(),
                None => serde_yaml::to_string(raw)
                    .map(|s| s.trim().trim_end_matches('\n').to_string())
                    .unwrap_or_default(),
            };
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            out.ingest_mihomo_entry(&entry, idx, bh.as_deref())?;
        }
        Ok(out)
    }

    /// 把一条 mihomo payload 条目并入 self。
    ///
    /// 自动判别（`behavior = None`）按下列优先级处理：
    /// 1. 以 `<TYPE>,payload[,adapter[,extra]]` 形式开头且 TYPE 是已知 Clash
    ///    规则类型 → 按 classical 规则行解析。
    /// 2. 形如 `geosite:` / `geoip:` / `rule-set:` / `match:` 等带冒号前缀
    ///    的"内部引用" → 跳过。
    /// 3. 含 `/` 且能解析为 IpNet → IP CIDR。
    /// 4. 以 `+.` / `*.` / `.` 开头 → suffix（含自身与所有子域名）。
    /// 5. 纯字符串 → suffix。
    fn ingest_mihomo_entry(
        &mut self,
        entry: &str,
        idx: usize,
        behavior: Option<&str>,
    ) -> Result<()> {
        match behavior {
            Some("domain") => {
                self.push_mihomo_domain_entry(entry, idx)?;
            }
            Some("ipcidr") | Some("ip-cidr") => {
                self.push_mihomo_ipcidr_entry(entry, idx)?;
            }
            Some("classical") => {
                self.push_mihomo_classical_entry(entry, idx)?;
            }
            // None 或未知：自动判别
            _ => {
                if looks_like_classical_rule(entry) {
                    self.push_mihomo_classical_entry(entry, idx)?;
                } else if is_internal_reference(entry) {
                    // 跳过 geosite:/geoip:/rule-set:/match: 等内部引用
                } else if let Some(parsed) = try_parse_cidr(entry) {
                    match parsed {
                        ParsedCidr::V4(addr, prefix) => self.ipv4_cidrs.push((addr, prefix)),
                        ParsedCidr::V6(addr, prefix) => self.ipv6_cidrs.push((addr, prefix)),
                    }
                } else {
                    self.push_mihomo_domain_entry(entry, idx)?;
                }
            }
        }
        Ok(())
    }

    /// 把一条域名条目并入 self。
    ///
    /// - `+.foo.com` / `*.foo.com` / `.foo.com` → suffix（含自身与所有子域名）
    /// - `foo.com` → 在 mihomo domain 行为下也匹配子域名，按 suffix 处理
    fn push_mihomo_domain_entry(&mut self, entry: &str, idx: usize) -> Result<()> {
        let mut s = entry.trim();
        // 去掉前缀通配符
        if let Some(rest) = s
            .strip_prefix("+.")
            .or_else(|| s.strip_prefix("*."))
            .or_else(|| s.strip_prefix("."))
        {
            s = rest;
        }
        if s.is_empty() {
            return Err(RuleSetError::ParseError {
                line: idx + 1,
                msg: format!("empty domain after stripping prefix: '{entry}'"),
            });
        }
        let lower = s.to_ascii_lowercase();
        validate_domain_len(&lower, idx + 1)?;
        // 写入 suffix（含自身与所有子域名）；与 reflex `domain-suffix` 语义一致
        self.domain_suffixes.push(lower);
        Ok(())
    }

    /// 把一条 IP CIDR 条目并入 self（自动识别 v4/v6）。
    fn push_mihomo_ipcidr_entry(&mut self, entry: &str, idx: usize) -> Result<()> {
        let entry = entry.trim();
        if let Some(parsed) = try_parse_cidr(entry) {
            match parsed {
                ParsedCidr::V4(addr, prefix) => self.ipv4_cidrs.push((addr, prefix)),
                ParsedCidr::V6(addr, prefix) => self.ipv6_cidrs.push((addr, prefix)),
            }
            Ok(())
        } else {
            Err(RuleSetError::ParseError {
                line: idx + 1,
                msg: format!("not a valid IP CIDR: '{entry}'"),
            })
        }
    }

    /// 解析一条 classical 风格规则行：`TYPE,payload[,adapter[,extra]]`。
    ///
    /// adapter 列忽略（reflex CompiledRuleSet 不存 adapter）。
    /// `no-resolve` / `src` 等修饰符对 reflex 并集匹配无意义，也忽略。
    fn push_mihomo_classical_entry(&mut self, entry: &str, idx: usize) -> Result<()> {
        let parts: Vec<&str> = entry.splitn(4, ',').map(|p| p.trim()).collect();
        if parts.len() < 2 {
            return Err(RuleSetError::ParseError {
                line: idx + 1,
                msg: format!("classical rule needs at least TYPE,payload: '{entry}'"),
            });
        }
        let ty = parts[0].to_ascii_uppercase();
        let payload = parts[1];
        match ty.as_str() {
            "DOMAIN" => {
                let lower = payload.to_ascii_lowercase();
                validate_domain_len(&lower, idx + 1)?;
                self.domains.push(lower);
            }
            "DOMAIN-SUFFIX" => {
                let v = payload.trim_matches('.').to_ascii_lowercase();
                validate_domain_len(&v, idx + 1)?;
                self.domain_suffixes.push(v);
            }
            "DOMAIN-KEYWORD" => {
                self.domain_keywords.push(payload.to_ascii_lowercase());
            }
            "DOMAIN-REGEX" | "DOMAIN-REG" => {
                Regex::new(payload)
                    .map_err(|e| RuleSetError::InvalidRegex(payload.to_string(), e.to_string()))?;
                self.domain_regexes.push(payload.to_string());
            }
            "IP-CIDR" | "IP-CIDR6" => {
                self.push_mihomo_ipcidr_entry(payload, idx + 1)?;
            }
            "PORT" => {
                let range = parse_port_range(payload)
                    .map_err(|_| RuleSetError::InvalidPort(payload.to_string()))?;
                self.ports.push(range);
            }
            // 其他类型（PROCESS-NAME / GEOIP / GEOSITE / SRC-IP-CIDR / etc）
            // reflex 不支持，跳过。比起 fail-fast，跳过更接近 mihomo 的"宽松处理"。
            _ => {}
        }
        Ok(())
    }
}

// ── 编码辅助 ─────────────────────────────────────────────────────────────────

/// 字符串列表编码：每条 1byte(len) + N bytes(utf8)
fn encode_strings(list: &[String]) -> Vec<u8> {
    if list.is_empty() {
        return vec![];
    }
    let mut buf = Vec::new();
    for s in list {
        buf.push(s.len() as u8);
        buf.extend_from_slice(s.as_bytes());
    }
    buf
}

fn encode_ipv4_cidrs(list: &[(Ipv4Addr, u8)]) -> Vec<u8> {
    if list.is_empty() {
        return vec![];
    }
    let mut buf = Vec::with_capacity(list.len() * IPV4_ENTRY_LEN);
    for (addr, prefix) in list {
        buf.extend_from_slice(&addr.octets());
        buf.push(*prefix);
    }
    buf
}

fn encode_ipv6_cidrs(list: &[(Ipv6Addr, u8)]) -> Vec<u8> {
    if list.is_empty() {
        return vec![];
    }
    let mut buf = Vec::with_capacity(list.len() * IPV6_ENTRY_LEN);
    for (addr, prefix) in list {
        buf.extend_from_slice(&addr.octets());
        buf.push(*prefix);
    }
    buf
}

fn encode_ports(list: &[(u16, u16)]) -> Vec<u8> {
    if list.is_empty() {
        return vec![];
    }
    let mut buf = Vec::with_capacity(list.len() * PORT_ENTRY_LEN);
    for (start, end) in list {
        buf.extend_from_slice(&start.to_le_bytes());
        buf.extend_from_slice(&end.to_le_bytes());
    }
    buf
}

/// 根据 section 类型和原始数据字节算出 entry 数量
fn entry_count_for(sec_type: &SectionType, data: &[u8]) -> usize {
    match sec_type {
        SectionType::IpCidrV4 => data.len() / IPV4_ENTRY_LEN,
        SectionType::IpCidrV6 => data.len() / IPV6_ENTRY_LEN,
        SectionType::Port => data.len() / PORT_ENTRY_LEN,
        // 字符串类型需要扫描计数（len-prefixed）
        _ => {
            let mut count = 0;
            let mut i = 0;
            while i < data.len() {
                let len = data[i] as usize;
                i += 1 + len;
                count += 1;
            }
            count
        }
    }
}

// ── 解析辅助 ─────────────────────────────────────────────────────────────────

fn validate_domain_len(domain: &str, line: usize) -> Result<()> {
    if domain.len() > 255 {
        return Err(RuleSetError::ParseError {
            line,
            msg: format!("domain too long ({}): '{}'", domain.len(), domain),
        });
    }
    Ok(())
}

fn parse_ipv4_cidr(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| RuleSetError::InvalidCidr(s.to_string(), "missing '/'".into()))?;

    let addr = Ipv4Addr::from_str(addr_str)
        .map_err(|e| RuleSetError::InvalidCidr(s.to_string(), e.to_string()))?;

    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| RuleSetError::InvalidCidr(s.to_string(), "invalid prefix length".into()))?;

    if prefix > 32 {
        return Err(RuleSetError::InvalidCidr(
            s.to_string(),
            "IPv4 prefix must be 0–32".into(),
        ));
    }

    // 网络地址规范化：清零主机位
    let addr = mask_ipv4(addr, prefix);
    Ok((addr, prefix))
}

fn parse_ipv6_cidr(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| RuleSetError::InvalidCidr(s.to_string(), "missing '/'".into()))?;

    let addr = Ipv6Addr::from_str(addr_str)
        .map_err(|e| RuleSetError::InvalidCidr(s.to_string(), e.to_string()))?;

    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| RuleSetError::InvalidCidr(s.to_string(), "invalid prefix length".into()))?;

    if prefix > 128 {
        return Err(RuleSetError::InvalidCidr(
            s.to_string(),
            "IPv6 prefix must be 0–128".into(),
        ));
    }

    let addr = mask_ipv6(addr, prefix);
    Ok((addr, prefix))
}

fn parse_port_range(s: &str) -> Result<(u16, u16)> {
    if let Some((start_s, end_s)) = s.split_once('-') {
        let start: u16 = start_s
            .trim()
            .parse()
            .map_err(|_| RuleSetError::InvalidPort(s.to_string()))?;
        let end: u16 = end_s
            .trim()
            .parse()
            .map_err(|_| RuleSetError::InvalidPort(s.to_string()))?;
        if start > end {
            return Err(RuleSetError::InvalidPort(s.to_string()));
        }
        Ok((start, end))
    } else {
        let port: u16 = s
            .trim()
            .parse()
            .map_err(|_| RuleSetError::InvalidPort(s.to_string()))?;
        Ok((port, port))
    }
}

fn mask_ipv4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::from(0u32);
    }
    let mask = !0u32 << (32 - prefix);
    Ipv4Addr::from(u32::from(addr) & mask)
}

fn mask_ipv6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::from(0u128);
    }
    let mask = !0u128 << (128 - prefix);
    Ipv6Addr::from(u128::from(addr) & mask)
}

// ── sing-box JSON 数据结构 ────────────────────────────────────────────────────

/// 顶层信封：只保留 version 和 rules 数组。
///
/// rules 中每个元素是 `serde_json::Value`（已解析的 JSON 值），
/// 但不会进一步反序列化为 `SingBoxRule`——那步留给 `from_singbox_json`
/// 逐条完成，处理完一条立即 drop，避免所有 rule 同时驻留内存。
#[derive(Debug, Deserialize)]
struct SingBoxEnvelope {
    #[allow(dead_code)]
    version: Option<u32>,
    /// 每条 rule 以 Value 存储，逐条取出后再反序列化为 SingBoxRule
    #[serde(default)]
    rules: Vec<serde_json::Value>,
}

/// sing-box 单条规则（字段之间为 OR）。
///
/// sub_rules 用 `Vec<Value>` 延迟解析，避免一次性展开整棵嵌套树。
///
/// meta-rules-dat 中部分文件将字段写成裸字符串而非数组，例如：
///   `"domain_suffix": "zotero.org"` 而不是 `"domain_suffix": ["zotero.org"]`
/// `string_or_vec` 同时兼容两种写法。
#[derive(Debug, Deserialize, Default)]
struct SingBoxRule {
    #[serde(default, deserialize_with = "string_or_vec")]
    domain: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    domain_suffix: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    domain_keyword: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    domain_regex: Vec<String>,
    #[serde(default, deserialize_with = "string_or_vec")]
    ip_cidr: Vec<String>,
    #[serde(default)]
    port: Vec<u16>,
    #[serde(default, deserialize_with = "string_or_vec")]
    port_range: Vec<String>,
    /// logical_and / logical_or 嵌套子规则，逐条按需反序列化
    #[serde(rename = "rules", default)]
    sub_rules: Vec<serde_json::Value>,
}

/// 兼容 sing-box JSON 里字段值为裸字符串或字符串数组两种写法：
///   `"domain_suffix": "example.com"`        → vec!["example.com"]
///   `"domain_suffix": ["a.com", "b.com"]`   → vec!["a.com", "b.com"]
fn string_or_vec<'de, D>(de: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{SeqAccess, Visitor};
    use std::fmt;

    struct StringOrVec;

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or array of strings")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_string<E: serde::de::Error>(
            self,
            v: String,
        ) -> std::result::Result<Self::Value, E> {
            Ok(vec![v])
        }

        fn visit_seq<A: SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Self::Value, A::Error> {
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    de.deserialize_any(StringOrVec)
}

/// 解析 sing-box 端口范围字符串，格式为 "start:end"（冒号分隔）
fn parse_singbox_port_range(s: &str) -> Result<(u16, u16)> {
    if let Some((start_s, end_s)) = s.split_once(':') {
        let start: u16 = start_s
            .trim()
            .parse()
            .map_err(|_| RuleSetError::InvalidPort(s.to_string()))?;
        let end: u16 = end_s
            .trim()
            .parse()
            .map_err(|_| RuleSetError::InvalidPort(s.to_string()))?;
        if start > end {
            return Err(RuleSetError::InvalidPort(s.to_string()));
        }
        Ok((start, end))
    } else {
        // 也兼容 "start-end" 连字符格式
        parse_port_range(s)
    }
}

// ── FST 构建辅助 ──────────────────────────────────────────────────────────────

/// 将域名转为 FST key（倒序 label 拼接，点分隔）
/// "www.google.com" → "com.google.www"
pub fn domain_to_fst_key(domain: &str) -> String {
    let mut labels: Vec<&str> = domain.split('.').collect();
    labels.reverse();
    labels.join(".")
}

/// 将域名转为 suffix FST key（倒序 label + 尾部点）
/// "google.com" → "com.google."
/// 查询时 "sub.google.com" → "com.google.sub"，检查前缀 "com.google." 是否存在即可
pub fn suffix_to_fst_key(domain: &str) -> String {
    let mut labels: Vec<&str> = domain.split('.').collect();
    labels.reverse();
    let mut key = labels.join(".");
    key.push('.');
    key
}

/// 构建精确域名 FST，返回序列化字节
/// FST 要求 key 按字典序插入，这里排序后构建
pub(super) fn build_domain_fst(domains: &[String]) -> Result<Vec<u8>> {
    if domains.is_empty() {
        return Ok(vec![]);
    }
    let mut keys: Vec<String> = domains.iter().map(|d| domain_to_fst_key(d)).collect();
    keys.sort_unstable();
    keys.dedup();

    let mut buf = Vec::new();
    let mut builder = SetBuilder::new(&mut buf).map_err(|e| RuleSetError::ParseError {
        line: 0,
        msg: e.to_string(),
    })?;
    for key in &keys {
        builder
            .insert(key.as_bytes())
            .map_err(|e| RuleSetError::ParseError {
                line: 0,
                msg: e.to_string(),
            })?;
    }
    builder.finish().map_err(|e| RuleSetError::ParseError {
        line: 0,
        msg: e.to_string(),
    })?;
    Ok(buf)
}

/// 构建后缀域名 FST，返回序列化字节
pub(super) fn build_suffix_fst(suffixes: &[String]) -> Result<Vec<u8>> {
    if suffixes.is_empty() {
        return Ok(vec![]);
    }
    let mut keys: Vec<String> = suffixes.iter().map(|d| suffix_to_fst_key(d)).collect();
    keys.sort_unstable();
    keys.dedup();

    let mut buf = Vec::new();
    let mut builder = SetBuilder::new(&mut buf).map_err(|e| RuleSetError::ParseError {
        line: 0,
        msg: e.to_string(),
    })?;
    for key in &keys {
        builder
            .insert(key.as_bytes())
            .map_err(|e| RuleSetError::ParseError {
                line: 0,
                msg: e.to_string(),
            })?;
    }
    builder.finish().map_err(|e| RuleSetError::ParseError {
        line: 0,
        msg: e.to_string(),
    })?;
    Ok(buf)
}

// ── mihomo yaml 辅助 ─────────────────────────────────────────────────────────

/// `try_parse_cidr` 的返回值：区分 IPv4 与 IPv6。
enum ParsedCidr {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

/// 尝试把字符串解析为 IP CIDR（v4 或 v6）。失败返回 `None`。
///
/// 与 `parse_ipv4_cidr` / `parse_ipv6_cidr` 的区别：
/// 后两者在失败时返回 `Err`，本函数返回 `Option`，便于在自动判别流程
/// 中作为"是否是 CIDR"的探测函数使用。
fn try_parse_cidr(s: &str) -> Option<ParsedCidr> {
    let (addr_str, prefix_str) = s.split_once('/')?;
    if let Ok(addr) = Ipv4Addr::from_str(addr_str) {
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        return Some(ParsedCidr::V4(mask_ipv4(addr, prefix), prefix));
    }
    if let Ok(addr) = Ipv6Addr::from_str(addr_str) {
        let prefix: u8 = prefix_str.parse().ok()?;
        if prefix > 128 {
            return None;
        }
        return Some(ParsedCidr::V6(mask_ipv6(addr, prefix), prefix));
    }
    None
}

/// 判断字符串是否形如 `<TYPE>,payload,...`，其中 TYPE 是已知 Clash 规则类型。
///
/// 仅做形式判断，不校验 payload；TYPE 大小写不敏感。
fn looks_like_classical_rule(s: &str) -> bool {
    let Some((ty, _)) = s.split_once(',') else {
        return false;
    };
    let ty = ty.trim().to_ascii_uppercase();
    matches!(
        ty.as_str(),
        "DOMAIN"
            | "DOMAIN-SUFFIX"
            | "DOMAIN-KEYWORD"
            | "DOMAIN-REGEX"
            | "DOMAIN-REG"
            | "IP-CIDR"
            | "IP-CIDR6"
            | "SRC-IP-CIDR"
            | "SRC-PORT"
            | "DST-PORT"
            | "PORT"
            | "PROCESS-NAME"
            | "PROCESS-PATH"
            | "GEOIP"
            | "GEOSITE"
            | "SRC-GEOIP"
            | "IP-ASN"
            | "RULE-SET"
            | "SUB-RULE"
            | "MATCH"
            | "NETWORK"
            | "IN-PORT"
            | "IN-TYPE"
            | "IN-USER"
            | "IN-NAME"
            | "DSCP"
            | "UID"
    )
}

/// 判断字符串是否是 mihomo 内部引用形式：`geosite:xxx` / `geoip:xxx` 等。
///
/// 这些条目在 reflex 中无法直接消费，加载时跳过。
fn is_internal_reference(s: &str) -> bool {
    let s = s.trim();
    matches!(
        s.split(':')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase()
            .as_str(),
        "geosite" | "geoip" | "rule-set" | "ruleset" | "match" | "subnet"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# 测试规则集
domain:         example.com
domain-suffix:  google.com
domain-suffix:  .github.com
domain-keyword: ads
domain-regex:   ^tracker\d+\.
ip-cidr:        192.168.0.0/16
ip-cidr:        10.0.0.0/8
ip-cidr6:       2001:db8::/32
port:           80
port:           8000-9000
"#;

    #[test]
    fn parse_sample() {
        let rs = CompiledRuleSet::from_text(SAMPLE).unwrap();
        assert_eq!(rs.domains, vec!["example.com"]);
        assert_eq!(rs.domain_suffixes, vec!["google.com", "github.com"]);
        assert_eq!(rs.domain_keywords, vec!["ads"]);
        assert_eq!(rs.domain_regexes, vec!["^tracker\\d+\\."]);
        assert_eq!(rs.ipv4_cidrs.len(), 2);
        assert_eq!(rs.ipv6_cidrs.len(), 1);
        assert_eq!(rs.ports, vec![(80, 80), (8000, 9000)]);
    }

    /// 验证 suffix 末尾点被正确 strip：
    /// `domain-suffix: "google.com."` 在 mihomo/sing-box 语义下
    /// 与 `domain-suffix: "google.com"` 完全等价。
    #[test]
    fn suffix_trailing_dot_normalized() {
        let src = "domain-suffix: google.com.\ndomain-suffix: github.com\n";
        let rs = CompiledRuleSet::from_text(src).unwrap();
        assert_eq!(rs.domain_suffixes, vec!["google.com", "github.com"]);
    }

    /// 验证 sing-box domain_suffix 末尾点也被 strip。
    #[test]
    fn singbox_suffix_trailing_dot_normalized() {
        let src = r#"{"version":2,"rules":[{"domain_suffix":["google.com.","github.com"]}]}"#;
        let rs = CompiledRuleSet::from_singbox_json(src).unwrap();
        assert_eq!(rs.domain_suffixes, vec!["google.com", "github.com"]);
    }

    /// 验证 classical 行 `DOMAIN-SUFFIX,google.com.,PROXY` 末尾点也被 strip。
    #[test]
    fn classical_suffix_trailing_dot_normalized() {
        // 通过 mihomo yaml + behavior=classical 路径走 classical 行解析
        let src = "payload:\n  - 'DOMAIN-SUFFIX,google.com.,PROXY'\n";
        let rs = CompiledRuleSet::from_mihomo_yaml(src, Some("classical")).unwrap();
        assert_eq!(rs.domain_suffixes, vec!["google.com"]);
    }

    /// 端到端：带末尾点的 suffix 规则，匹配不带末尾点的查询域名应成功。
    #[test]
    fn suffix_trailing_dot_end_to_end() {
        use crate::ruleset::{LoadedRuleSet, MatchTarget, RuleSet};

        let src = "domain-suffix: google.com.\n";
        let compiled = CompiledRuleSet::from_text(src).unwrap();
        let mut buf = Vec::new();
        compiled.serialize(&mut buf).unwrap();
        let rs = RuleSet::from_loaded(LoadedRuleSet::from_bytes(&buf).unwrap()).unwrap();

        // 查询不带末尾点 → 应命中（修复前会失败）
        assert!(rs.matches(&MatchTarget::Domain("google.com")));
        assert!(rs.matches(&MatchTarget::Domain("www.google.com")));
        // 不应误中
        assert!(!rs.matches(&MatchTarget::Domain("notgoogle.com")));
    }

    #[test]
    fn ipv4_masking() {
        // 192.168.1.5/16 → 网络地址应规范化为 192.168.0.0
        let (addr, prefix) = parse_ipv4_cidr("192.168.1.5/16").unwrap();
        assert_eq!(addr, Ipv4Addr::new(192, 168, 0, 0));
        assert_eq!(prefix, 16);
    }

    #[test]
    fn serialize_roundtrip() {
        let rs = CompiledRuleSet::from_text(SAMPLE).unwrap();
        let mut buf = Vec::new();
        rs.serialize(&mut buf).unwrap();

        // 检查魔数和版本
        assert_eq!(&buf[0..4], b"RRST");
        assert_eq!(buf[4], VERSION);
    }

    #[test]
    fn invalid_cidr() {
        assert!(CompiledRuleSet::from_text("ip-cidr: 192.168.0.0/33").is_err());
        assert!(CompiledRuleSet::from_text("ip-cidr: notanip/24").is_err());
    }

    #[test]
    fn invalid_port() {
        assert!(CompiledRuleSet::from_text("port: 9000-8000").is_err());
        assert!(CompiledRuleSet::from_text("port: 99999").is_err());
    }

    #[test]
    fn singbox_json_basic() {
        let json = r#"{
            "version": 2,
            "rules": [
                {
                    "domain": ["example.com"],
                    "domain_suffix": [".google.com", "github.com"],
                    "domain_keyword": ["ads"],
                    "ip_cidr": ["192.168.0.0/16", "2001:db8::/32"],
                    "port": [80, 443],
                    "port_range": ["8000:9000"]
                }
            ]
        }"#;
        let rs = CompiledRuleSet::from_singbox_json(json).unwrap();
        assert_eq!(rs.domains, vec!["example.com"]);
        assert_eq!(rs.domain_suffixes, vec!["google.com", "github.com"]);
        assert_eq!(rs.domain_keywords, vec!["ads"]);
        assert_eq!(rs.ipv4_cidrs.len(), 1);
        assert_eq!(rs.ipv6_cidrs.len(), 1);
        assert_eq!(rs.ports, vec![(80, 80), (443, 443), (8000, 9000)]);
    }

    #[test]
    fn singbox_json_auto_v4_v6() {
        let json = r#"{"version":2,"rules":[{"ip_cidr":["10.0.0.0/8","::1/128"]}]}"#;
        let rs = CompiledRuleSet::from_singbox_json(json).unwrap();
        assert_eq!(rs.ipv4_cidrs.len(), 1);
        assert_eq!(rs.ipv6_cidrs.len(), 1);
    }

    #[test]
    fn singbox_json_empty_rules() {
        let json = r#"{"version":2,"rules":[]}"#;
        let rs = CompiledRuleSet::from_singbox_json(json).unwrap();
        assert_eq!(rs.total_entries(), 0);
    }

    #[test]
    fn singbox_json_invalid() {
        assert!(CompiledRuleSet::from_singbox_json("not json").is_err());
    }

    #[test]
    fn singbox_json_bare_string_fields() {
        // meta-rules-dat 中部分文件用裸字符串而非数组，两种写法都要能解析
        let json = r#"{
            "version": 2,
            "rules": [
                {
                    "domain_suffix": "zotero.org",
                    "domain": "example.com",
                    "domain_keyword": "ads",
                    "domain_regex": "^tracker\\d+\\."
                }
            ]
        }"#;
        let rs = CompiledRuleSet::from_singbox_json(json).unwrap();
        assert_eq!(rs.domain_suffixes, vec!["zotero.org"]);
        assert_eq!(rs.domains, vec!["example.com"]);
        assert_eq!(rs.domain_keywords, vec!["ads"]);
        assert_eq!(rs.domain_regexes, vec!["^tracker\\d+\\."]);
    }

    #[test]
    fn singbox_port_range_colon() {
        let json = r#"{"version":2,"rules":[{"port_range":["1000:2000"]}]}"#;
        let rs = CompiledRuleSet::from_singbox_json(json).unwrap();
        assert_eq!(rs.ports, vec![(1000, 2000)]);
    }

    // ── mihomo yaml 解析 ────────────────────────────────────────────────────

    const MIHOMO_DOMAIN_YAML: &str = r#"
payload:
  - '+.google.com'
  - 'google.com'
  - '.github.com'
  - '*.example.com'
  - 'example.com'
  - '#comment-like-but-yaml-quoted'
"#;

    const MIHOMO_IPCIDR_YAML: &str = r#"
payload:
  - '192.168.0.0/16'
  - '10.0.0.0/8'
  - '2001:db8::/32'
"#;

    const MIHOMO_CLASSICAL_YAML: &str = r#"
payload:
  - DOMAIN,example.com
  - DOMAIN-SUFFIX,google.com
  - DOMAIN-KEYWORD,ads
  - IP-CIDR,10.0.0.0/8,no-resolve
  - IP-CIDR6,2001:db8::/32
  - GEOIP,CN
  - PORT,8080
"#;

    #[test]
    fn mihomo_yaml_domain_behavior() {
        let rs = CompiledRuleSet::from_mihomo_yaml(MIHOMO_DOMAIN_YAML, Some("domain")).unwrap();
        // 所有条目都规约成 suffix（含自身与所有子域名）
        // 注：'#comment-like-but-yaml-quoted' 会被当域名处理，这是合理的宽松行为
        assert!(rs.domain_suffixes.contains(&"google.com".to_string()));
        assert!(rs.domain_suffixes.contains(&"github.com".to_string()));
        assert!(rs.domain_suffixes.contains(&"example.com".to_string()));
        assert_eq!(rs.ipv4_cidrs.len(), 0);
        assert_eq!(rs.ipv6_cidrs.len(), 0);
    }

    #[test]
    fn mihomo_yaml_ipcidr_behavior() {
        let rs = CompiledRuleSet::from_mihomo_yaml(MIHOMO_IPCIDR_YAML, Some("ipcidr")).unwrap();
        assert_eq!(rs.ipv4_cidrs.len(), 2);
        assert_eq!(rs.ipv6_cidrs.len(), 1);
        assert_eq!(rs.ipv4_cidrs[0], (Ipv4Addr::new(192, 168, 0, 0), 16));
        assert_eq!(rs.ipv4_cidrs[1], (Ipv4Addr::new(10, 0, 0, 0), 8));
        assert_eq!(rs.domain_suffixes.len(), 0);
    }

    #[test]
    fn mihomo_yaml_classical_behavior() {
        let rs =
            CompiledRuleSet::from_mihomo_yaml(MIHOMO_CLASSICAL_YAML, Some("classical")).unwrap();
        assert_eq!(rs.domains, vec!["example.com"]);
        assert_eq!(rs.domain_suffixes, vec!["google.com"]);
        assert_eq!(rs.domain_keywords, vec!["ads"]);
        assert_eq!(rs.ipv4_cidrs.len(), 1);
        assert_eq!(rs.ipv6_cidrs.len(), 1);
        // PORT 走 parse_port_range（用 `-` 分隔），裸端口 8080 当单端口
        assert_eq!(rs.ports, vec![(8080, 8080)]);
    }

    #[test]
    fn mihomo_yaml_auto_detect_mixed() {
        // 无 behavior 参数：每条按内容自动判别
        let yaml = r#"
payload:
  - '+.google.com'
  - '192.168.0.0/16'
  - '2001:db8::/32'
  - 'geosite:cn'
  - 'DOMAIN-SUFFIX,example.com'
  - 'IP-CIDR,10.0.0.0/8,no-resolve'
"#;
        let rs = CompiledRuleSet::from_mihomo_yaml(yaml, None).unwrap();
        assert!(rs.domain_suffixes.contains(&"google.com".to_string()));
        assert!(rs.domain_suffixes.contains(&"example.com".to_string()));
        assert_eq!(rs.ipv4_cidrs.len(), 2); // 192.168.0.0/16 + 10.0.0.0/8
        assert_eq!(rs.ipv6_cidrs.len(), 1); // 2001:db8::/32
    }

    #[test]
    fn mihomo_yaml_skips_internal_references() {
        let yaml = r#"
payload:
  - 'geosite:cn'
  - 'geoip:cn'
  - 'rule-set:my-set'
  - 'match:example.com'
  - 'example.com'
"#;
        let rs = CompiledRuleSet::from_mihomo_yaml(yaml, None).unwrap();
        // 只有 example.com 被当域名处理
        assert_eq!(rs.domain_suffixes.len(), 1);
        assert_eq!(rs.domain_suffixes[0], "example.com");
    }

    #[test]
    fn mihomo_yaml_strips_wildcard_prefixes() {
        let yaml = r#"
payload:
  - '+.a.com'
  - '*.b.com'
  - '.c.com'
"#;
        let rs = CompiledRuleSet::from_mihomo_yaml(yaml, Some("domain")).unwrap();
        assert_eq!(rs.domain_suffixes, vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn mihomo_yaml_invalid_cidr_in_ipcidr_mode() {
        let yaml = r#"
payload:
  - 'not-an-ip'
"#;
        let err = CompiledRuleSet::from_mihomo_yaml(yaml, Some("ipcidr")).unwrap_err();
        assert!(matches!(err, RuleSetError::ParseError { .. }));
    }

    #[test]
    fn mihomo_yaml_empty_payload() {
        let yaml = "payload:\n";
        let rs = CompiledRuleSet::from_mihomo_yaml(yaml, None).unwrap();
        assert_eq!(rs.total_entries(), 0);
    }

    #[test]
    fn mihomo_yaml_invalid_syntax() {
        let yaml = ":\n  - [broken";
        let err = CompiledRuleSet::from_mihomo_yaml(yaml, None).unwrap_err();
        assert!(matches!(err, RuleSetError::ParseError { .. }));
    }

    /// 端到端：yaml → rrs bytes → LoadedRuleSet → RuleSet → 匹配。
    /// 这是用户实际使用 `reflex ruleset input.yaml -o out.rrs` 后
    /// 在路由中加载 .rrs 的完整链路。
    #[test]
    fn mihomo_yaml_end_to_end_match() {
        use crate::ruleset::{LoadedRuleSet, MatchTarget, RuleSet};
        use std::net::IpAddr;

        let yaml = r#"
payload:
  - '+.google.com'
  - 'example.com'
  - '192.168.0.0/16'
  - '2001:db8::/32'
  - 'DOMAIN-SUFFIX,github.com'
"#;
        let compiled = CompiledRuleSet::from_mihomo_yaml(yaml, None).unwrap();
        let mut buf = Vec::new();
        compiled.serialize(&mut buf).unwrap();

        // 检查 rrs 头
        assert_eq!(&buf[0..4], b"RRST");
        assert_eq!(buf[4], VERSION);

        let loaded = LoadedRuleSet::from_bytes(&buf).unwrap();
        let rs = RuleSet::from_loaded(loaded).unwrap();

        // domain-suffix 匹配
        assert!(rs.matches(&MatchTarget::Domain("www.google.com")));
        assert!(rs.matches(&MatchTarget::Domain("google.com"))); // +. 含自身
        assert!(rs.matches(&MatchTarget::Domain("api.example.com")));
        assert!(rs.matches(&MatchTarget::Domain("example.com")));
        assert!(rs.matches(&MatchTarget::Domain("api.github.com")));

        // 不匹配
        assert!(!rs.matches(&MatchTarget::Domain("evil.com")));
        assert!(!rs.matches(&MatchTarget::Domain("notexample.com")));

        // IP CIDR 匹配
        assert!(rs.matches(&MatchTarget::Ip("192.168.1.1".parse().unwrap())));
        assert!(rs.matches(&MatchTarget::Ip("2001:db8::1".parse().unwrap())));
        // rs 中只有 192.168.0.0/16 和 2001:db8::/32 两条 IP CIDR，
        // 10.0.0.1 不应匹配。下面单独构造一个 ipcidr-only 规则集做严格断言。
        let rs2 = {
            let compiled = CompiledRuleSet::from_mihomo_yaml(
                r#"payload:
  - '192.168.0.0/16'
  - '2001:db8::/32'"#,
                Some("ipcidr"),
            )
            .unwrap();
            let mut b = Vec::new();
            compiled.serialize(&mut b).unwrap();
            RuleSet::from_loaded(LoadedRuleSet::from_bytes(&b).unwrap()).unwrap()
        };
        assert!(rs2.matches(&MatchTarget::Ip("192.168.5.5".parse().unwrap())));
        assert!(!rs2.matches(&MatchTarget::Ip("10.0.0.1".parse().unwrap())));
        let v6_in: IpAddr = "2001:db8::1".parse().unwrap();
        let v6_out: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(rs2.matches(&MatchTarget::Ip(v6_in)));
        assert!(!rs2.matches(&MatchTarget::Ip(v6_out)));
    }

    #[test]
    fn mihomo_yaml_roundtrip_preserves_entries() {
        // yaml → rrs → LoadedRuleSet → RuleSet → 匹配
        // 验证 round-trip 不丢条目
        use crate::ruleset::{LoadedRuleSet, MatchTarget, RuleSet};

        let yaml = r#"
payload:
  - '+.google.com'
  - 'github.com'
  - '10.0.0.0/8'
  - '2001:db8::/32'
"#;
        let compiled = CompiledRuleSet::from_mihomo_yaml(yaml, None).unwrap();
        let original_count = compiled.total_entries();
        assert_eq!(original_count, 4);

        let mut buf = Vec::new();
        compiled.serialize(&mut buf).unwrap();

        let loaded = LoadedRuleSet::from_bytes(&buf).unwrap();
        let rs = RuleSet::from_loaded(loaded).unwrap();

        // 每条原始条目都应能匹配
        assert!(rs.matches(&MatchTarget::Domain("www.google.com")));
        assert!(rs.matches(&MatchTarget::Domain("google.com")));
        assert!(rs.matches(&MatchTarget::Domain("api.github.com")));
        assert!(rs.matches(&MatchTarget::Domain("github.com")));
        assert!(rs.matches(&MatchTarget::Ip("10.1.2.3".parse().unwrap())));
        assert!(rs.matches(&MatchTarget::Ip("2001:db8::1:2:3:4".parse().unwrap())));
    }
}
