use std::{
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Range,
    sync::Arc,
};

use super::{
    error::{Result, RuleSetError},
    format::*,
};

// ── FST 字节存储 ─────────────────────────────────────────────────────────────

/// FST 字节的存储方式。
///
/// 设计目标：让本地二进制规则集（`.rrs`）能通过 mmap 零拷贝加载——
/// FST 字节直接借用文件映射，无需读入进程堆。对 geosite 这类动辄数万
/// 域名的规则集，常驻堆内存可下降一个量级。
///
/// `fst::Set<D>` 只要求 `D: AsRef<[u8]>`，因此本类型实现 `AsRef<[u8]>`
/// 即可被 `Set::new` 接受，两种存储路径对 matcher 完全透明。
#[derive(Debug, Clone)]
pub enum ByteSource {
    /// 拥有的字节（in-memory 下载 / source 编译产出 / v1 兼容路径）。
    Owned(Arc<[u8]>),
    /// 借用 mmap 的字节切片：所有 section 共享同一个 `Arc<Mmap>`，
    /// 各自记录自己的 `[start, end)` 区间。
    Mmap {
        mmap: Arc<memmap2::Mmap>,
        range: Range<usize>,
    },
}

impl ByteSource {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    /// 字节长度。
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            ByteSource::Owned(b) => b.len(),
            ByteSource::Mmap { range, .. } => range.end - range.start,
        }
    }
}

impl AsRef<[u8]> for ByteSource {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        match self {
            ByteSource::Owned(b) => b,
            ByteSource::Mmap { mmap, range } => &mmap[range.clone()],
        }
    }
}

impl Default for ByteSource {
    fn default() -> Self {
        ByteSource::Owned(Arc::from(&[][..]))
    }
}

impl From<Vec<u8>> for ByteSource {
    fn from(v: Vec<u8>) -> Self {
        ByteSource::Owned(Arc::from(v))
    }
}

// ── LoadedRuleSet ─────────────────────────────────────────────────────────────

/// 从二进制流加载的原始数据，尚未建立索引结构。
/// 通常不直接使用，而是传给 [`crate::matcher::RuleSet::from_loaded`] 建立匹配引擎。
#[derive(Debug, Default)]
pub struct LoadedRuleSet {
    /// v1 旧版精确域名列表（字符串）
    pub domains: Vec<String>,
    /// v1 旧版后缀域名列表（字符串）
    pub domain_suffixes: Vec<String>,
    /// v2 精确域名 FST 字节（可直接传给 fst::Set::new）
    pub domain_fst: ByteSource,
    /// v2 后缀域名 FST 字节
    pub domain_suffix_fst: ByteSource,
    pub domain_keywords: Vec<String>,
    pub domain_regexes: Vec<String>,
    pub ipv4_cidrs: Vec<(Ipv4Addr, u8)>,
    pub ipv6_cidrs: Vec<(Ipv6Addr, u8)>,
    pub ports: Vec<(u16, u16)>,
    /// 例外（@@）精确域名 FST
    pub exclude_domain_fst: ByteSource,
    /// 例外（@@）后缀域名 FST
    pub exclude_domain_suffix_fst: ByteSource,
    /// 例外（@@）域名正则
    pub exclude_domain_regexes: Vec<String>,
}

impl LoadedRuleSet {
    /// 从任意 `Read` 加载二进制规则集，同时兼容 v1 和 v2。
    ///
    /// 内部把流读入 `Vec<u8>` 后走 [`from_bytes`]，因此本方法不适合
    /// 超大流式输入；本地文件请用 [`from_mmap`] 获得零拷贝加载。
    pub fn from_reader<R: Read>(mut r: R) -> Result<Self> {
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)
            .map_err(|_| RuleSetError::BadMagic)?;
        Self::from_bytes(&buf)
    }

    /// 从字节切片加载（适合内存中已有数据的场景）。
    ///
    /// section 字节会被拷贝一份到 `ByteSource::Owned`。对本地二进制文件，
    /// 推荐用 [`from_mmap`] 避免 FST 大段拷贝。
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let sections = parse_sections(data)?;
        Self::build_from_sections(data, &sections, None)
    }

    /// 把已 mmap 的本地二进制规则集零拷贝加载为 `LoadedRuleSet`。
    ///
    /// FST 字节直接借用 mmap（`ByteSource::Mmap`），不读入堆；
    /// 其余 section（CIDR / port / keyword / regex 等）仍按原逻辑解码为
    /// 拥有结构（这些 section 通常远小于 FST，拷贝代价可忽略）。
    ///
    /// # 安全性
    ///
    /// 使用 `MAP_SHARED` 只读映射。调用方应保证文件以原子替换方式更新
    /// （`mv` / `rename` / 编辑器原子写），否则原地 truncate+rewrite 可能
    /// 在访问越界页时触发 `SIGBUS`。`ruleset_registry` 的热更新监听走
    /// `reload_local` 重新读取并替换 `RuleSet`，新 `RuleSet` 持有新 mmap，
    /// 旧 mmap 随旧 `Arc<RuleSet>` 释放。
    pub fn from_mmap(mmap: Arc<memmap2::Mmap>) -> Result<Self> {
        let data: &[u8] = &mmap[..];
        let sections = parse_sections(data)?;
        Self::build_from_sections(data, &sections, Some(&mmap))
    }

    /// 直接从 [`CompiledRuleSet`] 构建，跳过 `serialize → from_bytes` 往返。
    ///
    /// 等价于 `compiled.serialize(buf); LoadedRuleSet::from_bytes(&buf)`，
    /// 但不经过 RRS 二进制中间表示，省掉一次 `Vec<u8>` 拷贝与 section 重新解析，
    /// 对大型 source 规则集（geosite / 大型 mihomo yaml）加载峰值内存显著下降。
    ///
    /// FST 字节由 `compiler::build_domain_fst` / `build_suffix_fst` 现场构建，
    /// 与 `serialize` 路径产出完全一致（同一函数），保证匹配语义不变。
    pub fn from_compiled(compiled: super::compiler::CompiledRuleSet) -> Result<Self> {
        use super::compiler::{build_domain_fst, build_suffix_fst};
        Ok(Self {
            // v2 路径：domains / domain_suffixes 走 FST，旧版 Vec 留空
            domains: Vec::new(),
            domain_suffixes: Vec::new(),
            domain_fst: build_domain_fst(&compiled.domains)?.into(),
            domain_suffix_fst: build_suffix_fst(&compiled.domain_suffixes)?.into(),
            domain_keywords: compiled.domain_keywords,
            domain_regexes: compiled.domain_regexes,
            ipv4_cidrs: compiled.ipv4_cidrs,
            ipv6_cidrs: compiled.ipv6_cidrs,
            ports: compiled.ports,
            exclude_domain_fst: build_domain_fst(&compiled.exclude_domains)?.into(),
            exclude_domain_suffix_fst: build_suffix_fst(&compiled.exclude_domain_suffixes)?
                .into(),
            exclude_domain_regexes: compiled.exclude_domain_regexes,
        })
    }

    /// 解析好的 section 列表 → `LoadedRuleSet`。
    ///
    /// `mmap` 为 `Some` 时，FST 类 section 走 `ByteSource::Mmap` 零拷贝；
    /// 为 `None` 时（in-memory），FST 字节拷贝为 `ByteSource::Owned`。
    /// 非 FST section（CIDR / port / keyword / regex）无论何种路径都解码为
    /// 拥有结构（它们通常远小于 FST，拷贝代价可忽略）。
    fn build_from_sections(
        data: &[u8],
        sections: &[ParsedSection],
        mmap: Option<&Arc<memmap2::Mmap>>,
    ) -> Result<Self> {
        let mut out = Self::default();
        for s in sections {
            let sec_bytes = &data[s.data_range.clone()];
            match s.sec_type {
                // v1 旧版字符串格式（向后兼容）
                SectionType::Domain => out.domains = decode_strings(sec_bytes, s.entry_count)?,
                SectionType::DomainSuffix => {
                    out.domain_suffixes = decode_strings(sec_bytes, s.entry_count)?
                }
                // v2 FST 格式：mmap 路径直接借用，否则拷贝为 Owned
                SectionType::DomainFst => {
                    out.domain_fst = Self::byte_source(data, &s.data_range, mmap)
                }
                SectionType::DomainSuffixFst => {
                    out.domain_suffix_fst = Self::byte_source(data, &s.data_range, mmap)
                }
                SectionType::ExcludeDomainFst => {
                    out.exclude_domain_fst = Self::byte_source(data, &s.data_range, mmap)
                }
                SectionType::ExcludeSuffixFst => {
                    out.exclude_domain_suffix_fst = Self::byte_source(data, &s.data_range, mmap)
                }
                SectionType::DomainKeyword => {
                    out.domain_keywords = decode_strings(sec_bytes, s.entry_count)?
                }
                SectionType::DomainRegex => {
                    out.domain_regexes = decode_strings(sec_bytes, s.entry_count)?
                }
                SectionType::ExcludeDomainRegex => {
                    out.exclude_domain_regexes = decode_strings(sec_bytes, s.entry_count)?
                }
                SectionType::IpCidrV4 => out.ipv4_cidrs = decode_ipv4_cidrs(sec_bytes, s.entry_count)?,
                SectionType::IpCidrV6 => out.ipv6_cidrs = decode_ipv6_cidrs(sec_bytes, s.entry_count)?,
                SectionType::Port => out.ports = decode_ports(sec_bytes, s.entry_count)?,
            }
        }
        Ok(out)
    }

    /// 构造单个 FST section 的字节源：mmap 路径零拷贝，in-memory 路径拷贝。
    #[inline]
    fn byte_source(
        data: &[u8],
        range: &Range<usize>,
        mmap: Option<&Arc<memmap2::Mmap>>,
    ) -> ByteSource {
        match mmap {
            Some(m) => ByteSource::Mmap {
                mmap: m.clone(),
                range: range.clone(),
            },
            None => {
                // 拷贝为 Arc<[u8]>；from_bytes 路径下 data 来自临时缓冲，
                // 必须拥有化才能让 fst::Set 长期持有。
                let slice = &data[range.clone()];
                ByteSource::Owned(Arc::from(slice))
            }
        }
    }
}

// ── 文件解析 ─────────────────────────────────────────────────────────────────

/// 解析后单个 section 的元信息：类型 + entry 数 + 在源 buffer 中的字节区间。
struct ParsedSection {
    sec_type: SectionType,
    entry_count: usize,
    data_range: Range<usize>,
}

/// 解析 RRS 文件头 + 各 section 头，返回 section 列表（含字节区间）。
///
/// 不拷贝任何 section 数据；区间指向 `data` 的子切片，由调用方决定
/// 拷贝（`from_bytes`）还是借用（`from_mmap`）。
fn parse_sections(data: &[u8]) -> Result<Vec<ParsedSection>> {
    if data.len() < HEADER_LEN {
        return Err(RuleSetError::BadMagic);
    }
    if data[0..4] != MAGIC {
        return Err(RuleSetError::BadMagic);
    }
    let ver = data[4];
    if ver != VERSION && ver != VERSION_V1 {
        return Err(RuleSetError::UnsupportedVersion(ver));
    }
    let section_count = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;

    let mut out = Vec::with_capacity(section_count);
    let mut off = HEADER_LEN;
    for _ in 0..section_count {
        if off + SECTION_HEADER_LEN > data.len() {
            return Err(RuleSetError::Truncated {
                expected: off + SECTION_HEADER_LEN,
                got: data.len(),
            });
        }
        let sec_type_byte = data[off];
        let entry_count = u32::from_le_bytes(data[off + 1..off + 5].try_into().unwrap()) as usize;
        let byte_len = u32::from_le_bytes(data[off + 5..off + 9].try_into().unwrap()) as usize;
        let sec_type =
            SectionType::try_from(sec_type_byte).map_err(RuleSetError::UnknownSection)?;
        off += SECTION_HEADER_LEN;
        if off + byte_len > data.len() {
            return Err(RuleSetError::Truncated {
                expected: off + byte_len,
                got: data.len(),
            });
        }
        out.push(ParsedSection {
            sec_type,
            entry_count,
            data_range: off..off + byte_len,
        });
        off += byte_len;
    }
    Ok(out)
}

// ── 解码辅助 ─────────────────────────────────────────────────────────────────

fn decode_strings(data: &[u8], expected: usize) -> Result<Vec<String>> {
    let mut result = Vec::with_capacity(expected);
    let mut i = 0;
    while i < data.len() {
        if i + 1 > data.len() {
            return Err(RuleSetError::Truncated {
                expected: i + 1,
                got: data.len(),
            });
        }
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            return Err(RuleSetError::Truncated {
                expected: i + len,
                got: data.len(),
            });
        }
        let s = std::str::from_utf8(&data[i..i + len])
            .map_err(|_| RuleSetError::InvalidUtf8)?
            .to_string();
        result.push(s);
        i += len;
    }
    Ok(result)
}

fn decode_ipv4_cidrs(data: &[u8], expected: usize) -> Result<Vec<(Ipv4Addr, u8)>> {
    if data.len() != expected * IPV4_ENTRY_LEN {
        return Err(RuleSetError::Truncated {
            expected: expected * IPV4_ENTRY_LEN,
            got: data.len(),
        });
    }
    Ok(data
        .as_chunks::<IPV4_ENTRY_LEN>()
        .0
        .iter()
        .map(|c| {
            let addr = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            let prefix = c[4];
            (addr, prefix)
        })
        .collect())
}

fn decode_ipv6_cidrs(data: &[u8], expected: usize) -> Result<Vec<(Ipv6Addr, u8)>> {
    if data.len() != expected * IPV6_ENTRY_LEN {
        return Err(RuleSetError::Truncated {
            expected: expected * IPV6_ENTRY_LEN,
            got: data.len(),
        });
    }
    Ok(data
        .as_chunks::<IPV6_ENTRY_LEN>()
        .0
        .iter()
        .map(|c| {
            let octets: [u8; 16] = c[..16].try_into().unwrap();
            let addr = Ipv6Addr::from(octets);
            let prefix = c[16];
            (addr, prefix)
        })
        .collect())
}

fn decode_ports(data: &[u8], expected: usize) -> Result<Vec<(u16, u16)>> {
    if data.len() != expected * PORT_ENTRY_LEN {
        return Err(RuleSetError::Truncated {
            expected: expected * PORT_ENTRY_LEN,
            got: data.len(),
        });
    }
    Ok(data
        .as_chunks::<PORT_ENTRY_LEN>()
        .0
        .iter()
        .map(|c| {
            let start = u16::from_le_bytes([c[0], c[1]]);
            let end = u16::from_le_bytes([c[2], c[3]]);
            (start, end)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::compiler::CompiledRuleSet;

    fn compile_and_load(src: &str) -> LoadedRuleSet {
        let compiled = CompiledRuleSet::from_text(src).unwrap();
        let mut buf = Vec::new();
        compiled.serialize(&mut buf).unwrap();
        LoadedRuleSet::from_bytes(&buf).unwrap()
    }

    #[test]
    fn roundtrip_domains() {
        let loaded =
            compile_and_load("domain: example.com\ndomain-suffix: google.com\ndomain-keyword: ads");
        // v2 格式：domains/domain_suffixes 为空，FST 有内容
        assert!(loaded.domains.is_empty());
        assert!(loaded.domain_suffixes.is_empty());
        assert!(!loaded.domain_fst.is_empty());
        assert!(!loaded.domain_suffix_fst.is_empty());
        assert_eq!(loaded.domain_keywords, vec!["ads"]);
    }

    #[test]
    fn roundtrip_cidrs() {
        let loaded = compile_and_load("ip-cidr: 10.0.0.0/8\nip-cidr6: 2001:db8::/32");
        assert_eq!(loaded.ipv4_cidrs, vec![(Ipv4Addr::new(10, 0, 0, 0), 8)]);
        assert_eq!(
            loaded.ipv6_cidrs,
            vec![("2001:db8::".parse::<Ipv6Addr>().unwrap(), 32)]
        );
    }

    #[test]
    fn roundtrip_ports() {
        let loaded = compile_and_load("port: 80\nport: 8000-9000");
        assert_eq!(loaded.ports, vec![(80, 80), (8000, 9000)]);
    }

    #[test]
    fn bad_magic() {
        let err = LoadedRuleSet::from_bytes(b"BADD\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        assert!(matches!(err, Err(RuleSetError::BadMagic)));
    }

    #[test]
    fn bad_version() {
        let buf = b"RRST\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec();
        let err = LoadedRuleSet::from_bytes(&buf);
        assert!(matches!(err, Err(RuleSetError::UnsupportedVersion(0xff))));
    }

    /// mmap 零拷贝加载路径：FST 字节直接借用文件映射，
    /// 匹配语义必须与 in-memory `from_bytes` 路径完全一致。
    #[test]
    fn mmap_load_matches_from_bytes() {
        let src = "domain: example.com\ndomain-suffix: google.com\ndomain-keyword: ads\n\
                   ip-cidr: 10.0.0.0/8\nip-cidr6: 2001:db8::/32\nport: 443";
        let compiled = CompiledRuleSet::from_text(src).unwrap();
        let mut buf = Vec::new();
        compiled.serialize(&mut buf).unwrap();

        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), &buf).unwrap();
        let file = std::fs::File::open(tmp.path()).unwrap();
        let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
        let loaded_mmap = LoadedRuleSet::from_mmap(std::sync::Arc::new(mmap)).unwrap();
        let loaded_mem = LoadedRuleSet::from_bytes(&buf).unwrap();

        // FST 字节内容一致（mmap 切片 == 拷贝字节）
        assert_eq!(loaded_mmap.domain_fst.as_ref(), loaded_mem.domain_fst.as_ref());
        assert_eq!(
            loaded_mmap.domain_suffix_fst.as_ref(),
            loaded_mem.domain_suffix_fst.as_ref()
        );
        // 非 FST section 解码结果一致
        assert_eq!(loaded_mmap.domain_keywords, loaded_mem.domain_keywords);
        assert_eq!(loaded_mmap.ipv4_cidrs, loaded_mem.ipv4_cidrs);
        assert_eq!(loaded_mmap.ipv6_cidrs, loaded_mem.ipv6_cidrs);
        assert_eq!(loaded_mmap.ports, loaded_mem.ports);

        // 端到端匹配：mmap 路径构建的 RuleSet 能正确匹配
        let rs = crate::ruleset::RuleSet::from_loaded(loaded_mmap).unwrap();
        use crate::ruleset::MatchTarget;
        assert!(rs.matches(&MatchTarget::Domain("example.com")));
        assert!(rs.matches(&MatchTarget::Domain("mail.google.com")));
        assert!(rs.matches(&MatchTarget::Domain("ads.example.org")));
        assert!(rs.matches(&MatchTarget::Ip("10.1.2.3".parse().unwrap())));
        assert!(rs.matches(&MatchTarget::Port(443)));
        assert!(!rs.matches(&MatchTarget::Domain("unrelated.test")));
    }

    /// `from_compiled` 直通路径与 `serialize → from_bytes` 等价。
    #[test]
    fn from_compiled_matches_roundtrip() {
        let src = "domain: a.example\ndomain-suffix: b.example\ndomain-keyword: kw\n\
                   ip-cidr: 192.168.0.0/16";
        let compiled = CompiledRuleSet::from_text(src).unwrap();
        let loaded_direct = LoadedRuleSet::from_compiled(compiled).unwrap();

        let compiled2 = CompiledRuleSet::from_text(src).unwrap();
        let mut buf = Vec::new();
        compiled2.serialize(&mut buf).unwrap();
        let loaded_roundtrip = LoadedRuleSet::from_bytes(&buf).unwrap();

        assert_eq!(
            loaded_direct.domain_fst.as_ref(),
            loaded_roundtrip.domain_fst.as_ref()
        );
        assert_eq!(
            loaded_direct.domain_suffix_fst.as_ref(),
            loaded_roundtrip.domain_suffix_fst.as_ref()
        );
        assert_eq!(loaded_direct.domain_keywords, loaded_roundtrip.domain_keywords);
        assert_eq!(loaded_direct.ipv4_cidrs, loaded_roundtrip.ipv4_cidrs);
    }
}
