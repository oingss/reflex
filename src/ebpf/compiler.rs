//! 内核面（eBPF 预分流）规则集编译器。
//!
//! 内核面与用户面完全独立（dae 式双层路由）：
//!
//! - **内核面**：来自 tproxy 入站 `ebpf` 配置中**显式声明**的纯 IP 规则集
//!   （`block_rulesets` / `direct_rulesets`，引用 `route.rule_set` 中已
//!   声明并加载的 tag），外加内置的私有网段直连集合。内核态固定裁决顺序
//!   （`reflex-bpf` 的 `route()`）：
//!   DNS-53 劫持（PROXY，受 `route.hijack_dns` 控制）→ BLOCK 集合 →
//!   DIRECT 集合 → 内置私有网段直连 → 未命中一律 PROXY 交用户态。
//! - **用户面**：`route.rules` 只对进入 tproxy 入站的流量求值，与本模块
//!   无任何交互——不再存在旧架构的「可编译前缀」截断语义。
//!
//! 编译产物：MatchSet 线性序列（写入 `ROUTING` map）+ LPM 前缀条目
//! （写入 `LPM` map）。每个裁决组编码为一组 `IP_SET` 条件、`GROUP_END`
//! 收尾与 `TERMINATE` 终止项，组内 OR、组间按序短路终止，与 `reflex-bpf`
//! 的 `route_loop_cb` 状态机一致（`interp.rs` 提供逐行同构的纯 Rust 镜像）。

use anyhow::Context as _;
use reflex_ebpf_common as common;
use reflex_ebpf_common::match_type;
use reflex_ebpf_common::MatchSet;
use reflex_ebpf_common::MAX_MATCH_SET_LEN;

use crate::ebpf::KernelVerdict;
use crate::ruleset::matcher::RuleSet;

/// 一条 LPM trie 条目（键已按两端约定编码：2B set_id + 16B addr）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LpmEntry {
    pub key: [u8; common::LPM_KEY_LEN],
    pub prefix_len: u32,
}

/// 内核面编译的输入：一个已加载的纯 IP 规则集及其 tag（供错误信息）。
pub struct KernelRuleset<'a> {
    pub tag: &'a str,
    pub ruleset: &'a RuleSet,
}

/// 编译产物：内核 map 的全部初始数据 + 摘要统计。
#[derive(Debug, Clone, Default)]
pub struct CompiledKernelPlane {
    /// MatchSet 线性序列（写入 `ROUTING` map，`META[0]` 为长度）。
    pub match_sets: Vec<MatchSet>,
    /// LPM 条目（写入 `LPM` map）。
    pub lpm_entries: Vec<LpmEntry>,
    /// BLOCK 规则集个数。
    pub block_rulesets: usize,
    /// DIRECT 规则集个数（不含内置私有集合）。
    pub direct_rulesets: usize,
    /// LPM 条目总数（= `lpm_entries.len()`，日志快捷字段）。
    pub lpm_total: usize,
    /// 本机地址集合号（独立于私有网段集合）：loader 写入 CONFIG 供内核
    /// DNS 劫持判断"发往本机地址:53"（此类查询不劫持，交回本机 DNS 服务，
    /// 避免代答回包 bind 本机 :53 与本机服务冲突）。
    pub local_set_id: u16,
}

/// 内置私有/特殊网段 + 本机地址直连集合。内核面独立于用户面
/// `route.rules`——未命中即 PROXY 的兜底会把局域网/组播/本机流量引向
/// 代理，因此私有网段直连是内核面的固定行为，不做成配置项。
///
/// 本机地址（`local_addrs`，全部接口的 v4/v6 地址）必须直连：tc ingress
/// 同样能抓到**发往本机**的流量（SSH/管理端口），不排除会被 PROXY 判决
/// 引流进 tproxy，形成自环（SSH 断连）。
///
/// v4：本网段、私有、CGN、回环、链路本地、IETF 协议预留、测试网段、
/// 组播、保留；v6：回环、ULA、链路本地、组播。
/// v4/v6 分开声明：LPM 前缀偏移按地址族不同（v4 映射 +112，v6 +16）。
const BUILTIN_PRIVATE_V4: [&str; 10] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
const BUILTIN_PRIVATE_V6: [&str; 4] = ["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];

/// 编译内核面。`block` 优先于 `direct`（内核按 MatchSet 顺序终止），
/// 内置私有直连集合 + 本机地址直连固定追加在最后。
///
/// fail-fast：规则集数 / LPM 条目数超过内核 map 容量时直接报错，不截断。
pub fn compile_kernel_plane(
    block: &[KernelRuleset<'_>],
    direct: &[KernelRuleset<'_>],
    local_addrs: &[std::net::IpAddr],
) -> anyhow::Result<CompiledKernelPlane> {
    let mut out = CompiledKernelPlane::default();
    let mut next_set_id: u16 = 1;

    // ── BLOCK 组 ──────────────────────────────────────────────────────────
    let mut block_conds = Vec::with_capacity(block.len());
    for ks in block {
        let set_id = register_ranges(ks, &mut next_set_id, &mut out)?;
        block_conds.push(MatchSet::new_cond(match_type::IP_SET, set_id as u32, 0));
    }
    out.block_rulesets = block.len();
    push_group(
        &mut out.match_sets,
        block_conds,
        common::KERNEL_OUTBOUND_BLOCK,
    );

    // ── DIRECT 组 ─────────────────────────────────────────────────────────
    let mut direct_conds = Vec::with_capacity(direct.len());
    for ks in direct {
        let set_id = register_ranges(ks, &mut next_set_id, &mut out)?;
        direct_conds.push(MatchSet::new_cond(match_type::IP_SET, set_id as u32, 0));
    }
    out.direct_rulesets = direct.len();
    push_group(
        &mut out.match_sets,
        direct_conds,
        common::KERNEL_OUTBOUND_DIRECT,
    );

    // ── 内置私有直连组（含本机地址，组内 OR）────────────────────────────
    // 本机地址额外独立成集合（local_set_id 写入 CONFIG）：内核 DNS 劫持
    // 需要区分"发往本机地址:53"的查询并跳过劫持（见 CONFIG_KEY_LOCAL_SET_ID）。
    let (private_set_id, local_set_id) =
        register_builtin_private(&mut next_set_id, &mut out, local_addrs)?;
    push_group(
        &mut out.match_sets,
        vec![
            MatchSet::new_cond(match_type::IP_SET, private_set_id as u32, 0),
            MatchSet::new_cond(match_type::IP_SET, local_set_id as u32, 0),
        ],
        common::KERNEL_OUTBOUND_DIRECT,
    );
    out.local_set_id = local_set_id;

    anyhow::ensure!(
        out.match_sets.len() <= MAX_MATCH_SET_LEN as usize,
        "内核面 MatchSet 数量 {} 超过内核 ROUTING map 容量 {MAX_MATCH_SET_LEN}\
         （规则集过多，请精简 block_rulesets/direct_rulesets）",
        out.match_sets.len()
    );
    anyhow::ensure!(
        out.lpm_entries.len() <= common::MAX_LPM_ENTRIES as usize,
        "内核面 LPM 条目数量 {} 超过内核 map 容量 {}",
        out.lpm_entries.len(),
        common::MAX_LPM_ENTRIES
    );
    out.lpm_total = out.lpm_entries.len();

    Ok(out)
}

/// 追加一个裁决组：`[IP_SET × n][GROUP_END][TERMINATE verdict]`。
/// 组内条件 OR（任一集合命中即整组命中）；空组直接跳过。
fn push_group(match_sets: &mut Vec<MatchSet>, conds: Vec<MatchSet>, verdict: KernelVerdict) {
    if conds.is_empty() {
        return;
    }
    match_sets.extend(conds);
    match_sets.push(MatchSet::new_group_end());
    match_sets.push(MatchSet::new_terminate(verdict, false, 0));
}

/// 为一个规则集分配 set_id 并把其 IP 区间精确分解为 LPM 前缀条目。
///
/// 区间来源是 `RuleSet` 内排序合并后的 `[lo, hi]` 闭区间（可能不再是
/// 单一 CIDR），必须先分解为恰好覆盖的 CIDR 列表才能进 LPM trie。
fn register_ranges(
    ks: &KernelRuleset<'_>,
    next_set_id: &mut u16,
    out: &mut CompiledKernelPlane,
) -> anyhow::Result<u16> {
    let set_id = alloc_set_id(next_set_id)?;

    for (lo, hi) in ks.ruleset.ipv4_ranges() {
        for (addr, prefix) in range_to_cidrs4(lo, hi) {
            let octets = addr.to_be_bytes();
            out.lpm_entries.push(LpmEntry {
                key: common::lpm_key(set_id, common::ipv4_mapped(octets)),
                prefix_len: common::LPM_V4_PREFIX_OFFSET + prefix as u32,
            });
        }
    }
    for (lo, hi) in ks.ruleset.ipv6_ranges() {
        for (addr, prefix) in range_to_cidrs6(lo, hi) {
            out.lpm_entries.push(LpmEntry {
                key: common::lpm_key(set_id, addr.to_be_bytes()),
                // v6 无映射偏移：16 位 set_id + 原生前缀。
                prefix_len: 16 + prefix as u32,
            });
        }
    }
    Ok(set_id)
}

/// 内置私有/特殊网段集合 + 本机地址集合（各自独立 set_id，共两个 LPM 子树）。
///
/// 返回 `(private_set_id, local_set_id)`。本机地址独立成集合的原因见
/// `CONFIG_KEY_LOCAL_SET_ID`（内核 DNS 劫持跳过"发往本机地址:53"）。
fn register_builtin_private(
    next_set_id: &mut u16,
    out: &mut CompiledKernelPlane,
    local_addrs: &[std::net::IpAddr],
) -> anyhow::Result<(u16, u16)> {
    let set_id = alloc_set_id(next_set_id)?;
    for cidr in BUILTIN_PRIVATE_V4 {
        let (addr, prefix) = parse_cidr(cidr).map_err(|e| {
            anyhow::anyhow!("内置私有网段解析失败: {cidr}（编译器内部错误）: {e}")
        })?;
        out.lpm_entries.push(LpmEntry {
            key: common::lpm_key(set_id, addr),
            prefix_len: common::LPM_V4_PREFIX_OFFSET + prefix,
        });
    }
    for cidr in BUILTIN_PRIVATE_V6 {
        let (addr, prefix) = parse_cidr(cidr).map_err(|e| {
            anyhow::anyhow!("内置私有网段解析失败: {cidr}（编译器内部错误）: {e}")
        })?;
        out.lpm_entries.push(LpmEntry {
            key: common::lpm_key(set_id, addr),
            // v6 无映射偏移：16 位 set_id + 原生前缀。
            prefix_len: 16 + prefix,
        });
    }
    // 本机自身地址：/32（v4 映射）/ /128（v6），发往本机的流量必须直连，
    // 否则 SSH/管理流量会被 PROXY 判决引流进 tproxy 形成自环。
    let local_set_id = alloc_set_id(next_set_id)?;
    for addr in local_addrs {
        match *addr {
            std::net::IpAddr::V4(v4) => out.lpm_entries.push(LpmEntry {
                key: common::lpm_key(local_set_id, common::ipv4_mapped(v4.octets())),
                prefix_len: common::LPM_V4_PREFIX_OFFSET + 32,
            }),
            std::net::IpAddr::V6(v6) => out.lpm_entries.push(LpmEntry {
                key: common::lpm_key(local_set_id, v6.octets()),
                prefix_len: 16 + 128,
            }),
        }
    }
    Ok((set_id, local_set_id))
}

fn alloc_set_id(next_set_id: &mut u16) -> anyhow::Result<u16> {
    let id = *next_set_id;
    *next_set_id = next_set_id
        .checked_add(1)
        .context("LPM 集合号耗尽（规则集数量超过 65535）")?;
    Ok(id)
}

/// 解析 CIDR：返回 16 字节地址（IPv4 映射形式）与**原始**前缀位数
/// （v4 不加 96；`prefix_len` 由调用方按地址族与偏移组合）。
pub fn parse_cidr(raw: &str) -> Result<([u8; 16], u32), String> {
    let (addr_part, prefix_part) = match raw.split_once('/') {
        Some((a, p)) => (a, p),
        None => (raw, "128"),
    };
    let prefix: u32 = prefix_part
        .trim()
        .parse()
        .map_err(|_| format!("无效 CIDR 前缀: {raw}"))?;
    let addr: std::net::IpAddr = addr_part
        .trim()
        .parse()
        .map_err(|_| format!("无效 CIDR 地址: {raw}"))?;
    match addr {
        std::net::IpAddr::V4(v4) => {
            if prefix > 32 {
                return Err(format!("IPv4 CIDR 前缀越界: {raw}"));
            }
            Ok((common::ipv4_mapped(v4.octets()), prefix))
        }
        std::net::IpAddr::V6(v6) => {
            if prefix > 128 {
                return Err(format!("IPv6 CIDR 前缀越界: {raw}"));
            }
            // 内核 LPM 语义下前缀位必须显式给出；裸地址视为 /128。
            Ok((v6.octets(), prefix))
        }
    }
}

/// 把闭区间 `[lo, hi]` 精确分解为恰好覆盖它的 CIDR 列表（无重叠、无越界）。
///
/// 算法：每步取「起始地址对齐的最大块」与「不越过 hi 的最大块」的较小者，
/// 输出后推进。产物顺序无意义（LPM 是前缀树，无顺序语义）。
pub(crate) fn range_to_cidrs4(lo: u32, hi: u32) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    if lo > hi {
        return out;
    }
    let mut cur = lo;
    loop {
        let align: u32 = if cur == 0 { 32 } else { cur.trailing_zeros() };
        // 剩余长度 rem+1 的最高幂指数：floor(log2(rem+1))，即满足
        // 2^n ≤ rem+1（块尾不超过 hi）。注意不能用 32-rem.leading_zeros()
        // （那是 floor(log2(rem))+1）：rem 非「全 1 位」时会高估 1 位，
        // 块尾越过 hi 导致后续 hi-cur 下溢。rem+1 == 2^32（cur==0 且
        // hi==u32::MAX）时直接取 32，由下方 n==32 分支整空间输出。
        let rem = hi - cur;
        let max_pow: u32 = if rem == u32::MAX {
            32
        } else {
            31 - (rem + 1).leading_zeros()
        };
        let n = align.min(max_pow);
        if n == 32 {
            // cur==0 且 hi==u32::MAX：整个地址空间一块（0.0.0.0/0）。
            out.push((0, 0));
            break;
        }
        // cur 按 2^n 对齐（低 n 位为 0），按位或与 cur+2^n-1 数学等价，
        // 但避免了 cur == u32::MAX（n == 0）时中间加法的溢出。
        let block_end = cur | ((1u32 << n) - 1);
        out.push((cur, (32 - n) as u8));
        if block_end == hi {
            break;
        }
        cur = block_end + 1;
    }
    out
}

/// 同 [`range_to_cidrs4`]，IPv6（128 位）版本。
pub(crate) fn range_to_cidrs6(lo: u128, hi: u128) -> Vec<(u128, u8)> {
    let mut out = Vec::new();
    if lo > hi {
        return out;
    }
    let mut cur = lo;
    loop {
        let align: u32 = if cur == 0 { 128 } else { cur.trailing_zeros() };
        // 同上：floor(log2(rem+1))，rem+1 == 2^128 时直接取 128。
        let rem = hi - cur;
        let max_pow: u32 = if rem == u128::MAX {
            128
        } else {
            127 - (rem + 1).leading_zeros()
        };
        let n = align.min(max_pow);
        if n == 128 {
            // cur==0 且 hi==u128::MAX：::/0。
            out.push((0, 0));
            break;
        }
        // 同上：按位或避免 cur == u128::MAX（n == 0）时中间加法溢出。
        let block_end = cur | ((1u128 << n) - 1);
        out.push((cur, (128 - n) as u8));
        if block_end == hi {
            break;
        }
        cur = block_end + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 区间分解正确性：分解出的 CIDR 有序无重叠，并集恰好等于原区间。
    #[test]
    fn range_to_cidrs4_exact_cover() {
        let cases: [(u32, u32); 10] = [
            (0, u32::MAX),
            (0, 0),
            (u32::MAX, u32::MAX),
            (10, 10),
            (10, 11),
            (10, 13),
            (10, 14),
            (0x0a00_0000, 0x0aff_ffff),  // 10.0.0.0 - 10.255.255.255（/8）
            (0xc0a8_0000, 0xc0a8_ffff),  // 192.168.0.0 - 192.168.255.255（/16）
            (0x6440_0000, 0x647f_ffff),  // 100.64.0.0 - 100.127.255.255（/10）
        ];
        for &(lo, hi) in &cases {
            let cidrs = range_to_cidrs4(lo, hi);
            // 有序无重叠
            let mut sorted = cidrs.clone();
            sorted.sort_by_key(|&(a, _)| a);
            assert_eq!(cidrs, sorted, "区间 {lo:#x}-{hi:#x}");
            // 并集恰好覆盖 [lo, hi]（用位掩码直接算块尾，避免 prefix=0 溢出）
            let mut covered: Vec<(u64, u64)> = cidrs
                .iter()
                .map(|&(base, prefix)| {
                    // mask 限制在 32 位空间内：prefix=0 时若用 u64::MAX
                    // 会把块尾推到 2^64-1，导致 cursor+1 溢出。
                    let mask: u64 = if prefix == 0 {
                        0xFFFF_FFFF
                    } else {
                        (1u64 << (32 - prefix as u32)) - 1
                    };
                    let end = (base as u64) | mask;
                    (base as u64, end)
                })
                .collect();
            covered.sort();
            let mut cursor = lo as u64;
            for (b, e) in covered {
                assert_eq!(b, cursor, "区间 {lo:#x}-{hi:#x} 覆盖断裂于 {b:#x}");
                cursor = e + 1;
            }
            assert_eq!(cursor, hi as u64 + 1, "区间 {lo:#x}-{hi:#x} 覆盖不足/越界");
        }
    }

    #[test]
    fn range_to_cidrs6_exact_cover() {
        let cases: [(u128, u128); 4] = [
            (0, u128::MAX),
            (0, 0),
            (
                0xfc00_fd00_0000_0000_0000_0000_0000_0000,
                0xfc00_fdff_ffff_ffff_ffff_ffff_ffff_ffff,
            ),
            (
                0x2001_0db8_0000_0000_0000_0000_0000_0001,
                0x2001_0db8_0000_0000_0000_0000_0000_0100,
            ),
        ];
        for &(lo, hi) in &cases {
            let cidrs = range_to_cidrs6(lo, hi);
            let mut sorted = cidrs.clone();
            sorted.sort_by_key(|&(a, _)| a);
            assert_eq!(cidrs, sorted, "区间 {lo:#x}-{hi:#x}");
            let mut covered: Vec<(u128, u128)> = cidrs
                .iter()
                .map(|&(base, prefix)| {
                    let mask: u128 = if prefix == 0 {
                        u128::MAX
                    } else {
                        (1u128 << (128 - prefix as u32)) - 1
                    };
                    (base, base | mask)
                })
                .collect();
            covered.sort();
            let mut cursor = lo;
            for (b, e) in covered {
                assert_eq!(b, cursor, "区间 {lo:#x}-{hi:#x} 覆盖断裂于 {b:#x}");
                cursor = e.saturating_add(1);
            }
            assert_eq!(cursor, hi.saturating_add(1), "区间 {lo:#x}-{hi:#x} 覆盖不足");
        }
    }

    /// 私有网段逐一落入内置集合；集合条目数与声明一致。
    #[test]
    fn builtin_private_entries() {
        let mut next_set_id = 1u16;
        let mut out = CompiledKernelPlane::default();
        let (set_id, local_set_id) =
            register_builtin_private(&mut next_set_id, &mut out, &[]).unwrap();
        assert_eq!(set_id, 1);
        assert_eq!(local_set_id, 2);
        assert_eq!(
            out.lpm_entries.len(),
            BUILTIN_PRIVATE_V4.len() + BUILTIN_PRIVATE_V6.len()
        );
        // 192.168.0.0/16 → key = set_id(1) + ::ffff:c0a8:0000，前缀 112+16=128
        let expect_v4 = common::lpm_key(1, common::ipv4_mapped([192, 168, 0, 0]));
        assert!(out.lpm_entries.iter().any(|e| {
            e.prefix_len == common::LPM_V4_PREFIX_OFFSET + 16 && e.key == expect_v4
        }));
        // ::1/128 → set_id=1 + ::1，前缀 16+128=144
        let mut expect_v6 = [0u8; 16];
        expect_v6[15] = 1;
        assert!(out.lpm_entries.iter().any(|e| {
            e.prefix_len == 144 && e.key[0] == 0 && e.key[1] == 1 && e.key[2..] == expect_v6
        }));
        // 全部条目前缀 ≤ 144（内核 LPM 上限 = key 位数；超限会被 -E2BIG 拒收）
        assert!(out
            .lpm_entries
            .iter()
            .all(|e| e.prefix_len <= (common::LPM_KEY_LEN as u32) * 8));
    }

    /// parse_cidr 基本语义（v4 映射 / v6 原生 / 前缀越界）。
    #[test]
    fn parse_cidr_semantics() {
        let (addr, p) = parse_cidr("10.0.0.0/8").unwrap();
        assert_eq!(addr, common::ipv4_mapped([10, 0, 0, 0]));
        assert_eq!(p, 8);
        let (addr6, p6) = parse_cidr("fc00::/7").unwrap();
        assert_eq!(addr6[0], 0xfc);
        assert_eq!(p6, 7);
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("::1/129").is_err());
        assert!(parse_cidr("not-an-ip/8").is_err());
    }
}
