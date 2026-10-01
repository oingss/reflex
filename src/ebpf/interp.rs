//! MatchSet 状态机的纯 Rust 实现（与 `reflex-bpf::route_loop_cb` 逐行同构）。
//!
//! 用途：不依赖内核环境验证编译产物语义。`reflex-bpf` 的回调与本模块的
//! [`eval_match_sets`] 必须保持逐条对应——修改任一端时同步修改另一端，并
//! 补充本模块的单测覆盖新语义。

use reflex_ebpf_common::match_type;
use reflex_ebpf_common::MatchSet;

/// 连接输入（与 bpf 端 `RouteInput` 的路由相关字段一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnInput {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    /// IPPROTO_TCP(6) / IPPROTO_UDP(17)。
    pub proto: u8,
    /// 4 / 6。
    pub ipversion: u8,
}

/// LPM 查询闭包：`(set_id, addr) -> 是否命中`（最长前缀语义由实现方保证）。
pub type LpmLookup<'a> = &'a dyn Fn(u16, &[u8; 16]) -> bool;

/// 求值结果：`Some((verdict, mark))` = 内核面命中；`None` = 未命中
/// （内核端等价为裁决 PROXY 转用户态继续匹配）。
pub fn eval_match_sets(
    match_sets: &[MatchSet],
    lpm: LpmLookup<'_>,
    input: &ConnInput,
) -> Option<(u8, u32)> {
    let mut group_hit = false;
    let mut rule_ok = true;

    for ms in match_sets {
        match ms.ty {
            match_type::IP_SET => {
                if !group_hit && lpm(ms.value[0] as u16, &input.daddr) {
                    group_hit = true;
                }
            }
            match_type::SOURCE_IP_SET => {
                if !group_hit && lpm(ms.value[0] as u16, &input.saddr) {
                    group_hit = true;
                }
            }
            match_type::PORT => {
                let (start, end) = (ms.value[0], ms.value[1]);
                if !group_hit && input.dport as u32 >= start && input.dport as u32 <= end {
                    group_hit = true;
                }
            }
            match_type::L4PROTO => {
                if !group_hit && input.proto == ms.value[0] as u8 {
                    group_hit = true;
                }
            }
            match_type::IP_VERSION => {
                if !group_hit && input.ipversion == ms.value[0] as u8 {
                    group_hit = true;
                }
            }
            match_type::GROUP_END => {
                if !group_hit {
                    rule_ok = false;
                }
                group_hit = false;
            }
            match_type::TERMINATE => {
                let hit = if ms.invert != 0 { !rule_ok } else { rule_ok };
                if hit {
                    return Some((ms.outbound, ms.mark));
                }
                // 本条规则未生效：复位状态，继续下一条规则。
                rule_ok = true;
                group_hit = false;
            }
            // 未知类型：与 bpf 端一致，视为内部错误（交用户态兜底）。
            _ => return None,
        }
    }
    // 扫完未命中任何 TERMINATE → 内核面未命中。
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::compiler::CompiledKernelPlane;
    use crate::ebpf::compiler::KernelRuleset;
    use crate::ebpf::compiler::LpmEntry;
    use crate::ebpf::compiler::compile_kernel_plane;
    use reflex_ebpf_common::ipv4_mapped;
    use reflex_ebpf_common::KERNEL_OUTBOUND_BLOCK;
    use reflex_ebpf_common::KERNEL_OUTBOUND_DIRECT;

    /// 构造纯 IP 规则集（行式源格式：ip-cidr / ip-cidr6，v4/v6 自动分流）。
    fn ruleset(cidrs: &[&str]) -> crate::ruleset::matcher::RuleSet {
        let text = cidrs
            .iter()
            .map(|c| {
                if c.contains(':') {
                    format!("ip-cidr6: {c}")
                } else {
                    format!("ip-cidr: {c}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        crate::ruleset::matcher::RuleSet::from_text(&text).unwrap()
    }

    fn input_v4(daddr: [u8; 4], dport: u16, proto: u8) -> ConnInput {
        ConnInput {
            saddr: ipv4_mapped([192, 168, 1, 2]),
            daddr: ipv4_mapped(daddr),
            sport: 40000,
            dport,
            proto,
            ipversion: 4,
        }
    }

    fn input_v6(daddr: [u8; 16]) -> ConnInput {
        ConnInput {
            saddr: [0u8; 16],
            daddr,
            sport: 40000,
            dport: 443,
            proto: 6,
            ipversion: 6,
        }
    }

    /// 测试用 LPM 查询：对条目做最长前缀语义的简化匹配（逐位比较前缀位）。
    fn lpm_lookup_from(
        entries: &[LpmEntry],
    ) -> impl Fn(u16, &[u8; 16]) -> bool + '_ {
        move |set_id: u16, addr: &[u8; 16]| {
            entries
                .iter()
                .any(|e| e.key[..2] == [(set_id >> 8) as u8, (set_id & 0xff) as u8] && {
                    // 前缀匹配：prefix_len 含 16 位 set_id；addr 部分逐位比较。
                    let data = &e.key[2..];
                    let bits = (e.prefix_len - 16).min(128) as usize;
                    (0..bits).all(|i| {
                        let byte = i / 8;
                        let bit = 7 - (i % 8);
                        data[byte] & (1 << bit) == addr[byte] & (1 << bit)
                    })
                })
        }
    }

    fn eval_plane(
        block: &[&crate::ruleset::matcher::RuleSet],
        direct: &[&crate::ruleset::matcher::RuleSet],
        input: &ConnInput,
    ) -> (Option<(u8, u32)>, CompiledKernelPlane) {
        let block_ks: Vec<KernelRuleset<'_>> = block
            .iter()
            .map(|r| KernelRuleset {
                tag: "block-test",
                ruleset: r,
            })
            .collect();
        let direct_ks: Vec<KernelRuleset<'_>> = direct
            .iter()
            .map(|r| KernelRuleset {
                tag: "direct-test",
                ruleset: r,
            })
            .collect();
        let compiled = compile_kernel_plane(&block_ks, &direct_ks, &[]).unwrap();
        let r = {
            let lookup = lpm_lookup_from(&compiled.lpm_entries);
            eval_match_sets(&compiled.match_sets, &lookup, input)
        };
        (r, compiled)
    }

    #[test]
    fn direct_ruleset_hit_and_miss() {
        let cn = ruleset(&["10.0.0.0/8"]);
        let (hit, compiled) = eval_plane(&[], &[&cn], &input_v4([10, 1, 2, 3], 443, 6));
        assert_eq!(hit, Some((KERNEL_OUTBOUND_DIRECT, 0)));
        assert_eq!(compiled.direct_rulesets, 1);
        assert_eq!(compiled.block_rulesets, 0);

        let (miss, _) = eval_plane(&[], &[&cn], &input_v4([8, 8, 8, 8], 443, 6));
        assert_eq!(miss, None, "内核面未命中应返回 None（=PROXY 转用户态）");
    }

    #[test]
    fn block_ruleset_hit() {
        let ads = ruleset(&["203.0.113.0/24"]);
        let (hit, _) = eval_plane(&[&ads], &[], &input_v4([203, 0, 113, 9], 443, 6));
        assert_eq!(hit, Some((KERNEL_OUTBOUND_BLOCK, 0)));
    }

    /// BLOCK 组排在 DIRECT 组之前：同一 IP 同时命中两个裁决组时 BLOCK 优先。
    #[test]
    fn block_wins_over_direct() {
        let block = ruleset(&["10.0.0.0/8"]);
        let direct = ruleset(&["10.1.0.0/16"]);
        let (hit, _) = eval_plane(&[&block], &[&direct], &input_v4([10, 1, 2, 3], 443, 6));
        assert_eq!(hit, Some((KERNEL_OUTBOUND_BLOCK, 0)));
    }

    /// 内置私有网段直连：无用户规则集时 192.168.x 也由内核裁决 DIRECT。
    #[test]
    fn builtin_private_direct() {
        let (hit, compiled) = eval_plane(&[], &[], &input_v4([192, 168, 1, 1], 443, 6));
        assert_eq!(hit, Some((KERNEL_OUTBOUND_DIRECT, 0)));
        assert_eq!(compiled.direct_rulesets, 0, "内置私有集合不计入用户声明数");
        assert_eq!(compiled.block_rulesets, 0);
        assert!(compiled.lpm_total > 0);

        // 回环 / ULA v6 同样直连。
        let mut loopback = [0u8; 16];
        loopback[15] = 1;
        let (hit6, _) = eval_plane(&[], &[], &input_v6(loopback));
        assert_eq!(hit6, Some((KERNEL_OUTBOUND_DIRECT, 0)));
        let mut ula = [0u8; 16];
        ula[0] = 0xfc;
        let (hit_ula, _) = eval_plane(&[], &[], &input_v6(ula));
        assert_eq!(hit_ula, Some((KERNEL_OUTBOUND_DIRECT, 0)));
    }

    /// 公网地址未命中任何集合（含内置私有）→ None → PROXY。
    #[test]
    fn public_ip_misses_everything() {
        for daddr in [[8u8, 8, 8, 8], [1, 1, 1, 1], [114, 114, 114, 114]] {
            let (miss, _) = eval_plane(&[], &[], &input_v4(daddr, 443, 6));
            assert_eq!(miss, None, "daddr={daddr:?}");
        }
    }

    /// IPv6 规则集（fc00::/7 命中 ULA；非 ULA 未命中）。
    #[test]
    fn ipv6_ruleset() {
        let ula = ruleset(&["fc00::/7"]);
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[15] = 0x42;
        let (hit, _) = eval_plane(&[], &[&ula], &input_v6(addr));
        assert_eq!(hit, Some((KERNEL_OUTBOUND_DIRECT, 0)));

        let mut public = [0u8; 16];
        public[0] = 0x20;
        public[1] = 0x01;
        let (miss, _) = eval_plane(&[], &[&ula], &input_v6(public));
        assert_eq!(miss, None);
    }

    /// 相邻 CIDR 在 RuleSet 内合并为连续区间后，区间分解必须还原精确覆盖
    /// （10.0.0.0/8 + 11.0.0.0/8 合并为 10.0.0.0-11.255.255.255，
    /// 分解回 10/8 + 11/8 两块，两端地址都命中）。
    #[test]
    fn merged_range_decomposition_still_hits() {
        let cn = ruleset(&["10.0.0.0/8", "11.0.0.0/8"]);
        for daddr in [[10u8, 0, 0, 1], [10, 255, 255, 254], [11, 127, 0, 1], [11, 255, 255, 255]] {
            let (hit, _) = eval_plane(&[], &[&cn], &input_v4(daddr, 443, 6));
            assert_eq!(hit, Some((KERNEL_OUTBOUND_DIRECT, 0)), "daddr={daddr:?}");
        }
        let (miss, _) = eval_plane(&[], &[&cn], &input_v4([12, 0, 0, 1], 443, 6));
        assert_eq!(miss, None);
    }

    /// 空内核面（无用户规则集）也保留内置私有直连。
    #[test]
    fn empty_plane_still_has_private_direct() {
        let compiled = compile_kernel_plane(&[], &[], &[]).unwrap();
        assert_eq!(compiled.match_sets.len(), 3); // [IP_SET private][GROUP_END][TERMINATE]
        assert_eq!(compiled.direct_rulesets, 0);
        assert_eq!(compiled.block_rulesets, 0);
    }
}
