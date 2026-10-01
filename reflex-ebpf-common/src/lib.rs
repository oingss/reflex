//! reflex eBPF 数据面共享类型（用户态编译器 ↔ 内核态 bpf 程序共用）。
//!
//! 本 crate 为 `no_std`，仅包含 `#[repr(C)]` 内存布局类型与常量，供两端
//! 直接按字节解释，保证 ABI 一致：
//!
//! - 用户态（`src/ebpf/compiler.rs`）：把 `RouteRuleConfig` 前缀编译为
//!   [`MatchSet`] 序列 + LPM 条目，经 aya 写入 bpf map；
//! - 内核态（`reflex-bpf`）：`bpf_loop` 逐条扫描 [`MatchSet`]，状态机
//!   求值后输出 [`KERNEL_OUTBOUND_DIRECT`] / [`KERNEL_OUTBOUND_PROXY`] /
//!   [`KERNEL_OUTBOUND_BLOCK`] 三种裁决。
//!
//! ## 匹配语义（与用户态 Router 对齐）
//!
//! 一条路由规则 = 条件组（AND）× 组内多值（OR）× 规则级 `invert`。
//! 编码为线性序列：
//!
//! ```text
//! [IpSet cn]  [Port 443] [Port 80]  [GroupEnd]  [Terminate outbound=direct]
//!  └─条件组1─┘ └──────条件组2（OR）──────┘  └─组收尾─┘ └────规则终止项────┘
//! ```
//!
//! 内核状态机：条件项在 `!group_hit` 时求值，命中置 `group_hit=1`；
//! `GroupEnd` 执行 `rule_ok &= group_hit` 并复位 `group_hit`；
//! `Terminate` 按 `invert` 取反 `rule_ok` 决定是否生效，未生效则清空状态
//! 继续下一条规则。

#![no_std]

/// 单条规则最多展开的 MatchSet 数量（含 GroupEnd 与 Terminate）。
pub const MAX_MATCH_SET_LEN: u32 = 512;

/// LPM trie 最大条目数（一个 trie 承载所有 IP 集合，set_id 前缀隔离子树）。
pub const MAX_LPM_ENTRIES: u32 = 65536;

/// TCP conn_state 缓存条目上限（LRU 自动淘汰）。
pub const MAX_CONN_STATE_ENTRIES: u32 = 262144;

/// eBPF 引流标记：PROXY 裁决的 skb 写入该 fwmark，
/// 配套策略路由 `ip rule fwmark <mark>/<mark> lookup <table>` → `local`。
pub const DEFAULT_TPROXY_MARK: u32 = 0x2023;

/// fwmark 策略路由使用的路由表号。
pub const FWMARK_TABLE_ID: u32 = 2023;

/// 内核裁决：直连（`TC_ACT_OK` 放行，mark 置 0 走主路由表）。
pub const KERNEL_OUTBOUND_DIRECT: u8 = 254;
/// 内核裁决：交用户态（写 fwmark → local 表 → tproxy 入站，用户态二次路由）。
pub const KERNEL_OUTBOUND_PROXY: u8 = 253;
/// 内核裁决：阻断（`TC_ACT_SHOT`）。
pub const KERNEL_OUTBOUND_BLOCK: u8 = 255;

/// MatchSet 条目类型（`MatchSet.ty`）。
pub mod match_type {
    /// 目标 IP 集合：`value[0]` = LPM 集合号（set_id）。
    pub const IP_SET: u8 = 1;
    /// 源 IP 集合：`value[0]` = LPM 集合号。
    pub const SOURCE_IP_SET: u8 = 2;
    /// 目标端口范围：`value[0]`=start，`value[1]`=end（主机字节序，闭区间）。
    pub const PORT: u8 = 3;
    /// 传输层协议：`value[0]` = IPPROTO_TCP(6) / IPPROTO_UDP(17)。
    pub const L4PROTO: u8 = 5;
    /// IP 版本：`value[0]` = 4 / 6。
    pub const IP_VERSION: u8 = 6;
    /// 条件组收尾：`rule_ok &= group_hit; group_hit = 0`。
    pub const GROUP_END: u8 = 7;
    /// 规则终止项：`outbound` = 内核裁决，`invert` = 规则级取反，`mark` = fwmark。
    pub const TERMINATE: u8 = 8;
}

/// 单条匹配项（24 字节，两端 `#[repr(C)]` 对齐）。
///
/// `value` 按 `ty` 解释（小端机器上 `u32` 数组即两端一致的布局）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchSet {
    pub value: [u32; 4],
    /// 条目类型，见 [`match_type`]。
    pub ty: u8,
    /// 仅 `TERMINATE` 有意义：规则级取反（对齐 `RouteRuleConfig::invert`）。
    pub invert: u8,
    /// 仅 `TERMINATE` 有意义：内核裁决（见 `KERNEL_OUTBOUND_*`）。
    pub outbound: u8,
    /// 保留对齐，恒为 0。
    pub reserved: u8,
    /// 仅 `TERMINATE` 有意义：direct 裁决可携带的 fwmark（阶段 0 恒为 0）。
    pub mark: u32,
}

impl MatchSet {
    pub const fn new_cond(ty: u8, v0: u32, v1: u32) -> Self {
        Self {
            value: [v0, v1, 0, 0],
            ty,
            invert: 0,
            outbound: 0,
            reserved: 0,
            mark: 0,
        }
    }

    pub const fn new_terminate(outbound: u8, invert: bool, mark: u32) -> Self {
        Self {
            value: [0, 0, 0, 0],
            ty: match_type::TERMINATE,
            invert: invert as u8,
            outbound,
            reserved: 0,
            mark,
        }
    }

    pub const fn new_group_end() -> Self {
        Self::new_cond(match_type::GROUP_END, 0, 0)
    }
}

/// 五元组键（TCP conn_state 缓存）。地址统一为 16 字节 IPv6 形式
/// （IPv4 使用 `::ffff:a.b.c.d` 映射，`proto` 为 IPPROTO 值）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TuplesKey {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub _pad: u8,
}

/// conn_state 缓存值：首包裁决（阶段 0 仅缓存 TCP；UDP 每包求值）。
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnEntry {
    /// `KERNEL_OUTBOUND_*` 裁决。
    pub verdict: u8,
    pub _pad: [u8; 3],
    /// direct 裁决携带的 fwmark（阶段 0 恒为 0）。
    pub mark: u32,
}

/// LPM 键：`data = set_id(2B, 大端) + addr(16B IPv6 形式)`。
///
/// `set_id` 置于前缀树最高位，天然把不同 IP 集合隔到互不干扰的子树；
/// IPv4 地址统一映射为 `::ffff:a.b.c.d`（前缀长度 +96）。
pub const LPM_KEY_LEN: usize = 18;

/// IPv4 前缀在 LPM 键中的偏移（set_id 16 bit + mapped 前缀 96 bit）。
pub const LPM_V4_PREFIX_OFFSET: u32 = 16 + 96;

/// 构造 LPM 键：`set_id` 大端放最高 16 位，`addr` 为 IPv6 形式地址。
pub const fn lpm_key(set_id: u16, addr: [u8; 16]) -> [u8; LPM_KEY_LEN] {
    let mut out = [0u8; LPM_KEY_LEN];
    out[0] = (set_id >> 8) as u8;
    out[1] = (set_id & 0xff) as u8;
    let mut i = 0;
    while i < 16 {
        out[2 + i] = addr[i];
        i += 1;
    }
    out
}

/// IPv4 → `::ffff:a.b.c.d`（16 字节）。
pub const fn ipv4_mapped(a: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a[0], a[1], a[2], a[3],
    ]
}

/// 内核 CONFIG map 键：tproxy fwmark（PROXY 裁决写入 skb->mark 的值）。
pub const CONFIG_KEY_MARK: u32 = 0;

/// 内核 CONFIG map 键：全局 DNS 劫持开关（对齐 `route.hijack_dns`：
/// 非 0 时目标端口 53 的流量直接裁决为 PROXY，交用户态 DNS 模块）。
pub const CONFIG_KEY_DNS_HIJACK: u32 = 1;

/// 内核 CONFIG map 键：reflex 自身出站的 SO_MARK 值（wan 模式专用）。
///
/// cgroup connect/sendmsg hook 命中该 mark 时直接放行——reflex 到上游
/// 代理服务器的出站连接不能被再次引流（回环）。用户态在 wan 模式下写入
/// `route.default_mark`（reflex 全局出站 mark），内核 hook 用
/// `bpf_getsockopt(SO_MARK)` 与之比对识别自身连接。0 表示未配置。
pub const CONFIG_KEY_ROUTING_MARK: u32 = 2;

/// 内核 CONFIG map 键：tproxy 监听侧回包 fwmark（wan 模式专用）。
///
/// wan 回环路径上，客户端包（socket SO_MARK = tproxy mark）与监听侧回包
/// （listener / writeback socket 的 SO_MARK = reply mark）都经策略路由回环
/// 到 lo ingress，五元组完全相同（src = dst = 原始目标 IP），仅凭包内容
/// 无法区分方向。lo ingress 程序按 mark 分流：client mark → `bpf_sk_assign`
/// 绑监听 socket；reply mark → 原样放行走既有连接查找。缺失（0）时 hook
/// 不做该跳过检查。0 表示未配置。
pub const CONFIG_KEY_REPLY_MARK: u32 = 3;

/// 内核 CONFIG map 键：本机地址 LPM 集合号。
///
/// DNS 劫持（dport==53）用它区分"发往本机地址:53"的查询：这类查询不
/// 劫持、走内置直连交回内核本地交付（本机 dnsmasq 等真实 DNS 服务代答）。
/// tproxy DNS 代答回包需 bind 原始目标地址（本机 :53），与本机已监听的
/// DNS 服务冲突（EADDRINUSE），客户端永远收不到回包。0 表示未配置
/// （保持劫持全部 dport 53 的旧语义）。
pub const CONFIG_KEY_LOCAL_SET_ID: u32 = 4;

/// 监听 socket 表（`LISTEN_SOCKETS`，BPF_MAP_TYPE_SOCKMAP）key：IPv4 TCP 监听。
pub const LISTEN_KEY_TCP4: u32 = 0;
/// 监听 socket 表 key：UDP 监听（双栈 socket，v4 走 v4-mapped）。
pub const LISTEN_KEY_UDP: u32 = 1;
/// 监听 socket 表 key：IPv6 TCP 监听。
pub const LISTEN_KEY_TCP6: u32 = 2;

// ── aya::Pod 实现（仅用户态）────────────────────────────────────────────
// 三个类型均为 #[repr(C)] 且全字段 u8/u16/u32 定长，无内部填充指针，
// 逐字节可安全复制。实现在本 crate（类型定义处）以通过孤儿规则——
// loader 侧无法为外部类型实现外部 trait。
#[cfg(feature = "aya-pod")]
mod aya_pod_impls {
    use super::{ConnEntry, MatchSet, TuplesKey};

    unsafe impl aya::Pod for MatchSet {}
    unsafe impl aya::Pod for TuplesKey {}
    unsafe impl aya::Pod for ConnEntry {}
}
