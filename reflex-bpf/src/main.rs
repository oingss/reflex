#![no_std]
#![no_main]

//! reflex eBPF 数据面：双部署模式（对应 dae 的 "Real Direct" 架构）。
//!
//! ## lan 模式（tc ingress，阶段 0）：网关/旁路由
//!
//! 在数据包进入 TCP/IP 协议栈之前完成路由预判，三种裁决：
//!
//! | 裁决 | 动作 | 说明 |
//! | --- | --- | --- |
//! | `DIRECT` | `skb->mark = mark`，`TC_ACT_OK` | 直连流量留在内核 L3 转发，不进用户态 |
//! | `PROXY` | `skb->mark = tproxy_mark`，`TC_ACT_OK` | fwmark 策略路由送 local 表 → tproxy 入站（用户态二次路由） |
//! | `BLOCK` | `TC_ACT_SHOT` | 静默丢弃 |
//!
//! PROXY 包在 tc 层额外做 `bpf_sk_assign`（`LISTEN_SOCKETS`，见下）——本地
//! 交付时内核按原始目的端口查 listener 必然落空，没有 sk_assign 就没有
//! 流量能进入 tproxy 入站。
//!
//! ## wan 模式（cgroup sock_addr，阶段 2）：本机 / Android
//!
//! tc ingress 只能抓**转发**流量，抓不到本机 socket。wan 模式把 hook 挪到
//! cgroup v2 的 `connect4/6` + `sendmsg4/6`（sock_addr 类，每 socket 连接/
//! 每数据报触发一次），直接对目标五元组求值：
//!
//! | 裁决 | 动作 | 说明 |
//! | --- | --- | --- |
//! | `DIRECT` | 放行（残留 tproxy_mark 时清 0） | socket 走主路由表直连 |
//! | `PROXY` | `setsockopt(SO_MARK, tproxy_mark)` 后放行 | fwmark 策略路由送 local 表 → tproxy 入站 |
//! | `BLOCK` | 返回 0（`EPERM`） | 连接/数据报被拒绝 |
//!
//! 回环防护：reflex 自身出站 socket 带全局 `routing_mark`（用户态写入
//! `CONFIG[CONFIG_KEY_ROUTING_MARK]` = `route.default_mark`），hook 读
//! `bpf_getsockopt(SO_MARK)` 与之比对，命中即放行——reflex 到上游代理
//! 服务器的连接绝不能被二次引流。已托管 socket（带 tproxy_mark / reply
//! mark）同样直接放行，见 `wan_route` 步骤 1.5。
//!
//! wan 模式的交付闭环由 `reflex_lo_ingress`（lo ingress + sk_assign）完成，
//! 见其文档。
//!
//! ## 共用规则匹配
//!
//! `bpf_loop` 扫描 `ROUTING`（用户态编译器产出的 MatchSet 线性序列），
//! 状态机语义见 `reflex-ebpf-common` 模块文档。IP 集合走 LPM trie
//! （set_id 置于前缀树最高位隔离各集合）。lan 模式 TCP 首包（SYN）裁决
//! 写入 `CONN_STATE`（LRU），established 包直接复用；UDP 每包求值；
//! wan 模式无缓存（hook 天然每连接/每数据报一次）。
//!
//! 语义边界：仅加载规则列表的可编译前缀；前缀之外（含全部域名/进程/
//! clash_mode 条件规则）由用户态 Router 兜底——未命中内核前缀的包一律
//! 裁决 PROXY 转用户态，保证与纯用户态匹配结果一致。
//!
//! 要求：内核 ≥ 5.17（`bpf_loop`）；lan 模式挂 LAN 侧接口 tc ingress，
//! wan 模式挂 cgroup v2（`SO_MARK` setsockopt 需内核 ≥ 5.12）+ lo tc
//! ingress（`bpf_sk_assign`：TCP ≥ 5.7，UDP ≥ 5.13）。

use aya_ebpf::{
    helpers::{bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_release},
    macros::{classifier, cgroup_sock_addr, map},
    maps::{
        array::Array,
        hash_map::{HashMap, LruHashMap},
        lpm_trie::{Key, LpmTrie},
        sock_map::SockMap,
    },
    programs::{SockAddrContext, TcContext},
};
use core::ffi::c_void;
use reflex_ebpf_common::*;

const TC_ACT_OK: i32 = 0;
const TC_ACT_SHOT: i32 = 2;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// ── maps ────────────────────────────────────────────────────────────────────

/// 路由规则序列（用户态编译器写入；META[0] 为有效长度）。
#[map]
static ROUTING: Array<MatchSet> = Array::with_max_entries(MAX_MATCH_SET_LEN, 0);

/// 有效 MatchSet 数量：`META[0]`。用户态更新规则时先写 ROUTING 再写 META。
#[map]
static META: Array<u32> = Array::with_max_entries(2, 0);

/// 全部 IP 集合共用一个 LPM trie（key 前两位为 set_id，隔离各集合子树）。
///
/// key 类型 = [`common::lpm_key`] 产出的 18 字节数组（2B **大端** set_id +
/// 16B 地址），与用户态 loader 写入的 key 逐字节同构。切勿改回
/// `struct LpmData { set_id: u16, .. }`：`u16` 字段按**编译目标本机序**
/// 序列化（el 小端目标下高低字节倒置），与用户态大端 key 永远对不上，
/// 所有 IP_SET 查询恒 miss（geoip/私网/本机直连全失效，内核面退化成
/// 全量 PROXY）。
#[map]
static LPM: LpmTrie<[u8; common::LPM_KEY_LEN], u32> =
    LpmTrie::with_max_entries(MAX_LPM_ENTRIES, 0);

/// 运行时配置：`CONFIG[CONFIG_KEY_MARK]`=tproxy fwmark，
/// `CONFIG[CONFIG_KEY_DNS_HIJACK]`=全局 DNS 劫持开关。
#[map]
static CONFIG: HashMap<u32, u32> = HashMap::with_max_entries(8, 0);

/// TCP 首包裁决缓存（LRU 自动淘汰，写满后新连接退化为每包求值）。
#[map]
static CONN_STATE: LruHashMap<TuplesKey, ConnEntry> =
    LruHashMap::with_max_entries(MAX_CONN_STATE_ENTRIES, 0);

/// tproxy 监听 socket 表（`BPF_MAP_TYPE_SOCKMAP`，用户态 loader 写入监听 fd）。
///
/// key（对齐 dae `listen_socket_map`）：0=tcp4 监听，1=udp 监听（双栈），
/// 2=tcp6 监听。PROXY 引流包在 tc 层 `bpf_sk_assign` 绑定到该 socket——
/// 本地交付时内核按**原始目的端口**查找 listener 必然落空（监听的是
/// tproxy_port），没有这一步，引流包永远进不了 tproxy 入站（等价于
/// iptables/nftables TPROXY target 完成的 socket 绑定，见 dae
/// `tproxy_dae0peer_ingress` 的 `assign_listener`）。
#[map]
static LISTEN_SOCKETS: SockMap = SockMap::with_max_entries(3, 0);

// ── LPM key（prefix_len + 2B set_id + 16B addr）─────────────────────────────
//
// key 构造统一走 [`common::lpm_key`]（大端 set_id，见 LPM map 文档）。

// ── 网络头（仅读取路由所需字段，字节序转换由调用方完成）─────────────────────

#[repr(C)]
struct EthHdr {
    #[allow(dead_code)]
    h_dest: [u8; 6],
    #[allow(dead_code)]
    h_source: [u8; 6],
    h_proto: u16,
}

#[repr(C)]
struct Ipv4Hdr {
    /// 高 4 位 version，低 4 位 IHL。
    ihl_version: u8,
    #[allow(dead_code)]
    tos: u8,
    #[allow(dead_code)]
    tot_len: u16,
    #[allow(dead_code)]
    id: u16,
    /// 高 3 位 flags + 低 13 位 fragment offset（网络序）。
    frag_off: u16,
    #[allow(dead_code)]
    ttl: u8,
    protocol: u8,
    #[allow(dead_code)]
    check: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
}

#[repr(C)]
struct Ipv6Hdr {
    /// version / traffic class / flow label（4 字节，本程序不使用）。
    _vtfl: [u8; 4],
    #[allow(dead_code)]
    payload_len: u16,
    nexthdr: u8,
    #[allow(dead_code)]
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

#[repr(C)]
struct TcpHdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    seq: u32,
    #[allow(dead_code)]
    ack_seq: u32,
    /// byte12 = doff<<4 | reserved，byte13 = flags。
    doff_flags: [u8; 2],
    #[allow(dead_code)]
    window: u16,
    #[allow(dead_code)]
    check: u16,
    #[allow(dead_code)]
    urg_ptr: u16,
}

#[repr(C)]
struct UdpHdr {
    source: u16,
    dest: u16,
    #[allow(dead_code)]
    len: u16,
    #[allow(dead_code)]
    check: u16,
}

/// 解析结果：进入路由状态机所需的最小输入。
struct RouteInput {
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
    proto: u8,
    ipversion: u8,
    /// TCP 且为 SYN 且无 ACK（新建连接，裁决后写入 conn_state）。
    is_new_tcp: bool,
    is_tcp: bool,
}

// ── tc 入口 ─────────────────────────────────────────────────────────────────

#[classifier]
pub fn reflex_tc_ingress(mut ctx: TcContext) -> i32 {
    match try_reflex_tc_ingress(&mut ctx) {
        Ok(ret) => ret,
        // 解析失败（含 nonlinear skb 越界）：放行。宁可漏分流也不断网——
        // 本程序只挂 LAN ingress，漏分流的包进入协议栈后按主路由表转发。
        Err(_) => TC_ACT_OK,
    }
}

fn try_reflex_tc_ingress(ctx: &mut TcContext) -> Result<i32, i64> {
    let eth: EthHdr = ctx.load(0)?;
    // h_proto 是网络序原始值，而 ETHERTYPE_* 常量是主机序：必须先 from_be，
    // 否则小端机器（x86_64/aarch64）上 IPv4 读出 0x0008 永远匹配不到 0x0800，
    // 所有包都落入 `_ => TC_ACT_OK` 被原样放行，内核面整体失效。
    let (ip_offset, input) = match u16::from_be(eth.h_proto) {
        ETHERTYPE_IPV4 => {
            let ip: Ipv4Hdr = ctx.load(14)?;
            // 分片（MF 置位或 fragment offset 非 0）不判定：TC_ACT_OK 原样放行。
            // 注意必须屏蔽 DF（0x4000）：现代 TCP/QUIC 包几乎都置 DF，
            // 旧写法 `frag_off != 0` 会把它们全部当分片放行，导致内核面
            // 对绝大多数流量失效（CONN_STATE 恒空、DIRECT 集合从不命中）。
            if (u16::from_be(ip.frag_off) & 0x3fff) != 0 {
                return Ok(TC_ACT_OK);
            }
            // 下方 L4 头偏移按 IHL=5（20 字节）硬编码，带 IP 选项的包放行。
            if (ip.ihl_version & 0x0f) != 5 {
                return Ok(TC_ACT_OK);
            }
            let (proto, input) = match ip.protocol {
                IPPROTO_TCP => {
                    let tcp: TcpHdr = ctx.load(14 + 20)?;
                    let flags = tcp.doff_flags[1];
                    let input = RouteInput {
                        saddr: ipv4_mapped(ip.saddr),
                        daddr: ipv4_mapped(ip.daddr),
                        sport: u16::from_be(tcp.source),
                        dport: u16::from_be(tcp.dest),
                        proto: IPPROTO_TCP,
                        ipversion: 4,
                        is_new_tcp: (flags & 0x02) != 0 && (flags & 0x10) == 0,
                        is_tcp: true,
                    };
                    (IPPROTO_TCP, input)
                }
                IPPROTO_UDP => {
                    let udp: UdpHdr = ctx.load(14 + 20)?;
                    let input = RouteInput {
                        saddr: ipv4_mapped(ip.saddr),
                        daddr: ipv4_mapped(ip.daddr),
                        sport: u16::from_be(udp.source),
                        dport: u16::from_be(udp.dest),
                        proto: IPPROTO_UDP,
                        ipversion: 4,
                        is_new_tcp: false,
                        is_tcp: false,
                    };
                    (IPPROTO_UDP, input)
                }
                // ICMP 等其它协议不在分流范围内（icmp 规则仅 TUN 入站可命中）。
                _ => return Ok(TC_ACT_OK),
            };
            let _ = proto;
            (14 + 20, input)
        }
        ETHERTYPE_IPV6 => {
            let ip: Ipv6Hdr = ctx.load(14)?;
            let (proto, input) = match ip.nexthdr {
                IPPROTO_TCP => {
                    let tcp: TcpHdr = ctx.load(14 + 40)?;
                    let flags = tcp.doff_flags[1];
                    let input = RouteInput {
                        saddr: ip.saddr,
                        daddr: ip.daddr,
                        sport: u16::from_be(tcp.source),
                        dport: u16::from_be(tcp.dest),
                        proto: IPPROTO_TCP,
                        ipversion: 6,
                        is_new_tcp: (flags & 0x02) != 0 && (flags & 0x10) == 0,
                        is_tcp: true,
                    };
                    (IPPROTO_TCP, input)
                }
                IPPROTO_UDP => {
                    let udp: UdpHdr = ctx.load(14 + 40)?;
                    let input = RouteInput {
                        saddr: ip.saddr,
                        daddr: ip.daddr,
                        sport: u16::from_be(udp.source),
                        dport: u16::from_be(udp.dest),
                        proto: IPPROTO_UDP,
                        ipversion: 6,
                        is_new_tcp: false,
                        is_tcp: false,
                    };
                    (IPPROTO_UDP, input)
                }
                _ => return Ok(TC_ACT_OK),
            };
            let _ = proto;
            (14 + 40, input)
        }
        // ARP / VLAN 等：不在分流范围，原样放行。
        _ => return Ok(TC_ACT_OK),
    };
    let _ = ip_offset;

    // IPv4 映射地址::ffff:0:0/96 段不会是真实目标，纯内部约定。
    apply_verdict(ctx, &input)
}

// ── lo ingress（wan 模式）───────────────────────────────────────────────────

/// wan 模式：lo ingress。
///
/// cgroup hook 打了 tproxy mark 的本机出站包经 fwmark 策略路由回环
/// （`ip rule fwmark → local default dev lo`），包从 lo ingress 进入本地
/// 交付路径。此时内核按**原始目的端口**做 socket 查找必然落空（监听的是
/// tproxy_port），必须在此 `bpf_sk_assign` 绑定监听 socket，否则引流包被
/// RST / ICMP 丢弃，tproxy 入站永远收不到流量。
///
/// mark 分流（回环包两侧五元组完全相同——src = dst = 原始目标 IP，无法凭
/// 包内容区分方向，只能靠 mark）：
/// - **client mark**（`CONFIG[CONFIG_KEY_MARK]`）：应用侧包。TCP 仅 SYN
///   需要绑定（established 包走内核既有连接查找即可命中 accept 出的子
///   socket），UDP 每包绑定；
/// - **reply mark** / reflex 自身出站 mark / 普通 loopback 流量：mark 不
///   匹配，原样放行——UDP 回包若被误绑回 listener 会形成自环。
///
/// 注意 lo 没有链路层头，skb->data 从 IP 头开始，不能复用 tc ingress 的
/// eth 解析。
#[classifier]
pub fn reflex_lo_ingress(mut ctx: TcContext) -> i32 {
    match try_reflex_lo_ingress(&mut ctx) {
        Ok(ret) => ret,
        // 解析失败：放行宁漏勿断（mark 过滤已把范围限到引流包，漏掉只影响单包）。
        Err(_) => TC_ACT_OK,
    }
}

fn try_reflex_lo_ingress(ctx: &mut TcContext) -> Result<i32, i64> {
    let client_mark = tproxy_mark();
    if client_mark == 0 {
        return Ok(TC_ACT_OK);
    }
    // __sk_buff.mark：本机出站包携带 socket 的 SO_MARK。
    let mark = unsafe { (*ctx.skb.skb).mark };
    if mark != client_mark {
        return Ok(TC_ACT_OK);
    }

    // lo 无链路层头：IP 版本取首字节高 4 位（避免 __sk_buff.protocol 的
    // 字节序歧义）。
    match ctx.load::<u8>(0)? >> 4 {
        4 => {
            let ip: Ipv4Hdr = ctx.load(0)?;
            if (u16::from_be(ip.frag_off) & 0x3fff) != 0 {
                return Ok(TC_ACT_OK);
            }
            if (ip.ihl_version & 0x0f) != 5 {
                return Ok(TC_ACT_OK);
            }
            let input = match ip.protocol {
                IPPROTO_TCP => {
                    let tcp: TcpHdr = ctx.load(20)?;
                    let flags = tcp.doff_flags[1];
                    RouteInput {
                        saddr: ipv4_mapped(ip.saddr),
                        daddr: ipv4_mapped(ip.daddr),
                        sport: u16::from_be(tcp.source),
                        dport: u16::from_be(tcp.dest),
                        proto: IPPROTO_TCP,
                        ipversion: 4,
                        is_new_tcp: (flags & 0x02) != 0 && (flags & 0x10) == 0,
                        is_tcp: true,
                    }
                }
                IPPROTO_UDP => {
                    let udp: UdpHdr = ctx.load(20)?;
                    RouteInput {
                        saddr: ipv4_mapped(ip.saddr),
                        daddr: ipv4_mapped(ip.daddr),
                        sport: u16::from_be(udp.source),
                        dport: u16::from_be(udp.dest),
                        proto: IPPROTO_UDP,
                        ipversion: 4,
                        is_new_tcp: false,
                        is_tcp: false,
                    }
                }
                // ICMP 等其它协议：原样放行。
                _ => return Ok(TC_ACT_OK),
            };
            if needs_listen_assign(input.is_tcp, input.is_new_tcp) {
                assign_listen_socket(ctx, listen_key(input.is_tcp, input.ipversion));
            }
            Ok(TC_ACT_OK)
        }
        6 => {
            let ip: Ipv6Hdr = ctx.load(0)?;
            let input = match ip.nexthdr {
                IPPROTO_TCP => {
                    let tcp: TcpHdr = ctx.load(40)?;
                    let flags = tcp.doff_flags[1];
                    RouteInput {
                        saddr: ip.saddr,
                        daddr: ip.daddr,
                        sport: u16::from_be(tcp.source),
                        dport: u16::from_be(tcp.dest),
                        proto: IPPROTO_TCP,
                        ipversion: 6,
                        is_new_tcp: (flags & 0x02) != 0 && (flags & 0x10) == 0,
                        is_tcp: true,
                    }
                }
                IPPROTO_UDP => {
                    let udp: UdpHdr = ctx.load(40)?;
                    RouteInput {
                        saddr: ip.saddr,
                        daddr: ip.daddr,
                        sport: u16::from_be(udp.source),
                        dport: u16::from_be(udp.dest),
                        proto: IPPROTO_UDP,
                        ipversion: 6,
                        is_new_tcp: false,
                        is_tcp: false,
                    }
                }
                _ => return Ok(TC_ACT_OK),
            };
            if needs_listen_assign(input.is_tcp, input.is_new_tcp) {
                assign_listen_socket(ctx, listen_key(input.is_tcp, input.ipversion));
            }
            Ok(TC_ACT_OK)
        }
        _ => Ok(TC_ACT_OK),
    }
}

// ── WAN 入口（cgroup sock_addr hook，wan 模式）─────────────────────────────

// sock_addr 程序内的 socket 选项读写 helper。aya-ebpf 0.1.1 未生成安全
// 包装，这里按 helper ID 转函数指针调用（aya-ebpf 自身的做法）。
// 切勿改回 `extern "C" { fn bpf_xxx(..); }`：bpf-linker 会把它当作 BPF 子函数
// 生成 pseudo-call（src_reg=1）+ 未定义符号重定位，aya 加载时报
// "function 0x.. not found while relocating ..."。
// 内核 UAPI：`bpf_getsockopt`/`bpf_setsockopt` 自 5.12 起在 cgroup sock_addr
// 程序可用，`SO_MARK` 写入同版本放开。
const BPF_FUNC_SETSOCKOPT: usize = 49;
const BPF_FUNC_GETSOCKOPT: usize = 57;
const BPF_FUNC_LOOP: usize = 181;

#[inline(always)]
unsafe fn bpf_getsockopt(
    ctx: *mut c_void,
    level: i32,
    optname: i32,
    optval: *mut c_void,
    optlen: i32,
) -> i64 {
    let f: unsafe extern "C" fn(*mut c_void, i32, i32, *mut c_void, i32) -> i64 =
        core::mem::transmute(BPF_FUNC_GETSOCKOPT);
    f(ctx, level, optname, optval, optlen)
}

#[inline(always)]
unsafe fn bpf_setsockopt(
    ctx: *mut c_void,
    level: i32,
    optname: i32,
    optval: *const c_void,
    optlen: i32,
) -> i64 {
    let f: unsafe extern "C" fn(*mut c_void, i32, i32, *const c_void, i32) -> i64 =
        core::mem::transmute(BPF_FUNC_SETSOCKOPT);
    f(ctx, level, optname, optval, optlen)
}

const SOL_SOCKET: i32 = 1;
const SO_MARK: i32 = 36;

/// cgroup sock_addr hook 返回值：放行（connect/sendmsg 正常继续）。
const SOCK_ALLOW: i32 = 1;
/// cgroup sock_addr hook 返回值：拒绝（connect/sendmsg 返回 `EPERM`）。
const SOCK_DENY: i32 = 0;

/// wan 模式核心逻辑，connect4/6 与 sendmsg4/6 四个 hook 共用。
///
/// 1. 回环防护：socket 当前 `SO_MARK` == reflex 全局出站 mark
///    （`CONFIG[CONFIG_KEY_ROUTING_MARK]`）→ reflex 到上游代理的连接，
///    直接放行，绝不二次引流。
/// 2. 目标取自 hook 上下文（`user_ip4/6` + `user_port`，网络序），构造
///    [`RouteInput`] 走与 lan 模式完全相同的 [`route`] 状态机。
/// 3. 裁决执行见 [`wan_route`] 内部 match。
///
/// 边界：connect 时刻源地址未定，`saddr` 置 0——`source_ip_set` 条件在
/// wan 模式不命中，含该条件的规则退化交用户态兜底（语义安全，不会误判）。
#[inline(always)]
fn wan_route(ctx: SockAddrContext, is_ipv4: bool) -> i32 {
    let sa = unsafe { &*ctx.sock_addr };

    // ── 1. 回环防护 ────────────────────────────────────────────────────
    // 未配置 routing_mark（0 / 键缺失）：无法识别自身连接，放行宁漏勿断
    // （此时若拦截，reflex 自身出站会被引回 tproxy 死循环）。
    let self_mark = match (unsafe { CONFIG.get(&CONFIG_KEY_ROUTING_MARK) }).map(|v| *v) {
        Some(m) if m != 0 => m,
        _ => return SOCK_ALLOW,
    };
    let mut cur_mark: u32 = 0;
    let got_mark = unsafe {
        bpf_getsockopt(
            ctx.sock_addr.cast(),
            SOL_SOCKET,
            SO_MARK,
            (&mut cur_mark as *mut u32).cast(),
            core::mem::size_of::<u32>() as i32,
        )
    };
    if got_mark == 0 && cur_mark == self_mark {
        return SOCK_ALLOW;
    }

    // ── 1.5 已托管 socket 直接放行 ─────────────────────────────────────
    // 两类 socket 的包必须保持当前 mark 走 fwmark 策略路由回环 local，
    // 不能被再次求值：
    // - cur_mark == tproxy_mark：客户端 socket 首包已由本 hook 写入引流
    //   mark（UDP 连发/重传的后续数据报、TCP 重连）；
    // - cur_mark == reply mark：listener / writeback socket 的回包。回包
    //   目的地址是"客户端 socket 的伪装地址"（= 原始目标 IP），按规则
    //   求值可能得到 DIRECT 裁决把 mark 清 0，回包从物理口发出，客户端
    //   永远收不到（透明回环死锁）。
    let tproxy_mark_val = tproxy_mark();
    if tproxy_mark_val != 0 && cur_mark == tproxy_mark_val {
        return SOCK_ALLOW;
    }
    if let Some(reply_mark) = (unsafe { CONFIG.get(&CONFIG_KEY_REPLY_MARK) }).map(|v| *v) {
        if reply_mark != 0 && cur_mark == reply_mark {
            return SOCK_ALLOW;
        }
    }

    // ── 2. 解析目标（bpf_sock_addr 字段均为网络序；port 低 16 位有效）──
    let dport = u16::from_be((sa.user_port & 0xffff) as u16);
    let (daddr, ipversion) = if is_ipv4 {
        (ipv4_mapped(sa.user_ip4.to_be_bytes()), 4u8)
    } else {
        let mut a = [0u8; 16];
        let mut i = 0;
        while i < 4 {
            let seg = sa.user_ip6[i].to_be_bytes();
            a[i * 4] = seg[0];
            a[i * 4 + 1] = seg[1];
            a[i * 4 + 2] = seg[2];
            a[i * 4 + 3] = seg[3];
            i += 1;
        }
        (a, 6u8)
    };
    let input = RouteInput {
        saddr: [0u8; 16],
        daddr,
        sport: 0,
        dport,
        proto: sa.protocol as u8,
        ipversion,
        // wan hook 天然每连接（connect）/每数据报（sendmsg）触发一次，
        // 不进 CONN_STATE 缓存。
        is_new_tcp: false,
        is_tcp: false,
    };

    // ── 3. 裁决执行 ────────────────────────────────────────────────────
    let (verdict, _) = route(&input);
    match verdict {
        KERNEL_OUTBOUND_DIRECT => {
            // UDP 多目标 socket 会残留上一次 PROXY 裁决写入的 tproxy_mark，
            // 纠正回 0（主路由表），避免新目标被陈旧引流。仅当当前 mark
            // 恰为 tproxy_mark 时才动（不碰其它程序设置的 mark）。
            if got_mark == 0 {
                if cur_mark == tproxy_mark() {
                    let zero: u32 = 0;
                    unsafe {
                        bpf_setsockopt(
                            ctx.sock_addr.cast(),
                            SOL_SOCKET,
                            SO_MARK,
                            (&zero as *const u32).cast(),
                            core::mem::size_of::<u32>() as i32,
                        );
                    }
                }
            }
            SOCK_ALLOW
        }
        KERNEL_OUTBOUND_BLOCK => SOCK_DENY,
        // PROXY：socket mark 写为 tproxy_mark 后放行——该连接的出站包由
        // fwmark 策略路由送 local 表 → tproxy 入站。写失败极罕见（内核
        // < 5.12 / 权限回退），放行宁漏勿断。
        _ => {
            let m = tproxy_mark();
            if m != 0 {
                unsafe {
                    bpf_setsockopt(
                        ctx.sock_addr.cast(),
                        SOL_SOCKET,
                        SO_MARK,
                        (&m as *const u32).cast(),
                        core::mem::size_of::<u32>() as i32,
                    );
                }
            }
            SOCK_ALLOW
        }
    }
}

/// 当前 tproxy fwmark（`CONFIG[CONFIG_KEY_MARK]`，用户态启动时写入）。
#[inline(always)]
fn tproxy_mark() -> u32 {
    (unsafe { CONFIG.get(&CONFIG_KEY_MARK) }).map(|v| *v).unwrap_or(0)
}

#[cgroup_sock_addr(connect4)]
pub fn reflex_cg_connect4(ctx: SockAddrContext) -> i32 {
    wan_route(ctx, true)
}

#[cgroup_sock_addr(connect6)]
pub fn reflex_cg_connect6(ctx: SockAddrContext) -> i32 {
    wan_route(ctx, false)
}

#[cgroup_sock_addr(sendmsg4)]
pub fn reflex_cg_sendmsg4(ctx: SockAddrContext) -> i32 {
    wan_route(ctx, true)
}

#[cgroup_sock_addr(sendmsg6)]
pub fn reflex_cg_sendmsg6(ctx: SockAddrContext) -> i32 {
    wan_route(ctx, false)
}

// ── 裁决执行 ────────────────────────────────────────────────────────────────

/// 把 skb 绑定到 [`LISTEN_SOCKETS`] 中 `index` 指向的监听 socket
/// （`bpf_sk_assign`，等价 iptables/nftables TPROXY target 的 socket 绑定）。
///
/// 失败（key 未注册 / socket 非 fullsock / 内核不支持 UDP assign）只影响
/// 本包交付——包继续走既有路径（大概率被 RST/丢弃），不改变 `TC_ACT_OK`
/// 语义，与"宁漏勿断"的程序级错误处理一致。成功时 lookup 返回的 socket
/// 引用已转移给 skb（assign 内部持引用），仍需 `bpf_sk_release` 释放
/// lookup 自身的引用（与 aya `SockMap::redirect_sk_lookup` 同构）。
#[inline(always)]
fn assign_listen_socket(ctx: &TcContext, index: u32) {
    unsafe {
        // SockMap 布局 = UnsafeCell<bpf_map_def>（单字段，首地址即 map def）；
        // 内部可变性由 UnsafeCell 保证，取 *mut 传 helper 与 aya 内部
        // （&self.def as *mut _）的转换一致。
        let map_ptr = &LISTEN_SOCKETS as *const SockMap as *mut _;
        let sk = bpf_map_lookup_elem(map_ptr, &index as *const _ as *const _);
        if sk.is_null() {
            return;
        }
        let _ = bpf_sk_assign(ctx.skb.skb.cast(), sk, 0);
        bpf_sk_release(sk);
    }
}

/// PROXY 引流包是否需要 sk_assign：TCP 仅 SYN（新建连接；established 包走
/// 内核既有连接查找即可命中 accept 出的子 socket），UDP 每包都需要。
fn needs_listen_assign(is_tcp: bool, is_new_tcp: bool) -> bool {
    !is_tcp || is_new_tcp
}

/// PROXY 引流包对应的 LISTEN_SOCKETS key。
fn listen_key(is_tcp: bool, ipversion: u8) -> u32 {
    if is_tcp {
        if ipversion == 4 {
            LISTEN_KEY_TCP4
        } else {
            LISTEN_KEY_TCP6
        }
    } else {
        LISTEN_KEY_UDP
    }
}

fn apply_verdict(ctx: &mut TcContext, input: &RouteInput) -> Result<i32, i64> {
    let (verdict, mark) = if input.is_tcp && !input.is_new_tcp {
        match established_tcp_verdict(input) {
            Some(v) => (v.verdict, v.mark),
            // 缓存 miss（重启后残留连接 / LRU 淘汰）：重新求值并回填。
            None => {
                let v = route(input);
                let entry = ConnEntry {
                    verdict: v.0,
                    _pad: [0; 3],
                    mark: v.1,
                };
                let _ = CONN_STATE.insert(&tuples_key(input), &entry, 0);
                v
            }
        }
    } else {
        let v = route(input);
        if input.is_tcp && input.is_new_tcp {
            let entry = ConnEntry {
                verdict: v.0,
                _pad: [0; 3],
                mark: v.1,
            };
            // LRU 写满则放弃缓存：后续包退化为每包求值，正确性不受影响。
            let _ = CONN_STATE.insert(&tuples_key(input), &entry, 0);
        }
        v
    };

    // PROXY：mark 必须写 tproxy_mark（CONFIG[CONFIG_KEY_MARK]）——route()
    // 结果里的 mark 是规则集自定义 mark（当前恒为 0），PROXY 包只有带上
    // tproxy_mark 才会命中 `ip rule fwmark <mark>/<mark>` 策略路由送 local
    // 表；写 0 的话引流彻底失效。
    let is_proxy = verdict == KERNEL_OUTBOUND_PROXY;
    let mark = if is_proxy { tproxy_mark() } else { mark };
    ctx.set_mark(mark);
    // PROXY 首包绑定监听 socket：本地交付时内核按原始目的端口查 listener
    // 必然落空（listener 监听的是 tproxy_port），必须显式 sk_assign——没有
    // 这一步 fwmark 引流只会把包送进 local 表然后被 RST / ICMP 丢弃，
    // tproxy 入站永远收不到流量（见 LISTEN_SOCKETS 文档）。
    if is_proxy && mark != 0 && needs_listen_assign(input.is_tcp, input.is_new_tcp) {
        assign_listen_socket(ctx, listen_key(input.is_tcp, input.ipversion));
    }
    match verdict {
        KERNEL_OUTBOUND_BLOCK => Ok(TC_ACT_SHOT),
        // DIRECT：mark 已写入（阶段 0 恒为 0，走主路由表转发）。
        // PROXY：mark = tproxy_mark，fwmark 策略路由送 local 表 → tproxy 入站。
        _ => Ok(TC_ACT_OK),
    }
}

/// established TCP：查缓存，未命中返回 None（调用方回填）。
fn established_tcp_verdict(input: &RouteInput) -> Option<ConnEntry> {
    // LruHashMap::get 为 unsafe（aya-ebpf 惯例：并发 lookup 由 BPF 运行时保证
    // 原子性，此处只读值拷贝，无引用逃逸）。
    Some(*unsafe { CONN_STATE.get(&tuples_key(input))? })
}

fn tuples_key(input: &RouteInput) -> TuplesKey {
    TuplesKey {
        saddr: input.saddr,
        daddr: input.daddr,
        sport: input.sport,
        dport: input.dport,
        proto: input.proto,
        _pad: 0,
    }
}

// ── 路由状态机 ──────────────────────────────────────────────────────────────

/// 求值返回 `(verdict, mark)`；`verdict` 为 `KERNEL_OUTBOUND_*`。
fn route(input: &RouteInput) -> (u8, u32) {
    // 全局 DNS 劫持（对齐 route.hijack_dns：端口 53 直接交用户态 DNS 模块）。
    // 例外：发往**本机地址**:53 的查询不劫持——tproxy DNS 代答回包需 bind
    // 原始目标地址（本机 :53），与本机 dnsmasq 等已监听服务冲突
    //（EADDRINUSE），客户端永远收不到回包；交回内置直连由内核本地交付，
    // 本机 DNS 服务以真实地址代答。
    if input.dport == 53 {
        if let Some(v) = (unsafe { CONFIG.get(&CONFIG_KEY_DNS_HIJACK) }).map(|v| *v) {
            if v != 0 {
                let local_set_id =
                    (unsafe { CONFIG.get(&CONFIG_KEY_LOCAL_SET_ID) }).map(|v| *v).unwrap_or(0);
                if local_set_id == 0 || !lpm_hit(local_set_id as u16, &input.daddr) {
                    return (KERNEL_OUTBOUND_PROXY, 0);
                }
            }
        }
    }

    let Some(len) = META.get(0).map(|v| *v) else {
        return (KERNEL_OUTBOUND_PROXY, 0);
    };
    if len == 0 {
        return (KERNEL_OUTBOUND_PROXY, 0);
    }
    if len > MAX_MATCH_SET_LEN {
        return (KERNEL_OUTBOUND_PROXY, 0);
    }

    let mut loop_ctx = RouteLoopCtx {
        saddr: input.saddr,
        daddr: input.daddr,
        sport: input.sport as u32,
        dport: input.dport as u32,
        proto: input.proto,
        ipversion: input.ipversion,
        group_hit: 0,
        rule_ok: 1,
        result: 0,
    };

    unsafe {
        bpf_loop(
            len,
            route_loop_cb,
            &mut loop_ctx as *mut RouteLoopCtx as *mut c_void,
            0,
        );
    }

    if loop_ctx.result == 0 || loop_ctx.result == RESULT_ERROR {
        // 前缀规则未命中（或 map 异常）→ 交用户态继续匹配（含兜底规则）。
        (KERNEL_OUTBOUND_PROXY, 0)
    } else {
        let mark = loop_ctx.result >> 8;
        ((loop_ctx.result & 0xff) as u8, mark)
    }
}

/// bpf_loop 回调上下文。
#[repr(C)]
struct RouteLoopCtx {
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u32,
    dport: u32,
    proto: u8,
    ipversion: u8,
    /// 当前条件组是否已有命中（组内 OR 短路）。
    group_hit: u8,
    /// 已收尾条件组是否全部命中（组间 AND，初始 1）。
    rule_ok: u8,
    /// 低 8 位 verdict、高位 mark；0 = 前缀未命中，RESULT_ERROR = 内部错误。
    result: u32,
}

const RESULT_ERROR: u32 = u32::MAX;

unsafe extern "C" fn route_loop_cb(index: u32, data: *mut c_void) -> i32 {
    let ctx = &mut *(data as *mut RouteLoopCtx);
    let Some(ms) = ROUTING.get(index) else {
        ctx.result = RESULT_ERROR;
        return 1;
    };
    match ms.ty {
        match_type::IP_SET => {
            if ctx.group_hit == 0 && lpm_hit(ms.value[0] as u16, &ctx.daddr) {
                ctx.group_hit = 1;
            }
        }
        match_type::SOURCE_IP_SET => {
            if ctx.group_hit == 0 && lpm_hit(ms.value[0] as u16, &ctx.saddr) {
                ctx.group_hit = 1;
            }
        }
        match_type::PORT => {
            let (start, end) = (ms.value[0], ms.value[1]);
            if ctx.group_hit == 0 && ctx.dport >= start && ctx.dport <= end {
                ctx.group_hit = 1;
            }
        }
        match_type::L4PROTO => {
            if ctx.group_hit == 0 && ctx.proto == (ms.value[0] as u8) {
                ctx.group_hit = 1;
            }
        }
        match_type::IP_VERSION => {
            if ctx.group_hit == 0 && ctx.ipversion == (ms.value[0] as u8) {
                ctx.group_hit = 1;
            }
        }
        match_type::GROUP_END => {
            if ctx.group_hit == 0 {
                ctx.rule_ok = 0;
            }
            ctx.group_hit = 0;
        }
        match_type::TERMINATE => {
            let hit = if ms.invert != 0 {
                ctx.rule_ok == 0
            } else {
                ctx.rule_ok != 0
            };
            if hit {
                ctx.result = (ms.outbound as u32) | ((ms.mark as u32) << 8);
                return 1;
            }
            // 本条规则未生效：复位状态，继续下一条规则。
            ctx.rule_ok = 1;
            ctx.group_hit = 0;
        }
        // 未知类型（两端版本不一致）：交用户态兜底。
        _ => {
            ctx.result = RESULT_ERROR;
            return 1;
        }
    }
    0
}

fn lpm_hit(set_id: u16, addr: &[u8; 16]) -> bool {
    // 查询用最长前缀：16(set_id) + 128(addr) = 144 bit。
    // key 构造必须与用户态 loader 写入的 lpm_key() 逐字节一致
    //（大端 set_id），见 LPM map 文档。
    let key = Key::new(
        16 + 128,
        common::lpm_key(set_id, *addr),
    );
    LPM.get(&key).is_some()
}

// ── bpf_loop helper ─────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn bpf_loop(
    nr_loops: u32,
    callback: unsafe extern "C" fn(u32, *mut c_void) -> i32,
    callback_ctx: *mut c_void,
    flags: u64,
) -> u64 {
    let f: unsafe extern "C" fn(
        u32,
        unsafe extern "C" fn(u32, *mut c_void) -> i32,
        *mut c_void,
        u64,
    ) -> u64 = core::mem::transmute(BPF_FUNC_LOOP);
    f(nr_loops, callback, callback_ctx, flags)
}

// ── 常量 ────────────────────────────────────────────────────────────────────

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
