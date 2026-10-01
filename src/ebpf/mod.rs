//! eBPF 预分流（内核面直连卸载，dae 式双层路由的内核层）。
//!
//! 架构（对应 `reflex-ebpf-common` 模块文档）：
//!
//! - [`compiler`]：把 tproxy 入站 `ebpf` 配置中**显式声明**的纯 IP 规则集
//!   （`block_rulesets` / `direct_rulesets`）+ 内置私有网段直连集合编译为
//!   MatchSet 线性序列 + LPM 条目。内核面与用户面（`route.rules`）完全
//!   独立：内核按「DNS-53 劫持 → BLOCK → DIRECT → 内置私有直连 → 未命中
//!   一律 PROXY」的固定顺序裁决（见 `bpf` 端 `route()`），不感知任何
//!   用户态规则——用户面规则只对进入 tproxy 入站的流量二次路由。
//! - [`interp`]：MatchSet 状态机的纯 Rust 实现，与 `reflex-bpf` 的
//!   `route_loop_cb` 逐行同构；单元测试用它验证编译产物语义。
//! - `loader`（`feature = "ebpf"` + Linux）：aya 装载 eBPF 对象——缺省从
//!   **构建期内嵌对象**加载（build.rs 把 `reflex.bpf.el.o` / `.eb.o` 通过
//!   `include_bytes!` 编译进二进制，类比 Windows 端内置 wintun.dll；显式
//!   `bpf_object` 可覆盖）——填充 map 后按 `mode` 挂载：`lan` 逐接口挂
//!   tc ingress，`wan` 在 `cgroup_path` 挂 4 个 sock_addr hook
//!   （connect4/6 + sendmsg4/6，本机/Android 场景）+ lo tc ingress，并把
//!   tproxy 监听 fd 注册进 `LISTEN_SOCKETS`（sk_assign 交付闭环）；并注册
//!   shutdown 清理。
//! - `netlink`（同上）：自动维护 fwmark 策略路由
//!   `fwmark <mark>/<mark> lookup <TABLE>` → `local default dev lo`。
//!
//! 语义边界：内核面只吃纯 IP 规则集（域名/端口条件 fail-fast 拒绝）；
//! 内核未命中的流量一律 PROXY 交用户态，用户面规则语义不受影响。

pub mod compiler;
pub mod interp;
pub mod setup;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod loader;
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub mod netlink;

/// 内核可表达的出站裁决（`KERNEL_OUTBOUND_*` 的类型化包装）。
pub type KernelVerdict = u8;

// ── tproxy 监听句柄（跨平台，供 loader 注册 SOCKMAP）───────────────────────

/// tproxy 入站监听 socket 句柄。
///
/// 由 `TProxyInbound::prepare_listeners()` **同步**创建（早于任何 tokio
/// task），App 持一份传给 `ebpf::setup`（loader 把 fd 写入 `LISTEN_SOCKETS`
/// SOCKMAP，内核面 `bpf_sk_assign` 依赖），另一份 move 进入站 run 循环。
/// fd 必须始终存活：SOCKMAP 持有 socket 引用，listener 关闭会让内核面
/// assign 失效。
#[derive(Debug)]
pub struct TProxyListeners {
    /// IPv4 TCP 监听（SOCKMAP key 0）。
    pub tcp4: Option<std::net::TcpListener>,
    /// IPv6 TCP 监听（SOCKMAP key 2）。
    pub tcp6: Option<std::net::TcpListener>,
    /// UDP 监听（双栈 socket，SOCKMAP key 1）。
    pub udp: Option<std::net::UdpSocket>,
}

/// reply mark 缺省值：由 tproxy mark 翻转第 30 位派生，恒不等于 mark 本身。
/// 与 default_mark / routing_mark 撞值时由 setup 校验 fail-fast，届时用户
/// 显式配置 `ebpf.reply_mark` 即可。
pub const REPLY_MARK_DERIVE_MASK: u32 = 0x4000_0000;

/// 由 tproxy mark 派生默认 reply mark（见 [`REPLY_MARK_DERIVE_MASK`]）。
pub fn derive_reply_mark(mark: u32) -> u32 {
    mark ^ REPLY_MARK_DERIVE_MASK
}
