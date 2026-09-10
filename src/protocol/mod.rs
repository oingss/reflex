//! 协议原语公共包：inbound 服务端与 outbound 客户端共享的编解码原语。
//!
//! 设计原则（对齐 sing-box `protocol/` 目录）：
//! - 只放纯算法/帧格式原语：cipher 枚举、KDF、salt/key 长度、AEAD 编解码器、
//!   地址编解码、帧常量。不含连接管理、握手状态机、I/O 调度。
//! - 方向无关：`build_request`（客户端）和 `parse_request`（服务端）共存于
//!   同一模块，共享地址/帧编解码底层函数。
//! - inbound 和 outbound 各自实现角色逻辑（拨号 vs accept），引用此处的原语。
//!
//! 当前覆盖：vless / shadowsocks / trojan / vmess / naive / anytls /
//! hysteria2 / tuic / shadowquic。后续新增协议按同样模式扩展子模块。

pub mod anytls;
pub mod hysteria2;
pub mod naive;
pub mod shadowsocks;
pub mod shadowquic;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;
pub mod wireguard;
