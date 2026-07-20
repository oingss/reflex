//! 出站公共支撑模块
//!
//! 收纳各协议共享的纯计算工具、多路复用、节点组和网卡查找等功能，
//! 供 `src/outbound/` 下的各协议出站引用。

pub mod group;
pub mod interface_finder;
#[cfg(feature = "outbound-net")]
pub mod proto;
#[cfg(feature = "outbound-net")]
pub mod smux;
