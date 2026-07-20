//! 出站传输层公共模块
//!
//! 将各协议共享的传输实现（WebSocket、XHTTP、gRPC）统一收口在此目录，
//! 供 VLESS、VMess、Trojan、Shadowsocks 等出站协议引用，避免重复实现。

#[cfg(feature = "outbound-net")]
pub mod grpc;
#[cfg(feature = "outbound-net")]
pub mod websocket;
#[cfg(feature = "outbound-net")]
pub mod xhttp;
