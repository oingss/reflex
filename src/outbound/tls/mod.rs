//! 出站 TLS 支持模块
//!
//! 将所有与 TLS 相关的实现统一收口在此目录：
//!
//! - [`connector`]：共用 TLS 连接器（rustls 原始 ClientHello / uTLS 自动切换）
//! - [`utls`]：uTLS 浏览器 TLS 指纹伪造
//! - [`reality`]：REALITY 客户端握手实现
//! - [`ech`]：ECH（Encrypted Client Hello，RFC 9460）配置解析与握手入口
//!
//! `connector` 模块的公开项通过 `pub use` 重新导出，
//! 因此 `crate::outbound::tls::build_client_config`、
//! `crate::outbound::tls::connect_tls_or_utls` 等路径保持不变。

pub mod connector;
pub mod ech;
pub mod reality;
pub mod utls;

pub use connector::*;
