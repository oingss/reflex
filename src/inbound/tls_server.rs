//! inbound 服务端 TLS 支持：从 sing-box 风格的 [`InboundTlsConfig`]
//! 构建 rustls `ServerConfig`。
//!
//! 字段与 sing-box inbound tls 对齐：
//! - `certificate` / `certificate_path`：证书链（PEM）
//! - `key` / `key_path`：私钥（PEM，支持 RSA / PKCS8 / EC）
//! - `alpn`：应用层协议协商
//!
//! 服务端与客户端 TLS 是不同的配置面（服务端要证书/私钥，不需要
//! insecure/utls/ech），因此独立于 `outbound/tls` 实现，避免公共配置
//! 结构体互相污染。

use std::io::BufReader;
use std::sync::Arc;

use tokio_rustls::rustls::{server::ServerConnection, ServerConfig};
use tokio_rustls::{Accept, TlsAcceptor};

use crate::config::inbound::InboundTlsConfig;

/// 构建服务端 `ServerConfig`。
///
/// 证书来源优先级（与 sing-box 一致）：内联 `certificate` → `certificate_path`。
/// 私钥来源：内联 `key` → `key_path`。
pub fn build_server_config(cfg: &InboundTlsConfig) -> anyhow::Result<Arc<ServerConfig>> {
    anyhow::ensure!(cfg.enabled, "inbound tls.enabled must be true");

    // ── 证书链 ────────────────────────────────────────────────────────────
    let cert_pems: Vec<String> = if !cfg.certificate.is_empty() {
        cfg.certificate.clone()
    } else if let Some(path) = &cfg.certificate_path {
        let data = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read certificate_path '{path}': {e}"))?;
        vec![data]
    } else {
        anyhow::bail!(
            "inbound tls: either certificate or certificate_path is required \
             (server-side TLS cannot work without a certificate)"
        )
    };

    let mut certs = Vec::new();
    for pem in &cert_pems {
        let mut reader = BufReader::new(pem.as_bytes());
        for cert in rustls_pemfile::certs(&mut reader) {
            certs.push(cert.map_err(|e| anyhow::anyhow!("parse certificate PEM: {e}"))?);
        }
    }
    anyhow::ensure!(!certs.is_empty(), "inbound tls: no certificates parsed from PEM");

    // ── 私钥 ──────────────────────────────────────────────────────────────
    let key_pem: String = if let Some(k) = &cfg.key {
        k.clone()
    } else if let Some(path) = &cfg.key_path {
        std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read key_path '{path}': {e}"))?
    } else {
        anyhow::bail!(
            "inbound tls: either key or key_path is required \
             (server-side TLS cannot work without a private key)"
        )
    };
    let mut key_reader = BufReader::new(key_pem.as_bytes());
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("inbound tls: no private key found in PEM"))?;

    // ── 组装 ServerConfig ─────────────────────────────────────────────────
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("inbound tls: invalid cert/key pair: {e}"))?;

    if !cfg.alpn.is_empty() {
        config.alpn_protocols = cfg.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    Ok(Arc::new(config))
}

/// 构建 TLS acceptor（供各协议入站复用）。
pub fn build_acceptor(cfg: &InboundTlsConfig) -> anyhow::Result<TlsAcceptor> {
    Ok(TlsAcceptor::from(build_server_config(cfg)?))
}

/// TLS 握手失败的错误分类：客户端发来非 TLS 流量（如普通 HTTP 或探测）时
/// 会得到协议错误，属于正常现象，应记 debug 而非 error。
pub fn is_client_protocol_error(e: &std::io::Error) -> bool {
    use tokio_rustls::rustls::{Error, PeerMisbehaved as P};
    match e.get_ref().and_then(|r| r.downcast_ref::<Error>()) {
        // 客户端发来无法解析的数据（明文 HTTP / 随机探测字节）
        Some(
            Error::InvalidMessage(_)
            | Error::DecryptError
            | Error::InappropriateMessage { .. }
            | Error::InappropriateHandshakeMessage { .. },
        ) => true,
        // 客户端在错误时机发来 alert（非 TLS 客户端的常见反应）
        Some(Error::AlertReceived(_)) => true,
        // 客户端不符合协议要求的行为（如缺 key_share）也视为客户端侧问题
        Some(Error::PeerMisbehaved(kind)) => matches!(
            kind,
            P::MissingKeyShare
                | P::InvalidKeyShare
                | P::EarlyDataAttemptedInSecondClientHello
        ),
        _ => false,
    }
}

/// 便于在协议入站内部直接引用 ServerConnection（ALPN 读取等）。
pub type ServerTlsStream<S> = tokio_rustls::server::TlsStream<S>;

/// 从已完成的 TLS 流中读取协商出的 ALPN（调试/日志用）。
pub fn negotiated_alpn(conn: &ServerConnection) -> Option<String> {
    conn.alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned())
}

// 保留 Accept 类型引用以避免未使用导入警告（调用方可按需使用）
#[allow(dead_code)]
type _AcceptAlias = Accept<tokio::net::TcpStream>;
