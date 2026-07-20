//! 共用 TLS 连接器，供所有出站协议复用。
//!
//! 提供两条连接路径：
//!
//! 1. **普通 TLS**（`connect_tls`）：使用 rustls 原始 ClientHello，
//!    TLS 指纹为 rustls 默认值。
//!
//! 2. **uTLS**（`connect_tls_or_utls`）：当 `TlsConfig.utls.enabled = true` 时，
//!    通过 [`crate::outbound::tls::utls`] 模块发送浏览器伪造的 ClientHello，
//!    后续握手和加密仍由 rustls 完成（安全性不降级）。

use std::{io::BufReader, sync::Arc};

use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::config::outbound::TlsConfig;

// ── 配置构建 ──────────────────────────────────────────────────────────────────

/// 根据配置构建 rustls ClientConfig。
///
/// 支持：
/// - 内联 CA 证书（`tls.certificate`，PEM 字符串列表）
/// - 自定义 CA 路径（`tls.certificate_path`，与 sing-box 对齐）
/// - 自定义 CA 路径（`tls.ca_path`，reflex 历史字段，等价于 `certificate_path`）
/// - 系统根证书（默认）
/// - 跳过证书验证（`tls.insecure`）
/// - ALPN（`tls.alpn`）
///
/// 优先级：`certificate` > `certificate_path` > `ca_path` > 系统根证书。
pub fn build_client_config(tls: &TlsConfig) -> anyhow::Result<Arc<ClientConfig>> {
    let mut root_store = RootCertStore::empty();

    if !tls.certificate.is_empty() {
        // 内联 PEM 字符串列表（sing-box `certificate` 字段）
        for pem in &tls.certificate {
            let mut reader = BufReader::new(pem.as_bytes());
            for cert in rustls_pemfile::certs(&mut reader) {
                root_store.add(cert?)?;
            }
        }
    } else if let Some(path) = &tls.certificate_path {
        let ca_data = std::fs::read(path)?;
        let mut reader = BufReader::new(ca_data.as_slice());
        for cert in rustls_pemfile::certs(&mut reader) {
            root_store.add(cert?)?;
        }
    } else if let Some(ca_path) = &tls.ca_path {
        let ca_data = std::fs::read(ca_path)?;
        let mut reader = BufReader::new(ca_data.as_slice());
        for cert in rustls_pemfile::certs(&mut reader) {
            root_store.add(cert?)?;
        }
    } else {
        // 系统根证书：使用 rustls_native_certs 加载。
        // 注意：忽略单张证书的加载/解析错误（某些系统会有过期或格式异常的根证书），
        // 但如果整体加载失败或根证书库为空，必须记录警告——否则所有非 insecure
        // 连接都会因"找不到可信 CA"而失败，客户端会发 unknown_certificate alert。
        let native = rustls_native_certs::load_native_certs();
        if !native.errors.is_empty() {
            tracing::warn!(
                errors = ?native.errors,
                "load native root certs encountered errors (some certs may be skipped)"
            );
        }
        let mut added = 0usize;
        for cert in native.certs {
            if root_store.add(cert).is_ok() {
                added += 1;
            }
        }
        if added == 0 {
            tracing::error!(
                "no trusted root certs available; non-insecure TLS connections will fail \
                 with certificate verification errors. \
                 Set tls.insecure=true (not recommended) or provide tls.certificate_path"
            );
        } else {
            tracing::debug!(roots = added, "loaded native root certs");
        }
    }

    let mut config = if tls.insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // ALPN 配置
    if !tls.alpn.is_empty() {
        config.alpn_protocols = tls.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    }

    Ok(Arc::new(config))
}

// ── 连接入口 ──────────────────────────────────────────────────────────────────

/// 在已有 TCP 流上建立 TLS 连接（普通 rustls，不伪造指纹）。
pub async fn connect_tls(
    stream: TcpStream,
    server_name: &str,
    config: Arc<ClientConfig>,
) -> anyhow::Result<TlsStream<TcpStream>> {
    let connector = TlsConnector::from(config);
    let sni = ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("invalid server name: {server_name}"))?;
    Ok(connector.connect(sni, stream).await?)
}

/// 统一 TLS 连接入口：根据 `TlsConfig.utls` 自动选择普通 TLS 或 uTLS。
///
/// - 若 `ech.enabled = true`：进入 ECH 握手分支（见 [`crate::outbound::tls::ech`]）
/// - 若 `utls.enabled = true`：发送浏览器伪造 ClientHello（uTLS 模式）
/// - 否则：使用标准 rustls ClientHello
///
/// 返回 [`TlsStreamBox`]，可作为普通 `AsyncRead + AsyncWrite` 使用。
///
/// **ECH 当前限制**：rustls 0.23 不原生支持 ECH。当 `tls.ech.enabled = true`
/// 且成功解析出 ECHConfigList 后，会调用 [`crate::outbound::tls::ech::connect_ech`]
/// 返回明确的"未支持"错误，避免静默降级为不安全的非 ECH 连接（与 sing-box
/// 在 ECH 启用但握手失败时的行为一致）。配置错误（PEM/二进制格式错误）会
/// 在握手前暴露。
pub async fn connect_tls_or_utls(
    tcp: TcpStream,
    server_name: &str,
    tls: &TlsConfig,
) -> anyhow::Result<TlsStreamBox> {
    // ECH 分支：优先级最高（uTLS 与 ECH 不兼容，sing-box 中二者互斥）
    if let Some(ech_opts) = &tls.ech {
        if ech_opts.enabled {
            // 从 inline config / config_path 解析 ECHConfigList。
            // 返回 None 表示配置中未提供，需要通过 DNS HTTPS RR 获取——
            // 但 connect_tls_or_utls 当前不接受 resolver，无法在此完成。
            // 由调用方自行调用 ech::fetch_ech_config_from_dns + ech::connect_ech。
            return match crate::outbound::tls::ech::resolve_ech_config_list(ech_opts)? {
                Some(ech_config_list) => {
                    crate::outbound::tls::ech::connect_ech(
                        tcp,
                        server_name,
                        tls,
                        ech_config_list,
                    )
                    .await
                }
                None => anyhow::bail!(
                    "ECH is enabled but no ECHConfigList is provided via `ech.config` or \
                     `ech.config_path`. DNS HTTPS RR based fetching is not available in this \
                     entry; supply an explicit ECH config or use the resolver-aware entry."
                ),
            };
        }
    }

    let cfg = build_client_config(tls)?;

    // uTLS 分支
    if let Some(utls_cfg) = &tls.utls {
        if utls_cfg.enabled {
            let stream = crate::outbound::tls::utls::connect_utls(
                tcp,
                server_name,
                &utls_cfg.fingerprint,
                cfg,
                &tls.alpn,
            )
            .await?;
            return Ok(TlsStreamBox::Utls(Box::new(stream)));
        }
    }

    // 普通 TLS 分支
    let stream = connect_tls(tcp, server_name, cfg).await?;
    Ok(TlsStreamBox::Plain(stream))
}

// ── TlsStreamBox：统一 uTLS 和普通 TLS 的 I/O 类型 ──────────────────────────

use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 包装 rustls TLS 流或 uTLS 流，向上层提供统一的 `AsyncRead + AsyncWrite`。
pub enum TlsStreamBox {
    /// 普通 rustls TLS 流
    Plain(TlsStream<TcpStream>),
    /// uTLS 流（浏览器指纹）
    Utls(Box<TlsStream<crate::outbound::tls::utls::UtlsStream>>),
}

impl AsyncRead for TlsStreamBox {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_read(cx, buf),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStreamBox {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_write(cx, data),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_flush(cx),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            TlsStreamBox::Plain(s) => Pin::new(s).poll_shutdown(cx),
            TlsStreamBox::Utls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

// ── 证书验证跳过（insecure 模式）─────────────────────────────────────────────

#[derive(Debug)]
pub struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
