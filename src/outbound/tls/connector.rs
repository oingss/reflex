use std::{io::BufReader, sync::Arc};

use dashmap::DashMap;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

use crate::config::outbound::TlsConfig;

static CLIENT_CONFIG_CACHE: once_cell::sync::Lazy<DashMap<String, Arc<ClientConfig>>> =
    once_cell::sync::Lazy::new(DashMap::new);

/// 计算配置指纹。仅用于缓存键，不要求密码学安全。
fn config_fingerprint(tls: &TlsConfig) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("insecure={}", tls.insecure));
    parts.push(format!("alpn={:?}", tls.alpn));
    if let Some(p) = &tls.ca_path {
        parts.push(format!("ca_path={p}"));
    }
    if !tls.certificate.is_empty() {
        // 内联证书：用第一张证书的长度+前 32 字节摘要作为指纹
        let first = tls.certificate.first().map(|s| s.len()).unwrap_or(0);
        parts.push(format!(
            "cert_inline_count={}_len0={}",
            tls.certificate.len(),
            first
        ));
    }
    if let Some(u) = &tls.utls {
        parts.push(format!("utls={:?}_enabled={}", u.fingerprint, u.enabled));
    }
    if let Some(e) = &tls.ech {
        parts.push(format!("ech_enabled={}", e.enabled));
    }
    parts.join("|")
}

/// 构建一个新的 `Arc<ClientConfig>`（不查缓存）。供需要独立 config 的场景使用。
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

pub fn build_client_config_cached(tls: &TlsConfig) -> anyhow::Result<Arc<ClientConfig>> {
    let key = config_fingerprint(tls);
    if let Some(entry) = CLIENT_CONFIG_CACHE.get(&key) {
        return Ok(entry.clone());
    }
    let cfg = build_client_config(tls)?;
    CLIENT_CONFIG_CACHE.insert(key, cfg.clone());
    Ok(cfg)
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
                    crate::outbound::tls::ech::connect_ech(tcp, server_name, tls, ech_config_list)
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

    let cfg = build_client_config_cached(tls)?;

    if let Some(utls_cfg) = &tls.utls {
        if utls_cfg.enabled {
            tracing::debug!(
                server_name = %server_name,
                fingerprint = ?utls_cfg.fingerprint,
                "uTLS fingerprinting enabled (key_share patched from rustls ClientHello)"
            );
            return crate::outbound::tls::utls::connect_utls(
                tcp,
                server_name,
                &utls_cfg.fingerprint,
                cfg,
                &tls.alpn,
            )
            .await
            .map(|s| TlsStreamBox::Utls(Box::new(s)));
        }
    }

    // 标准 rustls TLS 分支
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
#[allow(clippy::large_enum_variant)]
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
