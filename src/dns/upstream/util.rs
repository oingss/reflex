use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::config::dns::DnsServerConfig;

use super::DnsUpstream;

// ── 地址解析辅助 ─────────────────────────────────────────────────────────────

pub(super) fn parse_addr(s: &str, default_port: u16) -> anyhow::Result<SocketAddr> {
    if s.starts_with('[') {
        return Ok(s.parse()?);
    }
    if s.contains(':') {
        return Ok(s.parse()?);
    }
    Ok(format!("{s}:{default_port}").parse()?)
}

/// 解析 EDNS Client Subnet 配置字符串，如 "1.2.3.0/24" 或 "2001:db8::/32"。
///
/// 返回 (IpAddr, prefix_len)。解析失败返回 None 并打印 warning，
/// 让上游仍可工作（只是不注入 EDNS0_SUBNET）。
///
/// 对齐 sing-box `option.DNSClientOptions.ClientSubnet.Build(netip.Prefix{})`：
/// 解析 CIDR 字符串为 (addr, bits)。
pub(super) fn parse_client_subnet(s: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr_str, prefix_str) = s.split_once('/')?;
    let addr: std::net::IpAddr = addr_str.parse().ok()?;
    let prefix_len: u8 = prefix_str.parse().ok()?;
    // 校验 prefix_len 范围
    let max = match addr {
        std::net::IpAddr::V4(_) => 32u8,
        std::net::IpAddr::V6(_) => 128u8,
    };
    if prefix_len > max {
        tracing::warn!(client_subnet=%s, "prefix_len exceeds address family max, ignoring");
        return None;
    }
    Some((addr, prefix_len))
}

/// 从原始配置地址字符串中提取 SNI host（用于 DoT/DoQ/DoH 默认 SNI）。
///
/// 对齐 sing-box `common/tls/std_client.go` 的逻辑：
/// - 未配置 `tls.server_name` 时，用 server 地址作 SNI 默认值
/// - IP 地址：用 IP 字符串（rustls 会自动识别为 ServerName::IpAddress，做 IP SAN 校验）
/// - 域名：用 host 字符串（rustls 识别为 ServerName::DnsName，做 DNS SAN 校验）
///
/// 修复旧实现的 IPv6 无端口解析 bug：
/// - 旧实现 `raw.rsplit_once(':')` 对 `[2001:db8::1]` 会被错误切分为
///   `("[2001:db8", ":1]")`，导致 SNI = `"2001:db8"`（无效）
/// - 修复后：先用 `]` 定位 IPv6 结束位置，再判断是否有 `:port`，避免误切
pub(super) fn extract_sni_host(raw: &str) -> String {
    // IPv6 地址：[::1] 或 [::1]:port
    if raw.starts_with('[') {
        if let Some(end) = raw.find(']') {
            let host = &raw[1..end]; // 不含括号
                                     // host 已是 IPv6 字符串，直接返回（rustls 会识别为 IpAddress）
            return host.to_string();
        }
        // 格式异常，回退到去掉括号的整体
        return raw
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
    }
    // IPv4 或域名：用最后一个 `:` 切分（如有端口）
    let host = raw.rsplit_once(':').map(|(h, _)| h).unwrap_or(raw);
    host.to_string()
}

pub(super) async fn resolve_or_cached(
    cache: &std::sync::Mutex<Option<std::net::IpAddr>>,
    host: &str,
    port: u16,
    domain_resolver: Option<&Arc<DnsUpstream>>,
    tag: &str,
) -> anyhow::Result<std::net::IpAddr> {
    {
        let cached = *cache.lock().unwrap();
        if let Some(ip) = cached {
            return Ok(ip);
        }
    }
    let ip = if let Some(resolver) = domain_resolver {
        debug!(upstream=%tag, domain_resolver=%resolver.tag, host=%host,
            "resolving host via domain_resolver");
        resolver.resolve_host(host).await?
    } else {
        tokio::net::lookup_host(format!("{host}:{port}"))
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("system DNS lookup failed for {host}"))?
            .ip()
    };
    *cache.lock().unwrap() = Some(ip);
    Ok(ip)
}

// ── TLS 配置构建（outbound-net） ──────────────────────────────────────────────

pub(super) fn build_rustls_client_config(
    cfg: &DnsServerConfig,
) -> anyhow::Result<std::sync::Arc<rustls::ClientConfig>> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    // 加载系统根证书
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = root_store.add(cert);
    }

    let tls_config = if cfg.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(crate::outbound::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(std::sync::Arc::new(tls_config))
}

/// 构建 DNS-over-QUIC 专用 quinn::ClientConfig
pub(super) fn build_doq_quic_config(
    cfg: &DnsServerConfig,
) -> anyhow::Result<std::sync::Arc<quinn::ClientConfig>> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = root_store.add(cert);
    }

    let mut tls_config = if cfg.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(crate::outbound::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // RFC 9250 要求 ALPN = "doq"
    tls_config.alpn_protocols = vec![b"doq".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()))
        .keep_alive_interval(Some(Duration::from_secs(10)));

    let mut quic_cfg = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    quic_cfg.transport_config(std::sync::Arc::new(transport));

    Ok(std::sync::Arc::new(quic_cfg))
}

/// 构建 DNS-over-HTTP/3 专用 quinn::ClientConfig
///
/// 与 `build_doq_quic_config` 的唯一区别：ALPN = "h3"（RFC 9114）。
/// 其它配置（idle timeout / keep-alive）与 DoQ 一致。
pub(super) fn build_h3_quic_config(
    cfg: &DnsServerConfig,
) -> anyhow::Result<std::sync::Arc<quinn::ClientConfig>> {
    use rustls::RootCertStore;

    let mut root_store = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = root_store.add(cert);
    }

    let mut tls_config = if cfg.insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(crate::outbound::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    // RFC 9114 要求 ALPN = "h3"
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_idle_timeout(Some(quinn::VarInt::from_u32(30_000).into()))
        .keep_alive_interval(Some(Duration::from_secs(10)));

    let mut quic_cfg = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    ));
    quic_cfg.transport_config(std::sync::Arc::new(transport));

    Ok(std::sync::Arc::new(quic_cfg))
}

// ── DNS-over-TCP 帧收发（DoT / DoQ stream 共用） ─────────────────────────────

/// DNS over TCP/TLS/QUIC-stream 帧格式：2 字节大端长度前缀
pub(super) async fn tcp_framed_exchange<S>(stream: &mut S, msg: Bytes) -> anyhow::Result<Bytes>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin + ?Sized,
{
    stream.write_all(&(msg.len() as u16).to_be_bytes()).await?;
    stream.write_all(&msg).await?;
    let len = stream.read_u16().await? as usize;
    anyhow::ensure!(len >= 12, "dns tcp response too short: {len}");
    anyhow::ensure!(len <= 65535, "dns tcp response too large: {len}");
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── extract_sni_host ──
    #[test]
    fn extract_sni_ipv4_with_port() {
        assert_eq!(extract_sni_host("1.1.1.1:853"), "1.1.1.1");
    }

    #[test]
    fn extract_sni_ipv4_no_port() {
        assert_eq!(extract_sni_host("1.1.1.1"), "1.1.1.1");
    }

    #[test]
    fn extract_sni_ipv6_with_port() {
        assert_eq!(extract_sni_host("[2001:db8::1]:853"), "2001:db8::1");
    }

    #[test]
    fn extract_sni_ipv6_no_port() {
        // 旧实现在这里会返回 "2001:db8"（错误）
        assert_eq!(extract_sni_host("[2001:db8::1]"), "2001:db8::1");
    }

    #[test]
    fn extract_sni_domain_with_port() {
        assert_eq!(extract_sni_host("dns.google:853"), "dns.google");
    }

    #[test]
    fn extract_sni_domain_no_port() {
        assert_eq!(extract_sni_host("dns.google"), "dns.google");
    }

    // ── parse_addr ──
    #[test]
    fn parse_addr_bare() {
        assert_eq!(
            parse_addr("8.8.8.8", 53).unwrap(),
            "8.8.8.8:53".parse().unwrap()
        );
    }
    #[test]
    fn parse_addr_with_port() {
        assert_eq!(
            parse_addr("8.8.8.8:5353", 53).unwrap(),
            "8.8.8.8:5353".parse().unwrap()
        );
    }
    #[test]
    fn parse_addr_ipv6() {
        assert_eq!(
            parse_addr("[::1]:53", 53).unwrap(),
            "[::1]:53".parse().unwrap()
        );
    }
}
