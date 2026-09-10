//! ShadowQuic 协议原语层：配置映射与地址互转辅助。
//!
//! ## 设计说明（线格式归 shadowquic crate 所有）
//! ShadowQuic 的全部线级编解码——QUIC 握手、JLS SNI 伪装、SQConnect/SQAssociate
//! 帧、UDP over datagram/stream 分帧——均由 `shadowquic` crate 封装实现
//! （服务端 `shadowquic::shadowquic::inbound::ShadowQuicServer`，客户端
//! `shadowquic::shadowquic::outbound::ShadowQuicClient`）。reflex **不重复实现
//! 任何线格式**，本模块只提供入站/出站共用的胶水辅助：
//!
//! - reflex 配置字符串 → [`CongestionControl`] 枚举映射（服务端与客户端共用）
//! - reflex [`Target`] ↔ crate [`SocksAddr`] 地址互转
//! - reflex 入站配置 → [`ShadowQuicServerCfg`] 服务端配置构建
//!
//! 服务端入站见 [`crate::inbound::shadowquic`]，客户端出站见
//! [`crate::outbound::shadowquic`]。

use std::net::SocketAddr;

use shadowquic::{
    config::{AuthUser, CongestionControl, JlsUpstream, ShadowQuicServerCfg},
    msgs::socks5::{AddrOrDomain, SocksAddr},
};

use crate::inbound::Target;

// ── 拥塞控制映射 ─────────────────────────────────────────────────────────────

/// 将配置字符串映射为 shadowquic [`CongestionControl`]。
///
/// 支持 `"bbr"`（默认）/ `"cubic"` / `"new-reno"` / `"brutal"`；未知值回退 BBR
/// （与 shadowquic crate serde 默认一致）。
pub fn parse_congestion_control(s: &str) -> CongestionControl {
    match s {
        "cubic" => CongestionControl::Cubic,
        "new-reno" => CongestionControl::NewReno,
        // 入站配置无 brutal 带宽字段，使用 crate 默认参数（对齐 flux 服务端行为）
        "brutal" => CongestionControl::Brutal(Default::default()),
        _ => CongestionControl::Bbr,
    }
}

// ── 地址互转 ─────────────────────────────────────────────────────────────────

/// 将 reflex [`Target`] 转换为 shadowquic [`SocksAddr`]（域名原样保留，不再二次解析）。
pub fn target_to_socks_addr(target: &Target) -> SocksAddr {
    match target {
        Target::Domain(host, port) => SocksAddr::from_domain(host.clone(), *port),
        Target::Socket(addr) => (*addr).into(),
    }
}

/// 将 shadowquic [`SocksAddr`] 转换回 reflex [`Target`]。
///
/// 域名按 UTF-8 lossy 解码（ShadowQuic 协议中域名即 bytes，理论上恒为合法 UTF-8）。
pub fn socks_addr_to_target(addr: &SocksAddr) -> Target {
    match &addr.addr {
        AddrOrDomain::V4(octets) => {
            Target::Socket(SocketAddr::new(std::net::IpAddr::V4((*octets).into()), addr.port))
        }
        AddrOrDomain::V6(octets) => {
            Target::Socket(SocketAddr::new(std::net::IpAddr::V6((*octets).into()), addr.port))
        }
        AddrOrDomain::Domain(var_vec) => Target::Domain(
            String::from_utf8_lossy(&var_vec.contents).into_owned(),
            addr.port,
        ),
    }
}

// ── 服务端配置映射 ───────────────────────────────────────────────────────────

/// 将 reflex 入站配置要素映射为 shadowquic crate 的 [`ShadowQuicServerCfg`]。
///
/// - `users`：`(username, password)` 列表，逐项转 crate [`AuthUser`]（JLS 凭证）
/// - `jls_upstream`：JLS 伪装上游（`host:port`，必须是真实 HTTPS 站点），不限速
/// - `server_name`：SNI 校验域名；未配置时从 `jls_upstream` 的 host 部分推断
///   （对齐 flux 服务端行为；再不可得则跳过 SNI 校验，由 crate 处理）
/// - 其余字段对齐 crate serde 默认值：alpn `["h3"]`、zero_rtt 开、
///   initial_mtu 1300 / min_mtu 1290、GSO 与 MTU 发现开、黑洞检测关
pub fn build_server_cfg(
    bind_addr: SocketAddr,
    users: Vec<(String, String)>,
    jls_upstream: &str,
    server_name: Option<String>,
    congestion_control: &str,
) -> ShadowQuicServerCfg {
    // server_name：未配置则从 jls_upstream 的 host 部分推断
    let server_name = server_name.or_else(|| {
        jls_upstream
            .split(':')
            .next()
            .map(|s| s.trim_start_matches('[').trim_end_matches(']'))
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    });

    ShadowQuicServerCfg {
        bind_addr,
        users: users
            .into_iter()
            .map(|(username, password)| AuthUser { username, password })
            .collect(),
        server_name,
        jls_upstream: JlsUpstream {
            addr: jls_upstream.to_string(),
            rate_limit: u64::MAX, // 不限速
        },
        alpn: vec!["h3".to_string()],
        zero_rtt: true,
        congestion_control: parse_congestion_control(congestion_control),
        initial_mtu: 1300,
        min_mtu: 1290,
        gso: true,
        mtu_discovery: true,
        blackhole_detection: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn congestion_control_mapping() {
        assert!(matches!(
            parse_congestion_control("bbr"),
            CongestionControl::Bbr
        ));
        assert!(matches!(
            parse_congestion_control("cubic"),
            CongestionControl::Cubic
        ));
        assert!(matches!(
            parse_congestion_control("new-reno"),
            CongestionControl::NewReno
        ));
        assert!(matches!(
            parse_congestion_control("brutal"),
            CongestionControl::Brutal(_)
        ));
        // 未知值回退 BBR
        assert!(matches!(
            parse_congestion_control("whatever"),
            CongestionControl::Bbr
        ));
    }

    #[test]
    fn target_socks_addr_roundtrip_domain() {
        let target = Target::Domain("example.com".into(), 443);
        let socks = target_to_socks_addr(&target);
        assert_eq!(socks.port, 443);
        match &socks.addr {
            AddrOrDomain::Domain(v) => {
                assert_eq!(v.contents, b"example.com");
            }
            _ => panic!("expected domain"),
        }
        let back = socks_addr_to_target(&socks);
        assert_eq!(back, target);
    }

    #[test]
    fn target_socks_addr_roundtrip_ipv4() {
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let socks = target_to_socks_addr(&target);
        assert_eq!(socks.port, 80);
        assert!(matches!(socks.addr, AddrOrDomain::V4([1, 2, 3, 4])));
        assert_eq!(socks_addr_to_target(&socks), target);
    }

    #[test]
    fn target_socks_addr_roundtrip_ipv6() {
        let target = Target::Socket("[2001:db8::1]:53".parse().unwrap());
        let socks = target_to_socks_addr(&target);
        assert_eq!(socks.port, 53);
        assert!(matches!(socks.addr, AddrOrDomain::V6(_)));
        assert_eq!(socks_addr_to_target(&socks), target);
    }

    #[test]
    fn build_server_cfg_fields() {
        let cfg = build_server_cfg(
            "0.0.0.0:1443".parse().unwrap(),
            vec![("u1".into(), "p1".into())],
            "camo.example.com:443",
            None,
            "bbr",
        );
        assert_eq!(cfg.bind_addr, "0.0.0.0:1443".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].username, "u1");
        assert_eq!(cfg.users[0].password, "p1");
        // server_name 未配置 → 从 jls_upstream 推断
        assert_eq!(cfg.server_name.as_deref(), Some("camo.example.com"));
        assert_eq!(cfg.jls_upstream.addr, "camo.example.com:443");
        assert_eq!(cfg.jls_upstream.rate_limit, u64::MAX);
        assert_eq!(cfg.alpn, vec!["h3".to_string()]);
        assert!(cfg.zero_rtt);
        assert_eq!(cfg.initial_mtu, 1300);
        assert_eq!(cfg.min_mtu, 1290);
        assert!(cfg.gso);
        assert!(cfg.mtu_discovery);
        assert!(!cfg.blackhole_detection);
        assert!(matches!(cfg.congestion_control, CongestionControl::Bbr));
    }

    #[test]
    fn build_server_cfg_explicit_server_name_wins() {
        let cfg = build_server_cfg(
            "127.0.0.1:443".parse().unwrap(),
            vec![],
            "1.2.3.4:443",
            Some("explicit.example.com".into()),
            "cubic",
        );
        assert_eq!(cfg.server_name.as_deref(), Some("explicit.example.com"));
        assert!(matches!(
            cfg.congestion_control,
            CongestionControl::Cubic
        ));
    }
}
