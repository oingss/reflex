use std::time::Duration;

use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::inbound::SniffedStream;

/// 嗅探结果
pub struct SniffResult {
    /// 识别出的域名（不含端口），若协议不携带域名则为 None
    pub domain: Option<String>,
    /// 应用层协议标识：`"tls"` / `"h2"` / `"http"` / `"quic"` / `"ssh"` /
    /// `"bittorrent"` / `"dns"` / `"dtls"` / `"stun"` / `"ntp"` / `"rdp"`
    pub protocol: &'static str,
}

/// 可选的嗅探协议类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SniffType {
    Tls,
    Http,
    Quic,
    Ssh,
    BitTorrent,
    /// DNS over UDP / DNS over TCP（2 字节长度前缀 + DNS 报文）
    Dns,
    /// DTLS 1.x record（UDP）
    Dtls,
    /// STUN 消息（UDP）
    Stun,
    /// NTP 客户端请求（UDP）
    Ntp,
    /// RDP over TPKT/COTP（TCP）
    Rdp,
}

impl SniffType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "tls" => Some(Self::Tls),
            "http" => Some(Self::Http),
            "quic" => Some(Self::Quic),
            "ssh" => Some(Self::Ssh),
            "bittorrent" | "bt" => Some(Self::BitTorrent),
            "dns" => Some(Self::Dns),
            "dtls" => Some(Self::Dtls),
            "stun" => Some(Self::Stun),
            "ntp" => Some(Self::Ntp),
            "rdp" => Some(Self::Rdp),
            _ => None,
        }
    }

    /// 默认启用的协议列表：仅 TLS / HTTP / QUIC 三种，覆盖日常上网场景
    /// （HTTPS 站点、HTTP 站点、HTTP/3 流量）。
    ///
    /// 设计动机：sing-box 默认列出了 6 种 TCP + QUIC 嗅探器，reflex 之前更激进
    /// 地默认启用 10 种。但对绝大多数上网流量而言，多余协议只会带来无谓开销
    /// （每个新连接都要尝试匹配）。SSH/BT/DNS/DTLS/STUN/NTP/RDP 等场景化
    /// 协议交给用户按需配置 `sniff_type` 字段。
    ///
    /// 如需启用其他协议，例如要做 WebRTC 视频通话分流：
    /// ```json
    /// { "sniff": true, "sniff_type": ["tls", "http", "quic", "stun", "dtls"] }
    /// ```
    pub fn defaults() -> Vec<Self> {
        vec![Self::Tls, Self::Http, Self::Quic]
    }
}

/// 默认嗅探超时
const DEFAULT_TIMEOUT_MS: u64 = 300;
/// 单次最多读取字节数（2048 字节在栈上完全安全，Rust 默认栈 8MB）
const PEEK_BUF_SIZE: usize = 2048;
/// 已读字节数达到此阈值仍未命中时提前停止，避免在长流上读满整个缓冲区。
/// 256 字节覆盖了常见协议头部（TLS ClientHello 含 SNI 一般 < 512）。
const GIVE_UP_BYTES: usize = 256;

/// 对 `stream` 进行非破坏性协议嗅探。
///
/// - `sniff_types`：为空时使用默认协议列表（TLS/HTTP/QUIC/SSH/BitTorrent）
/// - 读出最多 [`PEEK_BUF_SIZE`] 字节，解析后通过 `stream.prepend()` 归还
///
/// ## 动态读取（P3-1 优化）
///
/// 旧实现只调用一次 `read()`，若客户端首包不足协议识别所需最小字节
/// （如 TLS ClientHello 被分片、HTTP 请求行被切到第二个 segment），
/// 嗅探会直接失败。新实现采用**循环读取 + deadline**：
/// 1. 用 `tokio::time::Instant` 设定总 deadline
/// 2. 每次用 `timeout_at(deadline, read)` 读取，避免阻塞超过总超时
/// 3. 读到一批后立即尝试匹配；命中即返回
/// 4. 未命中且字节数 < [`GIVE_UP_BYTES`] 时继续读
/// 5. deadline 到 / EOF / 缓冲区满 / 已读 ≥ [`GIVE_UP_BYTES`] 仍未命中时终止
///
/// 这样可以在客户端慢启动或分片场景下仍正确识别协议，
/// 同时对正常情况（首包就足够）零额外开销（首轮就命中即返回）。
pub async fn sniff(
    stream: &mut SniffedStream,
    timeout_ms: u64,
    sniff_types: &[SniffType],
) -> Option<SniffResult> {
    let timeout = Duration::from_millis(if timeout_ms == 0 {
        DEFAULT_TIMEOUT_MS
    } else {
        timeout_ms
    });

    let defaults_storage;
    let effective_types: &[SniffType] = if sniff_types.is_empty() {
        defaults_storage = SniffType::defaults();
        &defaults_storage
    } else {
        sniff_types
    };

    // 优化：栈数组替代堆分配 vec。PEEK_BUF_SIZE=2048，远小于默认栈大小（8MB）。
    // 每条 TCP 连接触发嗅探时省去一次堆分配+释放。
    let mut buf = [0u8; PEEK_BUF_SIZE];
    let deadline = tokio::time::Instant::now() + timeout;
    let mut total = 0usize;

    loop {
        // 用 deadline 限制单次 read，避免超过总超时
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let n = match tokio::time::timeout_at(deadline, stream.inner.read(&mut buf[total..])).await
        {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => n,
            Ok(Err(_)) => break, // 读错误，停止
            Err(_) => break,     // 超时
        };
        if n == 0 {
            break;
        }
        total += n;

        // 每次读到新数据都尝试匹配
        let data = &buf[..total];
        for sniff_type in effective_types {
            let result = match sniff_type {
                SniffType::Tls => try_tls(data),
                SniffType::Http => try_http_host(data),
                SniffType::Quic => try_quic(data),
                SniffType::Ssh => try_ssh(data),
                SniffType::BitTorrent => try_bittorrent(data),
                SniffType::Dns => try_dns_stream(data),
                SniffType::Dtls => try_dtls(data),
                SniffType::Stun => try_stun(data),
                SniffType::Ntp => try_ntp(data),
                SniffType::Rdp => try_rdp(data),
            };
            if let Some(r) = result {
                // 命中：归还读出的字节并返回
                stream.prepend(bytes::Bytes::copy_from_slice(&buf[..total]));
                debug!(
                    domain = ?r.domain,
                    protocol = r.protocol,
                    bytes = total,
                    "sniffed"
                );
                return Some(r);
            }
        }

        // 缓冲区满，停止读取
        if total >= PEEK_BUF_SIZE {
            break;
        }

        // 已读 ≥ GIVE_UP_BYTES 字节仍未命中：认为协议不在 sniff_types 列表中，
        // 提前停止以节省 deadline 时间。
        if total >= GIVE_UP_BYTES {
            break;
        }

        // 字节数不足 GIVE_UP_BYTES 时继续读，可能是分片场景。
    }

    // 未命中：仍需归还读出的字节（保持非破坏性语义）
    if total > 0 {
        stream.prepend(bytes::Bytes::copy_from_slice(&buf[..total]));
        debug!(bytes = total, "sniff: no match after dynamic read");
    } else {
        debug!("sniff: no data read before deadline");
    }
    None
}

/// 对 UDP 包进行协议嗅探。
///
/// 支持的 UDP 协议：QUIC, DNS, DTLS, STUN, NTP, BitTorrent (uTP / UDP Tracker)。
/// 返回 `(protocol, domain)`。
pub fn sniff_packet(data: &[u8], sniff_types: &[SniffType]) -> Option<SniffResult> {
    let defaults_storage;
    let effective_types: &[SniffType] = if sniff_types.is_empty() {
        defaults_storage = SniffType::defaults();
        &defaults_storage
    } else {
        sniff_types
    };

    for sniff_type in effective_types {
        let result = match sniff_type {
            SniffType::Quic => try_quic(data),
            SniffType::Dns => try_dns_packet(data),
            SniffType::Dtls => try_dtls(data),
            SniffType::Stun => try_stun(data),
            SniffType::Ntp => try_ntp(data),
            SniffType::BitTorrent => try_bittorrent_udp(data),
            // TCP-only protocols are skipped for UDP packets
            SniffType::Tls | SniffType::Http | SniffType::Ssh | SniffType::Rdp => None,
        };
        if let Some(r) = result {
            return Some(r);
        }
    }
    None
}

// ── 嗅探过滤器（force_domain / skip_domain / skip_src_address）──────────────

/// 嗅探过滤器：决定是否对一条连接/包执行嗅探。
///
/// 三个字段的语义（对齐 sing-box `route.SniffOptions` 同名字段）：
/// - `force_domain`：白名单。非空时**仅**这些域名做嗅探；空 = 不限制。
/// - `skip_domain`：黑名单。命中则跳过嗅探。
/// - `skip_src_address`：源 IP CIDR 黑名单。命中则跳过嗅探。
///
/// 域名匹配规则（不区分大小写）：
/// - 入口以 `.` 开头 → 视为后缀匹配（`".cn"` 匹配 `"example.cn"`、`"a.b.cn"`）
/// - 入口不以 `.` 开头 → 视为「精确或后缀」匹配（`"google.com"` 匹配
///   `"google.com"` 与 `"www.google.com"`，但不匹配 `"notgoogle.com"`）
///
/// 该结构在 `CompiledRule::compile()` 期间一次性构造，热路径上仅做遍历比较。
#[derive(Debug, Clone, Default)]
pub struct SniffFilter {
    pub force_domain: Vec<String>,
    pub skip_domain: Vec<String>,
    /// 预解析的源 IP CIDR 列表（解析失败的条目会被丢弃并在编译期 warn）
    pub skip_src_address: Vec<(std::net::IpAddr, u8)>,
}

impl SniffFilter {
    /// 从原始配置字符串构造过滤器。无法解析的 CIDR 会被丢弃并记录 warning。
    pub fn from_config(
        force_domain: Vec<String>,
        skip_domain: Vec<String>,
        skip_src_address: Vec<String>,
    ) -> Self {
        let skip_src_address = skip_src_address
            .iter()
            .filter_map(|s| {
                if let Some((ip_str, prefix_str)) = s.split_once('/') {
                    let ip: std::net::IpAddr = match ip_str.parse() {
                        Ok(ip) => ip,
                        Err(e) => {
                            tracing::warn!(cidr = %s, err = %e, "sniff_filter: bad skip_src_address IP, dropped");
                            return None;
                        }
                    };
                    let prefix: u8 = match prefix_str.parse() {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(cidr = %s, err = %e, "sniff_filter: bad skip_src_address prefix, dropped");
                            return None;
                        }
                    };
                    // 简单范围校验（IPv4 ≤32，IPv6 ≤128）
                    let max = if ip.is_ipv4() { 32 } else { 128 };
                    if prefix > max {
                        tracing::warn!(cidr = %s, "sniff_filter: prefix out of range, dropped");
                        return None;
                    }
                    Some((ip, prefix))
                } else {
                    // 无前缀默认 /32 (v4) 或 /128 (v6)
                    match s.parse::<std::net::IpAddr>() {
                        Ok(ip) => {
                            let prefix = if ip.is_ipv4() { 32 } else { 128 };
                            Some((ip, prefix))
                        }
                        Err(e) => {
                            tracing::warn!(cidr = %s, err = %e, "sniff_filter: bad skip_src_address, dropped");
                            None
                        }
                    }
                }
            })
            .collect();

        Self {
            force_domain,
            skip_domain,
            skip_src_address,
        }
    }

    /// 判断是否应该对该条流量执行嗅探。
    /// - `target_host`：连接目标域名（来自 `Target::Domain` 或已嗅探到的域名）；
    ///   `None` 表示目标不是域名（如纯 IP）。无域名时 `force_domain` 自动放行
    ///   （白名单无法匹配，与 sing-box 行为一致：IP 目标不受 force_domain 限制）。
    /// - `src_ip`：连接来源 IP；`None` 视为不在任何 skip_src_address 命中范围内。
    pub fn should_sniff(
        &self,
        target_host: Option<&str>,
        src_ip: Option<std::net::IpAddr>,
    ) -> bool {
        // 1. 源 IP 黑名单优先级最高
        if let Some(ip) = src_ip {
            if self
                .skip_src_address
                .iter()
                .any(|(net_ip, prefix)| ip_in_cidr(ip, *net_ip, *prefix))
            {
                return false;
            }
        }

        // 2. 域名黑名单
        if let Some(host) = target_host {
            if self.skip_domain.iter().any(|p| domain_match(host, p)) {
                return false;
            }
        }

        // 3. 域名白名单（非空时仅这些域名通过）
        if !self.force_domain.is_empty() {
            // 白名单存在但目标无域名 → 与 sing-box 一致，IP 目标放行
            // （force_domain 只对域名生效，避免误屏蔽所有 IP 流量）
            if let Some(host) = target_host {
                if !self.force_domain.iter().any(|p| domain_match(host, p)) {
                    return false;
                }
            }
        }

        true
    }
}

/// 域名匹配（不区分大小写）：
/// - pattern 以 `.` 开头 → 后缀匹配（".cn" 匹配 "example.cn" 与 "a.b.cn"）
/// - 否则 → 精确或后缀匹配（"google.com" 匹配 "google.com" 与 "www.google.com"，
///   但不匹配 "notgoogle.com"）
fn domain_match(host: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let host = host.as_bytes();
    let pat = pattern.as_bytes();
    if pat[0] == b'.' {
        // 后缀匹配：host == pat 或 host 以 pat 结尾
        host.len() >= pat.len() && host[host.len() - pat.len()..].eq_ignore_ascii_case(pat)
    } else {
        // 精确或 .后缀
        host.eq_ignore_ascii_case(pat)
            || (host.len() > pat.len() + 1
                && host[host.len() - pat.len() - 1] == b'.'
                && host[host.len() - pat.len()..].eq_ignore_ascii_case(pat))
    }
}

/// 简易 CIDR 匹配（不引入 ipnet 依赖）
fn ip_in_cidr(ip: std::net::IpAddr, net_ip: std::net::IpAddr, prefix: u8) -> bool {
    match (ip, net_ip) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask: u32 = if prefix == 32 {
                u32::MAX
            } else {
                !((1u32 << (32 - prefix)) - 1)
            };
            let a_bits = u32::from(a);
            let b_bits = u32::from(b);
            (a_bits & mask) == (b_bits & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let a_bits = a.octets();
            let b_bits = b.octets();
            let full_bytes = (prefix / 8) as usize;
            let rem_bits = prefix % 8;
            if a_bits[..full_bytes] != b_bits[..full_bytes] {
                return false;
            }
            if rem_bits == 0 {
                return true;
            }
            let mask = !((1u8 << (8 - rem_bits)) - 1);
            (a_bits[full_bytes] & mask) == (b_bits[full_bytes] & mask)
        }
        // IPv4 vs IPv6 不匹配
        _ => false,
    }
}

#[cfg(test)]
mod sniff_filter_tests {
    use super::*;

    #[test]
    fn domain_match_exact_or_suffix() {
        assert!(domain_match("google.com", "google.com"));
        assert!(domain_match("www.google.com", "google.com"));
        assert!(!domain_match("notgoogle.com", "google.com"));
        assert!(!domain_match("google.com", ""));
    }

    #[test]
    fn domain_match_pure_suffix() {
        assert!(domain_match("example.cn", ".cn"));
        assert!(domain_match("a.b.cn", ".cn"));
        assert!(!domain_match("cn", ".cn"));
        assert!(!domain_match("notcnn", ".cn"));
    }

    #[test]
    fn domain_match_case_insensitive() {
        assert!(domain_match("Google.COM", "google.com"));
        assert!(domain_match("EXAMPLE.CN", ".cn"));
    }

    #[test]
    fn ipv4_cidr_match() {
        let ip: std::net::IpAddr = "192.168.1.5".parse().unwrap();
        let net: std::net::IpAddr = "192.168.0.0".parse().unwrap();
        assert!(ip_in_cidr(ip, net, 16));
        assert!(!ip_in_cidr(ip, net, 24)); // 192.168.1.x 不在 192.168.0.0/24
        let net2: std::net::IpAddr = "192.168.1.0".parse().unwrap();
        assert!(ip_in_cidr(ip, net2, 24));
        assert!(!ip_in_cidr(ip, net2, 32));
    }

    #[test]
    fn ipv6_cidr_match() {
        let ip: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        let net: std::net::IpAddr = "2001:db8::".parse().unwrap();
        assert!(ip_in_cidr(ip, net, 32));
        assert!(ip_in_cidr(ip, net, 64));
        let net2: std::net::IpAddr = "2001:db9::".parse().unwrap();
        assert!(!ip_in_cidr(ip, net2, 32));
    }

    #[test]
    fn should_sniff_filters() {
        let filter = SniffFilter::from_config(
            vec![],                                   // 不限制
            vec![".local".into(), "test.com".into()], // 黑名单
            vec!["127.0.0.0/8".into()],               // 源 IP 黑名单
        );

        // 普通域名不在黑名单中
        assert!(filter.should_sniff(Some("example.com"), None));
        // 黑名单后缀
        assert!(!filter.should_sniff(Some("my.local"), None));
        // 黑名单精确或后缀
        assert!(!filter.should_sniff(Some("test.com"), None));
        assert!(!filter.should_sniff(Some("sub.test.com"), None));
        assert!(filter.should_sniff(Some("notest.com"), None));
        // 源 IP 命中黑名单
        let local: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert!(!filter.should_sniff(Some("example.com"), Some(local)));
        let external: std::net::IpAddr = "8.8.8.8".parse().unwrap();
        assert!(filter.should_sniff(Some("example.com"), Some(external)));
    }

    #[test]
    fn force_domain_whitelist() {
        let filter =
            SniffFilter::from_config(vec![".cn".into(), "google.com".into()], vec![], vec![]);
        // 命中白名单
        assert!(filter.should_sniff(Some("example.cn"), None));
        assert!(filter.should_sniff(Some("google.com"), None));
        assert!(filter.should_sniff(Some("www.google.com"), None));
        // 未命中白名单 → 不嗅探
        assert!(!filter.should_sniff(Some("example.org"), None));
        // 无域名（IP 目标）→ 与 sing-box 一致放行
        assert!(filter.should_sniff(None, None));
    }

    #[test]
    fn bad_cidr_dropped() {
        let filter = SniffFilter::from_config(
            vec![],
            vec![],
            vec![
                "not_an_ip".into(),
                "192.168.0.0/notanum".into(),
                "10.0.0.0/8".into(),
            ],
        );
        assert_eq!(filter.skip_src_address.len(), 1);
    }
}

// ── TLS ClientHello 解析 ──────────────────────────────────────────────────────
//
// TLS record 格式（RFC 5246 §6.2）:
//   ContentType(1) Version(2) Length(2) Handshake...
// Handshake ClientHello（RFC 5246 §7.4.1.2）:
//   HandshakeType(1)=0x01 Length(3) ProtocolVersion(2)
//   Random(32) SessionIDLen(1) SessionID(var)
//   CipherSuitesLen(2) CipherSuites(var)
//   CompressionMethodsLen(1) CompressionMethods(var)
//   ExtensionsLen(2) Extensions(var)
// SNI extension  type 0x0000 （RFC 6066 §3）
// ALPN extension type 0x0010 （RFC 7301 §3）

fn try_tls(buf: &[u8]) -> Option<SniffResult> {
    if buf.len() < 43 {
        return None;
    }
    if buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    if buf[5] != 0x01 {
        return None;
    }

    let mut pos = 5 + 4 + 2 + 32;

    if pos >= buf.len() {
        return None;
    }
    let sid_len = buf[pos] as usize;
    pos += 1 + sid_len;

    if pos + 2 > buf.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > buf.len() {
        return None;
    }
    let cm_len = buf[pos] as usize;
    pos += 1 + cm_len;

    // Extensions 字段是可选的（RFC 5246：TLS 1.2 以下 ClientHello 可不含扩展）。
    // 若缓冲区在压缩方法后结束，说明无扩展——仍应识别为 TLS。
    if pos + 2 > buf.len() {
        return Some(SniffResult {
            domain: None,
            protocol: "tls",
        });
    }
    let ext_total = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let ext_end = (pos + ext_total).min(buf.len());

    let mut sni: Option<String> = None;
    let mut is_h2 = false;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        let ext_data_end = (pos + ext_len).min(ext_end);

        match ext_type {
            0x0000 if pos + 2 <= ext_data_end => {
                let mut p = pos + 2;
                if p < ext_data_end && buf[p] == 0x00 {
                    p += 1;
                    if p + 2 <= ext_data_end {
                        let name_len = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
                        p += 2;
                        if p + name_len <= ext_data_end {
                            if let Ok(name) = std::str::from_utf8(&buf[p..p + name_len]) {
                                sni = Some(name.to_string());
                            }
                        }
                    }
                }
            }
            0x0010 if pos + 2 <= ext_data_end => {
                let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                let mut p = pos + 2;
                let list_end = (p + list_len).min(ext_data_end);
                while p < list_end {
                    let proto_len = buf[p] as usize;
                    p += 1;
                    if p + proto_len <= list_end {
                        if &buf[p..p + proto_len] == b"h2" {
                            is_h2 = true;
                        }
                        p += proto_len;
                    } else {
                        break;
                    }
                }
            }
            _ => {}
        }

        pos = ext_data_end;

        if sni.is_some() && is_h2 {
            break;
        }
    }

    // 对齐 sing-box：即使 ClientHello 不含 SNI 扩展，仍应识别为 TLS 协议。
    // sing-box TLSClientHello 在 clientHello != nil 时设置 Protocol = "tls"，
    // Domain = clientHello.ServerName（可能为空字符串）。
    // 旧实现在 sni = None 时直接返回 None，导致 protocol: ["tls"] 路由规则
    // 无法匹配无 SNI 的 TLS 连接（如某些 IP 直连证书）。
    Some(SniffResult {
        domain: sni,
        protocol: if is_h2 { "h2" } else { "tls" },
    })
}

// ── HTTP/1.x Host 解析 ───────────────────────────────────────────────────────

fn try_http_host(buf: &[u8]) -> Option<SniffResult> {
    let text = std::str::from_utf8(buf).ok()?;

    let first_line_end = text.find("\r\n")?;
    let first_line = &text[..first_line_end];
    if !first_line.contains(" HTTP/") {
        return None;
    }

    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host:") {
            let host = rest.trim();
            let domain = host.split(':').next().unwrap_or(host);
            if !domain.is_empty() {
                return Some(SniffResult {
                    domain: Some(domain.to_string()),
                    protocol: "http",
                });
            }
        }
    }

    None
}

// ── QUIC ClientHello SNI 解析 ─────────────────────────────────────────────────
//
// 解析 QUIC Initial 包（QUIC v1/v2/Draft-29）中的 ClientHello SNI。
// 参照 sing-box common/sniff/quic.go 和 RFC 9001。
//
// QUIC Long Header Initial 包格式:
//   First byte (1): 0x40 | type bits
//   Version (4)
//   Dest Conn ID Len (1) + Dest Conn ID (var)
//   Src  Conn ID Len (1) + Src  Conn ID (var)
//   Token Len (varint)   + Token (var)
//   Packet Len (varint)
//   Packet Number (1-4, AEAD 保护，需解密)
//   QUIC Crypto frame → TLS ClientHello (AEAD 保护，需解密)
//
// QUIC 使用 HKDF 派生的 Initial secrets 对 Initial 包加密，
// 本实现对 Initial 包做 AEAD 解密后提取内嵌 TLS ClientHello 中的 SNI。

fn try_quic(buf: &[u8]) -> Option<SniffResult> {
    // 最小长度检查：first byte + version(4) + dcil(1)
    if buf.len() < 6 {
        return None;
    }
    // Long header: 最高位为1，Fixed bit(0x40)必须为1
    if buf[0] & 0xC0 != 0xC0 {
        return None;
    }

    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    // 仅支持 QUIC v1 (0x00000001), v2 (0x6b3343cf), Draft-29 (0xff00001d)
    let (is_v2, initial_salt) = match version {
        0x00000001 => (false, QUIC_V1_INITIAL_SALT.as_slice()),
        0x6b3343cf => (true, QUIC_V2_INITIAL_SALT.as_slice()),
        0xff00001d => (false, QUIC_DRAFT29_INITIAL_SALT.as_slice()),
        _ => return None,
    };

    // 检查 packet type = Initial (0x00 for v1/draft, 0x01 for v2)
    let ptype = (buf[0] & 0x30) >> 4;
    let expected_ptype = if is_v2 { 0x01 } else { 0x00 };
    if ptype != expected_ptype {
        return None;
    }

    let mut pos = 5usize;

    // Destination Connection ID
    if pos >= buf.len() {
        return None;
    }
    let dcid_len = buf[pos] as usize;
    pos += 1;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    if pos + dcid_len > buf.len() {
        return None;
    }
    let dcid = &buf[pos..pos + dcid_len];
    pos += dcid_len;

    // Source Connection ID
    if pos >= buf.len() {
        return None;
    }
    let scid_len = buf[pos] as usize;
    pos += 1;
    if pos + scid_len > buf.len() {
        return None;
    }
    pos += scid_len;

    // Token
    let (token_len, vl) = read_varint(buf, pos)?;
    pos += vl + token_len as usize;

    // Packet Length
    let (pkt_len, vl2) = read_varint(buf, pos)?;
    pos += vl2;

    if pos >= buf.len() {
        return None;
    }
    // 注意：`pos` 现在指向 packet number 的起始位置（紧跟 Length 字段）。
    // QUIC Initial 包结构：[Header 第一字节][ver(4)][DCIL][DCID][SCIL][SCID][Token][Length][PN(1-4)][ciphertext+tag]
    // 旧实现把 `&buf[pos..]` 当作"加密负载"传给解密函数，但里面把 `payload[0]`
    // 误当成 QUIC 包头第一字节来恢复 pn_len，导致 pn_len 是随机值、AAD 构造错误、
    // 整个解密必然失败。这里改为传入完整 buf + pn_offset，让解密函数自己重建 AAD。
    let pn_offset = pos;
    let encrypted_payload = &buf[pn_offset..pos.saturating_add(pkt_len as usize).min(buf.len())];
    if encrypted_payload.is_empty() {
        return None;
    }

    // 派生 Initial secrets 并解密
    let plaintext = decrypt_quic_initial(
        dcid,
        initial_salt,
        buf,
        pn_offset,
        encrypted_payload.len(),
        is_v2,
    )?;

    // 从解密后的 QUIC CRYPTO frame 中提取 TLS ClientHello
    extract_sni_from_quic_crypto(&plaintext)
}

// QUIC Initial salt 常量
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_INITIAL_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const QUIC_DRAFT29_INITIAL_SALT: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

/// 读取 QUIC 可变长整数，返回 (值, 已消耗字节数)
fn read_varint(buf: &[u8], pos: usize) -> Option<(u64, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let first = buf[pos];
    let prefix = (first & 0xC0) >> 6;
    match prefix {
        0 => Some((first as u64 & 0x3F, 1)),
        1 => {
            if pos + 2 > buf.len() {
                return None;
            }
            let v = u16::from_be_bytes([first & 0x3F, buf[pos + 1]]);
            Some((v as u64, 2))
        }
        2 => {
            if pos + 4 > buf.len() {
                return None;
            }
            let v = u32::from_be_bytes([first & 0x3F, buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
            Some((v as u64, 4))
        }
        3 => {
            if pos + 8 > buf.len() {
                return None;
            }
            let v = u64::from_be_bytes([
                first & 0x3F,
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
                buf[pos + 4],
                buf[pos + 5],
                buf[pos + 6],
                buf[pos + 7],
            ]);
            Some((v, 8))
        }
        _ => None,
    }
}

/// 使用 HKDF + AES-128-GCM 解密 QUIC Initial 包负载。
/// 参照 RFC 9001 §5.2 和 sing-box 实现。
///
/// 关键修正：
/// - 旧实现把 `payload[0]` 当作 QUIC 包头第一字节来恢复 `pn_len`，但 `payload`
///   实际从 packet number 字段开始，`payload[0]` 是已加密的 PN 第一字节 → pn_len
///   是随机值、AAD 构造错误、解密必然失败。这里改为传入完整 `buf` 和 `pn_offset`
///   （PN 在 buf 中的偏移），用 `buf[0]` 作为 QUIC 包头第一字节。
/// - AAD = `buf[0..pn_offset+pn_len]`（QUIC 长包头第一字节 + 后续字段 + 已恢复的
///   packet number 字节），对齐 RFC 9000 §17.2.2 的 AAD 构造。
/// - GCM tag 验证补齐 `E(K, J0) XOR` 步骤（旧 gcm_tag 只返回 GHASH）。
fn decrypt_quic_initial(
    dcid: &[u8],
    initial_salt: &[u8],
    buf: &[u8],
    pn_offset: usize,
    payload_len: usize,
    is_v2: bool,
) -> Option<Vec<u8>> {
    // HKDF-Extract(initial_salt, dcid) → initial_secret
    let initial_secret = hkdf_extract_sha256(initial_salt, dcid);

    // HKDF-Expand-Label(initial_secret, "client in", "", 32) → client_initial_secret
    let client_secret = hkdf_expand_label_sha256(&initial_secret, b"client in", b"", 32)?;

    // 派生 key(16), iv(12), hp(16)
    // 关键：QUIC v2 (RFC 9369) 使用不同的 HKDF label 前缀（"quicv2 " vs "quic "）。
    // 旧实现始终使用 v1 label，导致 v2 Initial 包解密 100% 失败（GCM tag 不匹配）。
    let (key_label, iv_label, hp_label): (&[u8], &[u8], &[u8]) = if is_v2 {
        (b"quicv2 key", b"quicv2 iv", b"quicv2 hp")
    } else {
        (b"quic key", b"quic iv", b"quic hp")
    };
    let key = hkdf_expand_label_sha256(&client_secret, key_label, b"", 16)?;
    let iv = hkdf_expand_label_sha256(&client_secret, iv_label, b"", 12)?;
    let hp = hkdf_expand_label_sha256(&client_secret, hp_label, b"", 16)?;

    if payload_len < 20 {
        return None;
    }

    // Header Protection: sample 取自 packet number 之后 16 字节
    // (RFC 9001 §5.4.2: sample = pn_offset+4 .. pn_offset+20)
    if pn_offset + 20 > buf.len() {
        return None;
    }
    let sample = &buf[pn_offset + 4..pn_offset + 20];
    let mask = aes128_ecb_block(&hp, sample)?;

    // 还原 QUIC 包头第一字节的低 4 位（long header: mask 0-3 位作用于 first byte）
    // 关键：用 buf[0]（真正的 QUIC 第一字节），不是 payload[0]（已加密 PN 字节）。
    let first_byte = buf[0] ^ (mask[0] & 0x0F);
    let pn_len = ((first_byte & 0x03) + 1) as usize;

    if payload_len < pn_len + 16 {
        return None;
    }

    // 还原 packet number 字节（位于 buf[pn_offset..pn_offset+pn_len]）
    let mut pn_bytes = [0u8; 4];
    for i in 0..pn_len {
        pn_bytes[i] = buf[pn_offset + i] ^ mask[1 + i];
    }
    // packet_number（截断形式，仅用于 nonce）
    let pn = u32::from_be_bytes(pn_bytes);

    // 构造 AEAD nonce = iv XOR packet_number（右对齐）
    let mut nonce = iv.clone();
    let pn_be = pn.to_be_bytes();
    for i in 0..4 {
        nonce[8 + i] ^= pn_be[i];
    }

    // 密文 = buf[pn_offset+pn_len .. pn_offset+payload_len-16]
    // AEAD tag = buf[pn_offset+payload_len-16 .. pn_offset+payload_len]
    let ciphertext_start = pn_offset + pn_len;
    let ciphertext_end = pn_offset + payload_len - 16;
    if ciphertext_end < ciphertext_start || ciphertext_end + 16 > buf.len() {
        return None;
    }
    let ciphertext = &buf[ciphertext_start..ciphertext_end];
    let tag = &buf[ciphertext_end..ciphertext_end + 16];

    // 构造 AAD = 完整 QUIC 长包头 + 已恢复的 packet number 字节
    // (RFC 9000 §17.2.2: AAD = Header + PN，PN 用解掩码后的明文字节)
    // 布局：[unmasked first_byte][buf[1..pn_offset] = ver|DCIL|DCID|SCIL|SCID|Token|Len][unmasked PN]
    let mut aad = Vec::with_capacity(pn_offset + pn_len);
    aad.push(first_byte);
    aad.extend_from_slice(&buf[1..pn_offset]);
    aad.extend_from_slice(&pn_bytes[..pn_len]);

    // AES-128-GCM 解密
    aes128_gcm_decrypt(&key, &nonce, &aad, ciphertext, tag)
}

/// HKDF-Extract with SHA-256
fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac_sha256(salt, ikm)
}

/// HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 64;
    let mut k = if key.len() > BLOCK_SIZE {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    k.resize(BLOCK_SIZE, 0);

    let mut ipad = vec![0x36u8; BLOCK_SIZE];
    let mut opad = vec![0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = ipad;
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    let mut outer = opad;
    outer.extend_from_slice(&inner_hash);
    sha256(&outer).to_vec()
}

/// HKDF-Expand-Label (TLS 1.3 style)
fn hkdf_expand_label_sha256(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    // HkdfLabel = length(2) + label_len(1) + "tls13 " + label + context_len(1) + context
    let prefix = b"tls13 ";
    let full_label_len = prefix.len() + label.len();
    let mut hkdf_label = Vec::with_capacity(2 + 1 + full_label_len + 1 + context.len());
    hkdf_label.push((len >> 8) as u8);
    hkdf_label.push(len as u8);
    hkdf_label.push(full_label_len as u8);
    hkdf_label.extend_from_slice(prefix);
    hkdf_label.extend_from_slice(label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // HKDF-Expand: T(1) = HMAC(secret, hkdf_label || 0x01)
    // 只需第一块（len <= 32 时）
    if len > 32 {
        return None;
    }
    let mut info = hkdf_label;
    info.push(0x01);
    let t = hmac_sha256(secret, &info);
    Some(t[..len].to_vec())
}

/// 纯 Rust SHA-256（无外部依赖）
fn sha256(data: &[u8]) -> [u8; 32] {
    // 使用 Rust 标准库不包含 SHA-256，这里实现一个简单版本
    // K 常量
    #[allow(clippy::unreadable_literal)]
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    // 预处理
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    // 处理每个 512-bit 块
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// AES-128-ECB 加密单块（16字节）
fn aes128_ecb_block(key: &[u8], block: &[u8]) -> Option<[u8; 16]> {
    if key.len() != 16 || block.len() < 16 {
        return None;
    }
    let mut state = [0u8; 16];
    state.copy_from_slice(&block[..16]);
    let round_keys = aes128_key_schedule(key);
    aes128_encrypt_block(&mut state, &round_keys);
    Some(state)
}

/// AES-128-GCM 解密
fn aes128_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    if key.len() != 16 || nonce.len() != 12 || tag.len() != 16 {
        return None;
    }

    let round_keys = aes128_key_schedule(key);

    // GCM counter: J0 = nonce || 0x00000001
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;

    // 验证 GCM tag：tag = GHASH(H, AAD, C) XOR E(K, J0)
    // 旧实现 gcm_tag 只返回 GHASH，缺失 E(K, J0) XOR，导致 computed_tag != tag
    // 永远成立 → QUIC SNI 嗅探 100% 失败。这里补齐 E(K, J0) XOR。
    let h_block = {
        let mut b = [0u8; 16];
        aes128_encrypt_block(&mut b, &round_keys);
        b
    };
    let ghash = gcm_ghash(&h_block, aad, ciphertext);
    let mut e_j0 = j0;
    aes128_encrypt_block(&mut e_j0, &round_keys);
    let mut computed_tag = [0u8; 16];
    for i in 0..16 {
        computed_tag[i] = ghash[i] ^ e_j0[i];
    }
    if &computed_tag[..] != tag {
        return None; // tag 不匹配（加密数据或连接不是 QUIC Initial）
    }

    // CTR 解密：counter 从 J0+1 开始
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = j0;
    gcm_inc32(&mut counter);

    for chunk in ciphertext.chunks(16) {
        let mut keystream = counter;
        aes128_encrypt_block(&mut keystream, &round_keys);
        for (i, &b) in chunk.iter().enumerate() {
            plaintext.push(b ^ keystream[i]);
        }
        gcm_inc32(&mut counter);
    }

    Some(plaintext)
}

fn gcm_inc32(block: &mut [u8; 16]) {
    let n = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    let n = n.wrapping_add(1);
    block[12..].copy_from_slice(&n.to_be_bytes());
}

/// GCM GHASH 计算（不含 E(K, J0) XOR，由调用方负责）。
/// 输入：H = E(K, 0^128)，AAD，密文；输出 GHASH(H, AAD, C)。
fn gcm_ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];

    // GHASH over AAD
    for chunk in padded_chunks(aad) {
        xor16(&mut y, &chunk);
        y = gf128_mul(&y, h);
    }
    // GHASH over ciphertext
    for chunk in padded_chunks(ciphertext) {
        xor16(&mut y, &chunk);
        y = gf128_mul(&y, h);
    }
    // GHASH over lengths
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    xor16(&mut y, &len_block);
    y = gf128_mul(&y, h);

    y
}

fn padded_chunks(data: &[u8]) -> impl Iterator<Item = [u8; 16]> + '_ {
    let full = data.len() / 16;
    let rem = data.len() % 16;
    (0..full)
        .map(move |i| {
            let mut b = [0u8; 16];
            b.copy_from_slice(&data[i * 16..(i + 1) * 16]);
            b
        })
        .chain(if rem > 0 {
            let mut b = [0u8; 16];
            b[..rem].copy_from_slice(&data[full * 16..]);
            Some(b).into_iter()
        } else {
            None.into_iter()
        })
}

fn xor16(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// GF(2^128) 乘法，多项式 x^128 + x^7 + x^2 + x + 1
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;
    for i in 0..128 {
        let byte = i / 8;
        let bit = 7 - (i % 8);
        if (x[byte] >> bit) & 1 == 1 {
            xor16(&mut z, &v);
        }
        let lsb = v[15] & 1;
        // v >> 1
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j - 1] & 1) << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xE1; // 对应多项式 x^128 + x^7 + x^2 + x + 1 的归约
        }
    }
    z
}

// ── AES-128 实现 ──────────────────────────────────────────────────────────────

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn xtime(x: u8) -> u8 {
    (x << 1) ^ if x & 0x80 != 0 { 0x1b } else { 0 }
}

fn aes128_key_schedule(key: &[u8]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[i * 4..i * 4 + 4]);
    }
    for i in 4..44 {
        let mut temp = w[i - 1];
        if i % 4 == 0 {
            temp.rotate_left(1);
            for b in temp.iter_mut() {
                *b = SBOX[*b as usize];
            }
            temp[0] ^= RCON[i / 4 - 1];
        }
        for j in 0..4 {
            w[i][j] = w[i - 4][j] ^ temp[j];
        }
    }
    let mut round_keys = [[0u8; 16]; 11];
    for i in 0..11 {
        for j in 0..4 {
            round_keys[i][j * 4..j * 4 + 4].copy_from_slice(&w[i * 4 + j]);
        }
    }
    round_keys
}

fn aes128_encrypt_block(state: &mut [u8; 16], round_keys: &[[u8; 16]; 11]) {
    // AddRoundKey 0
    for i in 0..16 {
        state[i] ^= round_keys[0][i];
    }
    for (round, rk) in round_keys[1..]
        .iter()
        .enumerate()
        .map(|(i, rk)| (i + 1, rk))
    {
        // SubBytes
        for b in state.iter_mut() {
            *b = SBOX[*b as usize];
        }
        // ShiftRows
        let s = *state;
        state[1] = s[5];
        state[5] = s[9];
        state[9] = s[13];
        state[13] = s[1];
        state[2] = s[10];
        state[6] = s[14];
        state[10] = s[2];
        state[14] = s[6];
        state[3] = s[15];
        state[7] = s[3];
        state[11] = s[7];
        state[15] = s[11];
        // MixColumns (skip for round 10)
        if round < 10 {
            for col in 0..4 {
                let i = col * 4;
                let s0 = state[i];
                let s1 = state[i + 1];
                let s2 = state[i + 2];
                let s3 = state[i + 3];
                state[i] = xtime(s0) ^ xtime(s1) ^ s1 ^ s2 ^ s3;
                state[i + 1] = s0 ^ xtime(s1) ^ xtime(s2) ^ s2 ^ s3;
                state[i + 2] = s0 ^ s1 ^ xtime(s2) ^ xtime(s3) ^ s3;
                state[i + 3] = xtime(s0) ^ s0 ^ s1 ^ s2 ^ xtime(s3);
            }
        }
        // AddRoundKey
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }
}

/// 从解密后的 QUIC CRYPTO frame 载荷中提取 TLS ClientHello SNI
///
/// 对齐 sing-box QUICClientHello：收集所有 CRYPTO frame 片段（含 offset），
/// 按 offset 排序后拼接为完整的 TLS Handshake message，再解析 ClientHello。
/// 旧实现只取第一个 CRYPTO frame，当 ClientHello 被拆分到多个 CRYPTO frame
/// 时（Chrome 对大 ClientHello 会拆分），SNI 提取失败。
fn extract_sni_from_quic_crypto(data: &[u8]) -> Option<SniffResult> {
    // QUIC frame types (RFC 9000 §19)
    const FRAME_TYPE_PADDING: u8 = 0x00;
    const FRAME_TYPE_PING: u8 = 0x01;
    const FRAME_TYPE_ACK: u8 = 0x02;
    const FRAME_TYPE_ACK_ECN: u8 = 0x03;
    const FRAME_TYPE_CRYPTO: u8 = 0x06;
    const FRAME_TYPE_CONNECTION_CLOSE: u8 = 0x1c;

    // 收集所有 CRYPTO frame 片段 (offset, data)
    let mut fragments: Vec<(u64, &[u8])> = Vec::new();

    let mut pos = 0;
    while pos < data.len() {
        let frame_type = data[pos];
        pos += 1;
        match frame_type {
            FRAME_TYPE_PADDING | FRAME_TYPE_PING => {
                // 无载荷，继续
            }
            FRAME_TYPE_ACK | FRAME_TYPE_ACK_ECN => {
                // ACK frame: Largest Acknowledged(varint), ACK Delay(varint),
                // ACK Range Count(varint), First ACK Range(varint),
                // [Gap(varint), ACK Range Length(varint)] * ack_range_count
                // 若 ECN (type 0x03): 额外 3 个 varint (ECT0, ECT1, ECN-CE)
                let (largest_ack, vl) = read_varint(data, pos)?;
                pos += vl;
                let (_ack_delay, vl) = read_varint(data, pos)?;
                pos += vl;
                let (ack_range_count, vl) = read_varint(data, pos)?;
                pos += vl;
                let (_first_ack_range, vl) = read_varint(data, pos)?;
                pos += vl;
                let _ = largest_ack;
                for _ in 0..ack_range_count {
                    let (_, vl) = read_varint(data, pos)?;
                    pos += vl;
                    let (_, vl) = read_varint(data, pos)?;
                    pos += vl;
                }
                if frame_type == FRAME_TYPE_ACK_ECN {
                    // ECT0 Count, ECT1 Count, ECN-CE Count
                    for _ in 0..3 {
                        let (_, vl) = read_varint(data, pos)?;
                        pos += vl;
                    }
                }
            }
            FRAME_TYPE_CRYPTO => {
                // CRYPTO frame: offset(varint), length(varint), data
                let (offset, vl) = read_varint(data, pos)?;
                pos += vl;
                let (length, vl2) = read_varint(data, pos)?;
                pos += vl2;
                let end = (pos + length as usize).min(data.len());
                let crypto_data = &data[pos..end];
                fragments.push((offset, crypto_data));
                pos = end;
            }
            FRAME_TYPE_CONNECTION_CLOSE => {
                // CONNECTION_CLOSE: Error Code(varint), Frame Type(varint),
                // Reason Phrase Length(varint), Reason Phrase(var)
                let (_, vl) = read_varint(data, pos)?;
                pos += vl;
                let (_, vl) = read_varint(data, pos)?;
                pos += vl;
                let (reason_len, vl) = read_varint(data, pos)?;
                pos += vl;
                pos += reason_len as usize;
            }
            _ => break,
        }
    }

    if fragments.is_empty() {
        return None;
    }

    // 按 offset 排序并拼接（对齐 sing-box 的 fragment reassembly）
    fragments.sort_by_key(|(offset, _)| *offset);
    let mut reassembled = Vec::new();
    let mut expected_offset = 0u64;
    for (offset, payload) in &fragments {
        if *offset == expected_offset {
            reassembled.extend_from_slice(payload);
            expected_offset = offset + payload.len() as u64;
        } else if *offset > expected_offset {
            // 间隙：填充零（对齐 sing-box 的行为，缺失数据用零填充）
            let gap = (*offset - expected_offset) as usize;
            reassembled.extend(std::iter::repeat_n(0u8, gap));
            reassembled.extend_from_slice(payload);
            expected_offset = offset + payload.len() as u64;
        }
        // offset < expected_offset 的重复片段跳过
    }

    // TLS Handshake: type(1)=0x01(ClientHello), length(3), ...
    if reassembled.len() >= 4 && reassembled[0] == 0x01 {
        // 构造一个假 TLS record 头让 try_tls 解析
        let handshake_len = reassembled.len();
        let mut fake_record = vec![0x16u8, 0x03, 0x03];
        // TLS record length (2 bytes, big-endian)
        fake_record.push((handshake_len >> 8) as u8);
        fake_record.push(handshake_len as u8);
        fake_record.extend_from_slice(&reassembled);
        return try_tls(&fake_record);
    }

    None
}

// ── SSH 协议检测 ──────────────────────────────────────────────────────────────
//
// SSH 连接以 "SSH-" 开头（RFC 4253 §4.2）

fn try_ssh(buf: &[u8]) -> Option<SniffResult> {
    if buf.starts_with(b"SSH-") {
        Some(SniffResult {
            domain: None,
            protocol: "ssh",
        })
    } else {
        None
    }
}

// ── BitTorrent 握手检测 ───────────────────────────────────────────────────────
//
// BitTorrent 握手格式（BEP 003）:
//   pstrlen(1) = 19
//   pstr(19) = "BitTorrent protocol"
//   reserved(8)
//   info_hash(20)
//   peer_id(20)

fn try_bittorrent(buf: &[u8]) -> Option<SniffResult> {
    const BT_HEADER: &[u8] = b"\x13BitTorrent protocol";
    if buf.len() >= BT_HEADER.len() && buf.starts_with(BT_HEADER) {
        Some(SniffResult {
            domain: None,
            protocol: "bittorrent",
        })
    } else {
        None
    }
}

// ── BitTorrent UDP (uTP + UDP Tracker) ────────────────────────────────────────
//
// 对齐 sing-box UTP 和 UDPTracker：
// - uTP (BEP 0029): version=1, type<=4, extension 链合法
// - UDP Tracker (BEP 0015): protocol_id=0x41727101980, action=0 (connect)

fn try_bittorrent_udp(buf: &[u8]) -> Option<SniffResult> {
    if try_utp(buf).is_some() || try_udp_tracker(buf).is_some() {
        return Some(SniffResult {
            domain: None,
            protocol: "bittorrent",
        });
    }
    None
}

/// uTP (Micro Transport Protocol, BEP 0029)
fn try_utp(buf: &[u8]) -> Option<()> {
    if buf.len() < 20 {
        return None;
    }
    let version = buf[0] & 0x0F;
    let ty = buf[0] >> 4;
    if version != 1 || ty > 4 {
        return None;
    }
    // 验证 extension 链（从 byte 1 开始，0 表示结束）
    let mut extension = buf[1];
    let mut pos = 20usize;
    while extension != 0 {
        if pos >= buf.len() {
            return None;
        }
        extension = buf[pos];
        pos += 1;
        if extension > 0x04 {
            return None;
        }
        if pos >= buf.len() {
            return None;
        }
        let ext_len = buf[pos] as usize;
        pos += 1 + ext_len;
        if pos > buf.len() {
            return None;
        }
    }
    Some(())
}

/// UDP Tracker Protocol (BEP 0015) — connect 请求
fn try_udp_tracker(buf: &[u8]) -> Option<()> {
    if buf.len() < 16 {
        return None;
    }
    let protocol_id = u64::from_be_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    if protocol_id != 0x41727101980 {
        return None;
    }
    let action = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if action != 0 {
        return None;
    }
    Some(())
}

// ── DNS over TCP / DNS over UDP ───────────────────────────────────────────────

/// DNS over TCP：2 字节长度前缀 + DNS 报文
fn try_dns_stream(buf: &[u8]) -> Option<SniffResult> {
    if buf.len() < 14 {
        return None;
    }
    let length = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if length < 12 || buf.len() < 2 + length {
        return None;
    }
    let dns_data = &buf[2..2 + length];
    if is_dns_wire(dns_data) {
        Some(SniffResult {
            domain: None,
            protocol: "dns",
        })
    } else {
        None
    }
}

/// DNS over UDP：直接 DNS 报文
fn try_dns_packet(buf: &[u8]) -> Option<SniffResult> {
    if is_dns_wire(buf) {
        Some(SniffResult {
            domain: None,
            protocol: "dns",
        })
    } else {
        None
    }
}

// ── DTLS 1.x record 检测（UDP）─────────────────────────────────────────────────
//
// 对齐 sing-box DTLSRecord：
//   ContentType(1) ∈ {20,21,22,23,25}
//   Version = 0xfeff (DTLS 1.0) 或 0xfefd (DTLS 1.2)

fn try_dtls(buf: &[u8]) -> Option<SniffResult> {
    const FIXED_HEADER_SIZE: usize = 13;
    if buf.len() < FIXED_HEADER_SIZE {
        return None;
    }
    let content_type = buf[0];
    match content_type {
        20 | 21 | 22 | 23 | 25 => {}
        _ => return None,
    }
    if buf[1] != 0xfe {
        return None;
    }
    if buf[2] != 0xff && buf[2] != 0xfd {
        return None;
    }
    Some(SniffResult {
        domain: None,
        protocol: "dtls",
    })
}

// ── STUN 消息检测（UDP）─────────────────────────────────────────────────────────
//
// 对齐 sing-box STUNMessage：
//   前 4 字节：type(2) + length(2)
//   bytes[4..8] = magic cookie 0x2112A442
//   总长度 >= 20 + length

fn try_stun(buf: &[u8]) -> Option<SniffResult> {
    if buf.len() < 20 {
        return None;
    }
    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if magic != 0x2112A442 {
        return None;
    }
    let message_length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if buf.len() < 20 + message_length {
        return None;
    }
    Some(SniffResult {
        domain: None,
        protocol: "stun",
    })
}

// ── NTP 客户端请求检测（UDP）────────────────────────────────────────────────────
//
// 对齐 sing-box NTP：
//   LI(2bit) <= 3, VN(3bit) ∈ {3,4}, Mode(3bit) = 3 (client)
//   Root Delay / Root Dispersion 不超过 16 秒

fn try_ntp(buf: &[u8]) -> Option<SniffResult> {
    if buf.len() < 48 {
        return None;
    }
    let first_byte = buf[0];
    let li = (first_byte >> 6) & 0x03;
    let vn = (first_byte >> 3) & 0x07;
    let mode = first_byte & 0x07;
    if li > 3 {
        return None;
    }
    if vn != 3 && vn != 4 {
        return None;
    }
    if mode != 3 {
        return None;
    }
    let root_delay = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let root_dispersion = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    // 每单位 = 1/2^16 秒，最大 16 秒 = 1048576
    if root_delay > 1_048_576 || root_dispersion > 1_048_576 {
        return None;
    }
    Some(SniffResult {
        domain: None,
        protocol: "ntp",
    })
}

// ── RDP over TPKT/COTP 检测（TCP）──────────────────────────────────────────────
//
// 对齐 sing-box RDP：
//   TPKT: version=3, reserved=0, length=19
//   COTP: length=14, type=0xE0
//   RDP:  type=0x01, length=8

fn try_rdp(buf: &[u8]) -> Option<SniffResult> {
    // TPKT header (4) + COTP (2) + 5 skipped + RDP (3) = 14 bytes minimum
    if buf.len() < 14 {
        return None;
    }
    // TPKT
    if buf[0] != 0x03 || buf[1] != 0x00 {
        return None;
    }
    let tpkt_length = u16::from_be_bytes([buf[2], buf[3]]);
    if tpkt_length != 19 {
        return None;
    }
    // COTP
    if buf[4] != 14 {
        return None;
    }
    if buf[5] != 0xE0 {
        return None;
    }
    // Skip 5 bytes (COTP fields: dst-ref(2) + src-ref(2) + flags(1))
    // RDP
    if buf.len() < 11 + 3 {
        return None;
    }
    let rdp_type = buf[11];
    if rdp_type != 0x01 {
        return None;
    }
    let rdp_length = buf[13];
    if rdp_length != 8 {
        return None;
    }
    Some(SniffResult {
        domain: None,
        protocol: "rdp",
    })
}

// ── DNS 协议检测 ──────────────────────────────────────────────────────────────

/// 检测是否为 DNS 查询报文（非响应）。
///
/// 对齐 sing-box DomainNameQuery：
/// - QR = 0（查询，非响应）
/// - Opcode <= 2（标准查询/反向查询/状态查询）
/// - QDCOUNT > 0（至少一个问题）
/// - ANCOUNT = 0 且 NSCOUNT = 0（查询报文不应包含回答/权威记录）
///
/// 旧实现缺少 QR=0 和 ANCOUNT/NSCOUNT 检查，会误判 DNS 响应报文为查询，
/// 导致 UDP 53 端口上的 DNS 响应被误识别为 DNS 查询协议。
pub fn is_dns_wire(buf: &[u8]) -> bool {
    if buf.len() < 12 {
        return false;
    }
    let flags = buf[2];
    let qr = (flags & 0x80) != 0;
    if qr {
        // QR=1 是响应报文，跳过
        return false;
    }
    let opcode = (flags >> 3) & 0x0f;
    if opcode > 2 {
        return false;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return false;
    }
    // 查询报文不应包含 Answer / Authority 记录
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let nscount = u16::from_be_bytes([buf[8], buf[9]]);
    if ancount != 0 || nscount != 0 {
        return false;
    }
    true
}

// ── 单元测试 ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(r: Option<SniffResult>) -> Option<String> {
        r.and_then(|r| r.domain)
    }
    fn protocol(r: Option<SniffResult>) -> Option<&'static str> {
        r.map(|r| r.protocol)
    }

    #[test]
    fn parse_http_host() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n";
        assert_eq!(domain(try_http_host(req)), Some("example.com".into()));
        assert_eq!(protocol(try_http_host(req)), Some("http"));
    }

    #[test]
    fn parse_http_host_with_port() {
        let req = b"POST /api HTTP/1.1\r\nHost: api.example.com:8080\r\n\r\n";
        assert_eq!(domain(try_http_host(req)), Some("api.example.com".into()));
    }

    #[test]
    fn http_host_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nHOST: Example.COM\r\n\r\n";
        assert_eq!(domain(try_http_host(req)), Some("example.com".into()));
    }

    #[test]
    fn not_http_returns_none() {
        let data = b"\x16\x03\x01 not tls either";
        assert!(try_http_host(data).is_none());
    }

    #[test]
    fn tls_too_short() {
        let data = b"\x16\x03\x01\x00\x05\x01";
        assert!(try_tls(data).is_none());
    }

    #[test]
    fn ssh_detection() {
        let data = b"SSH-2.0-OpenSSH_8.0\r\n";
        assert_eq!(protocol(try_ssh(data)), Some("ssh"));
    }

    #[test]
    fn bittorrent_detection() {
        let mut data = vec![0x13u8];
        data.extend_from_slice(b"BitTorrent protocol");
        data.extend_from_slice(&[0u8; 28]);
        assert_eq!(protocol(try_bittorrent(&data)), Some("bittorrent"));
    }

    #[test]
    fn sniff_type_from_str() {
        assert_eq!(SniffType::parse("tls"), Some(SniffType::Tls));
        assert_eq!(SniffType::parse("TLS"), Some(SniffType::Tls));
        assert_eq!(SniffType::parse("http"), Some(SniffType::Http));
        assert_eq!(SniffType::parse("quic"), Some(SniffType::Quic));
        assert_eq!(SniffType::parse("ssh"), Some(SniffType::Ssh));
        assert_eq!(SniffType::parse("bittorrent"), Some(SniffType::BitTorrent));
        assert_eq!(SniffType::parse("dns"), Some(SniffType::Dns));
        assert_eq!(SniffType::parse("dtls"), Some(SniffType::Dtls));
        assert_eq!(SniffType::parse("stun"), Some(SniffType::Stun));
        assert_eq!(SniffType::parse("ntp"), Some(SniffType::Ntp));
        assert_eq!(SniffType::parse("rdp"), Some(SniffType::Rdp));
        assert_eq!(SniffType::parse("unknown"), None);
    }

    #[test]
    fn tls_without_sni_returns_tls() {
        // TLS ClientHello without SNI extension — should still return protocol="tls"
        // Minimal ClientHello: record header + handshake + no extensions
        let mut hello = vec![
            0x16, 0x03, 0x01, // TLS record: Handshake, version
        ];
        let mut body = vec![
            0x01, // ClientHello
            0x00, 0x00, 0x00, // length (placeholder)
            0x03, 0x03, // version TLS 1.2
        ];
        body.extend_from_slice(&[0u8; 32]); // Random
        body.push(0x00); // Session ID length = 0
        body.push(0x00);
        body.push(0x02); // Cipher suites length = 2
        body.push(0x00);
        body.push(0x2f); // TLS_RSA_WITH_AES_128_CBC_SHA
        body.push(0x01); // Compression methods length = 1
        body.push(0x00); // null compression
                         // No extensions → SNI = None
        let body_len = body.len() as u16;
        hello.push((body_len >> 8) as u8);
        hello.push(body_len as u8);
        // Fix handshake length (bytes 1-3 of body)
        let hs_len = body.len() - 4;
        body[1] = ((hs_len >> 16) & 0xff) as u8;
        body[2] = ((hs_len >> 8) & 0xff) as u8;
        body[3] = (hs_len & 0xff) as u8;
        hello.extend_from_slice(&body);

        let result = try_tls(&hello);
        assert!(result.is_some(), "TLS without SNI should still be detected");
        let r = result.unwrap();
        assert_eq!(r.protocol, "tls");
        assert!(r.domain.is_none(), "domain should be None without SNI");
    }

    #[test]
    fn dns_query_detection() {
        // Minimal DNS query: header(12) + question
        let mut query = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: RD=1, QR=0 (query)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        // Question: example.com A
        query.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        query.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        query.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        assert!(is_dns_wire(&query));

        // DNS response should NOT be detected as query
        let mut response = query.clone();
        response[2] |= 0x80; // Set QR=1
        assert!(!is_dns_wire(&response));
    }

    #[test]
    fn dtls_detection() {
        // DTLS 1.2 record
        let mut dtls = vec![22, 0xfe, 0xfd]; // Handshake, DTLS 1.2
        dtls.extend_from_slice(&[0u8; 10]); // rest of header
        assert_eq!(protocol(try_dtls(&dtls)), Some("dtls"));

        // DTLS 1.0
        let mut dtls10 = vec![22, 0xfe, 0xff];
        dtls10.extend_from_slice(&[0u8; 10]);
        assert_eq!(protocol(try_dtls(&dtls10)), Some("dtls"));

        // Not DTLS
        let not_dtls = [22u8, 0x03, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(try_dtls(&not_dtls).is_none());
    }

    #[test]
    fn stun_detection() {
        let mut stun = vec![
            0x00, 0x01, // type: Binding Request
            0x00, 0x00, // length: 0
            0x21, 0x12, 0xA4, 0x42, // magic cookie
        ];
        stun.extend_from_slice(&[0u8; 12]); // transaction ID
        assert_eq!(protocol(try_stun(&stun)), Some("stun"));

        // Wrong magic cookie
        let mut bad = stun.clone();
        bad[4] = 0x00;
        assert!(try_stun(&bad).is_none());
    }

    #[test]
    fn ntp_detection() {
        // NTP v4 client request
        let mut ntp = vec![0xe3]; // LI=0, VN=4, Mode=3 (client)
        ntp.push(0x00); // stratum
        ntp.push(0x06); // poll
        ntp.push(0xec); // precision
        ntp.extend_from_slice(&[0u8; 4]); // root delay
        ntp.extend_from_slice(&[0u8; 4]); // root dispersion
        ntp.extend_from_slice(&[0u8; 4]); // reference ID
        ntp.extend_from_slice(&[0u8; 8]); // reference timestamp
        ntp.extend_from_slice(&[0u8; 8]); // origin timestamp
        ntp.extend_from_slice(&[0u8; 8]); // receive timestamp
        ntp.extend_from_slice(&[0u8; 8]); // transmit timestamp
        assert_eq!(protocol(try_ntp(&ntp)), Some("ntp"));

        // Mode != 3 (not client)
        let mut bad = ntp.clone();
        bad[0] = 0xe4; // Mode=4 (server)
        assert!(try_ntp(&bad).is_none());
    }

    #[test]
    fn rdp_detection() {
        // RDP Connection Request over TPKT/COTP
        let rdp = vec![
            0x03, 0x00, // TPKT: version=3, reserved=0
            0x00, 0x13, // TPKT: length=19
            0x0e, // COTP: length=14
            0xe0, // COTP: type=0xE0 (Connection Request)
            0x00, 0x00, // dst-ref
            0x00, 0x00, // src-ref
            0x00, // flags
            0x01, // RDP: type=1
            0x00, // RDP: flags
            0x08, // RDP: length=8
            0x00, 0x00, 0x00, 0x00, 0x00, // padding
        ];
        assert_eq!(protocol(try_rdp(&rdp)), Some("rdp"));
    }

    #[test]
    fn utp_detection() {
        // uTP packet: version=1, type=1 (DATA), no extensions
        let mut utp = vec![0x11]; // type=1 (4 bits) | version=1 (4 bits)
        utp.push(0x00); // extension=0 (none)
        utp.extend_from_slice(&[0u8; 18]); // rest of 20-byte header
        let result = try_bittorrent_udp(&utp);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "bittorrent");
    }

    #[test]
    fn udp_tracker_detection() {
        // UDP Tracker connect request
        let mut pkt = vec![];
        pkt.extend_from_slice(&0x41727101980u64.to_be_bytes()); // protocol_id
        pkt.extend_from_slice(&0u32.to_be_bytes()); // action=0 (connect)
        pkt.extend_from_slice(&0x12345678u32.to_be_bytes()); // transaction_id
        let result = try_bittorrent_udp(&pkt);
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, "bittorrent");
    }

    #[test]
    fn sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = sha256(b"");
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
    }
}
