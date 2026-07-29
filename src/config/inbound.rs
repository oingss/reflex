use serde::{Deserialize, Serialize};
use tracing::warn;

/// 所有入站类型的枚举，用 `type` 字段做 tag。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundConfig {
    /// Linux TProxy，需要外部 iptables/nftables 配合（TCP + UDP）
    TProxy(TProxyInboundConfig),
    /// Linux Redirect（iptables -j REDIRECT / nftables redirect to），仅 TCP
    Redir(RedirInboundConfig),
    /// SOCKS5 + HTTP CONNECT 混合入站
    Mixed(MixedInboundConfig),
    /// 纯 HTTP 代理入站（CONNECT + 转发代理）
    Http(HttpInboundConfig),
    /// 纯 SOCKS5 代理入站（CONNECT + UDP ASSOCIATE）
    Socks(SocksInboundConfig),
    /// DNS 服务器入站（将查询交由内部 DNS 模块处理后返回）
    Dns(DnsInboundConfig),
    /// TUN 虚拟网卡入站（L3 透明代理，TCP + UDP）
    ///
    /// 字段较多（336B），装箱以避免拉大整个 `InboundConfig` 枚举尺寸
    /// （参见 clippy::large_enum_variant）。
    Tun(Box<TunInboundConfig>),
}

impl InboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::TProxy(c) => &c.tag,
            Self::Redir(c) => &c.tag,
            Self::Mixed(c) => &c.tag,
            Self::Http(c) => &c.tag,
            Self::Socks(c) => &c.tag,
            Self::Dns(c) => &c.tag,
            Self::Tun(c) => &c.tag,
        }
    }

    pub fn listen_addr(&self) -> (&str, u16) {
        match self {
            Self::TProxy(c) => (&c.listen, c.listen_port),
            Self::Redir(c) => (&c.listen, c.listen_port),
            Self::Mixed(c) => (&c.listen, c.listen_port),
            Self::Http(c) => (&c.listen, c.listen_port),
            Self::Socks(c) => (&c.listen, c.listen_port),
            Self::Dns(c) => (&c.listen, c.listen_port),
            // TUN 入站无 listen 地址；port=0 在校验中豁免
            Self::Tun(_) => ("", 0),
        }
    }
}

// ── TProxy ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TProxyInboundConfig {
    pub tag: String,

    /// 监听地址，默认 0.0.0.0
    #[serde(default = "default_listen")]
    pub listen: String,

    pub listen_port: u16,

    /// 支持的网络协议
    #[serde(default)]
    pub network: Network,

    /// SO_MARK，用于 writeback socket 绕过 TProxy 规则，与 global.routing_mark 一致
    #[serde(default)]
    pub routing_mark: u32,
}

// ── Redirect (NAT) ────────────────────────────────────────────────────────────

/// Linux Redirect 入站配置。
///
/// 对应 `iptables -t nat -j REDIRECT` 或 `nftables redirect to` 规则。
/// 仅支持 TCP；UDP 无法通过 REDIRECT 还原原始目标地址。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirInboundConfig {
    pub tag: String,

    /// 监听地址，默认 0.0.0.0（接收所有被 redirect 过来的连接）
    #[serde(default = "default_listen")]
    pub listen: String,

    /// 监听端口，需与 nftables/iptables 规则中的 redirect 目标端口一致
    pub listen_port: u16,
}

// ── Mixed（SOCKS5 + HTTP CONNECT）────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixedInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    pub listen_port: u16,

    #[serde(default)]
    pub network: Network,

    /// SOCKS5 用户名（可选，不填则不鉴权）
    #[serde(default)]
    pub username: Option<String>,

    /// SOCKS5 密码
    #[serde(default)]
    pub password: Option<String>,

    /// UDP 会话空闲超时（如 "300s"、"5m"）。未配置时使用默认值 300s。
    /// 与 sing-box ListenOptions.UDPTimeout 对齐。
    #[serde(default)]
    pub udp_timeout: Option<String>,
}

impl MixedInboundConfig {
    /// 解析 `udp_timeout` 为 `Duration`。未配置或解析失败时返回 `None`，
    /// 调用方应回退到默认值（300s）。
    pub fn udp_timeout_duration(&self) -> Option<std::time::Duration> {
        self.udp_timeout
            .as_deref()
            .and_then(|s| match crate::config::outbound::parse_duration(s) {
                Ok(d) => Some(d),
                Err(e) => {
                    warn!(
                        tag = %self.tag,
                        value = %s,
                        err = %e,
                        "mixed inbound: invalid udp_timeout, falling back to default"
                    );
                    None
                }
            })
    }
}

// ── HTTP ────────────────────────────────────────────────────────────────────

/// HTTP 代理入站配置（仅 HTTP CONNECT + 转发代理）。
///
/// 配置写法与 sing-box 一致：
/// ```json
/// {
///   "type": "http",
///   "tag": "http-in",
///   "listen": "127.0.0.1",
///   "listen_port": 2080,
///   "users": [{"username": "admin", "password": "secret"}]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    pub listen_port: u16,

    /// 用户列表（可选，为空则不鉴权）。
    /// 认证方式：HTTP `Proxy-Authorization: Basic` 头。
    #[serde(default)]
    pub users: Vec<AuthUser>,
}

// ── SOCKS ───────────────────────────────────────────────────────────────────

/// SOCKS5 代理入站配置（仅 SOCKS5 CONNECT + UDP ASSOCIATE）。
///
/// 配置写法与 sing-box 一致：
/// ```json
/// {
///   "type": "socks",
///   "tag": "socks-in",
///   "listen": "127.0.0.1",
///   "listen_port": 1080,
///   "users": [{"username": "admin", "password": "secret"}]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    pub listen_port: u16,

    /// 用户列表（可选，为空则不鉴权）。
    /// 认证方式：SOCKS5 用户名/密码子协商（RFC 1929）。
    #[serde(default)]
    pub users: Vec<AuthUser>,

    /// UDP 会话空闲超时（如 "300s"、"5m"）。未配置时使用默认值 300s。
    /// 与 sing-box ListenOptions.UDPTimeout 对齐。
    #[serde(default)]
    pub udp_timeout: Option<String>,
}

impl SocksInboundConfig {
    /// 解析 `udp_timeout` 为 `Duration`。未配置或解析失败时返回 `None`，
    /// 调用方应回退到默认值（300s）。
    pub fn udp_timeout_duration(&self) -> Option<std::time::Duration> {
        self.udp_timeout
            .as_deref()
            .and_then(|s| match crate::config::outbound::parse_duration(s) {
                Ok(d) => Some(d),
                Err(e) => {
                    warn!(
                        tag = %self.tag,
                        value = %s,
                        err = %e,
                        "socks inbound: invalid udp_timeout, falling back to default"
                    );
                    None
                }
            })
    }
}

// ── 认证用户 ──────────────────────────────────────────────────────────────────

/// 代理认证用户，sing-box 风格的 `users` 数组元素。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

// ── DNS-in ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_local")]
    pub listen: String,

    /// 默认 53
    #[serde(default = "default_dns_port")]
    pub listen_port: u16,

    #[serde(default)]
    pub network: Network,
}

// ── 公共辅助类型 ──────────────────────────────────────────────────────────────

/// 网络协议选择
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// 仅 TCP
    Tcp,
    /// 仅 UDP
    Udp,
    /// TCP + UDP（默认）
    #[default]
    #[serde(alias = "tcp+udp")]
    TcpUdp,
}

impl Network {
    pub fn tcp(&self) -> bool {
        matches!(self, Self::Tcp | Self::TcpUdp)
    }
    pub fn udp(&self) -> bool {
        matches!(self, Self::Udp | Self::TcpUdp)
    }
}

fn default_listen() -> String {
    "0.0.0.0".into()
}
fn default_listen_local() -> String {
    "127.0.0.1".into()
}
fn default_dns_port() -> u16 {
    53
}

// ── TUN ───────────────────────────────────────────────────────────────────────

/// TUN 虚拟网卡入站配置。
///
/// 创建一个 TUN 设备，从 L3 层截获所有经过该网卡的 IP 流量（TCP + UDP），
/// 解析出目标地址后交给路由层，无需 iptables/nftables 配合。
///
/// ## 平台支持矩阵
///
/// | 字段                  | Linux | macOS | Windows |
/// |-----------------------|-------|-------|---------|
/// | auto_route            | ✓     | ✓     | ✓       |
/// | iproute2_table_index  | ✓     | —     | —       |
/// | iproute2_rule_index   | ✓     | —     | —       |
/// | strict_route          | ✓     | —     | ✓ (WFP) |
/// | include_interface     | ✓     | —     | —       |
/// | exclude_interface     | ✓     | —     | —       |
/// | include_uid           | ✓     | —     | —       |
/// | exclude_uid           | ✓     | —     | —       |
/// | udp_timeout           | ✓     | ✓     | ✓       |
///
/// ## 典型用法
/// ```json
/// {
///   "type": "tun",
///   "tag": "tun-in",
///   "interface_name": "tun0",
///   "address": ["198.18.0.1/16", "fd00::1/126"],
///   "mtu": 9000,
///   "auto_route": true,
///   "strict_route": true,
///   "stack": "system"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunInboundConfig {
    /// 入站标识，用于路由规则匹配
    pub tag: String,

    /// TUN 设备名，留空则由系统自动分配
    /// Linux: `tun0`，macOS: `utun<N>`，Windows: 由 WinTun 分配
    #[serde(default)]
    pub interface_name: Option<String>,

    /// TUN 设备 MTU，默认 9000
    #[serde(default = "default_tun_mtu")]
    pub mtu: u32,

    /// TUN 设备绑定的 IPv4/IPv6 地址前缀列表
    /// 例如 `["198.18.0.1/16", "fd00::1/126"]`，至少需要一个 IPv4 前缀。
    /// 网关地址由第一个前缀自动推导（Linux/Windows 取下一个 IP，macOS 取自身）。
    pub address: Vec<String>,

    /// 是否自动配置系统路由，将默认流量导入 TUN 设备。
    ///
    /// - **Linux**：在独立路由表（`iproute2_table_index`，默认 2022）中添加路由，
    ///   通过策略规则（`iproute2_rule_index`，默认优先级 9000）引导流量；
    ///   自身出站流量通过 fwmark / `iif lo` 规则绕过，避免环回。
    /// - **macOS**：通过 `AF_ROUTE` socket（`RTM_ADD`）添加路由条目。
    /// - **Windows**：通过 `CreateIpForwardEntry2` WinAPI 添加路由。
    #[serde(default)]
    pub auto_route: bool,

    /// Linux 专用：`auto_route` 使用的 iproute2 路由表编号，默认 2022。
    /// 不同实例需使用不同的表编号以避免冲突。
    #[serde(default = "default_iproute2_table_index")]
    pub iproute2_table_index: u32,

    /// Linux 专用：`auto_route` 策略规则起始优先级，默认 9000。
    /// 规则集实际占用的槽位数量取决于配置（UID 规则数、接口规则数、地址数等），
    /// 建议预留至少 200 个优先级槽位（即不要在 `[priority, priority+200)` 内放其他规则）。
    /// nop 锚点固定在 `priority + 100`，teardown 时根据 setup 记录的状态精确清理。
    #[serde(default = "default_iproute2_rule_index")]
    pub iproute2_rule_index: u32,

    /// Linux 专用：出站 socket 的 fwmark 值。
    /// 设置后 reflex 自身出站流量会带上此 mark，路由规则可据此绕过 TUN，
    /// 避免路由循环。与 clash-rs 的 `so_mark` 配置项一致。
    /// 默认不设置（None）。
    #[serde(default)]
    pub so_mark: Option<u32>,

    /// 严格路由模式，需配合 `auto_route`。
    ///
    /// - **Linux**：为缺失地址族（无 IPv4 或无 IPv6 地址时）添加
    ///   `FR_ACT_UNREACHABLE` 规则，阻止不支持的协议流量绕过 TUN。
    /// - **Windows**：通过 WFP（Windows Filtering Platform）阻止非 TUN
    ///   接口的 DNS（53 端口）流量，防止多宿主 DNS 泄漏。
    ///   （需要 Windows 10 及以上；更低版本会打印警告并跳过）
    /// - **macOS**：无效果，macOS 无对应内核机制。
    #[serde(default)]
    pub strict_route: bool,

    /// 网络栈实现：
    /// - `"system"`（默认）：依赖内核网络栈进行 L3→L4 转换，性能最佳
    /// - `"gvisor"`：用户态 gVisor 协议栈，兼容性更强
    /// - `"mixed"`：TCP 用 system，UDP 用 gVisor
    #[serde(default = "default_tun_stack")]
    pub stack: String,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截来自这些网络接口的流量，留空表示全部接口。
    /// 通过 `ip rule add iif <iface> goto <table_rule>` 实现白名单。
    /// 与 `exclude_interface` 互斥。
    #[serde(default)]
    pub include_interface: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除来自这些网络接口的流量。
    /// 通过 `ip rule add iif <iface> goto <nop>` 跳过 TUN 路由实现。
    /// 与 `include_interface` 互斥。
    #[serde(default)]
    pub exclude_interface: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截属于这些 UID 的流量，留空表示全部用户。
    /// 实现方式：先为指定 UID 建立包含规则，再将其余所有 UID 范围
    /// 通过 `ip rule add uidrange ... goto <nop>` 排除。
    #[serde(default)]
    pub include_uid: Vec<u32>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除属于这些 UID 的流量。
    /// 通过 `ip rule add uidrange <uid>-<uid> goto <nop>` 实现。
    #[serde(default)]
    pub exclude_uid: Vec<u32>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 仅拦截这些 UID 范围的流量，使用 `"start:end"` 字符串形式（与 sing-box 一致）。
    /// 例如 `["1000:2000"]` 表示拦截 UID 1000-2000。
    /// 与 `include_uid` 叠加；解析后与 `include_uid` 合并。
    #[serde(default)]
    pub include_uid_range: Vec<String>,

    /// **Linux 专用**（需要 `auto_route`）：
    /// 排除这些 UID 范围的流量，使用 `"start:end"` 字符串形式（与 sing-box 一致）。
    /// 例如 `["0:999"]` 表示排除 UID 0-999。
    /// 与 `exclude_uid` 叠加；解析后与 `exclude_uid` 合并。
    #[serde(default)]
    pub exclude_uid_range: Vec<String>,

    /// **所有平台**（需要 `auto_route`）：
    /// 仅将指定 CIDR 范围的流量导入 TUN（与 sing-box `route_address` 一致）。
    /// 留空表示劫持默认路由（`0.0.0.0/0` 和 `::/0`）。
    /// 例如 `["1.1.1.0/24", "8.8.8.0/24"]` 表示只代理这两个网段。
    #[serde(default)]
    pub route_address: Vec<String>,

    /// **所有平台**（需要 `auto_route`）：
    /// 排除指定 CIDR 范围的流量不导入 TUN（与 sing-box `route_exclude_address` 一致）。
    /// 优先级高于 `route_address` 和默认劫持。
    /// 例如 `["192.168.0.0/16"]` 表示排除局域网。
    #[serde(default)]
    pub route_exclude_address: Vec<String>,

    /// **所有平台**：
    /// 用于 acceptLoop 中目标重写的 loopback 地址（与 sing-box `loopback_address` 一致）。
    /// 默认为 `127.0.0.1` 和 `::1`。
    /// 若指定，必须同时给出 IPv4 和 IPv6 地址（或仅给出需要的地址族）。
    #[serde(default)]
    pub loopback_address: Vec<String>,

    /// UDP NAT 会话超时（秒），0 表示使用默认值 300 秒。
    #[serde(default)]
    pub udp_timeout: u64,

    /// TCP MSS clamping 上限（参照 sing-tun `clampTCPMSS`）。
    ///
    /// 设为 `Some(mss)` 后，所有经过 TUN 的 TCP SYN / SYN-ACK 包中
    /// MSS option 会被改写为 `min(原值, mss)`，避免 PMTUD 黑洞。
    /// 未配置（`None`）时不做 MSS 改写，保留原包。
    ///
    /// 常见取值：
    /// - `1452`：MTU 1492（PPPoE）下常用
    /// - `1400`：MTU 1440（VPN / WireGuard 默认）下常用
    /// - `1280`：IPv6 最小 MTU 1280 对应的 MSS
    #[serde(default)]
    pub tcp_mss: Option<u16>,

    // ── Android 专用 ──────────────────────────────────────────────────────────

    /// **Android 专用**：要包含的 Android 用户 ID 列表。
    /// 每个用户对应一个完整的 UID 空间（user_id * 100000）。
    /// 留空时自动枚举 `/data/user/` 目录。
    #[serde(default)]
    pub include_android_user: Vec<i32>,

    /// **Android 专用**：将指定的 Android 包名转为其 UID 后加入包含列表。
    /// 解析 `/data/system/packages.xml` 获取包名到 UID 的映射。
    #[serde(default)]
    pub include_package: Vec<String>,

    /// **Android 专用**：将指定的 Android 包名转为其 UID 后加入排除列表。
    #[serde(default)]
    pub exclude_package: Vec<String>,

    /// **Android 专用**：是否覆盖系统 VPN 检测。
    /// 当系统 VPN 启用时，reflex 默认会创建规则绕过系统 VPN。
    /// 设为 true 后，reflex 接管系统 VPN 的流量。
    #[serde(default)]
    pub override_android_vpn: bool,
}

fn default_tun_mtu() -> u32 {
    9000
}

fn default_tun_stack() -> String {
    "system".to_string()
}

fn default_iproute2_table_index() -> u32 {
    2022
}

fn default_iproute2_rule_index() -> u32 {
    9000
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_redir() {
        let v = json!({
            "type": "redir",
            "tag": "redir-in",
            "listen": "0.0.0.0",
            "listen_port": 7892
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "redir-in");
        assert!(matches!(ib, InboundConfig::Redir(_)));
        let (listen, port) = ib.listen_addr();
        assert_eq!(listen, "0.0.0.0");
        assert_eq!(port, 7892);
    }

    #[test]
    fn parse_redir_defaults() {
        let v = json!({
            "type": "redir",
            "tag": "redir-in",
            "listen_port": 7892
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        let (listen, _) = ib.listen_addr();
        assert_eq!(listen, "0.0.0.0");
    }

    #[test]
    fn parse_tproxy() {
        let v = json!({
            "type": "tproxy",
            "tag": "tp-in",
            "listen": "0.0.0.0",
            "listen_port": 7893,
            "network": "tcp+udp",
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "tp-in");
        assert!(matches!(ib, InboundConfig::TProxy(_)));
    }

    #[test]
    fn parse_mixed_defaults() {
        let v = json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen_port": 7890
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        let (listen, port) = ib.listen_addr();
        assert_eq!(listen, "127.0.0.1");
        assert_eq!(port, 7890);
        if let InboundConfig::Mixed(c) = &ib {
            assert!(c.network.udp());
        }
    }

    #[test]
    fn parse_http_inbound() {
        let v = json!({
            "type": "http",
            "tag": "http-in",
            "listen": "0.0.0.0",
            "listen_port": 2080,
            "users": [{"username": "admin", "password": "secret"}]
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "http-in");
        assert!(matches!(ib, InboundConfig::Http(_)));
        if let InboundConfig::Http(c) = &ib {
            assert_eq!(c.listen, "0.0.0.0");
            assert_eq!(c.listen_port, 2080);
            assert_eq!(c.users.len(), 1);
            assert_eq!(c.users[0].username, "admin");
        }
    }

    #[test]
    fn parse_http_no_auth() {
        let v = json!({
            "type": "http",
            "tag": "http-in",
            "listen_port": 2080
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        if let InboundConfig::Http(c) = &ib {
            assert!(c.users.is_empty());
            assert_eq!(c.listen, "127.0.0.1");
        }
    }

    #[test]
    fn parse_socks_inbound() {
        let v = json!({
            "type": "socks",
            "tag": "socks-in",
            "listen": "0.0.0.0",
            "listen_port": 1080,
            "users": [{"username": "admin", "password": "secret"}]
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "socks-in");
        assert!(matches!(ib, InboundConfig::Socks(_)));
        if let InboundConfig::Socks(c) = &ib {
            assert_eq!(c.listen_port, 1080);
            assert_eq!(c.users.len(), 1);
        }
    }

    #[test]
    fn parse_socks_no_auth() {
        let v = json!({
            "type": "socks",
            "tag": "socks-in",
            "listen_port": 1080
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        if let InboundConfig::Socks(c) = &ib {
            assert!(c.users.is_empty());
        }
    }

    #[test]
    fn socks_and_mixed_udp_timeout_duration() {
        let v = json!({
            "type": "socks",
            "tag": "socks-in",
            "listen_port": 1080,
            "udp_timeout": "5m"
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        if let InboundConfig::Socks(c) = &ib {
            assert_eq!(
                c.udp_timeout_duration(),
                Some(std::time::Duration::from_secs(300))
            );
        } else {
            panic!("expected Socks");
        }

        let v = json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen_port": 7890,
            "udp_timeout": "120s"
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        if let InboundConfig::Mixed(c) = &ib {
            assert_eq!(
                c.udp_timeout_duration(),
                Some(std::time::Duration::from_secs(120))
            );
            // 未配置时为 None
            assert!(
                MixedInboundConfig::udp_timeout_duration(&MixedInboundConfig {
                    tag: "x".into(),
                    listen: "127.0.0.1".into(),
                    listen_port: 1,
                    network: Network::TcpUdp,
                    username: None,
                    password: None,
                    udp_timeout: None,
                })
                .is_none()
            );
        } else {
            panic!("expected Mixed");
        }
    }

    #[test]
    fn parse_dns_in() {
        let v = json!({
            "type": "dns",
            "tag": "dns-in",
            "listen": "0.0.0.0",
            "listen_port": 5353,
            "network": "udp"
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert!(matches!(ib, InboundConfig::Dns(_)));
        if let InboundConfig::Dns(c) = ib {
            assert!(c.network.udp());
            assert!(!c.network.tcp());
        }
    }

    #[test]
    fn network_both() {
        let n: Network = serde_json::from_str("\"tcp+udp\"").unwrap();
        assert!(n.tcp() && n.udp());
    }

    #[test]
    fn parse_tun_minimal() {
        let v = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": ["198.18.0.1/16"]
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ib.tag(), "tun-in");
        assert!(matches!(ib, InboundConfig::Tun(_)));
        if let InboundConfig::Tun(c) = &ib {
            assert_eq!(c.mtu, 9000);
            assert_eq!(c.stack, "system");
            assert!(!c.auto_route);
            assert!(!c.strict_route);
            assert!(c.interface_name.is_none());
        }
    }

    #[test]
    fn parse_tun_full() {
        let v = json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "utun0",
            "mtu": 65535,
            "address": ["198.18.0.1/16", "fd00::1/126"],
            "auto_route": true,
            "strict_route": true,
            "stack": "gvisor",
            "include_interface": ["eth0"],
            "exclude_uid": [0],
            "include_uid_range": ["1000:2000"],
            "exclude_uid_range": ["3000:4000"],
            "route_address": ["1.1.1.0/24"],
            "route_exclude_address": ["192.168.0.0/16"],
            "loopback_address": ["127.0.0.1", "::1"],
            "udp_timeout": 120
        });
        let ib: InboundConfig = serde_json::from_value(v).unwrap();
        if let InboundConfig::Tun(c) = &ib {
            assert_eq!(c.interface_name.as_deref(), Some("utun0"));
            assert_eq!(c.mtu, 65535);
            assert_eq!(c.address.len(), 2);
            assert!(c.auto_route);
            assert!(c.strict_route);
            assert_eq!(c.stack, "gvisor");
            assert_eq!(c.include_interface, vec!["eth0"]);
            assert_eq!(c.exclude_uid, vec![0u32]);
            assert_eq!(c.include_uid_range, vec!["1000:2000".to_string()]);
            assert_eq!(c.exclude_uid_range, vec!["3000:4000".to_string()]);
            assert_eq!(c.route_address, vec!["1.1.1.0/24".to_string()]);
            assert_eq!(c.route_exclude_address, vec!["192.168.0.0/16".to_string()]);
            assert_eq!(
                c.loopback_address,
                vec!["127.0.0.1".to_string(), "::1".to_string()]
            );
            assert_eq!(c.udp_timeout, 120);
        } else {
            panic!("expected Tun");
        }
    }
}
