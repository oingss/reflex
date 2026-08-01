use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiplexConfig {
    /// 是否启用多路复用，默认 false
    #[serde(default)]
    pub enabled: bool,

    /// 多路复用协议：`"smux"`（默认）、`"yamux"`、`"h2mux"`
    /// 目前实现 smux；yamux/h2mux 配置可解析但降级到 smux
    #[serde(default = "default_mux_protocol")]
    pub protocol: String,

    /// 最大物理连接数，0 = 不限（默认 0）
    #[serde(default)]
    pub max_connections: usize,

    /// 每条物理连接上打开新流所需的最低现有流数（用于控制何时新建连接），默认 4
    #[serde(default = "default_min_streams")]
    pub min_streams: usize,

    /// 每条物理连接允许的最大并发流数，0 = 不限（默认 0）
    #[serde(default)]
    pub max_streams: usize,

    /// 是否在 smux 帧上增加随机填充（对抗流量分析）
    #[serde(default)]
    pub padding: bool,

    /// Brutal 拥塞控制（仅 H2Mux，保留字段，当前不生效）
    #[serde(default)]
    pub brutal: Option<BrutalConfig>,
}

impl Default for MultiplexConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            protocol: default_mux_protocol(),
            max_connections: 0,
            min_streams: default_min_streams(),
            max_streams: 0,
            padding: false,
            brutal: None,
        }
    }
}

/// Brutal 拥塞控制配置（兼容 sing-box，当前保留字段）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrutalConfig {
    #[serde(default)]
    pub enabled: bool,
    pub up_mbps: Option<u64>,
    pub down_mbps: Option<u64>,
}

fn default_mux_protocol() -> String {
    "smux".into()
}
fn default_min_streams() -> usize {
    4
}

// ── WireGuard 出站配置 ────────────────────────────────────────────────────────

/// WireGuard 对端配置，与 sing-box `WireGuardPeer` 字段完全对齐。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeer {
    /// 对端服务器地址（域名或 IP），对应 sing-box `address`
    #[serde(default)]
    pub address: Option<String>,

    /// 对端服务器端口，对应 sing-box `port`
    #[serde(default)]
    pub port: u16,

    /// 对端公钥（base64），对应 sing-box `public_key`
    #[serde(default)]
    pub public_key: Option<String>,

    /// 预共享密钥（可选，base64），对应 sing-box `pre_shared_key`
    #[serde(default)]
    pub pre_shared_key: Option<String>,

    /// 允许路由的 CIDR 列表，对应 sing-box `allowed_ips`
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// 持久保活间隔（秒），对应 sing-box `persistent_keepalive_interval`
    #[serde(default)]
    pub persistent_keepalive_interval: u16,

    /// Reserved 字节（3 字节，Cloudflare WARP 使用），对应 sing-box `reserved`
    #[serde(default)]
    pub reserved: Vec<u8>,
}

/// WireGuard 出站配置，与 sing-box `WireGuardEndpointOptions` 字段完全对齐。
///
/// ## sing-box 标准格式（peers 数组）
/// ```json
/// {
///   "type": "wireguard",
///   "tag": "wg-out",
///   "address": ["10.0.0.2/32", "fd00::2/128"],
///   "private_key": "<base64>",
///   "peers": [{
///     "address": "wg.example.com",
///     "port": 51820,
///     "public_key": "<base64>",
///     "pre_shared_key": "<base64>",
///     "allowed_ips": ["0.0.0.0/0", "::/0"]
///   }],
///   "mtu": 1408
/// }
/// ```
///
/// ## 简化格式（单对端，与其他出站类型风格一致）
/// ```json
/// {
///   "type": "wireguard",
///   "tag": "wg-out",
///   "server": "wg.example.com",
///   "server_port": 51820,
///   "local_address": ["10.0.0.2/32"],
///   "private_key": "<base64>",
///   "peer_public_key": "<base64>"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardOutboundConfig {
    pub tag: String,

    // ── sing-box 标准字段 ──────────────────────────────────────────────────
    /// 本机 WireGuard 接口地址列表（含前缀长度），对应 sing-box `address`
    /// 与 `local_address` 二选一，优先使用此字段
    #[serde(default)]
    pub address: Vec<String>,

    /// 本机私钥（base64），对应 sing-box `private_key`
    pub private_key: String,

    /// 多对端配置，对应 sing-box `peers`
    /// 填写后 `server`/`server_port`/`peer_public_key` 被忽略
    #[serde(default)]
    pub peers: Vec<WireGuardPeer>,

    /// MTU，对应 sing-box `mtu`，默认 1408
    #[serde(default = "default_wg_mtu")]
    pub mtu: u32,

    /// 工作线程数，对应 sing-box `workers`，默认 2
    #[serde(default = "default_wg_workers")]
    pub workers: usize,

    /// UDP 超时，对应 sing-box `udp_timeout`（秒），默认 0（不超时）
    #[serde(default)]
    pub udp_timeout: u64,

    /// 使用系统内核 WireGuard（Linux `wg` 模块），对应 sing-box `system`
    /// 默认 false（用户态实现）
    #[serde(default)]
    pub system: bool,

    /// TUN 接口名称，对应 sing-box `name`，留空自动分配
    #[serde(default)]
    pub name: Option<String>,

    // ── Reflex 扩展（简化单对端写法，兼容其他出站类型风格）────────────────
    /// 服务端地址（简化写法，等价于 `peers[0].address`）
    #[serde(default)]
    pub server: Option<String>,

    /// 服务端端口（简化写法，等价于 `peers[0].port`）
    #[serde(default)]
    pub server_port: u16,

    /// 本机接口地址（简化写法，等价于 `address`，历史兼容）
    #[serde(default)]
    pub local_address: Vec<String>,

    /// 对端公钥（简化写法，等价于 `peers[0].public_key`）
    #[serde(default)]
    pub peer_public_key: Option<String>,

    /// 预共享密钥（简化写法，等价于 `peers[0].pre_shared_key`）
    #[serde(default)]
    pub pre_shared_key: Option<String>,

    /// DNS 服务器列表（隧道内解析用）
    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// 全局 SO_MARK（Linux，通过 global.routing_mark 自动传入）
    #[serde(skip)]
    pub routing_mark: u32,
}

impl WireGuardOutboundConfig {
    /// 解析出规范化的本机地址列表（优先 `address`，fallback `local_address`）
    pub fn local_addresses(&self) -> &[String] {
        if !self.address.is_empty() {
            &self.address
        } else {
            &self.local_address
        }
    }

    /// 解析出规范化的 peers 列表（优先 `peers`，fallback 简化字段）
    pub fn resolved_peers(&self) -> Vec<WireGuardPeer> {
        if !self.peers.is_empty() {
            return self.peers.clone();
        }
        // 从简化字段构造单 peer
        if self.server.is_some() || self.peer_public_key.is_some() {
            vec![WireGuardPeer {
                address: self.server.clone(),
                port: self.server_port,
                public_key: self.peer_public_key.clone(),
                pre_shared_key: self.pre_shared_key.clone(),
                allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                persistent_keepalive_interval: 0,
                reserved: vec![],
            }]
        } else {
            vec![]
        }
    }
}

fn default_wg_mtu() -> u32 {
    1408
}
fn default_wg_workers() -> usize {
    2
}

// ── SSH 出站配置 ─────────────────────────────────────────────────────────────

/// SSH 出站配置（参照 clash-rs `OutboundSsh` + `HandlerOptions`）。
///
/// 通过 SSH 协议（russh）建立到远端服务器的 SSH 隧道，
/// 使用 `direct-tcpip` channel 转发 TCP 流量。
///
/// 支持的认证方式：
/// - 密码（`password`）
/// - 公钥（`private_key`，可以是文件路径或 PEM 内容）
/// - 键盘交互（含 TOTP 2FA，通过 `totp_opt` 配置）
///
/// 配置示例：
/// ```json
/// {
///   "type": "ssh",
///   "tag": "ssh-out",
///   "server": "ssh.example.com",
///   "server_port": 22,
///   "username": "user",
///   "password": "your-password",
///   "private_key": "~/.ssh/id_ed25519",
///   "host_key": ["ssh-ed25519 AAAA..."]
/// }
/// ```
///
/// 带 TOTP 2FA 的示例：
/// ```json
/// {
///   "type": "ssh",
///   "tag": "ssh-2fa",
///   "server": "ssh.example.com",
///   "server_port": 22,
///   "username": "user",
///   "password": "your-password",
///   "totp_opt": {
///     "secret": "JBSWY3DPEHPK3PXP",
///     "step": 30,
///     "digits": 6,
///     "algorithm": "sha1"
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshOutboundConfig {
    pub tag: String,

    /// SSH 服务器域名或 IP
    pub server: String,

    /// SSH 服务器端口（默认 22）
    #[serde(default = "default_ssh_port")]
    pub server_port: u16,

    /// 登录用户名
    pub username: String,

    /// 密码认证（可选，配合键盘交互或单独使用）
    #[serde(default)]
    pub password: Option<String>,

    /// 私钥路径或 PEM 内容。
    /// 若包含 `"PRIVATE KEY"` 视为内联 PEM 内容；否则视为文件路径。
    /// 文件路径支持 `~` 前缀（展开为 home 目录）。
    #[serde(default)]
    pub private_key: Option<String>,

    /// 私钥文件的保护密码（仅当 `private_key` 为加密的 PEM 文件时使用）
    #[serde(default)]
    pub private_key_passphrase: Option<String>,

    /// 期望的服务端公钥列表（OpenSSH 格式字符串，如 `"ssh-ed25519 AAAA..."`）。
    /// 留空时跳过 host key 校验（不安全，仅调试用）。
    #[serde(default)]
    pub host_key: Option<Vec<String>>,

    /// 支持的 host key 算法列表（如 `"ssh-ed25519"`、`"rsa-sha2-256"`）。
    /// 留空时使用 russh 默认值。
    #[serde(default)]
    pub host_key_algorithms: Option<Vec<String>>,

    /// TOTP 2FA 配置（用于键盘交互式认证的 `Verification code:` 提示）
    #[serde(default)]
    pub totp_opt: Option<TotpOption>,

    /// 出站链式代理（预留）
    #[serde(default)]
    pub detour: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

/// TOTP 配置，支持 otpauth URL 或显式字段
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum TotpOption {
    /// otpauth:// URL（如 `otpauth://totp/Example:alice@google.com?secret=...&period=30`）
    OtpAuth {
        /// otpauth URL 字符串
        secret: String,
    },
    /// 显式字段配置
    Common(TotpConfig),
}

/// TOTP 显式配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32 编码的密钥
    pub secret: String,

    /// TOTP 步长（秒），默认 30
    #[serde(default = "default_totp_step")]
    pub step: u64,

    /// 数字位数，默认 6
    #[serde(default = "default_totp_digits")]
    pub digits: usize,

    /// 哈希算法：`"sha1"`（默认）、`"sha256"`、`"sha512"`
    #[serde(default = "default_totp_algorithm")]
    pub algorithm: String,
}

fn default_totp_step() -> u64 {
    30
}
fn default_totp_digits() -> usize {
    6
}
fn default_totp_algorithm() -> String {
    "sha1".into()
}

// ── Tailscale 出站配置 ───────────────────────────────────────────────────────

/// Tailscale 出站配置（参照 clash-rs `OutboundTailscale` + `HandlerOptions`）。
///
/// 通过 Tailscale userspace netstack（`tailscale-rs` crate）建立到 Tailscale
/// 网络中其他节点或经由 subnet router 可达的内部服务的连接。
///
/// 注意：clash-rs 的 Tailscale 出站**不暴露 exit-node 选择**，
/// 它依赖 Tailscale 的 subnet router 通告的路由来转发流量。
/// 在 reflex 中保持一致：用户应通过 Tailscale 的控制台配置 subnet router，
/// 然后把目标 IP 设为该 subnet 内的地址。
///
/// 配置示例：
/// ```json
/// {
///   "type": "tailscale",
///   "tag": "ts-out",
///   "auth_key": "tskey-auth-XXXXX",
///   "hostname": "reflex-node",
///   "state_dir": "/var/lib/reflex/tailscale"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailscaleOutboundConfig {
    pub tag: String,

    /// Tailscale 控制服务器 URL（默认 `https://controlplane.tailscale.com`）。
    /// 自托管 Headscale 时填写 Headscale 地址。
    #[serde(default)]
    pub control_url: Option<String>,

    /// Tailscale 认证 key（用于自动加入 tailnet，可从 Tailscale 控制台生成）
    #[serde(default)]
    pub auth_key: Option<String>,

    /// 在 tailnet 中显示的主机名（不填时由控制服务器分配）
    #[serde(default)]
    pub hostname: Option<String>,

    /// 客户端名称（用于 Tailscale 控制台展示，默认 `"reflex"`）
    #[serde(default = "default_ts_client_name")]
    pub client_name: Option<String>,

    /// 状态文件目录（保存 Tailscale 私钥等状态）。
    /// 留空时使用内存中的临时状态（每次进程重启都需要重新认证）。
    #[serde(default)]
    pub state_dir: Option<String>,

    /// 是否以 ephemeral 模式运行（节点退出 tailnet 后自动清理）。
    /// 默认 false。设为 true 时忽略 `state_dir`。
    #[serde(default)]
    pub ephemeral: bool,

    /// 出站链式代理（预留）
    #[serde(default)]
    pub detour: Option<String>,
}

fn default_ts_client_name() -> Option<String> {
    Some("reflex".into())
}

/// 所有出站类型，用 `type` 字段做 tag。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OutboundConfig {
    Vless(VlessOutboundConfig),
    Vmess(VmessOutboundConfig),
    Shadowsocks(ShadowsocksOutboundConfig),
    Hysteria2(Hysteria2OutboundConfig),
    Tuic(TuicOutboundConfig),
    Trojan(TrojanOutboundConfig),
    #[serde(rename = "anytls")]
    AnyTls(AnyTlsOutboundConfig),
    #[serde(rename = "shadowquic")]
    ShadowQuic(ShadowQuicOutboundConfig),
    Naive(NaiveOutboundConfig),
    Direct(DirectOutboundConfig),
    Block(BlockOutboundConfig),
    Socks(SocksOutboundConfig),
    Selector(SelectorOutboundConfig),
    UrlTest(UrlTestOutboundConfig),
    WireGuard(WireGuardOutboundConfig),
    Ssh(SshOutboundConfig),
    Tailscale(TailscaleOutboundConfig),
}

impl OutboundConfig {
    pub fn tag(&self) -> &str {
        match self {
            Self::Vless(c) => &c.tag,
            Self::Vmess(c) => &c.tag,
            Self::Shadowsocks(c) => &c.tag,
            Self::Hysteria2(c) => &c.tag,
            Self::Tuic(c) => &c.tag,
            Self::Trojan(c) => &c.tag,
            Self::AnyTls(c) => &c.tag,
            Self::ShadowQuic(c) => &c.tag,
            Self::Naive(c) => &c.tag,
            Self::Direct(c) => &c.tag,
            Self::Block(c) => &c.tag,
            Self::Socks(c) => &c.tag,
            Self::Selector(c) => &c.tag,
            Self::UrlTest(c) => &c.tag,
            Self::WireGuard(c) => &c.tag,
            Self::Ssh(c) => &c.tag,
            Self::Tailscale(c) => &c.tag,
        }
    }

    pub fn child_outbounds(&self) -> &[String] {
        match self {
            Self::Selector(c) => &c.outbounds,
            Self::UrlTest(c) => &c.outbounds,
            _ => &[],
        }
    }

    pub fn group_providers(&self) -> Option<&crate::config::provider::ProviderRef> {
        match self {
            Self::Selector(c) => c.providers.as_ref(),
            Self::UrlTest(c) => c.providers.as_ref(),
            _ => None,
        }
    }

    pub fn group_default(&self) -> Option<&str> {
        match self {
            Self::Selector(c) => c.r#default.as_deref(),
            _ => None,
        }
    }

    pub fn is_group(&self) -> bool {
        matches!(self, Self::Selector(_) | Self::UrlTest(_))
    }
}

// ── AnyTLS ────────────────────────────────────────────────────────────────────

/// AnyTLS 出站配置（与 sing-box AnyTLSOutboundOptions 对齐）。
///
/// AnyTLS 是基于 TLS 的多路复用代理协议。
/// - 认证：TLS 握手后发送 sha256(password) + padding
/// - 会话复用：多个 Stream 复用同一 TLS 连接
/// - UDP：使用 sing-box UDP-over-TCP v2 协议封装（目标地址 `sp.v2.udp-over-tcp.arpa:443`）
///
/// 配置示例：
/// ```json
/// {
///   "type": "anytls",
///   "tag": "anytls-proxy",
///   "server": "example.com",
///   "server_port": 443,
///   "password": "your-password",
///   "tls": {
///     "enabled": true,
///     "server_name": "example.com",
///     "insecure": false
///   },
///   "idle_session_check_interval": "30s",
///   "idle_session_timeout": "60s",
///   "min_idle_session": 0
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnyTlsOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// 认证密码
    pub password: String,

    /// TLS 配置（AnyTLS 必须启用 TLS）
    #[serde(default)]
    pub tls: TlsConfig,

    /// 空闲会话检查间隔（如 "30s"，默认 "30s"）
    #[serde(default)]
    pub idle_session_check_interval: Option<String>,

    /// 空闲会话超时（如 "60s"，默认 "60s"）
    #[serde(default)]
    pub idle_session_timeout: Option<String>,

    /// 最少保留的空闲会话数（默认 0）
    #[serde(default)]
    pub min_idle_session: u32,

    /// 出站链式代理（预留）
    #[serde(default)]
    pub detour: Option<String>,
}

// ── ShadowQuic ───────────────────────────────────────────────────────────────

/// ShadowQuic 出站配置（参考 clash-rs `OutboundShadowQuic` + shadowquic `ShadowQuicClientCfg`）。
///
/// ShadowQuic 是基于 0-RTT QUIC + JLS SNI 伪装的代理协议：
/// - 0-RTT：首包即数据，降低握手延迟
/// - JLS：SNI 伪装，TLS 握手呈现的是伪装域名，实际连接到 shadowquic 服务端
/// - UDP：支持 datagram 模式（高效，推荐）和 stream 模式（兼容性更好）
///
/// 配置示例：
/// ```json
/// {
///   "type": "shadowquic",
///   "tag": "sq-out",
///   "server": "example.com",
///   "server_port": 443,
///   "password": "your-password",
///   "username": "your-username",
///   "server_name": "camouflage.example.com",
///   "congestion_control": "bbr",
///   "zero_rtt": true,
///   "over_stream": false
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowQuicOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// JLS 认证密码（必须与服务端一致）
    pub password: String,

    /// JLS 认证用户名（必须与服务端一致）
    #[serde(default)]
    pub username: String,

    /// SNI 伪装域名（必须与服务端 jls_upstream 域名一致）
    pub server_name: String,

    /// TLS ALPN，默认 ["h3"]，必须与服务端有交集
    #[serde(default = "default_sq_alpn")]
    pub alpn: Vec<String>,

    /// 初始 MTU（≥1200，高丢包网络建议 1400，默认 1300）
    #[serde(default = "default_sq_initial_mtu")]
    pub initial_mtu: u16,

    /// 拥塞控制算法：`"bbr"`（默认）、`"cubic"`、`"new-reno"`、`"brutal"`
    #[serde(default = "default_sq_congestion_control")]
    pub congestion_control: String,

    /// Brutal 拥塞控制的上行带宽（bps），仅当 `congestion_control = "brutal"` 时生效。
    /// 默认 10 Mbps（10_000_000）
    #[serde(default = "default_sq_brutal_bandwidth")]
    pub brutal_bandwidth: u64,

    /// 启用 0-RTT 握手（默认 true）
    #[serde(default = "default_sq_zero_rtt")]
    pub zero_rtt: bool,

    /// UDP over stream 模式：true 用 QUIC 单向流传 UDP，false 用 QUIC datagram。
    /// 代理 HTTP3 流量时建议 false（避免 TCP-in-TCP 熔断）。
    /// 默认 false
    #[serde(default = "default_sq_over_stream")]
    pub over_stream: bool,

    /// 最小 MTU（必须小于 initial_mtu，≥1200，默认 1290）
    #[serde(default = "default_sq_min_mtu")]
    pub min_mtu: u16,

    /// Keep alive 间隔（毫秒），0 表示禁用（应 < 30000 空闲超时），默认 0
    #[serde(default = "default_sq_keep_alive_interval")]
    pub keep_alive_interval: u32,

    /// 启用 QUIC GSO（Generic Segmentation Offload），默认 true
    #[serde(default = "default_sq_gso")]
    pub gso: bool,

    /// 启用 MTU 自动发现，默认 true。稳定 UDP 网络可关闭并设固定 initial_mtu
    #[serde(default = "default_sq_mtu_discovery")]
    pub mtu_discovery: bool,

    /// 启用 MTU 黑洞检测（默认 false）。高丢包网络建议关闭
    #[serde(default = "default_sq_blackhole_detection")]
    pub blackhole_detection: bool,

    /// 出站链式代理（预留）
    #[serde(default)]
    pub detour: Option<String>,
}

fn default_sq_alpn() -> Vec<String> {
    vec!["h3".into()]
}
fn default_sq_initial_mtu() -> u16 {
    1300
}
fn default_sq_congestion_control() -> String {
    "bbr".into()
}
fn default_sq_brutal_bandwidth() -> u64 {
    10_000_000
}
fn default_sq_zero_rtt() -> bool {
    true
}
fn default_sq_over_stream() -> bool {
    false
}
fn default_sq_min_mtu() -> u16 {
    1290
}
fn default_sq_keep_alive_interval() -> u32 {
    0
}
fn default_sq_gso() -> bool {
    true
}
fn default_sq_mtu_discovery() -> bool {
    true
}
fn default_sq_blackhole_detection() -> bool {
    false
}

// ── Naive ────────────────────────────────────────────────────────────────────

/// NaiveProxy 出站配置（与 sing-box `NaiveOutboundOptions` 字段完全对齐）。
///
/// NaiveProxy 使用 HTTP/2 CONNECT 方法建立隧道，承载于 TLS 之上。
/// 协议参考：https://github.com/klzgrad/naiveproxy
///
/// sing-box 通过 cronet-go（Chrome 网络栈）实现，本实现使用 `h2` crate
/// 提供 HTTP/2 over TCP+TLS 隧道（QUIC/HTTP3 模式暂不支持，配置字段保留）。
///
/// 配置示例：
/// ```json
/// {
///   "type": "naive",
///   "tag": "naive-out",
///   "server": "example.com",
///   "server_port": 443,
///   "username": "user",
///   "password": "pass",
///   "tls": {
///     "enabled": true,
///     "server_name": "example.com",
///     "certificate": ["<PEM 内容>"]
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaiveOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP（对应 sing-box `ServerOptions.Server`）
    pub server: String,

    /// 服务器端口（对应 sing-box `ServerOptions.ServerPort`）
    pub server_port: u16,

    /// 用户名（对应 sing-box `Username`）
    #[serde(default)]
    pub username: String,

    /// 密码（对应 sing-box `Password`）
    #[serde(default)]
    pub password: String,

    /// 不安全并发数（对应 sing-box `InsecureConcurrency`）。
    /// 大于 1 时会启动多个独立的连接池轮询使用，sing-box 原生含义与 cronet
    /// 连接池隔离有关；本实现将其记录但暂不强制隔离（单连接池已足够）。
    #[serde(default)]
    pub insecure_concurrency: u32,

    /// 额外 HTTP 请求头（对应 sing-box `ExtraHeaders`）。
    /// sing-box 原始类型为 `map[string][]string`，此处取首个值。
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,

    /// HTTP/2 流接收窗口大小（字节，对应 sing-box `stream_receive_window`）。
    /// 接受纯数字或带 K/M/G 后缀的字符串（如 `"64K"`、`"1M"`）。0 = 使用 h2 默认值。
    #[serde(default)]
    pub stream_receive_window: MemoryBytes,

    /// UDP over TCP 配置（对应 sing-box `udp_over_tcp`）。
    /// 启用后 UDP 流量通过 TCP 隧道传输。
    #[serde(default)]
    pub udp_over_tcp: Option<UdpOverTcpConfig>,

    /// 启用 QUIC/HTTP3 模式（对应 sing-box `QUIC`）。
    /// 当前实现仅支持 HTTP/2 over TCP+TLS；启用此选项会返回错误。
    #[serde(default)]
    pub quic: bool,

    /// QUIC 拥塞控制算法（对应 sing-box `QUICCongestionControl`）。
    /// 可选值：`""`（默认）、`"bbr"`、`"bbr2"`、`"cubic"`、`"reno"`。
    #[serde(default)]
    pub quic_congestion_control: String,

    /// QUIC 会话接收窗口大小（对应 sing-box `quic_session_receive_window`）。
    /// 格式同 `stream_receive_window`。仅在 QUIC 模式下生效。
    #[serde(default)]
    pub quic_session_receive_window: MemoryBytes,

    /// TLS 配置（NaiveProxy 必须启用 TLS）。
    /// 对应 sing-box `OutboundTLSOptionsContainer.TLS`。
    #[serde(default)]
    pub tls: TlsConfig,
}

/// UDP over TCP 配置（与 sing-box `UDPOverTCPOptions` 对齐）。
///
/// 序列化支持两种 JSON 形式（与 sing-box 行为一致）：
/// - 简写：`true` / `false`（version 默认 2）
/// - 完整：`{ "enabled": true, "version": 2 }`
///
/// 默认 version = 2（与 sing-box `uot.Version` 一致）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpOverTcpConfig {
    pub enabled: bool,
    pub version: u8,
}

impl UdpOverTcpConfig {
    /// 默认 UoT 版本（与 sing-box `uot.Version` 对齐）。
    pub const DEFAULT_VERSION: u8 = 2;
}

impl Serialize for UdpOverTcpConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        // version 为 0 或默认值时按 bool 序列化（与 sing-box MarshalJSON 一致）
        if self.version == 0 || self.version == Self::DEFAULT_VERSION {
            serializer.serialize_bool(self.enabled)
        } else {
            let mut map = serializer.serialize_map(Some(2))?;
            map.serialize_entry("enabled", &self.enabled)?;
            map.serialize_entry("version", &self.version)?;
            map.end()
        }
    }
}

impl<'de> Deserialize<'de> for UdpOverTcpConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // 先尝试按 bool 解析（简写形式），失败再按结构体解析
        #[derive(serde::Deserialize, Default)]
        struct Inner {
            #[serde(default)]
            enabled: bool,
            #[serde(default)]
            version: u8,
        }
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Some(b) = value.as_bool() {
            return Ok(Self {
                enabled: b,
                version: Self::DEFAULT_VERSION,
            });
        }
        let inner: Inner = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
        Ok(Self {
            enabled: inner.enabled,
            version: if inner.version == 0 {
                Self::DEFAULT_VERSION
            } else {
                inner.version
            },
        })
    }
}

/// 内存字节大小（对应 sing-box `byteformats.MemoryBytes`）。
///
/// 接受以下 JSON 形式：
/// - 纯数字：`65536` → 65536 字节
/// - 数字字符串：`"65536"` → 65536 字节
/// - 带后缀字符串：`"64K"` / `"64KB"` → 65536 字节（K/M/G 不区分大小写，1024 进制）
///
/// 0 表示未设置（由实现使用默认值）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryBytes(pub u64);

impl MemoryBytes {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl Serialize for MemoryBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MemoryBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if let Some(n) = value.as_u64() {
            return Ok(Self(n));
        }
        if let Some(s) = value.as_str() {
            return Ok(Self(
                parse_memory_bytes(s).map_err(serde::de::Error::custom)?,
            ));
        }
        Err(serde::de::Error::custom(format!(
            "expected number or string, got: {value}"
        )))
    }
}

/// 解析带 K/M/G 后缀的字节字符串（不区分大小写，1024 进制）。
fn parse_memory_bytes(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let upper = s.to_ascii_uppercase();
    let (num, multiplier) = if let Some(rest) = upper.strip_suffix("KB") {
        (rest.trim_end(), 1024u64)
    } else if let Some(rest) = upper.strip_suffix("K") {
        (rest.trim_end(), 1024u64)
    } else if let Some(rest) = upper.strip_suffix("MB") {
        (rest.trim_end(), 1024u64 * 1024)
    } else if let Some(rest) = upper.strip_suffix("M") {
        (rest.trim_end(), 1024u64 * 1024)
    } else if let Some(rest) = upper.strip_suffix("GB") {
        (rest.trim_end(), 1024u64 * 1024 * 1024)
    } else if let Some(rest) = upper.strip_suffix("G") {
        (rest.trim_end(), 1024u64 * 1024 * 1024)
    } else {
        (s, 1u64)
    };
    let n: u64 = num
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid memory bytes number: '{num}'"))?;
    Ok(n.saturating_mul(multiplier))
}

// ── Shadowsocks ───────────────────────────────────────────────────────────────

/// Shadowsocks 出站配置。
///
/// 支持的加密方法（与 sing-box 对齐）：
/// - AEAD：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`
/// - AEAD-2022：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、
///   `2022-blake3-chacha20-poly1305`
/// - 明文（仅测试）：`none`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// 加密方法，如 `"aes-128-gcm"`、`"chacha20-ietf-poly1305"`、
    /// `"2022-blake3-aes-128-gcm"` 等。
    pub method: String,

    /// 密码（AEAD 模式）或 PSK（AEAD-2022，base64 编码）
    pub password: String,

    /// SIP003 插件名称，如 `"obfs-local"`（可选）
    #[serde(default)]
    pub plugin: Option<String>,

    /// SIP003 插件参数，如 `"obfs=http;obfs-host=www.example.com"`（可选）
    #[serde(default)]
    pub plugin_opts: Option<String>,

    /// 传输层配置（可选）；支持 xhttp 传输。
    /// 使用 xhttp 时，SS 加密后的数据将通过 HTTP 流传输，而非裸 TCP。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<ShadowsocksTransportConfig>,

    /// TLS 配置（xhttp 传输时可配合使用；裸 TCP 模式通常不需要）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    /// 多路复用配置（SMux/Yamux）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<MultiplexConfig>,

    /// 出站本身走哪个 outbound（链式代理，预留）
    #[serde(default)]
    pub detour: Option<String>,
}

/// Shadowsocks 传输层配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ShadowsocksTransportConfig {
    /// WebSocket 传输
    Ws(WsTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
    /// gRPC 传输（基于 HTTP/2）
    Grpc(GrpcTransportConfig),
}

// ── VLESS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VlessOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// UUID（标准格式，如 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"）
    pub uuid: String,

    /// Flow（与 sing-box `flow` 字段对齐）：
    /// - `""` 或省略：普通 VLESS
    /// - `"xtls-rprx-vision"`：XTLS Vision 流控，握手后在用户态绕过 TLS AEAD
    ///   直接读写裸 TCP（参照 sing-vmess vless/vision.go）。
    ///   仅在裸 TCP+TLS（无 transport、无 multiplex）时生效。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,

    /// 传输层配置：ws 或 tcp。可选，缺省时视为裸 TCP。
    /// 与 sing-box 一致：`{ "type": "ws", "path": "...", "headers": {} }`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<VlessTransportConfig>,

    /// TLS 配置（与 sing-box 对齐）：
    /// - 普通 TLS：`{ "enabled": true, "server_name": "..." }`
    /// - REALITY：在 tls 对象内嵌套 `"reality": { "public_key": "...", "short_id": "..." }`
    /// - 无 TLS：省略此字段或 `{ "enabled": false }`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<VlessTlsConfig>,

    /// 多路复用配置（SMux/Yamux）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<MultiplexConfig>,

    /// 出站本身走哪个 outbound（用于链式代理，暂未实现，预留字段）
    #[serde(default)]
    pub detour: Option<String>,
}

/// VLESS 传输层配置（与 sing-box V2RayTransportOptions 对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VlessTransportConfig {
    Ws(WsTransportConfig),
    /// 裸 TCP 传输
    Tcp(TcpTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
    /// gRPC 传输（基于 HTTP/2）
    Grpc(GrpcTransportConfig),
}

/// TCP 传输配置（VLESS over TCP）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TcpTransportConfig {
    /// 是否启用 HTTP/1.1 伪装（预留）
    #[serde(default)]
    pub http_upgrade: bool,
}

/// VLESS TLS 配置（与 sing-box OutboundTLSOptions 对齐）
///
/// 普通 TLS 示例：
/// ```json
/// { "enabled": true, "server_name": "example.com", "insecure": false }
/// ```
/// REALITY 示例（reality 嵌套在 tls 内）：
/// ```json
/// {
///   "enabled": true,
///   "server_name": "www.apple.com",
///   "reality": { "enabled": true, "public_key": "...", "short_id": "..." }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VlessTlsConfig {
    /// 是否启用 TLS，默认 false
    #[serde(default)]
    pub enabled: bool,

    /// SNI，默认等于 server 字段
    #[serde(default)]
    pub server_name: Option<String>,

    /// 跳过证书验证（不安全，仅调试用）
    #[serde(default)]
    pub insecure: bool,

    /// 自定义 CA 证书路径（PEM）
    #[serde(default)]
    pub ca_path: Option<String>,

    /// ALPN 列表
    #[serde(default)]
    pub alpn: Vec<String>,

    /// REALITY 配置（存在时启用 REALITY，忽略普通 TLS 验证）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<RealityConfig>,

    /// uTLS 浏览器指纹配置（与 sing-box utls 字段对齐）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utls: Option<UtlsConfig>,

    /// ECH（Encrypted Client Hello）配置（与 sing-box ech 字段对齐）。
    /// 启用后会加密 ClientHello 中的 SNI 等敏感字段，防止中间人观察真实域名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech: Option<OutboundECHOptions>,
}

/// REALITY 客户端配置（嵌套在 tls 对象内，与 sing-box OutboundRealityOptions 对齐）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealityConfig {
    /// 启用标志（sing-box 兼容）
    #[serde(default)]
    pub enabled: bool,

    /// 服务端 x25519 公钥（base64url 编码）
    #[serde(default)]
    pub public_key: String,

    /// shortId（hex，0~16字符，偶数位）
    #[serde(default)]
    pub short_id: String,
}

/// 出站 ECH（Encrypted Client Hello）配置，与 sing-box `OutboundECHOptions` 对齐。
///
/// ECH（RFC 9460）通过加密 ClientHello 中的 SNI 等敏感字段，防止中间人观察
/// 客户端正在连接的真实域名。客户端使用服务端在 DNS HTTPS RR 中发布的
/// `ECHConfigList`（或显式配置）派生 HPKE 密钥，将真实的 inner ClientHello
/// 加密封装到 outer ClientHello 的 ECH 扩展中。
///
/// 配置示例（与 sing-box 一致）：
/// ```json
/// "tls": {
///   "enabled": true,
///   "server_name": "example.com",
///   "ech": {
///     "enabled": true,
///     "config": ["-----BEGIN ECH CONFIGS-----\n...\n-----END ECH CONFIGS-----"]
///   }
/// }
/// ```
///
/// 也可以仅启用 ECH 而不提供 `config`，此时应在运行时通过 DNS HTTPS RR
/// 获取 ECHConfigList（对应 sing-box 中 `query_server_name` 为空时回退到
/// `server_name` 的行为）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutboundECHOptions {
    /// 是否启用 ECH，默认 false
    #[serde(default)]
    pub enabled: bool,

    /// ECH 配置（PEM 字符串列表，类型为 `ECH CONFIGS`）。
    /// 多个字符串会按 sing-box 行为以 `\n` 拼接后整体 PEM 解码。
    /// 与 sing-box `ech.config` 字段对齐。
    #[serde(default)]
    pub config: Vec<String>,

    /// ECH 配置文件路径（PEM 格式，`ECH CONFIGS` 块）。
    /// 与 sing-box `ech.config_path` 字段对齐。
    #[serde(default)]
    pub config_path: Option<String>,

    /// 通过 DNS HTTPS RR 获取 ECHConfigList 时使用的查询域名。
    /// 为空时回退到 TLS `server_name`。与 sing-box `ech.query_server_name` 对齐。
    #[serde(default)]
    pub query_server_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsTransportConfig {
    /// WebSocket 握手路径，默认 "/"
    #[serde(default = "default_ws_path")]
    pub path: String,

    /// 额外请求头（常用于设置 Host）
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// 早期数据（0-RTT），字节数，0 表示禁用
    #[serde(default)]
    pub early_data_header_name: Option<String>,

    #[serde(default)]
    pub max_early_data: u32,
}

/// XHTTP (SplitHTTP) 传输配置
///
/// 字段名与 sing-box / Xray xhttp transport 完全对齐，示例：
/// ```json
/// {
///   "type": "xhttp",
///   "host": "example.com",
///   "path": "/xhttp/",
///   "mode": "packet-up",
///   "headers": { "X-Custom": "value" },
///   "scMaxEachPostBytes": 1000000,
///   "scMinPostsIntervalMs": 30,
///   "scMaxBufferedPosts": 512,
///   "noGRPCHeader": false,
///   "noSSEHeader": false,
///   "uplinkHTTPMethod": "POST",
///   "xmux": {
///     "maxConcurrency": 8,
///     "maxConnections": 4,
///     "cMaxReuseTimes": 64,
///     "hMaxRequestTimes": 128,
///     "hMaxReusableSecs": 300
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XhttpTransportConfig {
    /// HTTP Host 头（可选，缺省使用 server 字段或 TLS SNI）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,

    /// URL 路径，默认 "/"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// 传输模式：`stream-one` | `stream-up` | `packet-up`（默认）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// 额外自定义请求头
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// packet-up 模式每个 POST 的最大字节数
    /// sing-box / Xray 字段名：`scMaxEachPostBytes`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "scMaxEachPostBytes"
    )]
    pub sc_max_each_post_bytes: Option<u64>,

    /// 相邻两次 POST 的最小间隔毫秒数
    /// sing-box / Xray 字段名：`scMinPostsIntervalMs`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "scMinPostsIntervalMs"
    )]
    pub sc_min_posts_interval_ms: Option<u64>,

    /// 允许缓冲的最大 POST 数
    /// sing-box / Xray 字段名：`scMaxBufferedPosts`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "scMaxBufferedPosts"
    )]
    pub sc_max_buffered_posts: Option<u64>,

    /// 禁用 gRPC 兼容头（`content-type: application/grpc`）
    /// sing-box / Xray 字段名：`noGRPCHeader`
    #[serde(default, rename = "noGRPCHeader")]
    pub no_grpc_header: bool,

    /// 禁用 SSE 响应头（`content-type: text/event-stream`）
    /// sing-box / Xray 字段名：`noSSEHeader`
    #[serde(default, rename = "noSSEHeader")]
    pub no_sse_header: bool,

    /// 上行 HTTP 方法，默认 `"POST"`
    /// sing-box / Xray 字段名：`uplinkHTTPMethod`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "uplinkHTTPMethod"
    )]
    pub uplink_http_method: Option<String>,

    /// Xmux 连接复用配置
    /// sing-box / Xray 字段名：`xmux`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xmux: Option<XmuxConfig>,
}

/// Xmux 连接复用配置（与 sing-box / Xray `xmux` 字段对齐）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XmuxConfig {
    /// 单连接最大并发流数
    /// sing-box / Xray 字段名：`maxConcurrency`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxConcurrency"
    )]
    pub max_concurrency: Option<u32>,

    /// 最大连接数
    /// sing-box / Xray 字段名：`maxConnections`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "maxConnections"
    )]
    pub max_connections: Option<u32>,

    /// 客户端连接最大复用次数
    /// sing-box / Xray 字段名：`cMaxReuseTimes`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "cMaxReuseTimes"
    )]
    pub c_max_reuse_times: Option<u32>,

    /// 每条 h2 连接最大请求次数
    /// sing-box / Xray 字段名：`hMaxRequestTimes`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hMaxRequestTimes"
    )]
    pub h_max_request_times: Option<u32>,

    /// h2 连接最长复用秒数
    /// sing-box / Xray 字段名：`hMaxReusableSecs`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hMaxReusableSecs"
    )]
    pub h_max_reusable_secs: Option<u32>,

    /// h2 keepalive 间隔秒数
    /// sing-box / Xray 字段名：`hKeepAlivePeriod`
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "hKeepAlivePeriod"
    )]
    pub h_keep_alive_period: Option<u64>,
}

// ── VMess ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmessOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// VMess 用户 UUID
    pub uuid: String,

    /// VMess security 字段，如 "auto"、"none"、"aes-128-gcm"、"chacha20-poly1305"。
    #[serde(default = "default_vmess_security")]
    pub security: String,

    /// 传输层配置：tcp 或 ws。
    #[serde(default)]
    pub transport: VmessTransportConfig,

    /// TLS 配置；默认关闭，配置 { "enabled": true } 时启用。
    #[serde(default = "default_disabled_tls")]
    pub tls: TlsConfig,

    /// 多路复用配置（SMux/Yamux）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<MultiplexConfig>,

    #[serde(default)]
    pub detour: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VmessTransportConfig {
    #[default]
    Tcp,
    Ws(WsTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
    /// gRPC 传输（基于 HTTP/2）
    Grpc(GrpcTransportConfig),
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2OutboundConfig {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    pub password: String,

    #[serde(default)]
    pub tls: TlsConfig,

    /// 上行带宽 Mbps（与 sing-box up_mbps 对齐），0 表示不限速
    #[serde(default)]
    pub up_mbps: u64,

    /// 下行带宽 Mbps（与 sing-box down_mbps 对齐），0 表示不限速
    #[serde(default)]
    pub down_mbps: u64,

    #[serde(default)]
    pub detour: Option<String>,
}

/// Mbps → bytes/s 转换（供出站内部使用）
pub fn mbps_to_bps(mbps: u64) -> u64 {
    mbps * 1_000_000 / 8
}

// ── TUIC ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicOutboundConfig {
    pub tag: String,

    pub server: String,
    pub server_port: u16,

    /// TUIC UUID
    pub uuid: String,

    /// TUIC password
    pub password: String,

    /// 拥塞控制算法，如 "cubic"、"new_reno"、"bbr"。
    #[serde(default = "default_tuic_congestion_control")]
    pub congestion_control: String,

    /// UDP relay mode，如 "native"。
    #[serde(default = "default_tuic_udp_relay_mode")]
    pub udp_relay_mode: String,

    /// TUIC 基于 QUIC/TLS，默认启用 TLS。
    #[serde(default)]
    pub tls: TlsConfig,

    #[serde(default)]
    pub heartbeat: Option<String>,

    /// 与 sing-box 对齐：zero_rtt_handshake
    #[serde(default)]
    pub zero_rtt_handshake: bool,

    #[serde(default)]
    pub detour: Option<String>,
}

// ── Trojan ────────────────────────────────────────────────────────────────────

/// Trojan 出站配置。
///
/// 支持传输层：
/// - `{ "type": "tcp" }` 裸 TCP（通常配合 TLS）
/// - `{ "type": "ws", "path": "/", "headers": {} }` WebSocket
///
/// TLS 配置通过 `tls` 字段控制（默认启用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrojanOutboundConfig {
    pub tag: String,

    /// 服务器域名或 IP
    pub server: String,

    pub server_port: u16,

    /// Trojan 密码（明文，握手时 SHA-224 后 hex 编码）
    pub password: String,

    /// 传输层配置。可选，缺省时为裸 TCP（与 sing-box 一致）。
    /// WS 示例：`{ "type": "ws", "path": "/ws", "headers": { "Host": "..." } }`
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TrojanTransportConfig>,

    /// TLS 配置（Trojan 通常必须启用 TLS）
    #[serde(default)]
    pub tls: TlsConfig,

    /// 多路复用配置（SMux/Yamux）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplex: Option<MultiplexConfig>,

    /// 出站链式代理（预留）
    #[serde(default)]
    pub detour: Option<String>,
}

/// Trojan 传输层配置
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum TrojanTransportConfig {
    /// 裸 TCP 传输（默认）
    Tcp(TrojanTcpConfig),
    /// WebSocket 传输
    Ws(WsTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(XhttpTransportConfig),
    /// gRPC 传输（基于 HTTP/2）
    Grpc(GrpcTransportConfig),
}

impl Default for TrojanTransportConfig {
    fn default() -> Self {
        Self::Tcp(TrojanTcpConfig::default())
    }
}

/// Trojan over TCP 配置（暂无额外字段，保留扩展空间）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrojanTcpConfig {}

// ── Direct / Block ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DirectOutboundConfig {
    pub tag: String,

    /// 绑定本地出口 IP（可选）
    #[serde(default)]
    pub bind_address: Option<String>,

    /// 拨号策略，对齐 sing-box `network_strategy`。
    /// - 不填或 `"default"`：仅用 DNS 解析结果的首选地址连接（原有行为，单地址，无回退）。
    /// - `"happy_eyeballs"`：域名同时有 A/AAAA 记录时，并发/错峰尝试多个候选地址
    ///   （IPv4 + IPv6），谁先连上用谁，谁先失败就尽快换下一个候选——参照
    ///   RFC 8305，能显著降低双栈网络下因某个协议栈故障/丢包导致的连接延迟。
    ///   仅对域名目标生效；目标本身就是 IP 时该选项无意义。
    #[serde(default)]
    pub network_strategy: Option<String>,

    /// `network_strategy = "happy_eyeballs"` 时，启动下一个候选地址前的等待
    /// 毫秒数，对齐 sing-box `fallback_delay`。默认 250（RFC 8305 推荐值）。
    #[serde(default)]
    pub fallback_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockOutboundConfig {
    pub tag: String,

    /// reject 方式，对齐 sing-box reject 动作的 `method` 字段：
    /// - 不填或 `"default"`：立即关闭连接（原有行为）。
    /// - `"drop"`：静默丢弃——不发送任何关闭信号，只是不再读写数据，让连接
    ///   挂起直到客户端自己超时。可用于让主动扫探/审查系统更难区分"被墙"
    ///   和"目标不存在"。
    ///
    /// 注：sing-box 还有一个 `"reply"`（伪造协议相关的应答后再关闭）方式未实现，
    /// 因为需要按具体协议构造看起来合理的回包，复杂度和收益不成正比，暂不支持。
    #[serde(default)]
    pub method: Option<String>,
}

// ── SOCKS ─────────────────────────────────────────────────────────────────────

/// SOCKS5/SOCKS4/SOCKS4a 出站配置（与 sing-box SOCKSOutboundOptions 对齐）。
///
/// 配置示例（SOCKS5 带认证）：
/// ```json
/// {
///   "type": "socks",
///   "tag": "socks-out",
///   "server": "127.0.0.1",
///   "server_port": 1080,
///   "version": "5",
///   "username": "user",
///   "password": "pass"
/// }
/// ```
///
/// SOCKS4 示例（不支持域名，客户端需预先解析）：
/// ```json
/// {
///   "type": "socks",
///   "tag": "socks4-out",
///   "server": "127.0.0.1",
///   "server_port": 1080,
///   "version": "4"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksOutboundConfig {
    pub tag: String,

    /// 代理服务器地址（域名或 IP）
    pub server: String,

    /// 代理服务器端口
    pub server_port: u16,

    /// 协议版本："5"（默认）、"4a"、"4"
    /// 与 sing-box `version` 字段对齐；缺省为 SOCKS5
    #[serde(default)]
    pub version: Option<String>,

    /// 用户名（SOCKS5 USER/PASS 认证，可选）
    #[serde(default)]
    pub username: Option<String>,

    /// 密码（SOCKS5 USER/PASS 认证，可选）
    #[serde(default)]
    pub password: Option<String>,
}

impl SocksOutboundConfig {
    /// 解析 version 字符串，返回规范化值。
    /// 合法值："5" | "4a" | "4"，其余视为错误。
    pub fn parsed_version(&self) -> anyhow::Result<SocksVersion> {
        match self.version.as_deref().unwrap_or("5") {
            "5" | "" => Ok(SocksVersion::V5),
            "4a" => Ok(SocksVersion::V4a),
            "4" => Ok(SocksVersion::V4),
            other => anyhow::bail!("unsupported socks version: '{other}', expected 5 / 4a / 4"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocksVersion {
    V5,
    V4a,
    V4,
}

// ── Selector / URL-Test ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectorOutboundConfig {
    pub tag: String,

    /// 静态 outbound tag 列表（在 providers 展开节点之前，排在最前面）。
    #[serde(default)]
    pub outbounds: Vec<String>,

    /// 引用的 provider 及过滤配置（展开节点追加在 outbounds 之后）。
    #[serde(default)]
    pub providers: Option<crate::config::provider::ProviderRef>,

    /// 默认选中的 outbound tag；为空时使用 outbounds[0]。
    #[serde(default)]
    pub r#default: Option<String>,

    /// 切换节点时是否强制中断经由本组的现有连接（默认 false）。
    #[serde(default)]
    pub interrupt_existing_connections: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlTestOutboundConfig {
    pub tag: String,

    /// 参与测速和自动选择的静态 outbound tag 列表。
    #[serde(default)]
    pub outbounds: Vec<String>,

    /// 引用的 provider 及过滤配置。
    #[serde(default)]
    pub providers: Option<crate::config::provider::ProviderRef>,

    /// 测速 URL。
    #[serde(default = "default_url_test_url")]
    pub url: String,

    /// 测速间隔，如 "3m"、"30s"、"1h"。
    #[serde(default = "default_url_test_interval")]
    pub interval: String,

    /// 单次测速最大等待时间。
    #[serde(default = "default_url_test_idle_timeout")]
    pub idle_timeout: String,

    /// 延迟容差（毫秒）：当前节点延迟在最低延迟 + tolerance 内时不切换。
    #[serde(default)]
    pub tolerance: u64,
}

impl UrlTestOutboundConfig {
    pub fn interval_duration(&self) -> anyhow::Result<std::time::Duration> {
        parse_duration(&self.interval)
    }

    pub fn idle_timeout_duration(&self) -> anyhow::Result<std::time::Duration> {
        parse_duration(&self.idle_timeout)
    }
}

// ── gRPC 传输配置 ────────────────────────────────────────────────────────────

/// gRPC 传输配置（与 clash-rs `GrpcOpt` / Xray `transport.internet.grpc` 对齐）。
///
/// gRPC 传输基于 HTTP/2，通过 POST `{service_name}/Tun` 建立双向流，
/// 数据按 `[grpc header 5B][protobuf field][varint len][data]` 帧格式封装。
///
/// 配置示例：
/// ```json
/// {
///   "type": "grpc",
///   "service_name": "GunService",
///   "host": "example.com"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GrpcTransportConfig {
    /// gRPC service name（对应 clash-rs `grpc_service_name`，会拼接成 `/{service_name}/Tun` 路径）。
    /// 留空时使用 `/`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,

    /// HTTP/2 :authority 头（对应 sing-box host）。留空时使用 TLS SNI 或 `server`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

// ── 公共 TLS 配置 ─────────────────────────────────────────────────────────────

/// uTLS 支持的浏览器指纹。
///
/// 与 sing-box `utls.fingerprint` 字段完全对齐。
/// 不填时默认使用 `"chrome"`。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UtlsFingerprint {
    /// Chrome（默认，最广泛）
    #[default]
    Chrome,
    /// Firefox
    Firefox,
    /// Safari
    Safari,
    /// iOS Safari
    Ios,
    /// Android 客户端
    Android,
    /// Edge
    Edge,
    /// 360 浏览器
    #[serde(rename = "360")]
    Browser360,
    /// QQ 浏览器
    Qq,
    /// 随机选择一种浏览器指纹
    Random,
    /// 使用 Go 标准 crypto/tls（即不伪造指纹）
    Go,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// SNI，默认等于 server 字段
    #[serde(default)]
    pub server_name: Option<String>,

    /// 跳过证书验证（不安全，仅调试用）
    #[serde(default)]
    pub insecure: bool,

    /// 自定义 CA 证书路径（PEM）。reflex 历史字段，与 sing-box `certificate_path` 等价。
    /// 优先级低于 `certificate` / `certificate_path`。
    #[serde(default)]
    pub ca_path: Option<String>,

    /// 内联 CA 证书内容（PEM 字符串列表），与 sing-box `certificate` 字段对齐。
    /// 多个 PEM 字符串会依次加入根证书库。优先级最高。
    #[serde(default)]
    pub certificate: Vec<String>,

    /// 自定义 CA 证书路径（PEM），与 sing-box `certificate_path` 字段对齐。
    /// 优先级低于 `certificate`，高于 `ca_path`。
    #[serde(default)]
    pub certificate_path: Option<String>,

    /// ALPN 列表，默认由协议层决定
    #[serde(default)]
    pub alpn: Vec<String>,

    /// 最低 TLS 版本
    #[serde(default)]
    pub min_version: Option<TlsVersion>,

    /// 最高 TLS 版本
    #[serde(default)]
    pub max_version: Option<TlsVersion>,

    /// uTLS 配置：启用浏览器 TLS 指纹伪造。
    ///
    /// 与 sing-box `utls` 字段对齐：
    /// ```json
    /// "utls": { "enabled": true, "fingerprint": "chrome" }
    /// ```
    /// 启用后将向服务端发送真实 Chrome/Firefox/Safari 的 ClientHello 字节，
    /// 通过大多数基于 TLS 指纹的检测。
    #[serde(default)]
    pub utls: Option<UtlsConfig>,

    /// ECH（Encrypted Client Hello）配置（与 sing-box `ech` 字段对齐）。
    ///
    /// 启用后会对 ClientHello 中的 SNI 等敏感字段进行加密，防止中间人观察
    /// 客户端正在连接的真实域名。
    ///
    /// ```json
    /// "ech": { "enabled": true, "config": ["<PEM ECH CONFIGS>"] }
    /// ```
    #[serde(default)]
    pub ech: Option<OutboundECHOptions>,
}

/// uTLS 配置块
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtlsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 浏览器指纹类型，默认 chrome
    #[serde(default)]
    pub fingerprint: UtlsFingerprint,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            server_name: None,
            insecure: false,
            ca_path: None,
            certificate: vec![],
            certificate_path: None,
            alpn: vec![],
            min_version: None,
            max_version: None,
            utls: None,
            ech: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

fn default_ws_path() -> String {
    "/".into()
}
fn default_vmess_security() -> String {
    "auto".into()
}
fn default_tuic_congestion_control() -> String {
    "cubic".into()
}
fn default_tuic_udp_relay_mode() -> String {
    "native".into()
}
fn default_true() -> bool {
    true
}
fn default_disabled_tls() -> TlsConfig {
    TlsConfig {
        enabled: false,
        ..Default::default()
    }
}
fn default_url_test_url() -> String {
    "https://www.gstatic.com/generate_204".into()
}
fn default_url_test_interval() -> String {
    "3m".into()
}
fn default_url_test_idle_timeout() -> String {
    "30m".into()
}

/// 内部使用的 REALITY 拨号配置，由 VlessTlsConfig + RealityConfig 组合而来，
/// 传递给 `reality::reality_connect()`。不对应任何 JSON 字段。
#[derive(Debug, Clone)]
pub struct RealityDialConfig {
    pub public_key: String,
    pub short_id: String,
    pub server_name: Option<String>,
    pub server: String,
    pub alpn: Vec<String>,
    pub fingerprint: String,
}

pub fn parse_duration(s: &str) -> anyhow::Result<std::time::Duration> {
    let s = s.trim();
    anyhow::ensure!(!s.is_empty(), "duration cannot be empty");
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    anyhow::ensure!(!num.is_empty(), "duration missing number: '{s}'");
    let value: u64 = num.parse()?;
    let seconds = match unit {
        "" | "s" => value,
        "m" => value * 60,
        "h" => value * 60 * 60,
        "d" => value * 24 * 60 * 60,
        _ => anyhow::bail!("unsupported duration unit in '{s}'"),
    };
    Ok(std::time::Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_vless() {
        // sing-box 格式：tls 字段 + transport 可选
        let v = json!({
            "type": "vless",
            "tag": "proxy",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "transport": {
                "type": "ws",
                "path": "/ws",
                "headers": { "Host": "example.com" }
            },
            "tls": {
                "enabled": true,
                "server_name": "example.com",
                "insecure": false
            }
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ob.tag(), "proxy");
        if let OutboundConfig::Vless(c) = ob {
            assert_eq!(c.server, "example.com");
            let tls = c.tls.as_ref().expect("expected tls");
            assert!(tls.enabled);
            assert_eq!(tls.server_name.as_deref(), Some("example.com"));
            assert!(!tls.insecure);
            let Some(VlessTransportConfig::Ws(ref ws)) = c.transport else {
                panic!("expected ws transport");
            };
            assert_eq!(ws.path, "/ws");
            assert_eq!(ws.headers.get("Host").unwrap(), "example.com");
        }
    }

    #[test]
    fn parse_vless_reality() {
        // sing-box 格式：reality 嵌套在 tls 内，transport 可省略
        let v = json!({
            "type": "vless",
            "tag": "reality-proxy",
            "server": "1.2.3.4",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "tls": {
                "enabled": true,
                "server_name": "www.example.com",
                "reality": {
                    "enabled": true,
                    "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "short_id": "0123456789abcdef"
                }
            }
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ob.tag(), "reality-proxy");
        if let OutboundConfig::Vless(c) = ob {
            // transport 缺省时为 None（裸 TCP）
            assert!(c.transport.is_none());
            let tls = c.tls.as_ref().expect("expected tls");
            let reality = tls.reality.as_ref().expect("expected reality");
            assert_eq!(reality.short_id, "0123456789abcdef");
            assert_eq!(tls.server_name.as_deref(), Some("www.example.com"));
        } else {
            panic!("expected vless outbound");
        }
    }

    #[test]
    fn parse_vmess_ws_tcp_tls_options() {
        let ws: OutboundConfig = serde_json::from_value(json!({
            "type": "vmess",
            "tag": "vmess-ws-tls",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "security": "auto",
            "transport": {
                "type": "ws",
                "path": "/vmess",
                "headers": { "Host": "example.com" }
            },
            "tls": { "enabled": true, "server_name": "example.com" }
        }))
        .unwrap();
        if let OutboundConfig::Vmess(c) = ws {
            assert!(c.tls.enabled);
            assert!(matches!(c.transport, VmessTransportConfig::Ws(_)));
        } else {
            panic!("expected vmess config");
        }

        let tcp: OutboundConfig = serde_json::from_value(json!({
            "type": "vmess",
            "tag": "vmess-tcp",
            "server": "example.com",
            "server_port": 80,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "transport": { "type": "tcp" },
            "tls": { "enabled": false }
        }))
        .unwrap();
        if let OutboundConfig::Vmess(c) = tcp {
            assert!(!c.tls.enabled);
            assert!(matches!(c.transport, VmessTransportConfig::Tcp));
        }
    }

    #[test]
    fn parse_tuic() {
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "tuic",
            "tag": "tuic",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "password": "secret",
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "tls": { "enabled": true, "server_name": "example.com" }
        }))
        .unwrap();
        if let OutboundConfig::Tuic(c) = ob {
            assert_eq!(c.congestion_control, "bbr");
            assert!(c.tls.enabled);
        } else {
            panic!("expected tuic config");
        }
    }

    #[test]
    fn parse_hysteria2() {
        let v = json!({
            "type": "hysteria2",
            "tag": "hy2",
            "server": "example.com",
            "server_port": 443,
            "password": "secret",
            "up_mbps": 50,
            "down_mbps": 200
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        assert_eq!(ob.tag(), "hy2");
    }

    #[test]
    fn parse_direct_block() {
        let direct: OutboundConfig =
            serde_json::from_value(json!({ "type": "direct", "tag": "direct" })).unwrap();
        let block: OutboundConfig =
            serde_json::from_value(json!({ "type": "block", "tag": "block" })).unwrap();
        assert_eq!(direct.tag(), "direct");
        assert_eq!(block.tag(), "block");
    }

    #[test]
    fn parse_socks_defaults() {
        // 最简配置：仅必填字段，version 缺省 → SOCKS5，无认证
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "socks",
            "tag": "socks-out",
            "server": "127.0.0.1",
            "server_port": 1080
        }))
        .unwrap();
        assert_eq!(ob.tag(), "socks-out");
        if let OutboundConfig::Socks(c) = ob {
            assert_eq!(c.server, "127.0.0.1");
            assert_eq!(c.server_port, 1080);
            assert!(c.version.is_none());
            assert!(c.username.is_none());
            assert!(c.password.is_none());
            assert_eq!(c.parsed_version().unwrap(), SocksVersion::V5);
        } else {
            panic!("expected socks config");
        }
    }

    #[test]
    fn parse_socks5_with_auth() {
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "socks",
            "tag": "socks5-auth",
            "server": "proxy.example.com",
            "server_port": 1080,
            "version": "5",
            "username": "alice",
            "password": "s3cr3t"
        }))
        .unwrap();
        if let OutboundConfig::Socks(c) = ob {
            assert_eq!(c.parsed_version().unwrap(), SocksVersion::V5);
            assert_eq!(c.username.as_deref(), Some("alice"));
            assert_eq!(c.password.as_deref(), Some("s3cr3t"));
        } else {
            panic!("expected socks config");
        }
    }

    #[test]
    fn parse_socks4a() {
        let ob: OutboundConfig = serde_json::from_value(json!({
            "type": "socks",
            "tag": "socks4a-out",
            "server": "127.0.0.1",
            "server_port": 1080,
            "version": "4a"
        }))
        .unwrap();
        if let OutboundConfig::Socks(c) = ob {
            assert_eq!(c.parsed_version().unwrap(), SocksVersion::V4a);
        } else {
            panic!("expected socks config");
        }
    }

    #[test]
    fn parse_selector_and_url_test() {
        let selector: OutboundConfig = serde_json::from_value(json!({
            "type": "selector",
            "tag": "🚀 节点选择",
            "outbounds": ["自动选择", "香港节点 01", "direct"],
            "default": "自动选择"
        }))
        .unwrap();
        assert_eq!(selector.tag(), "🚀 节点选择");
        if let OutboundConfig::Selector(c) = selector {
            assert_eq!(c.outbounds.len(), 3);
            assert_eq!(c.r#default.as_deref(), Some("自动选择"));
        } else {
            panic!("expected selector config");
        }

        let url_test: OutboundConfig = serde_json::from_value(json!({
            "type": "url-test",
            "tag": "自动选择",
            "outbounds": ["香港节点 01", "台湾节点 01", "美国节点 01"],
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "idle_timeout": "30m",
            "tolerance": 50
        }))
        .unwrap();
        assert_eq!(url_test.tag(), "自动选择");
        if let OutboundConfig::UrlTest(c) = url_test {
            assert_eq!(c.interval_duration().unwrap().as_secs(), 180);
            assert_eq!(c.idle_timeout_duration().unwrap().as_secs(), 1800);
            assert_eq!(c.tolerance, 50);
        } else {
            panic!("expected url-test config");
        }
    }

    #[test]
    fn bandwidth_mbps_to_bps() {
        // 与 sing-box 对齐：整数 Mbps → bytes/s
        assert_eq!(mbps_to_bps(100), 12_500_000);
        assert_eq!(mbps_to_bps(0), 0);
        assert_eq!(mbps_to_bps(1000), 125_000_000);
    }

    #[test]
    fn tls_defaults() {
        let tls = TlsConfig::default();
        assert!(tls.enabled);
        assert!(!tls.insecure);
        assert!(tls.server_name.is_none());
        assert!(tls.ech.is_none());
    }

    #[test]
    fn parse_ech_options() {
        // ECH 配置嵌套在 tls 内，与 sing-box `ech` 字段对齐
        let v = json!({
            "type": "vmess",
            "tag": "ech-proxy",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "tls": {
                "enabled": true,
                "server_name": "example.com",
                "ech": {
                    "enabled": true,
                    "config": ["-----BEGIN ECH CONFIGS-----\nfoo\n-----END ECH CONFIGS-----"],
                    "query_server_name": "example.com"
                }
            }
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        if let OutboundConfig::Vmess(c) = ob {
            assert!(c.tls.ech.as_ref().unwrap().enabled);
            assert_eq!(
                c.tls.ech.as_ref().unwrap().query_server_name.as_deref(),
                Some("example.com")
            );
            assert_eq!(c.tls.ech.as_ref().unwrap().config.len(), 1);
        } else {
            panic!("expected vmess config");
        }
    }

    #[test]
    fn parse_vless_ech_options() {
        let v = json!({
            "type": "vless",
            "tag": "vless-ech",
            "server": "example.com",
            "server_port": 443,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "tls": {
                "enabled": true,
                "ech": {
                    "enabled": true,
                    "config_path": "/etc/reflex/ech.pem"
                }
            }
        });
        let ob: OutboundConfig = serde_json::from_value(v).unwrap();
        if let OutboundConfig::Vless(c) = ob {
            let ech = c.tls.as_ref().unwrap().ech.as_ref().unwrap();
            assert!(ech.enabled);
            assert_eq!(ech.config_path.as_deref(), Some("/etc/reflex/ech.pem"));
        } else {
            panic!("expected vless config");
        }
    }
}
