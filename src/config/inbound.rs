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
    /// VLESS 协议服务端入站（sing-box 格式）
    Vless(VlessInboundConfig),
    /// VMess 协议服务端入站（sing-box 格式）
    Vmess(VmessInboundConfig),
    /// Trojan 协议服务端入站（sing-box 格式）
    Trojan(TrojanInboundConfig),
    /// Shadowsocks 协议服务端入站（sing-box 格式，支持 SS2022）
    Shadowsocks(ShadowsocksInboundConfig),
    /// NaiveProxy 协议服务端入站（HTTP/2 CONNECT + Basic Auth + padding）
    Naive(NaiveInboundConfig),
    /// AnyTLS 协议服务端入站
    Anytls(AnytlsInboundConfig),
    /// Hysteria2 协议服务端入站（QUIC）
    Hysteria2(Hysteria2InboundConfig),
    /// TUIC 协议服务端入站（QUIC）
    Tuic(TuicInboundConfig),
    /// ShadowQuic 协议服务端入站（0-RTT QUIC + JLS SNI 伪装）
    Shadowquic(ShadowQuicInboundConfig),
    /// WireGuard 服务端入站（参考 flux wireguard server）
    Wireguard(WireGuardInboundConfig),
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
            Self::Vless(c) => &c.tag,
            Self::Vmess(c) => &c.tag,
            Self::Trojan(c) => &c.tag,
            Self::Shadowsocks(c) => &c.tag,
            Self::Naive(c) => &c.tag,
            Self::Anytls(c) => &c.tag,
            Self::Hysteria2(c) => &c.tag,
            Self::Tuic(c) => &c.tag,
            Self::Shadowquic(c) => &c.tag,
            Self::Wireguard(c) => &c.tag,
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
            Self::Vless(c) => (&c.listen, c.listen_port),
            Self::Vmess(c) => (&c.listen, c.listen_port),
            Self::Trojan(c) => (&c.listen, c.listen_port),
            Self::Shadowsocks(c) => (&c.listen, c.listen_port),
            Self::Naive(c) => (&c.listen, c.listen_port),
            Self::Anytls(c) => (&c.listen, c.listen_port),
            Self::Hysteria2(c) => (&c.listen, c.listen_port),
            Self::Tuic(c) => (&c.listen, c.listen_port),
            Self::Shadowquic(c) => (&c.listen, c.listen_port),
            Self::Wireguard(c) => (&c.listen, c.listen_port),
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

// ── VLESS / VMess / Trojan 服务端（sing-box 格式）───────────────────────────
//
// 配置写法与 sing-box 完全一致（字段名、默认值、嵌套结构）：
//
// ```json
// {
//   "type": "vless",
//   "tag": "vless-in",
//   "listen": "::",
//   "listen_port": 443,
//   "users": [
//     { "name": "user1", "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "" }
//   ],
//   "tls": {
//     "enabled": true,
//     "server_name": "example.com",
//     "alpn": ["http/1.1"],
//     "certificate_path": "/path/fullchain.pem",
//     "key_path": "/path/privkey.pem"
//   }
// }
// ```
//
// vmess: `"users": [{ "name": "u1", "uuid": "...", "alterId": 0 }]`（仅支持 alterId=0 AEAD）
// trojan: `"users": [{ "name": "u1", "password": "..." }]`

/// sing-box 风格的入站用户（vless/vmess/trojan 共用，按协议取用各自字段）。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyUser {
    /// 用户名（可选，仅用于日志展示）
    #[serde(default)]
    pub name: Option<String>,

    /// VLESS / VMess：UUID
    #[serde(default)]
    pub uuid: Option<String>,

    /// VLESS：flow（如 "xtls-rprx-vision"）。reflex 服务端暂不支持 Vision，非空报错
    #[serde(default)]
    pub flow: Option<String>,

    /// VMess：alterId（camelCase 与 sing-box 一致）。仅支持 0（AEAD）
    #[serde(rename = "alterId", alias = "alter_id", default)]
    pub alter_id: Option<i64>,

    /// Trojan：密码
    #[serde(default)]
    pub password: Option<String>,
}

/// 服务端 TLS 配置，字段与 sing-box inbound tls 完全一致。
/// 与 outbound 的 `config::outbound::TlsConfig` 的区别：服务端需要证书/私钥，
/// 不需要 insecure/utls/ech 等 client 专属字段。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundTlsConfig {
    #[serde(default)]
    pub enabled: bool,

    /// 期望的 SNI（服务端用于日志与 ALPN 决策；rustls 服务端不做强制校验）
    #[serde(default)]
    pub server_name: Option<String>,

    /// ALPN 列表（如 ["h2", "http/1.1"]）
    #[serde(default)]
    pub alpn: Vec<String>,

    /// 证书 PEM 列表（内联，sing-box `certificate`）
    #[serde(default)]
    pub certificate: Vec<String>,

    /// 证书文件路径（sing-box `certificate_path`）
    #[serde(default)]
    pub certificate_path: Option<String>,

    /// 私钥 PEM（内联，sing-box `key`）
    #[serde(default)]
    pub key: Option<String>,

    /// 私钥文件路径（sing-box `key_path`）
    #[serde(default)]
    pub key_path: Option<String>,

    /// REALITY 服务端配置（存在且 enabled 时替代普通 TLS，对齐 sing-box
    /// inbound tls.reality）。Reality 模式下无需证书/私钥 PEM。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<InboundRealityConfig>,
}

/// REALITY 服务端配置（对齐 sing-box InboundRealityOptions）。
///
/// ```json
/// "tls": {
///   "enabled": true,
///   "server_name": "www.apple.com",
///   "reality": {
///     "enabled": true,
///     "handshake": { "server": "www.apple.com", "server_port": 443 },
///     "private_key": "...",
///     "short_id": ["0123abcd"]
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundRealityConfig {
    #[serde(default)]
    pub enabled: bool,

    /// 非 Reality 客户端（探测/扫描）的回落目标：真实转发到该站点，
    /// 对齐 sing-box `reality.handshake`。server_port 缺省 443。
    #[serde(default)]
    pub handshake: Option<RealityHandshakeConfig>,

    /// 服务端 x25519 私钥（base64url / base64，32 字节）
    #[serde(default)]
    pub private_key: String,

    /// shortId 白名单（hex，每项 ≤ 8 字节）
    #[serde(default)]
    pub short_id: Vec<String>,

    /// 客户端时间戳最大允许偏差（秒），≤ 0 表示不校验。缺省 60。
    #[serde(default, alias = "max_time_diff")]
    pub max_time_difference: i64,
}

impl InboundRealityConfig {
    /// 实际生效的最大时间偏差（秒）：未配置时默认 60（对齐 sing-box）
    pub fn effective_max_time_diff(&self) -> i64 {
        if self.max_time_difference == 0 {
            60
        } else {
            self.max_time_difference
        }
    }
}

/// REALITY 回落（handshake）目标
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealityHandshakeConfig {
    pub server: String,
    #[serde(default = "default_reality_handshake_port")]
    pub server_port: u16,
}

fn default_reality_handshake_port() -> u16 {
    443
}

// ── inbound 传输层（v2ray transport，对齐 sing-box V2RayTransportOptions）────

/// VLESS/VMess/Trojan inbound 传输层配置，与 sing-box `transport` 字段对齐。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundTransportConfig {
    /// 裸 TCP（缺省）
    Tcp,
    /// WebSocket 传输
    Ws(InboundWsTransportConfig),
    /// gRPC（HTTP/2）传输
    Grpc(InboundGrpcTransportConfig),
    /// XHTTP (SplitHTTP) 传输
    Xhttp(InboundXhttpTransportConfig),
}

/// WebSocket inbound 传输配置（对齐 sing-box V2RayWebsocketOptions）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundWsTransportConfig {
    /// 握手路径，默认 "/"
    #[serde(default = "default_ws_path_inbound")]
    pub path: String,

    /// 可选 Host 头校验
    #[serde(default)]
    pub host: Option<String>,

    /// 额外请求头校验（存在性/值）
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,

    /// 0-RTT 早期数据最大字节数，0 = 禁用
    #[serde(default)]
    pub max_early_data: u32,

    /// 早期数据 HTTP 头名；None = path 末尾 base64url 模式
    #[serde(default)]
    pub early_data_header_name: Option<String>,
}

fn default_ws_path_inbound() -> String {
    "/".to_string()
}

/// gRPC inbound 传输配置（对齐 sing-box V2RayGRPCOptions）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundGrpcTransportConfig {
    /// gRPC 服务名（客户端 path 为 /<service_name>/Tun），默认 ""
    #[serde(default)]
    pub service_name: String,

    /// 可选 Host（:authority）校验
    #[serde(default)]
    pub host: Option<String>,
}

/// XHTTP inbound 传输配置（对齐 sing-box V2RaySplitHTTPOptions）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InboundXhttpTransportConfig {
    /// 基础路径，默认 "/"；自动规范化为前后带 `/`
    #[serde(default = "default_ws_path_inbound")]
    pub path: String,

    /// 可选 Host 头校验
    #[serde(default)]
    pub host: Option<String>,

    /// 模式（auto/packet-up/stream-up/stream-one），服务端全模式自适应，仅记录
    #[serde(default)]
    pub mode: Option<String>,
}

/// VLESS / VMess / Trojan 服务端共享配置结构。
///
/// 三种协议的可配置面完全一致（listen/users/tls），仅 users 内的
/// 必填字段不同，因此共用一个结构体、三个枚举变体分别命名。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyInboundConfig {
    pub tag: String,

    /// 监听地址，sing-box 默认 "::"（双栈）
    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// 用户列表（必填，至少一个；启动时校验）
    #[serde(default)]
    pub users: Vec<ProxyUser>,

    /// 服务端 TLS（disabled 时为明文；reality.enabled 时为 REALITY）
    #[serde(default)]
    pub tls: InboundTlsConfig,

    /// 传输层（对齐 sing-box V2RayTransportOptions）：
    /// `{"type":"tcp"}`（缺省）、`ws`、`grpc`、`xhttp`。
    #[serde(default)]
    pub transport: Option<InboundTransportConfig>,
}

impl ProxyInboundConfig {
    /// 启动时校验：users 非空、按协议字段齐全、tls/transport 配置合法性。
    pub fn validate(&self, protocol: &str) -> anyhow::Result<()> {
        if self.users.is_empty() {
            anyhow::bail!("{protocol} inbound '{}': users must not be empty", self.tag);
        }
        for (i, u) in self.users.iter().enumerate() {
            match protocol {
                "vless" | "vmess" => {
                    let uuid = u.uuid.as_deref().unwrap_or("");
                    anyhow::ensure!(
                        !uuid.is_empty(),
                        "{protocol} inbound '{}': users[{i}].uuid is required",
                        self.tag
                    );
                }
                "trojan" => {
                    anyhow::ensure!(
                        !u.password.as_deref().unwrap_or("").is_empty(),
                        "trojan inbound '{}': users[{i}].password is required",
                        self.tag
                    );
                }
                _ => {}
            }
            if protocol == "vmess" {
                anyhow::ensure!(
                    u.alter_id.unwrap_or(0) == 0,
                    "vmess inbound '{}': only alterId=0 (AEAD) is supported",
                    self.tag
                );
            }
        }
        // TLS / REALITY 校验（与实现入口对齐：crate::inbound::transport::InboundStack）
        let tls = &self.tls;
        if let Some(reality) = tls.reality.as_ref().filter(|r| r.enabled) {
            let priv_bytes = crate::inbound::transport::reality::base64_url_decode(
                &reality.private_key,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "{protocol} inbound '{}': tls.reality.private_key 无效: {e}",
                    self.tag
                )
            })?;
            anyhow::ensure!(
                priv_bytes.len() == 32,
                "{protocol} inbound '{}': tls.reality.private_key 须为 32 字节",
                self.tag
            );
            for sid_hex in &reality.short_id {
                let sid = hex::decode(sid_hex.trim())
                    .map_err(|e| anyhow::anyhow!("{protocol} inbound '{}': tls.reality.short_id '{sid_hex}' 非法 hex: {e}", self.tag))?;
                anyhow::ensure!(
                    sid.len() <= 8,
                    "{protocol} inbound '{}': tls.reality.short_id '{sid_hex}' 超过 8 字节",
                    self.tag
                );
            }
        }
        if let Some(InboundTransportConfig::Ws(ws)) = &self.transport {
            anyhow::ensure!(
                !ws.path.is_empty(),
                "{protocol} inbound '{}': transport.ws.path must not be empty",
                self.tag
            );
        }
        Ok(())
    }
}

pub type VlessInboundConfig = ProxyInboundConfig;
pub type VmessInboundConfig = ProxyInboundConfig;
pub type TrojanInboundConfig = ProxyInboundConfig;

// ── Shadowsocks（sing-box 格式，SS2022）───────────────────────────────────────
//
// ```json
// {
//   "type": "shadowsocks", "tag": "ss-in",
//   "listen": "::", "listen_port": 8388,
//   "method": "2022-blake3-aes-256-gcm",
//   "password": "base64-key",
//   "users": [{ "name": "u1", "password": "base64-key" }]
// }
// ```
// 单用户用 `password`，多用户用 `users`（此时忽略顶层 password）。

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// 加密方法（仅支持 SS2022：2022-blake3-aes-128-gcm /
    /// 2022-blake3-aes-256-gcm / 2022-blake3-chacha20-poly1305）
    pub method: String,

    /// 单用户密码（Base64 密钥）
    #[serde(default)]
    pub password: Option<String>,

    /// 多用户列表
    #[serde(default)]
    pub users: Vec<SsUser>,

    /// 网络协议（默认 TCP+UDP）
    #[serde(default)]
    pub network: Network,

    /// 传输层（tcp/ws/grpc/xhttp）。注：sing-box 原生不支持 ss inbound 传输层，
    /// 此为 reflex 扩展（对齐自身 ss outbound 的 ws/grpc/xhttp 能力）。
    /// 仅影响 TCP；UDP 会话不受影响。
    #[serde(default)]
    pub transport: Option<InboundTransportConfig>,

    /// 外层 TLS/REALITY 加密（通常与 transport 搭配使用，如 ss-over-ws+TLS）
    #[serde(default)]
    pub tls: InboundTlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsUser {
    #[serde(default)]
    pub name: Option<String>,
    pub password: String,
}

impl ShadowsocksInboundConfig {
    /// 展开为 (name, password) 列表：优先 users，回退顶层 password。
    pub fn effective_users(&self) -> Vec<(String, String)> {
        if !self.users.is_empty() {
            return self
                .users
                .iter()
                .map(|u| {
                    (
                        u.name.clone().unwrap_or_else(|| "user".into()),
                        u.password.clone(),
                    )
                })
                .collect();
        }
        match &self.password {
            Some(p) => vec![("user".into(), p.clone())],
            None => vec![],
        }
    }
}

// ── NaiveProxy（HTTP/2 CONNECT + Basic Auth）─────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NaiveInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// Basic Auth 用户（username/password）
    #[serde(default)]
    pub users: Vec<AuthUser>,

    /// NaiveProxy 必须使用 TLS（H2）
    #[serde(default)]
    pub tls: InboundTlsConfig,

    /// 是否启用首 8 次读写的 padding（对等协商，默认关闭）
    #[serde(default)]
    pub padding: bool,
}

// ── AnyTLS ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnytlsInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// 用户列表（取 ProxyUser.password）
    #[serde(default)]
    pub users: Vec<ProxyUser>,

    /// AnyTLS 必须使用 TLS
    #[serde(default)]
    pub tls: InboundTlsConfig,

    /// 自定义 padding scheme（sing-box padding_scheme 字段，透传给协议层）
    #[serde(default)]
    pub padding_scheme: Option<String>,
}

// ── Hysteria2（QUIC）─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hysteria2InboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// 用户列表（取 ProxyUser.password； hysteria2 auth 为 password 列表）
    #[serde(default)]
    pub users: Vec<ProxyUser>,

    /// 上行带宽限制（Mbps，可省略表示 BBR 不限速）
    #[serde(default, rename = "up_mbps", alias = "up")]
    pub up_mbps: Option<u32>,

    /// 下行带宽限制（Mbps）
    #[serde(default, rename = "down_mbps", alias = "down")]
    pub down_mbps: Option<u32>,

    /// 忽略客户端带宽（true 时服务端始终 BBR）
    #[serde(default)]
    pub ignore_client_bandwidth: bool,

    /// Hysteria2 必须使用 TLS
    #[serde(default)]
    pub tls: InboundTlsConfig,
}

// ── TUIC（QUIC）──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// 用户列表（uuid + password）
    #[serde(default)]
    pub users: Vec<TuicUser>,

    /// 拥塞控制：cubic（默认）/ new_reno / bbr
    #[serde(default = "default_tuic_congestion_control")]
    pub congestion_control: String,

    /// 认证超时（秒，默认 3）
    #[serde(default = "default_tuic_auth_timeout")]
    pub auth_timeout: u64,

    /// 0-RTT 握手（默认 false）
    #[serde(default)]
    pub zero_rtt_handshake: bool,

    /// 心跳间隔（秒，默认 10）
    #[serde(default = "default_tuic_heartbeat")]
    pub heartbeat: u64,

    /// TUIC 必须使用 TLS
    #[serde(default)]
    pub tls: InboundTlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuicUser {
    #[serde(default)]
    pub name: Option<String>,
    pub uuid: String,
    pub password: String,
}

fn default_tuic_congestion_control() -> String {
    "cubic".into()
}
fn default_tuic_auth_timeout() -> u64 {
    3
}
fn default_tuic_heartbeat() -> u64 {
    10
}

// ── ShadowQuic（0-RTT QUIC + JLS）────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowQuicInboundConfig {
    pub tag: String,

    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// JLS 用户列表（username/password）
    #[serde(default)]
    pub users: Vec<AuthUser>,

    /// JLS 伪装上游（host:port，必须是真实 HTTPS 站点）
    #[serde(default)]
    pub jls_upstream: Option<String>,

    /// SNI 域名（必须与客户端 server_name 一致）
    #[serde(default)]
    pub server_name: Option<String>,

    /// 拥塞控制：bbr（默认）/ cubic / new-reno / brutal
    #[serde(default = "default_sq_congestion_control")]
    pub congestion_control: String,
}

fn default_sq_congestion_control() -> String {
    "bbr".into()
}

// ── WireGuard（服务端）────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardInboundConfig {
    pub tag: String,

    /// 监听地址（UDP）
    #[serde(default = "default_listen_dual")]
    pub listen: String,

    pub listen_port: u16,

    /// 本端私钥（Base64）
    pub private_key: String,

    /// 对端列表
    #[serde(default)]
    pub peers: Vec<WireGuardPeerInboundConfig>,

    /// 本端隧道地址（如 "10.0.0.1/24"），未配置则不为客户端分配地址
    #[serde(default)]
    pub address: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardPeerInboundConfig {
    /// 对端公钥（Base64）
    pub public_key: String,
    /// 预共享密钥（可选）
    #[serde(default)]
    pub pre_shared_key: Option<String>,
    /// 允许的客户端隧道地址（CIDR 或 IP）
    #[serde(default)]
    pub allowed_ips: Vec<String>,
}

fn default_listen_dual() -> String {
    "::".into()
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

    // ── 网关 / DNS 覆盖（对齐 sing-tun Inet4GatewayAddr 覆盖语义）──────────
    /// 覆盖 IPv4 网关/服务地址（NAT 目标 / listener 绑定 / DNS 推导的基准）。
    /// 留空则从第一个 IPv4 地址前缀推导（地址 +1，sing-tun NewSystem 语义）。
    #[serde(default)]
    pub inet4_gateway_address: Option<String>,

    /// 覆盖 IPv6 网关/服务地址。留空则从第一个 IPv6 地址前缀推导。
    #[serde(default)]
    pub inet6_gateway_address: Option<String>,

    /// **Windows**：覆盖下发到系统的 DNS 服务器列表（按地址族分别下发）。
    /// 留空则使用 TUN 网关地址（与 sing-tun Inet4DNSAddr 默认行为一致）。
    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// 从外部传入的 TUN 文件描述符（对齐 sing-box `file_descriptor`）。
    /// 主要用于 Android `VpnService.Builder.establish()` 返回的 fd。
    /// 设置后 reflex 直接接管该 fd（**接管所有权**），不再自行创建 TUN 设备，
    /// 也不执行地址/路由配置（由调用方负责）。仅 Unix 平台支持。
    #[serde(default)]
    pub file_descriptor: Option<i32>,

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

    // ── Linux auto_redirect (nftables TPROXY) ──────────────────────────────
    /// **Linux 专用**：自动配置 nftables TPROXY 规则重定向流量到 TUN。
    ///
    /// 启用后，reflex 会在 setup 阶段通过 `nft` 命令创建 nftables 表和链：
    /// - `mangle` 表的 `PREROUTING` 链：对入站 TCP/UDP 包打 input_mark
    /// - `mangle` 表的 `OUTPUT` 链：对 reflex 自身出站包打 output_mark（绕过 TPROXY）
    /// - `ip rule fwmark <input_mark> lookup <table>`：将打了 mark 的包路由到 TUN
    ///
    /// 适用于 TUN 无法捕获某些流量（如 Docker 容器流量）的场景。
    /// 对齐 sing-tun `auto_redirect` 功能。
    #[serde(default)]
    pub auto_redirect: bool,

    /// **Linux 专用**：auto_redirect 入站 fwmark 值。
    /// 默认 `0x2022`（与 iproute2_table_index 关联）。
    /// 此 mark 被打到入站包上，触发 `ip rule fwmark` 规则路由到 TUN 表。
    #[serde(default = "default_auto_redirect_input_mark")]
    pub auto_redirect_input_mark: u32,

    /// **Linux 专用**：auto_redirect 出站 fwmark 值。
    /// 默认 `0x3022`。reflex 自身出站 socket 设置此 mark，
    /// `nft OUTPUT` 链根据此 mark 跳过 TPROXY，避免路由循环。
    #[serde(default = "default_auto_redirect_output_mark")]
    pub auto_redirect_output_mark: u32,
}

fn default_auto_redirect_input_mark() -> u32 {
    0x2022
}

fn default_auto_redirect_output_mark() -> u32 {
    0x3022
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
