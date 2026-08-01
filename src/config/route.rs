use serde::{Deserialize, Serialize};

use crate::config::dns::DnsServerRef;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    /// 路由规则，顺序匹配，第一条命中生效
    #[serde(default)]
    pub rules: Vec<RouteRuleConfig>,

    /// 所有规则未命中时的默认出站 tag
    ///
    /// 缺省时为 `"direct"`——与未配置 outbounds 时自动补的 direct 出站自动关联，
    /// 实现"零配置即可启动"（仅 mixed 入站 + 直连出站）。
    #[serde(default = "default_route_final")]
    pub r#final: String,

    /// 规则集声明（local 或 remote）
    #[serde(default)]
    pub rule_set: Vec<RuleSetRef>,

    /// 是否对 DNS 响应中的 IP 也做路由（用于 fake-ip 或 IP 分流）
    #[serde(default)]
    pub resolve_dns: bool,

    /// 是否允许 IPv6 流量流经核心（默认 true）。
    ///
    /// - `true`：IPv6 正常处理，DNS 解析行为由 `dns.strategy` 控制。
    /// - `false`：完全屏蔽 IPv6，DNS 仅发 A 记录查询，`dns.strategy` 此时无效。
    #[serde(default = "default_true")]
    pub ipv6: bool,

    /// 自动检测并绑定默认出口网络接口（仅 Linux / macOS / Windows 支持）。
    ///
    /// 启用后，direct 出站会自动绑定到系统路由表中优先级最高的物理接口，
    /// 解决多网卡/VPN 环境下直连流量走错接口的问题。
    /// 与 sing-box `route.auto_detect_interface` 字段对齐。
    ///
    /// 典型用法：
    /// ```json
    /// "route": { "auto_detect_interface": true, "final": "🚀 节点选择" }
    /// ```
    #[serde(default)]
    pub auto_detect_interface: bool,

    /// 默认出口网络接口名称（覆盖自动检测结果）。
    ///
    /// 与 sing-box `route.default_interface` 对齐。
    /// 填写后强制所有 direct 连接绑定到该接口；与 `auto_detect_interface`
    /// 同时使用时本字段优先。
    #[serde(default)]
    pub default_interface: Option<String>,

    /// 默认路由标记（Linux fwmark，仅 Linux 支持）。
    ///
    /// 与 sing-box `route.default_mark` 对齐。
    /// 用于配合 iptables/nftables 策略路由，避免代理流量形成回环。
    #[serde(default)]
    pub default_mark: Option<u32>,

    /// 全局 DNS 劫持快捷开关：设为 true 时，所有目标端口为 53 的 TCP/UDP 流量
    /// 直接交给内部 DNS 模块处理，跳过整个路由匹配过程。
    ///
    /// 等价于在规则列表最前面加一条：
    /// ```json
    /// { "port": [53], "hijack_dns": true }
    /// ```
    /// 但更简洁，且省去路由表查找开销。典型用法（TUN 入站接管系统 DNS）：
    /// ```json
    /// { "route": { "hijack_dns": true, "final": "proxy" } }
    /// ```
    ///
    /// 注意：
    /// - 仅对目标端口 53 生效；DoH/DoT（853）等不会被劫持。
    /// - 与规则级 `hijack_dns: true` 共存时，全局开关优先（端口 53 流量不会
    ///   走规则匹配）。
    /// - 不影响 FakeIP 反查（仍然在路由前执行）。
    #[serde(default)]
    pub hijack_dns: bool,
}

// ── Rule ─────────────────────────────────────────────────────────────────────

/// 一条路由规则，所有非空条件之间是 AND 语义，
/// 同一条件内多个值是 OR 语义。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RouteRuleConfig {
    // ── 来源条件 ──────────────────────────────────────────────
    /// 来自指定入站 tag。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub inbound: Vec<String>,

    /// 网络类型过滤
    #[serde(default)]
    pub network: Option<NetworkFilter>,

    /// 来源 IP CIDR（OR），匹配连接的源地址。
    ///
    /// 与 sing-box `source_ip_cidr` 字段对齐。
    /// 支持 IPv4 和 IPv6 CIDR，例如 `["192.168.0.0/16", "10.0.0.0/8"]`。
    /// 也支持单字符串形式：`"source_ip_cidr": "192.168.0.0/16"`。
    ///
    /// 典型用法：限制只有局域网来源的流量走直连：
    /// ```json
    /// { "source_ip_cidr": ["192.168.0.0/16"], "outbound": "direct" }
    /// ```
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub source_ip_cidr: Vec<String>,

    // ── 目标条件 ──────────────────────────────────────────────
    /// 命中的 ruleset tag（OR），同时支持域名和 IP 规则集。
    /// 配置形式支持单字符串或数组：`"ruleset": "geosite-cn"` 或
    /// `"ruleset": ["geosite-cn", "geoip-cn"]`。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub ruleset: Vec<String>,

    /// 内联精确域名（OR）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub domain: Vec<String>,

    /// 内联域名后缀（OR）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub domain_suffix: Vec<String>,

    /// 内联域名关键词（OR）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub domain_keyword: Vec<String>,

    /// 内联域名正则表达式（OR）。
    ///
    /// 与 sing-box `domain_regex` 字段对齐。匹配目标域名（大小写不敏感）。
    /// 每个元素是一个 Rust/Go 兼容的正则表达式。支持单字符串或数组形式。
    ///
    /// 示例：匹配所有 Google 相关域名：
    /// ```json
    /// { "domain_regex": ["^.*\\.google\\.com$", "^.*\\.googleapis\\.com$"], "outbound": "proxy" }
    /// ```
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub domain_regex: Vec<String>,

    /// 内联 IP CIDR（OR），支持 v4 和 v6。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub ip_cidr: Vec<String>,

    /// 目标端口过滤（OR），支持单端口和范围。
    /// 单值形式：`"port": 443` 或 `"port": "8000-9000"`；
    /// 数组形式：`"port": [80, 443, "8000-9000"]`。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub port: Vec<PortFilter>,

    /// 目标端口范围（备用写法，与 port 字段合并处理）。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub port_range: Vec<String>,

    // ── 进程匹配 ─────────────────────────────────────────────────────────
    /// 按进程名匹配（OR 语义）。仅在 Linux 上支持，其他平台规则不生效。
    /// 支持单字符串或数组形式。
    ///
    /// 进程名来自 `/proc/<pid>/comm`（如 `"chrome"`、`"Telegram"`），
    /// 大小写敏感完整匹配。
    ///
    /// 典型用法（让 Telegram 走代理）：
    /// ```json
    /// { "process_name": ["Telegram"], "outbound": "proxy" }
    /// ```
    ///
    /// 注意：进程查找需要读取 `/proc`，开销较高，规则匹配会带 5 秒 LRU 缓存。
    /// 仅对 TUN/TProxy 入站有效（能拿到真实源地址），SOCKS5/HTTP 入站拿到的
    /// 是客户端 socket 地址，可能匹配不到进程。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub process_name: Vec<String>,

    /// 按进程可执行文件路径匹配（OR 语义）。仅在 Linux 上支持。
    /// 支持单字符串或数组形式。
    ///
    /// 路径来自 `/proc/<pid>/exe`（如 `"/usr/bin/telegram-desktop"`），
    /// 大小写敏感的子串包含匹配（包含即命中，对齐 sing-box `process_path`）。
    ///
    /// 典型用法：
    /// ```json
    /// { "process_path": ["/usr/bin/telegram-desktop"], "outbound": "proxy" }
    /// ```
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub process_path: Vec<String>,

    // ── 规则反转 ──────────────────────────────────────────────
    /// 反转所有匹配条件的结果（逻辑 NOT）。
    ///
    /// 与 sing-box `invert` 字段对齐。
    /// 设为 true 时，规则在所有其他条件**均不命中**时才触发。
    ///
    /// 示例：所有非国内流量走代理：
    /// ```json
    /// { "ruleset": ["geosite-cn"], "invert": true, "outbound": "proxy" }
    /// ```
    /// 等价于：未命中 geosite-cn 的流量 → proxy。
    ///
    /// 注意：`invert` 对 `sniff`、`resolve`、`hijack_dns` 等动作类字段无效，
    /// 只反转地址/协议/端口等匹配条件的聚合结果。
    #[serde(default)]
    pub invert: bool,

    // ── Clash API 模式 ────────────────────────────────────────────────────
    /// 仅当 Clash API 当前模式（`PATCH /configs` 设置的 `mode`）等于该值时才
    /// 命中本规则，大小写不敏感。与 sing-box `clash_mode` 规则条件对齐。
    ///
    /// 和 sing-box 一样，"global"/"direct" 这些模式名本身没有任何硬编码行为——
    /// 是否在某个模式下强制走某个 outbound，完全由你自己写规则决定：
    /// ```json
    /// { "clash_mode": "global", "outbound": "我的全局选择器" }
    /// { "clash_mode": "direct", "outbound": "direct" }
    /// ```
    /// 把这两条放在规则列表最前面，就能让 Dashboard 上的模式切换按钮真正生效。
    ///
    /// 该条件作为硬性前置过滤（类似 `inbound`/`network`/`protocol`），不受
    /// `invert` 影响。
    #[serde(default)]
    pub clash_mode: Option<String>,

    // ── 嗅探 ─────────────────────────────────────────────────
    /// 命中本规则时先对 TCP 流做协议嗅探，
    /// 用嗅探结果更新目标域名后重新路由。
    /// 通常配合「无条件 catch-all」规则置于规则链最前面使用。
    #[serde(default)]
    pub sniff: bool,

    /// 嗅探超时（毫秒），0 表示使用默认值（300 ms）
    #[serde(default)]
    pub sniff_timeout_ms: u64,

    /// 指定启用的嗅探协议列表，如 `["tls", "http", "quic", "ssh", "bittorrent"]`。
    /// 省略或为空时使用默认列表 `["tls", "http", "quic"]`（覆盖日常上网场景）。
    /// 需要其他协议（如 WebRTC 视频通话、SSH、BT）时按需显式配置。
    /// 支持的值：`"tls"`, `"http"`, `"quic"`, `"ssh"`, `"bittorrent"`（或 `"bt"`），
    /// `"dns"`, `"dtls"`, `"stun"`, `"ntp"`, `"rdp"`。
    /// 支持单字符串或数组形式：`"sniff_type": "tls"` 或 `"sniff_type": ["tls", "http"]`。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub sniff_type: Vec<String>,

    /// 嗅探到域名后是否覆盖目标地址（默认 false）。
    /// 设为 true 时将连接目标地址替换为嗅探到的域名（适用于 FakeIP 模式）；
    /// 设为 false 时仅将嗅探结果用于路由规则匹配，目标地址保持不变。
    #[serde(default)]
    pub sniff_override_destination: bool,

    /// 嗅探白名单：仅对这些域名（精确或后缀匹配，大小写不敏感）做嗅探。
    /// 留空时不生效（不限制）；非空时仅匹配到的目标域名会被嗅探。
    /// 与 sing-box `route.rule_set` 默认 sniff `force_domain` 字段对齐。
    /// 支持单字符串或数组形式。
    ///
    /// 典型用法：只对 `*.cn` 域名做嗅探
    /// ```json
    /// { "sniff": true, "sniff_force_domain": [".cn"], "outbound": "proxy" }
    /// ```
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub sniff_force_domain: Vec<String>,

    /// 嗅探黑名单：跳过对这些域名的嗅探（精确或后缀匹配，大小写不敏感）。
    /// 命中时直接跳过嗅探步骤，按原始目标进入下一阶段路由。
    /// 与 sing-box `route.rule_set` 默认 sniff `skip_domain` 字段对齐。
    /// 支持单字符串或数组形式。
    ///
    /// 典型用法：不对内网域名做嗅探（避免私有 TLD 触发误判）
    /// ```json
    /// { "sniff": true, "sniff_skip_domain": [".local", ".lan"], "outbound": "proxy" }
    /// ```
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub sniff_skip_domain: Vec<String>,

    /// 嗅探源 IP 黑名单：跳过来自这些 CIDR 的连接/包的嗅探。
    /// 支持 IPv4 和 IPv6 CIDR，例如 `["127.0.0.0/8", "fe80::/10"]`。
    /// 与 sing-box `route.rule_set` 默认 sniff `skip_src_address` 字段对齐。
    /// 支持单字符串或数组形式。
    ///
    /// 典型用法：不对来自本机/局域网的流量做嗅探
    /// ```json
    /// { "sniff": true, "sniff_skip_src_address": ["127.0.0.0/8", "192.168.0.0/16"], "outbound": "proxy" }
    /// ```
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub sniff_skip_src_address: Vec<String>,

    /// 嗅探到的应用层协议过滤（OR），如 `["dns"]`。
    /// 匹配由 DNS inbound 进入或嗅探识别出的协议名称。
    /// 目前支持的值：`"dns"`。支持单字符串或数组形式。
    #[serde(default, deserialize_with = "super::deserialize_one_or_many")]
    pub protocol: Vec<String>,

    // ── DNS 解析（用于域名→IP 后继续匹配后续 IP 规则）────────────
    /// 将本规则的动作设为 resolve：遇到此规则时，若目标是域名，
    /// 先用内部 DNS 将其解析为 IP，然后继续向后匹配（跳过所有 resolve 规则）。
    ///
    /// 典型用法：放在域名规则集与 IP 规则集之间，使域名流量在未被前面域名
    /// 规则命中时先解析成 IP，再让后续 IP 规则集继续命中。
    ///
    /// ```json
    /// { "resolve": true }
    /// { "resolve": true, "server": "dns-domestic" }
    /// ```
    ///
    /// `server`：可选，指定用于解析的 DNS server tag（必须在 `dns.servers` 中声明）。
    /// 不填则使用默认 DNS 服务器。
    ///
    /// 设为 true 时 `outbound` 字段被忽略。
    #[serde(default)]
    pub resolve: bool,

    /// 解析时使用的 DNS server tag（s）（选填，仅在 `resolve = true` 时生效）。
    ///
    /// 支持单字符串（向后兼容）或数组形式（mihomo 风格并发）：
    /// - `{ "resolve": true, "server": "dns-domestic" }`
    /// - `{ "resolve": true, "server": ["dns-domestic", "dns-foreign"] }`
    ///
    /// 数组形式时解析器同时向所有上游发起查询，首个成功响应即返回。
    #[serde(default, rename = "server")]
    pub resolve_server: Option<DnsServerRef>,

    // ── 私有 IP 快捷方式 ──────────────────────────────────────
    /// 目标 IP 属于私有/保留地址时命中，并自动直连（无需填写 `outbound`）。
    ///
    /// 覆盖范围：
    /// - `127.0.0.0/8`、`::1/128`（回环）
    /// - `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`（RFC 1918）
    /// - `169.254.0.0/16`、`fe80::/10`（链路本地）
    /// - `fc00::/7`（IPv6 ULA）
    /// - `100.64.0.0/10`（共享地址空间，RFC 6598）
    /// - `0.0.0.0/8`（本机网络）
    ///
    /// 典型用法：
    /// ```json
    /// { "private_ip": true }
    /// ```
    /// 等价于手动列出所有私有 `ip_cidr` + `"outbound": "direct"`，但更简洁。
    /// `outbound` 字段在此规则中被忽略，动作固定为直连。
    #[serde(default)]
    pub private_ip: bool,

    // ── DNS 劫持 ──────────────────────────────────────────────
    /// 将本规则的动作设为 hijack-dns（等价于 sing-box 的 `"action": "hijack-dns"`）。
    ///
    /// **必须**配合至少一个匹配条件（`inbound`、`protocol`、`network`、端口等）
    /// 一起使用，否则配置加载时报错。
    ///
    /// 典型用法：
    /// - `{"hijack_dns": true, "protocol": ["dns"]}` —— 劫持所有嗅探为 DNS 协议的流量
    /// - `{"hijack_dns": true, "inbound": ["dns-in"]}` —— 劫持来自 dns-in 入站的流量
    ///
    /// 设为 true 时 `outbound` 字段被忽略，action 固定为交给 DNS 模块处理。
    #[serde(default)]
    pub hijack_dns: bool,

    // ── 动作 ─────────────────────────────────────────────────
    /// 目标 outbound tag，特殊值 "dns-out" 表示交给 DNS 模块。
    /// 当 `sniff = true` 或 `hijack_dns = true` 时该字段可留空。
    #[serde(default)]
    pub outbound: String,

    // ── 动作精细化选项（对齐 sing-box route action 的扩展字段）──────────
    /// 命中后改写连接的目标地址（IP 或域名），原始目标仅用于规则匹配，
    /// 不影响后续转发。对齐 sing-box `override_address`。
    ///
    /// 典型用法：把某个域名/IP 重定向到局域网内的另一台机器：
    /// ```json
    /// { "domain": "printer.local", "override_address": "192.168.1.50", "outbound": "direct" }
    /// ```
    /// 注意：会在 `sniff`/`resolve` 之后、最终建立连接之前生效；多条规则都设置
    /// 该字段时，以最终命中（决定 outbound）的那条规则为准。
    #[serde(default)]
    pub override_address: Option<String>,

    /// 命中后改写连接的目标端口。对齐 sing-box `override_port`。
    /// 可与 `override_address` 配合使用，也可单独使用（只改端口不改地址）。
    #[serde(default)]
    pub override_port: Option<u16>,

    /// 命中后覆盖该连接的 UDP 会话空闲超时（秒）。对齐 sing-box `udp_timeout`。
    /// 仅对 UDP 流量生效，未设置时使用全局默认值。
    ///
    /// 典型用法：游戏/直播等需要长连接保活的 UDP 流量适当调大超时：
    /// ```json
    /// { "domain_suffix": [".game.example.com"], "network": "udp", "udp_timeout": 300, "outbound": "direct" }
    /// ```
    #[serde(default)]
    pub udp_timeout: Option<u64>,
}

impl RouteRuleConfig {
    /// 是否有任何匹配条件（全空的规则无意义）
    pub fn has_conditions(&self) -> bool {
        !self.inbound.is_empty()
            || self.network.is_some()
            || !self.protocol.is_empty()
            || !self.ruleset.is_empty()
            || !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
            || !self.ip_cidr.is_empty()
            || !self.source_ip_cidr.is_empty()
            || !self.port.is_empty()
            || !self.port_range.is_empty()
            || !self.process_name.is_empty()
            || !self.process_path.is_empty()
            || self.private_ip
            || self.clash_mode.is_some()
    }
}

// ── RuleSet 引用 ──────────────────────────────────────────────────────────────

/// 规则集来源类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetType {
    /// 本地文件，必须配合 `path` 字段使用
    Local,
    /// 远程 URL，必须配合 `url` 字段使用；可选填 `path` 作为本地缓存路径
    Remote,
}

/// 规则集文件格式，与 sing-box `format` 字段对齐。
///
/// | 值          | 含义                                                        |
/// |-------------|-------------------------------------------------------------|
/// | `"binary"`  | 预编译的 `.rrs` 二进制格式（默认）                          |
/// | `"source"`  | 文本或 sing-box JSON Source Rule Set，运行时自动编译        |
///
/// `"source"` 格式支持两种内容：
/// - sing-box JSON（`{"version":2,"rules":[...]}` 格式，`.json`/`.srs` 文件）
/// - Reflex 文本格式（每行 `key: value`，`.txt`/`.list` 文件）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSetFormat {
    /// 预编译二进制（`.rrs`），默认值
    #[default]
    Binary,
    /// 文本或 sing-box JSON Source Rule Set，启动时实时编译
    Source,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetRef {
    /// 在 rules 中引用的名字
    pub tag: String,

    /// 来源类型：`"local"` 或 `"remote"`
    pub r#type: RuleSetType,

    /// 规则集文件格式，与 sing-box `format` 字段对齐。
    /// - `"binary"`（默认）：预编译的 `.rrs` 二进制
    /// - `"source"`：sing-box JSON 或 Reflex 文本格式，运行时自动编译
    #[serde(default)]
    pub format: RuleSetFormat,

    /// 本地文件路径。
    /// - `type = "local"` 时**必填**，指定规则集文件位置。
    /// - `type = "remote"` 时**选填**，作为下载后的本地缓存路径；
    ///   不填则缓存到 cache_file（若未启用则仅驻留内存）。
    #[serde(default)]
    pub path: Option<String>,

    /// 远程规则集 URL（`type = "remote"` 时**必填**）。
    #[serde(default)]
    pub url: Option<String>,

    /// 用于下载远程规则集的出站 tag（选填）。
    /// 填写时通过该出站下载，无法下载则报错；不填则直连下载。
    #[serde(default)]
    pub download_detour: Option<String>,

    /// 定时更新间隔（仅 `type = "remote"` 有效），与 sing-box `update_interval` 对齐。
    ///
    /// 格式同 provider 的 `update_interval`：`"1h"`、`"30m"`、`"1d"` 等。
    /// 不填则不自动更新（只在启动时下载一次）。
    #[serde(default)]
    pub update_interval: Option<String>,
}

// ── 辅助类型 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFilter {
    Tcp,
    Udp,
}

/// 端口过滤：可以是数字或 "start-end" 字符串，用自定义反序列化处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortFilter(pub u16, pub u16); // (start, end)，单端口则 start == end

impl PortFilter {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.0 && port <= self.1
    }
}

impl<'de> Deserialize<'de> for PortFilter {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = PortFilter;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a port number or a range string like \"8000-9000\"")
            }
            // JSON 数字
            fn visit_u64<E: Error>(self, v: u64) -> Result<Self::Value, E> {
                if v > 65535 {
                    return Err(E::custom(format!("port {v} out of range")));
                }
                Ok(PortFilter(v as u16, v as u16))
            }
            // JSON 字符串 "8000-9000"
            fn visit_str<E: Error>(self, v: &str) -> Result<Self::Value, E> {
                if let Some((s, e)) = v.split_once('-') {
                    let start: u16 = s.trim().parse().map_err(E::custom)?;
                    let end: u16 = e.trim().parse().map_err(E::custom)?;
                    if start > end {
                        return Err(E::custom(format!("invalid range: {v}")));
                    }
                    Ok(PortFilter(start, end))
                } else {
                    let p: u16 = v.trim().parse().map_err(E::custom)?;
                    Ok(PortFilter(p, p))
                }
            }
        }
        de.deserialize_any(Visitor)
    }
}

impl Serialize for PortFilter {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if self.0 == self.1 {
            s.serialize_u16(self.0)
        } else {
            s.serialize_str(&format!("{}-{}", self.0, self.1))
        }
    }
}

fn default_true() -> bool {
    true
}

/// `route.final` 的默认值：`"direct"`。
///
/// 与 OutboundManager 自动补的 direct 出站自动关联，实现零配置启动。
fn default_route_final() -> String {
    "direct".to_string()
}

impl Default for RouteConfig {
    fn default() -> Self {
        RouteConfig {
            rules: Vec::new(),
            r#final: default_route_final(),
            rule_set: Vec::new(),
            resolve_dns: false,
            ipv6: default_true(),
            auto_detect_interface: false,
            default_interface: None,
            default_mark: None,
            hijack_dns: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_route_config() {
        let v = json!({
            "rules": [
                {
                    "inbound": ["dns-in"],
                    "outbound": "dns-out"
                },
                {
                    "ruleset": ["geoip-cn", "geosite-cn"],
                    "outbound": "direct"
                },
                {
                    "network": "udp",
                    "port": [53],
                    "outbound": "dns-out"
                },
                {
                    "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
                    "outbound": "direct"
                },
                {
                    "domain_suffix": [".cn"],
                    "port": [80, 443, "8000-9000"],
                    "outbound": "direct"
                }
            ],
            "final": "proxy",
            "rule_set": [
                { "tag": "geosite-cn", "type": "local", "path": "/etc/proxy/rules/geosite-cn.rrs" },
                { "tag": "geoip-cn",   "type": "local", "path": "/etc/proxy/rules/geoip-cn.rrs"   }
            ]
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules.len(), 5);
        assert_eq!(route.r#final, "proxy");
        assert_eq!(route.rule_set.len(), 2);
    }

    #[test]
    fn parse_domain_regex() {
        let v = json!({
            "rules": [
                {
                    "domain_regex": ["^.*\\.google\\.com$", "^.*\\.googleapis\\.com$"],
                    "outbound": "proxy"
                }
            ],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].domain_regex.len(), 2);
        assert_eq!(route.rules[0].domain_regex[0], "^.*\\.google\\.com$");
    }

    #[test]
    fn parse_source_ip_cidr() {
        let v = json!({
            "rules": [
                {
                    "source_ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
                    "outbound": "direct"
                }
            ],
            "final": "proxy"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].source_ip_cidr.len(), 2);
    }

    #[test]
    fn parse_invert() {
        let v = json!({
            "rules": [
                {
                    "ruleset": ["geosite-cn"],
                    "invert": true,
                    "outbound": "proxy"
                }
            ],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert!(route.rules[0].invert);
    }

    #[test]
    fn parse_string_or_array_fields() {
        // ruleset：单字符串 vs 数组 vs 缺省
        let v = json!({
            "rules": [{ "ruleset": "geosite-cn", "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].ruleset, vec!["geosite-cn"]);

        let v = json!({
            "rules": [{ "ruleset": ["geosite-cn", "geoip-cn"], "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].ruleset, vec!["geosite-cn", "geoip-cn"]);

        let v = json!({
            "rules": [{ "domain_suffix": [".cn"], "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert!(route.rules[0].ruleset.is_empty());

        // domain / domain_suffix / domain_keyword：单字符串形式
        let v = json!({
            "rules": [{
                "domain": "example.com",
                "domain_suffix": ".cn",
                "domain_keyword": "google",
                "domain_regex": "^.*\\.google\\.com$",
                "outbound": "direct"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].domain, vec!["example.com"]);
        assert_eq!(route.rules[0].domain_suffix, vec![".cn"]);
        assert_eq!(route.rules[0].domain_keyword, vec!["google"]);
        assert_eq!(route.rules[0].domain_regex, vec!["^.*\\.google\\.com$"]);

        // ip_cidr / source_ip_cidr：单字符串形式
        let v = json!({
            "rules": [{
                "ip_cidr": "192.168.0.0/16",
                "source_ip_cidr": "10.0.0.0/8",
                "outbound": "direct"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].ip_cidr, vec!["192.168.0.0/16"]);
        assert_eq!(route.rules[0].source_ip_cidr, vec!["10.0.0.0/8"]);

        // port：单值 u16 / 单值字符串范围 / 数组
        let v = json!({
            "rules": [{ "port": 443, "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].port, vec![PortFilter(443, 443)]);

        let v = json!({
            "rules": [{ "port": "8000-9000", "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].port, vec![PortFilter(8000, 9000)]);

        let v = json!({
            "rules": [{ "port": [80, 443, "8000-9000"], "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(
            route.rules[0].port,
            vec![
                PortFilter(80, 80),
                PortFilter(443, 443),
                PortFilter(8000, 9000)
            ]
        );

        // port_range：单字符串 vs 数组
        let v = json!({
            "rules": [{ "port_range": "8000-9000", "outbound": "direct" }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].port_range, vec!["8000-9000"]);

        // inbound / process_name / process_path：单字符串形式
        let v = json!({
            "rules": [{
                "inbound": "tun-in",
                "process_name": "Telegram",
                "process_path": "/usr/bin/telegram-desktop",
                "outbound": "proxy"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].inbound, vec!["tun-in"]);
        assert_eq!(route.rules[0].process_name, vec!["Telegram"]);
        assert_eq!(
            route.rules[0].process_path,
            vec!["/usr/bin/telegram-desktop"]
        );

        // sniff 相关字段：单字符串形式
        let v = json!({
            "rules": [{
                "sniff": true,
                "sniff_type": "tls",
                "sniff_force_domain": ".cn",
                "sniff_skip_domain": ".local",
                "sniff_skip_src_address": "127.0.0.0/8",
                "protocol": "dns",
                "outbound": "proxy"
            }],
            "final": "direct"
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rules[0].sniff_type, vec!["tls"]);
        assert_eq!(route.rules[0].sniff_force_domain, vec![".cn"]);
        assert_eq!(route.rules[0].sniff_skip_domain, vec![".local"]);
        assert_eq!(route.rules[0].sniff_skip_src_address, vec!["127.0.0.0/8"]);
        assert_eq!(route.rules[0].protocol, vec!["dns"]);
    }

    #[test]
    fn parse_auto_detect_interface() {
        let v = json!({
            "rules": [],
            "final": "proxy",
            "auto_detect_interface": true,
            "default_interface": "eth0",
            "default_mark": 100
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert!(route.auto_detect_interface);
        assert_eq!(route.default_interface.as_deref(), Some("eth0"));
        assert_eq!(route.default_mark, Some(100));
    }

    #[test]
    fn has_conditions_with_new_fields() {
        let base = RouteRuleConfig::default();

        let with_regex = RouteRuleConfig {
            domain_regex: vec![".*\\.google\\.com".into()],
            ..base.clone()
        };
        assert!(with_regex.has_conditions());

        let with_src_cidr = RouteRuleConfig {
            source_ip_cidr: vec!["192.168.0.0/16".into()],
            ..base.clone()
        };
        assert!(with_src_cidr.has_conditions());

        // invert 单独不算条件
        let invert_only = RouteRuleConfig {
            invert: true,
            ..base.clone()
        };
        assert!(!invert_only.has_conditions());
    }

    #[test]
    fn parse_ruleset_format_and_update_interval() {
        let v = json!({
            "rules": [],
            "final": "direct",
            "rule_set": [
                // binary（默认，省略 format 字段）
                {
                    "tag": "geosite-cn",
                    "type": "local",
                    "path": "/tmp/geosite-cn.rrs"
                },
                // source 格式 + update_interval
                {
                    "tag": "geosite-ads",
                    "type": "remote",
                    "format": "source",
                    "url": "https://example.com/geosite-ads.json",
                    "path": "/tmp/geosite-ads.json",
                    "update_interval": "24h"
                },
                // source 格式本地文件
                {
                    "tag": "custom-list",
                    "type": "local",
                    "format": "source",
                    "path": "/etc/reflex/custom.txt"
                }
            ]
        });
        let route: RouteConfig = serde_json::from_value(v).unwrap();
        assert_eq!(route.rule_set.len(), 3);

        // 默认 binary
        assert_eq!(route.rule_set[0].format, RuleSetFormat::Binary);
        assert!(route.rule_set[0].update_interval.is_none());

        // source + update_interval
        assert_eq!(route.rule_set[1].format, RuleSetFormat::Source);
        assert_eq!(route.rule_set[1].update_interval.as_deref(), Some("24h"));
        assert_eq!(
            route.rule_set[1].url.as_deref(),
            Some("https://example.com/geosite-ads.json")
        );

        // source 本地
        assert_eq!(route.rule_set[2].format, RuleSetFormat::Source);
        assert_eq!(route.rule_set[2].r#type, RuleSetType::Local);
    }

    #[test]
    fn port_filter_number() {
        let pf: PortFilter = serde_json::from_value(json!(443)).unwrap();
        assert_eq!(pf, PortFilter(443, 443));
        assert!(pf.contains(443));
        assert!(!pf.contains(80));
    }

    #[test]
    fn port_filter_range_str() {
        let pf: PortFilter = serde_json::from_value(json!("8000-9000")).unwrap();
        assert_eq!(pf, PortFilter(8000, 9000));
        assert!(pf.contains(8000));
        assert!(pf.contains(8500));
        assert!(pf.contains(9000));
        assert!(!pf.contains(7999));
    }

    #[test]
    fn port_filter_invalid_range() {
        let r: Result<PortFilter, _> = serde_json::from_value(json!("9000-8000"));
        assert!(r.is_err());
    }

    #[test]
    fn rule_has_conditions() {
        let empty = RouteRuleConfig {
            inbound: vec![],
            network: None,
            protocol: vec![],
            ruleset: vec![],
            domain: vec![],
            domain_suffix: vec![],
            domain_keyword: vec![],
            domain_regex: vec![],
            ip_cidr: vec![],
            source_ip_cidr: vec![],
            port: vec![],
            port_range: vec![],
            sniff: false,
            sniff_timeout_ms: 0,
            sniff_type: vec![],
            sniff_override_destination: false,
            resolve: false,
            resolve_server: None,
            private_ip: false,
            hijack_dns: false,
            invert: false,
            outbound: "direct".into(),
            ..Default::default()
        };
        assert!(!empty.has_conditions());

        // hijack_dns 单独存在不算条件（会在 router 层报错）
        let hijack_only = RouteRuleConfig {
            hijack_dns: true,
            ..empty.clone()
        };
        assert!(!hijack_only.has_conditions());

        // private_ip=true 本身就是条件
        let with_private_ip = RouteRuleConfig {
            private_ip: true,
            ..empty.clone()
        };
        assert!(with_private_ip.has_conditions());

        let with_ruleset = RouteRuleConfig {
            ruleset: vec!["geosite-cn".into()],
            ..empty.clone()
        };
        assert!(with_ruleset.has_conditions());

        let with_protocol = RouteRuleConfig {
            protocol: vec!["dns".into()],
            ..empty
        };
        assert!(with_protocol.has_conditions());
    }

    #[test]
    fn port_filter_serialize() {
        let single = PortFilter(443, 443);
        assert_eq!(serde_json::to_string(&single).unwrap(), "443");

        let range = PortFilter(8000, 9000);
        assert_eq!(serde_json::to_string(&range).unwrap(), "\"8000-9000\"");
    }
}
