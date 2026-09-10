use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::timeout;
use tracing::{debug, warn};

use super::hosts::HostsFile;
use super::util::tcp_framed_exchange;
use crate::dns::rcode::question_section_end;
use crate::dns::{make_noerror_empty, make_nxdomain};
#[cfg(any(target_os = "windows", target_os = "macos"))]
use crate::outbound::common::interface_finder;

/// resolv.conf 缓存有效期（对齐 sing-box `resolv.go` 的 5 秒节流）。
const RESOLV_CACHE_TTL: Duration = Duration::from_secs(5);

/// 默认 resolv.conf 路径。
fn default_resolv_conf_path() -> PathBuf {
    if cfg!(windows) {
        // Windows 没有标准 resolv.conf，返回一个不存在的路径让解析失败回退到默认 NS
        PathBuf::from("C:\\Windows\\System32\\Drivers\\etc\\resolv.conf")
    } else {
        PathBuf::from("/etc/resolv.conf")
    }
}

/// resolv.conf 解析结果（对齐 sing-box `dnsConfig`）。
#[derive(Debug, Clone)]
struct ResolvConfig {
    /// DNS 服务器列表（带端口，如 "1.2.3.4:53"）
    servers: Vec<SocketAddr>,
    /// search 域名列表（已 FQDN 化，末尾带 `.`）
    search: Vec<String>,
    /// ndots 阈值（域名中点数 >= ndots 时优先绝对名查询）
    ndots: u32,
    /// 单次查询超时
    timeout: Duration,
    /// 每个服务器重试次数
    attempts: u32,
    /// 是否轮询服务器（rotate）
    rotate: bool,
    /// 是否强制 TCP
    use_tcp: bool,
    /// 上次读取时的 mtime（用于热加载检测）
    mtime: Option<SystemTime>,
}

impl Default for ResolvConfig {
    fn default() -> Self {
        Self {
            servers: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53)],
            search: vec![],
            ndots: 1,
            timeout: Duration::from_secs(5),
            attempts: 2,
            rotate: false,
            use_tcp: false,
            mtime: None,
        }
    }
}

/// 解析 resolv.conf 内容（对齐 sing-box `resolv_unix.go:17-140`）。
///
/// 支持的指令：
/// - `nameserver <ip>`：DNS 服务器（最多保留 3 个，端口固定 53）
/// - `domain <name>`：单一 search（覆盖式）
/// - `search <name1> [name2 ...]`：search 列表
/// - `options`：`ndots:N` / `timeout:N` / `attempts:N` / `rotate` / `use-vc` / `single-request`
/// - `#` 或 `;` 开头为注释
///
/// 未读到 nameserver 时用默认 127.0.0.1:53。
fn parse_resolv_conf(content: &str) -> ResolvConfig {
    let mut cfg = ResolvConfig::default();
    cfg.servers.clear(); // 清空默认，未读到时再回退
    cfg.search.clear();

    let mut domain_set: Option<String> = None;
    let mut search_set: Vec<String> = vec![];

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let keyword = match fields.next() {
            Some(k) => k,
            None => continue,
        };
        match keyword {
            "nameserver" => {
                if cfg.servers.len() >= 3 {
                    continue; // sing-box 限制最多 3 个
                }
                if let Some(ip_str) = fields.next() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        cfg.servers.push(SocketAddr::new(ip, 53));
                    }
                }
            }
            "domain" => {
                if let Some(d) = fields.next() {
                    domain_set = Some(fqdn(d));
                }
            }
            "search" => {
                search_set.clear();
                for d in fields {
                    if d == "." {
                        continue; // 跳过根
                    }
                    search_set.push(fqdn(d));
                }
            }
            "options" => {
                for opt in fields {
                    apply_option(&mut cfg, opt);
                }
            }
            _ => {}
        }
    }

    // search 优先级：search 指令 > domain 指令 > 空
    if !search_set.is_empty() {
        cfg.search = search_set;
    } else if let Some(d) = domain_set {
        cfg.search = vec![d];
    }

    // 兜底：未读到 nameserver 用默认
    if cfg.servers.is_empty() {
        cfg.servers = ResolvConfig::default().servers;
    }

    cfg
}

/// 应用单个 options 子项（对齐 sing-box `resolv_unix.go:87-124`）。
fn apply_option(cfg: &mut ResolvConfig, opt: &str) {
    if let Some(v) = opt.strip_prefix("ndots:") {
        if let Ok(n) = v.parse::<u32>() {
            cfg.ndots = n.min(15);
        }
    } else if let Some(v) = opt.strip_prefix("timeout:") {
        if let Ok(n) = v.parse::<u64>() {
            cfg.timeout = Duration::from_secs(n.max(1));
        }
    } else if let Some(v) = opt.strip_prefix("attempts:") {
        if let Ok(n) = v.parse::<u32>() {
            cfg.attempts = n.max(1);
        }
    } else if opt == "rotate" {
        cfg.rotate = true;
    } else if matches!(opt, "use-vc" | "usevc" | "tcp") {
        cfg.use_tcp = true;
    }
    // single-request / trust-ad / edns0 / no-reload 等忽略（reflex 用并发模型，无意义）
}

/// 把域名 FQDN 化（末尾加 `.`，对齐 sing-box `dns.Fqdn`）。
fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// 生成候选查询名列表（对齐 sing-box `resolv.go:103-135` `nameList`）。
///
/// 规则：
/// - 已根化（末尾 `.`）的名字：直接返回 `[name]`
/// - 未根化：
///   - `has_ndots = dots(name) >= ndots`
///   - `has_ndots`：先尝试绝对名，再拼 search 后缀
///   - `!has_ndots`：先拼 search 后缀，最后绝对名兜底
fn name_list(cfg: &ResolvConfig, name: &str) -> Vec<String> {
    let l = name.len();
    if l > 254 {
        return vec![];
    }
    let rooted = name.ends_with('.');
    if rooted {
        return vec![name.to_string()];
    }
    let has_ndots = name.matches('.').count() as u32 >= cfg.ndots;
    let name_fq = format!("{name}.");
    let mut names: Vec<String> = Vec::with_capacity(1 + cfg.search.len());
    if has_ndots {
        names.push(name_fq.clone());
    }
    for suffix in &cfg.search {
        let fqdn = format!("{name_fq}{suffix}");
        if fqdn.len() <= 254 {
            names.push(fqdn);
        }
    }
    if !has_ndots {
        names.push(name_fq);
    }
    names
}

/// 计算域名中的点数（不含末尾根点）。
#[allow(dead_code)]
fn _dots(name: &str) -> u32 {
    name.trim_end_matches('.').matches('.').count() as u32
}

/// 带缓存的 resolv.conf 读取器（对齐 sing-box `resolverConfig.tryUpdate`）。
struct ResolvConfigCache {
    path: PathBuf,
    state: Mutex<ResolvCacheState>,
}

struct ResolvCacheState {
    config: ResolvConfig,
    last_check: Instant,
}

impl ResolvConfigCache {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(ResolvCacheState {
                config: ResolvConfig::default(),
                last_check: Instant::now() - RESOLV_CACHE_TTL * 2, // 强制首次读取
            }),
        }
    }

    /// 获取最新配置（5s 节流 + mtime 检测）。
    fn get(&self) -> ResolvConfig {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        // 5s 节流
        if now.duration_since(state.last_check) < RESOLV_CACHE_TTL {
            return state.config.clone();
        }
        state.last_check = now;

        // stat 检测 mtime
        let mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        // 仅当文件存在（mtime 可得）且未变化时跳过重读；文件不存在
        //（mtime=None，Windows 上 resolv.conf 必然不存在）时必须走下方
        // 重读/系统 DNS 枚举，否则永远停留在初值 127.0.0.1:53。
        if mtime.is_some() && mtime == state.config.mtime {
            return state.config.clone();
        }

        // 读取并解析
        let read_result = std::fs::read_to_string(&self.path);
        // mut 仅在 Windows 分支回填系统 DNS 时需要
        #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
        let mut new_cfg = match read_result {
            Ok(ref content) => {
                let mut c = parse_resolv_conf(content);
                c.mtime = mtime;
                c
            }
            // Windows：没有标准 resolv.conf，文件必然不存在。旧实现保留
            // 初值 127.0.0.1:53 —— 本机根本没人在 53 上监听，所有 local
            // 上游查询全部超时（TUN auto_route 下网络瘫痪的根因之一）。
            // 这里先返回空解析占位，随后用 GetAdaptersAddresses 枚举的
            // 系统 DNS（优先物理网卡，自动排除 TUN 劫持地址）回填。
            Err(_) if cfg!(windows) => parse_resolv_conf(""),
            // 非 Windows：读取失败，保留旧配置（graceful degradation）
            Err(_) => state.config.clone(),
        };
        #[cfg(target_os = "windows")]
        if read_result.is_err() {
            let servers = interface_finder::windows_iface::system_dns_servers();
            if !servers.is_empty() {
                tracing::debug!(
                    servers = ?servers,
                    "dns local: using system DNS servers (GetAdaptersAddresses)"
                );
                new_cfg.servers = servers
                    .into_iter()
                    .map(|ip| std::net::SocketAddr::new(ip, 53))
                    .collect();
            }
        }
        state.config = new_cfg.clone();
        new_cfg
    }
}

/// Local DNS 服务器（对齐 sing-box `local.Transport`）。
pub struct LocalUpstream {
    /// hosts 文件（A/AAAA 查询优先查此）
    hosts: HostsFile,
    /// resolv.conf 配置缓存
    resolv: ResolvConfigCache,
    /// 服务器轮询偏移（rotate 模式用）
    soffset: AsyncMutex<u32>,
}

impl Default for LocalUpstream {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalUpstream {
    /// 使用默认路径（/etc/hosts + /etc/resolv.conf）构造。
    pub fn new() -> Self {
        Self::with_paths(
            super::hosts::default_hosts_path(),
            default_resolv_conf_path(),
        )
    }

    /// 使用自定义 hosts / resolv.conf 路径构造（主要供测试用）。
    pub fn with_paths(hosts_path: PathBuf, resolv_path: PathBuf) -> Self {
        Self {
            hosts: HostsFile::new(hosts_path),
            resolv: ResolvConfigCache::new(resolv_path),
            soffset: AsyncMutex::new(0),
        }
    }

    /// 处理 DNS 查询（对齐 sing-box `local.go:82-94`）。
    pub async fn reply(&self, query: &[u8]) -> Bytes {
        let qtype = crate::dns::wire::extract_qtype(query);
        let qname = crate::dns::wire::extract_qname(query);

        let (qtype, qname) = match (qtype, qname) {
            (Some(t), Some(n)) => (t, n),
            _ => return make_nxdomain(query),
        };

        // 1. A/AAAA 优先查 hosts（对齐 sing-box local.go:87-91）
        if qtype == 1 || qtype == 28 {
            let addrs = self.hosts.lookup(&qname);
            if !addrs.is_empty() {
                let filtered: Vec<IpAddr> = match qtype {
                    1 => addrs.into_iter().filter(|a| a.is_ipv4()).collect(),
                    28 => addrs.into_iter().filter(|a| a.is_ipv6()).collect(),
                    _ => addrs,
                };
                if !filtered.is_empty() {
                    return build_ip_response(query, qtype, &filtered);
                }
                // hosts 命中但类型不匹配：返回空 NOERROR
                return make_noerror_empty(query);
            }
        }

        // 2. 未命中 hosts，走系统 DNS
        let cfg = self.resolv.get();
        if cfg.servers.is_empty() {
            warn!("local upstream: no nameserver configured");
            return make_nxdomain(query);
        }

        // 3. 生成候选名列表（search + ndots）
        let candidates = name_list(&cfg, &qname);
        if candidates.is_empty() {
            return make_nxdomain(query);
        }

        // 4. 依次尝试每个候选名（串行，对齐 sing-box exchangeSingleRequest）
        // 对齐 sing-box local_shared.go:28-39：A/AAAA 默认并发，但 reflex 简化为串行
        // （并发竞速收益在 local 场景有限，且会放大上游负载）
        let mut last_resp: Option<Bytes> = None;
        for cand in &candidates {
            // 用候选名重建查询
            let cand_query = rebuild_query_with_name(query, cand);
            match self.exchange_one(&cfg, &cand_query).await {
                Ok(resp) => {
                    // 检查是否 NXDOMAIN：若该候选名返回 NXDOMAIN，继续尝试下一个
                    if resp.len() >= 4 && (resp[3] & 0x0F) == 3 {
                        last_resp = Some(resp);
                        continue;
                    }
                    // 非 NXDOMAIN（NOERROR 或其他）：立即返回
                    return resp;
                }
                Err(e) => {
                    debug!(candidate=%cand, err=%e, "local upstream query failed");
                    last_resp = None;
                }
            }
        }
        last_resp.unwrap_or_else(|| make_nxdomain(query))
    }

    /// 向系统 DNS 服务器发送单次查询（对齐 sing-box `exchangeOne` + `exchangeUDP`/`exchangeTCP`）。
    ///
    /// 流程：
    /// - attempts × servers 双层重试（rotate 时偏移自增）
    /// - use_tcp 或 UDP TC bit → 降级 TCP
    async fn exchange_one(&self, cfg: &ResolvConfig, query: &[u8]) -> anyhow::Result<Bytes> {
        let n_servers = cfg.servers.len() as u32;
        let mut soffset = self.soffset.lock().await;
        let start_offset = if cfg.rotate {
            let s = *soffset;
            *soffset = (*soffset + 1) % n_servers.max(1);
            s
        } else {
            0
        };
        drop(soffset);

        let mut last_err: Option<anyhow::Error> = None;
        for _attempt in 0..cfg.attempts {
            for i in 0..n_servers {
                let server_idx = ((start_offset + i) % n_servers) as usize;
                let server = cfg.servers[server_idx];
                let query_bytes = Bytes::copy_from_slice(query);

                let result = if cfg.use_tcp {
                    self.query_tcp(server, query_bytes.clone()).await
                } else {
                    match self.query_udp(server, query_bytes.clone()).await {
                        Ok(resp) => {
                            // 检查 TC bit
                            if resp.len() >= 3 && (resp[2] & 0x02) != 0 {
                                debug!(server=%server, "local udp TC bit set, retrying over TCP");
                                self.query_tcp(server, query_bytes.clone()).await
                            } else {
                                Ok(resp)
                            }
                        }
                        Err(e) => Err(e),
                    }
                };

                match result {
                    Ok(resp) => return Ok(resp),
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }
            // attempt 之间无额外等待（sing-box 也无 backoff）
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("local upstream: all attempts exhausted")))
    }

    /// UDP 查询（对齐 sing-box `exchangeUDP`）。
    async fn query_udp(&self, server: SocketAddr, msg: Bytes) -> anyhow::Result<Bytes> {
        let socket = if server.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0").await?
        } else {
            UdpSocket::bind("[::]:0").await?
        };
        // TUN auto_route 接管默认路由后，未绑定网卡的 socket 的查询包会被
        // TUN 重新截获：Windows 默认不开转发，包进 TUN 后直接丢弃，
        // 表现为查询永远超时（对齐 sing-box：自身出站必须绑定出口网卡）。
        // 在首次收发前把 socket 钉到探测到的物理网卡上。
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawSocket;
            interface_finder::windows_iface::bind_socket_to_physical_interface(
                socket.as_raw_socket(),
                server.ip(),
            );
        }
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::AsRawFd;
            interface_finder::macos_iface::bind_socket_to_physical_interface(
                socket.as_raw_fd(),
                server.ip(),
            );
        }
        socket.connect(server).await?;
        socket.send(&msg).await?;
        let mut buf = vec![0u8; 4096]; // EDNS0 默认 4096
        let n = timeout(cfg_udp_timeout(), socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("local udp query timeout"))??;
        buf.truncate(n);
        anyhow::ensure!(n >= 12, "local udp response too short: {n}");
        Ok(Bytes::from(buf))
    }

    /// TCP 查询（对齐 sing-box `exchangeTCP`，2 字节长度前缀帧）。
    async fn query_tcp(&self, server: SocketAddr, msg: Bytes) -> anyhow::Result<Bytes> {
        // 用 connect_tcp_interface 在 connect 之前把 socket 绑定到物理网卡
        // （Windows IP_UNICAST_IF / macOS IP_BOUND_IF）：SYN 已按 TUN 默认路由
        // 发出后再事后绑定是无效的，TCP 必须在连接前绑定。
        let mut stream = crate::outbound::connect_tcp_interface(server).await?;
        // 复用 DoT 的 framed exchange 工具
        tcp_framed_exchange(&mut stream, msg).await
    }
}

/// 默认 UDP 查询超时（对齐 sing-box `resolv_unix.go:20` 默认 5s）。
fn cfg_udp_timeout() -> Duration {
    Duration::from_secs(5)
}

/// 构造 A/AAAA 响应（多 RR）——与 hosts.rs 的 build_ip_response 同逻辑，独立实现避免跨模块依赖。
fn build_ip_response(query: &[u8], qtype: u16, addrs: &[IpAddr]) -> Bytes {
    if query.len() < 12 {
        return make_noerror_empty(query);
    }
    const TTL: u32 = 600;
    let rdata_len: usize = if qtype == 1 { 4 } else { 16 };
    let ancount = addrs.len() as u16;

    // 只复制 Question section，不复制 Additional section（EDNS0 OPT）。
    // 详见 hosts.rs build_ip_response 的注释——同样的 bug 修复。
    let question_end = match question_section_end(query, 12) {
        Some(end) => end,
        None => return make_noerror_empty(query),
    };
    let question_bytes = &query[12..question_end];

    let mut resp = Vec::with_capacity(12 + question_bytes.len() + addrs.len() * (12 + rdata_len));
    resp.extend_from_slice(&query[..2]); // ID
    resp.extend_from_slice(&[0x85, 0x80]); // flags: QR+AA+RD, RA, RCODE=0
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(question_bytes); // 回显 Question
    for addr in addrs {
        resp.extend_from_slice(&[0xC0, 0x0C]); // name 指针
        resp.extend_from_slice(&qtype.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // class IN
        resp.extend_from_slice(&TTL.to_be_bytes());
        resp.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        match addr {
            IpAddr::V4(v4) => resp.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => resp.extend_from_slice(&v6.octets()),
        }
    }
    Bytes::from(resp)
}

/// 用新域名重建查询报文（替换 Question 段的 QNAME）。
///
/// 对齐 sing-box `exchangeOne` 直接用 `question.Name` 构造新 Msg 的行为。
/// 这里在 wire 层重写 QNAME：保留 header + 新 QNAME + 原 QTYPE + QCLASS。
fn rebuild_query_with_name(query: &[u8], new_name: &str) -> Vec<u8> {
    if query.len() < 12 {
        return query.to_vec();
    }
    // 解析原 QTYPE（Question 段 QNAME 之后 2 字节）
    // 简单扫描 QNAME 终止符
    let mut pos = 12;
    while pos < query.len() {
        let len = query[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + len;
    }
    let qtype_class = if pos + 4 <= query.len() {
        &query[pos..pos + 4]
    } else {
        &[0u8; 4]
    };

    // 构建新 QNAME：每个 label 前加长度字节，末尾 0
    let mut new_qname: Vec<u8> = Vec::new();
    for label in new_name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        new_qname.push(label.len() as u8);
        new_qname.extend_from_slice(label.as_bytes());
    }
    new_qname.push(0);

    let mut new_query = Vec::with_capacity(12 + new_qname.len() + 4);
    new_query.extend_from_slice(&query[..12]); // header（含原 ID/flags）
    new_query.extend_from_slice(&new_qname);
    new_query.extend_from_slice(qtype_class);
    new_query
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_resolv_conf_basic() {
        let content = "\
nameserver 8.8.8.8
nameserver 1.1.1.1
search example.com sub.example.com
options ndots:2 attempts:3 timeout:2 rotate
";
        let cfg = parse_resolv_conf(content);
        assert_eq!(
            cfg.servers,
            vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            ]
        );
        assert_eq!(cfg.search, vec!["example.com.", "sub.example.com."]);
        assert_eq!(cfg.ndots, 2);
        assert_eq!(cfg.attempts, 3);
        assert_eq!(cfg.timeout, Duration::from_secs(2));
        assert!(cfg.rotate);
    }

    #[test]
    fn parse_resolv_conf_domain_directive() {
        let content = "nameserver 8.8.8.8\ndomain corp.local\n";
        let cfg = parse_resolv_conf(content);
        assert_eq!(cfg.search, vec!["corp.local."]);
    }

    #[test]
    fn parse_resolv_conf_use_vc() {
        let cfg = parse_resolv_conf("nameserver 8.8.8.8\noptions use-vc\n");
        assert!(cfg.use_tcp);
    }

    #[test]
    fn parse_resolv_conf_defaults_on_empty() {
        let cfg = parse_resolv_conf("# empty\n");
        // 兜底 127.0.0.1:53
        assert_eq!(
            cfg.servers,
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53)]
        );
        assert_eq!(cfg.ndots, 1);
        assert_eq!(cfg.attempts, 2);
    }

    #[test]
    fn parse_resolv_conf_limits_three_nameservers() {
        let content = "\
nameserver 1.1.1.1
nameserver 2.2.2.2
nameserver 3.3.3.3
nameserver 4.4.4.4
";
        let cfg = parse_resolv_conf(content);
        assert_eq!(cfg.servers.len(), 3); // 超过 3 个截断
    }

    #[test]
    fn name_list_rooted_name() {
        let cfg = ResolvConfig {
            ndots: 1,
            search: vec!["example.com.".to_string()],
            ..Default::default()
        };
        // 已根化 → 直接返回单元素
        let names = name_list(&cfg, "foo.com.");
        assert_eq!(names, vec!["foo.com."]);
    }

    #[test]
    fn name_list_ndots_met() {
        let cfg = ResolvConfig {
            ndots: 2,
            search: vec!["example.com.".to_string()],
            ..Default::default()
        };
        // "a.b" 有 1 个点 < ndots=2 → has_ndots=false
        let names = name_list(&cfg, "a.b");
        // 先拼 search，再绝对名兜底
        assert_eq!(names, vec!["a.b.example.com.", "a.b."]);
    }

    #[test]
    fn name_list_ndots_not_met() {
        let cfg = ResolvConfig {
            ndots: 1,
            search: vec!["example.com.".to_string()],
            ..Default::default()
        };
        // "a.b.c" 有 2 个点 >= ndots=1 → has_ndots=true
        let names = name_list(&cfg, "a.b.c");
        // 先绝对名，再拼 search
        assert_eq!(names, vec!["a.b.c.", "a.b.c.example.com."]);
    }

    #[test]
    fn rebuild_query_preserves_header_and_qtype() {
        let original = crate::dns::wire::build_query_bytes("original.com", 1);
        let rebuilt = rebuild_query_with_name(&original, "replacement.example.com.");
        // ID 一致
        assert_eq!(&rebuilt[..2], &original[..2]);
        // qtype 一致（A=1）
        let qtype = crate::dns::wire::extract_qtype(&rebuilt).unwrap();
        assert_eq!(qtype, 1);
        // qname 是新域名
        let qname = crate::dns::wire::extract_qname(&rebuilt).unwrap();
        assert_eq!(qname, "replacement.example.com");
    }

    #[test]
    fn local_upstream_hosts_hit_skips_system_dns() {
        use std::io::Write;
        // 构造一个 hosts 文件 + 一个不存在的 resolv.conf
        let mut hosts_tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(hosts_tmp, "10.20.30.40 from-hosts.com").unwrap();
        hosts_tmp.flush().unwrap();

        let resolv_path = std::env::temp_dir().join("reflex_test_nonexistent_resolv.conf");
        let upstream =
            LocalUpstream::with_paths(hosts_tmp.path().to_path_buf(), resolv_path.clone());
        let query = crate::dns::wire::build_query_bytes("from-hosts.com", 1);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let resp = rt.block_on(upstream.reply(&query));
        // 应从 hosts 命中，返回 10.20.30.40
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[10, 20, 30, 40]);
    }
}
