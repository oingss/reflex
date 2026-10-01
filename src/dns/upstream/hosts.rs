use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;

use crate::dns::rcode::question_section_end;
use crate::dns::{make_noerror_empty, make_nxdomain};

/// hosts 文件缓存最大有效期（对齐 sing-box `cacheMaxAge = 5 * time.Second`）。
const CACHE_MAX_AGE: Duration = Duration::from_secs(5);

/// 默认 hosts 文件路径。
///
/// Unix 系（Linux/macOS/BSD）：`/etc/hosts`
/// Windows：`C:\Windows\System32\Drivers\etc\hosts`（简化处理，不调用 GetSystemDirectory）
pub fn default_hosts_path() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\Windows\System32\Drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

/// 规范化域名为小写 + 末尾 `.`（对齐 sing-box `mDNS.CanonicalName`）。
fn canonical(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with('.') {
        lower
    } else {
        format!("{lower}.")
    }
}

/// 一个 hosts 文件 + 其缓存。
///
/// 对齐 sing-box `hosts.File`：惰性加载、5s 缓存窗口、mtime+size 变化检测、
/// 解析失败时保留旧缓存（graceful degradation）。
pub struct HostsFile {
    path: PathBuf,
    inner: Mutex<HostsFileState>,
}

struct HostsFileState {
    /// 域名 → IP 列表。键为规范化域名（小写 + 末尾 `.`）。
    by_name: HashMap<String, Vec<IpAddr>>,
    /// 当前缓存到期时间。
    expire: Option<Instant>,
    /// 上次读取时的文件 mtime。
    mtime: Option<SystemTime>,
    /// 上次读取时的文件大小。
    size: u64,
}

impl HostsFile {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            inner: Mutex::new(HostsFileState {
                by_name: HashMap::new(),
                expire: None,
                mtime: None,
                size: 0,
            }),
        }
    }

    /// 查询域名对应的 IP 列表（对齐 sing-box `File.Lookup`）。
    ///
    /// 内部触发 `update` 刷新缓存。返回的切片引用在调用者持有锁期间有效，
    /// 这里返回 `Vec<IpAddr>` 的 clone 以简化生命周期（hosts 查询频率低，开销可接受）。
    pub fn lookup(&self, name: &str) -> Vec<IpAddr> {
        let canon = canonical(name);
        let mut state = self.inner.lock().unwrap();
        self.update(&mut state);
        state.by_name.get(&canon).cloned().unwrap_or_default()
    }

    /// 刷新缓存（对齐 sing-box `File.update`）。
    ///
    /// 多层防护：
    /// 1. 时间窗口缓存：5s 内不重复 stat
    /// 2. mtime + size 比对：未变更则仅续期，不重读
    /// 3. 解析/打开失败：保留旧缓存，不覆盖
    fn update(&self, state: &mut HostsFileState) {
        let now = Instant::now();
        // 1. 缓存窗口内直接返回
        if let Some(expire) = state.expire {
            if now < expire && !state.by_name.is_empty() {
                return;
            }
        }

        // 2. stat 文件
        let metadata = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => return, // 文件不存在/不可访问，保留旧缓存
        };
        let mtime = metadata.modified().ok();
        let size = metadata.len();

        // 3. mtime + size 未变，仅续期
        if state.mtime == mtime && state.size == size {
            state.expire = Some(now + CACHE_MAX_AGE);
            return;
        }

        // 4. 读取并解析文件
        let content = match std::fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return, // 读取失败，保留旧缓存
        };
        let parsed = parse_hosts_content(&content);
        // 解析成功（即便空文件也更新），更新缓存
        state.by_name = parsed;
        state.expire = Some(now + CACHE_MAX_AGE);
        state.mtime = mtime;
        state.size = size;
    }
}

/// 解析 hosts 文件内容（对齐 sing-box `hosts_file.go:60-97` 的行解析逻辑）。
///
/// 格式：`IP domain1 [domain2 ...]`，`#` 起注释，空白行/字段不足 2 的行跳过。
/// IPv4/IPv6 混合存储；同一域名多行追加。
pub fn parse_hosts_content(content: &str) -> HashMap<String, Vec<IpAddr>> {
    let mut by_name: HashMap<String, Vec<IpAddr>> = HashMap::new();
    for raw_line in content.lines() {
        // 剥离行内注释（# 之后全部丢弃）
        let line = match raw_line.find('#') {
            Some(pos) => &raw_line[..pos],
            None => raw_line,
        };
        // 按空白切分，连续空白压缩
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        // 第 1 列 IP
        let addr: IpAddr = match fields[0].parse() {
            Ok(a) => a,
            Err(_) => continue, // IP 解析失败，跳过该行
        };
        // 后续列均为域名
        for name in &fields[1..] {
            let canon = canonical(name);
            by_name.entry(canon).or_default().push(addr);
        }
    }
    by_name
}

/// Hosts DNS 服务器（对齐 sing-box `hosts.Transport`）。
pub struct HostsUpstream {
    /// 按顺序查询的 hosts 文件列表。
    files: Vec<HostsFile>,
    /// 内存预定义映射（优先级高于文件）。键为规范化域名。
    predefined: HashMap<String, Vec<IpAddr>>,
}

impl HostsUpstream {
    /// 从预定义映射 + 可选自定义路径构造。
    ///
    /// - `predefined`：域名 → IP 列表（域名会被规范化）
    /// - `paths`：hosts 文件路径列表；为空时使用 `default_hosts_path()`
    pub fn new(predefined: HashMap<String, Vec<IpAddr>>, paths: Vec<PathBuf>) -> Self {
        let predefined_norm: HashMap<String, Vec<IpAddr>> = predefined
            .into_iter()
            .map(|(k, v)| (canonical(&k), v))
            .collect();
        let files = if paths.is_empty() {
            vec![HostsFile::new(default_hosts_path())]
        } else {
            paths.into_iter().map(HostsFile::new).collect()
        };
        Self {
            files,
            predefined: predefined_norm,
        }
    }

    /// 处理 DNS 查询（对齐 sing-box `hosts.Transport.Exchange`）。
    ///
    /// 流程：
    /// 1. 仅 A/AAAA 查询走映射查找，其他类型直接 NXDOMAIN
    /// 2. predefined 优先
    /// 3. 按顺序遍历 files，任一命中即返回
    /// 4. 未命中返回 NXDOMAIN
    ///
    /// 命中时根据 qtype 过滤地址族：A 查询只返回 IPv4，AAAA 查询只返回 IPv6
    /// （对齐 sing-box `dns.FixedResponse` 的类型过滤行为）。
    pub fn reply(&self, query: &[u8]) -> Bytes {
        // 解析 qtype + qname
        let qtype = crate::dns::wire::extract_qtype(query);
        let qname = crate::dns::wire::extract_qname(query);

        let qtype = match qtype {
            Some(t) => t,
            None => return make_nxdomain(query),
        };
        // 仅处理 A(1) / AAAA(28)
        if qtype != 1 && qtype != 28 {
            return make_nxdomain(query);
        }
        let qname = match qname {
            Some(n) => n,
            None => return make_nxdomain(query),
        };

        let canon = canonical(&qname);

        // 收集所有候选 IP（predefined 优先，然后按序遍历文件）
        // 对齐 sing-box：predefined 命中即短路，不再查文件
        let mut addrs: Vec<IpAddr> = Vec::new();
        if let Some(v) = self.predefined.get(&canon) {
            addrs.extend_from_slice(v);
        } else {
            for file in &self.files {
                let v = file.lookup(&qname);
                if !v.is_empty() {
                    addrs.extend(v);
                    break; // 对齐 sing-box：任一文件命中即短路
                }
            }
        }

        if addrs.is_empty() {
            return make_nxdomain(query);
        }

        // 按 qtype 过滤地址族（A → IPv4，AAAA → IPv6）
        // 对齐 sing-box FixedResponse 的行为：不匹配类型的地址被剔除
        let filtered: Vec<IpAddr> = match qtype {
            1 => addrs.into_iter().filter(|a| a.is_ipv4()).collect(),
            28 => addrs.into_iter().filter(|a| a.is_ipv6()).collect(),
            _ => addrs,
        };

        if filtered.is_empty() {
            // 类型不匹配：返回空 NOERROR（域名存在但无对应类型记录）
            return make_noerror_empty(query);
        }

        build_ip_response(query, qtype, &filtered)
    }
}

/// 构造包含多个 answer RR 的 A/AAAA 响应。
///
/// 对齐 sing-box `dns.FixedResponse`：flags = QR=1, AA=1, RD=1, RA=1, RCODE=0；
/// 每个 answer 用 `[0xC0, 0x0C]` 指针压缩指向 Question 段的域名；
/// TTL = 600（对齐 sing-box `C.DefaultDNSTTL`，与 reflex fakeip 一致）。
fn build_ip_response(query: &[u8], qtype: u16, addrs: &[IpAddr]) -> Bytes {
    if query.len() < 12 {
        return make_noerror_empty(query);
    }
    const TTL: u32 = 600;
    // 每个 RR：name(2=ptr) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata(4或16)
    let rdata_len: usize = if qtype == 1 { 4 } else { 16 };
    let ancount = addrs.len() as u16;

    // 只复制 Question section，不复制 Additional section（EDNS0 OPT）。
    // 旧实现 `extend_from_slice(&query[12..])` 会把客户端 EDNS0 OPT 记录
    // 也带进响应，但 header 声明 ARCOUNT=0，导致报文畸形——dig 报
    // "malformed message packet"，Go net.LookupHost 报 "no such host"。
    // 对齐 sing-box FixedResponse：只回显 Question，不回显 Additional。
    let question_end = match question_section_end(query, 12) {
        Some(end) => end,
        None => return make_noerror_empty(query),
    };
    let question_bytes = &query[12..question_end];

    let mut resp = Vec::with_capacity(12 + question_bytes.len() + addrs.len() * (12 + rdata_len));
    // header
    resp.extend_from_slice(&query[..2]); // ID
    resp.extend_from_slice(&[0x85, 0x80]); // flags: QR+AA+RD, RA, RCODE=0
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    resp.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(question_bytes); // 回显 Question 段
                                            // 追加每个 answer RR
    for addr in addrs {
        resp.extend_from_slice(&[0xC0, 0x0C]); // name 指针 → offset 12
        resp.extend_from_slice(&qtype.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // class = IN
        resp.extend_from_slice(&TTL.to_be_bytes());
        resp.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        match addr {
            IpAddr::V4(v4) => resp.extend_from_slice(&v4.octets()),
            IpAddr::V6(v6) => resp.extend_from_slice(&v6.octets()),
        }
    }
    Bytes::from(resp)
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn canonical_lowercases_and_dots() {
        assert_eq!(canonical("Example.COM"), "example.com.");
        assert_eq!(canonical("a.b.c"), "a.b.c.");
        assert_eq!(canonical("already.dotted."), "already.dotted.");
    }

    #[test]
    fn parse_hosts_basic() {
        let content = "\
127.0.0.1 localhost
::1 localhost
192.168.1.1 nas.local my-nas.local
# this is a comment
10.0.0.1 server.local  # trailing comment
";
        let m = parse_hosts_content(content);
        // localhost, nas.local, my-nas.local, server.local = 4 keys
        assert_eq!(m.len(), 4);
        assert_eq!(
            m.get(&canonical("localhost")),
            Some(&vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ])
        );
        assert_eq!(
            m.get(&canonical("nas.local")),
            Some(&vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))])
        );
        assert_eq!(
            m.get(&canonical("my-nas.local")),
            Some(&vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))])
        );
    }

    #[test]
    fn parse_hosts_ignores_malformed() {
        let content = "\
not_an_ip foo.com
1.2.3.4
  # only comment
1.1.1.1 valid.com
";
        let m = parse_hosts_content(content);
        assert_eq!(m.len(), 1);
        assert!(m.contains_key(&canonical("valid.com")));
    }

    #[test]
    fn hosts_reply_a_query() {
        let mut predefined = HashMap::new();
        predefined.insert(
            "example.com".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        );
        let upstream = HostsUpstream::new(predefined, vec![]);
        let query = crate::dns::wire::build_query_bytes("example.com", 1);
        let resp = upstream.reply(&query);
        // 应返回 1 个 A 记录（ANCOUNT 位于 header offset 6-7）
        assert_eq!(resp[6], 0); // ANCOUNT high byte
        assert_eq!(resp[7], 1); // ANCOUNT low byte = 1
                                // 最后 4 字节应为 1.2.3.4
        let tail = &resp[resp.len() - 4..];
        assert_eq!(tail, &[1, 2, 3, 4]);
    }

    #[test]
    fn hosts_reply_aaaa_query_filters_ipv4() {
        let mut predefined = HashMap::new();
        // predefined 中只有 IPv4，AAAA 查询应返回空 NOERROR
        predefined.insert(
            "v4only.com".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        );
        let upstream = HostsUpstream::new(predefined, vec![]);
        let query = crate::dns::wire::build_query_bytes("v4only.com", 28);
        let resp = upstream.reply(&query);
        // RCODE=0 (NOERROR)，ANCOUNT=0
        assert_eq!(resp[3] & 0x0F, 0); // NOERROR
        assert_eq!(resp[6], 0); // ANCOUNT=0
    }

    #[test]
    fn hosts_reply_aaaa_query_returns_ipv6() {
        let mut predefined = HashMap::new();
        predefined.insert(
            "dualstack.com".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ],
        );
        let upstream = HostsUpstream::new(predefined, vec![]);
        let query = crate::dns::wire::build_query_bytes("dualstack.com", 28);
        let resp = upstream.reply(&query);
        assert_eq!(resp[7], 1); // ANCOUNT=1 (low byte at offset 7)
        let tail = &resp[resp.len() - 16..];
        assert_eq!(
            tail,
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]
        );
    }

    #[test]
    fn hosts_reply_nxdomain_for_unknown() {
        let upstream = HostsUpstream::new(HashMap::new(), vec![]);
        let query = crate::dns::wire::build_query_bytes("nonexistent.com", 1);
        let resp = upstream.reply(&query);
        assert_eq!(resp[3] & 0x0F, 3); // RCODE=3 NXDOMAIN
    }

    #[test]
    fn hosts_reply_nxdomain_for_non_a_aaaa() {
        let mut predefined = HashMap::new();
        predefined.insert(
            "mx.com".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        );
        let upstream = HostsUpstream::new(predefined, vec![]);
        // MX 查询（qtype=15）应返回 NXDOMAIN（对齐 sing-box hosts.go:79-86）
        let query = crate::dns::wire::build_query_bytes("mx.com", 15);
        let resp = upstream.reply(&query);
        assert_eq!(resp[3] & 0x0F, 3); // NXDOMAIN
    }

    #[test]
    fn hosts_file_lookup_with_temp_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "10.20.30.40 temp.example.com").unwrap();
        tmp.flush().unwrap();
        let hf = HostsFile::new(tmp.path().to_path_buf());
        let result = hf.lookup("temp.example.com");
        assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))]);
        // 大小写不敏感
        let result = hf.lookup("TEMP.Example.COM");
        assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40))]);
    }

    #[test]
    fn hosts_file_cache_does_not_reread_within_window() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "1.1.1.1 cached.com").unwrap();
        tmp.flush().unwrap();
        let path = tmp.path().to_path_buf();
        let hf = HostsFile::new(path.clone());
        // 第一次读取
        let r1 = hf.lookup("cached.com");
        assert_eq!(r1.len(), 1);
        // 立即修改文件（mtime 可能精度不足，但内容变了）
        // 由于 5s 缓存窗口，第二次 lookup 应返回旧缓存（即便文件已变）
        std::thread::sleep(Duration::from_millis(100));
        let mut tmp2 = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        writeln!(tmp2, "2.2.2.2 cached.com").unwrap();
        tmp2.flush().unwrap();
        drop(tmp2);
        // 缓存窗口内仍返回旧值 1.1.1.1
        let r2 = hf.lookup("cached.com");
        assert_eq!(r2, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
    }

    #[test]
    fn predefined_takes_priority_over_file() {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "9.9.9.9 conflict.com").unwrap();
        tmp.flush().unwrap();
        let mut predefined = HashMap::new();
        predefined.insert(
            "conflict.com".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))],
        );
        let upstream = HostsUpstream::new(predefined, vec![tmp.path().to_path_buf()]);
        let query = crate::dns::wire::build_query_bytes("conflict.com", 1);
        let resp = upstream.reply(&query);
        let tail = &resp[resp.len() - 4..];
        // 应返回 predefined 的 1.2.3.4，而非文件的 9.9.9.9
        assert_eq!(tail, &[1, 2, 3, 4]);
    }
}
