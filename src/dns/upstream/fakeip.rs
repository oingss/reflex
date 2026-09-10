use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use bytes::Bytes;

use crate::dns::make_noerror_empty;
use crate::dns::rcode::question_section_end;
use crate::experimental::CacheFile;

// ── FakeIP 地址池 ─────────────────────────────────────────────────────────────

pub struct FakeIpStore {
    inet4_net: Option<(Ipv4Addr, Ipv4Addr)>,
    inet6_net: Option<(Ipv6Addr, Ipv6Addr)>,
    inner: RwLock<FakeIpInner>,
    cache_file: Option<Arc<CacheFile>>,
    /// 控制 fakeip 响应哪种记录类型（与 DnsResolver.strategy 联动）。
    /// 用 AtomicU8 存储，允许在 Arc<FakeIpStore> 下热更新（如 global.ipv6 变化时）。
    /// 值含义：0=PreferIpv4, 1=PreferIpv6, 2=Ipv4Only, 3=Ipv6Only
    pub strategy: std::sync::atomic::AtomicU8,
}

struct FakeIpInner {
    inet4_current: Option<Ipv4Addr>,
    inet6_current: Option<Ipv6Addr>,
    addr_to_domain: HashMap<std::net::IpAddr, String>,
    domain_to_v4: HashMap<String, Ipv4Addr>,
    domain_to_v6: HashMap<String, Ipv6Addr>,
}

impl FakeIpStore {
    pub fn new(cfg: &crate::config::dns::FakeIpConfig) -> anyhow::Result<Self> {
        Self::new_with_cache(cfg, None, None)
    }

    pub fn new_with_cache(
        cfg: &crate::config::dns::FakeIpConfig,
        cache_file: Option<Arc<CacheFile>>,
        cache_reader: Option<Arc<crate::experimental::CacheFileReader>>,
    ) -> anyhow::Result<Self> {
        let inet4_net = cfg
            .inet4_range
            .as_deref()
            .map(parse_ipv4_cidr)
            .transpose()?;
        let inet6_net = cfg
            .inet6_range
            .as_deref()
            .map(parse_ipv6_cidr)
            .transpose()?;

        if inet4_net.is_none() && inet6_net.is_none() {
            anyhow::bail!("fakeip: at least one of inet4_range or inet6_range must be set");
        }

        // ── range 容量校验（参照 mihomo Pool.New: !first.Less(last)） ──────────
        //
        // reflex 的分配约定：初值 inet4_current = start+1（gateway，永不分配），
        // 首次分配返回 start+2，wrap 目标也是 start+2。因此必须满足：
        //   start+2 <= end (broadcast)
        //
        // - /30 (4 addrs: 网络/gateway/first_alloc/broadcast): start+2=start+2 <= end=start+3 ✓
        // - /31 (2 addrs): start+2 > end=start+1 ✗
        // - /32 (1 addr):  start+2 > end=start     ✗
        //
        // 不校验时：/31 /32 会 wrap 到 start+2，但 start+2 落在 range 外，
        // `contains()` 返回 false，路由层会把 fake IP 当成真实 IP，连接失败。
        // mihomo 的 first=start+3 要求 /29+；reflex 的 first=start+2 要求 /30+。
        if let Some((start, end)) = inet4_net {
            let s = u32::from(start) as u64;
            let e = u32::from(end) as u64;
            anyhow::ensure!(
                s + 2 <= e,
                "fakeip: inet4_range too small — need at least /30 (4 addresses) so that \
                 start+2 (first alloc) <= broadcast, got start={start} end={end}"
            );
        }
        if let Some((start, end)) = inet6_net {
            let s = u128::from(start);
            let e = u128::from(end);
            // u128 加法在 s 接近 u128::MAX 时会溢出；用 checked_add 安全判定。
            let first_alloc = s.checked_add(2);
            anyhow::ensure!(
                first_alloc.is_some_and(|fa| fa <= e),
                "fakeip: inet6_range too small — need at least /126 (4 addresses) so that \
                 start+2 (first alloc) <= broadcast, got start={start} end={end}"
            );
        }

        let inet4_current = inet4_net.map(|(start, _)| ipv4_next(start));
        let inet6_current = inet6_net.map(|(start, _)| ipv6_next(start));

        let mut inner = FakeIpInner {
            inet4_current,
            inet6_current,
            addr_to_domain: HashMap::new(),
            domain_to_v4: HashMap::new(),
            domain_to_v6: HashMap::new(),
        };

        if let (Some(ref cr), Some(ref cf)) = (&cache_reader, &cache_file) {
            if cf.store_fakeip {
                // ── 参照 sing-box Store.Start()：检测 range 是否变化 ────────────
                // 构造当前 range 的标记字符串（inet4_range|inet6_range）。
                let current_range_tag = format!(
                    "{}|{}",
                    cfg.inet4_range.as_deref().unwrap_or(""),
                    cfg.inet6_range.as_deref().unwrap_or(""),
                );
                let persisted_range_tag = cr.load_fakeip_range_tag();
                let range_changed = persisted_range_tag
                    .as_deref()
                    .map(|t| t != current_range_tag)
                    .unwrap_or(false); // 首次启动（无记录）= 无需重置

                if range_changed {
                    // range 发生变化：清空持久化数据，从头分配，防止旧 IP 记录污染。
                    tracing::warn!(
                        old_range = persisted_range_tag.as_deref().unwrap_or(""),
                        new_range = %current_range_tag,
                        "fakeip range changed, clearing persisted mappings"
                    );
                    cf.clear_fakeip();
                    cf.store_fakeip_range_tag(&current_range_tag);
                } else {
                    // range 未变（或首次启动）：恢复持久化的 ip→domain 映射。
                    match cr.load_all_fakeip() {
                        Ok(records) => {
                            let count = records.len();
                            for (ip, domain) in records {
                                // 归一化为小写（RFC 4343）。
                                // 旧版持久化记录可能以原始大小写存储；升级后新查询已统一
                                // 走 to_lowercase()，若不归一化旧记录，重启后反向查找会
                                // 因大小写不一致而 miss，触发重复分配、浪费地址池。
                                // 参照 mihomo Pool.Lookup: host = strings.ToLower(host)。
                                let domain = domain.to_lowercase();
                                match ip {
                                    std::net::IpAddr::V4(v4) => {
                                        if inet4_net.is_some_and(|(s, e)| v4 >= s && v4 <= e) {
                                            inner.addr_to_domain.insert(ip, domain.clone());
                                            inner.domain_to_v4.insert(domain, v4);
                                            if let Some(cur) = inner.inet4_current {
                                                if v4 >= cur {
                                                    inner.inet4_current = Some(ipv4_next(v4));
                                                }
                                            }
                                        }
                                    }
                                    std::net::IpAddr::V6(v6) => {
                                        if inet6_net.is_some_and(|(s, e)| v6 >= s && v6 <= e) {
                                            inner.addr_to_domain.insert(ip, domain.clone());
                                            inner.domain_to_v6.insert(domain, v6);
                                            if let Some(cur) = inner.inet6_current {
                                                if v6 >= cur {
                                                    inner.inet6_current = Some(ipv6_next(v6));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            // 指针溢出 range 时回绕到 start+2（对齐 sing-box wrap-around）。
                            if let Some((start, end)) = inet4_net {
                                if inner.inet4_current.is_some_and(|c| c >= end) {
                                    inner.inet4_current = Some(ipv4_next(ipv4_next(start)));
                                }
                            }
                            if let Some((start, end)) = inet6_net {
                                if inner.inet6_current.is_some_and(|c| c >= end) {
                                    inner.inet6_current = Some(ipv6_next(ipv6_next(start)));
                                }
                            }
                            // ── 加载持久化的分配指针（对齐 sing-box store.go:72-74）
                            //
                            // sing-box 在 range 未变时**无条件**采用持久化指针：
                            //   s.inet4Current = metadata.Inet4Current
                            //   s.inet6Current = metadata.Inet6Current
                            //
                            // 旧实现取 max(重建值, 持久化值)，初衷是防止「指针未刷但 record 已写」
                            // 的崩溃 race，但这会**破坏 wrap-around 正确性**：
                            //   当指针 wrap 回 start+2 后，持久化值 = start+2（小），而重建值
                            //   = max(record)+1（大，因为高位的 record 仍在）。max 会取重建值，
                            //   忽略 wrap，重启后从高位继续分配，可能与仍存活的高位映射冲突。
                            //
                            // 修复：对齐 sing-box，range 未变时无条件采用持久化指针（仅在持久化
                            // 指针缺失或落在 range 外时回退到重建值）。wrap 后持久化值 = start+2，
                            // 重启后正确从 start+2 继续分配，避免冲突。
                            if let Some((pv4, pv6)) = cr.load_fakeip_pointers() {
                                if let Some(pv4) = pv4 {
                                    // 仅当持久化指针落在 range 内才采纳，防止旧 range 残留污染。
                                    let in_range =
                                        inet4_net.is_some_and(|(s, e)| pv4 >= s && pv4 <= e);
                                    if in_range {
                                        inner.inet4_current = Some(pv4);
                                    }
                                }
                                if let Some(pv6) = pv6 {
                                    let in_range =
                                        inet6_net.is_some_and(|(s, e)| pv6 >= s && pv6 <= e);
                                    if in_range {
                                        inner.inet6_current = Some(pv6);
                                    }
                                }
                            }
                            tracing::info!(count, "restored fakeip mappings from cache");
                            // 首次启动时（无 range tag 记录）写入当前 range，
                            // 供下次启动做变化检测。
                            if persisted_range_tag.is_none() {
                                cf.store_fakeip_range_tag(&current_range_tag);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(err=%e, "failed to load fakeip from cache, starting fresh");
                        }
                    }
                }
            }
        }

        Ok(Self {
            inet4_net,
            inet6_net,
            inner: RwLock::new(inner),
            cache_file,
            strategy: std::sync::atomic::AtomicU8::new(0), // 默认 PreferIpv4
        })
    }

    /// 设置 fakeip 的 strategy，与 ResolveStrategy 对应：
    /// PreferIpv4=0, PreferIpv6=1, Ipv4Only=2, Ipv6Only=3
    pub fn set_strategy(&self, s: crate::config::dns::ResolveStrategy) {
        use crate::config::dns::ResolveStrategy::*;
        let v = match s {
            PreferIpv4 => 0,
            PreferIpv6 => 1,
            Ipv4Only => 2,
            Ipv6Only => 3,
        };
        self.strategy.store(v, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn diag_sizes(&self) -> (usize, usize, usize) {
        let inner = self.inner.read().unwrap();
        (
            inner.addr_to_domain.len(),
            inner.domain_to_v4.len(),
            inner.domain_to_v6.len(),
        )
    }

    pub fn contains(&self, addr: std::net::IpAddr) -> bool {
        match addr {
            std::net::IpAddr::V4(v4) => self.inet4_net.is_some_and(|(s, e)| v4 >= s && v4 <= e),
            std::net::IpAddr::V6(v6) => self.inet6_net.is_some_and(|(s, e)| v6 >= s && v6 <= e),
        }
    }

    pub fn lookup(&self, addr: std::net::IpAddr) -> Option<String> {
        self.inner
            .read()
            .unwrap()
            .addr_to_domain
            .get(&addr)
            .cloned()
    }

    /// 重置 FakeIP 存储（参照 sing-box `cacheFile.FakeIPReset()`）。
    ///
    /// 清空内存中的 ip→domain / domain→ip 映射，把 inet4_current/inet6_current
    /// 指针回退到 `start+1`（跳过网络地址），并调用 `cache_file.clear_fakeip()`
    /// 清空持久化表。range 标记保留不变（range 本身未变）。
    ///
    /// 用于 Clash API `POST /cache/fakeip/flush`。
    pub fn reset(&self) {
        let mut inner = self.inner.write().unwrap();
        let cleared = inner.addr_to_domain.len();
        inner.addr_to_domain.clear();
        inner.domain_to_v4.clear();
        inner.domain_to_v6.clear();
        // 指针回退到 start+1（对齐 new_with_cache 中的初值：ipv4_next(start)）。
        inner.inet4_current = self.inet4_net.map(|(start, _)| ipv4_next(start));
        inner.inet6_current = self.inet6_net.map(|(start, _)| ipv6_next(start));
        drop(inner);
        if let Some(ref cf) = self.cache_file {
            cf.clear_fakeip();
        }
        tracing::info!(cleared, "fakeip store reset (memory + persistent)");
    }

    /// 对外暴露 reply 结果，用 Result 区分「正常应答」和「不支持的查询类型」。
    /// 参照 sing-box fakeip.Transport.Exchange()：非 A/AAAA 直接返回 Err，
    /// 上层 DnsUpstream::query() 负责将 Err 向外传播（而非吞掉）。
    pub fn reply(&self, query: &[u8]) -> anyhow::Result<Bytes> {
        use crate::dns::{extract_qname, extract_qtype};

        let qtype = match extract_qtype(query) {
            Some(t) => t,
            None => return Ok(make_noerror_empty(query)),
        };
        // 参照 sing-box：仅支持 A(1) / AAAA(28)，其他类型直接报错，
        // 让 DNS 路由层感知失败（而非静默返回空成功）。
        if qtype != 1 && qtype != 28 {
            anyhow::bail!("fakeip: only A/AAAA queries are supported, got qtype={qtype}");
        }

        let qname = match extract_qname(query) {
            Some(n) => n,
            None => return Ok(make_noerror_empty(query)),
        };

        // RFC 4343: DNS is case-insensitive on the wire. Normalize to lowercase
        // before lookup/allocate so that "Example.com" and "example.com" share
        // the same fake IP. 参照 mihomo Pool.Lookup: host = strings.ToLower(host).
        //
        // 不在 extract_qname 内做归一化，避免影响 DNS 路由规则匹配 / 缓存键等其它路径。
        // 仅在 fakeip 分配层归一化：分配幂等性、反向查找一致性都依赖此处。
        //
        // 响应里的 Question 段仍按原 query 字节回显（build_ip_response 直接复制
        // query[12..question_end]），保留客户端原始大小写，符合 RFC 4343。
        let qname = qname.to_lowercase();

        // 读取当前 strategy：0=PreferIpv4, 1=PreferIpv6, 2=Ipv4Only, 3=Ipv6Only
        let strat = self.strategy.load(std::sync::atomic::Ordering::Relaxed);

        if qtype == 1 {
            // A 查询：Ipv6Only 时拒绝返回 IPv4 fakeip（参照 sing-box inet4Enabled 开关）
            if strat == 3 {
                return Ok(make_noerror_empty(query));
            }
            Ok(match self.allocate_v4(&qname) {
                Some(ip) => build_a_response(query, ip),
                None => make_noerror_empty(query),
            })
        } else {
            // AAAA 查询：Ipv4Only 时拒绝返回 IPv6 fakeip
            if strat == 2 {
                return Ok(make_noerror_empty(query));
            }
            Ok(match self.allocate_v6(&qname) {
                Some(ip) => build_aaaa_response(query, ip),
                None => make_noerror_empty(query),
            })
        }
    }

    fn allocate_v4(&self, domain: &str) -> Option<Ipv4Addr> {
        // 读锁快速路径：域名已存在则直接返回（参照 sing-box Create() 锁外先检查）。
        // 使用 read() 而非 write()，允许并发 DNS 查询同时检查不同域名。
        {
            let inner = self.inner.read().unwrap();
            if let Some(&existing) = inner.domain_to_v4.get(domain) {
                drop(inner);
                if let Some(ref cf) = self.cache_file {
                    cf.touch_fakeip_entry(std::net::IpAddr::V4(existing));
                }
                return Some(existing);
            }
        }
        // 写锁后 double-check（防止并发重复分配）。
        let mut inner = self.inner.write().unwrap();
        if let Some(&existing) = inner.domain_to_v4.get(domain) {
            if let Some(ref cf) = self.cache_file {
                cf.touch_fakeip_entry(std::net::IpAddr::V4(existing));
            }
            return Some(existing);
        }
        let (start, end) = self.inet4_net?;
        let current = inner.inet4_current?;
        // 参照 sing-box：next == last（广播地址）或超出 range 时从 start+2 重绕，
        // 跳过网络地址（start+1）以避免分配到可能被保留的地址。
        let candidate = ipv4_next(current);
        let next = if candidate >= end {
            ipv4_next(ipv4_next(start))
        } else {
            candidate
        };
        inner.inet4_current = Some(next);
        if let Some(old_domain) = inner.addr_to_domain.remove(&std::net::IpAddr::V4(next)) {
            inner.domain_to_v4.remove(&old_domain);
        }
        inner
            .addr_to_domain
            .insert(std::net::IpAddr::V4(next), domain.to_string());
        inner.domain_to_v4.insert(domain.to_string(), next);
        if let Some(ref cf) = self.cache_file {
            cf.store_fakeip_entry(std::net::IpAddr::V4(next), domain);
            // 持久化分配指针（参照 sing-box FakeIPSaveMetadataAsync）。
            // 异步串行写入，不阻塞查询路径。
            cf.store_fakeip_pointers(Some(next), inner.inet6_current);
        }
        Some(next)
    }

    fn allocate_v6(&self, domain: &str) -> Option<Ipv6Addr> {
        // 读锁快速路径：域名已存在则直接返回。
        // 使用 read() 而非 write()，允许并发 DNS 查询同时检查不同域名。
        {
            let inner = self.inner.read().unwrap();
            if let Some(&existing) = inner.domain_to_v6.get(domain) {
                drop(inner);
                if let Some(ref cf) = self.cache_file {
                    cf.touch_fakeip_entry(std::net::IpAddr::V6(existing));
                }
                return Some(existing);
            }
        }
        // 写锁后 double-check（防止并发重复分配）。
        let mut inner = self.inner.write().unwrap();
        if let Some(&existing) = inner.domain_to_v6.get(domain) {
            if let Some(ref cf) = self.cache_file {
                cf.touch_fakeip_entry(std::net::IpAddr::V6(existing));
            }
            return Some(existing);
        }
        let (start, end) = self.inet6_net?;
        let current = inner.inet6_current?;
        // 参照 sing-box：start+2 重绕。
        let candidate = ipv6_next(current);
        let next = if candidate >= end {
            ipv6_next(ipv6_next(start))
        } else {
            candidate
        };
        inner.inet6_current = Some(next);
        if let Some(old_domain) = inner.addr_to_domain.remove(&std::net::IpAddr::V6(next)) {
            inner.domain_to_v6.remove(&old_domain);
        }
        inner
            .addr_to_domain
            .insert(std::net::IpAddr::V6(next), domain.to_string());
        inner.domain_to_v6.insert(domain.to_string(), next);
        if let Some(ref cf) = self.cache_file {
            cf.store_fakeip_entry(std::net::IpAddr::V6(next), domain);
            // 持久化分配指针（参照 sing-box FakeIPSaveMetadataAsync）。
            cf.store_fakeip_pointers(inner.inet4_current, Some(next));
        }
        Some(next)
    }
}

// ── FakeIP wire 应答构造 ──────────────────────────────────────────────────────

fn build_a_response(query: &[u8], ip: Ipv4Addr) -> Bytes {
    build_ip_response(query, 1, &ip.octets())
}

fn build_aaaa_response(query: &[u8], ip: Ipv6Addr) -> Bytes {
    build_ip_response(query, 28, &ip.octets())
}

fn build_ip_response(query: &[u8], rtype: u16, rdata: &[u8]) -> Bytes {
    if query.len() < 12 {
        return make_noerror_empty(query);
    }
    // 参照 sing-box constant.DefaultDNSTTL = 600。
    // fakeip 应答幂等（同域名始终同 IP），600s TTL 可减少重复 DNS 查询，
    // 同时 fakeip store 本身保证一致性，缓存不会造成地址错位。
    const TTL: u32 = 600;

    // 只复制 Question section（QDCOUNT=1），不复制 Additional section。
    // 旧实现 `extend_from_slice(&query[12..])` 会把客户端的 EDNS0 OPT 记录
    // 也带进响应，但 header 声明 ARCOUNT=0，导致报文畸形。dig 报
    // "malformed message packet"，Go net.LookupHost 报 "no such host"。
    // 对齐 sing-box FixedResponse：只回显 Question，不回显 Additional。
    let question_end = match question_section_end(query, 12) {
        Some(end) => end,
        None => return make_noerror_empty(query),
    };
    let question_bytes = &query[12..question_end];

    let mut resp = Vec::with_capacity(12 + question_bytes.len() + 12 + rdata.len());
    resp.extend_from_slice(&query[..2]); // ID
    resp.extend_from_slice(&[0x81, 0x80]); // flags: QR=1 RD=1 RA=1
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    resp.extend_from_slice(question_bytes);
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer → offset 12
    resp.extend_from_slice(&rtype.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x01]); // class IN
    resp.extend_from_slice(&TTL.to_be_bytes());
    resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    resp.extend_from_slice(rdata);
    Bytes::from(resp)
}

// ── CIDR 解析 ────────────────────────────────────────────────────────────────

fn parse_ipv4_cidr(s: &str) -> anyhow::Result<(Ipv4Addr, Ipv4Addr)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid IPv4 CIDR: {s}"))?;
    let addr: Ipv4Addr = addr_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv4 address in CIDR: {s}"))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid prefix length in CIDR: {s}"))?;
    anyhow::ensure!(prefix <= 32, "IPv4 prefix length must be ≤ 32: {s}");
    let mask = if prefix == 0 {
        0u32
    } else {
        !0u32 << (32 - prefix)
    };
    let net = u32::from(addr) & mask;
    let bcast = net | !mask;
    Ok((Ipv4Addr::from(net), Ipv4Addr::from(bcast)))
}

fn parse_ipv6_cidr(s: &str) -> anyhow::Result<(Ipv6Addr, Ipv6Addr)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid IPv6 CIDR: {s}"))?;
    let addr: Ipv6Addr = addr_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv6 address in CIDR: {s}"))?;
    let prefix: u32 = prefix_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid prefix length in CIDR: {s}"))?;
    anyhow::ensure!(prefix <= 128, "IPv6 prefix length must be ≤ 128: {s}");
    let raw = u128::from(addr);
    let mask = if prefix == 0 {
        0u128
    } else {
        !0u128 << (128 - prefix)
    };
    let net = raw & mask;
    let last = net | !mask;
    Ok((Ipv6Addr::from(net), Ipv6Addr::from(last)))
}

fn ipv4_next(addr: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(addr).wrapping_add(1))
}
fn ipv6_next(addr: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(addr).wrapping_add(1))
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::dns::FakeIpConfig;
    use std::time::Duration;

    fn make_fakeip_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut msg = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0x00);
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&[0x00, 0x01]);
        msg
    }

    fn new_store_v4() -> FakeIpStore {
        FakeIpStore::new(&FakeIpConfig {
            inet4_range: Some("198.18.0.0/15".into()),
            inet6_range: None,
        })
        .unwrap()
    }

    #[test]
    fn fakeip_a_query_returns_valid_ip() {
        let store = new_store_v4();
        let q = make_fakeip_query("example.com", 1);
        let resp = store.reply(&q).unwrap();
        assert_eq!(resp[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
    }

    /// 验证带 EDNS0 OPT 的查询报文不会污染响应——
    /// 旧 bug：`extend_from_slice(&query[12..])` 会把 Additional section（OPT 记录）
    /// 带进响应，但 header 声明 ARCOUNT=0，导致报文畸形。dig 报
    /// "malformed message packet"，Go net.LookupHost 报 "no such host"。
    #[test]
    fn fakeip_response_excludes_edns0_opt() {
        let store = new_store_v4();
        // 构造带 EDNS0 OPT 的查询（ARCOUNT=1，OPT 记录在 Additional section）
        let mut q = make_fakeip_query("edns.example.com", 1);
        q[10] = 0x00;
        q[11] = 0x01; // ARCOUNT=1
                      // 追加 EDNS0 OPT 记录：name=root(0x00), type=OPT(41), class=4096, ttl=0, rdlength=0
        q.extend_from_slice(&[
            0x00, // root label
            0x00, 0x29, // TYPE = OPT (41)
            0x10, 0x00, // CLASS = UDP payload size 4096
            0x00, 0x00, 0x00, 0x00, // TTL
            0x00, 0x00, // RDLENGTH = 0
        ]);

        let resp = store.reply(&q).unwrap();
        // ARCOUNT 必须为 0（不回显 OPT）
        assert_eq!(
            u16::from_be_bytes([resp[10], resp[11]]),
            0,
            "ARCOUNT should be 0"
        );
        // QDCOUNT=1
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        // ANCOUNT=1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // 响应长度应等于 header(12) + question + answer RR，不应包含 OPT 记录的 11 字节
        let question_len = q.len() - 12 - 11; // 原始 question 段长度
        let expected_len = 12 + question_len + 12 + 4; // header + question + (ptr+type+class+ttl+rdlen=12) + rdata(4)
        assert_eq!(
            resp.len(),
            expected_len,
            "response should not contain EDNS0 OPT bytes"
        );
        // 最后 4 字节是 IPv4 地址
        let ip = Ipv4Addr::from(<[u8; 4]>::try_from(&resp[resp.len() - 4..]).unwrap());
        assert!(store.contains(std::net::IpAddr::V4(ip)));
    }

    #[test]
    fn fakeip_idempotent_same_domain() {
        let store = new_store_v4();
        let q = make_fakeip_query("same.example.com", 1);
        let r1 = store.reply(&q).unwrap();
        let r2 = store.reply(&q).unwrap();
        assert_eq!(&r1[r1.len() - 4..], &r2[r2.len() - 4..]);
    }

    #[test]
    fn fakeip_different_domains_get_different_ips() {
        let store = new_store_v4();
        let r1 = store.reply(&make_fakeip_query("a.com", 1)).unwrap();
        let r2 = store.reply(&make_fakeip_query("b.com", 1)).unwrap();
        assert_ne!(&r1[r1.len() - 4..], &r2[r2.len() - 4..]);
    }

    /// RFC 4343：DNS 在 wire 上大小写不敏感。"Example.com" 与 "example.com"
    /// 必须映射到同一个 fake IP。参照 mihomo `Pool.Lookup` 中的
    /// `host = strings.ToLower(host)`。
    ///
    /// **回归测试**：未做归一化时，大小写不同的同域名会触发新分配，
    /// 既浪费地址池空间，也会让反向查找（按 IP 找域名）与连接层 SNI 大小写
    /// 不一致时返回错误域名，导致路由判断错误。
    #[test]
    fn fakeip_rfc4343_case_insensitive() {
        let store = new_store_v4();

        // 全小写基线
        let lower = store.reply(&make_fakeip_query("case.example.com", 1)).unwrap();
        let lower_ip: [u8; 4] = lower[lower.len() - 4..].try_into().unwrap();

        // 各种大小写变体必须返回同一个 IP
        for variant in [
            "Case.Example.com",
            "CASE.EXAMPLE.COM",
            "case.EXAMPLE.com",
            "CaSe.eXaMpLe.CoM",
        ] {
            let r = store.reply(&make_fakeip_query(variant, 1)).unwrap();
            let ip: [u8; 4] = r[r.len() - 4..].try_into().unwrap();
            assert_eq!(
                ip, lower_ip,
                "RFC 4343: '{variant}' should map to same IP as 'case.example.com'"
            );
        }

        // 反向查找返回小写形式（与 mihomo 一致：存储时即归一化）
        let ip = std::net::IpAddr::V4(Ipv4Addr::from(lower_ip));
        assert_eq!(
            store.lookup(ip).as_deref(),
            Some("case.example.com"),
            "reverse lookup should return lowercased domain"
        );
    }

    /// 验证 AAAA 查询也走 RFC 4343 归一化。
    #[test]
    fn fakeip_rfc4343_case_insensitive_v6() {
        let store = FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: Some("fc00::/18".into()),
        })
        .unwrap();

        let lower = store
            .reply(&make_fakeip_query("v6.example.com", 28))
            .unwrap();
        let lower_ip: [u8; 16] = lower[lower.len() - 16..].try_into().unwrap();

        let mixed = store
            .reply(&make_fakeip_query("V6.Example.COM", 28))
            .unwrap();
        let mixed_ip: [u8; 16] = mixed[mixed.len() - 16..].try_into().unwrap();
        assert_eq!(mixed_ip, lower_ip);

        let ip = std::net::IpAddr::V6(Ipv6Addr::from(lower_ip));
        assert_eq!(store.lookup(ip).as_deref(), Some("v6.example.com"));
    }

    /// range 太小必须报错：/31 仅 2 个地址（网络 + 广播），不够分配 start+2。
    /// 参照 mihomo `Pool.New`: `!first.Less(last)` 拒绝过小 range。
    ///
    /// **回归测试**：未校验时 /31 会 wrap 到 start+2，但 start+2 落在 range 外，
    /// `contains()` 返回 false，路由层把 fake IP 当成真实 IP，连接失败。
    #[test]
    fn fakeip_rejects_too_small_v4_range() {
        // /31: start=198.18.0.0, end=198.18.0.1 — start+2=198.18.0.2 > end
        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: Some("198.18.0.0/31".into()),
            inet6_range: None,
        })
        .is_err());

        // /32: 单地址 — start+2 > end
        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: Some("198.18.0.0/32".into()),
            inet6_range: None,
        })
        .is_err());

        // /30: 4 地址 — start+2=start+2 <= end=start+3 ✓（最小合法 prefix）
        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: Some("198.18.0.0/30".into()),
            inet6_range: None,
        })
        .is_ok());
    }

    /// 同上，IPv6 的 /127 (2 addrs) 和 /128 (1 addr) 必须报错。
    #[test]
    fn fakeip_rejects_too_small_v6_range() {
        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: Some("fc00::/127".into()),
        })
        .is_err());

        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: Some("fc00::/128".into()),
        })
        .is_err());

        // /126 = 4 地址，最小合法 prefix
        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: Some("fc00::/126".into()),
        })
        .is_ok());
    }

    #[test]
    fn fakeip_reverse_lookup() {
        let store = new_store_v4();
        let resp = store
            .reply(&make_fakeip_query("lookup.example.com", 1))
            .unwrap();
        let ip_bytes: [u8; 4] = resp[resp.len() - 4..].try_into().unwrap();
        let ip = std::net::IpAddr::V4(Ipv4Addr::from(ip_bytes));
        assert!(store.contains(ip));
        assert_eq!(store.lookup(ip).as_deref(), Some("lookup.example.com"));
    }

    /// 参照 sing-box：非 A/AAAA 查询由 fakeip transport 返回 error，而非静默 NOERROR-empty。
    #[test]
    fn fakeip_non_ip_query_returns_error() {
        let store = new_store_v4();
        let result = store.reply(&make_fakeip_query("txt.example.com", 16));
        assert!(result.is_err(), "expected Err for non-A/AAAA qtype, got Ok");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("only A/AAAA"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn fakeip_aaaa_no_inet6() {
        let store = new_store_v4();
        let resp = store
            .reply(&make_fakeip_query("v6.example.com", 28))
            .unwrap();
        assert_eq!(resp[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn fakeip_ipv6_allocation() {
        let store = FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: Some("fc00::/18".into()),
        })
        .unwrap();
        let resp = store
            .reply(&make_fakeip_query("v6only.example.com", 28))
            .unwrap();
        assert_eq!(resp[3] & 0x0F, 0);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        let ip_bytes: [u8; 16] = resp[resp.len() - 16..].try_into().unwrap();
        let ip = std::net::IpAddr::V6(Ipv6Addr::from(ip_bytes));
        assert!(store.contains(ip));
        assert_eq!(store.lookup(ip).as_deref(), Some("v6only.example.com"));
    }

    #[test]
    fn fakeip_missing_config_errors() {
        assert!(FakeIpStore::new(&FakeIpConfig {
            inet4_range: None,
            inet6_range: None,
        })
        .is_err());
    }

    #[test]
    fn fakeip_cidr_parse_v4() {
        let (start, end) = parse_ipv4_cidr("198.18.0.0/15").unwrap();
        assert_eq!(start, Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(end, Ipv4Addr::new(198, 19, 255, 255));
    }

    #[test]
    fn fakeip_cidr_parse_v6() {
        let (start, _) = parse_ipv6_cidr("fc00::/18").unwrap();
        assert_eq!(start, "fc00::".parse::<Ipv6Addr>().unwrap());
    }

    /// 验证 fakeip 分配指针持久化与重启恢复：
    /// 1) 第一次启动：分配若干 IP，指针前移
    /// 2) 重启：从持久化恢复，指针应不回退（≥ 重建值），避免重复分配已分配的 IP
    ///
    /// 参照 sing-box `Store.Start()` 从 metadata 恢复 `inet4Current/inet6Current`。
    #[tokio::test]
    async fn fakeip_pointer_persistence_across_restart() {
        use crate::experimental::cache_file::open_cache_file;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().unwrap();
        let cfg = FakeIpConfig {
            inet4_range: Some("198.18.0.0/15".into()),
            inet6_range: None,
        };

        // 第一次启动：分配 5 个不同域名的 IP
        let (cf1, rd1) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store1 =
            FakeIpStore::new_with_cache(&cfg, Some(cf1.clone()), Some(rd1.clone())).unwrap();
        for i in 0..5 {
            let q = make_fakeip_query(&format!("host{i}.example.com"), 1);
            let _ = store1.reply(&q).unwrap();
        }
        // 等待异步写入刷盘
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 取最后一次分配的 IP（指针位置）
        let last_q = make_fakeip_query("last.example.com", 1);
        let last_resp = store1.reply(&last_q).unwrap();
        let last_ip_bytes: [u8; 4] = last_resp[last_resp.len() - 4..].try_into().unwrap();
        let last_ip = Ipv4Addr::from(last_ip_bytes);
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 重启：重新打开同一个 cache_file
        // 注意：必须 drop 旧句柄，redb 不允许多个写句柄同时打开同一文件
        drop(store1);
        drop(cf1);
        drop(rd1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (cf2, rd2) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store2 = FakeIpStore::new_with_cache(&cfg, Some(cf2), Some(rd2)).unwrap();

        // 重启后下一次分配的 IP 必须 > last_ip（指针未回退）
        let next_q = make_fakeip_query("next.example.com", 1);
        let next_resp = store2.reply(&next_q).unwrap();
        let next_ip_bytes: [u8; 4] = next_resp[next_resp.len() - 4..].try_into().unwrap();
        let next_ip = Ipv4Addr::from(next_ip_bytes);
        assert!(
            u32::from(next_ip) > u32::from(last_ip),
            "pointer regressed after restart: last={last_ip}, next={next_ip}"
        );
    }

    /// 验证 range 变化时持久化指针被清除（防止旧 range 的指针污染新 range）。
    /// 参照 sing-box `Store.Start()`：metadata.Inet4Range != s.inet4Range 时
    /// 调用 `FakeIPReset()` 清空持久化数据。
    #[tokio::test]
    async fn fakeip_range_change_clears_pointers() {
        use crate::experimental::cache_file::open_cache_file;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().unwrap();
        let cfg1 = FakeIpConfig {
            inet4_range: Some("198.18.0.0/15".into()),
            inet6_range: None,
        };

        // 第一次启动：分配 IP，持久化指针
        let (cf1, rd1) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store1 =
            FakeIpStore::new_with_cache(&cfg1, Some(cf1.clone()), Some(rd1.clone())).unwrap();
        let _ = store1
            .reply(&make_fakeip_query("a.example.com", 1))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        drop(store1);
        drop(cf1);
        drop(rd1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 第二次启动：换 range（从 /15 改成 /16）
        let cfg2 = FakeIpConfig {
            inet4_range: Some("198.18.0.0/16".into()),
            inet6_range: None,
        };
        let (cf2, rd2) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store2 = FakeIpStore::new_with_cache(&cfg2, Some(cf2), Some(rd2)).unwrap();

        // 新 range 下，第一次分配的 IP 应从 start+2 = 198.18.0.2 开始
        let resp = store2
            .reply(&make_fakeip_query("b.example.com", 1))
            .unwrap();
        let ip_bytes: [u8; 4] = resp[resp.len() - 4..].try_into().unwrap();
        let ip = Ipv4Addr::from(ip_bytes);
        assert_eq!(ip, Ipv4Addr::new(198, 18, 0, 2));
    }

    /// 验证 wrap-around 后持久化指针的正确恢复。
    ///
    /// **回归测试**：旧实现用 max(重建值, 持久化值) 采纳指针，破坏 wrap-around：
    ///   当指针 wrap 回 start+2 后，持久化值 = start+2（小），而重建值 = max(record)+1
    ///   （大，因为高位 record 仍在）。max 取重建值，忽略 wrap，重启后从高位继续分配。
    ///
    /// 修复后对齐 sing-box：range 未变时无条件采用持久化指针。wrap 后持久化值 = start+2，
    /// 重启后正确从 start+2 继续分配。
    ///
    /// 测试用一个很小的 range（/30 = 4 个地址：.0 网络、.1 start+1、.2 start+2、.3 广播），
    /// 分配 2 个域名触发 wrap-around，然后重启验证指针 = start+2。
    #[tokio::test]
    async fn fakeip_wrap_around_pointer_persistence() {
        use crate::experimental::cache_file::open_cache_file;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().unwrap();
        // /30 range: 198.51.100.0 - 198.51.100.3
        // 可分配：.1（start+1, 初值）、.2（start+2, wrap 目标）
        // .0 是网络地址，.3 是广播地址，均跳过
        let cfg = FakeIpConfig {
            inet4_range: Some("198.51.100.0/30".into()),
            inet6_range: None,
        };

        // 第一次启动：分配 2 个域名
        // 初始指针 = start+1 = .1
        // 第 1 次分配：candidate = .2，未 >= end(.3)，next = .2，指针 → .2
        // 第 2 次分配：candidate = .3，>= end(.3)，wrap → start+2 = .2，指针 → .2
        //   （.2 被重用，覆盖 host0 的映射）
        let (cf1, rd1) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store1 =
            FakeIpStore::new_with_cache(&cfg, Some(cf1.clone()), Some(rd1.clone())).unwrap();
        let _ = store1
            .reply(&make_fakeip_query("host0.example.com", 1))
            .unwrap();
        let _ = store1
            .reply(&make_fakeip_query("host1.example.com", 1))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 持久化指针应为 .2（wrap 后的值）
        let (pv4, _) = rd1.load_fakeip_pointers().unwrap();
        assert_eq!(pv4, Some(Ipv4Addr::new(198, 51, 100, 2)));

        drop(store1);
        drop(cf1);
        drop(rd1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 重启：持久化指针 = .2，应无条件采用（修复后），而非 max(重建值=.3, .2)=.3
        let (cf2, rd2) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store2 = FakeIpStore::new_with_cache(&cfg, Some(cf2), Some(rd2)).unwrap();

        // 重启后下一次分配：candidate = ipv4_next(.2) = .3，>= end(.3)，wrap → start+2 = .2
        // 所以新分配的 IP 应为 .2（wrap 后），而非 .3（广播地址，不应分配）
        let resp = store2
            .reply(&make_fakeip_query("host2.example.com", 1))
            .unwrap();
        let ip_bytes: [u8; 4] = resp[resp.len() - 4..].try_into().unwrap();
        let ip = Ipv4Addr::from(ip_bytes);
        assert_eq!(
            ip,
            Ipv4Addr::new(198, 51, 100, 2),
            "after wrap-around + restart, should allocate .2 (wrap target), not .3 (broadcast)"
        );
    }

    /// 验证 reset() 后持久化指针被清除，重启后指针回退到 start+1。
    ///
    /// **回归测试**：reset() 调用 clear_fakeip()，后者异步清除持久化指针
    /// （META_KEY_FAKEIP_POINTERS）。重启时 load_fakeip_pointers() 返回 None，
    /// 指针回退到重建值 = start+1。验证这一完整路径。
    #[tokio::test]
    async fn fakeip_reset_clears_persistent_pointers() {
        use crate::experimental::cache_file::open_cache_file;
        use tempfile::NamedTempFile;

        let f = NamedTempFile::new().unwrap();
        let cfg = FakeIpConfig {
            inet4_range: Some("198.18.0.0/15".into()),
            inet6_range: None,
        };

        // 第一次启动：分配 3 个 IP，指针前移
        // 初始指针 = start+1 = .1
        // Alloc 1: candidate = .2, next = .2, 指针 → .2
        // Alloc 2: candidate = .3, next = .3, 指针 → .3
        // Alloc 3: candidate = .4, next = .4, 指针 → .4
        let (cf1, rd1) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store1 =
            FakeIpStore::new_with_cache(&cfg, Some(cf1.clone()), Some(rd1.clone())).unwrap();
        for i in 0..3 {
            let _ = store1
                .reply(&make_fakeip_query(&format!("host{i}.example.com"), 1))
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 持久化指针应为 198.18.0.4
        let (pv4, _) = rd1.load_fakeip_pointers().unwrap();
        assert_eq!(pv4, Some(Ipv4Addr::new(198, 18, 0, 4)));

        // 调用 reset()：清空内存 + 持久化
        store1.reset();
        tokio::time::sleep(Duration::from_millis(150)).await;

        // 持久化指针应已被清除
        assert!(
            rd1.load_fakeip_pointers().is_none(),
            "persistent pointers should be cleared after reset()"
        );

        drop(store1);
        drop(cf1);
        drop(rd1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 重启：指针应回退到 start+1（初值），首次分配返回 ipv4_next(start+1) = start+2
        let (cf2, rd2) = open_cache_file(f.path(), true, 7, false, 3600).unwrap();
        let store2 = FakeIpStore::new_with_cache(&cfg, Some(cf2), Some(rd2)).unwrap();

        let resp = store2
            .reply(&make_fakeip_query("fresh.example.com", 1))
            .unwrap();
        let ip_bytes: [u8; 4] = resp[resp.len() - 4..].try_into().unwrap();
        let ip = Ipv4Addr::from(ip_bytes);
        assert_eq!(
            ip,
            Ipv4Addr::new(198, 18, 0, 2),
            "after reset() + restart, first alloc should be start+2 (pointer reset to start+1, alloc returns next)"
        );
    }
}
