use std::collections::HashMap;
use std::sync::Arc;

use crate::config::dns::{DnsServerConfig, ResolveStrategy};
use crate::dns::cache::{CacheResult, DnsCache};
use crate::dns::upstream::DnsUpstream;
use crate::dns::wire::extract_first_ip;

/// 从 DNS 缓存中查找代理节点域名对应的 IP。
/// 根据 strategy 选择查询 A/AAAA 或两者，返回首个匹配的 IP。
pub(super) fn lookup_ip_cache(
    cache: &DnsCache,
    server_tag: &str,
    host: &str,
    strategy: ResolveStrategy,
) -> Option<std::net::IpAddr> {
    match strategy {
        ResolveStrategy::Ipv4Only => {
            let cached = cache.get(server_tag, host, 1);
            ip_from_cache_result(cached, 1)
        }
        ResolveStrategy::Ipv6Only => {
            let cached = cache.get(server_tag, host, 28);
            ip_from_cache_result(cached, 28)
        }
        ResolveStrategy::PreferIpv4 => {
            let v4 = ip_from_cache_result(cache.get(server_tag, host, 1), 1);
            if v4.is_some() {
                return v4;
            }
            ip_from_cache_result(cache.get(server_tag, host, 28), 28)
        }
        ResolveStrategy::PreferIpv6 => {
            let v6 = ip_from_cache_result(cache.get(server_tag, host, 28), 28);
            if v6.is_some() {
                return v6;
            }
            ip_from_cache_result(cache.get(server_tag, host, 1), 1)
        }
    }
}

/// 从 CacheResult 中提取首个 IP（Hit 或 Stale 均视为有效）。
fn ip_from_cache_result(result: CacheResult, qtype: u16) -> Option<std::net::IpAddr> {
    match result {
        CacheResult::Hit(resp) | CacheResult::Stale(resp) => extract_first_ip(&resp, qtype),
        CacheResult::Miss => None,
    }
}

/// 将代理节点域名解析结果写入 DNS 缓存。
///
/// 由于 `resolve_domain_with_strategy` 直接查询 upstream 返回 IP（不返回原始报文），
/// 这里无法直接缓存 IP。改为构造一个最小 DNS 响应报文写入缓存，保持与全局
/// DNS 缓存格式一致，后续 lookup_ip_cache 可正确读取。
pub(super) fn store_ip_cache(
    cache: &DnsCache,
    server_tag: &str,
    host: &str,
    strategy: ResolveStrategy,
    ip: std::net::IpAddr,
    _upstream: &Arc<DnsUpstream>,
) {
    // 根据 strategy 和实际返回的 IP 类型决定写入哪个 qtype 的缓存
    let qtype = match ip {
        std::net::IpAddr::V4(_) => 1u16,  // A
        std::net::IpAddr::V6(_) => 28u16, // AAAA
    };

    // 仅当该 strategy 会查询此 qtype 时才写入，避免缓存污染
    let should_store = match strategy {
        ResolveStrategy::Ipv4Only => qtype == 1,
        ResolveStrategy::Ipv6Only => qtype == 28,
        ResolveStrategy::PreferIpv4 | ResolveStrategy::PreferIpv6 => true,
    };
    if !should_store {
        return;
    }

    let resp = build_minimal_dns_response(host, qtype, ip);
    cache.set(server_tag, host, qtype, resp.into(), 300);
}

/// 构造一个仅包含单条 Answer 记录的最小 DNS 响应报文，用于缓存写入。
pub(super) fn build_minimal_dns_response(host: &str, qtype: u16, ip: std::net::IpAddr) -> Vec<u8> {
    // DNS header: ID=0, QR=1(query response), QDCOUNT=1, ANCOUNT=1
    let mut msg = vec![
        0x00, 0x00, // ID
        0x81, 0x00, // flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x01, // ANCOUNT=1
        0x00, 0x00, // NSCOUNT=0
        0x00, 0x00, // ARCOUNT=0
    ];

    // Question section: QNAME + QTYPE + QCLASS
    for label in host.split('.') {
        if label.is_empty() {
            continue;
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN

    // Answer section: NAME(pointer to offset 12) + TYPE + CLASS + TTL + RDLENGTH + RDATA
    msg.push(0xc0); // 压缩指针指向 offset 12 (Question 的 QNAME)
    msg.push(0x0c);
    msg.extend_from_slice(&qtype.to_be_bytes()); // TYPE
    msg.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
    msg.extend_from_slice(&300u32.to_be_bytes()); // TTL=300
    match ip {
        std::net::IpAddr::V4(v4) => {
            msg.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH=4
            msg.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            msg.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH=16
            msg.extend_from_slice(&v6.octets());
        }
    }

    msg
}

/// 与 `extract_first_ip` 平行的实现：不是命中第一条就返回，而是收集**全部**
/// 匹配 `qtype` 的记录。供 `resolve_domain_all`（Happy Eyeballs 多候选拨号）
/// 使用。刻意不复用 `extract_first_ip` 内部逻辑（哪怕有重复），是为了不去碰
/// 已经过充分测试的原函数，降低改动风险。
pub(super) fn extract_all_ips(resp: &[u8], qtype: u16) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let mut out = Vec::new();
    if resp.len() < 12 {
        return out;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return out;
    }
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return out;
        }
        let len = resp[pos] as usize;
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
    pos += 4;
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        if resp[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            loop {
                if pos >= resp.len() {
                    return out;
                }
                let l = resp[pos] as usize;
                if l == 0 {
                    pos += 1;
                    break;
                }
                pos += 1 + l;
            }
        }
        if pos + 10 > resp.len() {
            break;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            break;
        }
        if rr_type == qtype {
            match qtype {
                1 if rdlength == 4 => {
                    out.push(IpAddr::V4(Ipv4Addr::new(
                        resp[pos],
                        resp[pos + 1],
                        resp[pos + 2],
                        resp[pos + 3],
                    )));
                }
                28 if rdlength == 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&resp[pos..pos + 16]);
                    out.push(IpAddr::V6(Ipv6Addr::from(o)));
                }
                _ => {}
            }
        }
        pos += rdlength;
    }
    out
}

// ── 拓扑排序 ──────────────────────────────────────────────────────────────────

pub(super) fn toposort_servers(servers: &[DnsServerConfig]) -> anyhow::Result<Vec<usize>> {
    let n = servers.len();
    let tag_to_idx: HashMap<&str, usize> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| (s.tag.as_str(), i))
        .collect();
    let mut in_degree = vec![0usize; n];
    let mut deps: Vec<Option<usize>> = vec![None; n];
    for (i, srv) in servers.iter().enumerate() {
        if let Some(ref tag) = srv.domain_resolver {
            let j = *tag_to_idx.get(tag.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "dns server '{}' domain_resolver '{}' not found",
                    srv.tag,
                    tag
                )
            })?;
            deps[i] = Some(j);
            in_degree[i] += 1;
            if let Some(k) = deps[j] {
                if k == i {
                    anyhow::bail!(
                        "dns server domain_resolver cycle between '{}' and '{}'",
                        servers[i].tag,
                        servers[j].tag
                    );
                }
            }
        }
    }
    let mut queue: std::collections::VecDeque<usize> =
        (0..n).filter(|&i| in_degree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    while let Some(node) = queue.pop_front() {
        order.push(node);
        for i in 0..n {
            if deps[i] == Some(node) {
                in_degree[i] -= 1;
                if in_degree[i] == 0 {
                    queue.push_back(i);
                }
            }
        }
    }
    if order.len() != n {
        anyhow::bail!("dns server domain_resolver has a cycle");
    }
    Ok(order)
}
