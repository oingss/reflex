use bytes::Bytes;

pub fn extract_qname(msg: &[u8]) -> Option<String> {
    if msg.len() < 13 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            break;
        }
        pos += 1;
        if pos + len > msg.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&msg[pos..pos + len]).into_owned());
        pos += len;
    }
    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

pub fn extract_qtype(msg: &[u8]) -> Option<u16> {
    if msg.len() < 13 {
        return None;
    }
    let mut pos = 12;
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
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
    if pos + 2 > msg.len() {
        return None;
    }
    Some(u16::from_be_bytes([msg[pos], msg[pos + 1]]))
}

pub(super) fn patch_id(resp: Bytes, query: &[u8]) -> Bytes {
    if resp.len() >= 2 && query.len() >= 2 {
        let mut v = resp.to_vec();
        v[0] = query[0];
        v[1] = query[1];
        Bytes::from(v)
    } else {
        resp
    }
}

/// 原 is_cacheable：只缓存 NOERROR + ANCOUNT>0
#[allow(dead_code)]
pub(super) fn is_cacheable(resp: &[u8]) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    rcode == 0 && ancount > 0
}

/// 扩展版：同时缓存负应答（NXDOMAIN / NOERROR-empty），以 SOA minimum TTL 为准。
/// 参照 sing-box extractNegativeTTL，避免对不存在域名反复查询上游。
pub(super) fn is_cacheable_or_negative(resp: &[u8]) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    // NOERROR(0) + ANCOUNT>0 → 正向缓存
    if rcode == 0 && u16::from_be_bytes([resp[6], resp[7]]) > 0 {
        return true;
    }
    // NXDOMAIN(3) 或 NOERROR + 无 answer → 负向缓存（若有 SOA TTL）
    if rcode == 0 || rcode == 3 {
        return extract_soa_ttl(resp).is_some();
    }
    false
}

/// 提取 min TTL（正向应答用），或 SOA minimum（负向应答用）。
pub(super) fn extract_min_ttl_or_negative(resp: &[u8]) -> Option<u32> {
    if resp.len() < 12 {
        return None;
    }
    let rcode = resp[3] & 0x0F;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);

    if (rcode == 0 || rcode == 3) && ancount == 0 {
        // 负应答：用 SOA 的 min(soaTTL, soaMinimum)。
        // 对齐 sing-box extractNegativeTTL —— 不硬编码 300s 上限，使用 SOA 真实值。
        // 无 SOA 时回退到 60s（避免对不存在域名反复查询上游），上限 3600s 防止极端值。
        return Some(extract_soa_ttl(resp).unwrap_or(60).min(3600));
    }
    extract_min_ttl(resp)
}

/// 从 Authority 区提取 SOA minimum TTL（负应答缓存 TTL 依据）。
/// 参照 sing-box extractNegativeTTL：min(soaTTL, soaMinimum)。
fn extract_soa_ttl(resp: &[u8]) -> Option<u32> {
    // 简单扫描 Authority section：NSCOUNT 个 RR，寻找 TYPE=SOA(6)
    if resp.len() < 12 {
        return None;
    }
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    if nscount == 0 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    // 跳过 Question section
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return None;
        }
        let l = resp[pos] as usize;
        if l == 0 {
            pos += 1;
            break;
        }
        if l & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + l;
    }
    pos += 4; // QTYPE + QCLASS
              // 跳过 Answer section
    for _ in 0..ancount {
        pos = skip_rr(resp, pos)?;
    }
    // 扫描 Authority section 找 SOA
    for _ in 0..nscount {
        let rr_start = pos;
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rr_ttl =
            u32::from_be_bytes([resp[pos + 4], resp[pos + 5], resp[pos + 6], resp[pos + 7]]);
        let _rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if rr_type == 6 {
            // SOA: MNAME + RNAME + serial(4) + refresh(4) + retry(4) + expire(4) + minimum(4)
            // 跳过 MNAME 和 RNAME 两个域名，定位 minimum 字段
            let mut soa_pos = pos;
            soa_pos = skip_name(resp, soa_pos)?;
            soa_pos = skip_name(resp, soa_pos)?;
            if soa_pos + 20 > resp.len() {
                return None;
            }
            let minimum = u32::from_be_bytes([
                resp[soa_pos + 16],
                resp[soa_pos + 17],
                resp[soa_pos + 18],
                resp[soa_pos + 19],
            ]);
            return Some(rr_ttl.min(minimum));
        }
        pos = rr_start;
        pos = skip_rr(resp, pos)?;
    }
    None
}

fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let l = msg[pos] as usize;
        if l == 0 {
            return Some(pos + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(pos + 2);
        }
        pos += 1 + l;
    }
}

fn skip_rr(msg: &[u8], pos: usize) -> Option<usize> {
    let pos = skip_name(msg, pos)?;
    if pos + 10 > msg.len() {
        return None;
    }
    let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
    Some(pos + 10 + rdlength)
}

pub(super) fn extract_min_ttl(resp: &[u8]) -> Option<u32> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return None;
        }
        let len = msg_label_len(resp, pos)?;
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
    pos += 4; // QTYPE + QCLASS
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        if pos >= resp.len() {
            break;
        }
        if resp[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            loop {
                if pos >= resp.len() {
                    return None;
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
        let ttl = u32::from_be_bytes(resp[pos + 4..pos + 8].try_into().ok()?);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10 + rdlength;
        if ttl < min_ttl {
            min_ttl = ttl;
        }
    }
    if min_ttl == u32::MAX {
        None
    } else {
        Some(min_ttl)
    }
}

fn msg_label_len(msg: &[u8], pos: usize) -> Option<usize> {
    msg.get(pos).map(|&b| b as usize)
}

pub fn build_query_bytes(name: &str, qtype: u16) -> Vec<u8> {
    build_query(name, qtype)
}

pub fn extract_first_ip_from_resp(resp: &[u8], qtype: u16) -> Option<std::net::IpAddr> {
    extract_first_ip(resp, qtype)
}

pub(super) fn build_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut msg = vec![
        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00);
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&[0x00, 0x01]);
    msg
}

pub(super) fn extract_first_ip(resp: &[u8], qtype: u16) -> Option<std::net::IpAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12;
    loop {
        if pos >= resp.len() {
            return None;
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
                    return None;
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
                    return Some(IpAddr::V4(Ipv4Addr::new(
                        resp[pos],
                        resp[pos + 1],
                        resp[pos + 2],
                        resp[pos + 3],
                    )))
                }
                28 if rdlength == 16 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&resp[pos..pos + 16]);
                    return Some(IpAddr::V6(Ipv6Addr::from(o)));
                }
                _ => {}
            }
        }
        pos += rdlength;
    }
    None
}

// ── EDNS Client Subnet 注入（对齐 sing-box SetClientSubnet） ──────────────────
//
// EDNS0_SUBNET (RFC 7871) wire format:
//   OPT RR (TYPE=41) in Additional section
//     NAME(1=0x00) + TYPE(2=0x0029) + CLASS(2=UDP payload size)
//     + TTL(4=extended RCODE+flags) + RDLENGTH(2) + RDATA(variable)
//   RDATA contains options in TLV format:
//     option-code(2) + option-len(2) + option-data(option-len bytes)
//   EDNS0_SUBNET (option-code=8) option-data:
//     FAMILY(2: 1=IPv4, 2=IPv6) + SOURCE-NETMASK(1) + SCOPE-NETMASK(1)
//     + ADDRESS(ceil(SOURCE-NETMASK/8) bytes — only the network prefix)
//
// 行为对齐 sing-box dns/extension_edns0_subnet.go setClientSubnet：
//   1. 查找 Additional 段中已有的 OPT RR（TYPE=41）
//   2. 在 OPT 的 RDATA 中查找已有的 EDNS0_SUBNET 选项
//   3. 若存在：替换其内容；若不存在：追加新选项
//   4. 若整个 OPT 不存在：在 Additional 段追加新 OPT RR，ARCOUNT++
//
// 保留原 OPT 的 UDP payload size 和 TTL（extended RCODE + flags），避免覆盖
// 客户端的 EDNS 协商参数。

/// 为 DNS 查询消息注入 EDNS Client Subnet（EDNS0_SUBNET, RFC 7871）。
///
/// 入参 `msg` 是原始查询字节；`subnet` 是客户端子网；`prefix_len` 是掩码位数
/// （IPv4: 0-32，IPv6: 0-128）。
///
/// 返回新的消息字节：若 `msg` 已含 OPT+EDNS0_SUBNET，原选项被替换；
/// 若 OPT 存在但无 EDNS0_SUBNET，追加新选项；若 OPT 不存在，追加新 OPT RR
/// 并把 ARCOUNT+1。
///
/// 解析失败时原样返回 `msg`，不报错（保守降级，保证查询能继续）。
pub fn set_client_subnet(msg: Bytes, subnet: std::net::IpAddr, prefix_len: u8) -> Bytes {
    if msg.len() < 12 {
        return msg;
    }
    // 校验 prefix_len 范围
    let max_prefix = match subnet {
        std::net::IpAddr::V4(_) => 32u8,
        std::net::IpAddr::V6(_) => 128u8,
    };
    if prefix_len > max_prefix {
        return msg;
    }

    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    let arcount = u16::from_be_bytes([msg[10], msg[11]]) as usize;

    // 跳过 Question 段
    let mut pos = 12;
    for _ in 0..qdcount {
        match skip_question(&msg, pos) {
            Some(p) => pos = p,
            None => return msg,
        }
    }
    // 跳过 Answer 段
    for _ in 0..ancount {
        match skip_rr(&msg, pos) {
            Some(p) => pos = p,
            None => return msg,
        }
    }
    // 跳过 Authority 段
    for _ in 0..nscount {
        match skip_rr(&msg, pos) {
            Some(p) => pos = p,
            None => return msg,
        }
    }
    let additional_start = pos;

    // 在 Additional 段中查找 OPT RR（TYPE=41）
    let mut opt_rr_start: Option<usize> = None;
    let mut cur = additional_start;
    for _ in 0..arcount {
        let rr_start = cur;
        match skip_rr(&msg, rr_start) {
            Some(next) => cur = next,
            None => return msg,
        }
        // OPT RR：NAME 之后是 TYPE(2)
        let after_name = match skip_name(&msg, rr_start) {
            Some(p) => p,
            None => continue,
        };
        if after_name + 2 > msg.len() {
            continue;
        }
        let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
        if rtype == 41 {
            opt_rr_start = Some(rr_start);
            break;
        }
    }

    // 构造 EDNS0_SUBNET 选项字节
    let (family, addr_octets) = match subnet {
        std::net::IpAddr::V4(v4) => (1u16, v4.octets().to_vec()),
        std::net::IpAddr::V6(v6) => (2u16, v6.octets().to_vec()),
    };
    // ADDRESS 只放前缀部分：ceil(prefix_len / 8) 字节
    let prefix_bytes_len = (prefix_len as usize).div_ceil(8);
    let prefix_bytes_len = prefix_bytes_len.min(addr_octets.len());
    let addr_prefix = &addr_octets[..prefix_bytes_len];

    // option-data: FAMILY(2) + SOURCE-NETMASK(1) + SCOPE-NETMASK(1) + ADDRESS
    let mut option_data = Vec::with_capacity(4 + prefix_bytes_len);
    option_data.extend_from_slice(&family.to_be_bytes());
    option_data.push(prefix_len);
    option_data.push(0); // SCOPE-NETMASK = 0（请求方）
    option_data.extend_from_slice(addr_prefix);

    // option TLV: option-code(2) + option-len(2) + option-data
    let mut option = Vec::with_capacity(4 + option_data.len());
    option.extend_from_slice(&8u16.to_be_bytes()); // EDNS0_SUBNET = 8
    option.extend_from_slice(&(option_data.len() as u16).to_be_bytes());
    option.extend_from_slice(&option_data);

    if let Some(opt_pos) = opt_rr_start {
        // OPT 已存在 — 修改其 RDATA：移除原 EDNS0_SUBNET（如有），追加新选项
        let after_name = match skip_name(&msg, opt_pos) {
            Some(p) => p,
            None => return msg,
        };
        // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 字节
        if after_name + 10 > msg.len() {
            return msg;
        }
        let udp_payload = u16::from_be_bytes([msg[after_name + 2], msg[after_name + 3]]);
        let ttl = u32::from_be_bytes([
            msg[after_name + 4],
            msg[after_name + 5],
            msg[after_name + 6],
            msg[after_name + 7],
        ]);
        let rdlength = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        if rdata_start + rdlength > msg.len() {
            return msg;
        }
        let rdata_end = rdata_start + rdlength;
        let rdata = &msg[rdata_start..rdata_end];

        // 遍历原 RDATA，复制除 EDNS0_SUBNET（option-code=8）外的所有选项
        let mut new_rdata: Vec<u8> = Vec::with_capacity(rdata.len() + option.len());
        let mut o_pos = 0;
        while o_pos + 4 <= rdata.len() {
            let o_code = u16::from_be_bytes([rdata[o_pos], rdata[o_pos + 1]]);
            let o_len = u16::from_be_bytes([rdata[o_pos + 2], rdata[o_pos + 3]]) as usize;
            if o_pos + 4 + o_len > rdata.len() {
                break; // RDATA 损坏，放弃解析
            }
            if o_code != 8 {
                new_rdata.extend_from_slice(&rdata[o_pos..o_pos + 4 + o_len]);
            }
            o_pos += 4 + o_len;
        }
        // 追加新 EDNS0_SUBNET 选项
        new_rdata.extend_from_slice(&option);

        // 重建消息：header + Question/Answer/Authority + Additional 中 OPT 之前的 RR
        // + 新 OPT RR + Additional 中 OPT 之后的 RR
        let mut new_msg: Vec<u8> = Vec::with_capacity(msg.len() + 32);
        new_msg.extend_from_slice(&msg[..opt_pos]); // ARCOUNT 不变（替换 OPT）
                                                    // 新 OPT RR
        new_msg.push(0); // NAME = root
        new_msg.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        new_msg.extend_from_slice(&udp_payload.to_be_bytes()); // CLASS = UDP payload size
        new_msg.extend_from_slice(&ttl.to_be_bytes()); // TTL
        new_msg.extend_from_slice(&(new_rdata.len() as u16).to_be_bytes()); // RDLENGTH
        new_msg.extend_from_slice(&new_rdata); // RDATA
                                               // Additional 中 OPT 之后的 RR（如果有）
        new_msg.extend_from_slice(&msg[rdata_end..]);
        Bytes::from(new_msg)
    } else {
        // OPT 不存在 — 在 Additional 末尾追加新 OPT RR，ARCOUNT++
        let mut new_msg: Vec<u8> = Vec::with_capacity(msg.len() + 20);
        new_msg.extend_from_slice(&msg[..10]); // 前 10 字节
        new_msg.extend_from_slice(&((arcount as u16) + 1).to_be_bytes()); // ARCOUNT+1
        new_msg.extend_from_slice(&msg[12..]); // Question/Answer/Authority/原 Additional
                                               // 新 OPT RR
        new_msg.push(0); // NAME = root
        new_msg.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        new_msg.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size 4096
        new_msg.extend_from_slice(&[0, 0, 0, 0]); // TTL = 0
        new_msg.extend_from_slice(&(option.len() as u16).to_be_bytes()); // RDLENGTH
        new_msg.extend_from_slice(&option); // RDATA
        Bytes::from(new_msg)
    }
}

/// 跳过 Question 段一条记录：QNAME + QTYPE(2) + QCLASS(2)
fn skip_question(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let l = msg[pos] as usize;
        if l == 0 {
            pos += 1;
            break;
        }
        if l & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1 + l;
        if pos > msg.len() {
            return None;
        }
    }
    if pos + 4 > msg.len() {
        return None;
    }
    Some(pos + 4)
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个标准 DNS 查询：example.com A IN
    fn build_dns_query(qid: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&qid.to_be_bytes());
        // flags: RD=1
        q.push(0x01);
        q.push(0x00);
        // QDCOUNT=1
        q.extend_from_slice(&1u16.to_be_bytes());
        // ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        // QNAME: \x07example\x03com\x00
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        // QTYPE=A=1, QCLASS=IN=1
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    /// 构造一个带 OPT RR（含已有 EDNS0_SUBNET 选项）的 DNS 查询
    fn build_dns_query_with_opt_subnet(
        qid: u16,
        existing_subnet: Option<(std::net::IpAddr, u8)>,
    ) -> Vec<u8> {
        let mut q = build_dns_query(qid);
        // 改 ARCOUNT=1
        let arcount_pos = 10;
        q[arcount_pos] = 0;
        q[arcount_pos + 1] = 1;
        // 追加 OPT RR
        q.push(0); // NAME = root
        q.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        q.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload size
        q.extend_from_slice(&[0, 0, 0, 0]); // TTL = 0
                                            // 构造 RDATA
        let mut rdata = Vec::new();
        if let Some((subnet, prefix_len)) = existing_subnet {
            let (family, addr_octets) = match subnet {
                std::net::IpAddr::V4(v4) => (1u16, v4.octets().to_vec()),
                std::net::IpAddr::V6(v6) => (2u16, v6.octets().to_vec()),
            };
            let prefix_bytes_len = (prefix_len as usize).div_ceil(8);
            let prefix_bytes_len = prefix_bytes_len.min(addr_octets.len());
            let mut option_data = Vec::with_capacity(4 + prefix_bytes_len);
            option_data.extend_from_slice(&family.to_be_bytes());
            option_data.push(prefix_len);
            option_data.push(0);
            option_data.extend_from_slice(&addr_octets[..prefix_bytes_len]);
            rdata.extend_from_slice(&8u16.to_be_bytes());
            rdata.extend_from_slice(&(option_data.len() as u16).to_be_bytes());
            rdata.extend_from_slice(&option_data);
        }
        q.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
        q.extend_from_slice(&rdata);
        q
    }

    /// 查找 Additional 段中 OPT RR 并返回其起始偏移
    fn find_opt_rr(msg: &[u8]) -> Option<usize> {
        if msg.len() < 12 {
            return None;
        }
        let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
        let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
        let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
        let arcount = u16::from_be_bytes([msg[10], msg[11]]) as usize;
        let mut pos = 12;
        for _ in 0..qdcount {
            pos = skip_question(msg, pos)?;
        }
        for _ in 0..ancount {
            pos = skip_rr(msg, pos)?;
        }
        for _ in 0..nscount {
            pos = skip_rr(msg, pos)?;
        }
        for _ in 0..arcount {
            let rr_start = pos;
            pos = skip_rr(msg, pos)?;
            let after_name = skip_name(msg, rr_start)?;
            if after_name + 2 > msg.len() {
                continue;
            }
            let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
            if rtype == 41 {
                return Some(rr_start);
            }
        }
        None
    }

    /// 从 OPT RR 的 RDATA 中提取 EDNS0_SUBNET 选项数据
    fn extract_subnet_option(msg: &[u8]) -> Option<(u16, u8, u8, Vec<u8>)> {
        let opt_pos = find_opt_rr(msg)?;
        let after_name = skip_name(msg, opt_pos)?;
        if after_name + 10 > msg.len() {
            return None;
        }
        let rdlength = u16::from_be_bytes([msg[after_name + 8], msg[after_name + 9]]) as usize;
        let rdata_start = after_name + 10;
        if rdata_start + rdlength > msg.len() {
            return None;
        }
        let rdata = &msg[rdata_start..rdata_start + rdlength];
        let mut o_pos = 0;
        while o_pos + 4 <= rdata.len() {
            let o_code = u16::from_be_bytes([rdata[o_pos], rdata[o_pos + 1]]);
            let o_len = u16::from_be_bytes([rdata[o_pos + 2], rdata[o_pos + 3]]) as usize;
            if o_pos + 4 + o_len > rdata.len() {
                return None;
            }
            if o_code == 8 && o_len >= 4 {
                let family = u16::from_be_bytes([rdata[o_pos + 4], rdata[o_pos + 5]]);
                let source_netmask = rdata[o_pos + 6];
                let scope_netmask = rdata[o_pos + 7];
                let addr = rdata[o_pos + 8..o_pos + 4 + o_len].to_vec();
                return Some((family, source_netmask, scope_netmask, addr));
            }
            o_pos += 4 + o_len;
        }
        None
    }

    #[test]
    fn injects_subnet_into_query_without_opt() {
        // 原 query 无 OPT RR → 注入后追加 OPT+EDNS0_SUBNET，ARCOUNT+1
        let q = build_dns_query(0xABCD);
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 0); // 原 ARCOUNT=0

        let new = set_client_subnet(Bytes::from(q), "1.2.3.0".parse().unwrap(), 24);

        // ARCOUNT 应变为 1
        assert_eq!(u16::from_be_bytes([new[10], new[11]]), 1);
        // 应能找到 OPT RR
        assert!(find_opt_rr(&new).is_some());
        // 提取 EDNS0_SUBNET：family=1(IPv4), source=24, scope=0, addr=1.2.3.0
        let (family, src, scope, addr) =
            extract_subnet_option(&new).expect("EDNS0_SUBNET should exist");
        assert_eq!(family, 1);
        assert_eq!(src, 24);
        assert_eq!(scope, 0);
        assert_eq!(addr, vec![1, 2, 3]); // /24 = 3 字节
    }

    #[test]
    fn injects_ipv6_subnet() {
        let q = build_dns_query(0);
        let new = set_client_subnet(Bytes::from(q), "2001:db8::".parse().unwrap(), 32);
        let (family, src, scope, addr) =
            extract_subnet_option(&new).expect("EDNS0_SUBNET should exist");
        assert_eq!(family, 2); // IPv6
        assert_eq!(src, 32);
        assert_eq!(scope, 0);
        // /32 = 4 字节 = 2001:0db8 → [0x20, 0x01, 0x0d, 0xb8]
        assert_eq!(addr, vec![0x20, 0x01, 0x0d, 0xb8]);
    }

    #[test]
    fn replaces_existing_subnet_in_opt() {
        // 原 query 已有 OPT + EDNS0_SUBNET=10.0.0.0/8 → 替换为 192.168.0.0/16
        let q = build_dns_query_with_opt_subnet(0, Some(("10.0.0.0".parse().unwrap(), 8)));
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 1); // ARCOUNT=1

        let new = set_client_subnet(Bytes::from(q), "192.168.0.0".parse().unwrap(), 16);

        // ARCOUNT 不变（替换 OPT 内容）
        assert_eq!(u16::from_be_bytes([new[10], new[11]]), 1);
        let (family, src, scope, addr) =
            extract_subnet_option(&new).expect("EDNS0_SUBNET should exist");
        assert_eq!(family, 1);
        assert_eq!(src, 16);
        assert_eq!(scope, 0);
        assert_eq!(addr, vec![192, 168]); // /16 = 2 字节
    }

    #[test]
    fn appends_subnet_to_opt_without_subnet() {
        // OPT RR 存在但无 EDNS0_SUBNET → 追加新选项
        let mut q = build_dns_query(0);
        // ARCOUNT=1
        q[10] = 0;
        q[11] = 1;
        // 空 RDATA 的 OPT RR
        q.push(0); // NAME = root
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&4096u16.to_be_bytes()); // CLASS = UDP payload
        q.extend_from_slice(&[0, 0, 0, 0]); // TTL = 0
        q.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0

        let new = set_client_subnet(Bytes::from(q.clone()), "1.2.3.0".parse().unwrap(), 24);

        // ARCOUNT 不变
        assert_eq!(u16::from_be_bytes([new[10], new[11]]), 1);
        // 应找到 EDNS0_SUBNET
        let (family, src, _, addr) =
            extract_subnet_option(&new).expect("EDNS0_SUBNET should exist");
        assert_eq!(family, 1);
        assert_eq!(src, 24);
        assert_eq!(addr, vec![1, 2, 3]);
    }

    #[test]
    fn preserves_opt_udp_payload_and_ttl() {
        // OPT RR 已有 UDP payload=1232 和 TTL=0x00010000 → 替换 subnet 时应保留
        let mut q = build_dns_query(0);
        q[10] = 0;
        q[11] = 1; // ARCOUNT=1
                   // OPT RR with custom values
        q.push(0); // NAME = root
        q.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
        q.extend_from_slice(&1232u16.to_be_bytes()); // CLASS = UDP payload size = 1232
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // TTL = 0x00010000
        q.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH = 0 (no options)

        let new = set_client_subnet(Bytes::from(q), "1.2.3.0".parse().unwrap(), 24);

        let opt_pos = find_opt_rr(&new).expect("OPT should exist");
        let after_name = skip_name(&new, opt_pos).unwrap();
        // TYPE = OPT = 41
        assert_eq!(
            u16::from_be_bytes([new[after_name], new[after_name + 1]]),
            41
        );
        // CLASS = UDP payload = 1232
        assert_eq!(
            u16::from_be_bytes([new[after_name + 2], new[after_name + 3]]),
            1232
        );
        // TTL = 0x00010000
        assert_eq!(
            u32::from_be_bytes([
                new[after_name + 4],
                new[after_name + 5],
                new[after_name + 6],
                new[after_name + 7]
            ]),
            0x00010000
        );
    }

    #[test]
    fn preserves_other_edns_options_when_replacing_subnet() {
        // OPT 同时含 EDNS0_SUBNET 和其他选项（如 EDNS0_COOKIE=10）→ 替换 subnet 时应保留 cookie
        let mut q = build_dns_query(0);
        q[10] = 0;
        q[11] = 1; // ARCOUNT=1
                   // 构造 RDATA: cookie + subnet
        let mut rdata = Vec::new();
        // EDNS0_COOKIE = 10, len=8, data=[1,2,3,4,5,6,7,8]
        rdata.extend_from_slice(&10u16.to_be_bytes());
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        // EDNS0_SUBNET = 8, len=8, data=[family=1, src=8, scope=0, addr=[10]]
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&8u16.to_be_bytes());
        rdata.extend_from_slice(&1u16.to_be_bytes()); // family
        rdata.push(8); // source netmask
        rdata.push(0); // scope netmask
        rdata.extend_from_slice(&[10u8]); // addr = 10.0.0.0/8 → 1 byte
                                          // OPT RR
        q.push(0);
        q.extend_from_slice(&41u16.to_be_bytes());
        q.extend_from_slice(&4096u16.to_be_bytes());
        q.extend_from_slice(&[0, 0, 0, 0]);
        q.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        q.extend_from_slice(&rdata);

        let new = set_client_subnet(Bytes::from(q), "192.168.0.0".parse().unwrap(), 16);

        // 验证 subnet 被替换
        let (family, src, _, addr) =
            extract_subnet_option(&new).expect("EDNS0_SUBNET should exist");
        assert_eq!(family, 1);
        assert_eq!(src, 16);
        assert_eq!(addr, vec![192, 168]);

        // 验证 cookie 仍存在（遍历 RDATA）
        let opt_pos = find_opt_rr(&new).unwrap();
        let after_name = skip_name(&new, opt_pos).unwrap();
        let rdlength = u16::from_be_bytes([new[after_name + 8], new[after_name + 9]]) as usize;
        let rdata = &new[after_name + 10..after_name + 10 + rdlength];
        let mut found_cookie = false;
        let mut o_pos = 0;
        while o_pos + 4 <= rdata.len() {
            let o_code = u16::from_be_bytes([rdata[o_pos], rdata[o_pos + 1]]);
            let o_len = u16::from_be_bytes([rdata[o_pos + 2], rdata[o_pos + 3]]) as usize;
            if o_code == 10 {
                found_cookie = true;
                assert_eq!(o_len, 8);
                assert_eq!(&rdata[o_pos + 4..o_pos + 12], &[1, 2, 3, 4, 5, 6, 7, 8]);
                break;
            }
            o_pos += 4 + o_len;
        }
        assert!(found_cookie, "EDNS0_COOKIE should be preserved");
    }

    #[test]
    fn prefix_zero_emits_empty_address() {
        // /0 → 0 字节 address
        let q = build_dns_query(0);
        let new = set_client_subnet(Bytes::from(q), "0.0.0.0".parse().unwrap(), 0);
        let (family, src, scope, addr) =
            extract_subnet_option(&new).expect("EDNS0_SUBNET should exist");
        assert_eq!(family, 1);
        assert_eq!(src, 0);
        assert_eq!(scope, 0);
        assert!(addr.is_empty());
    }

    #[test]
    fn non_byte_aligned_prefix_emits_partial_address() {
        // /20 → ceil(20/8)=3 字节
        let q = build_dns_query(0);
        let new = set_client_subnet(Bytes::from(q), "1.2.3.0".parse().unwrap(), 20);
        let (_, src, _, addr) = extract_subnet_option(&new).expect("EDNS0_SUBNET should exist");
        assert_eq!(src, 20);
        assert_eq!(addr.len(), 3);
        assert_eq!(addr, vec![1, 2, 3]);
    }

    #[test]
    fn invalid_prefix_len_returns_original() {
        // IPv4 prefix_len > 32 → 原样返回
        let q = build_dns_query(0);
        let new = set_client_subnet(
            Bytes::from(q.clone()),
            "1.2.3.0".parse().unwrap(),
            33, // 超过 IPv4 上限 32
        );
        assert_eq!(new.as_ref(), q.as_slice());
    }

    #[test]
    fn too_short_message_returns_original() {
        let short = vec![0u8; 5];
        let new = set_client_subnet(Bytes::from(short.clone()), "1.2.3.0".parse().unwrap(), 24);
        assert_eq!(new.as_ref(), &short[..]);
    }

    #[test]
    fn preserves_question_section() {
        // 注入后 Question 段必须保留
        let q = build_dns_query(0xABCD);
        let original_question = q[12..].to_vec();
        let new = set_client_subnet(Bytes::from(q), "1.2.3.0".parse().unwrap(), 24);
        // ID 不变
        assert_eq!(&new[0..2], &[0xAB, 0xCD]);
        // QDCOUNT=1
        assert_eq!(u16::from_be_bytes([new[4], new[5]]), 1);
        // Question 段应完整保留（OPT 在 Question 之后）
        let question_len = original_question.len();
        assert_eq!(&new[12..12 + question_len], &original_question[..]);
    }
}
