use bytes::Bytes;

pub(crate) fn question_section_end(msg: &[u8], offset: usize) -> Option<usize> {
    let mut i = offset;
    // 解析 QNAME
    loop {
        if i >= msg.len() {
            return None;
        }
        let len = msg[i] as usize;
        i += 1;
        if len == 0 {
            break;
        }
        // 高两位为 11 表示 compression pointer（Question 段不应有，但容错处理）
        if len & 0xC0 == 0xC0 {
            // pointer 占 2 字节，已读 1 字节，再读 1
            if i + 1 > msg.len() {
                return None;
            }
            i += 1;
            break;
        }
        // 普通 label
        i += len;
        if i > msg.len() {
            return None;
        }
    }
    // QTYPE(2) + QCLASS(2)
    if i + 4 > msg.len() {
        return None;
    }
    Some(i + 4)
}

/// 构造 rcode 响应。
///
/// 旧实现只输出 12 字节 header，flags 缺 AA/RD/RA 位且无 Question 段。
/// 新实现对齐 sing-box：flags 完整 + 回显 Question 段。
///
/// 若 query 的 Question 段解析失败，退化为只输出 header（QDCOUNT=0）。
fn build_rcode_response(query: &[u8], rcode: u8) -> Bytes {
    // 解析 query 的 QDCOUNT
    let qdcount: u16 = if query.len() >= 6 {
        u16::from_be_bytes([query[4], query[5]])
    } else {
        0
    };

    // 尝试解析 Question 段（仅 QDCOUNT >= 1 时）
    let question_end = if qdcount >= 1 {
        question_section_end(query, 12)
    } else {
        None
    };

    let id_bytes = if query.len() >= 2 {
        [query[0], query[1]]
    } else {
        [0, 0]
    };

    // flags: QR=1, AA=1, RD=1, RA=1, RCODE=rcode
    // byte2 = 0b1000_0101 = 0x85 (QR + AA + RD)
    // byte3 = 0b1000_xxxx = 0x80 | rcode (RA + RCODE)
    let flag_byte2: u8 = 0x85;
    let flag_byte3: u8 = 0x80 | (rcode & 0x0F);

    if let Some(end) = question_end {
        // 拷贝 header + Question 段
        let question_len = end - 12;
        let mut resp = Vec::with_capacity(12 + question_len);
        resp.extend_from_slice(&id_bytes);
        resp.push(flag_byte2);
        resp.push(flag_byte3);
        // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        resp.extend_from_slice(&query[12..end]);
        Bytes::from(resp)
    } else {
        // 退化路径：只输出 header（QDCOUNT=0）
        let resp = [
            id_bytes[0],
            id_bytes[1],
            flag_byte2,
            flag_byte3,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        Bytes::copy_from_slice(&resp)
    }
}

pub fn make_servfail(query: &[u8]) -> Bytes {
    build_rcode_response(query, 2)
}

pub fn make_refused(query: &[u8]) -> Bytes {
    build_rcode_response(query, 5)
}

pub fn make_noerror_empty(query: &[u8]) -> Bytes {
    build_rcode_response(query, 0)
}

pub fn make_nxdomain(query: &[u8]) -> Bytes {
    build_rcode_response(query, 3)
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个标准 DNS 查询：查询 example.com A
    fn build_query(qid: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&qid.to_be_bytes());
        // flags: RD=1
        q.push(0x01);
        q.push(0x00);
        // QDCOUNT=1
        q.extend_from_slice(&1u16.to_be_bytes());
        // ANCOUNT=0
        q.extend_from_slice(&0u16.to_be_bytes());
        // NSCOUNT=0
        q.extend_from_slice(&0u16.to_be_bytes());
        // ARCOUNT=0
        q.extend_from_slice(&0u16.to_be_bytes());
        // QNAME: \x07example\x03com\x00
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        // QTYPE=A=1
        q.extend_from_slice(&1u16.to_be_bytes());
        // QCLASS=IN=1
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[test]
    fn servfail_includes_question_and_flags() {
        let q = build_query(0xABCD);
        let r = make_servfail(&q);
        // 长度 = 12 (header) + 17 (question: \x07example\x03com\x00 + QTYPE + QCLASS)
        assert_eq!(r.len(), 12 + (1 + 7) + (1 + 3) + 1 + 4);
        // ID
        assert_eq!(&r[0..2], &[0xAB, 0xCD]);
        // flags byte2 = 0x85 (QR + AA + RD)
        assert_eq!(r[2], 0x85);
        // flags byte3 = 0x80 | 2 = 0x82 (RA + RCODE=SERVFAIL)
        assert_eq!(r[3], 0x82);
        // QDCOUNT=1
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 1);
        // Question 段回显
        assert_eq!(&r[12..], &q[12..]);
    }

    #[test]
    fn refused_rcode_5() {
        let q = build_query(0);
        let r = make_refused(&q);
        assert_eq!(r[3] & 0x0F, 5);
        assert_eq!(r[2], 0x85);
        assert_eq!(r[3] & 0xF0, 0x80); // RA bit set
    }

    #[test]
    fn noerror_rcode_0() {
        let q = build_query(0);
        let r = make_noerror_empty(&q);
        assert_eq!(r[3] & 0x0F, 0);
        assert_eq!(r[2], 0x85);
        assert_eq!(r[3] & 0xF0, 0x80); // RA bit set
    }

    #[test]
    fn nxdomain_rcode_3() {
        let q = build_query(0);
        let r = make_nxdomain(&q);
        assert_eq!(r[3] & 0x0F, 3);
        assert_eq!(r[2], 0x85);
        assert_eq!(r[3] & 0xF0, 0x80); // RA bit set
    }

    #[test]
    fn degraded_when_query_too_short() {
        // 仅 2 字节 ID
        let r = make_servfail(&[0xAB, 0xCD]);
        assert_eq!(r.len(), 12);
        assert_eq!(&r[0..2], &[0xAB, 0xCD]);
        assert_eq!(r[2], 0x85);
        assert_eq!(r[3], 0x82);
        // QDCOUNT=0
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 0);
    }

    #[test]
    fn degraded_when_qdcount_zero() {
        // header 完整但 QDCOUNT=0
        let q = vec![0, 0, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        let r = make_servfail(&q);
        assert_eq!(r.len(), 12);
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 0);
    }

    #[test]
    fn parses_ipv6_query_question() {
        // 构造查询 ipv6.google.com AAAA
        let mut q = Vec::new();
        q.extend_from_slice(&0u16.to_be_bytes()); // ID
        q.push(0x01);
        q.push(0x00);
        q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        // QNAME
        q.push(4);
        q.extend_from_slice(b"ipv6");
        q.push(6);
        q.extend_from_slice(b"google");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        // QTYPE=AAAA=28
        q.extend_from_slice(&28u16.to_be_bytes());
        // QCLASS=IN=1
        q.extend_from_slice(&1u16.to_be_bytes());

        let r = make_nxdomain(&q);
        assert_eq!(r.len(), 12 + (1 + 4) + (1 + 6) + (1 + 3) + 1 + 4);
        assert_eq!(&r[12..], &q[12..]);
        assert_eq!(r[3] & 0x0F, 3);
    }
}
