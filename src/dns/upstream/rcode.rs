//! 内置 rcode 上游：根据 `RcodeAction` 直接构造应答。

use bytes::Bytes;

use crate::config::dns::RcodeAction;
use crate::dns::{make_noerror_empty, make_nxdomain, make_refused};

pub(super) fn rcode_reply(query: &[u8], action: RcodeAction) -> Bytes {
    match action {
        RcodeAction::Refused => make_refused(query),
        RcodeAction::Success => make_noerror_empty(query),
        RcodeAction::NxDomain => make_nxdomain(query),
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rcode_refused() {
        // 标准 DNS 查询 example.com A
        let q = vec![
            0xAB, 0xCD, // ID
            0x01, 0x00, // flags: RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT/NSCOUNT/ARCOUNT=0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // QNAME end
            0x00, 0x01, // QTYPE=A
            0x00, 0x01, // QCLASS=IN
        ];
        let r = rcode_reply(&q, RcodeAction::Refused);
        // ID 回显
        assert_eq!(r[0], 0xAB);
        assert_eq!(r[1], 0xCD);
        // flags byte2 = 0x85 (QR + AA + RD)
        assert_eq!(r[2], 0x85);
        // RCODE=5, RA bit set
        assert_eq!(r[3] & 0x0F, 5);
        assert_eq!(r[3] & 0xF0, 0x80);
        // QDCOUNT=1
        assert_eq!(u16::from_be_bytes([r[4], r[5]]), 1);
        // Question 段回显
        assert_eq!(&r[12..], &q[12..]);
    }

    #[test]
    fn rcode_nxdomain() {
        let q = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let r = rcode_reply(&q, RcodeAction::NxDomain);
        assert_eq!(r[3] & 0x0F, 3);
        assert_eq!(r[2], 0x85); // flags 完整
    }

    #[test]
    fn rcode_success() {
        let q = vec![
            0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];
        let r = rcode_reply(&q, RcodeAction::Success);
        assert_eq!(r[3] & 0x0F, 0);
        assert_eq!(r[2], 0x85); // flags 完整
    }
}
