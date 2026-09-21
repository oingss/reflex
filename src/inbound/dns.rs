use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
};
use tracing::{debug, error, info, warn};

use crate::config::inbound::DnsInboundConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsQuerySource {
    /// 来自专用 DNS 入站（`dns-in` 监听端口直接接收的 DNS 查询）
    Inbound,
    /// 来自路由层 hijack_dns 规则（流量原本目标是 53 端口，被路由劫持）
    Hijacked,
}

/// 一次 DNS 查询请求，附带回复通道
#[derive(Debug)]
pub struct DnsQuery {
    /// 原始 DNS wire-format 查询报文
    pub message: Bytes,
    /// 查询来源（用于日志）
    pub from: SocketAddr,
    /// 来自哪个 dns-in tag
    pub inbound_tag: String,
    /// 查询来源类型（专用入站 / 路由劫持）
    pub source: DnsQuerySource,
    /// 回复通道：DNS 模块将 wire-format 响应写回此处
    pub reply_tx: oneshot::Sender<Bytes>,
}

pub type DnsQueryTx = mpsc::Sender<DnsQuery>;

// ── 入站主结构 ────────────────────────────────────────────────────────────────

pub struct DnsInbound {
    config: DnsInboundConfig,
    /// 向 DNS 解析器发送查询
    query_tx: DnsQueryTx,
}

impl DnsInbound {
    pub fn new(config: DnsInboundConfig, query_tx: DnsQueryTx) -> Self {
        Self { config, query_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind: SocketAddr =
            crate::inbound::parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let net = self.config.network;
        let tag = Arc::new(self.config.tag.clone());

        info!(tag = %tag, addr = %bind, "dns inbound starting");

        let mut handles = vec![];

        if net.udp() {
            let sock = UdpSocket::bind(bind).await?;
            let tx = self.query_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(async move { run_udp(sock, tx, tag).await }));
        }

        if net.tcp() {
            let listener = TcpListener::bind(bind).await?;
            let tx = self.query_tx.clone();
            let tag = tag.clone();
            handles.push(tokio::spawn(
                async move { run_tcp(listener, tx, tag).await },
            ));
        }

        for h in handles {
            h.await??;
        }
        Ok(())
    }
}

// ── UDP DNS ───────────────────────────────────────────────────────────────────

async fn run_udp(socket: UdpSocket, tx: DnsQueryTx, tag: Arc<String>) -> anyhow::Result<()> {
    let socket = Arc::new(socket);
    // 旧实现缓冲区仅 4096 字节，无法容纳 EDNS0 大包（RFC 6891 允许至 65535）。
    // DNSSEC 响应或大 OPT 记录会被静默截断，导致解析失败。
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, from) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                error!(err = %e, "dns udp recv error");
                continue;
            }
        };

        let message = Bytes::copy_from_slice(&buf[..n]);
        // 保留一份原始查询字节，用于在回复阶段按 EDNS0 截断
        let query_bytes = message.clone();
        let (reply_tx, reply_rx) = oneshot::channel();

        let query = DnsQuery {
            message,
            from,
            inbound_tag: (*tag).clone(),
            source: DnsQuerySource::Inbound,
            reply_tx,
        };

        let sock = socket.clone();
        let tx2 = tx.clone();

        tokio::spawn(async move {
            if tx2.send(query).await.is_err() {
                return;
            }
            match reply_rx.await {
                Ok(resp) => {
                    let mut resp = resp.to_vec();
                    // RFC 1035 / 6891: UDP DNS 响应必须按客户端 EDNS0 声明的大小截断并置 TC 位
                    truncate_dns_response(&query_bytes, &mut resp);
                    if let Err(e) = sock.send_to(&resp, from).await {
                        warn!(from = %from, err = %e, "dns udp reply error");
                    }
                }
                Err(_) => {
                    debug!(from = %from, "dns query dropped (no reply)");
                }
            }
        });
    }
}

/// 根据 RFC 1035 / RFC 6891 截断 UDP DNS 响应。
/// - 从查询消息中解析 EDNS0 OPT 记录获取客户端声明的 UDP payload size（无 EDNS0 默认 512）。
/// - 若响应超过该大小，设置 TC（Truncation）位并截断。
fn truncate_dns_response(query: &[u8], response: &mut Vec<u8>) {
    let max_size = edns0_udp_payload_size(query).unwrap_or(512);
    if response.len() <= max_size {
        return;
    }
    // 设置 TC 位（DNS header flags 的 bit 9，即 response[2] 的 bit 1）
    if response.len() >= 4 {
        response[2] |= 0x02;
    }
    response.truncate(max_size);
}

/// 从 DNS 查询消息中解析 EDNS0 OPT 记录的 UDP payload size。
/// 返回 None 表示没有 EDNS0（应使用 RFC 1035 默认 512）。
fn edns0_udp_payload_size(query: &[u8]) -> Option<usize> {
    if query.len() < 12 {
        return None;
    }
    let arcount = u16::from_be_bytes([query[10], query[11]]) as usize;
    if arcount == 0 {
        return None;
    }
    // 跳过 header (12 bytes)
    let mut cur = 12usize;
    // 跳过 QDCOUNT 个 question 条目
    let qdcount = u16::from_be_bytes([query[4], query[5]]) as usize;
    for _ in 0..qdcount {
        // 跳过 name（可能包含指针）
        if !skip_dns_name(query, &mut cur) {
            return None;
        }
        // type(2) + class(2)
        if cur + 4 > query.len() {
            return None;
        }
        cur += 4;
    }
    // 跳过 ANCOUNT + NSCOUNT 个 RR
    let ancount = u16::from_be_bytes([query[6], query[7]]) as usize;
    let nscount = u16::from_be_bytes([query[8], query[9]]) as usize;
    for _ in 0..(ancount + nscount) {
        if !skip_dns_name(query, &mut cur) {
            return None;
        }
        // type(2) + class(2) + ttl(4) + rdlength(2) + rdata(rdlength)
        if cur + 10 > query.len() {
            return None;
        }
        cur += 8; // type + class + ttl
        let rdlen = u16::from_be_bytes([query[cur], query[cur + 1]]) as usize;
        cur += 2;
        if cur + rdlen > query.len() {
            return None;
        }
        cur += rdlen;
    }
    // 遍历 ARCOUNT 个 Additional RR，找 OPT 记录
    for _ in 0..arcount {
        if !skip_dns_name(query, &mut cur) {
            return None;
        }
        if cur + 8 > query.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([query[cur], query[cur + 1]]);
        // OPT 记录的 name 应为 root (0x00)，type 应为 41 (0x29)
        // class 字段就是 UDP payload size
        if rtype == 41 {
            let payload_size = u16::from_be_bytes([query[cur + 2], query[cur + 3]]) as usize;
            // EDNS0 payload size 至少 512（RFC 6891）
            return Some(payload_size.max(512));
        }
        cur += 8; // type + class + ttl
        let rdlen = u16::from_be_bytes([query[cur], query[cur + 1]]) as usize;
        cur += 2;
        if cur + rdlen > query.len() {
            return None;
        }
        cur += rdlen;
    }
    None
}

/// 跳过 DNS name（处理压缩指针）。返回 false 表示解析失败。
fn skip_dns_name(msg: &[u8], cur: &mut usize) -> bool {
    loop {
        if *cur >= msg.len() {
            return false;
        }
        let len = msg[*cur];
        if len == 0 {
            *cur += 1;
            return true;
        }
        // 压缩指针（高 2 位为 11）
        if (len & 0xC0) == 0xC0 {
            *cur += 2;
            return true;
        }
        // 普通标签
        *cur += 1 + len as usize;
        if *cur > msg.len() {
            return false;
        }
    }
}

// ── TCP DNS（RFC 1035：2 字节长度前缀）────────────────────────────────────────

async fn run_tcp(listener: TcpListener, tx: DnsQueryTx, tag: Arc<String>) -> anyhow::Result<()> {
    loop {
        let (stream, from) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!(err = %e, "dns tcp accept error");
                continue;
            }
        };

        let tx2 = tx.clone();
        let tag2 = tag.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(stream, from, tx2, tag2).await {
                debug!(from = %from, err = %e, "dns tcp conn error");
            }
        });
    }
}

/// 单条 TCP 连接可能携带多个 DNS 查询（流水线），全部处理完再关闭
async fn handle_tcp_conn(
    mut stream: TcpStream,
    from: SocketAddr,
    tx: DnsQueryTx,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    loop {
        // DNS over TCP：先读 2 字节的消息长度
        // 加 30 秒读超时，避免空闲连接永久挂起泄漏任务
        let len = match tokio::time::timeout(std::time::Duration::from_secs(30), stream.read_u16())
            .await
        {
            Ok(Ok(v)) => v as usize,
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(anyhow::anyhow!("DNS TCP read timeout")),
        };

        // DNS-over-TCP 消息最大 65535 字节（2 字节长度前缀的极限）。
        // 旧实现限制 4096 会拒绝合法的 DNSSEC 大响应。
        anyhow::ensure!(len <= 65535, "DNS TCP message too large: {len}");

        let mut msg_buf = vec![0u8; len];
        stream.read_exact(&mut msg_buf).await?;
        let message = Bytes::from(msg_buf);

        let (reply_tx, reply_rx) = oneshot::channel::<Bytes>();

        tx.send(DnsQuery {
            message,
            from,
            inbound_tag: (*tag).clone(),
            source: DnsQuerySource::Inbound,
            reply_tx,
        })
        .await
        .map_err(|_| anyhow::anyhow!("dns resolver closed"))?;

        let resp = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("dns resolver dropped reply"))?;

        // 回复：2 字节长度 + 报文
        let resp_len = resp.len() as u16;
        stream.write_all(&resp_len.to_be_bytes()).await?;
        stream.write_all(&resp).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小的 DNS 查询报文（查 example.com A 记录）
    fn make_dns_query() -> Bytes {
        let raw: &[u8] = &[
            0x00, 0x01, // ID
            0x01, 0x00, // flags: QR=0 OPCODE=0 RD=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // QNAME: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm',
            0x00, // root label
            0x00, 0x01, // QTYPE  = A
            0x00, 0x01, // QCLASS = IN
        ];
        Bytes::copy_from_slice(raw)
    }

    #[tokio::test]
    async fn dns_query_channel() {
        let (tx, mut rx) = mpsc::channel::<DnsQuery>(4);

        let msg = make_dns_query();
        let (reply_tx, reply_rx) = oneshot::channel();

        tx.send(DnsQuery {
            message: msg.clone(),
            from: "127.0.0.1:12345".parse().unwrap(),
            inbound_tag: "dns-in".into(),
            source: DnsQuerySource::Inbound,
            reply_tx,
        })
        .await
        .unwrap();

        let q = rx.recv().await.unwrap();
        assert_eq!(q.message, msg);
        assert_eq!(q.inbound_tag, "dns-in");

        // 模拟 DNS 模块回复
        let fake_resp = Bytes::from_static(b"\x00\x01\x81\x80fake");
        q.reply_tx.send(fake_resp.clone()).unwrap();

        let resp = reply_rx.await.unwrap();
        assert_eq!(resp, fake_resp);
    }
}
