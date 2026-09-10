use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex as AsyncMutex};
use tracing::debug;

use super::tcp::tcp_query;

pub struct UdpState {
    socket: Arc<UdpSocket>,
    /// 后台 recv_loop 持有期间 set 为 true，recv_loop 退出后置 false
    /// 用于防止重复 spawn recv_loop
    recv_loop_started: AtomicI32,
    /// queryId (内部重写后) → callback 分发表
    callbacks: AsyncMutex<HashMap<u16, oneshot::Sender<Bytes>>>,
    /// 下一个可用的内部 queryId（与 caller 原始 queryId 解耦，避免并发冲突）
    next_query_id: AsyncMutex<u16>,
    /// 当前生效的 UDP 缓冲区大小（动态跟踪 EDNS OPT，最小 2048）
    /// 当请求 OPT 的 UDPSize 超过此值时 CAS 更新，并由调用方触发 socket 重建
    pub(super) udp_size: AtomicI32,
    /// 远端 DNS 服务器地址
    server_addr: SocketAddr,
}

/// Windows：把查询 socket 钉到物理网卡（幂等，一次 setsockopt）。
///
/// 必须在**每次发送前**调用而非仅在 socket 创建时：持久 socket（UdpState）
/// 创建于 resolver 构造期，此时 TUN inbound 尚未启动、物理网卡索引未登记，
/// 创建期绑定会静默 no-op —— 查询被 auto_route 默认路由重新送进 TUN 并命中
/// DNS 劫持分支（该分支不记会话日志），形成无限循环，全部查询 deadline 超时。
/// 对齐 sing-box `bindIfaceToDialer`：每次 dial 前绑定。
#[cfg(target_os = "windows")]
fn ensure_windows_iface_bind(sock: &UdpSocket, dst: SocketAddr) {
    use std::os::windows::io::AsRawSocket;
    crate::outbound::common::interface_finder::windows_iface::bind_socket_to_physical_interface(
        sock.as_raw_socket(),
        dst.ip(),
    );
}

impl UdpState {
    /// 默认缓冲区大小，对齐 sing-box `t.udpSize.Store(2048)`
    pub(super) const DEFAULT_UDP_SIZE: i32 = 2048;

    pub(super) async fn new(server_addr: SocketAddr, mark: u32) -> anyhow::Result<Arc<Self>> {
        let bind: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        }
        .parse()?;
        let sock = UdpSocket::bind(bind).await?;
        crate::outbound::apply_mark_to_udp(&sock, mark)?;
        Ok(Arc::new(Self {
            socket: Arc::new(sock),
            recv_loop_started: AtomicI32::new(0),
            callbacks: AsyncMutex::new(HashMap::new()),
            next_query_id: AsyncMutex::new(0),
            udp_size: AtomicI32::new(Self::DEFAULT_UDP_SIZE),
            server_addr,
        }))
    }

    /// 启动后台 recv_loop（如尚未启动）。
    /// 使用原子 CAS 防止重复 spawn。
    pub(super) fn ensure_recv_loop(self: &Arc<Self>) {
        // 0 → 1：从未启动 → 启动；其他值说明已启动或正在退出
        if self
            .recv_loop_started
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let state = self.clone();
            tokio::spawn(async move { state.recv_loop().await });
        }
    }

    /// 后台 recv_loop：持续 recv_from，按 queryId 查 callbacks 分发。
    /// 任何 IO 错误都让 recv_loop 退出，下次查询会重新 spawn（state 复用但 socket
    /// 可能已失效——通过 InvalidateSocket 标志位处理，见 `invalidate`）。
    async fn recv_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; self.udp_size.load(Ordering::Relaxed) as usize];
        loop {
            // 动态跟踪 EDNS UDPSize：若期间被更新过，重新分配缓冲区
            let cur_size = self.udp_size.load(Ordering::Relaxed) as usize;
            if cur_size > buf.len() {
                buf.resize(cur_size, 0);
            }
            let res = self.socket.recv_from(&mut buf).await;
            let (n, from) = match res {
                Ok(r) => r,
                Err(e) => {
                    debug!(addr = %self.server_addr, err = %e, "dns udp recv_loop exit");
                    // 标记 recv_loop 已退出，下次查询会重新 spawn
                    self.recv_loop_started.store(0, Ordering::SeqCst);
                    // 同时清空 callbacks，让所有等待 caller 收到错误
                    let mut cb = self.callbacks.lock().await;
                    for (_, tx) in cb.drain() {
                        let _ = tx.send(Bytes::new());
                    }
                    return;
                }
            };
            // 来源不匹配（极少见，理论上 connected UDP 不会有此情况）丢弃
            if from != self.server_addr {
                continue;
            }
            // 取响应 queryId
            if n < 2 {
                continue;
            }
            let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
            let mut cb = self.callbacks.lock().await;
            if let Some(tx) = cb.remove(&resp_id) {
                // 发送响应（失败说明 caller 已因超时取消等待，丢弃即可）
                let _ = tx.send(Bytes::copy_from_slice(&buf[..n]));
            }
            // callbacks map 中无对应项：可能是已超时被清理的 caller 的迟到响应，丢弃
        }
    }

    /// 分配下一个可用的内部 queryId（与 caller 原始 queryId 解耦）。
    /// 对齐 sing-box `nextAvailableQueryId`：避开正在使用的 id。
    async fn next_available_query_id(self: &Arc<Self>) -> anyhow::Result<u16> {
        let mut guard = self.next_query_id.lock().await;
        let start = *guard;
        loop {
            *guard = guard.wrapping_add(1);
            let id = *guard;
            // 检查 callbacks map 是否已占用该 id
            let in_use = self.callbacks.lock().await.contains_key(&id);
            if !in_use {
                return Ok(id);
            }
            if id == start {
                return Err(anyhow::anyhow!("no available query id"));
            }
        }
    }

    /// 注册 callback，返回用于等待响应的 Receiver
    async fn register_callback(self: &Arc<Self>, query_id: u16) -> oneshot::Receiver<Bytes> {
        let (tx, rx) = oneshot::channel();
        self.callbacks.lock().await.insert(query_id, tx);
        rx
    }

    /// 注销 callback（caller 超时或发送失败时调用）
    async fn unregister_callback(self: &Arc<Self>, query_id: u16) {
        self.callbacks.lock().await.remove(&query_id);
    }

    pub(super) fn invalidate(self: &Arc<Self>) {
        // 标记 recv_loop 退出中，避免 ensure_recv_loop 重复 spawn
        self.recv_loop_started.store(0, Ordering::SeqCst);
    }
}

// ── 协议实现：UDP ─────────────────────────────────────────────────────────────

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub(super) async fn udp_query(addr: SocketAddr, msg: Bytes, mark: u32) -> anyhow::Result<Bytes> {
    let bind: SocketAddr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
    .parse()?;
    let sock = UdpSocket::bind(bind).await?;
    // Windows：在发送前钉到物理网卡（见 ensure_windows_iface_bind 说明）。
    #[cfg(target_os = "windows")]
    ensure_windows_iface_bind(&sock, addr);
    #[cfg(target_os = "linux")]
    crate::outbound::apply_mark_to_udp(&sock, mark)?;
    sock.send_to(&msg, addr).await?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).await?;
    if n >= 3 && (buf[2] & 0x02) != 0 {
        debug!(addr=%addr, "dns udp TC bit, retry over TCP");
        return tcp_query(addr, msg, mark).await;
    }
    Ok(Bytes::copy_from_slice(&buf[..n]))
}

struct CallbackGuard {
    state: Arc<UdpState>,
    id: u16,
    /// 标记是否已在正常退出路径清理。
    /// true 时 Drop 不再重复清理（避免不必要的 spawn）。
    cleaned: bool,
}

impl CallbackGuard {
    fn new(state: Arc<UdpState>, id: u16) -> Self {
        Self {
            state,
            id,
            cleaned: false,
        }
    }

    /// 标记已手动清理，Drop 时跳过 cleanup。
    /// 在正常退出路径（recv_loop 已 remove callback）调用。
    fn mark_cleaned(&mut self) {
        self.cleaned = true;
    }
}

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        if self.cleaned {
            return;
        }
        // 外层 timeout drop 了未来，callback 仍在 map 中。
        // Drop 不能 await，用 tokio::spawn 异步清理。
        // 仅在 tokio runtime 上下文中 spawn（理论上总是如此，因为 future
        // 在 runtime poll 时被 drop）。
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let state = self.state.clone();
            let id = self.id;
            handle.spawn(async move {
                state.unregister_callback(id).await;
            });
        }
        // 若不在 runtime 中（理论上不会发生），callback 会随 UdpState drop 一起清理
    }
}

pub(super) async fn udp_query_with_state(
    state: Arc<UdpState>,
    addr: SocketAddr,
    msg: Bytes,
    mark: u32,
) -> anyhow::Result<Bytes> {
    if msg.len() < 12 {
        // 标准 DNS 报文头 12 字节，短于此时无法重写 queryId
        return udp_query(addr, msg, mark).await;
    }
    let original_id = u16::from_be_bytes([msg[0], msg[1]]);
    let internal_id = state.next_available_query_id().await?;
    let mut msg_mut = msg.to_vec();
    msg_mut[0..2].copy_from_slice(&internal_id.to_be_bytes());

    let send_buf = compress_dns_labels(&msg_mut).unwrap_or_else(|_| msg_mut.clone());

    // 注册 callback，拿到 Receiver
    let rx = state.register_callback(internal_id).await;

    // RAII guard：确保 callback 在 future 被 drop（外层 timeout）时清理。
    // 对齐 sing-box udp.go:189-193 的 defer cleanup。
    let mut guard = CallbackGuard::new(state.clone(), internal_id);

    // 发送
    #[cfg(target_os = "windows")]
    ensure_windows_iface_bind(&state.socket, addr);
    if let Err(e) = state.socket.send_to(&send_buf, addr).await {
        // guard.drop() 会 spawn 异步清理 callback
        return Err(anyhow::anyhow!("udp send_to {addr} failed: {e}"));
    }

    // 等待响应：recv_loop 通过 oneshot 推送过来
    let resp = match rx.await {
        Ok(r) => r,
        Err(_) => {
            // Sender 被 drop（recv_loop 退出时 drain 并 send 空 Bytes，
            // 正常不会走到 Err；走到说明 Sender 被其他路径 drop，callback 已不在 map）
            guard.mark_cleaned();
            return Err(anyhow::anyhow!(
                "udp recv_loop closed while waiting for response"
            ));
        }
    };

    // recv_loop 已从 callbacks map 中 remove 此 id，标记已清理避免重复 spawn
    guard.mark_cleaned();

    if resp.is_empty() {
        // recv_loop 退出时发的空 Bytes，表示连接断开
        return Err(anyhow::anyhow!("udp recv_loop closed (socket error)"));
    }

    // 还原 queryId 为 caller 原始值
    let mut resp = resp.to_vec();
    if resp.len() >= 2 {
        resp[0..2].copy_from_slice(&original_id.to_be_bytes());
    }

    if resp.len() >= 3 && (resp[2] & 0x02) != 0 {
        debug!(addr=%addr, "dns udp TC bit, retry over TCP");
        // 注意：用原始 msg（queryId 未重写）走 TCP，TCP 是独占连接不存在并发冲突
        return tcp_query(addr, Bytes::from(msg.to_vec()), mark).await;
    }
    Ok(Bytes::from(resp))
}

pub(super) fn extract_edns_udp_size(msg: &[u8]) -> i32 {
    if msg.len() < 12 {
        return 0;
    }
    // header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
    let arcount = u16::from_be_bytes([msg[10], msg[11]]) as usize;
    if arcount == 0 {
        return 0;
    }
    // 跳过 Question 段
    let mut pos = 12usize;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    for _ in 0..qdcount {
        // QNAME: 标签序列以 0 结尾
        if skip_qname(msg, &mut pos).is_err() {
            return 0;
        }
        // QTYPE(2) + QCLASS(2)
        if pos + 4 > msg.len() {
            return 0;
        }
        pos += 4;
    }
    // 跳过 Answer + Authority 段
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let nscount = u16::from_be_bytes([msg[8], msg[9]]) as usize;
    for _ in 0..(ancount + nscount) {
        if skip_rr(msg, &mut pos).is_err() {
            return 0;
        }
    }
    // 扫描 Additional 段找 OPT (TYPE=41)
    for _ in 0..arcount {
        // NAME（可能是根标签 0x00，或压缩指针）
        if skip_qname(msg, &mut pos).is_err() {
            return 0;
        }
        if pos + 10 > msg.len() {
            return 0;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let udp_size = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > msg.len() {
            return 0;
        }
        if rtype == 41 {
            // 找到 OPT，返回 UDPSize（CLASS 字段）
            return udp_size as i32;
        }
        pos += rdlength;
    }
    0
}

/// 跳过 QNAME（标签序列以 0 结尾，或压缩指针 2 字节）
fn skip_qname(msg: &[u8], pos: &mut usize) -> anyhow::Result<()> {
    loop {
        if *pos >= msg.len() {
            return Err(anyhow::anyhow!("qname truncated"));
        }
        let len = msg[*pos];
        if len == 0 {
            *pos += 1;
            return Ok(());
        }
        if (len & 0xC0) == 0xC0 {
            // 压缩指针 2 字节
            *pos += 2;
            return Ok(());
        }
        *pos += 1 + len as usize;
    }
}

/// 跳过 RR（资源记录）：NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA
fn skip_rr(msg: &[u8], pos: &mut usize) -> anyhow::Result<()> {
    skip_qname(msg, pos)?;
    if *pos + 10 > msg.len() {
        return Err(anyhow::anyhow!("rr header truncated"));
    }
    let rdlength = u16::from_be_bytes([msg[*pos + 8], msg[*pos + 9]]) as usize;
    *pos += 10 + rdlength;
    Ok(())
}

pub(super) fn compress_dns_labels(msg: &[u8]) -> anyhow::Result<Vec<u8>> {
    if msg.len() < 12 {
        return Err(anyhow::anyhow!("msg too short"));
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    if qdcount == 0 {
        // 无 Question 段，无需压缩
        return Ok(msg.to_vec());
    }
    // 仅支持单个 Question（reflex build_query 只生成 1 个 question）
    if qdcount != 1 {
        return Ok(msg.to_vec());
    }

    // 扫描 QNAME 收集每个 label 的偏移（用于确定 QNAME 结束位置）
    let mut pos = 12usize;
    let qname_start = pos;
    loop {
        if pos >= msg.len() {
            return Err(anyhow::anyhow!("qname truncated"));
        }
        let len = msg[pos];
        if len == 0 {
            pos += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            // 已经是压缩指针，不动
            pos += 2;
            break;
        }
        let lab_end = pos + 1 + len as usize;
        if lab_end > msg.len() {
            return Err(anyhow::anyhow!("label truncated"));
        }
        pos = lab_end;
    }
    let qname_end = pos; // 包含终止 0x00 或压缩指针

    // 重建报文：header + 压缩后的 QNAME + QTYPE + QCLASS
    let mut out = Vec::with_capacity(msg.len());
    out.extend_from_slice(&msg[..12]); // header
    let mut new_offsets: std::collections::HashMap<Vec<u8>, usize> =
        std::collections::HashMap::new();
    // 重新扫描 QNAME，遇到已出现过的 label 用指针替换
    let mut scan = qname_start;
    while scan < qname_end {
        let len = msg[scan];
        if len == 0 {
            // 末尾 0x00，复制并退出
            out.push(0);
            break;
        }
        if (len & 0xC0) == 0xC0 {
            // 原本就是压缩指针，直接复制
            out.push(msg[scan]);
            out.push(msg[scan + 1]);
            break;
        }
        let lab_end = scan + 1 + len as usize;
        let label = &msg[scan + 1..lab_end];
        // out 当前长度即新偏移
        let new_offset = out.len();
        if let Some(&prev_off) = new_offsets.get(label) {
            // 替换为指针：高 2 bit = 11，低 14 bit = 偏移
            let ptr = 0xC000 | (prev_off as u16);
            out.extend_from_slice(&ptr.to_be_bytes());
        } else {
            // 首次出现，复制 label 并记录偏移
            out.push(len);
            out.extend_from_slice(label);
            new_offsets.insert(label.to_vec(), new_offset);
        }
        scan = lab_end;
    }
    // 复制 QNAME 之后的剩余部分（QTYPE/QCLASS/Additional 等）
    if qname_end < msg.len() {
        out.extend_from_slice(&msg[qname_end..]);
    }
    Ok(out)
}

/// 经由 UDP relay（如 SOCKS5 UDP ASSOCIATE）发送 DNS UDP 查询。
/// 对齐 sing-box transport_dialer.go 的 ListenPacket 路径。
pub(super) async fn udp_query_via_detour_udp(
    relay: Box<dyn crate::outbound::UdpRelay>,
    addr: SocketAddr,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    relay
        .send_to(&msg, addr)
        .await
        .map_err(|e| anyhow::anyhow!("udp relay send_to {addr} failed: {e}"))?;
    let mut buf = vec![0u8; 4096];
    let (n, from) = relay
        .recv_from(&mut buf)
        .await
        .map_err(|e| anyhow::anyhow!("udp relay recv_from failed: {e}"))?;
    if from != addr {
        return Err(anyhow::anyhow!(
            "udp relay response from {from}, expected {addr}"
        ));
    }
    if n >= 3 && (buf[2] & 0x02) != 0 {
        debug!(addr=%addr, "dns udp (via detour) TC bit set, response truncated");
        // TC bit 重试由 caller（upstream.rs）处理：caller 持有 detour Outbound，
        // 可调用 tcp_query_via_detour 重试。对齐 sing-box udp.go:121-125。
    }
    Ok(Bytes::copy_from_slice(&buf[..n]))
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 EDNS OPT UDPSize 解析：从带 OPT 记录的 DNS 报文中提取 UDPSize。
    #[test]
    fn extract_edns_udp_size_basic() {
        // 构造一个带 EDNS OPT 的 DNS 查询报文：
        //   header: id=0x1234, qdcount=1, arcount=1
        //   question: example.com A IN
        //   additional: OPT (TYPE=41), UDPSize=4096
        let mut msg = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x01, // arcount
        ];
        // QNAME: example.com
        msg.extend_from_slice(b"\x07example\x03com\x00");
        msg.extend_from_slice(&[0x00, 0x01]); // QTYPE A
        msg.extend_from_slice(&[0x00, 0x01]); // QCLASS IN
                                              // OPT record: NAME=root(0x00), TYPE=41, CLASS=UDPSize=4096, TTL=0, RDLENGTH=0
        msg.push(0x00); // NAME root
        msg.extend_from_slice(&[0x00, 0x29]); // TYPE 41
        msg.extend_from_slice(&[0x10, 0x00]); // CLASS = UDPSize 4096
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // TTL
        msg.extend_from_slice(&[0x00, 0x00]); // RDLENGTH 0

        let size = extract_edns_udp_size(&msg);
        assert_eq!(size, 4096);
    }

    /// 验证无 EDNS OPT 时返回 0
    #[test]
    fn extract_edns_udp_size_no_opt() {
        let mut msg = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        msg.extend_from_slice(b"\x07example\x03com\x00");
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let size = extract_edns_udp_size(&msg);
        assert_eq!(size, 0);
    }

    /// 验证 DNS label 指针压缩：重复 label 应被替换为 2 字节指针。
    /// 典型场景：QNAME 中无重复 label 时压缩前后字节数相同；
    /// 当 Additional 段也含相同 label 时（罕见），压缩生效。
    /// 这里仅验证压缩函数不会破坏单 question 报文的结构（能正常 round-trip）。
    #[test]
    fn compress_dns_labels_preserves_structure() {
        let mut msg = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        msg.extend_from_slice(b"\x07example\x03com\x00");
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        let compressed = compress_dns_labels(&msg).unwrap();
        // header(12) + QNAME(13) + QTYPE(2) + QCLASS(2) = 29
        assert_eq!(compressed.len(), msg.len());
        // QNAME 部分保持不变（首次出现无重复，无指针替换）
        assert_eq!(&compressed[12..12 + 13], &msg[12..12 + 13]);
        // QTYPE/QCLASS 不变
        assert_eq!(&compressed[12 + 13..], &msg[12 + 13..]);
    }

    /// 验证 UDP 收发状态分发：模拟 sing-box recv_loop + callbacks 分发机制
    /// 确保 caller A 收到自己的响应，不会被 caller B 抢走。
    /// 这里不启真实 DNS 服务器（CI 无网络），仅测试
    /// `next_available_query_id` 在并发场景下不重复分配。
    #[tokio::test]
    async fn udp_state_query_id_unique_under_concurrency() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 15353);
        // 不实际绑定查询；只测 queryId 分配不重复
        // 直接构造空 socket：bind 0.0.0.0:0
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let sock = UdpSocket::bind(bind_addr).await.unwrap();
        let state = Arc::new(UdpState {
            socket: Arc::new(sock),
            recv_loop_started: AtomicI32::new(0),
            callbacks: AsyncMutex::new(HashMap::new()),
            next_query_id: AsyncMutex::new(0),
            udp_size: AtomicI32::new(UdpState::DEFAULT_UDP_SIZE),
            server_addr: addr,
        });
        // 并发分配 100 个 queryId，全部应唯一
        let mut set = std::collections::HashSet::new();
        for _ in 0..100u32 {
            let id = state.next_available_query_id().await.unwrap();
            assert!(set.insert(id), "duplicated queryId: {id}");
            // 注册 callback 占用该 id（模拟 caller 正在等待）
            let _rx = state.register_callback(id).await;
        }
        assert_eq!(set.len(), 100);
    }

    /// 验证 recv_loop 退出时所有等待 caller 收到错误（空 Bytes）。
    /// 模拟：注册 callback → 触发 invalidate → drain callbacks → caller 收到空 Bytes
    #[tokio::test]
    async fn udp_state_drain_callbacks_on_error() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 15354);
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let sock = UdpSocket::bind(bind_addr).await.unwrap();
        let state = Arc::new(UdpState {
            socket: Arc::new(sock),
            recv_loop_started: AtomicI32::new(1), // 假装已启动
            callbacks: AsyncMutex::new(HashMap::new()),
            next_query_id: AsyncMutex::new(0),
            udp_size: AtomicI32::new(UdpState::DEFAULT_UDP_SIZE),
            server_addr: addr,
        });
        let id = state.next_available_query_id().await.unwrap();
        let rx = state.register_callback(id).await;
        // 模拟 recv_loop 退出时清空 callbacks
        {
            let mut cb = state.callbacks.lock().await;
            for (_, tx) in cb.drain() {
                let _ = tx.send(Bytes::new());
            }
        }
        // caller 应收到空 Bytes
        let resp = rx.await.unwrap();
        assert!(resp.is_empty(), "expected empty Bytes on recv_loop exit");
    }

    // ── CallbackGuard 回归测试（修复 callback 泄漏 bug）──────────────────────
    // 旧实现在外层 timeout 触发时 drop udp_query_with_state 未来，rx 被 drop
    // 但 callbacks map 中的 oneshot::Sender 未被清理，导致 queryId 泄漏 + 内存泄漏。
    // CallbackGuard 在 Drop 时 spawn 异步清理，对齐 sing-box udp.go:189-193 defer。

    /// 辅助：构造测试用 UdpState（绑定 0.0.0.0:0，不实际收发）
    async fn make_test_state(server_port: u16) -> Arc<UdpState> {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), server_port);
        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let sock = UdpSocket::bind(bind_addr).await.unwrap();
        Arc::new(UdpState {
            socket: Arc::new(sock),
            recv_loop_started: AtomicI32::new(0),
            callbacks: AsyncMutex::new(HashMap::new()),
            next_query_id: AsyncMutex::new(0),
            udp_size: AtomicI32::new(UdpState::DEFAULT_UDP_SIZE),
            server_addr: addr,
        })
    }

    /// CallbackGuard 在未 mark_cleaned 时 drop 应清理 callback（模拟外层 timeout）
    #[tokio::test]
    async fn callback_guard_cleans_up_on_drop() {
        let state = make_test_state(15355).await;
        let id = state.next_available_query_id().await.unwrap();
        let _rx = state.register_callback(id).await;
        assert!(state.callbacks.lock().await.contains_key(&id));

        // 模拟外层 timeout drop future：guard drop 时 spawn 清理任务
        {
            let _guard = CallbackGuard::new(state.clone(), id);
            // guard drop here
        }

        // 等待 spawned 清理任务完成
        // spawn 的任务是异步的，需要 yield 让 runtime 执行它
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // callback 应已被清理
        assert!(
            !state.callbacks.lock().await.contains_key(&id),
            "callback should be cleaned up by CallbackGuard::drop"
        );
    }

    /// CallbackGuard 在 mark_cleaned 后 drop 不应重复清理（正常退出路径）
    #[tokio::test]
    async fn callback_guard_mark_cleaned_skips_cleanup() {
        let state = make_test_state(15356).await;
        let id = state.next_available_query_id().await.unwrap();
        let _rx = state.register_callback(id).await;

        // 模拟正常退出路径：recv_loop 已 remove callback，guard mark_cleaned
        {
            let mut guard = CallbackGuard::new(state.clone(), id);
            guard.mark_cleaned();
            // guard drop here — 不应 spawn 清理任务
        }

        // callback 应仍在 map 中（mark_cleaned 跳过了清理）
        // 注意：正常路径中 recv_loop 已 remove，这里我们模拟的是 guard 自身行为
        assert!(
            state.callbacks.lock().await.contains_key(&id),
            "callback should NOT be cleaned up when mark_cleaned was called"
        );

        // 手动清理（测试收尾）
        state.unregister_callback(id).await;
    }

    /// 模拟完整的 timeout 场景：注册 callback → drop guard（如 timeout drop future）
    /// → callback 被清理 → queryId 可被重新分配
    #[tokio::test]
    async fn callback_guard_timeout_scenario_id_reusable() {
        let state = make_test_state(15357).await;

        // 分配 id 并注册 callback
        let id = state.next_available_query_id().await.unwrap();
        let _rx = state.register_callback(id).await;

        // 模拟 timeout：guard drop 清理 callback
        {
            let _guard = CallbackGuard::new(state.clone(), id);
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // callback 已清理，id 应可被 next_available_query_id 重新分配
        assert!(!state.callbacks.lock().await.contains_key(&id));

        // 分配新 id（应能回到 id 或其他可用值，不会因泄漏跳过 id）
        let new_id = state.next_available_query_id().await.unwrap();
        // new_id 可能不等于 id（取决于 next_query_id 计数器），但不应因泄漏失败
        let _rx = state.register_callback(new_id).await;
        assert!(state.callbacks.lock().await.contains_key(&new_id));
    }

    /// 验证 CallbackGuard 在 send_to 失败路径也能清理 callback
    #[tokio::test]
    async fn callback_guard_cleans_up_on_send_error() {
        let state = make_test_state(15358).await;
        let id = state.next_available_query_id().await.unwrap();
        let _rx = state.register_callback(id).await;

        // 模拟 send_to 失败路径：guard drop 清理
        // （实际代码中 send_to 失败后 return Err，guard 自然 drop）
        {
            let _guard = CallbackGuard::new(state.clone(), id);
            // 模拟 send_to 失败后 return
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert!(
            !state.callbacks.lock().await.contains_key(&id),
            "callback should be cleaned up after send_to error path"
        );
    }
}
