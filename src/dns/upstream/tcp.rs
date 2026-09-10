use std::net::SocketAddr;

use bytes::Bytes;

use crate::outbound::Outbound;

use super::util::tcp_framed_exchange;

// ── 协议实现：TCP ─────────────────────────────────────────────────────────────

pub(super) async fn tcp_query(
    addr: SocketAddr,
    msg: Bytes,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] mark: u32,
) -> anyhow::Result<Bytes> {
    // 用 connect_tcp_interface 在 connect 之前把 socket 绑定到物理网卡
    // （Windows IP_UNICAST_IF / macOS IP_BOUND_IF）。旧实现
    // TcpStream::connect + 事后 apply_mark_to_tcp 在 Windows 上无效：
    // SYN 已按 TUN 接管后的默认路由发出并被丢弃，连接永远建立不起来。
    let mut stream = crate::outbound::connect_tcp_interface(addr)
        .await
        .map_err(|e| anyhow::anyhow!("TCP connect to {addr} failed: {e}"))?;
    #[cfg(target_os = "linux")]
    crate::outbound::apply_mark_to_tcp(&stream, mark)?;
    tcp_framed_exchange(&mut stream, msg).await
}

pub(super) async fn tcp_query_via_detour(
    outbound: &dyn Outbound,
    host: String,
    port: u16,
    msg: Bytes,
) -> anyhow::Result<Bytes> {
    tracing::debug!(detour = %outbound.tag(), host = %host, port, "dns tcp_query_via_detour: calling connect_tcp");
    let mut stream = outbound
        .connect_tcp(&host, port)
        .await
        .map_err(|e| {
            tracing::debug!(detour = %outbound.tag(), host = %host, port, err = %e, "dns tcp_query_via_detour: connect_tcp failed");
            e
        })?;
    tracing::debug!(detour = %outbound.tag(), host = %host, port, "dns tcp_query_via_detour: connected, exchanging");
    tcp_framed_exchange(stream.as_mut(), msg).await
}
