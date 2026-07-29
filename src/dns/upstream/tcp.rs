//! DNS-over-TCP 协议实现：每次查询建立新 TCP 连接，2 字节长度前缀帧。

use std::net::SocketAddr;

use bytes::Bytes;
use tokio::net::TcpStream;

use crate::outbound::Outbound;

use super::util::tcp_framed_exchange;

// ── 协议实现：TCP ─────────────────────────────────────────────────────────────

pub(super) async fn tcp_query(
    addr: SocketAddr,
    msg: Bytes,
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] mark: u32,
) -> anyhow::Result<Bytes> {
    let mut stream = TcpStream::connect(addr)
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
    let mut stream = outbound.connect_tcp(&host, port).await?;
    tcp_framed_exchange(stream.as_mut(), msg).await
}
