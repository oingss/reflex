use super::{packet::IpPacket, Packet};
use log::{error, trace};
use std::net::SocketAddr;
use tokio::sync::mpsc;

pub struct UdpPacket {
    pub data: Packet,
    /// src of the packet
    pub local_addr: SocketAddr,
    /// dst of the packet
    pub remote_addr: SocketAddr,
}
impl std::fmt::Debug for UdpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPacket")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .field("data_len", &self.data().len())
            .finish()
    }
}

impl<T> From<(T, SocketAddr, SocketAddr)> for UdpPacket
where
    T: Into<Packet>,
{
    fn from((data, local_addr, remote_addr): (T, SocketAddr, SocketAddr)) -> Self {
        UdpPacket {
            data: data.into(),
            local_addr,
            remote_addr,
        }
    }
}

impl UdpPacket {
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

pub struct UdpSocket {
    inbound: mpsc::UnboundedReceiver<Packet>,
}

impl UdpSocket {
    pub fn new(inbound: mpsc::UnboundedReceiver<Packet>) -> Self {
        Self { inbound }
    }

    /// 取出接收半部。
    ///
    /// UDP 回包由上层（gvisor.rs 的 UdpReplyEntry 回包 task）直接构造
    /// 原始 IP 包写回 TUN，不经过本 socket 的写半部，因此只需读半部。
    pub fn split(self) -> SplitRead {
        SplitRead { recv: self.inbound }
    }
}

pub struct SplitRead {
    recv: mpsc::UnboundedReceiver<Packet>,
}

impl SplitRead {
    pub async fn recv(&mut self) -> Option<UdpPacket> {
        self.recv.recv().await.and_then(|data| {
            let packet = match IpPacket::new_checked(data.data()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid IP packet: {err}");
                    return None;
                }
            };

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            // R3：跳过 IPv6 扩展头后再解析 UDP；旧实现 payload() 对带扩展头
            // 的包切片错位，UdpPacket::new_checked 必然失败（静默丢包）。
            let payload = match packet.transport() {
                Some((_, payload)) => payload,
                None => {
                    error!(
                        "cannot locate transport header: src_ip: {src_ip}, dst_ip: {dst_ip}"
                    );
                    return None;
                }
            };

            let packet = match smoltcp::wire::UdpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!(
                        "invalid err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, \
                         payload: {payload:?}"
                    );
                    return None;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            trace!("created UDP socket for {src_addr} <-> {dst_addr}");

            Some(UdpPacket {
                data: Packet::new(packet.payload().to_vec()),
                local_addr: src_addr,
                remote_addr: dst_addr,
            })
        })
    }
}
