use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use tokio::{net::UdpSocket, sync::Mutex, time};
use tracing::{info, warn};
use x25519_dalek::PublicKey;

use crate::{
    config::outbound::WireGuardOutboundConfig,
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket},
    outbound::{Outbound, OutboundStatus},
    protocol::wireguard::{
        aead_decrypt, build_transport_packet, build_udp_ip_packet, decode_key_base64, hash, hkdf2,
        parse_udp_ip_packet, WgHandshake, MSG_DATA, MSG_RESPONSE,
    },
};

// 兼容再导出：以下原语历史上由本模块直接提供（同名私有函数/常量），现已迁移至
// 共享协议模块 `crate::protocol::wireguard`（inbound 服务端同样复用）。历史上
// 它们是私有的，外部唯一引用点是 `WireGuardOutbound::new`，故此处仅保留少量
// 同名再导出以防万一；`WgHandshake` 等已被上方 `use` 引入作用域，外部可直接从
// `crate::protocol::wireguard` 引用。
pub use crate::protocol::wireguard::{
    hkdf3, hmac_hash, ip_checksum, ipv6_udp_checksum, tai64n_now, MSG_INITIATION,
};

/// 握手超时
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// 会话超时（3 分钟，WG 规范为 180s）
const SESSION_TIMEOUT: Duration = Duration::from_secs(180);
/// keepalive 间隔（与 wireguard-go defaultPersistentKeepaliveInterval = 25s 对齐）
const KEEPALIVE_SECS: u64 = 25;

// ── WireGuard 会话状态 ────────────────────────────────────────────────────────

struct WgSession {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    remote_idx: u32,
    #[allow(dead_code)]
    local_idx: u32,
    send_counter: u64,
    established_at: Instant,
}

impl WgSession {
    fn is_expired(&self) -> bool {
        self.established_at.elapsed() > SESSION_TIMEOUT
    }
}

// ── WireGuard 出站 ────────────────────────────────────────────────────────────

pub struct WireGuardOutbound {
    config: WireGuardOutboundConfig,
    resolver: Option<Arc<DnsResolver>>,
    session: Arc<Mutex<Option<WgSession>>>,
    routing_mark: u32,
}

impl WireGuardOutbound {
    pub fn new(
        config: WireGuardOutboundConfig,
        resolver: Option<Arc<DnsResolver>>,
    ) -> anyhow::Result<Self> {
        // 验证私钥格式
        decode_key_base64(&config.private_key).context("WireGuard: invalid private_key")?;
        // 验证 peers 里的公钥格式
        for peer in config.resolved_peers() {
            if let Some(pk) = &peer.public_key {
                decode_key_base64(pk).context("WireGuard: invalid peer public_key")?;
            }
        }
        Ok(Self {
            config,
            resolver,
            session: Arc::new(Mutex::new(None)),
            routing_mark: 0,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    /// 解析服务端地址（从 peers 或简化字段）
    async fn resolve_server(&self) -> anyhow::Result<SocketAddr> {
        let peers = self.config.resolved_peers();
        let peer = peers
            .first()
            .ok_or_else(|| anyhow!("WireGuard: no peer configured"))?;
        let host = peer
            .address
            .as_deref()
            .ok_or_else(|| anyhow!("WireGuard: peer has no address"))?;
        let port = peer.port;
        if port == 0 {
            return Err(anyhow!("WireGuard: peer port is 0"));
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        if let Some(ref resolver) = self.resolver {
            // 对齐其他出站协议：使用 resolve_proxy_domain 走
            // dns.proxy_domain_resolver 指定的上游，而非 resolve_domain
            // （后者按 dns.rules 路由，可能命中 fakeip 或 block-dns）。
            // 旧实现调用 resolve_domain，导致 WireGuard 节点的 server 域名
            // 解析绕过了 proxy_domain_resolver 配置，可能被 fakeip 拦截。
            let ip = resolver
                .resolve_proxy_domain(host)
                .await
                .context("WireGuard: DNS resolve failed")?;
            return Ok(SocketAddr::new(ip, port));
        }
        use tokio::net::lookup_host;
        let mut addrs = lookup_host(format!("{host}:{port}")).await?;
        addrs
            .next()
            .ok_or_else(|| anyhow!("WireGuard: no address for {host}"))
    }

    /// 建立或复用 WireGuard 会话，返回加密后的 UDP socket
    async fn ensure_session(&self, udp: &UdpSocket, server_addr: SocketAddr) -> anyhow::Result<()> {
        let mut guard = self.session.lock().await;
        if let Some(ref s) = *guard {
            if !s.is_expired() {
                return Ok(());
            }
        }

        let private_bytes = decode_key_base64(&self.config.private_key)?;
        let peers = self.config.resolved_peers();
        let peer = peers
            .first()
            .ok_or_else(|| anyhow!("WireGuard: no peer configured"))?;
        let peer_pub_bytes = match &peer.public_key {
            Some(k) => decode_key_base64(k)?,
            None => return Err(anyhow!("WireGuard: peer has no public_key")),
        };
        let psk = match &peer.pre_shared_key {
            Some(k) => Some(decode_key_base64(k)?),
            None => None,
        };

        let hs = WgHandshake::new(private_bytes, peer_pub_bytes, psk);
        let (init_msg, ck, h, sender_idx, ephemeral_secret) = hs.build_initiation();

        // Send initiation
        udp.send_to(&init_msg, server_addr)
            .await
            .context("WireGuard: send initiation failed")?;

        // Wait for response
        let mut resp_buf = vec![0u8; 92];
        let timeout = time::timeout(HANDSHAKE_TIMEOUT, udp.recv(&mut resp_buf))
            .await
            .map_err(|_| anyhow!("WireGuard: handshake timeout"))?
            .context("WireGuard: recv response failed")?;

        if timeout < 60 {
            return Err(anyhow!("WireGuard: response too short ({timeout} bytes)"));
        }

        let msg_type = u32::from_le_bytes(resp_buf[..4].try_into()?);
        if msg_type != MSG_RESPONSE {
            return Err(anyhow!(
                "WireGuard: expected MSG_RESPONSE(2), got {msg_type}"
            ));
        }

        let remote_idx = u32::from_le_bytes(resp_buf[4..8].try_into()?);
        // receiver_index (us) at bytes 8..12
        let ephemeral_resp_bytes = &resp_buf[12..44]; // 32 bytes

        // ── Noise_IKpsk2 Response 处理 ─────────────────────────────────────────
        // 继续 Initiation 之后的 Noise 状态机：
        //
        // ck, k = HKDF(ck, ee)           ← 混入响应方临时公钥
        // h  = HASH(h || ee)
        // ck, k = HKDF(ck, DH(e, ee))   ← 发起方临时↔响应方临时
        // ck, k = HKDF(ck, DH(si, ee))  ← 发起方静态↔响应方临时
        // AEAD-verify encrypted_nothing   ← bytes 44..60
        // h  = HASH(h || encrypted_nothing)
        //
        // 最终传输密钥：
        // send_key = HKDF1(ck, "")
        // recv_key = HKDF2(ck, "")

        let mut h = h;

        // ck, k = HKDF(ck, ee)
        let (ck, _k) = hkdf2(&ck, ephemeral_resp_bytes);
        h = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(ephemeral_resp_bytes);
            d
        });

        // ck, k = HKDF(ck, DH(e, ee))   ← 发起方临时私钥 ↔ 响应方临时公钥
        let ephemeral_resp_pk = PublicKey::from({
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&ephemeral_resp_bytes[..32]);
            arr
        });
        let dh_ee = ephemeral_secret.diffie_hellman(&ephemeral_resp_pk);
        let (ck, _k) = hkdf2(&ck, dh_ee.as_bytes());

        // ck, k = HKDF(ck, DH(se))  ← 发起方临时私钥 ↔ 响应方静态公钥
        // （与响应方侧 DH(响应方静态私钥, 发起方临时公钥) 对偶，Noise IK 的 se）
        let dh_se =
            ephemeral_secret.diffie_hellman(&x25519_dalek::PublicKey::from(hs.peer_pub));
        let (ck, key) = hkdf2(&ck, dh_se.as_bytes());

        // 验证 encrypted_nothing (bytes 44..60, 即 16B AEAD tag of empty plaintext)
        let encrypted_nothing = &resp_buf[44..60];
        if let Ok(decrypted) = aead_decrypt(&key, 0, encrypted_nothing, &h) {
            if !decrypted.is_empty() {
                return Err(anyhow!("WireGuard: encrypted_nothing should be empty"));
            }
        } else {
            return Err(anyhow!(
                "WireGuard: handshake response AEAD verification failed"
            ));
        }
        // 注：Noise 规范要求在 AEAD 验证后更新 h = HASH(h || encrypted_nothing)，
        // 但传输密钥仅从 ck 派生，h 在此之后不再被读取，故省略以避免无效计算。

        // ── 传输密钥派生 ─────────────────────────────────────────────────────
        let (send_key, recv_key) = hkdf2(&ck, &[0u8; 0]);

        let session = WgSession {
            send_key,
            recv_key,
            remote_idx,
            local_idx: sender_idx,
            send_counter: 0,
            established_at: Instant::now(),
        };

        info!("WireGuard: session established with {server_addr} (remote_idx={remote_idx:#x})");
        *guard = Some(session);

        // 启动 WireGuard keepalive：定期发送空数据包保持 NAT 映射存活。
        // 与 wireguard-go `PersistentKeepaliveInterval` (默认 25s) 对齐。
        // 旧实现无 keepalive，长时间空闲后 NAT 映射过期，后续包被丢弃。
        // 需要 owned UdpSocket 才能在 spawned task 中使用，故通过 try_clone 从
        // connected socket 创建一个独立句柄。
        {
            let session = Arc::clone(&self.session);
            // 为 keepalive 创建独立的 owned UdpSocket。
            let bind_addr: SocketAddr = if server_addr.is_ipv6() {
                "[::]:0".parse().unwrap()
            } else {
                "0.0.0.0:0".parse().unwrap()
            };
            let keepalive_sock = UdpSocket::bind(bind_addr)
                .await
                .context("WireGuard keepalive bind")?;
            keepalive_sock
                .connect(server_addr)
                .await
                .context("WireGuard keepalive connect")?;
            tokio::spawn(async move {
                loop {
                    time::sleep(Duration::from_secs(KEEPALIVE_SECS)).await;
                    let mut guard = session.lock().await;
                    let Some(sess) = guard.as_mut() else {
                        break;
                    };
                    let counter = sess.send_counter;
                    sess.send_counter += 1;
                    let pkt = build_transport_packet(sess.remote_idx, counter, &sess.send_key, &[]);
                    drop(guard);
                    if keepalive_sock.send(&pkt).await.is_err() {
                        break;
                    }
                }
            });
        }
        Ok(())
    }

    /// 封装并发送一个 WireGuard 数据包
    async fn send_packet(&self, udp: &UdpSocket, plain: &[u8]) -> anyhow::Result<()> {
        let mut guard = self.session.lock().await;
        let sess = guard
            .as_mut()
            .ok_or_else(|| anyhow!("WireGuard: no active session"))?;

        let counter = sess.send_counter;
        sess.send_counter += 1;

        let pkt = build_transport_packet(sess.remote_idx, counter, &sess.send_key, plain);

        udp.send(&pkt)
            .await
            .context("WireGuard: send_packet failed")?;
        Ok(())
    }

    /// 接收并解密一个 WireGuard 数据包
    async fn recv_packet(&self, udp: &UdpSocket) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.config.mtu as usize + 32 + 16];
        let n = udp
            .recv(&mut buf)
            .await
            .context("WireGuard: recv_packet failed")?;
        let pkt = &buf[..n];

        if pkt.len() < 32 {
            return Err(anyhow!("WireGuard: data packet too short ({n} bytes)"));
        }

        let msg_type = u32::from_le_bytes(pkt[..4].try_into()?);
        if msg_type != MSG_DATA {
            return Err(anyhow!(
                "WireGuard: expected data packet, got type {msg_type}"
            ));
        }

        let counter = u64::from_le_bytes(pkt[8..16].try_into()?);
        let encrypted = &pkt[16..];

        let guard = self.session.lock().await;
        let sess = guard
            .as_ref()
            .ok_or_else(|| anyhow!("WireGuard: no session"))?;
        let plain = aead_decrypt(&sess.recv_key, counter, encrypted, &[])?;
        Ok(plain)
    }
}

#[async_trait::async_trait]
impl Outbound for WireGuardOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let server_addr = self.resolve_server().await?;

        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let udp = UdpSocket::bind(bind_addr)
            .await
            .context("WireGuard: bind UDP failed")?;

        // 不再限定 target_os = "linux"：apply_mark_to_udp 内部已经按平台分别
        // 处理（Linux 设 SO_MARK，Windows 用 IP_UNICAST_IF 绑定物理网卡防
        // TUN 环回），这里统一调用即可，避免 WireGuard 在 Windows 上完全没有
        // 防环回保护。
        crate::outbound::apply_mark_to_udp(&udp, self.routing_mark)?;

        udp.connect(server_addr)
            .await
            .context("WireGuard: UDP connect failed")?;

        self.ensure_session(&udp, server_addr).await?;

        warn!(
            tag = %self.config.tag,
            target = %conn.target,
            "WireGuard: TCP-over-WG requires TUN stack; not yet implemented"
        );

        Err(anyhow!(
            "WireGuard TCP-over-tunnel not yet fully implemented; \
             please use WireGuard as a system interface and route traffic through it"
        ))
    }

    async fn handle_udp(&self, pkt: InboundUdpPacket) -> anyhow::Result<()> {
        let server_addr = self.resolve_server().await?;

        let bind_addr: SocketAddr = if server_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let udp = UdpSocket::bind(bind_addr).await?;

        // 不再限定 target_os = "linux"：apply_mark_to_udp 内部已经按平台分别
        // 处理（Linux 设 SO_MARK，Windows 用 IP_UNICAST_IF 绑定物理网卡防
        // TUN 环回），这里统一调用即可，避免 WireGuard 在 Windows 上完全没有
        // 防环回保护。
        crate::outbound::apply_mark_to_udp(&udp, self.routing_mark)?;

        udp.connect(server_addr).await?;
        self.ensure_session(&udp, server_addr).await?;

        // Build IP/UDP packet wrapping the payload
        let ip_pkt = build_udp_ip_packet(&pkt.data, &pkt.src, &pkt.target)?;
        self.send_packet(&udp, &ip_pkt).await?;

        // Receive response
        let plain = self.recv_packet(&udp).await?;
        let (payload, src_addr) = parse_udp_ip_packet(&plain)?;

        let _ = pkt
            .session
            .reply_tx
            .send((bytes::Bytes::from(payload), pkt.src, src_addr))
            .await;
        Ok(())
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "wireguard".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // 密钥解码 / HKDF / AEAD / TAI64N / 握手互通等原语测试已随实现迁移至
    // 共享协议模块 crate::protocol::wireguard（见其 #[cfg(test)] 块）。
    // 此处保留 IP 封装相关测试（引用再导出的原语，验证兼容路径可用）。
    use super::*;
    use crate::protocol::wireguard::{ip_checksum, parse_udp_ip_packet, build_udp_ip_packet};

    #[test]
    fn ip_checksum_known_value() {
        // RFC 1071 example header with zero checksum field
        let hdr = [
            0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00,
            0x00, // checksum = 0
            0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c,
        ];
        let cksum = ip_checksum(&hdr);
        // 计算出的 checksum 应为 0xB1E6（RFC 1071 经典示例）
        assert_eq!(cksum, 0xB1E6);
        // 将 checksum 填回后再计算：ip_checksum 返回 ~sum，
        // 校验通过时 sum=0xFFFF，~sum=0x0000
        let mut h = hdr;
        h[10] = (cksum >> 8) as u8;
        h[11] = (cksum & 0xff) as u8;
        assert_eq!(ip_checksum(&h), 0x0000);
    }

    #[test]
    fn udp_ip_packet_roundtrip() {
        let payload = b"hello wireguard";
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let dst = crate::inbound::Target::Socket("10.0.0.2:53".parse().unwrap());
        let pkt = build_udp_ip_packet(payload, &src, &dst).unwrap();
        let (decoded, src_addr) = parse_udp_ip_packet(&pkt).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(src_addr.port(), 12345);
    }
}
