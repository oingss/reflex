use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce,
};
use rand::RngCore;
use tokio::{net::UdpSocket, sync::Mutex, time};
use tracing::{info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    config::outbound::WireGuardOutboundConfig,
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{Outbound, OutboundStatus},
};

// ── WireGuard 协议常量 ────────────────────────────────────────────────────────

const MSG_INITIATION: u32 = 1;
const MSG_RESPONSE: u32 = 2;
const MSG_DATA: u32 = 4;

/// 握手超时
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// 会话超时（3 分钟，WG 规范为 180s）
const SESSION_TIMEOUT: Duration = Duration::from_secs(180);
/// keepalive 间隔（与 wireguard-go defaultPersistentKeepaliveInterval = 25s 对齐）
const KEEPALIVE_SECS: u64 = 25;

// ── Noise 协议常量 ────────────────────────────────────────────────────────────

const NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";

// ── 密钥解码 ──────────────────────────────────────────────────────────────────

fn decode_key_base64(s: &str) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .context("WireGuard key base64 decode failed")?;
    if bytes.len() != 32 {
        anyhow::bail!("WireGuard key must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// ── BLAKE2s-256（WireGuard Noise_IKpsk2 规范要求）─────────────────────────────
//
// WireGuard 规范（Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s）规定使用 BLAKE2s-256
// 作为哈希与 HMAC 基元。旧实现用 SHA-256 近似，导致握手 KDF/MAC 输出与真实
// WireGuard 服务端不匹配，任何标准 WG 服务端都会拒绝握手。
// blake2 crate 已在 outbound-net feature 下作为依赖项，直接使用即可。

fn hash(data: &[u8]) -> [u8; 32] {
    use blake2::Blake2s256;
    use blake2::Digest;
    let r = Blake2s256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn hmac_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
    // HMAC-BLAKE2s-256（RFC 2104），WireGuard Noise IKpsk2 的 MAC 构造即此。
    //
    // 注意：不能使用 hmac 0.12 的 Hmac<Blake2s256>——blake2 0.10 的 Blake2s256
    // 使用 Lazy buffer，而 hmac::Hmac<D> 要求 D::BufferKind == Eager，二者
    // 类型不兼容，无法编译。故按 RFC 2104 手动实现：
    //   HMAC(K, m) = H( (K' ⊕ opad) || H( (K' ⊕ ipad) || m ) )
    //   block size = 64（BLAKE2s），ipad=0x36，opad=0x5c，K' 为 K 零填充到 64 字节。
    const BLOCK_SIZE: usize = 64;
    let mut k_pad = [0u8; BLOCK_SIZE];
    // WireGuard 中 key 恒为 32 字节，必然 <= BLOCK_SIZE，直接零填充即可。
    // 此处仍按 RFC 2104 处理超长 key 的边界情况以保证通用正确性。
    if key.len() <= BLOCK_SIZE {
        k_pad[..key.len()].copy_from_slice(key);
    } else {
        let h = Blake2s256::digest(key);
        k_pad[..32].copy_from_slice(&h);
    }
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = k_pad[i] ^ 0x36;
        opad[i] = k_pad[i] ^ 0x5c;
    }
    // inner = H(ipad || data)
    let mut inner = Blake2s256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();
    // outer = H(opad || inner)
    let mut outer = Blake2s256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let r = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

fn hkdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let t1 = hmac_hash(key, &{
        let mut d = input.to_vec();
        d.push(0x01);
        d
    });
    let t2 = hmac_hash(key, &{
        let mut d = t1.to_vec();
        d.extend_from_slice(input);
        d.push(0x02);
        d
    });
    (t1, t2)
}

fn aead_encrypt(key: &[u8; 32], counter: u64, plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    cipher
        .encrypt(ChaChaNonce::from_slice(&nonce), Payload { msg: plain, aad })
        .expect("aead encrypt failed")
}

fn aead_decrypt(
    key: &[u8; 32],
    counter: u64,
    cipher_text: &[u8],
    aad: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    cipher
        .decrypt(
            ChaChaNonce::from_slice(&nonce),
            Payload {
                msg: cipher_text,
                aad,
            },
        )
        .map_err(|e| anyhow!("aead decrypt failed: {e}"))
}

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

// ── WireGuard 握手器 ──────────────────────────────────────────────────────────

#[allow(dead_code)]
pub(crate) struct WgHandshake {
    pub(crate) private_key: StaticSecret,
    pub(crate) public_key: PublicKey,
    pub(crate) peer_pub: [u8; 32],
    pub(crate) psk: Option<[u8; 32]>,
    pub(crate) chaining_key: [u8; 32],
    pub(crate) hash_val: [u8; 32],
}

impl WgHandshake {
    fn new(private_bytes: [u8; 32], peer_pub: [u8; 32], psk: Option<[u8; 32]>) -> Self {
        let private_key = StaticSecret::from(private_bytes);
        let public_key = PublicKey::from(&private_key);
        let initial_hash = hash(NOISE_CONSTRUCTION);
        let h = hash(&{
            let mut d = initial_hash.to_vec();
            d.extend_from_slice(WG_IDENTIFIER);
            d
        });
        let hash_val = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(&peer_pub);
            d
        });
        Self {
            private_key,
            public_key,
            peer_pub,
            psk,
            chaining_key: initial_hash,
            hash_val,
        }
    }

    /// 构建 Initiation 消息（type=1）
    ///
    /// 严格按照 WireGuard 白皮书（Noise_IKpsk2）流程：
    ///
    /// ```text
    /// ck = HASH(Construction)
    /// h  = HASH(ck || Identifier)
    /// h  = HASH(h || Spk_b)             ← 仅更新 h，不更新 ck
    ///
    /// ck, k = HKDF(ck, e)               ← 混入临时公钥
    /// h  = HASH(h || e)
    /// ck, k = HKDF(ck, DH(e, Spk_b))    ← 临时↔响应方静态
    /// encrypted_static = AEAD(k, 0, Si, h)
    /// h  = HASH(h || encrypted_static)
    /// ck, k = HKDF(ck, DH(si, Spk_b))   ← 发起方静态↔响应方静态
    /// encrypted_timestamp = AEAD(k, 0, TAI64N, h)
    /// h  = HASH(h || encrypted_timestamp)
    /// ck, tau, k = HKDF3(ck, psk)        ← PSK 混入
    /// h  = HASH(h || tau)
    /// ```
    ///
    /// 返回 (消息字节, 最终 chaining_key, 最终 h, sender_idx, ephemeral_secret)
    /// 以便后续处理 Response 时继续 Noise 状态机。
    fn build_initiation(&self) -> (Vec<u8>, [u8; 32], [u8; 32], u32, StaticSecret) {
        let mut rng = rand::thread_rng();

        let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
        let ephemeral_pub = PublicKey::from(&ephemeral_secret);

        let mut sender_index = [0u8; 4];
        rng.fill_bytes(&mut sender_index);
        let sender_idx = u32::from_le_bytes(sender_index);

        // ── 初始化 Noise 状态 ──────────────────────────────────────────────────
        let ck = hash(NOISE_CONSTRUCTION);
        let h = hash(&{
            let mut d = ck.to_vec();
            d.extend_from_slice(WG_IDENTIFIER);
            d
        });
        // 混入响应方静态公钥（仅更新 h，ck 不动——旧实现错误地将 peer_pub 混入 ck）
        let h = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(&self.peer_pub);
            d
        });

        // ── 临时密钥 ──────────────────────────────────────────────────────────
        let (ck, _k) = hkdf2(&ck, ephemeral_pub.as_bytes());
        let h = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(ephemeral_pub.as_bytes());
            d
        });

        // ── DH(ephemeral, responder_static) ───────────────────────────────────
        let peer_static = x25519_dalek::PublicKey::from(self.peer_pub);
        let dh_es = ephemeral_secret.diffie_hellman(&peer_static);
        let (ck, key) = hkdf2(&ck, dh_es.as_bytes());

        // encrypted_static：用当前 key 和 h(AAD) 加密发起方静态公钥
        let encrypted_static = aead_encrypt(&key, 0, self.public_key.as_bytes(), &h);
        let h = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(&encrypted_static);
            d
        });

        // ── DH(initiator_static, responder_static) ───────────────────────────
        let dh_ss = self.private_key.diffie_hellman(&peer_static);
        let (ck, key) = hkdf2(&ck, dh_ss.as_bytes());

        // encrypted_timestamp
        let ts = tai64n_now();
        let encrypted_timestamp = aead_encrypt(&key, 0, &ts, &h);
        let h = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(&encrypted_timestamp);
            d
        });

        // ── PSK 混入（HKDF3）─────────────────────────────────────────────────
        let psk_bytes = self.psk.unwrap_or([0u8; 32]);
        let (ck, tau, _k) = hkdf3(&ck, &psk_bytes);
        let h = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(&tau);
            d
        });

        // ── mac1 / mac2 ──────────────────────────────────────────────────────
        let mac1_key = hash(&{
            let mut d = LABEL_MAC1.to_vec();
            d.extend_from_slice(&self.peer_pub);
            d
        });

        // Build message
        let mut msg = Vec::with_capacity(148);
        msg.extend_from_slice(&MSG_INITIATION.to_le_bytes());
        msg.extend_from_slice(&sender_idx.to_le_bytes());
        msg.extend_from_slice(ephemeral_pub.as_bytes()); // 32B
        msg.extend_from_slice(&encrypted_static); // 32+16=48B
        msg.extend_from_slice(&encrypted_timestamp); // 12+16=28B

        // mac1 over all above
        let mac1 = &hmac_hash(&mac1_key, &msg)[..16];
        msg.extend_from_slice(mac1);
        // mac2 = zero (no cookie)
        msg.extend_from_slice(&[0u8; 16]);

        (msg, ck, h, sender_idx, ephemeral_secret)
    }
}

fn hkdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let t1 = hmac_hash(key, &{
        let mut d = input.to_vec();
        d.push(0x01);
        d
    });
    let t2 = hmac_hash(key, &{
        let mut d = t1.to_vec();
        d.extend_from_slice(input);
        d.push(0x02);
        d
    });
    let t3 = hmac_hash(key, &{
        let mut d = t2.to_vec();
        d.extend_from_slice(input);
        d.push(0x03);
        d
    });
    (t1, t2, t3)
}

fn tai64n_now() -> [u8; 12] {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() + 4611686018427387914u64; // TAI64 epoch offset
    let nanos = now.subsec_nanos();
    let mut buf = [0u8; 12];
    buf[..8].copy_from_slice(&secs.to_be_bytes());
    buf[8..].copy_from_slice(&nanos.to_be_bytes());
    buf
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
        let ephemeral_resp_pk = x25519_dalek::PublicKey::from({
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&ephemeral_resp_bytes[..32]);
            arr
        });
        let dh_ee = ephemeral_secret.diffie_hellman(&ephemeral_resp_pk);
        let (ck, _k) = hkdf2(&ck, dh_ee.as_bytes());

        // ck, k = HKDF(ck, DH(si, ee))  ← 发起方静态私钥 ↔ 响应方临时公钥
        let dh_se = hs.private_key.diffie_hellman(&ephemeral_resp_pk);
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
                    let encrypted = aead_encrypt(&sess.send_key, counter, &[], &[]);
                    let remote_idx = sess.remote_idx;
                    drop(guard);
                    let mut pkt = Vec::with_capacity(32 + encrypted.len());
                    pkt.extend_from_slice(&MSG_DATA.to_le_bytes());
                    pkt.extend_from_slice(&remote_idx.to_le_bytes());
                    pkt.extend_from_slice(&counter.to_le_bytes());
                    pkt.extend_from_slice(&encrypted);
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

        let encrypted = aead_encrypt(&sess.send_key, counter, plain, &[]);

        let mut pkt = Vec::with_capacity(32 + encrypted.len());
        pkt.extend_from_slice(&MSG_DATA.to_le_bytes());
        pkt.extend_from_slice(&sess.remote_idx.to_le_bytes());
        pkt.extend_from_slice(&counter.to_le_bytes());
        pkt.extend_from_slice(&encrypted);

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

        #[cfg(target_os = "linux")]
        if self.routing_mark != 0 {
            crate::outbound::apply_mark_to_udp(&udp, self.routing_mark)?;
        }

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

        #[cfg(target_os = "linux")]
        if self.routing_mark != 0 {
            crate::outbound::apply_mark_to_udp(&udp, self.routing_mark)?;
        }

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

// ── IP/UDP 封包辅助 ────────────────────────────────────────────────────────────

/// 将 payload 封装为 IPv4/UDP 或 IPv6/UDP 包（用于通过 WireGuard 隧道发送）。
/// 与 sing-box gVisor netstack 行为对齐：根据 src/dst 地址族自动选择 IPv4 或 IPv6 封装。
fn build_udp_ip_packet(payload: &[u8], src: &SocketAddr, dst: &Target) -> anyhow::Result<Vec<u8>> {
    let dst_addr = match dst {
        Target::Socket(addr) => *addr,
        Target::Domain(_, _) => {
            return Err(anyhow!(
                "WireGuard: domain target requires DNS resolution in tunnel"
            ));
        }
    };
    let is_v6 = src.is_ipv6() && dst_addr.is_ipv6();
    // 跨地址族拒绝（实际网络场景极罕见）
    if src.is_ipv4() != dst_addr.is_ipv4() && !is_v6 {
        return Err(anyhow!("WireGuard: mismatched address family"));
    }

    if is_v6 {
        let src_octets = match src.ip() {
            IpAddr::V6(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let dst_octets = match dst_addr.ip() {
            IpAddr::V6(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let udp_len = 8 + payload.len();
        let plen = udp_len as u16;
        let mut pkt = vec![0u8; 40 + udp_len];
        pkt[0] = 0x60;
        pkt[4] = (plen >> 8) as u8;
        pkt[5] = (plen & 0xff) as u8;
        pkt[6] = 0x11; // next header: UDP (17)
        pkt[7] = 64; // hop limit
        pkt[8..24].copy_from_slice(&src_octets);
        pkt[24..40].copy_from_slice(&dst_octets);
        pkt[40] = (src.port() >> 8) as u8;
        pkt[41] = (src.port() & 0xff) as u8;
        pkt[42] = (dst_addr.port() >> 8) as u8;
        pkt[43] = (dst_addr.port() & 0xff) as u8;
        pkt[44] = (udp_len >> 8) as u8;
        pkt[45] = (udp_len & 0xff) as u8;
        let cksum = ipv6_udp_checksum(&src_octets, &dst_octets, 17, &pkt[40..48], payload);
        pkt[46] = (cksum >> 8) as u8;
        pkt[47] = (cksum & 0xff) as u8;
        pkt[48..].copy_from_slice(payload);
        Ok(pkt)
    } else {
        let src_ip = match src.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let dst_ip = match dst_addr.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut pkt = vec![0u8; ip_len];
        pkt[0] = 0x45;
        pkt[1] = 0;
        let total = ip_len as u16;
        pkt[2] = (total >> 8) as u8;
        pkt[3] = (total & 0xff) as u8;
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src_ip);
        pkt[16..20].copy_from_slice(&dst_ip);
        let cksum = ip_checksum(&pkt[..20]);
        pkt[10] = (cksum >> 8) as u8;
        pkt[11] = (cksum & 0xff) as u8;
        pkt[20] = (src.port() >> 8) as u8;
        pkt[21] = (src.port() & 0xff) as u8;
        pkt[22] = (dst_addr.port() >> 8) as u8;
        pkt[23] = (dst_addr.port() & 0xff) as u8;
        pkt[24] = (udp_len >> 8) as u8;
        pkt[25] = (udp_len & 0xff) as u8;
        pkt[28..].copy_from_slice(payload);
        Ok(pkt)
    }
}

/// 解析 IP/UDP 包（IPv4 或 IPv6），返回 (payload, 源地址)
fn parse_udp_ip_packet(pkt: &[u8]) -> anyhow::Result<(Vec<u8>, SocketAddr)> {
    if pkt.len() < 20 {
        return Err(anyhow!("IP packet too short"));
    }
    let version = (pkt[0] >> 4) & 0xf;
    match version {
        4 => {
            if pkt.len() < 28 {
                return Err(anyhow!("IPv4 packet too short"));
            }
            let ihl = (pkt[0] & 0xf) as usize * 4;
            if pkt[9] != 17 {
                return Err(anyhow!("only UDP proto supported"));
            }
            let src_ip = std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
            let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let payload = pkt[ihl + 8..].to_vec();
            Ok((payload, SocketAddr::new(IpAddr::V4(src_ip), src_port)))
        }
        6 => {
            if pkt.len() < 48 {
                return Err(anyhow!("IPv6 packet too short"));
            }
            let nh = pkt[6];
            if nh == 0 {
                if pkt.len() < 50 {
                    return Err(anyhow!("IPv6+ext packet too short"));
                }
                if pkt[48..50] != [0x00, 0x11] {
                    return Err(anyhow!("IPv6: expected UDP frag"));
                }
            } else if nh != 17 {
                return Err(anyhow!("only UDP proto supported in IPv6"));
            }
            let header_end = 40usize;
            if pkt.len() < header_end + 8 {
                return Err(anyhow!("UDP header truncated"));
            }
            let src_ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).unwrap());
            let src_port = u16::from_be_bytes([pkt[header_end], pkt[header_end + 1]]);
            let payload = pkt[header_end + 8..].to_vec();
            Ok((payload, SocketAddr::new(IpAddr::V6(src_ip), src_port)))
        }
        _ => Err(anyhow!("unsupported IP version: {version}")),
    }
}

/// IPv6 UDP 伪头部校验和（RFC 2460 第 8.1 节）
fn ipv6_udp_checksum(
    src: &[u8; 16],
    dst: &[u8; 16],
    nxt: u8,
    udp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    let udp_len = 8 + payload.len() as u32;
    sum += udp_len >> 16;
    sum += udp_len & 0xffff;
    sum += nxt as u32;
    for w in udp_header.chunks(2) {
        let hi = w[0] as u32;
        let lo = if w.len() > 1 { w[1] as u32 } else { 0 };
        sum += (hi << 8) | lo;
    }
    for w in payload.chunks(2) {
        let hi = w[0] as u32;
        let lo = if w.len() > 1 { w[1] as u32 } else { 0 };
        sum += (hi << 8) | lo;
    }
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    if cksum == 0 {
        0xffff
    } else {
        cksum
    }
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn decode_key_valid() {
        // 32 bytes base64
        let key = base64::engine::general_purpose::STANDARD.encode([0x42u8; 32]);
        let decoded = decode_key_base64(&key).unwrap();
        assert_eq!(decoded, [0x42u8; 32]);
    }

    #[test]
    fn decode_key_invalid_length() {
        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        assert!(decode_key_base64(&key).is_err());
    }

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
    fn tai64n_format() {
        let ts = tai64n_now();
        assert_eq!(ts.len(), 12);
        // TAI64 seconds should be > 2^62 (2023+)
        let secs = u64::from_be_bytes(ts[..8].try_into().unwrap());
        assert!(secs > 4611686018427387914 + 1600000000);
    }

    #[test]
    fn hkdf2_deterministic() {
        let key = [1u8; 32];
        let input = b"test input";
        let (t1a, t2a) = hkdf2(&key, input);
        let (t1b, t2b) = hkdf2(&key, input);
        assert_eq!(t1a, t1b);
        assert_eq!(t2a, t2b);
        assert_ne!(t1a, t2a);
    }

    #[test]
    fn aead_roundtrip() {
        let key = [0x42u8; 32];
        let plain = b"WireGuard test payload";
        let cipher = aead_encrypt(&key, 0, plain, b"aad");
        let decrypted = aead_decrypt(&key, 0, &cipher, b"aad").unwrap();
        assert_eq!(&decrypted, plain);
    }

    #[test]
    fn udp_ip_packet_roundtrip() {
        let payload = b"hello wireguard";
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        let dst = Target::Socket("10.0.0.2:53".parse().unwrap());
        let pkt = build_udp_ip_packet(payload, &src, &dst).unwrap();
        let (decoded, src_addr) = parse_udp_ip_packet(&pkt).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(src_addr.port(), 12345);
    }
}
