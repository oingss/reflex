//! WireGuard 协议原语公共包：outbound（客户端/发起方）与 inbound（服务端/响应方）
//! 共享的 Noise_IKpsk2 握手编解码、传输帧加解密、密钥解析与 IP 封装原语。
//!
//! 设计原则（对齐 `protocol/` 目录约定）：
//! - 只放纯算法/帧格式原语：常量、KDF、AEAD、握手消息编解码、IP 包封装。
//!   不含连接管理、会话状态机、I/O 调度（这些留在 outbound / inbound 各自实现）。
//! - 方向无关：`WgHandshake::build_initiation`（发起方）与
//!   `parse_initiation` / `build_response`（响应方）共存于同一模块。
//!
//! WireGuard 密码套件（白皮书固定）：
//!   Curve25519（ECDH）+ ChaCha20-Poly1305（AEAD）+ BLAKE2s-256（哈希/HMAC）
//!   + HMAC-BLAKE2s(KDF)，握手模式 Noise_IKpsk2。

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Context};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce,
};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

// ── WireGuard 协议常量 ────────────────────────────────────────────────────────

/// 消息类型：握手发起（Initiation，148 字节）
pub const MSG_INITIATION: u32 = 1;
/// 消息类型：握手响应（Response，92 字节）
pub const MSG_RESPONSE: u32 = 2;
/// 消息类型：Cookie 回复（过载保护，本实现不产生）
pub const MSG_COOKIE: u32 = 3;
/// 消息类型：传输数据
pub const MSG_DATA: u32 = 4;

/// Initiation 消息总长度
pub const INITIATION_LEN: usize = 148;
/// Response 消息总长度
pub const RESPONSE_LEN: usize = 92;
/// 传输数据包固定头长度（type 4B + receiver 4B + counter 8B）
pub const TRANSPORT_HEADER_LEN: usize = 16;
/// AEAD 认证标签长度
pub const AEAD_TAG_LEN: usize = 16;

// ── Noise 协议常量 ────────────────────────────────────────────────────────────

/// Noise 构造串（WireGuard 白皮书固定值）
pub const NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
/// WireGuard 协议标识串
pub const WG_IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
/// mac1 计算的标签常量
pub const LABEL_MAC1: &[u8] = b"mac1----";

// ── 密钥解码 ──────────────────────────────────────────────────────────────────

/// 解析 Base64 编码的 32 字节 WireGuard 密钥（私钥/公钥/PSK 通用）
pub fn decode_key_base64(s: &str) -> anyhow::Result<[u8; 32]> {
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
// 作为哈希与 HMAC 基元。

/// BLAKE2s-256 摘要
pub fn hash(data: &[u8]) -> [u8; 32] {
    use blake2::{ Blake2s256, Digest };
    let r = Blake2s256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

/// HMAC-BLAKE2s-256（RFC 2104），WireGuard Noise IKpsk2 的 MAC 构造即此。
///
/// 注意：不能使用 hmac 0.12 的 `Hmac<Blake2s256>`——blake2 0.10 的 Blake2s256
/// 使用 Lazy buffer，而 `hmac::Hmac<D>` 要求 `D::BufferKind == Eager`，二者
/// 类型不兼容，无法编译。故按 RFC 2104 手动实现：
///   HMAC(K, m) = H( (K' ⊕ opad) || H( (K' ⊕ ipad) || m ) )
///   block size = 64（BLAKE2s），ipad=0x36，opad=0x5c，K' 为 K 零填充到 64 字节。
pub fn hmac_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use blake2::{Blake2s256, Digest};
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

/// HKDF（2 输出）：WireGuard 握手中混入 DH 结果的标准 KDF
pub fn hkdf2(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
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

/// HKDF（3 输出）：PSK 混入与最终传输密钥派生使用
pub fn hkdf3(key: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
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

// ── ChaCha20-Poly1305 AEAD（WireGuard nonce 构造）─────────────────────────────

/// WireGuard AEAD 加密：nonce = 4 字节零 + 8 字节 LE counter
pub fn aead_encrypt(key: &[u8; 32], counter: u64, plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    cipher
        .encrypt(ChaChaNonce::from_slice(&nonce), Payload { msg: plain, aad })
        .expect("aead encrypt failed")
}

/// WireGuard AEAD 解密
pub fn aead_decrypt(
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

// ── TAI64N 时间戳 ─────────────────────────────────────────────────────────────

/// 当前时刻的 TAI64N 编码（8B BE 秒 + 4B BE 纳秒，TAI64 epoch 偏移）
pub fn tai64n_now() -> [u8; 12] {
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

// ── mac1 ──────────────────────────────────────────────────────────────────────

/// 派生 mac1 密钥：HASH(LABEL_MAC1 || 本端公钥)。
/// 发送方向：`本端公钥` 为消息接收方的公钥。
pub fn mac1_key_for(receiver_public: &[u8; 32]) -> [u8; 32] {
    let mut d = LABEL_MAC1.to_vec();
    d.extend_from_slice(receiver_public);
    hash(&d)
}

/// 计算 mac1：HMAC(mac1_key, msg 前缀)[:16]
pub fn compute_mac1(mac1_key: &[u8; 32], signed: &[u8]) -> [u8; 16] {
    let m = hmac_hash(mac1_key, signed);
    let mut out = [0u8; 16];
    out.copy_from_slice(&m[..16]);
    out
}

// ── 发起方（客户端）握手 ─────────────────────────────────────────────────────

/// Noise_IKpsk2 握手发起器。
///
/// 持有发起方静态密钥、对端静态公钥与可选 PSK，用于构建 Initiation 消息；
/// Response 到达后由调用方继续 Noise 状态机（见 outbound/wireguard.rs）。
pub struct WgHandshake {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
    pub peer_pub: [u8; 32],
    pub psk: Option<[u8; 32]>,
    pub chaining_key: [u8; 32],
    pub hash_val: [u8; 32],
}

impl WgHandshake {
    pub fn new(private_bytes: [u8; 32], peer_pub: [u8; 32], psk: Option<[u8; 32]>) -> Self {
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
    pub fn build_initiation(&self) -> (Vec<u8>, [u8; 32], [u8; 32], u32, StaticSecret) {
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
        // 混入响应方静态公钥（仅更新 h，ck 不动）
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
        // mac1 密钥由消息接收方（响应方）公钥派生
        let mac1_key = mac1_key_for(&self.peer_pub);

        // Build message
        let mut msg = Vec::with_capacity(INITIATION_LEN);
        msg.extend_from_slice(&MSG_INITIATION.to_le_bytes());
        msg.extend_from_slice(&sender_idx.to_le_bytes());
        msg.extend_from_slice(ephemeral_pub.as_bytes()); // 32B
        msg.extend_from_slice(&encrypted_static); // 32+16=48B
        msg.extend_from_slice(&encrypted_timestamp); // 12+16=28B

        // mac1 over all above
        let mac1 = compute_mac1(&mac1_key, &msg);
        msg.extend_from_slice(&mac1);
        // mac2 = zero (no cookie)
        msg.extend_from_slice(&[0u8; 16]);

        (msg, ck, h, sender_idx, ephemeral_secret)
    }
}

// ── 响应方（服务端）握手 ─────────────────────────────────────────────────────

/// 服务端解析 Initiation 后得到的中间状态：
/// 已完成 Noise 状态机到 `encrypted_timestamp` 为止的部分，
/// PSK 混入与 Response 构建交给 [`build_response`]。
pub struct InitiationHandshake {
    /// 发起方随机 sender index（Response 的 receiver_index 字段）
    pub sender_idx: u32,
    /// 发起方临时公钥（Response 阶段 ee/se DH 需要）
    pub initiator_ephemeral: [u8; 32],
    /// 解密出的发起方静态公钥（用于查找 peer 配置）
    pub initiator_static: [u8; 32],
    /// 解密出的 TAI64N 时间戳（防重放：必须严格大于上次值）
    pub timestamp: [u8; 12],
    /// Noise chaining key（PSK 混入前）
    pub chaining_key: [u8; 32],
    /// Noise hash（PSK 混入前）
    pub hash_val: [u8; 32],
}

/// 服务端：解析握手 Initiation（type=1，148 字节）。
///
/// 仅依赖本端静态密钥即可解出发起方静态公钥，无需预知对端身份，
/// 因此先解析再按 `initiator_static` 查 peer 表（对齐 sing-box
/// noise-protocol.go 的 LookupPeer 逻辑）。mac1 校验失败或 AEAD
/// 验证失败即拒绝（防伪造/篡改）。
pub fn parse_initiation(
    msg: &[u8],
    our_static: &StaticSecret,
    our_public: &PublicKey,
) -> anyhow::Result<InitiationHandshake> {
    if msg.len() < INITIATION_LEN {
        return Err(anyhow!(
            "WireGuard: initiation too short ({}, need {INITIATION_LEN})",
            msg.len()
        ));
    }
    let msg_type = u32::from_le_bytes(msg[0..4].try_into()?);
    if msg_type != MSG_INITIATION {
        return Err(anyhow!("WireGuard: expected initiation (1), got {msg_type}"));
    }

    // mac1 校验：mac1 密钥由消息接收方（本端）公钥派生，覆盖 msg[..116]
    let mac1_key = mac1_key_for(our_public.as_bytes());
    let expect_mac1 = compute_mac1(&mac1_key, &msg[..116]);
    if msg[116..132] != expect_mac1 {
        return Err(anyhow!("WireGuard: initiation mac1 mismatch"));
    }

    let sender_idx = u32::from_le_bytes(msg[4..8].try_into()?);
    let ephemeral_bytes: [u8; 32] = msg[8..40].try_into()?;
    let encrypted_static = &msg[40..88]; // 48B = 32B 静态公钥 + 16B tag
    let encrypted_timestamp = &msg[88..116]; // 28B = 12B TAI64N + 16B tag

    // ── Noise 状态初始化 ──────────────────────────────────────────────────────
    let ck = hash(NOISE_CONSTRUCTION);
    let mut h = hash(&{
        let mut d = ck.to_vec();
        d.extend_from_slice(WG_IDENTIFIER);
        d
    });
    // h = HASH(h || 本端静态公钥)
    h = hash(&{
        let mut d = h.to_vec();
        d.extend_from_slice(our_public.as_bytes());
        d
    });

    // ck, k = HKDF(ck, e)；h = HASH(h || e)
    let (ck, _k) = hkdf2(&ck, &ephemeral_bytes);
    h = hash(&{
        let mut d = h.to_vec();
        d.extend_from_slice(&ephemeral_bytes);
        d
    });

    // ck, k = HKDF(ck, DH(本端静态, 发起方临时))；解密发起方静态公钥
    let eph_pub = PublicKey::from(ephemeral_bytes);
    let dh_es = our_static.diffie_hellman(&eph_pub);
    let (ck, key) = hkdf2(&ck, dh_es.as_bytes());
    let static_plain = aead_decrypt(&key, 0, encrypted_static, &h)
        .map_err(|_| anyhow!("WireGuard: static key decrypt failed"))?;
    if static_plain.len() != 32 {
        return Err(anyhow!("WireGuard: decrypted static key wrong length"));
    }
    let initiator_static: [u8; 32] = static_plain.try_into().expect("length checked");
    h = hash(&{
        let mut d = h.to_vec();
        d.extend_from_slice(encrypted_static);
        d
    });

    // ck, k = HKDF(ck, DH(本端静态, 发起方静态))；解密 TAI64N 时间戳
    let initiator_pk = PublicKey::from(initiator_static);
    let dh_ss = our_static.diffie_hellman(&initiator_pk);
    let (ck, key) = hkdf2(&ck, dh_ss.as_bytes());
    let ts_plain = aead_decrypt(&key, 0, encrypted_timestamp, &h)
        .map_err(|_| anyhow!("WireGuard: timestamp decrypt failed"))?;
    if ts_plain.len() != 12 {
        return Err(anyhow!("WireGuard: decrypted timestamp wrong length"));
    }
    let timestamp: [u8; 12] = ts_plain.try_into().expect("length checked");
    h = hash(&{
        let mut d = h.to_vec();
        d.extend_from_slice(encrypted_timestamp);
        d
    });

    Ok(InitiationHandshake {
        sender_idx,
        initiator_ephemeral: ephemeral_bytes,
        initiator_static,
        timestamp,
        chaining_key: ck,
        hash_val: h,
    })
}

/// 服务端：基于 [`parse_initiation`] 的结果混入 PSK、构建 Response（type=2，
/// 92 字节）并派生传输密钥。
///
/// 返回 `(response 消息, send_key, recv_key)`（响应方视角：
/// send = k2，recv = k1；与发起方 `hkdf2(ck, "")` 的 (k1, k2) 对偶）。
pub fn build_response(
    init: &InitiationHandshake,
    psk: Option<[u8; 32]>,
    our_static: &StaticSecret,
    _our_public: &PublicKey,
    local_idx: u32,
) -> anyhow::Result<(Vec<u8>, [u8; 32], [u8; 32])> {
    // ── PSK 混入（HKDF3）：ck, tau, k = HKDF3(ck, psk)；h = HASH(h || tau) ────
    let psk_bytes = psk.unwrap_or([0u8; 32]);
    let (ck_psk, tau, _k) = hkdf3(&init.chaining_key, &psk_bytes);
    let mut h = hash(&{
        let mut d = init.hash_val.to_vec();
        d.extend_from_slice(&tau);
        d
    });

    // ── 响应方临时密钥：ck, k = HKDF(ck, ee)；h = HASH(h || ee) ───────────────
    let mut rng = rand::thread_rng();
    let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
    let ephemeral_pub = PublicKey::from(&ephemeral_secret);
    let (ck_e, _k) = hkdf2(&ck_psk, ephemeral_pub.as_bytes());
    h = hash(&{
        let mut d = h.to_vec();
        d.extend_from_slice(ephemeral_pub.as_bytes());
        d
    });

    // ── ee = DH(响应方临时, 发起方临时)：ck, k = HKDF(ck, ee) ───────────────
    let init_eph = PublicKey::from(init.initiator_ephemeral);
    let dh_ee = ephemeral_secret.diffie_hellman(&init_eph);
    let (ck_ee, _k) = hkdf2(&ck_e, dh_ee.as_bytes());

    // ── se = DH(本端静态, 发起方临时)：ck, k = HKDF(ck, se) ───────────────────
    let dh_se = our_static.diffie_hellman(&init_eph);
    let (ck_se, key) = hkdf2(&ck_ee, dh_se.as_bytes());

    // ── encrypted_nothing：AEAD(key, 0, "", h)；h = HASH(h || en) ─────────────
    let encrypted_nothing = aead_encrypt(&key, 0, &[], &h);
    // 规范要求更新 h = HASH(h || en)，但响应消息编码不再使用 h
    let _h_final = hash(&{
        let mut d = h.to_vec();
        d.extend_from_slice(&encrypted_nothing);
        d
    });

    // ── 传输密钥：(k1, k2) = HKDF(ck, "")；响应方 send = k2, recv = k1 ────────
    let (k1, k2) = hkdf2(&ck_se, &[]);

    // ── 编码 Response ─────────────────────────────────────────────────────────
    // mac1 密钥由消息接收方（发起方）公钥派生
    let mac1_key = mac1_key_for(&init.initiator_static);
    let mut msg = Vec::with_capacity(RESPONSE_LEN);
    msg.extend_from_slice(&MSG_RESPONSE.to_le_bytes());
    msg.extend_from_slice(&local_idx.to_le_bytes());
    msg.extend_from_slice(&init.sender_idx.to_le_bytes());
    msg.extend_from_slice(ephemeral_pub.as_bytes());
    msg.extend_from_slice(&encrypted_nothing);
    let mac1 = compute_mac1(&mac1_key, &msg);
    msg.extend_from_slice(&mac1);
    msg.extend_from_slice(&[0u8; 16]); // mac2 = zero（无 cookie）

    Ok((msg, k2, k1))
}

// ── 传输数据帧（type=4）──────────────────────────────────────────────────────

/// 构建传输数据包：`type(4) || receiver_idx(4) || counter(8) || AEAD(plain)`。
pub fn build_transport_packet(
    remote_idx: u32,
    counter: u64,
    send_key: &[u8; 32],
    plain: &[u8],
) -> Vec<u8> {
    let encrypted = aead_encrypt(send_key, counter, plain, &[]);
    let mut pkt = Vec::with_capacity(TRANSPORT_HEADER_LEN + encrypted.len());
    pkt.extend_from_slice(&MSG_DATA.to_le_bytes());
    pkt.extend_from_slice(&remote_idx.to_le_bytes());
    pkt.extend_from_slice(&counter.to_le_bytes());
    pkt.extend_from_slice(&encrypted);
    pkt
}

/// 解析传输数据包头部，返回 `(receiver_idx, counter, ciphertext)`。
/// 非数据包或长度不足时返回 None。
pub fn parse_transport_packet(pkt: &[u8]) -> Option<(u32, u64, &[u8])> {
    if pkt.len() < TRANSPORT_HEADER_LEN {
        return None;
    }
    let msg_type = u32::from_le_bytes(pkt[0..4].try_into().ok()?);
    if msg_type != MSG_DATA {
        return None;
    }
    let receiver_idx = u32::from_le_bytes(pkt[4..8].try_into().ok()?);
    let counter = u64::from_le_bytes(pkt[8..16].try_into().ok()?);
    Some((receiver_idx, counter, &pkt[16..]))
}

/// 解密传输数据载荷（AAD 为空）
pub fn decrypt_transport(recv_key: &[u8; 32], counter: u64, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    aead_decrypt(recv_key, counter, ciphertext, &[])
}

// ── IP 封装/解析原语 ──────────────────────────────────────────────────────────

/// 将 payload 封装为 IPv4/UDP 或 IPv6/UDP 包（用于通过 WireGuard 隧道发送）。
/// 与 sing-box gVisor netstack 行为对齐：根据 src/dst 地址族自动选择 IPv4 或 IPv6 封装。
pub fn build_udp_ip_packet(
    payload: &[u8],
    src: &SocketAddr,
    dst: &crate::inbound::Target,
) -> anyhow::Result<Vec<u8>> {
    let dst_addr = match dst {
        crate::inbound::Target::Socket(addr) => *addr,
        crate::inbound::Target::Domain(_, _) => {
            return Err(anyhow!(
                "WireGuard: domain target requires DNS resolution in tunnel"
            ));
        }
    };
    build_udp_ip_packet_inner(payload, *src, dst_addr)
}

fn build_udp_ip_packet_inner(
    payload: &[u8],
    src: SocketAddr,
    dst_addr: SocketAddr,
) -> anyhow::Result<Vec<u8>> {
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
pub fn parse_udp_ip_packet(pkt: &[u8]) -> anyhow::Result<(Vec<u8>, SocketAddr)> {
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
pub fn ipv6_udp_checksum(
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

/// IPv4/IPv6 头校验和（RFC 1071）
pub fn ip_checksum(header: &[u8]) -> u16 {
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

/// 校验解密后的明文 IP 包长度并截断到实际长度（对齐 sing-box receive.go）。
///
/// - IPv4: len >= 20, totalLen = BE(pkt[2:4]), 20 <= totalLen <= len
/// - IPv6: len >= 40, payloadLen = BE(pkt[4:6]) + 40, payloadLen <= len
///
/// 校验通过后截断到 totalLen/payloadLen，丢弃尾部填充。
/// 返回 false 表示包无效，应丢弃。
pub fn validate_and_truncate_ip_packet(pkt: &mut Vec<u8>) -> bool {
    match pkt.first().map(|b| b >> 4) {
        Some(4) => {
            if pkt.len() < 20 {
                return false;
            }
            let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            if total_len < 20 || total_len > pkt.len() {
                return false;
            }
            pkt.truncate(total_len);
            true
        }
        Some(6) => {
            if pkt.len() < 40 {
                return false;
            }
            let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            let expected = payload_len + 40;
            if expected > pkt.len() {
                return false;
            }
            pkt.truncate(expected);
            true
        }
        _ => false,
    }
}

/// 从原始 IP 包头提取源地址（用于 AllowedIPs 检查）
pub fn packet_src_ip(pkt: &[u8]) -> IpAddr {
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => {
            IpAddr::V4(std::net::Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]))
        }
        Some(6) if pkt.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[8..24]);
            IpAddr::V6(std::net::Ipv6Addr::from(octets))
        }
        _ => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    }
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
    fn transport_frame_roundtrip() {
        let key = [0x11u8; 32];
        let plain = b"ip packet bytes";
        let pkt = build_transport_packet(0xdeadbeef, 42, &key, plain);
        let (idx, counter, ct) = parse_transport_packet(&pkt).unwrap();
        assert_eq!(idx, 0xdeadbeef);
        assert_eq!(counter, 42);
        assert_eq!(decrypt_transport(&key, counter, ct).unwrap(), plain);
    }

    #[test]
    fn tai64n_format() {
        let ts = tai64n_now();
        assert_eq!(ts.len(), 12);
        // TAI64 seconds should be > 2^62 (2023+)
        let secs = u64::from_be_bytes(ts[..8].try_into().unwrap());
        assert!(secs > 4611686018427387914 + 1600000000);
    }

    /// 完整握手互通测试：发起方与响应方基于同一套原语完成
    /// Noise_IKpsk2 握手，双方派生的传输密钥必须一致且互通。
    #[test]
    fn handshake_roundtrip_initiator_responder() {
        let mut rng = rand::thread_rng();
        let initiator_priv = StaticSecret::random_from_rng(&mut rng);
        let responder_priv = StaticSecret::random_from_rng(&mut rng);
        let initiator_pub = PublicKey::from(&initiator_priv);
        let responder_pub = PublicKey::from(&responder_priv);
        let psk = Some([0x5au8; 32]);

        // 发起方构建 Initiation
        let hs = WgHandshake::new(
            initiator_priv.to_bytes(),
            responder_pub.to_bytes(),
            psk,
        );
        let (init_msg, ck_init, h_final, sender_idx, eph_secret) = hs.build_initiation();
        assert_eq!(init_msg.len(), INITIATION_LEN);

        // 响应方解析并构建 Response
        let init = parse_initiation(&init_msg, &responder_priv, &responder_pub).unwrap();
        assert_eq!(init.initiator_static, initiator_pub.to_bytes());
        let (resp, resp_send, resp_recv) =
            build_response(&init, psk, &responder_priv, &responder_pub, 0x7777).unwrap();
        assert_eq!(resp.len(), RESPONSE_LEN);

        // 发起方处理 Response（与 outbound/wireguard.rs 的流程一致）
        let mut h = h_final;
        let ephemeral_resp_bytes = &resp[12..44];
        let (ck_e, _k) = hkdf2(&ck_init, ephemeral_resp_bytes);
        h = hash(&{
            let mut d = h.to_vec();
            d.extend_from_slice(ephemeral_resp_bytes);
            d
        });
        let eph_resp = PublicKey::from(<[u8; 32]>::try_from(&resp[12..44]).unwrap());
        let dh_ee = eph_secret.diffie_hellman(&eph_resp);
        let (ck_se, _k) = hkdf2(&ck_e, dh_ee.as_bytes());
        // se：与响应方侧 DH(响应方静态, 发起方临时) 对偶，
        // 发起方 = DH(发起方临时私钥, 响应方静态公钥)
        let dh_se = eph_secret.diffie_hellman(&responder_pub);
        let (ck_final, key) = hkdf2(&ck_se, dh_se.as_bytes());
        let encrypted_nothing = &resp[44..60];
        let _dec = aead_decrypt(&key, 0, encrypted_nothing, &h).unwrap();
        let (init_send, init_recv) = hkdf2(&ck_final, &[]);

        assert_eq!(init_send, resp_recv);
        assert_eq!(init_recv, resp_send);

        // 传输互通
        let pkt = build_transport_packet(sender_idx, 0, &init_send, b"ping");
        let (_, _, ct) = parse_transport_packet(&pkt).unwrap();
        assert_eq!(decrypt_transport(&resp_recv, 0, ct).unwrap(), b"ping");
    }
}
