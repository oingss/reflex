//! Shadowsocks 协议原语：inbound 服务端与 outbound 客户端共享。
//!
//! 覆盖：
//! - [`Method`] 加密方法枚举、key_len/salt_len/is_2022
//! - 密钥派生：EVP_BytesToKey（MD5 KDF）、HKDF-SHA1、BLAKE3 derive_key（SS2022）
//! - [`AeadCipher`] AEAD 编解码器（AES-GCM / ChaCha20-Poly1305），支持 nonce 计数
//! - SS2022 UDP 帧格式（AES 变体 / ChaCha20 变体）的 seal/open（含携带
//!   session_id 的 `*_with_session` 变体，供服务端回包会话追踪）
//! - SS2022 TCP 请求/响应 header 的构建与解析（[`ss2022_udp_build_server_body`]
//!   / [`ss2022_udp_parse_client_body`] / [`check_ss2022_timestamp`] 等服务端用）
//! - SOCKS 地址编解码（[`encode_target`] / [`parse_socks_addr`] / [`skip_socks5_addr`]）
//! - SS2022 帧常量与 header type
//!
//! 不含：TCP 连接管理（SsReader/SsWriter 的 I/O 调度）、relay 逻辑、
//! SS2022 TCP 请求/响应的时序编排（nonce=0,1,2... 的写入顺序属角色逻辑）。
//!
//! 对齐参考：sing-shadowsocks2 `shadowaead_2022/method.go`、`shadowaead/method.go`。

use crate::inbound::Target;
use aes_gcm::{aead::{AeadInPlace, KeyInit}, Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest as _, Md5};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

// ── 加密方法 ──────────────────────────────────────────────────────────────────

/// Shadowsocks 加密方法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Ss2022Aes128Gcm,
    Ss2022Aes256Gcm,
    Ss2022ChaCha20Poly1305,
    None,
}

impl Method {
    /// 从方法名解析（与 shadowsocks-rust `cipher.NewAeadCipher` 对齐）。
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Self::Aes128Gcm,
            "aes-256-gcm" => Self::Aes256Gcm,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Self::ChaCha20Poly1305,
            "2022-blake3-aes-128-gcm" => Self::Ss2022Aes128Gcm,
            "2022-blake3-aes-256-gcm" => Self::Ss2022Aes256Gcm,
            "2022-blake3-chacha20-poly1305" => Self::Ss2022ChaCha20Poly1305,
            "none" | "plain" => Self::None,
            other => anyhow::bail!("unsupported shadowsocks method: {other}"),
        })
    }

    /// 主密钥长度。
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Ss2022Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::Ss2022Aes256Gcm
            | Self::Ss2022ChaCha20Poly1305 => 32,
            Self::None => 0,
        }
    }

    /// salt 长度（与 key_len 相同）。
    pub fn salt_len(self) -> usize {
        self.key_len()
    }

    /// 是否为 SS2022 变体。
    pub fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm | Self::Ss2022ChaCha20Poly1305
        )
    }
}

// ── 常量 ──────────────────────────────────────────────────────────────────────

pub const TAG_LEN: usize = 16;
pub const MAX_PAYLOAD: usize = 0x3FFF;

/// SS 2022 BLAKE3 derive_key 上下文字符串
pub const SS2022_DERIVE_KEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

/// SS 2022 UDP AES 变体 header 长度（AES-ECB 加密的 sessionId+packetId）
pub const SS2022_AES_HEADER_LEN: usize = 16;
/// SS 2022 UDP ChaCha20 变体 nonce 长度
pub const SS2022_CHACHA_NONCE_LEN: usize = 24;

pub const SS2022_HEADER_TYPE_CLIENT: u8 = 0;
pub const SS2022_HEADER_TYPE_SERVER: u8 = 1;
pub const SS2022_MAX_PADDING: usize = 900;

/// SS2022 TCP 请求 fixed header 明文长度：type(1) + timestamp(8) + variableHeaderLen(2)
pub const SS2022_TCP_FIXED_HEADER_LEN: usize = 11;

/// SS2022 时间戳校验窗口（秒），对齐 shadowsocks-rust / sing-box（30s）。
pub const SS2022_MAX_TIMESTAMP_DIFF: u64 = 30;

/// 判断 SS2022 方法是否使用 AES 变体（需要 AES-ECB header）。
pub fn ss2022_is_aes(method: Method) -> bool {
    matches!(method, Method::Ss2022Aes128Gcm | Method::Ss2022Aes256Gcm)
}

// ── 密钥派生 ──────────────────────────────────────────────────────────────────

/// EVP_BytesToKey（MD5 KDF）：密码字符串 → master key。
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// HKDF-SHA1：master key + salt → session subkey（传统 AEAD）。
pub fn hkdf_sha1(master_key: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let hk = Hkdf::<sha1::Sha1>::new(Some(salt), master_key);
    let mut okm = vec![0u8; key_len];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("HKDF expand failed");
    okm
}

/// BLAKE3-KDF：PSK + salt → session subkey（AEAD-2022）。
///
/// SS 2022 规范使用 BLAKE3 的 `derive_key` 模式（而非 `keyed_hash`），
/// 上下文字符串为 `"shadowsocks 2022 session subkey"`。
pub fn ss2022_session_key(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(psk.len() + salt.len());
    input.extend_from_slice(psk);
    input.extend_from_slice(salt);
    let derived = blake3::derive_key(SS2022_DERIVE_KEY_CONTEXT, &input);
    derived[..key_len].to_vec()
}

// ── 时间戳辅助 ─────────────────────────────────────────────────────────────────

/// 当前 UNIX 时间（秒）。
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

/// 校验 SS2022 时间戳（±30s 窗口，防重放）。
pub fn check_ss2022_timestamp(ts: u64) -> anyhow::Result<()> {
    let diff = ts.abs_diff(now_unix_secs());
    if diff > SS2022_MAX_TIMESTAMP_DIFF {
        anyhow::bail!(
            "ss2022: timestamp diff {diff}s exceeds {}s limit",
            SS2022_MAX_TIMESTAMP_DIFF
        );
    }
    Ok(())
}

// ── AES-ECB 单块加解密（SS2022 UDP header） ────────────────────────────────────

/// AES-ECB 加密单个 16 字节块（使用 PSK 作为 key）。
pub fn aes_ecb_encrypt_block(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let mut b = aes::Block::clone_from_slice(block);
    if key.len() == 16 {
        let cipher = aes::Aes128::new_from_slice(key).expect("aes-128 key");
        cipher.encrypt_block(&mut b);
    } else {
        let cipher = aes::Aes256::new_from_slice(key).expect("aes-256 key");
        cipher.encrypt_block(&mut b);
    }
    block.copy_from_slice(&b);
}

/// AES-ECB 解密单个 16 字节块（使用 PSK 作为 key）。
pub fn aes_ecb_decrypt_block(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockDecrypt, KeyInit};
    if key.len() == 16 {
        let cipher = aes::Aes128::new_from_slice(key).expect("aes-128 key");
        let mut b = aes::Block::clone_from_slice(block);
        cipher.decrypt_block(&mut b);
        block.copy_from_slice(&b);
    } else {
        let cipher = aes::Aes256::new_from_slice(key).expect("aes-256 key");
        let mut b = aes::Block::clone_from_slice(block);
        cipher.decrypt_block(&mut b);
        block.copy_from_slice(&b);
    }
}

// ── AEAD 加解密器 ─────────────────────────────────────────────────────────────

/// AEAD 加解密器：封装 method + subkey + nonce counter。
///
/// `seal`/`open` 递增 counter（标准分帧用），`seal_with_nonce`/`open_with_nonce`
/// 不递增（SS2022 UDP 等自定义 nonce 场景用）。
pub struct AeadCipher {
    method: Method,
    subkey: Vec<u8>,
    counter: u64,
}

impl AeadCipher {
    pub fn new(method: Method, subkey: Vec<u8>) -> Self {
        Self {
            method,
            subkey,
            counter: 0,
        }
    }

    /// 使用指定的 subkey 创建（不递增 counter）。
    pub fn new_with_subkey(method: Method, subkey: Vec<u8>, counter: u64) -> Self {
        Self {
            method,
            subkey,
            counter,
        }
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// 使用指定的 nonce 加密，追加 16B tag（不递增 counter）。
    pub fn seal_with_nonce(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        let tag = self.seal_inner(buf, nonce)?;
        buf.extend_from_slice(&tag);
        Ok(())
    }

    /// 使用指定的 nonce 解密（含 trailing tag），去掉 tag（不递增 counter）。
    pub fn open_with_nonce(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        anyhow::ensure!(buf.len() >= TAG_LEN, "ciphertext too short");
        self.open_inner(buf, nonce)
    }

    /// 原地加密，追加 16B tag，递增 counter。
    pub fn seal(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        let nonce = self.nonce();
        let tag = self.seal_inner(buf, &nonce)?;
        buf.extend_from_slice(&tag);
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    /// 原地解密（含 trailing tag），去掉 tag，递增 counter。
    pub fn open(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        anyhow::ensure!(buf.len() >= TAG_LEN, "ciphertext too short");
        let nonce = self.nonce();
        self.open_inner(buf, &nonce)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(())
    }

    fn seal_inner(&self, buf: &mut [u8], nonce: &[u8; 12]) -> anyhow::Result<[u8; TAG_LEN]> {
        macro_rules! do_seal {
            ($C:ty) => {{
                let c = <$C>::new_from_slice(&self.subkey)
                    .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
                let tag = c
                    .encrypt_in_place_detached(nonce.into(), b"", buf)
                    .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
                let mut out = [0u8; TAG_LEN];
                out.copy_from_slice(tag.as_slice());
                out
            }};
        }
        Ok(match self.method {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => do_seal!(Aes128Gcm),
            Method::Aes256Gcm | Method::Ss2022Aes256Gcm => do_seal!(Aes256Gcm),
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => {
                do_seal!(ChaCha20Poly1305)
            }
            Method::None => [0u8; TAG_LEN],
        })
    }

    fn open_inner(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> anyhow::Result<()> {
        macro_rules! do_open {
            ($C:ty) => {{
                let c = <$C>::new_from_slice(&self.subkey)
                    .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
                c.decrypt_in_place(nonce.into(), b"", buf)
                    .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
            }};
        }
        match self.method {
            Method::Aes128Gcm | Method::Ss2022Aes128Gcm => do_open!(Aes128Gcm),
            Method::Aes256Gcm | Method::Ss2022Aes256Gcm => do_open!(Aes256Gcm),
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => {
                do_open!(ChaCha20Poly1305)
            }
            Method::None => {}
        }
        Ok(())
    }
}

// ── SS2022 UDP 帧格式 ──────────────────────────────────────────────────────────

/// 构建 SS 2022 UDP 帧（AES 变体）。
///
/// `body_plaintext` 应已包含 `[headerType][timestamp][paddingLen][padding][SOCKS_addr][payload]`。
pub fn ss2022_udp_seal_aes(
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
    body: &mut Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let key_len = psk.len();

    let mut hdr = [0u8; 16];
    hdr[..8].copy_from_slice(&session_id.to_be_bytes());
    hdr[8..].copy_from_slice(&packet_id.to_be_bytes());

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hdr[4..16]);

    let sid_bytes = session_id.to_be_bytes();
    let subkey = ss2022_session_key(psk, &sid_bytes, key_len);

    let method = if key_len == 16 {
        Method::Ss2022Aes128Gcm
    } else {
        Method::Ss2022Aes256Gcm
    };
    let cipher = AeadCipher::new_with_subkey(method, subkey, 0);
    cipher.seal_with_nonce(body, &nonce)?;

    aes_ecb_encrypt_block(&mut hdr, psk);

    let mut wire = Vec::with_capacity(SS2022_AES_HEADER_LEN + body.len());
    wire.extend_from_slice(&hdr);
    wire.extend_from_slice(body);
    Ok(wire)
}

/// 解密 SS 2022 UDP 帧（AES 变体）。返回解密后的 body 明文。
pub fn ss2022_udp_open_aes(psk: &[u8], buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    ss2022_udp_open_aes_with_session(psk, buf).map(|(_, body)| body)
}

/// 解密 SS 2022 UDP 帧（AES 变体），返回 `(session_id, body 明文)`。
///
/// 服务端需要 session_id 以在响应 body 中回显 clientSessionId。
pub fn ss2022_udp_open_aes_with_session(psk: &[u8], buf: &[u8]) -> anyhow::Result<(u64, Vec<u8>)> {
    anyhow::ensure!(
        buf.len() > SS2022_AES_HEADER_LEN + TAG_LEN,
        "ss2022 udp: frame too short"
    );

    let key_len = psk.len();

    let mut hdr = [0u8; 16];
    hdr.copy_from_slice(&buf[..SS2022_AES_HEADER_LEN]);
    aes_ecb_decrypt_block(&mut hdr, psk);

    let session_id = u64::from_be_bytes(hdr[..8].try_into().unwrap());

    let sid_bytes = session_id.to_be_bytes();
    let subkey = ss2022_session_key(psk, &sid_bytes, key_len);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hdr[4..16]);

    let mut ct = buf[SS2022_AES_HEADER_LEN..].to_vec();
    let method = if key_len == 16 {
        Method::Ss2022Aes128Gcm
    } else {
        Method::Ss2022Aes256Gcm
    };
    let cipher = AeadCipher::new_with_subkey(method, subkey, 0);
    cipher.open_with_nonce(&mut ct, &nonce)?;
    Ok((session_id, ct))
}

/// 构建 SS 2022 UDP 帧（ChaCha20 变体，使用 XChaCha20-Poly1305）。
pub fn ss2022_udp_seal_chacha(
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
    nonce_24: &[u8; 24],
    body: &mut [u8],
) -> anyhow::Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        XChaCha20Poly1305,
    };

    let mut plaintext = Vec::with_capacity(16 + body.len());
    plaintext.extend_from_slice(&session_id.to_be_bytes());
    plaintext.extend_from_slice(&packet_id.to_be_bytes());
    plaintext.extend_from_slice(body);

    let cipher = XChaCha20Poly1305::new_from_slice(psk)
        .map_err(|e| anyhow::anyhow!("xchacha20 key init: {e}"))?;
    let tag = cipher
        .encrypt_in_place_detached(nonce_24.into(), b"", &mut plaintext)
        .map_err(|e| anyhow::anyhow!("xchacha20 encrypt: {e}"))?;

    let mut wire = Vec::with_capacity(SS2022_CHACHA_NONCE_LEN + plaintext.len() + TAG_LEN);
    wire.extend_from_slice(nonce_24);
    wire.extend_from_slice(&plaintext);
    wire.extend_from_slice(&tag);
    Ok(wire)
}

/// 解密 SS 2022 UDP 帧（ChaCha20 变体）。返回去掉前 16B 后的 body 明文。
pub fn ss2022_udp_open_chacha(psk: &[u8], buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    ss2022_udp_open_chacha_with_session(psk, buf).map(|(_, body)| body)
}

/// 解密 SS 2022 UDP 帧（ChaCha20 变体），返回 `(session_id, body 明文)`。
///
/// ChaCha20 变体的 sessionId/packetId 位于明文前 16B（与 AES 变体的
/// ECB 加密 header 不同），解密后一并取出。
pub fn ss2022_udp_open_chacha_with_session(
    psk: &[u8],
    buf: &[u8],
) -> anyhow::Result<(u64, Vec<u8>)> {
    use chacha20poly1305::{
        aead::{AeadInPlace, KeyInit},
        XChaCha20Poly1305,
    };

    anyhow::ensure!(
        buf.len() > SS2022_CHACHA_NONCE_LEN + TAG_LEN,
        "ss2022 udp chacha: frame too short"
    );

    let nonce_24: &[u8; 24] = buf[..SS2022_CHACHA_NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce slice"))?;

    let mut ct = buf[SS2022_CHACHA_NONCE_LEN..].to_vec();
    let cipher = XChaCha20Poly1305::new_from_slice(psk)
        .map_err(|e| anyhow::anyhow!("xchacha20 key init: {e}"))?;
    cipher
        .decrypt_in_place(nonce_24.into(), b"", &mut ct)
        .map_err(|e| anyhow::anyhow!("xchacha20 decrypt: {e}"))?;

    anyhow::ensure!(ct.len() >= 16, "ss2022 udp chacha: body too short");
    let session_id = u64::from_be_bytes(ct[..8].try_into().unwrap());
    Ok((session_id, ct[16..].to_vec()))
}

// ── SOCKS 地址编解码 ──────────────────────────────────────────────────────────
//
// SS 的 ATYP：IPv4=0x01, Domain=0x03, IPv6=0x04（注意 IPv6 与 VLESS 不同）

/// SS SOCKS 地址：将目标编码为 `[ATYP][ADDR][PORT 2B BE]`（无长度前缀）。
pub fn encode_target(target: &Target) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    match target {
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buf.push(0x04);
                buf.extend_from_slice(&ip.octets());
            }
        },
        Target::Domain(host, _) => {
            buf.push(0x03);
            let b = host.as_bytes();
            buf.push(b.len() as u8);
            buf.extend_from_slice(b);
        }
    }
    buf.extend_from_slice(&target.port().to_be_bytes());
    buf
}

/// 解析 SS SOCKS 地址，返回 (消耗字节数, 目标地址)。
pub fn parse_socks_addr(data: &[u8]) -> anyhow::Result<(usize, Target)> {
    anyhow::ensure!(!data.is_empty(), "truncated");
    let atyp = data[0];
    match atyp {
        0x01 => {
            anyhow::ensure!(data.len() >= 7, "ipv4 truncated");
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok((7, Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))))
        }
        0x04 => {
            anyhow::ensure!(data.len() >= 19, "ipv6 truncated");
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok((
                19,
                Target::Socket(SocketAddr::new(IpAddr::V6(ip.into()), port)),
            ))
        }
        0x03 => {
            anyhow::ensure!(data.len() >= 2, "domain truncated (no len)");
            let dlen = data[1] as usize;
            anyhow::ensure!(data.len() >= 4 + dlen, "domain truncated");
            let domain = String::from_utf8(data[2..2 + dlen].to_vec())?;
            let port = u16::from_be_bytes([data[2 + dlen], data[3 + dlen]]);
            Ok((4 + dlen, Target::Domain(domain, port)))
        }
        _ => anyhow::bail!("unknown address type: 0x{atyp:02x}"),
    }
}

/// 解析 SS2022 UDP 服务器响应 body，返回纯 payload（跳过 header 字段）。
///
/// 服务器响应 body 格式（AEAD 解密后）：
/// `[headerType=1 1B][timestamp 8B BE][clientSessionId 8B BE][paddingLen 2B BE][padding][SOCKS_addr][payload]`
///
/// 安全性：与 sing-shadowsocks2 `shadowaead_2022/method.go` 对齐，对服务端响应
/// 也做时间戳校验（±30s），防止 MITM 重放旧 UDP 响应包。
pub fn ss2022_udp_parse_server_body(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 19 {
        return None;
    }
    let header_type = body[0];
    if header_type != SS2022_HEADER_TYPE_SERVER {
        return None;
    }

    // 时间戳校验（±30s），防止重放
    let epoch = u64::from_be_bytes(body[1..9].try_into().ok()?);
    let now = now_unix_secs();
    if (now as i64).wrapping_sub(epoch as i64).unsigned_abs() > SS2022_MAX_TIMESTAMP_DIFF {
        return None;
    }

    let padding_len = u16::from_be_bytes([body[17], body[18]]) as usize;
    let socks_start = 19 + padding_len;
    if body.len() < socks_start {
        return None;
    }
    // 解析 SOCKS_addr 长度
    let atyp = body[socks_start];
    let addr_len = match atyp {
        0x01 => 7,
        0x04 => 19,
        0x03 => {
            if body.len() < socks_start + 2 {
                return None;
            }
            let dlen = body[socks_start + 1] as usize;
            4 + dlen
        }
        _ => return None,
    };
    let payload_start = socks_start + addr_len;
    if body.len() < payload_start {
        return None;
    }
    Some(&body[payload_start..])
}

/// 解析 SS2022 UDP 客户端请求 body（服务端用），返回 `(目标地址, 纯 payload)`。
///
/// 客户端请求 body 格式（AEAD 解密后）：
/// `[headerType=0 1B][timestamp 8B BE][paddingLen 2B BE][padding][SOCKS_addr][payload]`
///
/// 含时间戳校验（±30s），防 UDP 重放。
pub fn ss2022_udp_parse_client_body(body: &[u8]) -> Option<(Target, &[u8])> {
    // 最小长度: headerType(1) + timestamp(8) + paddingLen(2) = 11
    if body.len() < 11 {
        return None;
    }
    let header_type = body[0];
    if header_type != SS2022_HEADER_TYPE_CLIENT {
        return None;
    }

    // 时间戳校验（±30s），防止重放
    let epoch = u64::from_be_bytes(body[1..9].try_into().ok()?);
    let now = now_unix_secs();
    if (now as i64).wrapping_sub(epoch as i64).unsigned_abs() > SS2022_MAX_TIMESTAMP_DIFF {
        return None;
    }

    let padding_len = u16::from_be_bytes([body[9], body[10]]) as usize;
    let socks_start = 11 + padding_len;
    if body.len() < socks_start {
        return None;
    }
    let (n, target) = parse_socks_addr(&body[socks_start..]).ok()?;
    Some((target, &body[socks_start + n..]))
}

/// 构建 SS2022 UDP 客户端请求 body（AEAD 加密前）。
///
/// 格式: `[headerType=0 1B][timestamp 8B BE][paddingLen 2B BE=0][SOCKS_addr][payload]`
pub fn ss2022_udp_build_client_body(timestamp: u64, socks_addr: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 8 + 2 + socks_addr.len() + payload.len());
    body.push(SS2022_HEADER_TYPE_CLIENT);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // paddingLen = 0
    body.extend_from_slice(socks_addr);
    body.extend_from_slice(payload);
    body
}

/// 构建 SS2022 UDP 服务端响应 body（AEAD 加密前，服务端用）。
///
/// 格式:
/// `[headerType=1 1B][timestamp 8B BE][clientSessionId 8B BE][paddingLen 2B BE=0][SOCKS_addr][payload]`
///
/// `client_session_id` 回显客户端请求帧的 sessionId（客户端据此关联会话）。
pub fn ss2022_udp_build_server_body(
    timestamp: u64,
    client_session_id: u64,
    socks_addr: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 8 + 8 + 2 + socks_addr.len() + payload.len());
    body.push(SS2022_HEADER_TYPE_SERVER);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&client_session_id.to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes()); // paddingLen = 0
    body.extend_from_slice(socks_addr);
    body.extend_from_slice(payload);
    body
}

/// 从 SOCKS5 地址+载荷的明文中跳过地址头，返回纯载荷。
///
/// SOCKS5 地址格式：
/// - 0x01 + IPv4(4B) + port(2B) = 7 字节头
/// - 0x03 + domain_len(1B) + domain + port(2B) = 4 + domain_len 字节头
/// - 0x04 + IPv6(16B) + port(2B) = 19 字节头
pub fn skip_socks5_addr(payload: &[u8]) -> Option<&[u8]> {
    if payload.is_empty() {
        return None;
    }
    let offset = match payload[0] {
        0x01 => {
            // IPv4: 1 + 4 + 2 = 7
            if payload.len() < 7 {
                return None;
            }
            7
        }
        0x03 => {
            // Domain: 1 + 1 + domain_len + 2
            if payload.len() < 4 {
                return None;
            }
            let domain_len = payload[1] as usize;
            let end = 2 + domain_len + 2;
            if payload.len() < end {
                return None;
            }
            end
        }
        0x04 => {
            // IPv6: 1 + 16 + 2 = 19
            if payload.len() < 19 {
                return None;
            }
            19
        }
        _ => return None,
    };
    Some(&payload[offset..])
}

// ── 密码 → 主密钥（传统 AEAD 用） ─────────────────────────────────────────────

/// 从密码字符串派生主密钥（传统 AEAD：EVP_BytesToKey）。
pub fn derive_master_key(password: &str, method: Method) -> Vec<u8> {
    evp_bytes_to_key(password.as_bytes(), method.key_len())
}

// ── 辅助：Hex 编码（PSK 解析用，SS2022 的 PSK 是 hex 编码的） ────────────────

/// 将 hex 字符串解码为字节（SS2022 PSK 格式）。
pub fn decode_hex_psk(s: &str) -> anyhow::Result<Vec<u8>> {
    hex::decode(s).map_err(|e| anyhow::anyhow!("invalid PSK (hex decode): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_from_str() {
        assert_eq!(Method::from_str("aes-128-gcm").unwrap(), Method::Aes128Gcm);
        assert_eq!(
            Method::from_str("2022-blake3-aes-256-gcm").unwrap(),
            Method::Ss2022Aes256Gcm
        );
        assert!(Method::from_str("unknown").is_err());
    }

    #[test]
    fn method_key_len() {
        assert_eq!(Method::Aes128Gcm.key_len(), 16);
        assert_eq!(Method::Aes256Gcm.key_len(), 32);
        assert_eq!(Method::None.key_len(), 0);
    }

    #[test]
    fn evp_bytes_to_key_ok() {
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn ss2022_session_key_len() {
        let psk = [0u8; 16];
        let salt = [0u8; 16];
        let key = ss2022_session_key(&psk, &salt, 16);
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn aead_cipher_roundtrip() {
        let method = Method::Aes128Gcm;
        let subkey = vec![0u8; 16];
        let mut enc = AeadCipher::new(method, subkey.clone());
        let plaintext = b"hello world".to_vec();
        let mut buf = plaintext.clone();
        enc.seal(&mut buf).unwrap();
        assert_eq!(buf.len(), plaintext.len() + TAG_LEN);

        let mut dec = AeadCipher::new(method, subkey);
        dec.open(&mut buf).unwrap();
        assert_eq!(&buf, &plaintext);
    }

    #[test]
    fn socks_addr_roundtrip_ipv4() {
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let encoded = encode_target(&target);
        let (n, parsed) = parse_socks_addr(&encoded).unwrap();
        assert_eq!(n, encoded.len());
        match parsed {
            Target::Socket(a) => {
                assert_eq!(a.ip().to_string(), "1.2.3.4");
                assert_eq!(a.port(), 80);
            }
            _ => panic!("expected socket"),
        }
    }

    #[test]
    fn socks_addr_roundtrip_domain() {
        let target = Target::Domain("example.com".into(), 443);
        let encoded = encode_target(&target);
        let (n, parsed) = parse_socks_addr(&encoded).unwrap();
        assert_eq!(n, encoded.len());
        match parsed {
            Target::Domain(ref h, p) => {
                assert_eq!(h, "example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain"),
        }
    }
}
