use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Aes256Gcm,
};
use bytes::Bytes;
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest as _, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    config::outbound::ShadowsocksOutboundConfig,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{apply_mark_to_tcp, apply_mark_to_udp, set_tcp_opts, Outbound, OutboundStatus},
};

// ── 加密方法 ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    Ss2022Aes128Gcm,
    Ss2022Aes256Gcm,
    Ss2022ChaCha20Poly1305,
    None,
}

impl Method {
    fn from_str(s: &str) -> anyhow::Result<Self> {
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

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Ss2022Aes128Gcm => 16,
            Self::Aes256Gcm
            | Self::ChaCha20Poly1305
            | Self::Ss2022Aes256Gcm
            | Self::Ss2022ChaCha20Poly1305 => 32,
            Self::None => 0,
        }
    }

    fn salt_len(self) -> usize {
        self.key_len()
    }

    fn is_2022(self) -> bool {
        matches!(
            self,
            Self::Ss2022Aes128Gcm | Self::Ss2022Aes256Gcm | Self::Ss2022ChaCha20Poly1305
        )
    }
}

const TAG_LEN: usize = 16;
const MAX_PAYLOAD: usize = 0x3FFF;

// ── 密钥派生 ──────────────────────────────────────────────────────────────────

/// EVP_BytesToKey（MD5 KDF）：密码字符串 → master key。
fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
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
fn hkdf_sha1(master_key: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
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
/// `derive_key` 内部会对 context 做一次 BLAKE3 哈希来生成内部密钥，
/// 因此不需要调用方提供 32 字节 key——PSK 可以是 16 或 32 字节。
///
/// 旧实现使用 `keyed_hash`，且对 16 字节 PSK 做了非标准的 `blake3::hash(psk)`
/// 来凑出 32 字节 key，这与 shadowsocks-rust / sing-shadowsocks2 的参考实现不一致。
fn ss2022_session_key(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut input = Vec::with_capacity(psk.len() + salt.len());
    input.extend_from_slice(psk);
    input.extend_from_slice(salt);
    let derived = blake3::derive_key(SS2022_DERIVE_KEY_CONTEXT, &input);
    derived[..key_len].to_vec()
}

/// SS 2022 BLAKE3 derive_key 上下文字符串
const SS2022_DERIVE_KEY_CONTEXT: &str = "shadowsocks 2022 session subkey";

// ── SS 2022 UDP 专用帧格式 ─────────────────────────────────────────────────────
//
// 对照 sing-shadowsocks2/shadowaead_2022/method.go 中 WritePacket / readPacket。
//
// **AES 变体**（2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm）：
//   wire = [encrypted_header 16B] [AEAD_ciphertext + 16B tag]
//
//   plaintext_header = [session_id 8B BE] [packet_id 8B BE]
//   encrypted_header = AES-ECB-Encrypt(PSK, plaintext_header)
//
//   AEAD plaintext (client→server) =
//     [headerType=0 1B] [timestamp 8B BE] [paddingLen 2B BE] [padding] [SOCKS_addr] [payload]
//   AEAD plaintext (server→client) =
//     [headerType=1 1B] [timestamp 8B BE] [clientSessionId 8B BE] [paddingLen 2B BE] [padding] [SOCKS_addr] [payload]
//
//   sessionKey = BLAKE3-deriveKey("shadowsocks 2022 session subkey", PSK + sessionId_8B)[..keyLen]
//   AEAD nonce = encrypted_header[4..16]  (12 字节)
//
// **ChaCha20 变体**（2022-blake3-chacha20-poly1305）：
//   wire = [nonce 24B] [XChaCha20-Poly1305 ciphertext + 16B tag]
//
//   nonce = 24 字节随机（来自 BLAKE3 keyed-hash RNG）
//   AEAD plaintext = [sessionId 8B BE] [packetId 8B BE] [headerType 1B] [timestamp 8B BE]
//                    [paddingLen 2B BE] [padding] [SOCKS_addr] [payload]
//   AEAD key = PSK 本身

const SS2022_AES_HEADER_LEN: usize = 16; // AES-ECB 加密的 sessionId+packetId
const SS2022_CHACHA_NONCE_LEN: usize = 24; // XChaCha20 nonce
const SS2022_HEADER_TYPE_CLIENT: u8 = 0;
const SS2022_HEADER_TYPE_SERVER: u8 = 1;
const SS2022_MAX_PADDING: usize = 900;

/// 判断 SS2022 方法是否使用 AES 变体（需要 AES-ECB header）。
fn ss2022_is_aes(method: Method) -> bool {
    matches!(method, Method::Ss2022Aes128Gcm | Method::Ss2022Aes256Gcm)
}

/// AES-ECB 加密单个 16 字节块（使用 PSK 作为 key）。
fn aes_ecb_encrypt_block(block: &mut [u8; 16], key: &[u8]) {
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
fn aes_ecb_decrypt_block(block: &mut [u8; 16], key: &[u8]) {
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

/// 构建 SS 2022 UDP 帧（AES 变体）。
///
/// `body_plaintext` 应已包含 `[headerType][timestamp][paddingLen][padding][SOCKS_addr][payload]`。
/// 返回完整的 wire 格式。
fn ss2022_udp_seal_aes(
    psk: &[u8],
    session_id: u64,
    packet_id: u64,
    body: &mut Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let key_len = psk.len();

    // 构造 16 字节 plaintext header: [sessionId 8B BE][packetId 8B BE]
    let mut hdr = [0u8; 16];
    hdr[..8].copy_from_slice(&session_id.to_be_bytes());
    hdr[8..].copy_from_slice(&packet_id.to_be_bytes());

    // AEAD nonce = plaintext_header[4..16]（加密前取值，同 sing-shadowsocks2 WritePacket）
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hdr[4..16]);

    // 派生 sessionKey = BLAKE3-deriveKey(ctx, PSK + sessionId_8B)
    let sid_bytes = session_id.to_be_bytes();
    let subkey = ss2022_session_key(psk, &sid_bytes, key_len);

    // 加密 body
    let method = if key_len == 16 {
        Method::Ss2022Aes128Gcm
    } else {
        Method::Ss2022Aes256Gcm
    };
    let cipher = AeadCipher::new_with_subkey(method, subkey, 0);
    cipher.seal_with_nonce(body, &nonce)?;

    // AES-ECB 加密 header（在 AEAD 加密之后）
    aes_ecb_encrypt_block(&mut hdr, psk);
    let enc_header = hdr;

    // wire = [enc_header 16B] [ciphertext + tag]
    let mut wire = Vec::with_capacity(SS2022_AES_HEADER_LEN + body.len());
    wire.extend_from_slice(&enc_header);
    wire.extend_from_slice(body);
    Ok(wire)
}

/// 解密 SS 2022 UDP 帧（AES 变体）。
///
/// 输入 buf 是完整的 wire 数据（含 16B enc header）。
/// 返回解密后的 body 明文。
fn ss2022_udp_open_aes(psk: &[u8], buf: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        buf.len() > SS2022_AES_HEADER_LEN + TAG_LEN,
        "ss2022 udp: frame too short"
    );

    let key_len = psk.len();

    // AES-ECB 解密 header
    let mut hdr = [0u8; 16];
    hdr.copy_from_slice(&buf[..SS2022_AES_HEADER_LEN]);
    aes_ecb_decrypt_block(&mut hdr, psk);

    let session_id = u64::from_be_bytes(hdr[..8].try_into().unwrap());

    // 派生 sessionKey
    let sid_bytes = session_id.to_be_bytes();
    let subkey = ss2022_session_key(psk, &sid_bytes, key_len);

    // AEAD nonce = decrypted_header[4..16]（同 sing-shadowsocks2 readPacket）
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hdr[4..16]);

    // 解密 body
    let mut ct = buf[SS2022_AES_HEADER_LEN..].to_vec();
    let method = if key_len == 16 {
        Method::Ss2022Aes128Gcm
    } else {
        Method::Ss2022Aes256Gcm
    };
    let cipher = AeadCipher::new_with_subkey(method, subkey, 0);
    cipher.open_with_nonce(&mut ct, &nonce)?;
    Ok(ct)
}

/// 构建 SS 2022 UDP 帧（ChaCha20 变体，使用 XChaCha20-Poly1305）。
///
/// `body` 应已包含 `[headerType][timestamp][paddingLen][padding][SOCKS_addr][payload]`。
/// 在 body 前面添加 sessionId+packetId，然后整体加密。
fn ss2022_udp_seal_chacha(
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

    // 构造完整明文: [sessionId 8B][packetId 8B][body...]
    let mut plaintext = Vec::with_capacity(16 + body.len());
    plaintext.extend_from_slice(&session_id.to_be_bytes());
    plaintext.extend_from_slice(&packet_id.to_be_bytes());
    plaintext.extend_from_slice(body);

    let cipher = XChaCha20Poly1305::new_from_slice(psk)
        .map_err(|e| anyhow::anyhow!("xchacha20 key init: {e}"))?;
    let tag = cipher
        .encrypt_in_place_detached(nonce_24.into(), b"", &mut plaintext)
        .map_err(|e| anyhow::anyhow!("xchacha20 encrypt: {e}"))?;

    // wire = [nonce 24B] [ciphertext + tag]
    let mut wire = Vec::with_capacity(SS2022_CHACHA_NONCE_LEN + plaintext.len() + TAG_LEN);
    wire.extend_from_slice(nonce_24);
    wire.extend_from_slice(&plaintext);
    wire.extend_from_slice(&tag);
    Ok(wire)
}

/// 解密 SS 2022 UDP 帧（ChaCha20 变体）。
fn ss2022_udp_open_chacha(psk: &[u8], buf: &[u8]) -> anyhow::Result<Vec<u8>> {
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

    // 跳过前 16 字节（sessionId + packetId），返回 body
    anyhow::ensure!(ct.len() >= 16, "ss2022 udp chacha: body too short");
    Ok(ct[16..].to_vec())
}

// ── AEAD 加解密器 ─────────────────────────────────────────────────────────────

struct AeadCipher {
    method: Method,
    subkey: Vec<u8>,
    counter: u64,
}

impl AeadCipher {
    fn new(method: Method, subkey: Vec<u8>) -> Self {
        Self {
            method,
            subkey,
            counter: 0,
        }
    }

    /// 使用指定的 subkey 创建（不递增 counter）。
    /// 用于 SS 2022 UDP 等需要自定义 nonce 的场景。
    fn new_with_subkey(method: Method, subkey: Vec<u8>, counter: u64) -> Self {
        Self {
            method,
            subkey,
            counter,
        }
    }

    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// 使用指定的 nonce 加密，追加 16B tag（不递增 counter）。
    fn seal_with_nonce(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        let tag = self.seal_inner(buf, nonce)?;
        buf.extend_from_slice(&tag);
        Ok(())
    }

    /// 使用指定的 nonce 解密（含 trailing tag），去掉 tag（不递增 counter）。
    fn open_with_nonce(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        anyhow::ensure!(buf.len() >= TAG_LEN, "ciphertext too short");
        self.open_inner(buf, nonce)
    }

    /// 原地加密，追加 16B tag，递增 counter。
    fn seal(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        let nonce = self.nonce();
        let tag = self.seal_inner(buf, &nonce)?;
        buf.extend_from_slice(&tag);
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
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => do_seal!(ChaCha20Poly1305),
            Method::None => [0u8; TAG_LEN],
        })
    }

    /// 原地解密（含 trailing tag），去掉 tag，递增 counter。
    fn open(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()> {
        if self.method == Method::None {
            return Ok(());
        }
        anyhow::ensure!(buf.len() >= TAG_LEN, "ciphertext too short");
        let nonce = self.nonce();
        self.open_inner(buf, &nonce)?;
        self.counter = self.counter.wrapping_add(1);
        Ok(())
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
            Method::ChaCha20Poly1305 | Method::Ss2022ChaCha20Poly1305 => do_open!(ChaCha20Poly1305),
            Method::None => {}
        }
        Ok(())
    }

    /// 预检解密（不递增 counter），仅用于提前读取 payload 长度。
    /// 成功返回 true 并修改 buf（去掉 tag），失败返回 false。
    fn open_inner_peek(&self, buf: &mut Vec<u8>, nonce: &[u8; 12]) -> bool {
        self.open_inner(buf, nonce).is_ok()
    }
}

// ── 拆分的读写两半 ────────────────────────────────────────────────────────────

/// 加密写半部：持有 WriteHalf<TcpStream> + enc cipher。
struct SsWriter {
    inner: WriteHalf<TcpStream>,
    enc: AeadCipher,
}

impl SsWriter {
    /// 写一个加密 chunk：[enc(len 2B)+tag][enc(payload)+tag]
    async fn write_chunk(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let mut len_buf = (data.len() as u16).to_be_bytes().to_vec();
        self.enc.seal(&mut len_buf)?;

        let mut payload_buf = data.to_vec();
        self.enc.seal(&mut payload_buf)?;

        self.inner.write_all(&len_buf).await?;
        self.inner.write_all(&payload_buf).await?;
        Ok(())
    }

    async fn shutdown(&mut self) {
        let _ = self.inner.shutdown().await;
    }
}

/// 解密读半部：持有 ReadHalf<TcpStream> + dec cipher。
///
/// `dec` 延迟初始化：首次 read_chunk 时先读取服务器 salt（key_len 字节），
/// 派生新的 session subkey，再创建解密器。
/// 对于 SS2022，还需读取 fixed response header（nonce=0）+ padding buffer（nonce=1），
/// 之后才进入标准 `[enc(2B len)][enc(payload)]` 分帧（nonce=2,3...）。
struct SsReader {
    inner: ReadHalf<TcpStream>,
    dec: Option<AeadCipher>,
    method: Method,
    /// PSK（SS2022）或 master key（传统 AEAD），用于派生服务器 subkey
    key_material: Vec<u8>,
    /// SS2022 请求 salt，用于校验响应中的 responseSalt
    request_salt: Option<Vec<u8>>,
}

impl SsReader {
    /// 延迟初始化 dec：读取服务器 salt、派生 subkey、（SS2022）读取响应头。
    async fn ensure_init(&mut self) -> anyhow::Result<()> {
        if self.dec.is_some() {
            return Ok(());
        }

        // 读取服务器 salt
        let salt_len = self.method.salt_len();
        let mut salt = vec![0u8; salt_len];
        self.inner.read_exact(&mut salt).await?;

        // 派生 session subkey
        let key_len = self.method.key_len();
        let subkey = if self.method.is_2022() {
            ss2022_session_key(&self.key_material, &salt, key_len)
        } else {
            hkdf_sha1(&self.key_material, &salt, key_len)
        };
        let mut dec = AeadCipher::new(self.method, subkey);

        // SS2022：读取 fixed response header + padding buffer
        if self.method.is_2022() {
            self.read_ss2022_response(&mut dec).await?;
        }

        self.dec = Some(dec);
        Ok(())
    }

    /// 读取 SS2022 响应头（在 ensure_init 中调用）。
    ///
    /// 响应格式（对照 sing-shadowsocks2 readResponse）：
    /// - fixed response header（nonce=0）：
    ///   `[type=1 1B][timestamp 8B BE][responseSalt keyLen B][paddingLen 2B BE]` + tag
    /// - padding buffer（nonce=1）：`[padding of paddingLen B]` + tag
    /// - 之后接标准分帧（nonce=2,3...）
    async fn read_ss2022_response(&mut self, dec: &mut AeadCipher) -> anyhow::Result<()> {
        let key_len = self.method.key_len();
        let fixed_len = 1 + 8 + key_len + 2; // type + timestamp + responseSalt + paddingLen

        let mut fixed_buf = vec![0u8; fixed_len + TAG_LEN];
        self.inner.read_exact(&mut fixed_buf).await?;
        dec.open(&mut fixed_buf)?; // nonce=0 → 1

        let header_type = fixed_buf[0];
        anyhow::ensure!(
            header_type == SS2022_HEADER_TYPE_SERVER,
            "ss2022 response: bad header type {}, expected {}",
            header_type,
            SS2022_HEADER_TYPE_SERVER
        );

        // timestamp 校验（±30s）
        let epoch = u64::from_be_bytes(fixed_buf[1..9].try_into().unwrap());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let diff = (now - epoch as i64).abs();
        if diff > 30 {
            return Err(anyhow::anyhow!(
                "ss2022 response: bad timestamp, diff {}s",
                diff
            ));
        }

        // responseSalt 校验（必须等于请求 salt）
        let response_salt = &fixed_buf[9..9 + key_len];
        if let Some(ref req_salt) = self.request_salt {
            if response_salt != req_salt.as_slice() {
                return Err(anyhow::anyhow!("ss2022 response: response salt mismatch"));
            }
        }

        let padding_len =
            u16::from_be_bytes([fixed_buf[9 + key_len], fixed_buf[10 + key_len]]) as usize;

        // 读取 padding buffer（nonce=1 → 2）
        let mut pad_buf = vec![0u8; padding_len + TAG_LEN];
        self.inner.read_exact(&mut pad_buf).await?;
        dec.open(&mut pad_buf)?;

        Ok(())
    }

    /// 读一个解密 chunk，返回明文。
    async fn read_chunk(&mut self) -> anyhow::Result<Vec<u8>> {
        self.ensure_init().await?;

        // 借用不同字段以安抚 borrow checker
        let Self { inner, dec, .. } = self;
        let dec = dec.as_mut().expect("ensure_init guaranteed dec");

        let mut len_buf = vec![0u8; 2 + TAG_LEN];
        inner.read_exact(&mut len_buf).await?;
        dec.open(&mut len_buf)?;
        let payload_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;

        let mut payload_buf = vec![0u8; payload_len + TAG_LEN];
        inner.read_exact(&mut payload_buf).await?;
        dec.open(&mut payload_buf)?;
        Ok(payload_buf)
    }
}

// ── 连接建立 ──────────────────────────────────────────────────────────────────

/// 建立 SS TCP 连接，发送 salt + 首个加密块（目标地址 + 可选首包），
/// 返回独立的 (SsReader, SsWriter)，可并发使用。
///
/// SS2022 与传统 AEAD 的 TCP 帧格式不同（对照 sing-shadowsocks2 writeRequest）：
/// - 传统 AEAD：`[salt][enc(2B len)+tag][enc(addr+payload)+tag]…`
/// - SS2022：`[salt][enc(type=0 + timestamp 8B + variableHeaderLen 2B, nonce=0)+tag]`
///   `[enc(SOCKS_addr + paddingLen 2B + padding, nonce=1)+tag]`
///   `[enc(2B len)+tag][enc(payload)+tag]…`（nonce=2,3...）
async fn ss_connect(
    server_addr: SocketAddr,
    method: Method,
    subkey: Vec<u8>,
    salt: Vec<u8>,
    first_payload: Vec<u8>,
    routing_mark: u32,
    key_material: Vec<u8>,
) -> anyhow::Result<(SsReader, SsWriter)> {
    let stream = TcpStream::connect(server_addr).await?;
    set_tcp_opts(&stream)?;
    apply_mark_to_tcp(&stream, routing_mark)?;

    let (rd, wr) = tokio::io::split(stream);
    let mut writer = SsWriter {
        inner: wr,
        enc: AeadCipher::new(method, subkey.clone()),
    };
    let request_salt = if method.is_2022() {
        Some(salt.clone())
    } else {
        None
    };
    let reader = SsReader {
        inner: rd,
        dec: None,
        method,
        key_material,
        request_salt,
    };

    // 发送 salt
    writer.inner.write_all(&salt).await?;

    if method.is_2022() {
        // SS2022 TCP 请求格式：
        // [salt] 已发送
        // [enc(type=0 + timestamp 8B + variableHeaderLen 2B, nonce=0) + tag]
        // [enc(SOCKS_addr + paddingLen 2B + padding, nonce=1) + tag]
        // 后续 standard chunks 从 nonce=2 开始
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // first_payload 即 SOCKS_addr（encode_target 的输出），无额外用户数据
        let socks_addr = &first_payload;

        // 随机 padding（1..=MaxPaddingLength），对照 sing-shadowsocks2 writeRequest
        use rand::{Rng, RngCore};
        let padding_len: usize = rand::thread_rng().gen_range(1..=SS2022_MAX_PADDING);
        let mut padding = vec![0u8; padding_len];
        rand::thread_rng().fill_bytes(&mut padding);

        // variableHeaderLen = SOCKS_addr + paddingLen(2) + padding + payload(0)
        let variable_header_len = socks_addr.len() + 2 + padding_len;

        // fixed header (11B): [type=0][timestamp 8B BE][variableHeaderLen 2B BE]
        let mut fixed_hdr = Vec::with_capacity(11 + TAG_LEN);
        fixed_hdr.push(SS2022_HEADER_TYPE_CLIENT);
        fixed_hdr.extend_from_slice(&now.to_be_bytes());
        fixed_hdr.extend_from_slice(&(variable_header_len as u16).to_be_bytes());
        writer.enc.seal(&mut fixed_hdr)?; // nonce=0 → 1

        // variable header: [SOCKS_addr][paddingLen 2B BE][padding]
        let mut var_hdr = Vec::with_capacity(variable_header_len + TAG_LEN);
        var_hdr.extend_from_slice(socks_addr);
        var_hdr.extend_from_slice(&(padding_len as u16).to_be_bytes());
        var_hdr.extend_from_slice(&padding);
        writer.enc.seal(&mut var_hdr)?; // nonce=1 → 2

        writer.inner.write_all(&fixed_hdr).await?;
        writer.inner.write_all(&var_hdr).await?;
        // 后续数据走标准分帧（nonce=2,3...），由 relay_ss 的 write_chunk 处理
    } else {
        // 传统 AEAD：首块使用标准 [enc(2B len)][enc(payload)] 分帧
        writer.write_chunk(&first_payload).await?;
    }

    Ok((reader, writer))
}

// ── 双向转发 ──────────────────────────────────────────────────────────────────

/// 在 inbound stream 和 SS 连接之间做双向透明转发。
/// 返回 `(upstream_bytes, downstream_bytes)`。
async fn relay_ss(
    inbound: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    mut ss_rd: SsReader,
    mut ss_wr: SsWriter,
) -> (u64, u64) {
    let (mut ib_rd, mut ib_wr) = tokio::io::split(inbound);

    // 上行：inbound → SS server
    let up = async move {
        let mut buf = vec![0u8; MAX_PAYLOAD];
        let mut total = 0u64;
        loop {
            let n = match ib_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if ss_wr.write_chunk(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        ss_wr.shutdown().await;
        total
    };

    // 下行：SS server → inbound
    let down = async move {
        let mut total = 0u64;
        loop {
            let chunk = match ss_rd.read_chunk().await {
                Ok(c) => c,
                Err(_) => break,
            };
            if ib_wr.write_all(&chunk).await.is_err() {
                break;
            }
            total += chunk.len() as u64;
        }
        let _ = ib_wr.shutdown().await;
        total
    };

    tokio::join!(up, down)
}

// ── SS AEAD over 泛型流 ───────────────────────────────────────────────────────
//
// 当底层传输是 XhttpStream（或任意 AsyncRead+AsyncWrite）时，
// 我们不能使用 ReadHalf<TcpStream> 类型的 SsReader/SsWriter。
// 改用这套纯泛型实现，将 SS AEAD 帧逻辑封装成一个 AsyncRead+AsyncWrite 类型。

/// 将任意 AsyncRead+AsyncWrite 流包装成 SS AEAD 加解密流。
///
/// 写入侧：自动在每次 write 时对数据做 AEAD 分帧加密并写入底层流。
/// 读取侧：首次读取时先消费服务器 salt（+ SS2022 响应头），再进入标准分帧解密。
struct SsXhttpStream<S> {
    inner: S,
    enc: AeadCipher,
    /// 延迟初始化：首次 poll_read 时读取服务器 salt 派生新 subkey
    dec: Option<AeadCipher>,
    method: Method,
    /// PSK（SS2022）或 master key（传统 AEAD），用于派生服务器 subkey
    key_material: Vec<u8>,
    /// SS2022 请求 salt，用于校验响应中的 responseSalt
    request_salt: Option<Vec<u8>>,
    /// 解密后的明文缓冲
    read_buf: Vec<u8>,
    /// 底层流读取缓冲（用于积累 SS 帧）
    raw_buf: Vec<u8>,
    /// 是否已完成 salt 发送
    salt_sent: bool,
    salt: Vec<u8>,
    /// SS2022 响应头是否已读取
    ss2022_response_read: bool,
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> SsXhttpStream<S> {
    fn new(
        inner: S,
        enc: AeadCipher,
        method: Method,
        key_material: Vec<u8>,
        request_salt: Option<Vec<u8>>,
    ) -> Self {
        Self {
            inner,
            enc,
            dec: None,
            method,
            key_material,
            request_salt,
            read_buf: Vec::new(),
            raw_buf: Vec::new(),
            salt_sent: true, // salt 由 ss_wrap_xhttp 在创建前发送
            salt: Vec::new(),
            ss2022_response_read: false,
        }
    }
}

// MAX_PAYLOAD 和 TAG_LEN 已在文件顶部定义（第 97-98 行），此处不重复定义。

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> tokio::io::AsyncRead
    for SsXhttpStream<S>
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::io::ErrorKind;
        use std::task::Poll;
        let this = self.get_mut();

        // 先消费解密缓冲
        if !this.read_buf.is_empty() {
            let n = buf.remaining().min(this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        loop {
            // ── 阶段 0：延迟初始化 dec（读取服务器 salt） ──
            if this.dec.is_none() {
                let salt_len = this.method.salt_len();
                if this.raw_buf.len() < salt_len {
                    match poll_read_more(&mut this.inner, &mut this.raw_buf, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())), // EOF
                        Poll::Ready(Ok(true)) => continue,
                    }
                }
                let salt: Vec<u8> = this.raw_buf[..salt_len].to_vec();
                this.raw_buf.drain(..salt_len);
                let key_len = this.method.key_len();
                let subkey = if this.method.is_2022() {
                    ss2022_session_key(&this.key_material, &salt, key_len)
                } else {
                    hkdf_sha1(&this.key_material, &salt, key_len)
                };
                this.dec = Some(AeadCipher::new(this.method, subkey));
                continue;
            }

            // ── 阶段 1（SS2022）：读取 fixed response header + padding buffer ──
            if this.method.is_2022() && !this.ss2022_response_read {
                let key_len = this.method.key_len();
                let fixed_len = 1 + 8 + key_len + 2 + TAG_LEN; // type+ts+respSalt+padLen + tag
                if this.raw_buf.len() < fixed_len {
                    match poll_read_more(&mut this.inner, &mut this.raw_buf, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "ss2022 response: EOF during fixed header",
                            )))
                        }
                        Poll::Ready(Ok(true)) => continue,
                    }
                }
                let dec = this.dec.as_mut().unwrap();
                let mut fixed_buf = this.raw_buf[..fixed_len].to_vec();
                if let Err(e) = dec.open(&mut fixed_buf) {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("ss2022 response fixed open: {e}"),
                    )));
                }
                this.raw_buf.drain(..fixed_len);

                let header_type = fixed_buf[0];
                if header_type != SS2022_HEADER_TYPE_SERVER {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "ss2022 response: bad header type {header_type}, expected {}",
                            SS2022_HEADER_TYPE_SERVER
                        ),
                    )));
                }
                // responseSalt 校验
                let response_salt = &fixed_buf[9..9 + key_len];
                if let Some(ref req_salt) = this.request_salt {
                    if response_salt != req_salt.as_slice() {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "ss2022 response: response salt mismatch",
                        )));
                    }
                }
                let padding_len =
                    u16::from_be_bytes([fixed_buf[9 + key_len], fixed_buf[10 + key_len]]) as usize;

                // 读取 padding buffer（nonce=1 → 2）
                let pad_needed = padding_len + TAG_LEN;
                if this.raw_buf.len() < pad_needed {
                    match poll_read_more(&mut this.inner, &mut this.raw_buf, cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(false)) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "ss2022 response: EOF during padding",
                            )))
                        }
                        Poll::Ready(Ok(true)) => continue,
                    }
                }
                let dec = this.dec.as_mut().unwrap();
                let mut pad_buf = this.raw_buf[..pad_needed].to_vec();
                if let Err(e) = dec.open(&mut pad_buf) {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!("ss2022 response padding open: {e}"),
                    )));
                }
                this.raw_buf.drain(..pad_needed);
                this.ss2022_response_read = true;
                continue;
            }

            // ── 阶段 2：标准 SS AEAD 帧读取 ──
            // 帧格式：[enc(len 2B) + tag 16B][enc(payload) + tag 16B]
            let len_chunk_size = 2 + TAG_LEN; // 18 字节

            if this.raw_buf.len() >= len_chunk_size {
                // 预解密 length（不递增 counter）以读取 payload 长度
                let dec = this.dec.as_ref().unwrap();
                let nonce = dec.nonce();
                let mut len_peek = this.raw_buf[..len_chunk_size].to_vec();
                if !dec.open_inner_peek(&mut len_peek, &nonce) {
                    return Poll::Ready(Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "SS AEAD length chunk decrypt failed",
                    )));
                }
                let payload_len = u16::from_be_bytes([len_peek[0], len_peek[1]]) as usize;
                let total_needed = len_chunk_size + payload_len + TAG_LEN;

                if this.raw_buf.len() >= total_needed {
                    // 真正执行两次 open（递增 counter）
                    let dec = this.dec.as_mut().unwrap();
                    let mut len_chunk = this.raw_buf[..len_chunk_size].to_vec();
                    if let Err(e) = dec.open(&mut len_chunk) {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("SS AEAD len open: {e}"),
                        )));
                    }
                    let mut payload_chunk = this.raw_buf[len_chunk_size..total_needed].to_vec();
                    if let Err(e) = dec.open(&mut payload_chunk) {
                        return Poll::Ready(Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!("SS AEAD payload open: {e}"),
                        )));
                    }
                    this.raw_buf.drain(..total_needed);
                    this.read_buf.extend_from_slice(&payload_chunk);

                    let n = buf.remaining().min(this.read_buf.len());
                    buf.put_slice(&this.read_buf[..n]);
                    this.read_buf.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                // payload 还不够，继续读
            }

            // 从底层读取更多数据
            match poll_read_more(&mut this.inner, &mut this.raw_buf, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())), // EOF
                Poll::Ready(Ok(true)) => continue,
            }
        }
    }
}

/// 从底层流读取更多数据到 raw_buf。
/// 返回 `Ok(true)` 表示读到了数据，`Ok(false)` 表示 EOF，`Pending` 表示需等待。
fn poll_read_more<S: tokio::io::AsyncRead + Unpin>(
    inner: &mut S,
    raw_buf: &mut Vec<u8>,
    cx: &mut std::task::Context<'_>,
) -> std::task::Poll<std::io::Result<bool>> {
    use std::task::Poll;
    let mut tmp = [0u8; 4096];
    let mut tmp_buf = tokio::io::ReadBuf::new(&mut tmp);
    match std::pin::Pin::new(inner).poll_read(cx, &mut tmp_buf) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Ready(Ok(())) => {
            let filled = tmp_buf.filled();
            if filled.is_empty() {
                Poll::Ready(Ok(false)) // EOF
            } else {
                raw_buf.extend_from_slice(filled);
                Poll::Ready(Ok(true))
            }
        }
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> tokio::io::AsyncWrite
    for SsXhttpStream<S>
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = self.get_mut();

        // 构建完整的加密输出：[salt 若未发送][enc(len)][enc(payload)]
        let mut out = Vec::new();
        if !this.salt_sent {
            out.extend_from_slice(&this.salt);
            this.salt_sent = true;
        }

        // 分块，每块不超过 MAX_PAYLOAD
        let mut offset = 0;
        while offset < data.len() {
            let chunk_end = (offset + MAX_PAYLOAD).min(data.len());
            let chunk = &data[offset..chunk_end];
            let payload_len = chunk.len() as u16;

            // 加密 length
            let mut len_buf = payload_len.to_be_bytes().to_vec();
            if let Err(e) = this.enc.seal(&mut len_buf) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("SS seal len: {e}"),
                )));
            }
            out.extend_from_slice(&len_buf);

            // 加密 payload
            let mut payload_buf = chunk.to_vec();
            if let Err(e) = this.enc.seal(&mut payload_buf) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("SS seal payload: {e}"),
                )));
            }
            out.extend_from_slice(&payload_buf);
            offset = chunk_end;
        }

        // 一次性写入底层流
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, &out) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(data.len())),
            other => other,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// 在已建立的泛型流上初始化 SS AEAD 上下文，发送 salt + 首个加密 payload，
/// 返回可直接用于双向转发的 `SsXhttpStream`。
///
/// SS2022 模式下首块格式（对照 sing-shadowsocks2 writeRequest）：
/// `[salt][enc(type=0 + timestamp 8B + variableHeaderLen 2B, nonce=0)+tag]`
/// `[enc(SOCKS_addr + paddingLen 2B + padding, nonce=1)+tag]`
/// 后续 standard chunks 从 nonce=2 开始。
///
/// 传统 AEAD 模式下为 `[salt][enc(2B len)][enc(addr + payload)]`。
async fn ss_wrap_xhttp<S>(
    mut stream: S,
    method: Method,
    subkey: Vec<u8>,
    salt: Vec<u8>,
    first_payload: Vec<u8>,
    key_material: Vec<u8>,
) -> anyhow::Result<SsXhttpStream<S>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncWriteExt;

    let mut enc = AeadCipher::new(method, subkey);
    let request_salt = if method.is_2022() {
        Some(salt.clone())
    } else {
        None
    };

    // 发送 salt（明文）
    stream.write_all(&salt).await?;

    if method.is_2022() {
        // SS2022 TCP 请求格式
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let socks_addr = &first_payload;

        // 随机 padding（1..=MaxPaddingLength）
        use rand::{Rng, RngCore};
        let padding_len: usize = rand::thread_rng().gen_range(1..=SS2022_MAX_PADDING);
        let mut padding = vec![0u8; padding_len];
        rand::thread_rng().fill_bytes(&mut padding);

        let variable_header_len = socks_addr.len() + 2 + padding_len;

        // fixed header (11B): [type=0][timestamp 8B BE][variableHeaderLen 2B BE]
        let mut fixed_hdr = Vec::with_capacity(11 + TAG_LEN);
        fixed_hdr.push(SS2022_HEADER_TYPE_CLIENT);
        fixed_hdr.extend_from_slice(&now.to_be_bytes());
        fixed_hdr.extend_from_slice(&(variable_header_len as u16).to_be_bytes());
        enc.seal(&mut fixed_hdr)?; // nonce=0 → 1

        // variable header: [SOCKS_addr][paddingLen 2B BE][padding]
        let mut var_hdr = Vec::with_capacity(variable_header_len + TAG_LEN);
        var_hdr.extend_from_slice(socks_addr);
        var_hdr.extend_from_slice(&(padding_len as u16).to_be_bytes());
        var_hdr.extend_from_slice(&padding);
        enc.seal(&mut var_hdr)?; // nonce=1 → 2

        stream.write_all(&fixed_hdr).await?;
        stream.write_all(&var_hdr).await?;
    } else {
        // 传统 AEAD：[enc(2B len)][enc(payload)]
        let payload_len = first_payload.len() as u16;
        let mut len_buf = payload_len.to_be_bytes().to_vec();
        enc.seal(&mut len_buf)?;
        stream.write_all(&len_buf).await?;

        let mut payload_buf = first_payload;
        enc.seal(&mut payload_buf)?;
        stream.write_all(&payload_buf).await?;
    }

    Ok(SsXhttpStream::new(
        stream,
        enc,
        method,
        key_material,
        request_salt,
    ))
}

// ── 地址编码（SOCKS5 格式） ───────────────────────────────────────────────────

fn encode_target(target: &Target) -> Vec<u8> {
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

/// 解析 SS 2022 UDP 服务器响应 body，返回纯 payload。
///
/// 服务器响应 body 格式（AEAD 解密后）：
/// `[headerType=1 1B][timestamp 8B BE][clientSessionId 8B BE][paddingLen 2B BE][padding][SOCKS_addr][payload]`
///
/// 客户端请求 body 格式（AEAD 解密后，用于回放检查等，此处不使用）：
/// `[headerType=0 1B][timestamp 8B BE][paddingLen 2B BE][padding][SOCKS_addr][payload]`
fn ss2022_udp_parse_server_body(body: &[u8]) -> Option<&[u8]> {
    // 最小长度: headerType(1) + timestamp(8) + clientSessionId(8) + paddingLen(2) = 19
    if body.len() < 19 {
        return None;
    }
    let header_type = body[0];
    if header_type != SS2022_HEADER_TYPE_SERVER {
        return None;
    }
    // 跳过 timestamp(8B) + clientSessionId(8B)
    let padding_len = u16::from_be_bytes([body[17], body[18]]) as usize;
    let socks_start = 19 + padding_len;
    if body.len() < socks_start {
        return None;
    }
    skip_socks5_addr(&body[socks_start..])
}

/// 构建 SS 2022 UDP 客户端请求 body（AEAD 加密前）。
///
/// 格式: `[headerType=0 1B][timestamp 8B BE][paddingLen 2B BE=0][SOCKS_addr][payload]`
fn ss2022_udp_build_client_body(timestamp: u64, socks_addr: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + 8 + 2 + socks_addr.len() + payload.len());
    body.push(SS2022_HEADER_TYPE_CLIENT);
    body.extend_from_slice(&timestamp.to_be_bytes());
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
fn skip_socks5_addr(payload: &[u8]) -> Option<&[u8]> {
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

// ── 主出站结构 ────────────────────────────────────────────────────────────────

pub struct ShadowsocksOutbound {
    config: ShadowsocksOutboundConfig,
    method: Method,
    /// 传统 AEAD：EVP_BytesToKey 派生的 master key；
    /// AEAD-2022：base64 解码的 PSK。
    key_material: Vec<u8>,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 多路复用连接池（multiplex.enabled 时非空）
    mux_pool: Option<Arc<crate::outbound::common::smux::MultiplexPool>>,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<crate::dns::DnsResolver>>,
}

impl ShadowsocksOutbound {
    pub fn new(config: ShadowsocksOutboundConfig) -> anyhow::Result<Self> {
        Self::new_with_resolver(config, None)
    }

    pub fn new_with_resolver(
        config: ShadowsocksOutboundConfig,
        resolver: Option<Arc<crate::dns::DnsResolver>>,
    ) -> anyhow::Result<Self> {
        let method = Method::from_str(&config.method)?;

        let key_material = if method.is_2022() {
            use base64::Engine as _;
            let psk = base64::engine::general_purpose::STANDARD
                .decode(config.password.trim())
                .map_err(|e| anyhow::anyhow!("2022 PSK base64 decode: {e}"))?;
            anyhow::ensure!(
                psk.len() == method.key_len(),
                "2022 PSK length mismatch: expected {} got {}",
                method.key_len(),
                psk.len()
            );
            psk
        } else if method == Method::None {
            Vec::new()
        } else {
            evp_bytes_to_key(config.password.as_bytes(), method.key_len())
        };

        // WS over TLS 通过 websocket::connect → connect_tls_or_utls 动态构建，
        // 不再在 new() 时提前压成 rustls::ClientConfig（避免丢失 uTLS/certificate 字段）。

        // 多路复用连接池（如果配置了 multiplex.enabled）
        let mux_pool = if config
            .multiplex
            .as_ref()
            .map(|m| m.enabled)
            .unwrap_or(false)
        {
            let mux_cfg = config.multiplex.clone().unwrap_or_default();
            let server = config.server.clone();
            let port = config.server_port;
            let dial_resolver = resolver.clone();
            let pool = crate::outbound::common::smux::MultiplexPool::new(mux_cfg, move || {
                let server = server.clone();
                let dial_resolver = dial_resolver.clone();
                async move {
                    let addr =
                        crate::outbound::resolve_server_addr(&server, port, dial_resolver.as_ref())
                            .await
                            .map_err(|e| {
                                anyhow::anyhow!("smux dial: DNS failed for {server}: {e}")
                            })?;
                    let tcp = tokio::net::TcpStream::connect(addr).await?;
                    let b: Box<dyn crate::outbound::common::smux::AsyncReadWrite> = Box::new(tcp);
                    Ok(b)
                }
            });
            Some(Arc::new(pool))
        } else {
            None
        };

        Ok(Self {
            config,
            method,
            key_material,
            routing_mark: 0,
            mux_pool,
            resolver,
        })
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    async fn server_addr(&self) -> anyhow::Result<SocketAddr> {
        let host = &self.config.server;
        let port = self.config.server_port;
        crate::outbound::resolve_server_addr(host, port, self.resolver.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("DNS lookup failed for {host}: {e}"))
    }

    fn random_salt(&self) -> Vec<u8> {
        use rand::RngCore;
        let mut salt = vec![0u8; self.method.salt_len()];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }

    fn derive_subkey(&self, salt: &[u8]) -> Vec<u8> {
        let key_len = self.method.key_len();
        if self.method.is_2022() {
            ss2022_session_key(&self.key_material, salt, key_len)
        } else {
            hkdf_sha1(&self.key_material, salt, key_len)
        }
    }

    /// 裸 TCP 模式的 SS 连接。
    /// XHTTP 模式由 `connect_ss_xhttp` 单独处理，`handle_tcp` 会提前分支，
    /// 不会调用到这里。
    async fn connect_ss(&self, target: &Target) -> anyhow::Result<(SsReader, SsWriter)> {
        let server_addr = self.server_addr().await?;
        let first_payload = encode_target(target);

        if self.method == Method::None {
            let stream = TcpStream::connect(server_addr).await?;
            set_tcp_opts(&stream)?;
            apply_mark_to_tcp(&stream, self.routing_mark)?;
            let (rd, mut wr) = tokio::io::split(stream);
            wr.write_all(&first_payload).await?;
            let reader = SsReader {
                inner: rd,
                dec: Some(AeadCipher::new(Method::None, Vec::new())),
                method: Method::None,
                key_material: Vec::new(),
                request_salt: None,
            };
            let writer = SsWriter {
                inner: wr,
                enc: AeadCipher::new(Method::None, Vec::new()),
            };
            return Ok((reader, writer));
        }

        let salt = self.random_salt();
        let subkey = self.derive_subkey(&salt);
        ss_connect(
            server_addr,
            self.method,
            subkey,
            salt,
            first_payload,
            self.routing_mark,
            self.key_material.clone(),
        )
        .await
    }

    /// 通过 XHTTP 传输建立 Shadowsocks 连接，返回双工异步 IO
    async fn connect_ss_xhttp(
        &self,
        target: &Target,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        use crate::config::outbound::ShadowsocksTransportConfig;
        use crate::outbound::transport::xhttp;
        use std::collections::HashMap;
        use tokio::io::AsyncWriteExt;

        let xhttp_cfg = match &self.config.transport {
            Some(ShadowsocksTransportConfig::Xhttp(cfg)) => cfg,
            _ => anyhow::bail!("connect_ss_xhttp called without xhttp config"),
        };

        let mut stream = xhttp::connect(
            &self.config.server,
            self.config.server_port,
            xhttp_cfg,
            self.config.tls.as_ref(),
            &HashMap::new(),
            self.routing_mark,
            self.resolver.clone(),
        )
        .await?;

        let first_payload = encode_target(target);

        if self.method == Method::None {
            // 明文模式：直接发送目标地址前缀
            stream.write_all(&first_payload).await?;
            return Ok(Box::new(stream));
        }

        // AEAD 模式：需要手动在 xhttp 流上做 SS 帧封装
        // 使用 ss_connect_generic 辅助（见下方）
        let salt = self.random_salt();
        let subkey = self.derive_subkey(&salt);
        Ok(Box::new(
            ss_wrap_xhttp(
                stream,
                self.method,
                subkey,
                salt,
                first_payload,
                self.key_material.clone(),
            )
            .await?,
        ))
    }

    /// 通过 WebSocket 传输建立 Shadowsocks 连接，返回双工异步 IO。
    /// 复用统一的 `transport::websocket::WsStream` 适配器做 WS 帧 ↔ 字节流转换，
    /// 再交给泛型的 `ss_wrap_xhttp` 做 SS AEAD 帧封装。
    async fn connect_ss_ws(
        &self,
        target: &Target,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        use crate::config::outbound::ShadowsocksTransportConfig;
        use crate::outbound::transport::websocket;

        let ws_cfg = match &self.config.transport {
            Some(ShadowsocksTransportConfig::Ws(cfg)) => cfg,
            _ => anyhow::bail!("connect_ss_ws called without ws config"),
        };

        let server = &self.config.server;
        let port = self.config.server_port;
        let tls_opt = self.config.tls.as_ref().filter(|t| t.enabled);
        let sni = self
            .config
            .tls
            .as_ref()
            .and_then(|t| t.server_name.as_deref())
            .unwrap_or(server.as_str());

        let ws = websocket::connect(
            server,
            port,
            sni,
            tls_opt,
            ws_cfg,
            self.routing_mark,
            self.resolver.clone(),
        )
        .await?;
        let ws_io = websocket::WsStream::new(ws);

        let first_payload = encode_target(target);

        if self.method == Method::None {
            use tokio::io::AsyncWriteExt;
            let mut boxed: Box<dyn crate::outbound::AsyncReadWrite> = Box::new(ws_io);
            boxed.write_all(&first_payload).await?;
            return Ok(boxed);
        }

        let salt = self.random_salt();
        let subkey = self.derive_subkey(&salt);
        Ok(Box::new(
            ss_wrap_xhttp(
                ws_io,
                self.method,
                subkey,
                salt,
                first_payload,
                self.key_material.clone(),
            )
            .await?,
        ))
    }

    /// 通过 gRPC 传输建立 Shadowsocks 连接，返回双工异步 IO。
    /// 复用 `transport::grpc::connect` 拿到 `GrpcStream`（AsyncRead+AsyncWrite），
    /// 再交给泛型 `ss_wrap_xhttp` 做 SS AEAD 帧封装。
    /// 与 `connect_ss_ws` / `connect_ss_xhttp` 同构。
    async fn connect_ss_grpc(
        &self,
        target: &Target,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        use crate::config::outbound::ShadowsocksTransportConfig;
        use crate::outbound::transport::grpc;
        use tokio::io::AsyncWriteExt;

        let grpc_cfg = match &self.config.transport {
            Some(ShadowsocksTransportConfig::Grpc(cfg)) => cfg,
            _ => anyhow::bail!("connect_ss_grpc called without grpc config"),
        };

        let server = &self.config.server;
        let port = self.config.server_port;
        let tls_opt = self.config.tls.as_ref().filter(|t| t.enabled);
        let sni = self
            .config
            .tls
            .as_ref()
            .and_then(|t| t.server_name.as_deref())
            .unwrap_or(server.as_str());

        let mut stream = grpc::connect(
            server,
            port,
            sni,
            tls_opt,
            grpc_cfg,
            self.routing_mark,
            self.resolver.clone(),
        )
        .await?;

        let first_payload = encode_target(target);

        if self.method == Method::None {
            stream.write_all(&first_payload).await?;
            return Ok(Box::new(stream));
        }

        let salt = self.random_salt();
        let subkey = self.derive_subkey(&salt);
        Ok(Box::new(
            ss_wrap_xhttp(
                stream,
                self.method,
                subkey,
                salt,
                first_payload,
                self.key_material.clone(),
            )
            .await?,
        ))
    }
}

#[async_trait::async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Shadowsocks".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        use crate::config::outbound::ShadowsocksTransportConfig;
        debug!(tag = %self.config.tag, target = %conn.target, "shadowsocks tcp relay");

        // 多路复用路径：通过 SMux 逻辑流承载 SS 流量
        if let Some(ref pool) = self.mux_pool {
            let mux_stream = pool.acquire().await?;
            let first_payload = encode_target(&conn.target);
            let salt = self.random_salt();
            let subkey = self.derive_subkey(&salt);
            let ss_stream = ss_wrap_xhttp(
                mux_stream,
                self.method,
                subkey,
                salt,
                first_payload,
                self.key_material.clone(),
            )
            .await?;
            let (bytes_up, bytes_dn) = crate::outbound::relay(conn.stream, ss_stream).await;
            return Ok((bytes_up, bytes_dn));
        }

        // XHTTP 传输模式：使用泛型 SS 封装流
        if matches!(
            &self.config.transport,
            Some(ShadowsocksTransportConfig::Xhttp(_))
        ) {
            let io = self.connect_ss_xhttp(&conn.target).await?;
            let (bytes_up, bytes_dn) = crate::outbound::relay(conn.stream, io).await;
            return Ok((bytes_up, bytes_dn));
        }

        // WebSocket 传输模式
        if matches!(
            &self.config.transport,
            Some(ShadowsocksTransportConfig::Ws(_))
        ) {
            let io = self.connect_ss_ws(&conn.target).await?;
            let (bytes_up, bytes_dn) = crate::outbound::relay(conn.stream, io).await;
            return Ok((bytes_up, bytes_dn));
        }

        // gRPC 传输模式
        if matches!(
            &self.config.transport,
            Some(ShadowsocksTransportConfig::Grpc(_))
        ) {
            let io = self.connect_ss_grpc(&conn.target).await?;
            let (bytes_up, bytes_dn) = crate::outbound::relay(conn.stream, io).await;
            return Ok((bytes_up, bytes_dn));
        }

        // 裸 TCP 模式（原有实现）
        let (ss_rd, ss_wr) = self.connect_ss(&conn.target).await?;
        Ok(relay_ss(conn.stream, ss_rd, ss_wr).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        use tokio::net::UdpSocket;

        debug!(tag = %self.config.tag, target = %packet.target, "shadowsocks udp relay");

        let server_addr = self.server_addr().await?;
        let local_bind = if server_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let udp = std::sync::Arc::new(UdpSocket::bind(local_bind).await?);
        apply_mark_to_udp(&udp, self.routing_mark)?;
        udp.connect(server_addr).await?;

        // SS2022: 生成随机 8 字节 session_id，packet_id 从 1 递增
        let (session_id, mut pkt_id) = if self.method.is_2022() {
            use rand::RngCore;
            let mut sid = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut sid);
            (u64::from_be_bytes(sid), 1u64)
        } else {
            (0u64, 0u64)
        };

        // 发送第一个上行包
        {
            let socks_addr = encode_target(&packet.target);
            let wire = if self.method == Method::None {
                let mut w = socks_addr;
                w.extend_from_slice(&packet.data);
                w
            } else if self.method.is_2022() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut body = ss2022_udp_build_client_body(now, &socks_addr, &packet.data);
                if ss2022_is_aes(self.method) {
                    ss2022_udp_seal_aes(&self.key_material, session_id, pkt_id, &mut body)?
                } else {
                    use rand::RngCore;
                    let mut nonce_24 = [0u8; 24];
                    rand::thread_rng().fill_bytes(&mut nonce_24);
                    ss2022_udp_seal_chacha(
                        &self.key_material,
                        session_id,
                        pkt_id,
                        &nonce_24,
                        &mut body,
                    )?
                }
            } else {
                let salt = self.random_salt();
                let subkey = self.derive_subkey(&salt);
                let mut cipher = AeadCipher::new(self.method, subkey);
                let mut addr_payload = socks_addr;
                addr_payload.extend_from_slice(&packet.data);
                cipher.seal(&mut addr_payload)?;
                let mut pkt = salt;
                pkt.extend_from_slice(&addr_payload);
                pkt
            };
            udp.send(&wire).await?;
            if self.method.is_2022() {
                pkt_id += 1;
            }
        }

        // 后续上行包
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let udp_send = udp.clone();
            let method = self.method;
            let key_material = self.key_material.clone();
            let sid = session_id;
            tokio::spawn(async move {
                use rand::RngCore;
                let mut pid = pkt_id;
                while let Some((target, data)) = upstream_rx.recv().await {
                    let socks_addr = encode_target(&target);
                    let wire = if method == Method::None {
                        let mut w = socks_addr;
                        w.extend_from_slice(&data);
                        w
                    } else if method.is_2022() {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let mut body = ss2022_udp_build_client_body(now, &socks_addr, &data);
                        let result = if ss2022_is_aes(method) {
                            ss2022_udp_seal_aes(&key_material, sid, pid, &mut body)
                        } else {
                            let mut nonce_24 = [0u8; 24];
                            rand::thread_rng().fill_bytes(&mut nonce_24);
                            ss2022_udp_seal_chacha(&key_material, sid, pid, &nonce_24, &mut body)
                        };
                        match result {
                            Ok(w) => w,
                            Err(_) => break,
                        }
                    } else {
                        let mut salt = vec![0u8; method.salt_len()];
                        rand::thread_rng().fill_bytes(&mut salt);
                        let key_len = method.key_len();
                        let subkey = if method.is_2022() {
                            ss2022_session_key(&key_material, &salt, key_len)
                        } else {
                            hkdf_sha1(&key_material, &salt, key_len)
                        };
                        let mut cipher = AeadCipher::new(method, subkey);
                        let mut addr_payload = socks_addr;
                        addr_payload.extend_from_slice(&data);
                        if cipher.seal(&mut addr_payload).is_err() {
                            break;
                        }
                        let mut pkt = salt;
                        pkt.extend_from_slice(&addr_payload);
                        pkt
                    };
                    if method.is_2022() {
                        pid += 1;
                    }
                    if udp_send.send(&wire).await.is_err() {
                        break;
                    }
                }
            });
        }

        // 持续接收回包
        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());
        let method = self.method;
        let key_material = self.key_material.clone();
        let salt_len = self.method.salt_len();
        let timeout = std::time::Duration::from_secs(10);
        let mut buf = vec![0u8; 65535];

        while let Ok(Ok(n)) = tokio::time::timeout(timeout, udp.recv(&mut buf)).await {
            let payload: Option<Vec<u8>> = if method == Method::None {
                        skip_socks5_addr(&buf[..n]).map(|s| s.to_vec())
                    } else if method.is_2022() {
                        // SS 2022 UDP：[enc_header 16B / nonce 24B][AEAD body + tag]
                        let result = if ss2022_is_aes(method) {
                            ss2022_udp_open_aes(&key_material, &buf[..n])
                        } else {
                            ss2022_udp_open_chacha(&key_material, &buf[..n])
                        };
                        match result {
                            Ok(body) => ss2022_udp_parse_server_body(&body).map(|s| s.to_vec()),
                            Err(_) => None,
                        }
                    } else if n > salt_len + TAG_LEN {
                        let (salt_bytes, ciphertext) = buf[..n].split_at(salt_len);
                        let key_len = method.key_len();
                        let subkey = if method.is_2022() {
                            ss2022_session_key(&key_material, salt_bytes, key_len)
                        } else {
                            hkdf_sha1(&key_material, salt_bytes, key_len)
                        };
                        let mut cipher = AeadCipher::new(method, subkey);
                        let mut ct = ciphertext.to_vec();
                        match cipher.open(&mut ct) {
                            Ok(()) => skip_socks5_addr(&ct).map(|s| s.to_vec()),
                            Err(_) => None,
                        }
                    } else {
                        None
                    };
                    if let Some(data) = payload {
                        if reply_tx
                            .send((Bytes::from(data), src, spoofed_src))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
        }
        Ok(())
    }
}
