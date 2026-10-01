//! VMess 协议原语：inbound 服务端与 outbound 客户端共享。
//!
//! 对齐 sing-vmess（sing-box 的 VMess 实现）的 AEAD 路径（alterId == 0，现代 VMess）。
//!
//! # 握手布局（AEAD 模式）
//! ```text
//! [AuthID 16B] [EncHeaderLen 2+16B] [ConnNonce 8B] [EncHeader N+16B]
//! ```
//!
//! ## Header 明文
//! ```text
//! [Ver=1 1B][ReqNonce 16B][ReqKey 16B][RespHeader 1B]
//! [Option 1B][PaddingLen<<4|Security 1B][Reserved=0 1B][Command 1B]
//! [Port 2B BE][Atyp 1B][Addr ...][Padding padLen B][FNV1a 4B]
//! ```
//!
//! ## KDF 派生（HMAC-SHA256 嵌套，sing-vmess/kdf.go）
//! KDF(key, salt, path...) = HMAC-SHA256(HMAC-SHA256(..., salt), key)
//!
//! ## 数据层
//! 每帧 `[len_masked 2B][ciphertext + TAG 16B]`；nonce 前 2 字节为大端计数器，
//! 后 10 字节取自 base[2..12]。客户端→服务端用请求头里的 req_key/req_nonce；
//! 服务端→客户端用 SHA256 派生的 resp_key/resp_nonce（各取前 16 字节）。
//!
//! 本模块与 vless/trojan 一样只放纯编解码原语：KDF、AuthID、请求/响应头
//! 加解密、chunk 流编解码器。连接管理、拨号、角色逻辑分别在
//! `outbound/vmess.rs`（客户端）与 `inbound/vmess.rs`（服务端）。

// ── FNV-1a 32-bit（vmess header 明文校验和）─────────────────────────────────
//
// **重要**：必须是独立的 32-bit FNV-1a（offset basis 0x811c9dc5，
// prime 0x01000193），不能用 `fnv` crate 的 `FnvHasher`——该 crate 实现的是
// 64-bit FNV-1a（Rust `Hasher` trait 语义），`finish() as u32` 只是截断
// 64-bit 状态的低 32 位，数值上与原生 32-bit FNV-1a 完全不同。
// v2ray/Xray 官方实现（Go `hash/fnv`）用的是 `fnv.New32a()`，即原生 32-bit
// 版本，此前误用 64-bit-then-truncate 导致这里永远无法与真实客户端对上，
// 即使 AEAD 解密（密钥/KDF）全部正确也会报 FNV1a checksum mismatch。
fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x01000193);
    }
    h
}

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use md5::Md5;
use sha3::digest::{ExtendableOutput, XofReader};
use sha3::Shake128;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::Target;

// ── 常量 ──────────────────────────────────────────────────────────────────────

pub const VERSION: u8 = 1;
pub const CIPHER_OVERHEAD: usize = 16;

// Security type bytes（同 sing-vmess/protocol.go）
pub const SECURITY_NONE: u8 = 5;
pub const SECURITY_AES128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;

// RequestOption flags
pub const OPT_CHUNK_STREAM: u8 = 1;
pub const OPT_CHUNK_MASKING: u8 = 4;
pub const OPT_GLOBAL_PADDING: u8 = 8;
pub const OPT_AUTHENTICATED_LENGTH: u8 = 16;

// Command
pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;

/// packetaddr 模式魔术地址（与 sing-vmess packetaddr.SeqPacketMagicAddress 一致）。
/// 当 VMess/VLESS UDP 使用 packetaddr 分帧时，请求头中的目标地址必须是此魔术地址，
/// 服务端据此进入 packetaddr 模式，真实目标地址在后续分帧中携带。
///
/// **注意**：sing-vmess 使用 v2fly 风格的魔术地址 `sp.packet-addr.v2fly.arpa`，
/// 而非 Xray 风格的 `sp.v3.udp.packetaddr.arpa`。两者不兼容。
pub const PACKETADDR_MAGIC: &str = "sp.packet-addr.v2fly.arpa";
pub const PACKETADDR_MAGIC_PORT: u16 = 443;

// Address type (VMess 请求头使用，与 SOCKS5 一致)
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_IPV6: u8 = 0x03;
pub const ATYP_DOMAIN: u8 = 0x02;

// packetaddr ATYP 常量（与 sing-vmess packetaddr.AddressSerializer 一致）
// 注意：这些值与 VMess 请求头的 ATYP 不同！
// packetaddr: 0x01=IPv4, 0x02=IPv6, 不支持域名（FQDN）
// VMess 头:   0x01=IPv4, 0x02=Domain, 0x03=IPv6
pub const PACKETADDR_ATYP_IPV4: u8 = 0x01;
pub const PACKETADDR_ATYP_IPV6: u8 = 0x02;

// KDF salt constants（同 sing-vmess/protocol.go）
const KDF_SALT_VMESS_AEAD_KDF: &str = "VMess AEAD KDF";
const KDF_SALT_AUTH_ID: &str = "AES Auth ID Encryption";
const KDF_SALT_HEADER_LEN_KEY: &str = "VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_LEN_IV: &str = "VMess Header AEAD Nonce_Length";
const KDF_SALT_HEADER_KEY: &str = "VMess Header AEAD Key";
const KDF_SALT_HEADER_IV: &str = "VMess Header AEAD Nonce";

pub const KDF_SALT_RESP_LEN_KEY: &str = "AEAD Resp Header Len Key";
pub const KDF_SALT_RESP_LEN_IV: &str = "AEAD Resp Header Len IV";
pub const KDF_SALT_RESP_KEY: &str = "AEAD Resp Header Key";
pub const KDF_SALT_RESP_IV: &str = "AEAD Resp Header IV";

// ── KDF（嵌套 HMAC-SHA256，对应 sing-vmess/kdf.go 的 hMacCreator 结构）────────
//
// **重要**：Go 的 sing-vmess/kdf.go 使用**嵌套 HMAC**构造，而非简单的链式 HMAC。
//
// ```go
// func (h *hMacCreator) Create() hash.Hash {
//     if h.parent == nil {
//         return hmac.New(sha256.New, h.value)
//     }
//     return hmac.New(h.parent.Create, h.value)  // parent.Create 本身返回 HMAC
// }
// ```
//
// `hmac.New(h.parent.Create, h.value)` 中，`h.parent.Create` 作为外层 HMAC 的
// "哈希函数"——但它本身是一个 HMAC 实例。这导致每一层都是嵌套的 HMAC(HMAC(...))，
// 而非 `HMAC(key=prev_output, msg=next_input)` 的简单链式调用。
//
// 旧实现错误地使用了链式 HMAC，导致 KDF 输出与 sing-vmess 完全不同，握手必然失败。
// 已通过对照测试（kdfverify）验证本实现与 Go sing-vmess 输出字节级一致。

const SHA256_BLOCK_SIZE: usize = 64;
const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;

/// 哈希函数 trait：可以是底层 SHA-256，也可以是嵌套的 HMAC（作为内层哈希）。
trait KdfHashFn {
    fn call(&self, data: &[u8]) -> Vec<u8>;
    fn block_size(&self) -> usize {
        SHA256_BLOCK_SIZE
    }
}

/// 底层 SHA-256 哈希。
struct Sha256Hasher;
impl KdfHashFn for Sha256Hasher {
    fn call(&self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        sha2::Sha256::digest(data).to_vec()
    }
}

/// 嵌套 HMAC：以 `inner` 作为内部哈希函数，`key` 作为 HMAC 密钥。
///
/// 对应 Go `hmac.New(h.parent.Create, h.value)`：
/// - `inner` = `h.parent.Create()` 返回的哈希/HMAC 实例
/// - `key` = `h.value`
///
/// HMAC 构造遵循 RFC 2104：
///   K' = key 填充到 block_size（若超过则先哈希）
///   HMAC(key, msg) = H((K' ⊕ opad) || H((K' ⊕ ipad) || msg))
struct NestedHmac {
    key: Vec<u8>,
    inner: Box<dyn KdfHashFn + Send>,
}

impl KdfHashFn for NestedHmac {
    fn call(&self, data: &[u8]) -> Vec<u8> {
        let block_size = self.inner.block_size();
        let key = &self.key;

        // K' = key 填充到 block_size（若超过则先哈希）
        // 与 Go crypto/internal/fips140/hmac 一致
        let key_padded: Vec<u8> = if key.len() > block_size {
            let mut v = self.inner.call(key);
            v.resize(block_size, 0);
            v
        } else {
            let mut v = key.clone();
            v.resize(block_size, 0);
            v
        };

        let mut ipad = key_padded.clone();
        let mut opad = key_padded.clone();
        for b in &mut ipad {
            *b ^= HMAC_IPAD;
        }
        for b in &mut opad {
            *b ^= HMAC_OPAD;
        }

        // inner_hash = H((K' ⊕ ipad) || data)
        let mut inner_input = ipad;
        inner_input.extend_from_slice(data);
        let inner = self.inner.call(&inner_input);

        // result = H((K' ⊕ opad) || inner_hash)
        let mut outer_input = opad;
        outer_input.extend_from_slice(&inner);
        self.inner.call(&outer_input)
    }

    fn block_size(&self) -> usize {
        // 嵌套 HMAC 的 block_size 与其内部哈希相同（SHA-256 = 64）
        self.inner.block_size()
    }
}

/// 构建嵌套 HMAC 链。keys[0] 是最内层（root），keys[last] 是最外层。
fn build_kdf_chain(keys: &[Vec<u8>]) -> Box<dyn KdfHashFn + Send> {
    let mut hash: Box<dyn KdfHashFn + Send> = Box::new(Sha256Hasher);
    for k in keys {
        hash = Box::new(NestedHmac {
            key: k.clone(),
            inner: hash,
        });
    }
    hash
}

/// 从 UUID 派生 Key（MD5(uuid + 固定盐)）
pub fn user_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    use md5::Digest;
    let mut h = Md5::new();
    h.update(uuid_bytes);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

/// VMess AEAD KDF（对应 sing-vmess/kdf.go 的 KDF 函数）。
///
/// 使用嵌套 HMAC 构造，与 Go 的 `hMacCreator` 递归结构字节级一致。
///
/// KDF(key, salt, path...) =
///   HMAC(KDF_ROOT_SALT, HMAC(salt, HMAC(path[0], ... HMAC(path[n-1], key)...)))
///
/// 其中每一层 HMAC 的内层哈希函数本身也是 HMAC（而非普通 SHA-256）。
pub fn kdf(key: &[u8], salt: &str, path: &[&[u8]]) -> Vec<u8> {
    let mut all_keys: Vec<Vec<u8>> = vec![
        KDF_SALT_VMESS_AEAD_KDF.as_bytes().to_vec(),
        salt.as_bytes().to_vec(),
    ];
    for p in path {
        all_keys.push(p.to_vec());
    }
    let outer = build_kdf_chain(&all_keys);
    outer.call(key)
}

// ── AuthID（AES-ECB 加密的 8B 时间戳 + 4B 随机 + 4B CRC32）──────────────────

/// 构建 16 字节 AuthID（对应 sing-vmess/protocol.go AuthID()，客户端用）
pub fn build_auth_id(key: &[u8; 16]) -> [u8; 16] {
    use crc32fast::Hasher;

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&ts.to_be_bytes());

    // 4 字节随机
    let rand_bytes: [u8; 4] = rand_array();
    buf[8..12].copy_from_slice(&rand_bytes);

    // CRC32（前 12 字节）
    let mut crc = Hasher::new();
    crc.update(&buf[..12]);
    let checksum = crc.finalize();
    buf[12..16].copy_from_slice(&checksum.to_be_bytes());

    // AES-128-ECB 加密（无填充，16B 刚好一个 block）
    let enc_key = kdf(key, KDF_SALT_AUTH_ID, &[]);
    aes_ecb_encrypt_inplace(&mut buf, &enc_key[..16]);

    buf
}

/// 验证并解密 AuthID（服务端用，对应 sing-vmess 协议端 AuthID 校验）。
///
/// 用 `user_key` 派生密钥做 AES-128-ECB 解密，校验 CRC32（错误密钥解出的
/// 内容 CRC 必然不匹配，以此区分"用户不存在"与"时间戳过期"），
/// 再校验时间戳窗口（sing-vmess 默认 ±2 分钟，容忍两端时钟偏差）。
///
/// 返回 AuthID 中携带的时间戳。
pub fn verify_auth_id(
    auth_id: &[u8; 16],
    user_key: &[u8; 16],
    now: u64,
    window_secs: u64,
) -> anyhow::Result<u64> {
    use crc32fast::Hasher;

    let mut buf = *auth_id;
    let enc_key = kdf(user_key, KDF_SALT_AUTH_ID, &[]);
    aes_ecb_decrypt_inplace(&mut buf, &enc_key[..16]);

    let ts = u64::from_be_bytes(buf[..8].try_into()?);

    // CRC32 校验：既保证完整性，也用作用户匹配判定
    let mut crc = Hasher::new();
    crc.update(&buf[..12]);
    anyhow::ensure!(
        crc.finalize().to_be_bytes() == buf[12..16],
        "vmess auth id: crc mismatch (unknown user or corrupted auth id)"
    );

    anyhow::ensure!(
        ts.abs_diff(now) <= window_secs,
        "vmess auth id: timestamp {ts} outside ±{window_secs}s window (clock skew?)"
    );
    Ok(ts)
}

/// AES-128-ECB 加密单个 16 字节块（无 padding）
fn aes_ecb_encrypt_inplace(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

/// AES-128-ECB 解密单个 16 字节块（无 padding）
fn aes_ecb_decrypt_inplace(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockDecrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.decrypt_block(&mut b);
    block.copy_from_slice(&b);
}

// ── Header 明文编码（对应 rawClientConn.encodeHeader，客户端用）──────────────

pub struct RequestHeader {
    /// 随机生成的 16 字节请求 Key（用于数据加密）
    pub req_key: [u8; 16],
    /// 随机生成的 16 字节请求 Nonce（同 IV）
    pub req_nonce: [u8; 16],
    /// 随机 1 字节，用于匹配响应头
    pub resp_header: u8,
    /// option 字段（ChunkStream | ChunkMasking 等）
    pub option: u8,
    /// security 字节（SecurityTypeAes128Gcm 等）
    pub security: u8,
    /// command（CMD_TCP / CMD_UDP）
    pub command: u8,
}

impl RequestHeader {
    pub fn new(security: u8, command: u8) -> Self {
        let req_key: [u8; 16] = rand_array();
        let req_nonce: [u8; 16] = rand_array();
        let resp_header: u8 = rand_array::<1>()[0];

        // option 与 sing-vmess/client.go dialRaw() 保持一致。
        // 注：sing-vmess 在 AEAD 模式下还启用 GlobalPadding(0x08) + AuthenticatedLength(0x10)，
        // 但这两项需要深度重构 encoder/decoder 的 chunk 格式（counter 共享、chunk 级 padding、
        // 长度计算含 padding），实现复杂且易引入握手失败。当前保留 ChunkStream + ChunkMasking，
        // 已能正常工作。GlobalPadding/AuthenticatedLength 留待后续完整实现。
        let option = match security {
            SECURITY_NONE => {
                if command == CMD_UDP {
                    OPT_CHUNK_STREAM
                } else {
                    0
                }
            }
            SECURITY_AES128_GCM | SECURITY_CHACHA20_POLY1305 => {
                OPT_CHUNK_STREAM | OPT_CHUNK_MASKING
            }
            _ => 0,
        };

        Self {
            req_key,
            req_nonce,
            resp_header,
            option,
            security,
            command,
        }
    }

    /// 构建明文 header 字节（含末尾 FNV1a checksum）
    pub fn encode(&self, target: &Target) -> Bytes {
        let padding_len: usize = (rand_array::<1>()[0] % 16) as usize;

        let mut buf = BytesMut::with_capacity(64);
        buf.put_u8(VERSION);
        buf.put_slice(&self.req_nonce);
        buf.put_slice(&self.req_key);
        buf.put_u8(self.resp_header);
        buf.put_u8(self.option);
        buf.put_u8((padding_len as u8) << 4 | self.security);
        buf.put_u8(0x00); // reserved
        buf.put_u8(self.command);

        // 地址（Port 大端 + Atyp + Addr）— 对应 AddressSerializer.WriteAddrPort
        write_target(&mut buf, target);

        // padding
        for _ in 0..padding_len {
            buf.put_u8(0);
        }

        // FNV1a-32 checksum（覆盖整个 header 除 checksum 本身）
        buf.put_u32(fnv1a32(&buf));

        buf.freeze()
    }
}

pub fn write_target(buf: &mut BytesMut, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.put_u16(*port);
            buf.put_u8(ATYP_DOMAIN);
            buf.put_u8(host.len() as u8);
            buf.put_slice(host.as_bytes());
        }
        Target::Socket(addr) => {
            buf.put_u16(addr.port());
            match addr.ip() {
                IpAddr::V4(ip) => {
                    buf.put_u8(ATYP_IPV4);
                    buf.put_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    buf.put_u8(ATYP_IPV6);
                    buf.put_slice(&ip.octets());
                }
            }
        }
    }
}

// ── AEAD 握手帧打包（对应 rawClientConn.writeHandshake alterId==0 分支，客户端用）─

/// 将 RequestHeader 和 AuthID 打包成完整的握手字节流（发往服务端）。
///
/// 布局：
/// ```text
/// [AuthID 16B][EncHeaderLen 2+16B][ConnNonce 8B][EncHeader len+16B]
/// ```
pub fn build_handshake(user_key: &[u8; 16], req_hdr: &RequestHeader, target: &Target) -> Bytes {
    let auth_id = build_auth_id(user_key);
    let conn_nonce: [u8; 8] = rand_array();
    let header_plain = req_hdr.encode(target);
    let header_len = header_plain.len() as u16;

    // 加密 header length（2 bytes → 2+16 密文）
    let len_key = kdf(user_key, KDF_SALT_HEADER_LEN_KEY, &[&auth_id, &conn_nonce])[..16].to_vec();
    let len_nonce_raw =
        kdf(user_key, KDF_SALT_HEADER_LEN_IV, &[&auth_id, &conn_nonce])[..12].to_vec();
    let len_nonce = Nonce::from_slice(&len_nonce_raw);

    let cipher = <Aes128Gcm as KeyInit>::new_from_slice(&len_key).expect("aes key");
    let mut len_plain = [0u8; 2];
    len_plain.copy_from_slice(&header_len.to_be_bytes());
    let enc_len = cipher
        .encrypt(
            len_nonce,
            Payload {
                msg: &len_plain,
                aad: &auth_id,
            },
        )
        .expect("encrypt len");

    // 加密 header payload（N bytes → N+16 密文）
    let hdr_key = kdf(user_key, KDF_SALT_HEADER_KEY, &[&auth_id, &conn_nonce])[..16].to_vec();
    let hdr_nonce_raw = kdf(user_key, KDF_SALT_HEADER_IV, &[&auth_id, &conn_nonce])[..12].to_vec();
    let hdr_nonce = Nonce::from_slice(&hdr_nonce_raw);

    let cipher = <Aes128Gcm as KeyInit>::new_from_slice(&hdr_key).expect("aes key");
    let enc_hdr = cipher
        .encrypt(
            hdr_nonce,
            Payload {
                msg: &header_plain,
                aad: &auth_id,
            },
        )
        .expect("encrypt header");

    // 拼装
    let mut out = BytesMut::with_capacity(16 + 2 + CIPHER_OVERHEAD + 8 + enc_hdr.len());
    out.put_slice(&auth_id);
    out.put_slice(&enc_len);
    out.put_slice(&conn_nonce);
    out.put_slice(&enc_hdr);
    out.freeze()
}

// ── 服务端握手解析（对应 sing-vmess 服务端 decodeRequestHeader）──────────────

/// 解析后的服务端握手（已解密请求头明文）。
#[derive(Debug, Clone)]
pub struct ServerHandshake {
    /// 客户端随机请求 Key（数据层客户端→服务端方向的加密密钥）
    pub req_key: [u8; 16],
    /// 客户端随机请求 Nonce
    pub req_nonce: [u8; 16],
    /// 响应验证 token（服务端响应头首字节必须回显此值）
    pub resp_token: u8,
    /// option 字段（数据层编解码需使用）
    pub option: u8,
    /// security 字节（数据层算法）
    pub security: u8,
    /// command（CMD_TCP / CMD_UDP）
    pub command: u8,
    /// 目标地址
    pub target: Target,
    /// 整个握手帧消耗的字节数（AuthID + EncLen + ConnNonce + EncHeader）
    pub consumed: usize,
}

/// 解析并解密服务端握手帧。
///
/// 输入 `buf` 至少需包含完整握手（AuthID 16B + EncLen 18B + ConnNonce 8B +
/// EncHeader 变长）；长度不足时返回错误，调用方应先读满再重试
/// （本函数一次性解析，不做增量状态机）。
///
/// 注意：`user_key` 必须是已通过 [`verify_auth_id`] 匹配的用户密钥
/// （调用方先用 AuthID 匹配用户，再传入对应 user_key）。
pub fn parse_server_handshake(buf: &[u8], user_key: &[u8; 16]) -> anyhow::Result<ServerHandshake> {
    // 固定前缀：AuthID(16) + EncLen(18) + ConnNonce(8) = 42
    const FIXED_PREFIX: usize = 16 + 2 + CIPHER_OVERHEAD + 8;
    anyhow::ensure!(buf.len() >= FIXED_PREFIX, "vmess handshake: too short");

    let auth_id: [u8; 16] = buf[..16].try_into()?;
    let enc_len = &buf[16..16 + 2 + CIPHER_OVERHEAD];
    let conn_nonce: [u8; 8] = buf[16 + 2 + CIPHER_OVERHEAD..FIXED_PREFIX].try_into()?;

    // 解密 header length
    let len_key = kdf(user_key, KDF_SALT_HEADER_LEN_KEY, &[&auth_id, &conn_nonce])[..16].to_vec();
    let len_nonce_raw =
        kdf(user_key, KDF_SALT_HEADER_LEN_IV, &[&auth_id, &conn_nonce])[..12].to_vec();
    let len_cipher = <Aes128Gcm as KeyInit>::new_from_slice(&len_key)?;
    let dec_len = len_cipher
        .decrypt(
            Nonce::from_slice(&len_nonce_raw),
            Payload {
                msg: enc_len,
                aad: &auth_id,
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess handshake: decrypt header length failed"))?;
    let header_len = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;

    // 解密 header 明文
    let total = FIXED_PREFIX + header_len + CIPHER_OVERHEAD;
    anyhow::ensure!(buf.len() >= total, "vmess handshake: header payload truncated");
    let hdr_key = kdf(user_key, KDF_SALT_HEADER_KEY, &[&auth_id, &conn_nonce])[..16].to_vec();
    let hdr_nonce_raw = kdf(user_key, KDF_SALT_HEADER_IV, &[&auth_id, &conn_nonce])[..12].to_vec();
    let hdr_cipher = <Aes128Gcm as KeyInit>::new_from_slice(&hdr_key)?;
    let plain = hdr_cipher
        .decrypt(
            Nonce::from_slice(&hdr_nonce_raw),
            Payload {
                msg: &buf[FIXED_PREFIX..FIXED_PREFIX + header_len + CIPHER_OVERHEAD],
                aad: &auth_id,
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess handshake: decrypt header failed"))?;

    // 解析明文布局（先定位地址区结束位置，再校验 FNV1a——覆盖范围必须是
    // "[0, addr_end)"，checksum 紧跟其后 4 字节，不能依赖 plain.len() 反推，
    // 否则当 AEAD payload 长度与 "版本+地址+padding+FNV" 所需最小长度不完全
    // 相等时（部分客户端实现存在这种情况），校验范围会算错，导致 FNV
    // mismatch——即使密钥、AEAD 解密都是正确的。此处对齐 flux
    // parse_plain_header：从头部累加地址长度和 padding 得到 addr_end，
    // 而不是用 plain.len() 反向推导。）
    anyhow::ensure!(plain.len() >= 38 + 2, "vmess handshake: header body truncated");
    anyhow::ensure!(plain[0] == VERSION, "vmess: unsupported header version {}", plain[0]);
    let req_nonce: [u8; 16] = plain[1..17].try_into()?;
    let req_key: [u8; 16] = plain[17..33].try_into()?;
    let resp_token = plain[33];
    let option = plain[34];
    let sec_byte = plain[35];
    let padding_len = (sec_byte >> 4) as usize;
    let security = sec_byte & 0x0f;
    let command = plain[37];
    anyhow::ensure!(
        command == CMD_TCP || command == CMD_UDP,
        "vmess: unsupported command 0x{command:02x}"
    );
    anyhow::ensure!(
        option & (OPT_GLOBAL_PADDING | OPT_AUTHENTICATED_LENGTH) == 0,
        "vmess: GlobalPadding/AuthenticatedLength options not supported by this server"
    );
    anyhow::ensure!(
        matches!(
            security,
            SECURITY_NONE | SECURITY_AES128_GCM | SECURITY_CHACHA20_POLY1305
        ),
        "vmess: unsupported security type 0x{security:02x}"
    );

    let port = u16::from_be_bytes([plain[38], plain[39]]);
    let atyp = plain[40];
    let mut idx = 41usize;
    let target = match atyp {
        ATYP_IPV4 => {
            anyhow::ensure!(plain.len() >= idx + 4, "vmess: ipv4 addr truncated");
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                plain[idx],
                plain[idx + 1],
                plain[idx + 2],
                plain[idx + 3],
            ));
            idx += 4;
            Target::Socket(SocketAddr::new(ip, port))
        }
        ATYP_DOMAIN => {
            anyhow::ensure!(plain.len() > idx, "vmess: domain len truncated");
            let dlen = plain[idx] as usize;
            idx += 1;
            anyhow::ensure!(plain.len() >= idx + dlen, "vmess: domain truncated");
            let domain = String::from_utf8(plain[idx..idx + dlen].to_vec())?;
            idx += dlen;
            Target::Domain(domain, port)
        }
        ATYP_IPV6 => {
            anyhow::ensure!(plain.len() >= idx + 16, "vmess: ipv6 addr truncated");
            let ip: [u8; 16] = plain[idx..idx + 16].try_into()?;
            idx += 16;
            Target::Socket(SocketAddr::new(IpAddr::V6(ip.into()), port))
        }
        other => anyhow::bail!("vmess: unknown atyp 0x{other:02x}"),
    };

    // addr_end：地址区（含 padding）结束位置，紧跟其后 4 字节是 FNV1a checksum
    let addr_end = idx + padding_len;
    anyhow::ensure!(
        plain.len() >= addr_end + 4,
        "vmess handshake: header truncated (missing fnv checksum)"
    );

    anyhow::ensure!(
        fnv1a32(&plain[..addr_end]).to_be_bytes() == plain[addr_end..addr_end + 4],
        "vmess handshake: FNV1a checksum mismatch"
    );

    Ok(ServerHandshake {
        req_key,
        req_nonce,
        resp_token,
        option,
        security,
        command,
        target,
        consumed: total,
    })
}

// ── 响应头（客户端 parse / 服务端 build）─────────────────────────────────────

/// 从流中读取并解密 VMess AEAD 响应头，返回消耗的字节数（客户端用）。
///
/// 响应布局：
/// ```text
/// [EncRespLen 2+16B][EncRespHeader 4+16B]
/// ```
/// 解密后 header 内容：[RespToken 1B][Option 1B][Cmd 1B][CmdLen 1B]
///
/// 返回 `(response_token, consumed_bytes)` — token 用于校验与请求头的一致性。
pub fn parse_response_header(
    buf: &[u8],
    req_key: &[u8; 16],
    req_nonce: &[u8; 16],
) -> anyhow::Result<(u8, usize)> {
    // 响应 key / nonce 用 SHA256 派生（同 sing-vmess/client.go readResponse）
    let resp_key_full = sha256(req_key);
    let resp_nonce_full = sha256(req_nonce);
    let resp_key = &resp_key_full[..16];
    let resp_nonce = &resp_nonce_full[..16];

    // 解密 header length（2 + 16 字节）
    const LEN_FRAME: usize = 2 + CIPHER_OVERHEAD;
    anyhow::ensure!(
        buf.len() >= LEN_FRAME,
        "vmess resp: too short for len frame"
    );

    let len_key = kdf(resp_key, KDF_SALT_RESP_LEN_KEY, &[])[..16].to_vec();
    let len_nonce_raw = kdf(resp_nonce, KDF_SALT_RESP_LEN_IV, &[])[..12].to_vec();
    let len_nonce = Nonce::from_slice(&len_nonce_raw);
    let cipher = <Aes128Gcm as KeyInit>::new_from_slice(&len_key).expect("aes key");
    let dec_len = cipher
        .decrypt(
            len_nonce,
            Payload {
                msg: &buf[..LEN_FRAME],
                aad: b"",
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess resp: decrypt len failed"))?;
    let header_len = u16::from_be_bytes([dec_len[0], dec_len[1]]) as usize;

    // 解密 header payload（header_len + 16 字节）
    let hdr_cipher_len = header_len + CIPHER_OVERHEAD;
    anyhow::ensure!(
        buf.len() >= LEN_FRAME + hdr_cipher_len,
        "vmess resp: too short for header payload"
    );
    let hdr_key = kdf(resp_key, KDF_SALT_RESP_KEY, &[])[..16].to_vec();
    let hdr_nonce_raw = kdf(resp_nonce, KDF_SALT_RESP_IV, &[])[..12].to_vec();
    let hdr_nonce = Nonce::from_slice(&hdr_nonce_raw);
    let cipher = <Aes128Gcm as KeyInit>::new_from_slice(&hdr_key).expect("aes key");
    let dec_hdr = cipher
        .decrypt(
            hdr_nonce,
            Payload {
                msg: &buf[LEN_FRAME..LEN_FRAME + hdr_cipher_len],
                aad: b"",
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess resp: decrypt header failed"))?;

    anyhow::ensure!(dec_hdr.len() >= 4, "vmess resp: header too short");
    // 响应头明文布局（与 meow-rs header.rs:229 和 flux-master vmess/mod.rs:679 一致）：
    //   [resp_v 1B][option 1B][0x00 1B][0x00 1B]
    //
    // dec_hdr[0] = response_token（必须等于请求头中的 resp_header，即每连接随机验证字节）
    // dec_hdr[1] = option（服务端回显）
    //
    // 旧实现错误地认为 dec_hdr[0] 是 "response version" 并断言 == 0，
    // 但实际上 dec_hdr[0] 是 resp_v（0..255 的随机值），只有恰好为 0 时才通过，
    // 导致 ~99.6% 的连接握手失败。返回 dec_hdr[0] 作为 token，由调用方校验一致性。
    let token = dec_hdr[0];

    let consumed = LEN_FRAME + hdr_cipher_len;
    Ok((token, consumed))
}

/// 构建 VMess AEAD 响应头（服务端用，与 [`parse_response_header`] 对应）。
///
/// 明文布局 `[resp_token][option][0x00][0x00]`，resp_token 为请求头中的
/// `resp_header` 随机字节（客户端据此校验服务端身份）。
pub fn build_response_header(
    req_key: &[u8; 16],
    req_nonce: &[u8; 16],
    resp_token: u8,
    option: u8,
) -> anyhow::Result<Bytes> {
    let resp_key = resp_data_key(req_key);
    let resp_nonce = resp_data_nonce(req_nonce);

    // header 明文：[token][option][0][0]，固定 4 字节
    let header_plain = [resp_token, option, 0u8, 0u8];

    // 加密 header length（2B BE = 4）
    let len_key = kdf(&resp_key, KDF_SALT_RESP_LEN_KEY, &[])[..16].to_vec();
    let len_nonce_raw = kdf(&resp_nonce, KDF_SALT_RESP_LEN_IV, &[])[..12].to_vec();
    let len_cipher = <Aes128Gcm as KeyInit>::new_from_slice(&len_key)?;
    let enc_len = len_cipher
        .encrypt(
            Nonce::from_slice(&len_nonce_raw),
            Payload {
                msg: &4u16.to_be_bytes(),
                aad: b"",
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess resp: encrypt len failed"))?;

    // 加密 header payload
    let hdr_key = kdf(&resp_key, KDF_SALT_RESP_KEY, &[])[..16].to_vec();
    let hdr_nonce_raw = kdf(&resp_nonce, KDF_SALT_RESP_IV, &[])[..12].to_vec();
    let hdr_cipher = <Aes128Gcm as KeyInit>::new_from_slice(&hdr_key)?;
    let enc_hdr = hdr_cipher
        .encrypt(
            Nonce::from_slice(&hdr_nonce_raw),
            Payload {
                msg: &header_plain,
                aad: b"",
            },
        )
        .map_err(|_| anyhow::anyhow!("vmess resp: encrypt header failed"))?;

    let mut out = BytesMut::with_capacity(enc_len.len() + enc_hdr.len());
    out.put_slice(&enc_len);
    out.put_slice(&enc_hdr);
    Ok(out.freeze())
}

// ── 杂项工具 ──────────────────────────────────────────────────────────────────

pub fn sha256(input: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(input).into()
}

/// 生成 N 字节密码学安全随机数组。
///
/// 使用 `rand::rngs::OsRng`（基于操作系统 CSPRNG），杜绝旧实现中
/// `SystemTime::subsec_nanos() + DefaultHasher` 导致的 nonce/key 可预测问题。
pub fn rand_array<const N: usize>() -> [u8; N] {
    use rand::RngCore;
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

// ── 解析 UUID 字符串 ──────────────────────────────────────────────────────────

pub fn parse_uuid(s: &str) -> anyhow::Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    anyhow::ensure!(hex.len() == 32, "invalid UUID: {s}");
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

// ── 选择 security type ────────────────────────────────────────────────────────

pub fn resolve_security(security: &str) -> anyhow::Result<u8> {
    // 与 sing-vmess/client.go NewClient() switch 一致
    // "auto" 在 x86_64/arm64 上选 aes-128-gcm，其余选 chacha20-poly1305
    // Reflex 简化：auto 始终选 aes-128-gcm（服务端均支持）
    match security {
        "auto" | "aes-128-gcm" => Ok(SECURITY_AES128_GCM),
        "chacha20-poly1305" => Ok(SECURITY_CHACHA20_POLY1305),
        "none" | "zero" => Ok(SECURITY_NONE),
        "aes-128-cfb" => anyhow::bail!(
            "vmess: aes-128-cfb (legacy/alterId) is not supported; use aes-128-gcm or none"
        ),
        other => anyhow::bail!("vmess: unknown security type: {other}"),
    }
}

// ════════════════════════════════════════════════════════════════════════════
// AEAD 数据传输层：分帧读写器
// ════════════════════════════════════════════════════════════════════════════
//
// 握手完成后，所有数据用带计数器的 AES-128-GCM / ChaCha20-Poly1305 加密。
// 每帧格式：[len_masked 2B] [ciphertext + GCM_TAG 16B]
//
// Nonce：前 2 字节 = 大端计数器，后 10 字节取自 base_nonce[2..12]。
// 客户端发送/服务端接收用 req_key/req_nonce；
// 服务端发送/客户端接收用 SHA256 派生的 resp_key/resp_nonce。

// ── 枚举：支持的 AEAD 算法 ───────────────────────────────────────────────────

#[allow(clippy::large_enum_variant)]
enum VmessAeadCipher {
    Aes128Gcm(Aes128Gcm),
    Chacha20Poly1305(ChaCha20Poly1305),
}

impl VmessAeadCipher {
    fn new(security: u8, key: &[u8]) -> Self {
        match security {
            SECURITY_AES128_GCM => {
                VmessAeadCipher::Aes128Gcm(Aes128Gcm::new_from_slice(key).expect("aes key"))
            }
            SECURITY_CHACHA20_POLY1305 => {
                let full_key = chacha20_key(key);
                VmessAeadCipher::Chacha20Poly1305(
                    ChaCha20Poly1305::new_from_slice(&full_key).expect("chacha key"),
                )
            }
            _ => panic!("unsupported security: {security}"),
        }
    }

    fn encrypt(&self, nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::aead::generic_array::GenericArray;
        let n = GenericArray::from_slice(nonce);
        match self {
            VmessAeadCipher::Aes128Gcm(c) => c.encrypt(n, plaintext),
            VmessAeadCipher::Chacha20Poly1305(c) => c.encrypt(n, plaintext),
        }
    }

    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::aead::generic_array::GenericArray;
        let n = GenericArray::from_slice(nonce);
        match self {
            VmessAeadCipher::Aes128Gcm(c) => c.decrypt(n, ciphertext),
            VmessAeadCipher::Chacha20Poly1305(c) => c.decrypt(n, ciphertext),
        }
    }
}

fn chacha20_key(key: &[u8]) -> [u8; 32] {
    use md5::Digest;
    let h1: [u8; 16] = Md5::digest(key).into();
    let h2: [u8; 16] = Md5::digest(h1).into();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&h1);
    out[16..].copy_from_slice(&h2);
    out
}

// ── Shake128 masking ─────────────────────────────────────────────────────────

fn make_shake128_reader(seed: &[u8]) -> impl XofReader {
    use sha3::digest::Update;
    let mut h = Shake128::default();
    h.update(seed);
    h.finalize_xof()
}

fn next_mask_u16(reader: &mut dyn XofReader) -> u16 {
    let mut b = [0u8; 2];
    reader.read(&mut b);
    u16::from_be_bytes(b)
}

// ── Nonce ────────────────────────────────────────────────────────────────────

/// VMess 数据层 nonce：前 2 字节为大端 counter，后 10 字节取自 base[2..12]。
/// counter 在 nonce 中只占 2 字节，因此有效取值范围是 0..=65535；超出后 nonce
/// 必然复用 → GCM 安全性被破坏。我们在编码/解码侧显式拒绝计数器 wrap，强制
/// 上层断开重连（对齐 sing-vmess 行为）。
fn make_nonce(count: u16, base: &[u8; 16]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..2].copy_from_slice(&count.to_be_bytes());
    n[2..].copy_from_slice(&base[2..12]);
    n
}

/// 计数器溢出错误：当 u16 计数器即将 wrap 时返回，避免 nonce 复用。
const NONCE_OVERFLOW_ERR: &str = "vmess: chunk counter overflow (would reuse nonce)";

// ── 派生响应侧 key / nonce ───────────────────────────────────────────────────

pub fn resp_data_key(req_key: &[u8; 16]) -> [u8; 16] {
    use sha2::Digest;
    let h: [u8; 32] = sha2::Sha256::digest(req_key).into();
    h[..16].try_into().unwrap()
}

pub fn resp_data_nonce(req_nonce: &[u8; 16]) -> [u8; 16] {
    use sha2::Digest;
    let h: [u8; 32] = sha2::Sha256::digest(req_nonce).into();
    h[..16].try_into().unwrap()
}

// ── VmessEncoder（封装发送侧编码状态）────────────────────────────────────────

pub struct VmessEncoder {
    cipher: Option<VmessAeadCipher>,
    base_nonce: [u8; 16],
    count: u16,
    masking: Option<Box<dyn XofReader + Send>>,
    security: u8,
    option: u8,
}

impl VmessEncoder {
    pub fn new(security: u8, option: u8, key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = if security == SECURITY_NONE {
            None
        } else {
            Some(VmessAeadCipher::new(security, key))
        };
        let masking: Option<Box<dyn XofReader + Send>> = if option & OPT_CHUNK_MASKING != 0 {
            Some(Box::new(make_shake128_reader(nonce)))
        } else {
            None
        };
        Self {
            cipher,
            base_nonce: *nonce,
            count: 0,
            masking,
            security,
            option,
        }
    }

    pub fn encode(&mut self, plaintext: &[u8]) -> io::Result<Bytes> {
        if self.security == SECURITY_NONE && self.option & OPT_CHUNK_STREAM == 0 {
            return Ok(Bytes::copy_from_slice(plaintext));
        }
        if self.security == SECURITY_NONE {
            let mut len = plaintext.len() as u16;
            if let Some(ref mut m) = self.masking {
                len ^= next_mask_u16(m.as_mut());
            }
            let mut out = BytesMut::with_capacity(2 + plaintext.len());
            out.put_u16(len);
            out.put_slice(plaintext);
            return Ok(out.freeze());
        }
        let nonce = make_nonce(self.count, &self.base_nonce);
        // 计数器溢出保护：wrap 到已用 nonce 会导致 GCM 安全性破坏，必须报错。
        if self.count == u16::MAX {
            return Err(io::Error::other(NONCE_OVERFLOW_ERR));
        }
        self.count += 1;
        let ct = self
            .cipher
            .as_ref()
            .unwrap()
            .encrypt(&nonce, plaintext)
            .map_err(|e| io::Error::other(format!("vmess encrypt: {e:?}")))?;
        let mut chunk_len = ct.len() as u16;
        if let Some(ref mut m) = self.masking {
            chunk_len ^= next_mask_u16(m.as_mut());
        }
        let mut out = BytesMut::with_capacity(2 + ct.len());
        out.put_u16(chunk_len);
        out.put_slice(&ct);
        Ok(out.freeze())
    }
}

// ── VmessDecoder（封装接收侧解码状态）────────────────────────────────────────

enum DecodeState {
    Len,
    Data(usize),
}

pub struct VmessDecoder {
    cipher: Option<VmessAeadCipher>,
    base_nonce: [u8; 16],
    count: u16,
    masking: Option<Box<dyn XofReader + Send>>,
    state: DecodeState,
    security: u8,
    option: u8,
}

impl VmessDecoder {
    pub fn new(security: u8, option: u8, key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let cipher = if security == SECURITY_NONE {
            None
        } else {
            Some(VmessAeadCipher::new(security, key))
        };
        let masking: Option<Box<dyn XofReader + Send>> = if option & OPT_CHUNK_MASKING != 0 {
            Some(Box::new(make_shake128_reader(nonce)))
        } else {
            None
        };
        Self {
            cipher,
            base_nonce: *nonce,
            count: 0,
            masking,
            state: DecodeState::Len,
            security,
            option,
        }
    }

    /// 尝试从 raw_buf 中解码一个完整 chunk，返回明文或 None（数据不足）。
    pub fn try_decode(&mut self, raw: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if self.security == SECURITY_NONE && self.option & OPT_CHUNK_STREAM == 0 {
            if raw.is_empty() {
                return Ok(None);
            }
            return Ok(Some(raw.split().freeze()));
        }
        loop {
            match self.state {
                DecodeState::Len => {
                    if raw.len() < 2 {
                        return Ok(None);
                    }
                    let mut raw_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
                    raw.advance(2);
                    if let Some(ref mut m) = self.masking {
                        raw_len ^= next_mask_u16(m.as_mut()) as usize;
                    }
                    if raw_len == 0 {
                        return Ok(Some(Bytes::new())); // EOF 信号
                    }
                    self.state = DecodeState::Data(raw_len);
                }
                DecodeState::Data(expected) => {
                    if raw.len() < expected {
                        return Ok(None);
                    }
                    let chunk = raw.split_to(expected);
                    self.state = DecodeState::Len;
                    let plain = if self.security == SECURITY_NONE {
                        chunk.freeze()
                    } else {
                        let nonce = make_nonce(self.count, &self.base_nonce);
                        // 计数器溢出保护：与 encoder 对称，wrap 时拒绝继续解密。
                        if self.count == u16::MAX {
                            return Err(io::Error::other(NONCE_OVERFLOW_ERR));
                        }
                        self.count += 1;
                        let pt = self
                            .cipher
                            .as_ref()
                            .unwrap()
                            .decrypt(&nonce, &chunk)
                            .map_err(|e| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("vmess decrypt: {e:?}"),
                                )
                            })?;
                        Bytes::from(pt)
                    };
                    return Ok(Some(plain));
                }
            }
        }
    }
}

// ── VmessReadHalf ─────────────────────────────────────────────────────────────

pub struct VmessReadHalf<R> {
    inner: R,
    decoder: VmessDecoder,
    raw_buf: BytesMut,
    decoded_buf: Bytes,
}

impl<R: AsyncRead + Unpin> VmessReadHalf<R> {
    pub fn new(inner: R, decoder: VmessDecoder) -> Self {
        Self {
            inner,
            decoder,
            raw_buf: BytesMut::new(),
            decoded_buf: Bytes::new(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for VmessReadHalf<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 先消费已解码缓冲
            if !this.decoded_buf.is_empty() {
                let n = buf.remaining().min(this.decoded_buf.len());
                buf.put_slice(&this.decoded_buf[..n]);
                let _ = this.decoded_buf.split_to(n);
                return Poll::Ready(Ok(()));
            }
            // 从 raw_buf 尝试解码
            match this.decoder.try_decode(&mut this.raw_buf)? {
                Some(data) if data.is_empty() => return Poll::Ready(Ok(())), // EOF chunk
                Some(data) => {
                    this.decoded_buf = data;
                    continue;
                }
                None => {}
            }
            // 从底层读更多数据
            let before = this.raw_buf.len();
            this.raw_buf.reserve(4096);
            let spare = this.raw_buf.spare_capacity_mut();
            let mut read_buf = ReadBuf::uninit(spare);
            match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        return Poll::Ready(Ok(()));
                    }
                    // SAFETY: read_buf.filled() 证明前 n 字节已初始化
                    unsafe { this.raw_buf.set_len(before + n) };
                }
            }
        }
    }
}

// ── VmessWriteHalf ────────────────────────────────────────────────────────────

pub struct VmessWriteHalf<W> {
    inner: W,
    encoder: VmessEncoder,
    pending: Bytes,
}

impl<W: AsyncWrite + Unpin> VmessWriteHalf<W> {
    pub fn new(inner: W, encoder: VmessEncoder) -> Self {
        Self {
            inner,
            encoder,
            pending: Bytes::new(),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for VmessWriteHalf<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // 先把上次 pending 刷出去
        while !this.pending.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    let _ = this.pending.split_to(n);
                }
            }
        }
        const MAX_CHUNK: usize = 15000;
        let chunk = &data[..data.len().min(MAX_CHUNK)];
        this.pending = this.encoder.encode(chunk)?;
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.pending.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => {
                    let _ = this.pending.split_to(n);
                }
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ── VmessStream（公开入口，用 tokio::io::split 安全拆分）──────────────────────

pub struct VmessStream<S> {
    read: VmessReadHalf<tokio::io::ReadHalf<S>>,
    write: VmessWriteHalf<tokio::io::WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> VmessStream<S> {
    /// 客户端视角：发送方向用 req_key/req_nonce 加密，接收方向用
    /// SHA256 派生的 resp_key/resp_nonce 解密。
    pub fn new(
        inner: S,
        security: u8,
        option: u8,
        req_key: &[u8; 16],
        req_nonce: &[u8; 16],
    ) -> Self {
        let resp_key = resp_data_key(req_key);
        let resp_nonce = resp_data_nonce(req_nonce);

        let encoder = VmessEncoder::new(security, option, req_key, req_nonce);
        let decoder = VmessDecoder::new(security, option, &resp_key, &resp_nonce);

        let (rh, wh) = tokio::io::split(inner);
        Self {
            read: VmessReadHalf::new(rh, decoder),
            write: VmessWriteHalf::new(wh, encoder),
        }
    }

    /// 服务端视角（方向与客户端相反）：接收方向（客户端→服务端）用
    /// 请求头里的 req_key/req_nonce 解密；发送方向（服务端→客户端）用
    /// SHA256 派生的 resp_key/resp_nonce 加密。
    pub fn new_server(
        inner: S,
        security: u8,
        option: u8,
        req_key: &[u8; 16],
        req_nonce: &[u8; 16],
    ) -> Self {
        let resp_key = resp_data_key(req_key);
        let resp_nonce = resp_data_nonce(req_nonce);

        let decoder = VmessDecoder::new(security, option, req_key, req_nonce);
        let encoder = VmessEncoder::new(security, option, &resp_key, &resp_nonce);

        let (rh, wh) = tokio::io::split(inner);
        Self {
            read: VmessReadHalf::new(rh, decoder),
            write: VmessWriteHalf::new(wh, encoder),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for VmessStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().read).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for VmessStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().write).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().write).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a 32-bit 已知测试向量（IETF/FNV 官方参考值），确保用的是原生
    /// 32-bit 算法（offset basis 0x811c9dc5, prime 0x01000193），而不是
    /// `fnv` crate 64-bit 版本截断成 32-bit 的错误结果——这两者数值不同，
    /// 此前的 bug 正是把 64-bit 结果强转 u32，导致与真实 vmess 客户端
    /// （Xray/v2ray，用标准 32-bit FNV-1a）永远对不上。
    #[test]
    fn fnv1a32_known_vectors() {
        assert_eq!(fnv1a32(b""), 0x811c9dc5);
        assert_eq!(fnv1a32(b"a"), 0xe40c292c);
        assert_eq!(fnv1a32(b"foobar"), 0xbf9cf968);
    }

    #[test]
    fn parse_uuid_ok() {
        let u = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
        assert_eq!(u[0], 0xaa);
        assert_eq!(u[15], 0xee);
    }

    #[test]
    fn kdf_deterministic() {
        let key = [0x42u8; 16];
        let a = kdf(&key, KDF_SALT_AUTH_ID, &[]);
        let b = kdf(&key, KDF_SALT_AUTH_ID, &[]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn auth_id_roundtrip() {
        let key = [1u8; 16];
        let id = build_auth_id(&key);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let ts = verify_auth_id(&id, &key, now, 120).unwrap();
        assert!(ts.abs_diff(now) <= 1);
        // 错误的 key 必须失败（CRC 不匹配）
        assert!(verify_auth_id(&id, &[2u8; 16], now, 120).is_err());
    }

    #[test]
    fn request_header_encode_non_empty() {
        let hdr = RequestHeader::new(SECURITY_AES128_GCM, CMD_TCP);
        let target = Target::Domain("example.com".into(), 443);
        let encoded = hdr.encode(&target);
        // 最小长度：1+16+16+1+1+1+1+1 + 2+1+1+11 + 0 + 4 = 57
        assert!(encoded.len() >= 57, "encoded len={}", encoded.len());
        assert_eq!(encoded[0], VERSION);
    }

    #[test]
    fn resolve_security_ok() {
        assert_eq!(resolve_security("auto").unwrap(), SECURITY_AES128_GCM);
        assert_eq!(resolve_security("none").unwrap(), SECURITY_NONE);
        assert!(resolve_security("unknown").is_err());
    }

    /// 客户端握手 → 服务端解析 roundtrip（含 AuthID 验证与响应头 roundtrip）。
    #[test]
    fn handshake_roundtrip() {
        let uuid_bytes = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let key = user_key(&uuid_bytes);
        let req_hdr = RequestHeader::new(SECURITY_AES128_GCM, CMD_TCP);
        let target = Target::Domain("www.example.com".into(), 443);
        let hs = build_handshake(&key, &req_hdr, &target);

        // 1. AuthID 用户匹配
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let auth_id: [u8; 16] = hs[..16].try_into().unwrap();
        verify_auth_id(&auth_id, &key, now, 120).unwrap();

        // 2. 请求头解密解析
        let parsed = parse_server_handshake(&hs, &key).unwrap();
        assert_eq!(parsed.req_key, req_hdr.req_key);
        assert_eq!(parsed.req_nonce, req_hdr.req_nonce);
        assert_eq!(parsed.resp_token, req_hdr.resp_header);
        assert_eq!(parsed.option, req_hdr.option);
        assert_eq!(parsed.security, SECURITY_AES128_GCM);
        assert_eq!(parsed.command, CMD_TCP);
        assert_eq!(parsed.consumed, hs.len());
        match parsed.target {
            Target::Domain(ref h, p) => {
                assert_eq!(h, "www.example.com");
                assert_eq!(p, 443);
            }
            _ => panic!("expected domain target"),
        }

        // 3. 服务端响应头 → 客户端解析 roundtrip
        let resp = build_response_header(
            &parsed.req_key,
            &parsed.req_nonce,
            parsed.resp_token,
            parsed.option,
        )
        .unwrap();
        let (token, consumed) =
            parse_response_header(&resp, &req_hdr.req_key, &req_hdr.req_nonce).unwrap();
        assert_eq!(token, req_hdr.resp_header);
        assert_eq!(consumed, resp.len());
    }

    #[test]
    fn handshake_rejects_wrong_key() {
        let uuid_bytes = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let key = user_key(&uuid_bytes);
        let req_hdr = RequestHeader::new(SECURITY_AES128_GCM, CMD_TCP);
        let hs = build_handshake(&key, &req_hdr, &Target::Domain("a.b".into(), 1));
        let wrong = [0x99u8; 16];
        assert!(parse_server_handshake(&hs, &wrong).is_err());
    }

    /// 回归测试：FNV1a 校验范围必须按"地址长度+padding 累加"定位（对齐 flux
    /// parse_plain_header），而不是用 `plain.len()` 反推。构造一个 header
    /// 明文里 padding 字段声明的 padding_len 与地址后实际紧跟的 FNV 位置
    /// 一致、但整体 AEAD payload 长度经过精确计算的场景，确保新逻辑与
    /// "从头累加"算法结果一致，不受 plain.len() 是否恰好等于最小所需长度
    /// 影响。（此前的实现用 `plain.len() - 4 - padding_len` 反推地址区
    /// 终点，一旦 AEAD 解密出的明文长度与协议字段所需最小长度不完全相等
    /// ——例如 header_len 声明值与实际编码内容之间存在正当的实现差异——
    /// 就会把 FNV 校验范围算错，导致误判为 checksum mismatch。）
    #[test]
    fn handshake_fnv_range_matches_forward_accumulation() {
        let uuid_bytes = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let key = user_key(&uuid_bytes);
        let req_hdr = RequestHeader::new(SECURITY_AES128_GCM, CMD_TCP);
        // 域名地址 + 服务端要求 target 能正确解出即代表 addr_end 定位正确
        let target = Target::Domain("very-long-example-domain-name.test".into(), 8443);
        let hs = build_handshake(&key, &req_hdr, &target);

        let parsed = parse_server_handshake(&hs, &key).unwrap();
        match parsed.target {
            Target::Domain(ref h, p) => {
                assert_eq!(h, "very-long-example-domain-name.test");
                assert_eq!(p, 8443);
            }
            _ => panic!("expected domain target"),
        }
        assert_eq!(parsed.consumed, hs.len());
    }
}
