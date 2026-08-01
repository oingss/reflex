use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    io::{self},
    pin::Pin,
    task::{Context, Poll},
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Nonce,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use md5::Md5;
use sha3::{
    digest::{ExtendableOutput, XofReader},
    Shake128,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::{
    config::outbound::{VmessOutboundConfig, VmessTransportConfig},
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{
        apply_mark_to_tcp, relay, resolve_server_addr, resolve_target_with_dns, set_tcp_opts,
        AsyncReadWrite, Outbound, OutboundStatus,
    },
};

// ════════════════════════════════════════════════════════════════════════════
// 协议帧构建与 KDF 派生（原 frame.rs）
// ════════════════════════════════════════════════════════════════════════════
//
// 对照 sing-vmess/protocol.go 和 sing-vmess/client.go 的 AEAD 握手路径
// （alterId == 0，即现代 VMess）实现。
//
// # 握手布局（AEAD 模式）
// ```text
// [AuthID 16B] [EncHeaderLen 2+16B] [ConnNonce 8B] [EncHeader N+16B]
// ```
//
// ## Header 明文（在 encodeHeader 中构建）
// ```text
// [Ver=1 1B][ReqNonce 16B][ReqKey 16B][RespHeader 1B]
// [Option 1B][PaddingLen<<4|Security 1B][Reserved=0 1B][Command 1B]
// [Port 2B BE][Atyp 1B][Addr ...][Padding padLen B][FNV1a 4B]
// ```
//
// ## KDF 派生（HMAC-SHA256 链式，sing-vmess/kdf.go）
// KDF(key, salt, path...) = HMAC-SHA256(HMAC-SHA256(..., salt), key)

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
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x03;
const ATYP_DOMAIN: u8 = 0x02;

// packetaddr ATYP 常量（与 sing-vmess packetaddr.AddressSerializer 一致）
// 注意：这些值与 VMess 请求头的 ATYP 不同！
// packetaddr: 0x01=IPv4, 0x02=IPv6, 不支持域名（FQDN）
// VMess 头:   0x01=IPv4, 0x02=Domain, 0x03=IPv6
const PACKETADDR_ATYP_IPV4: u8 = 0x01;
const PACKETADDR_ATYP_IPV6: u8 = 0x02;

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

/// 构建 16 字节 AuthID（对应 sing-vmess/protocol.go AuthID()）
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

/// AES-128-ECB 加密单个 16 字节块（无 padding）
fn aes_ecb_encrypt_inplace(block: &mut [u8; 16], key: &[u8]) {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new_from_slice(key).expect("aes key");
    let mut b = aes::Block::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    block.copy_from_slice(&b);
}

// ── Header 明文编码（对应 rawClientConn.encodeHeader）────────────────────────

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
        use fnv::FnvHasher;
        use std::hash::Hasher;

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
        let mut h = FnvHasher::default();
        h.write(&buf);
        buf.put_u32(h.finish() as u32);

        buf.freeze()
    }
}

fn write_target(buf: &mut BytesMut, target: &Target) {
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

// ── AEAD 握手帧打包（对应 rawClientConn.writeHandshake alterId==0 分支）───────

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

// ── 响应头解析（对应 rawClientConn.readResponse alterId==0 分支）─────────────

/// 从流中读取并解密 VMess AEAD 响应头，返回消耗的字节数。
///
/// 响应布局：
/// ```text
/// [EncRespLen 2+16B][EncRespHeader 4+16B]
/// ```
/// 解密后 header 内容：[RespVersion 1B][RespToken 1B][Cmd 1B][CmdLen 1B]
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

// ── 杂项工具 ──────────────────────────────────────────────────────────────────

fn sha256(input: &[u8]) -> [u8; 32] {
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
// AEAD 数据传输层：分帧读写器（原 aead.rs）
// ════════════════════════════════════════════════════════════════════════════
//
// 握手完成后，所有数据用带计数器的 AES-128-GCM / ChaCha20-Poly1305 加密。
// 每帧格式：[len_masked 2B] [ciphertext + GCM_TAG 16B]
//
// Nonce：前 2 字节 = 大端计数器，后 10 字节取自 req_nonce[2..12]。
// 发送用 req_key/req_nonce，接收用 SHA256(req_key)/SHA256(req_nonce) 的前 16 字节。

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
    read: VmessReadHalf<ReadHalf<S>>,
    write: VmessWriteHalf<WriteHalf<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> VmessStream<S> {
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

// ════════════════════════════════════════════════════════════════════════════
// 主结构与 Outbound 实现（原 mod.rs）
// ════════════════════════════════════════════════════════════════════════════

pub struct VmessOutbound {
    config: VmessOutboundConfig,
    user_key: [u8; 16],
    security: u8,
    /// 全局 SO_MARK（来自 global.routing_mark），0 表示不设置
    routing_mark: u32,
    /// 用于解析 `server` 域名（走 dns.proxy_domain_resolver），None 时回退系统 DNS
    resolver: Option<Arc<DnsResolver>>,
}

impl VmessOutbound {
    pub fn new(config: VmessOutboundConfig) -> anyhow::Result<Self> {
        let uuid = parse_uuid(&config.uuid)?;
        let user_key = user_key(&uuid);
        // 与 sing-box protocol/vmess/outbound.go:93-99 对齐：
        // security 为空时默认 "auto"；"auto" + TLS 启用时降级为 "zero"（明文），
        // 因为外层 TLS 已提供机密性，内层再加密是冗余。
        let normalized = if config.security.is_empty() {
            "auto"
        } else {
            config.security.as_str()
        };
        let effective_security = match (normalized, config.tls.enabled) {
            ("auto", true) => "zero",
            (s, _) => s,
        };
        let security = resolve_security(effective_security)?;
        Ok(Self {
            config,
            user_key,
            security,
            routing_mark: 0,
            resolver: None,
        })
    }

    pub fn with_resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    pub fn with_mark(mut self, mark: u32) -> Self {
        self.routing_mark = mark;
        self
    }

    // ── 建立底层连接 ────────────────────────────────────────────────────────

    async fn connect_raw(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        match &self.config.transport {
            VmessTransportConfig::Ws(ws_cfg) => {
                let sni = self
                    .config
                    .tls
                    .server_name
                    .as_deref()
                    .unwrap_or(self.config.server.as_str());
                let tls_opt = if self.config.tls.enabled {
                    Some(&self.config.tls)
                } else {
                    None
                };
                let ws = crate::outbound::transport::websocket::connect(
                    &self.config.server,
                    self.config.server_port,
                    sni,
                    tls_opt,
                    ws_cfg,
                    self.routing_mark,
                    self.resolver.clone(),
                )
                .await?;
                Ok(Box::new(
                    crate::outbound::transport::websocket::WsStream::new(ws),
                ))
            }
            VmessTransportConfig::Xhttp(xhttp_cfg) => {
                use crate::outbound::transport::xhttp;
                use std::collections::HashMap;
                let stream = xhttp::connect(
                    &self.config.server,
                    self.config.server_port,
                    xhttp_cfg,
                    if self.config.tls.enabled {
                        Some(&self.config.tls)
                    } else {
                        None
                    },
                    &HashMap::new(),
                    self.routing_mark,
                    self.resolver.clone(),
                )
                .await?;
                Ok(Box::new(stream))
            }
            VmessTransportConfig::Grpc(grpc_cfg) => {
                let sni = self
                    .config
                    .tls
                    .server_name
                    .as_deref()
                    .unwrap_or(self.config.server.as_str());
                let tls_opt = if self.config.tls.enabled {
                    Some(&self.config.tls)
                } else {
                    None
                };
                let stream = crate::outbound::transport::grpc::connect(
                    &self.config.server,
                    self.config.server_port,
                    sni,
                    tls_opt,
                    grpc_cfg,
                    self.routing_mark,
                    self.resolver.clone(),
                )
                .await?;
                Ok(Box::new(stream))
            }
            VmessTransportConfig::Tcp => self.connect_tcp_raw().await,
        }
    }

    async fn connect_tcp_raw(&self) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let server = &self.config.server;
        let port = self.config.server_port;
        let addr = resolve_server_addr(server, port, self.resolver.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;
        let tcp = TcpStream::connect(addr).await?;
        set_tcp_opts(&tcp)?;
        apply_mark_to_tcp(&tcp, self.routing_mark)?;
        if self.config.tls.enabled {
            let sni = self
                .config
                .tls
                .server_name
                .as_deref()
                .unwrap_or(server.as_str());
            let stream =
                crate::outbound::tls::connect_tls_or_utls(tcp, sni, &self.config.tls).await?;
            Ok(Box::new(stream))
        } else {
            Ok(Box::new(tcp))
        }
    }

    // ── VMess 握手 ───────────────────────────────────────────────────────────

    async fn handshake(
        &self,
        mut raw: Box<dyn AsyncReadWrite>,
        target: &Target,
        command: u8,
    ) -> anyhow::Result<VmessStream<Box<dyn AsyncReadWrite>>> {
        let req_hdr = RequestHeader::new(self.security, command);

        // 1. 发送握手帧（AuthID + EncLen + ConnNonce + EncHeader）
        let handshake_bytes = build_handshake(&self.user_key, &req_hdr, target);
        raw.write_all(&handshake_bytes).await?;
        raw.flush().await?;

        // 2. 读取响应头
        // AEAD 响应：[EncLen 2+16B][EncHeader 4+16B] = 38 字节
        const RESP_TOTAL: usize = (2 + 16) + (4 + 16);
        let mut resp_buf = vec![0u8; RESP_TOTAL];
        raw.read_exact(&mut resp_buf).await?;

        let (token, _) = parse_response_header(&resp_buf, &req_hdr.req_key, &req_hdr.req_nonce)?;
        anyhow::ensure!(
            token == req_hdr.resp_header,
            "vmess: response token mismatch (got {token:#04x}, expected {:#04x})",
            req_hdr.resp_header
        );

        debug!(tag = %self.config.tag, target = %target, "vmess handshake ok");

        // 3. 包装为 VmessStream
        Ok(VmessStream::new(
            raw,
            self.security,
            req_hdr.option,
            &req_hdr.req_key,
            &req_hdr.req_nonce,
        ))
    }
}

// ── Outbound impl ─────────────────────────────────────────────────────────────

#[async_trait::async_trait]
impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "VMess".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn connect_tcp(&self, host: &str, port: u16) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let raw = self.connect_raw().await?;
        let stream = self.handshake(raw, &target, CMD_TCP).await?;
        Ok(Box::new(stream))
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        let raw = self.connect_raw().await?;
        let vmess = self.handshake(raw, &conn.target, CMD_TCP).await?;
        debug!(tag = %self.config.tag, target = %conn.target, "vmess tcp relay");
        Ok(relay(conn.stream, vmess).await)
    }

    async fn handle_udp(&self, mut packet: InboundUdpPacket) -> anyhow::Result<()> {
        let raw = self.connect_raw().await?;
        // packetaddr 模式：请求头中使用魔术地址，服务端据此进入 packetaddr 模式。
        // 真实目标地址通过后续分帧的 [ATYP][ADDR][PORT][DATA] 携带。
        // 旧实现将实际目标写入请求头，服务端不进入 packetaddr 模式 → UDP 不可用。
        use crate::inbound::Target;
        let magic_target = Target::Domain(PACKETADDR_MAGIC.to_string(), PACKETADDR_MAGIC_PORT);
        let mut vmess = self.handshake(raw, &magic_target, CMD_UDP).await?;
        debug!(tag = %self.config.tag, target = %packet.target, "vmess udp relay (packetaddr)");

        // packetaddr 不支持 FQDN（sing-vmess packetaddr.ErrFqdnUnsupported），
        // 必须先将域名目标解析为 IP，再构建 packetaddr 帧。
        // 与 sing-box protocol/vmess/outbound.go:198 对齐：
        //   "packetaddr: domain destination is not supported"
        let first_dst_addr =
            resolve_target_with_dns(&packet.target, self.resolver.as_ref()).await?;

        // VMess UDP 使用 packetaddr 分帧（与 sing-vmess packetaddr.AddressSerializer 一致）：
        //   [ATYP 1B][ADDR 4/16B][PORT u16 BE][DATA]
        // 无长度前缀，帧边界由 VMess AEAD chunk stream 的 chunk 边界提供。
        // 旧实现直接 write_all(&packet.data)，将裸 payload 写入流隧道，
        // 服务端无法区分包边界，也无法将回包关联到正确目标地址，
        // 导致 UDP 实质不可用。

        // 发送第一个包（带 packetaddr 帧）
        let frame = build_packetaddr_frame(first_dst_addr, &packet.data);
        vmess.write_all(&frame).await?;
        vmess.flush().await?;

        let reply_tx = packet.session.reply_tx.clone();
        let src = packet.src;
        let spoofed_src = packet
            .origin_destination
            .unwrap_or_else(|| packet.target.to_socket_addr_lossy());
        let timeout = std::time::Duration::from_secs(10);

        // 若有后续上行包，spawn task 持续写入 vmess 隧道（每包带 packetaddr 帧）
        if let Some(mut upstream_rx) = packet.upstream_rx.take() {
            let (vmess_rd, mut vmess_wr) = tokio::io::split(vmess);
            let resolver = self.resolver.clone();
            // 会话按 (src, outbound) 聚合后每包目标可能不同；packetaddr
            // 不支持 FQDN，需按每包 target 解析为 SocketAddr。用 HashMap 缓存
            // 避免同一目标每包都走 DNS。
            let first_target = packet.target.clone();

            tokio::spawn(async move {
                let mut dst_cache: std::collections::HashMap<Target, SocketAddr> =
                    std::collections::HashMap::new();
                dst_cache.insert(first_target, first_dst_addr);
                while let Some((target, data)) = upstream_rx.recv().await {
                    let dst_addr = match dst_cache.get(&target).copied() {
                        Some(d) => d,
                        None => match resolve_target_with_dns(&target, resolver.as_ref()).await {
                            Ok(d) => {
                                dst_cache.insert(target, d);
                                d
                            }
                            Err(e) => {
                                debug!(target=%target, err=%e, "vmess udp: dns resolve error");
                                continue;
                            }
                        },
                    };
                    let frame = build_packetaddr_frame(dst_addr, &data);
                    if vmess_wr.write_all(&frame).await.is_err() || vmess_wr.flush().await.is_err()
                    {
                        break;
                    }
                }
            });

            // 接收侧：从流中按 packetaddr 帧解析回包
            let mut reader = PacketAddrReader::new(vmess_rd);
            let mut buf = vec![0u8; 65535];
            loop {
                match tokio::time::timeout(timeout, reader.read_packet(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        let _ = reply_tx
                            .send((Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                            .await;
                    }
                    Ok(Err(_)) => break,
                }
            }
        } else {
            let mut reader = PacketAddrReader::new(vmess);
            let mut buf = vec![0u8; 65535];
            loop {
                match tokio::time::timeout(timeout, reader.read_packet(&mut buf)).await {
                    Ok(Ok(0)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        let _ = reply_tx
                            .send((Bytes::copy_from_slice(&buf[..n]), src, spoofed_src))
                            .await;
                    }
                    Ok(Err(_)) => break,
                }
            }
        }
        Ok(())
    }
}

// ════════════════════════════════════════════════════════════════════════════
// VMess UDP packetaddr 分帧
// ════════════════════════════════════════════════════════════════════════════
//
// VMess CMD_UDP 模式下，所有 UDP 数据包通过一条 TCP 流隧道传输。
// 为区分包边界并携带目标地址，每个包使用 packetaddr 帧格式：
//
//   [ATYP 1B][ADDR 4/16B][PORT u16 BE][DATA]
//
// 与 sing-vmess packetaddr.AddressSerializer 一致：
//   - ATYP 0x01 = IPv4 (4 字节地址)
//   - ATYP 0x02 = IPv6 (16 字节地址)
//   - 不支持域名（FQDN），调用方必须先解析域名
//
// **无长度前缀**：帧边界由 VMess AEAD chunk stream 的 chunk 边界提供。
// 每次 write_all 写入一个 chunk = 一个 packetaddr 帧；
// 每次 read 返回一个 chunk = 一个完整帧。
// 这与 sing-vmess packetconn.ReadPacket 的行为一致（底层 NetPacketConn.ReadPacket
// 读取一个 chunk 到 buffer，再从 buffer 头部解析 AddrPort，剩余即为 payload）。

/// 构建 packetaddr 帧：[ATYP][ADDR][PORT u16 BE][DATA]
///
/// 调用方必须传入已解析的 `SocketAddr`，因为 packetaddr 不支持 FQDN。
pub(crate) fn build_packetaddr_frame(addr: SocketAddr, data: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(32 + data.len());
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.put_u8(PACKETADDR_ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.put_u8(PACKETADDR_ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
    }
    buf.put_u16(addr.port());
    buf.put_slice(data);
    buf
}

/// 从 VMess UDP 流中按 packetaddr 帧逐包读取。
///
/// 每帧格式：[ATYP 1B][ADDR 4/16B][PORT u16 BE][DATA]
///
/// **无长度前缀**：VMess AEAD chunk stream 每次 `read` 返回一个 chunk 的数据，
/// 一个 chunk = 一个完整的 packetaddr 帧。因此一次 `read` 即可获得完整帧，
/// 从帧头解析 ATYP/ADDR/PORT 后，剩余字节即为 payload。
///
/// 这与 sing-vmess packetconn.ReadPacket 的行为一致：
/// ```go
/// func (c *PacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
///     _, err = c.NetPacketConn.ReadPacket(buffer)  // 读取一个 chunk
///     destination, err = AddressSerializer.ReadAddrPort(buffer)  // 解析帧头
///     return destination.Unwrap(), nil  // buffer 剩余字节 = payload
/// }
/// ```
pub(crate) struct PacketAddrReader<R> {
    inner: R,
    /// 内部读取缓冲区（一次 read 返回一个 chunk = 一个 packetaddr 帧）
    /// 大于 VMess MAX_CHUNK=15000，确保单次 read 能容纳整个 chunk
    chunk_buf: Vec<u8>,
}

impl<R: AsyncRead + Unpin> PacketAddrReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            chunk_buf: vec![0u8; 17000],
        }
    }

    /// 读取一个完整的 packetaddr 帧，将 payload 写入 out，返回 payload 长度。
    /// 返回 0 表示流结束。
    pub(crate) async fn read_packet(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // VMess chunk stream 每次 poll_read 返回一个 chunk 的数据。
        // 一个 chunk = 一个 packetaddr 帧 = [ATYP][ADDR][PORT u16 BE][DATA]
        // 因此一次 read 即可获得完整帧，无需长度前缀。
        let n = self.inner.read(&mut self.chunk_buf).await?;
        if n == 0 {
            return Ok(0);
        }

        if n < 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vmess packetaddr: frame too short for ATYP",
            ));
        }
        let atyp = self.chunk_buf[0];

        // 根据 ATYP 计算地址长度（与 sing-vmess packetaddr.AddressSerializer 一致）
        let addr_len = match atyp {
            PACKETADDR_ATYP_IPV4 => 4,
            PACKETADDR_ATYP_IPV6 => 16,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("vmess packetaddr: unknown ATYP {atyp:#04x}"),
                ))
            }
        };

        // 帧头 = ATYP(1) + ADDR(addr_len) + PORT(2)
        let header_len = 1 + addr_len + 2;
        if n < header_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("vmess packetaddr: frame {n} bytes shorter than header {header_len}"),
            ));
        }

        // 剩余字节即为 payload（无长度前缀，chunk 边界提供帧边界）
        let payload_len = n - header_len;
        if payload_len > out.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "vmess packetaddr: payload {payload_len} exceeds buffer {}",
                    out.len()
                ),
            ));
        }

        out[..payload_len].copy_from_slice(&self.chunk_buf[header_len..n]);
        Ok(payload_len)
    }
}

// ════════════════════════════════════════════════════════════════════════════
// 单元测试
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

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
    fn auth_id_length() {
        let key = [1u8; 16];
        let id = build_auth_id(&key);
        assert_eq!(id.len(), 16);
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
}
