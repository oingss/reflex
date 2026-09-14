use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tracing::debug;

use crate::config::outbound::UtlsFingerprint;

// ── TLS 记录层常量 ────────────────────────────────────────────────────────────

const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
const TLS_VERSION_LEGACY: u16 = 0x0301; // TLS 1.0（ClientHello legacy version）
const HS_CLIENT_HELLO: u8 = 0x01;

// ── 公开 API ──────────────────────────────────────────────────────────────────

/// 在 TCP 流上执行 uTLS 握手，返回经过 rustls 加密的 TLS 流。
///
/// 内部创建 [`UtlsStream`] 拦截 rustls 的第一次 ClientHello 写入，
/// 替换为对应 `fingerprint` 浏览器的 ClientHello 字节。
pub async fn connect_utls(
    tcp: TcpStream,
    server_name: &str,
    fingerprint: &UtlsFingerprint,
    tls_config: std::sync::Arc<rustls::ClientConfig>,
    alpn: &[String],
) -> anyhow::Result<tokio_rustls::client::TlsStream<UtlsStream>> {
    let fp = resolve_fingerprint(fingerprint);
    let hello_bytes = build_client_hello(server_name, fp, alpn);
    let wrapped = UtlsStream::new(tcp, hello_bytes);

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let sni = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| anyhow::anyhow!("utls: invalid server name: {server_name}"))?;

    let tls = connector
        .connect(sni, wrapped)
        .await
        .map_err(|e| anyhow::anyhow!("utls handshake failed: {e}"))?;
    Ok(tls)
}

// ── 指纹解析 ─────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum FpKind {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Random,
}

fn resolve_fingerprint(fp: &UtlsFingerprint) -> FpKind {
    match fp {
        UtlsFingerprint::Chrome | UtlsFingerprint::Android => FpKind::Chrome,
        UtlsFingerprint::Firefox => FpKind::Firefox,
        UtlsFingerprint::Safari | UtlsFingerprint::Ios => FpKind::Safari,
        UtlsFingerprint::Edge => FpKind::Edge,
        UtlsFingerprint::Browser360 | UtlsFingerprint::Qq => FpKind::Chrome,
        UtlsFingerprint::Go => FpKind::Chrome, // Go → Chrome 作保底
        UtlsFingerprint::Random => FpKind::Random,
    }
}

// ── ClientHello 构造 ──────────────────────────────────────────────────────────

/// 构造完整的 TLS 1.3 ClientHello TLS Record（含 TLS 记录头）。
///
/// 使用真实随机 random (32B) 和 session_id (32B)，
/// key_share 中的 x25519 公钥也随机生成（服务端只用于验证，rustls 会再次协商）。
fn build_client_hello(sni: &str, fp: FpKind, alpn_override: &[String]) -> Vec<u8> {
    let fp = match fp {
        FpKind::Random => {
            let choices = [
                FpKind::Chrome,
                FpKind::Firefox,
                FpKind::Safari,
                FpKind::Edge,
            ];
            choices[rand::thread_rng().gen_range(0..choices.len())]
        }
        other => other,
    };

    let body = build_hello_body(sni, fp, alpn_override);

    // Handshake header: type(1) + length(3)
    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(HS_CLIENT_HELLO);
    let blen = body.len() as u32;
    hs.push(((blen >> 16) & 0xff) as u8);
    hs.push(((blen >> 8) & 0xff) as u8);
    hs.push((blen & 0xff) as u8);
    hs.extend_from_slice(&body);

    // TLS Record header: content_type(1) + legacy_version(2) + length(2)
    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(TLS_CONTENT_HANDSHAKE);
    rec.push(((TLS_VERSION_LEGACY >> 8) & 0xff) as u8);
    rec.push((TLS_VERSION_LEGACY & 0xff) as u8);
    let hlen = hs.len() as u16;
    rec.push(((hlen >> 8) & 0xff) as u8);
    rec.push((hlen & 0xff) as u8);
    rec.extend_from_slice(&hs);
    rec
}

fn build_hello_body(sni: &str, fp: FpKind, alpn_override: &[String]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // random (32B)
    let mut random = [0u8; 32];
    rng.fill(&mut random);

    // session_id (32B)
    let mut session_id = [0u8; 32];
    rng.fill(&mut session_id);

    // x25519 key_share public key (32B, random placeholder)
    let mut ks_pub = [0u8; 32];
    rng.fill(&mut ks_pub);

    let cipher_suites = cipher_suites_for(fp);
    let extensions = build_extensions(sni, fp, &ks_pub, alpn_override);

    let mut b = Vec::new();
    // legacy_version TLS 1.2
    b.extend_from_slice(&[0x03, 0x03]);
    // random
    b.extend_from_slice(&random);
    // session_id length + data
    b.push(32u8);
    b.extend_from_slice(&session_id);
    // cipher_suites
    let cs_len = (cipher_suites.len() * 2) as u16;
    b.push(((cs_len >> 8) & 0xff) as u8);
    b.push((cs_len & 0xff) as u8);
    for cs in &cipher_suites {
        b.push(((cs >> 8) & 0xff) as u8);
        b.push((cs & 0xff) as u8);
    }
    // compression methods: [1, 0x00]
    b.extend_from_slice(&[0x01, 0x00]);
    // extensions
    let ext_len = extensions.len() as u16;
    b.push(((ext_len >> 8) & 0xff) as u8);
    b.push((ext_len & 0xff) as u8);
    b.extend_from_slice(&extensions);
    b
}

// ── Cipher Suites ─────────────────────────────────────────────────────────────

/// Chrome 120 cipher suites (JA3 順序)
const CHROME_CIPHERS: &[u16] = &[
    0xdada, // GREASE
    0x1301, // TLS_AES_128_GCM_SHA256
    0x1302, // TLS_AES_256_GCM_SHA384
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
    0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
];

const FIREFOX_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc00a, 0xc013,
    0xc014, 0x002f, 0x0035,
];

const SAFARI_CIPHERS: &[u16] = &[
    0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0xc030, 0xc02f, 0xcca9, 0xcca8, 0xc024, 0xc023, 0xc028,
    0xc027, 0xc00a, 0xc009, 0xc014, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
];

fn cipher_suites_for(fp: FpKind) -> Vec<u16> {
    let base: &[u16] = match fp {
        FpKind::Chrome | FpKind::Edge | FpKind::Random => CHROME_CIPHERS,
        FpKind::Firefox => FIREFOX_CIPHERS,
        FpKind::Safari => SAFARI_CIPHERS,
    };
    // 将 GREASE 0xdada 替换为随机 GREASE 值（格式：0xXAXA，X 随机）
    base.iter()
        .map(|&cs| {
            if cs == 0xdada {
                // GREASE 值格式 0xXAXA（X = 0..15），与 grease_value() 一致用 0x1010 步长。
                // 旧实现用 0x1111 步长，当 x=15 时 15*0x1111+0x0a0a = 0x10A09 溢出 u16。
                let idx = rand::thread_rng().gen_range(0u16..16);
                0x0a0a + idx * 0x1010
            } else {
                cs
            }
        })
        .collect()
}

// ── Extensions ───────────────────────────────────────────────────────────────

fn build_extensions(sni: &str, fp: FpKind, ks_pub: &[u8; 32], alpn_override: &[String]) -> Vec<u8> {
    let mut exts = Vec::new();

    // GREASE extension (Chrome/Edge)
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        let grease = grease_value();
        append_ext(&mut exts, grease, &[0u8; 0]); // empty GREASE
    }

    // SNI (0x0000)
    {
        let name = sni.as_bytes();
        let mut d = Vec::new();
        // ServerNameList length
        let list_len = (name.len() + 3) as u16;
        d.push(((list_len >> 8) & 0xff) as u8);
        d.push((list_len & 0xff) as u8);
        // NameType host_name = 0
        d.push(0x00);
        let name_len = name.len() as u16;
        d.push(((name_len >> 8) & 0xff) as u8);
        d.push((name_len & 0xff) as u8);
        d.extend_from_slice(name);
        append_ext(&mut exts, 0x0000, &d);
    }

    // extended_master_secret (0x0017)
    append_ext(&mut exts, 0x0017, &[]);

    // renegotiation_info (0xff01)
    append_ext(&mut exts, 0xff01, &[0x00]);

    // supported_groups (0x000a)
    {
        let groups: &[u16] = match fp {
            FpKind::Chrome | FpKind::Edge => &[0x001d, 0x0017, 0x0018], // x25519, secp256r1, secp384r1
            FpKind::Firefox => &[0x001d, 0x0017, 0x0018, 0x0019],
            FpKind::Safari | FpKind::Random => &[0x001d, 0x0017, 0x001e, 0x0018, 0x0019],
        };
        let mut d = Vec::new();
        let list_len = (groups.len() * 2) as u16;
        d.push(((list_len >> 8) & 0xff) as u8);
        d.push((list_len & 0xff) as u8);
        for g in groups {
            d.push(((g >> 8) & 0xff) as u8);
            d.push((g & 0xff) as u8);
        }
        append_ext(&mut exts, 0x000a, &d);
    }

    // ec_point_formats (0x000b)
    append_ext(&mut exts, 0x000b, &[0x01, 0x00]);

    // session_ticket (0x0023) - empty
    append_ext(&mut exts, 0x0023, &[]);

    // ALPN (0x0010)
    {
        let proto_list: Vec<&str> = if !alpn_override.is_empty() {
            alpn_override.iter().map(|s| s.as_str()).collect()
        } else {
            match fp {
                FpKind::Chrome | FpKind::Edge => vec!["h2", "http/1.1"],
                FpKind::Firefox => vec!["h2", "http/1.1"],
                FpKind::Safari | FpKind::Random => vec!["h2", "http/1.1"],
            }
        };
        let mut proto_bytes = Vec::new();
        for p in &proto_list {
            proto_bytes.push(p.len() as u8);
            proto_bytes.extend_from_slice(p.as_bytes());
        }
        let inner_len = proto_bytes.len() as u16;
        let mut d = Vec::new();
        d.push(((inner_len >> 8) & 0xff) as u8);
        d.push((inner_len & 0xff) as u8);
        d.extend_from_slice(&proto_bytes);
        append_ext(&mut exts, 0x0010, &d);
    }

    // status_request OCSP (0x0005)
    append_ext(&mut exts, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);

    // signature_algorithms (0x000d)
    {
        let algs: &[u16] = match fp {
            FpKind::Firefox => &[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
            ],
            _ => &[
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
        };
        let mut d = Vec::new();
        let list_len = (algs.len() * 2) as u16;
        d.push(((list_len >> 8) & 0xff) as u8);
        d.push((list_len & 0xff) as u8);
        for a in algs {
            d.push(((a >> 8) & 0xff) as u8);
            d.push((a & 0xff) as u8);
        }
        append_ext(&mut exts, 0x000d, &d);
    }

    // signed_cert_timestamps (0x0012) - empty
    append_ext(&mut exts, 0x0012, &[]);

    // key_share (0x0033) - x25519 only
    {
        // ClientShares: one entry for x25519 (0x001d)
        let mut share = vec![0x00];
        share.push(0x1d); // group x25519
        share.push(0x00);
        share.push(0x20); // key_exchange length 32
        share.extend_from_slice(ks_pub);

        let shares_len = share.len() as u16;
        let mut d = Vec::new();
        d.push(((shares_len >> 8) & 0xff) as u8);
        d.push((shares_len & 0xff) as u8);
        d.extend_from_slice(&share);
        append_ext(&mut exts, 0x0033, &d);
    }

    // psk_key_exchange_modes (0x002d)
    append_ext(&mut exts, 0x002d, &[0x01, 0x01]); // psk_dhe_ke

    // supported_versions (0x002b) TLS 1.3 + 1.2
    {
        let versions: &[u16] = &[0x0304, 0x0303]; // TLS 1.3, TLS 1.2
        let mut d = Vec::new();
        d.push((versions.len() * 2) as u8);
        for v in versions {
            d.push(((v >> 8) & 0xff) as u8);
            d.push((v & 0xff) as u8);
        }
        append_ext(&mut exts, 0x002b, &d);
    }

    // compress_certificate (0x001b) - Chrome/Edge
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        append_ext(&mut exts, 0x001b, &[0x02, 0x00, 0x02]); // brotli
    }

    // application_settings (0x4469) - Chrome ALPS
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        // Advertise h2 support
        append_ext(&mut exts, 0x4469, &[0x00, 0x03, 0x02, b'h', b'2']);
    }

    // padding (0x0015) - Chrome pads to avoid fingerprinting on length
    if matches!(fp, FpKind::Chrome | FpKind::Edge) {
        // Add padding to reach ~512 byte total extensions; calculate needed
        let current = exts.len() + 4; // +4 for this extension's header
        let target = 512usize;
        if current < target {
            let pad_len = target - current;
            let padding = vec![0u8; pad_len];
            append_ext(&mut exts, 0x0015, &padding);
        }
    }

    exts
}

fn append_ext(buf: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    buf.push(((ext_type >> 8) & 0xff) as u8);
    buf.push((ext_type & 0xff) as u8);
    let dlen = data.len() as u16;
    buf.push(((dlen >> 8) & 0xff) as u8);
    buf.push((dlen & 0xff) as u8);
    buf.extend_from_slice(data);
}

fn grease_value() -> u16 {
    // GREASE values: 0x0A0A, 0x1A1A, ..., 0xFAFA
    let idx = rand::thread_rng().gen_range(0u16..16);
    0x0a0a + idx * 0x1010
}

// ── UtlsStream ────────────────────────────────────────────────────────────────

// TCP 流包装器，拦截 rustls 的第一次 write（ClientHello），
// 替换为浏览器伪造的 ClientHello TLS Record。
// 后续所有 I/O 正常透传。
pin_project_lite::pin_project! {
    pub struct UtlsStream {
        #[pin]
        inner: TcpStream,
        // 替换用的伪造 ClientHello；None 表示已发送过
        fake_hello: Option<Vec<u8>>,
    }
}

impl UtlsStream {
    pub fn new(inner: TcpStream, fake_hello: Vec<u8>) -> Self {
        Self {
            inner,
            fake_hello: Some(fake_hello),
        }
    }
}

/// 从 rustls 生成的 ClientHello 中提取 key_share 扩展里的 x25519 公钥，
/// 然后把伪造 ClientHello 中对应位置的随机公钥替换为真实公钥。
///
/// **背景**：旧实现用随机生成的 x25519 公钥填充伪造 ClientHello 的 key_share，
/// 但 rustls 内部使用自己的私钥计算 ECDH 共享密钥。服务端用伪造的公钥 →
/// 共享密钥 A，rustls 用自己的私钥 → 共享密钥 B，两者不匹配 → Finished MAC
/// 失败，握手必然失败。这就是 `connect_tls_or_utls` 中 uTLS 被静默回退到
/// rustls 的根本原因。
///
/// **修正**：在 UtlsStream::poll_write 拦截到 rustls 的 ClientHello 时，
/// 解析其中的 key_share 扩展（extension type 0x0033），提取 x25519 (group 0x001d)
/// 的 32 字节公钥，然后 patch 到伪造 ClientHello 的对应位置。这样服务端和
/// rustls 使用相同的公钥/私钥对，ECDH 共享密钥一致，Finished MAC 通过。
///
/// 与 sing-box badtls/registry_utls.go 的思路对齐：让 uTLS 指纹层和 rustls
/// 的密钥层共享同一对密钥。
fn patch_key_share(fake: &mut [u8], rustls_hello: &[u8]) {
    let real_key = match extract_x25519_key_share(rustls_hello) {
        Some(k) => k,
        None => {
            debug!(
                "utls: failed to extract x25519 key_share from rustls ClientHello ({} bytes), \
                 keeping random key_share — handshake will likely fail",
                rustls_hello.len()
            );
            return;
        }
    };

    if let Some(pos) = find_x25519_key_share_pos(fake) {
        fake[pos..pos + 32].copy_from_slice(&real_key);
        debug!(
            "utls: patched fake ClientHello key_share at offset {} with real rustls x25519 pubkey",
            pos
        );
    } else {
        debug!("utls: fake ClientHello has no x25519 key_share to patch");
    }
}

/// 从 TLS ClientHello record 中解析 key_share 扩展，提取 x25519 (group 0x001d) 的公钥。
///
/// ClientHello record 布局：
/// ```text
/// [record: type=0x16 ver=0x0301 len=2B]
///   [handshake: type=0x01 len=3B]
///     [body: legacy_ver=2B random=32B session_id_len=1B session_id=N
///            cipher_suites_len=2B cipher_suites comp_len=1B comp=N
///            extensions_len=2B extensions...]
///       extension: type=2B len=2B data
///         key_share (0x0033): client_shares_len=2B
///           share: group=2B key_len=2B key=N
/// ```
fn extract_x25519_key_share(record: &[u8]) -> Option<[u8; 32]> {
    // 跳过 record header (5B) + handshake type (1B)
    if record.len() < 6 {
        return None;
    }
    if record[0] != 0x16 {
        return None;
    }
    // handshake length (3B)
    let hs_len = ((record[3] as usize) << 16) | ((record[4] as usize) << 8) | (record[5] as usize);
    if record.len() < 5 + 1 + 3 + hs_len {
        return None;
    }
    // 跳到 handshake body
    let body = &record[5 + 1 + 3..];
    // 跳过 legacy_version (2B) + random (32B)
    if body.len() < 34 {
        return None;
    }
    let mut pos = 34;
    // 跳过 session_id
    let sid_len = *body.get(pos)?;
    pos += 1 + sid_len as usize;
    // 跳过 cipher_suites
    let cs_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2 + cs_len;
    // 跳过 compression_methods
    let cm_len = *body.get(pos)?;
    pos += 1 + cm_len as usize;
    // extensions
    let ext_total_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;

    while pos + 4 <= ext_end.min(body.len()) {
        let ext_type = ((body[pos] as u16) << 8) | (body[pos + 1] as u16);
        let ext_len = ((body[pos + 2] as usize) << 8) | (body[pos + 3] as usize);
        pos += 4;
        if pos + ext_len > body.len() {
            break;
        }
        if ext_type == 0x0033 {
            // key_share extension
            return parse_key_share_extension(&body[pos..pos + ext_len]);
        }
        pos += ext_len;
    }
    None
}

/// 解析 key_share 扩展数据，找到 x25519 (group 0x001d) 的公钥。
fn parse_key_share_extension(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 2 {
        return None;
    }
    let total_len = ((data[0] as usize) << 8) | (data[1] as usize);
    let mut pos = 2;
    let end = 2 + total_len.min(data.len() - 2);
    while pos + 4 <= end {
        let group = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let key_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;
        if pos + key_len > data.len() {
            break;
        }
        if group == 0x001d && key_len == 32 {
            // x25519
            let mut key = [0u8; 32];
            key.copy_from_slice(&data[pos..pos + 32]);
            return Some(key);
        }
        pos += key_len;
    }
    None
}

/// 在伪造的 ClientHello 中找到 x25519 key_share 公钥的位置（offset）。
/// 返回公钥 32 字节的起始偏移。
fn find_x25519_key_share_pos(record: &[u8]) -> Option<usize> {
    // 与 extract_x25519_key_share 类似的解析逻辑，但返回位置而非值。
    if record.len() < 6 || record[0] != 0x16 {
        return None;
    }
    let body = &record[5 + 1 + 3..];
    if body.len() < 34 {
        return None;
    }
    let mut pos = 34;
    let sid_len = *body.get(pos)?;
    pos += 1 + sid_len as usize;
    let cs_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2 + cs_len;
    let cm_len = *body.get(pos)?;
    pos += 1 + cm_len as usize;
    let ext_total_len = ((*body.get(pos)?) as usize) << 8 | (*body.get(pos + 1)?) as usize;
    pos += 2;
    let ext_end = pos + ext_total_len;

    let body_start = 5 + 1 + 3; // body 在 record 中的绝对偏移
    while pos + 4 <= ext_end.min(body.len()) {
        let ext_type = ((body[pos] as u16) << 8) | (body[pos + 1] as u16);
        let ext_len = ((body[pos + 2] as usize) << 8) | (body[pos + 3] as usize);
        let ext_data_pos = pos + 4;
        if ext_data_pos + ext_len > body.len() {
            break;
        }
        if ext_type == 0x0033 {
            // key_share extension: client_shares_len(2B) + shares
            let shares_data = &body[ext_data_pos..ext_data_pos + ext_len];
            if shares_data.len() < 2 {
                break;
            }
            let total = ((shares_data[0] as usize) << 8) | (shares_data[1] as usize);
            let mut sp = 2;
            let s_end = 2 + total.min(shares_data.len() - 2);
            while sp + 4 <= s_end {
                let group = ((shares_data[sp] as u16) << 8) | (shares_data[sp + 1] as u16);
                let key_len =
                    ((shares_data[sp + 2] as usize) << 8) | (shares_data[sp + 3] as usize);
                let key_pos = sp + 4;
                if key_pos + key_len > shares_data.len() {
                    break;
                }
                if group == 0x001d && key_len == 32 {
                    // 返回在 record 中的绝对偏移
                    return Some(body_start + ext_data_pos + key_pos);
                }
                sp = key_pos + key_len;
            }
            break;
        }
        pos = ext_data_pos + ext_len;
    }
    None
}

impl AsyncRead for UtlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for UtlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut this = self.project();
        if let Some(hello) = this.fake_hello.as_mut() {
            // 拦截到 rustls 的第一次 write（ClientHello）。
            // 此时 `data` 是 rustls 生成的真实 ClientHello，从中提取 x25519 公钥
            // 并 patch 到伪造的 ClientHello（hello）中，修复 key_share 不匹配问题。
            //
            // 注意：仅当 data 看起来是 TLS Handshake record (type=0x16) 时才 patch，
            // 避免误处理非 ClientHello 的写入。
            if data.len() > 5 && data[0] == 0x16 {
                patch_key_share(hello, data);
            }

            // 循环发送伪造 ClientHello，正确处理 TCP 部分写入。
            loop {
                match this.inner.as_mut().poll_write(cx, hello) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "utls: write zero sending fake ClientHello",
                        )));
                    }
                    Poll::Ready(Ok(written)) => {
                        if written >= hello.len() {
                            debug!(
                                "utls: intercepted rustls ClientHello ({} bytes), \
                                 sent fake ClientHello ({} bytes)",
                                data.len(),
                                written
                            );
                            *this.fake_hello = None;
                            return Poll::Ready(Ok(data.len()));
                        }
                        // 部分写入，drain 已写入部分，继续发送剩余
                        hello.drain(..written);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }
        } else {
            this.inner.poll_write(cx, data)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_hello_is_valid_tls_record() {
        let hello = build_client_hello("example.com", FpKind::Chrome, &[]);
        // TLS record header
        assert_eq!(hello[0], TLS_CONTENT_HANDSHAKE);
        assert_eq!(hello[1], 0x03);
        assert_eq!(hello[2], 0x01);
        // Handshake type = ClientHello
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len);
        assert_eq!(hello[5], HS_CLIENT_HELLO);
    }

    #[test]
    fn firefox_hello_contains_sni() {
        let hello = build_client_hello("test.example.com", FpKind::Firefox, &[]);
        let bytes = hello.as_slice();
        let found = bytes.windows(16).any(|w| w == b"test.example.com");
        assert!(found, "SNI not found in Firefox ClientHello");
    }

    #[test]
    fn safari_hello_is_valid() {
        let hello = build_client_hello("safari.example.com", FpKind::Safari, &[]);
        assert!(hello.len() > 100);
        assert_eq!(hello[0], TLS_CONTENT_HANDSHAKE);
    }

    #[test]
    fn alpn_override_applied() {
        let hello = build_client_hello("sni.example.com", FpKind::Chrome, &["h2".to_string()]);
        let found = hello.windows(2).any(|w| w == b"h2");
        assert!(found, "ALPN h2 not found in ClientHello");
    }

    #[test]
    fn grease_value_is_grease() {
        for _ in 0..100 {
            let g = grease_value();
            let lo = g & 0xff;
            let _hi = (g >> 8) & 0xff;
            assert_eq!(lo, 0x0a + ((g & 0xf0) >> 4) * 0x10 + 0x0a - (lo & 0x0f));
            // Simpler: just check it's in the known GREASE set
            let valid = [
                0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
                0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
            ];
            assert!(valid.contains(&g), "0x{g:04x} is not a valid GREASE value");
        }
    }
}
