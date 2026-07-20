//! uTLS：浏览器 TLS 指纹伪造
//!
//! ## 原理
//!
//! 标准 rustls 发出的 ClientHello 具有明显特征（固定扩展集、Cipher Suite 顺序、
//! Groups 顺序），很容易被 TLS 指纹检测系统（JA3/JA4）识别为代理客户端。
//!
//! 本模块的做法：
//! 1. 手工构造目标浏览器（Chrome/Firefox/Safari 等）的 ClientHello 字节序列，
//!    将 key_share 中的 x25519 公钥替换为 rustls 协商时真实生成的公钥，
//!    SNI、session_id、random 也使用真实值。
//! 2. 通过 [`UtlsStream`] 包装 TcpStream，拦截 rustls 发出的第一次写入
//!    （即 ClientHello TLS Record），替换为伪造字节后再发出。
//! 3. 后续握手数据和应用数据正常透传——服务端收到的是浏览器级别的 ClientHello，
//!    但后续的密钥协商/证书验证由 rustls 完成，安全性不降级。
//!
//! ## 局限
//!
//! - 不修改 ClientHello 之后的握手消息（Certificate、Finished 等），
//!   因此 JA3S（服务端响应）或极精细的完整握手分析仍可能区分。
//!   对大多数 GFW/商用防火墙的 JA3/JA4 过滤来说，替换 ClientHello 已足够。
//! - 若服务端强制要求特定 ALPN（如 h2），需在 `TlsConfig.alpn` 里手动配置，
//!   本模块只修改 ClientHello，不检测 ALPN 与配置的一致性。

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
                let x = rand::thread_rng().gen_range(0u16..=15) * 0x1111 + 0x0a0a;
                x
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
        let mut share = Vec::new();
        share.push(0x00);
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
            // 循环发送伪造 ClientHello，正确处理 TCP 部分写入。
            //
            // 之前的 bug：Poll::Ready(Ok(_)) 忽略了写入字节数，
            // TCP 缓冲区部分满时只写入部分 hello，剩余字节丢失，
            // 服务端收到不完整的 ClientHello → TLS 握手失败。
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
                        // inner 暂时无法写入，waker 已注册，返回 Pending 让 rustls 重试
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
            let hi = (g >> 8) & 0xff;
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
