//! 服务端 REALITY TLS 层（VLESS/VMess/Trojan inbound 共用）。
//!
//! 移植自 flux-master `src/vless/tls/reality.rs`（其逻辑对齐 Xray
//! github.com/xtls/reality 与 sing-box `transport/vless`）：
//!
//! 1. 完整读取首个 TLS record 并解析 ClientHello（可移植实现——不依赖 unix 专属的
//!    `MSG_PEEK`，Windows 上同样可用；已消费字节经 [`PrefixStream`] 回放）；
//! 2. 校验 Reality 客户端：SNI 白名单、auth_key（x25519 DH + HKDF("REALITY")）、
//!    AES/ChaCha20 AEAD 解密 session_id、时间戳防重放、short_id 白名单；
//! 3. 校验通过 → 每连接实时生成 Reality 专用 ed25519 证书
//!    （signatureValue = HMAC-SHA512(auth_key, pub_key)）并完成 TLS 握手；
//!    auth_key 由客户端 ECDHE 临时公钥推导，每连接不同，证书必须实时生成。
//! 4. 校验失败 → 判定为非 Reality 客户端（扫描/探测），回落转发到
//!    `handshake.dest`（对齐 sing-box reality.handshake）。

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::Context as _;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::outbound::AsyncReadWrite;

// ── 运行时配置（从 config::inbound::InboundRealityConfig 解析）───────────────

pub struct RealityServer {
    /// 期望的 SNI（客户端 server_name 必须匹配；空 = 不校验）
    pub server_name: String,
    /// 服务端 x25519 私钥
    pub private_key: [u8; 32],
    /// shortId 白名单（二进制）
    pub short_ids: Vec<Vec<u8>>,
    /// 回落目标 "host:port"（None = 直接断开）
    pub dest: Option<String>,
    /// 客户端时间戳最大偏差（秒），≤ 0 = 不校验
    pub max_time_diff: i64,
}

impl RealityServer {
    pub fn from_config(
        cfg: &crate::config::inbound::InboundRealityConfig,
        expected_sni: Option<&str>,
    ) -> anyhow::Result<Self> {
        let priv_bytes = base64_url_decode(&cfg.private_key)?;
        anyhow::ensure!(
            priv_bytes.len() == 32,
            "reality private_key must be 32 bytes"
        );
        let mut short_ids = Vec::with_capacity(cfg.short_id.len());
        for sid_hex in &cfg.short_id {
            let sid = hex::decode(sid_hex.trim())
                .map_err(|e| anyhow::anyhow!("reality short_id '{sid_hex}' invalid hex: {e}"))?;
            anyhow::ensure!(sid.len() <= 8, "reality short_id '{sid_hex}' exceeds 8 bytes");
            short_ids.push(sid);
        }
        let dest = cfg
            .handshake
            .as_ref()
            .map(|h| format!("{}:{}", h.server, h.server_port));
        Ok(Self {
            server_name: expected_sni.unwrap_or("").to_string(),
            private_key: priv_bytes.try_into().expect("length checked"),
            short_ids,
            dest,
            max_time_diff: cfg.effective_max_time_diff(),
        })
    }
}

// ── 入口 ─────────────────────────────────────────────────────────────────────

/// 对一条已接受的 TCP 连接执行 REALITY 握手。
///
/// 返回 TLS 流（Reality 伪装证书）；非 Reality 客户端会回落转发到 dest 并
/// 返回 `Err`（连接已在本函数内被消费/转发）。
pub async fn accept(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &RealityServer,
) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
    let (record, stream) = read_client_hello_record(stream).await?;

    match verify_reality_client(&record, cfg) {
        Ok(auth_key) => {
            debug!(
                peer = %peer,
                "reality: client verified, generating per-connection cert"
            );
            let sc = build_per_connection_config(cfg, &auth_key)?;
            let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(sc)));
            let prefixed = PrefixStream::new(record, stream);
            let tls_stream = acceptor
                .accept(prefixed)
                .await
                .map_err(|e| anyhow::anyhow!("reality TLS handshake failed: {e}"))?;
            Ok(Box::new(tls_stream))
        }
        Err(e) => {
            debug!(peer = %peer, err = %e, "reality: non-reality client");
            forward_to_dest(PrefixStream::new(record, stream), cfg).await;
            anyhow::bail!("reality: non-reality client forwarded to dest")
        }
    }
}

// ── ClientHello record 读取（可移植实现）────────────────────────────────────

/// 完整读取首个 TLS record：`[type 1B][version 2B][length 2B BE][body]`。
/// 返回 (record 全字节, 原 stream)；stream 中被消费的字节由调用方通过
/// [`PrefixStream`] 回放（TLS 握手需要重新读到 ClientHello）。
async fn read_client_hello_record(mut stream: TcpStream) -> anyhow::Result<(Vec<u8>, TcpStream)> {
    let mut hdr = [0u8; 5];
    stream
        .read_exact(&mut hdr)
        .await
        .map_err(|e| anyhow::anyhow!("reality: read record header: {e}"))?;
    let record_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    anyhow::ensure!(
        record_len > 0 && record_len <= 0x4000 + 2048,
        "reality: invalid TLS record length {record_len}"
    );
    let mut record = Vec::with_capacity(5 + record_len);
    record.extend_from_slice(&hdr);
    record.resize(5 + record_len, 0);
    stream
        .read_exact(&mut record[5..])
        .await
        .map_err(|e| anyhow::anyhow!("reality: read record body: {e}"))?;
    Ok((record, stream))
}

// ── PrefixStream：把已消费的字节回放给后续读取方 ────────────────────────────

pub struct PrefixStream<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> PrefixStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            buf.put_slice(&self.prefix[self.pos..self.pos + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── 核心验证逻辑（移植 flux/Xray）───────────────────────────────────────────

// TLS ClientHello 布局常量
const RECORD_HDR: usize = 5;
const HANDSHAKE_HDR: usize = 4;
const LEGACY_VER_LEN: usize = 2;
const RANDOM_OFFSET: usize = RECORD_HDR + HANDSHAKE_HDR + LEGACY_VER_LEN; // 11
const RANDOM_LEN: usize = 32;
const SID_LEN_OFFSET: usize = RANDOM_OFFSET + RANDOM_LEN; // 43
const SID_OFFSET: usize = SID_LEN_OFFSET + 1; // 44

fn verify_reality_client(record: &[u8], cfg: &RealityServer) -> anyhow::Result<[u8; 32]> {
    if record.len() < SID_OFFSET + 32 + 4 {
        anyhow::bail!("record too short, not a ClientHello");
    }
    if record[0] != 0x16 {
        anyhow::bail!("not a TLS Handshake record (type={:#x})", record[0]);
    }
    if record[RECORD_HDR] != 0x01 {
        anyhow::bail!("not a ClientHello");
    }
    if record[SID_LEN_OFFSET] != 32 {
        anyhow::bail!(
            "session_id_len={} != 32, not a uTLS Reality client",
            record[SID_LEN_OFFSET]
        );
    }

    // SNI 校验（对齐 sing-box: config.ServerNames[serverName]）
    let client_sni = extract_sni_from_client_hello(record).unwrap_or_default();
    if !client_sni.is_empty() && !cfg.server_name.is_empty() && client_sni != cfg.server_name {
        anyhow::bail!(
            "SNI mismatch: client='{client_sni}' expected='{}'",
            cfg.server_name
        );
    }

    let random = &record[RANDOM_OFFSET..RANDOM_OFFSET + RANDOM_LEN];
    let session_id = &record[SID_OFFSET..SID_OFFSET + 32];

    let ecdhe_pub =
        extract_x25519_from_key_share(record).context("extract x25519 from key_share")?;

    let raw_auth_key = x25519_dh(&cfg.private_key, &ecdhe_pub);

    // 对齐 Xray：salt = random[..20]，info = "REALITY"
    let hk = Hkdf::<Sha256>::new(Some(&random[..20]), &raw_auth_key);
    let mut auth_key = [0u8; 32];
    hk.expand(b"REALITY", &mut auth_key)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    let nonce_bytes = &random[20..32];
    let use_aes = cipher_suite_prefers_aes(record);

    // AAD 与 Xray 一致：从 Handshake type byte 开始（不含 record 头）、
    // sessionId 字段清零
    let mut aad = record[RECORD_HDR..].to_vec();
    let aad_sid_start = SID_OFFSET - RECORD_HDR;
    aad[aad_sid_start..aad_sid_start + 32].fill(0);

    let plaintext: Vec<u8> = if use_aes {
        let aes_key = Key::<Aes256Gcm>::from_slice(&auth_key);
        let cipher = Aes256Gcm::new(aes_key);
        cipher
            .decrypt(
                Nonce::from_slice(nonce_bytes),
                Payload {
                    msg: session_id,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("AES-GCM decrypt failed, not a reality client"))?
    } else {
        let cipher = ChaCha20Poly1305::new_from_slice(&auth_key)
            .map_err(|_| anyhow::anyhow!("ChaCha20 key length error"))?;
        cipher
            .decrypt(
                ChaNonce::from_slice(nonce_bytes),
                Payload {
                    msg: session_id,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow::anyhow!("ChaCha20-Poly1305 decrypt failed, not a reality client")
            })?
    };

    // 时间戳防重放（对齐 sing-box MaxTimeDiff；明文 [0:4] ver + [4:8] time）
    if cfg.max_time_diff > 0 && plaintext.len() >= 8 {
        let client_time =
            u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]) as i64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let diff = (now - client_time).abs();
        if diff > cfg.max_time_diff {
            anyhow::bail!(
                "time skew {diff}s exceeds max_time_diff {}s, possible replay",
                cfg.max_time_diff
            );
        }
    }

    // short_id 白名单
    for sid_bytes in &cfg.short_ids {
        let n = sid_bytes.len();
        if n == 0 {
            return Ok(auth_key);
        }
        if plaintext.len() >= 8 + n && &plaintext[8..8 + n] == sid_bytes.as_slice() {
            return Ok(auth_key);
        }
    }

    anyhow::bail!("short_id mismatch")
}

// ── Reality 专用 per-connection 证书（移植 flux）────────────────────────────

/// 绕过 rustls 签名方案交集检查的 Ed25519 包装器。
///
/// uTLS 伪装成 Chrome 时 supported_signature_algorithms 是真实浏览器列表，
/// Ed25519 往往靠后或不出现，rustls 会报 NoSignatureSchemesInCommon。
/// Xray 的做法是直接强制 hs.sigAlg = Ed25519；这里对齐：
/// choose_scheme 无视客户端 offered 列表强制 Ed25519
/// （Reality 客户端只校验证书里的 HMAC-SHA512，不检查 CertificateVerify 方案）。
#[derive(Debug)]
struct AnySchemeEd25519Key(Arc<dyn rustls::sign::SigningKey>);

impl rustls::sign::SigningKey for AnySchemeEd25519Key {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        self.0.choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.0.algorithm()
    }
}

#[derive(Debug)]
struct AnySchemeEd25519CertResolver(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for AnySchemeEd25519CertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

fn build_per_connection_config(
    cfg: &RealityServer,
    auth_key: &[u8; 32],
) -> anyhow::Result<rustls::ServerConfig> {
    use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    // 1. 每连接生成 ed25519 密钥对（auth_key 每连接不同，证书不能复用）
    let key_pair =
        KeyPair::generate_for(&PKCS_ED25519).context("rcgen generate ed25519 key pair")?;

    // 2. 提取原始 ed25519 公钥（SPKI DER 末尾 32 字节）
    let spki = key_pair.public_key_raw();
    anyhow::ensure!(
        spki.len() >= 32,
        "ed25519 SPKI too short: {} bytes",
        spki.len()
    );
    let pub_key_32 = &spki[spki.len() - 32..];

    // 3. Reality 专用 Signature = HMAC-SHA512(auth_key, pub_key)
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth_key)
        .map_err(|_| anyhow::anyhow!("HMAC-SHA512 init failed"))?;
    mac.update(pub_key_32);
    let reality_sig: Vec<u8> = mac.finalize().into_bytes().to_vec();

    // 4. 自签名证书 + 替换 signatureValue
    // SAN：server_name 为空时不设 SAN（rcgen new() 不接受空串域名）
    let sans: Vec<String> = if cfg.server_name.is_empty() {
        vec![]
    } else {
        vec![cfg.server_name.clone()]
    };
    let params = CertificateParams::new(sans).context("build CertificateParams")?;
    let cert = params.self_signed(&key_pair).context("rcgen self signed")?;
    let mut der_bytes = cert.der().to_vec();
    replace_signature_in_cert_der(&mut der_bytes, &reality_sig)
        .context("replace cert signatureValue")?;

    // 5. 构建 rustls SigningKey
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
        .map_err(|e| anyhow::anyhow!("serialize private key: {e}"))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| anyhow::anyhow!("build SigningKey: {e}"))?;

    // 6. 包装 + 注入 resolver（绕过签名方案交集检查）
    let wrapped_key = Arc::new(AnySchemeEd25519Key(signing_key));
    let cert_der = CertificateDer::from(der_bytes);
    let certified_key = Arc::new(rustls::sign::CertifiedKey::new(vec![cert_der], wrapped_key));
    let resolver = Arc::new(AnySchemeEd25519CertResolver(certified_key));
    let mut sc = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    sc.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(sc)
}

// ── X.509 DER signatureValue 替换（RFC 5280 布局，移植 flux）────────────────
//
// Certificate DER：
//   SEQUENCE {
//     SEQUENCE { ... }            ← tbsCertificate
//     SEQUENCE { OID, ... }       ← signatureAlgorithm
//     BIT STRING { 0x00, <sig> }  ← signatureValue  ← 替换目标
//   }

fn replace_signature_in_cert_der(der: &mut Vec<u8>, new_sig: &[u8]) -> anyhow::Result<()> {
    if der.is_empty() || der[0] != 0x30 {
        anyhow::bail!("DER first byte is not SEQUENCE (0x30)");
    }
    let outer_content_start = der_tlv_content_start(der, 0)?;

    let mut pos = outer_content_start;
    for field_idx in 0..3usize {
        if pos >= der.len() {
            anyhow::bail!("DER incomplete: field {} not found", field_idx + 1);
        }
        let (total, _content) = der_tlv_lens(der, pos)?;
        if field_idx == 2 {
            if der[pos] != 0x03 {
                anyhow::bail!("signatureValue is not BIT STRING, tag={:#x}", der[pos]);
            }
            let mut new_content = vec![0x00u8];
            new_content.extend_from_slice(new_sig);
            let new_tlv = der_encode_tlv(0x03, &new_content);
            der.splice(pos..pos + total, new_tlv);
            der_fix_outer_sequence_length(der)?;
            return Ok(());
        }
        pos += total;
    }
    anyhow::bail!("signatureValue (3rd field) not found in DER")
}

/// 返回 (total_tlv_bytes, content_bytes)
fn der_tlv_lens(data: &[u8], pos: usize) -> anyhow::Result<(usize, usize)> {
    if pos + 1 >= data.len() {
        anyhow::bail!("TLV parse out of range pos={pos}");
    }
    let (content_len, len_field_bytes) = der_decode_length(data, pos + 1)?;
    Ok((1 + len_field_bytes + content_len, content_len))
}

fn der_tlv_content_start(data: &[u8], pos: usize) -> anyhow::Result<usize> {
    let (_content_len, len_field_bytes) = der_decode_length(data, pos + 1)?;
    Ok(pos + 1 + len_field_bytes)
}

fn der_decode_length(data: &[u8], pos: usize) -> anyhow::Result<(usize, usize)> {
    if pos >= data.len() {
        anyhow::bail!("DER length out of range pos={pos}");
    }
    let first = data[pos];
    if first < 0x80 {
        return Ok((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || pos + 1 + n > data.len() {
        anyhow::bail!("DER invalid multi-byte length");
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | data[pos + 1 + i] as usize;
    }
    Ok((len, 1 + n))
}

fn der_encode_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let len = content.len();
    if len < 0x80 {
        v.push(len as u8);
    } else if len < 0x100 {
        v.extend_from_slice(&[0x81, len as u8]);
    } else if len < 0x10000 {
        v.extend_from_slice(&[0x82, (len >> 8) as u8, (len & 0xff) as u8]);
    } else {
        v.extend_from_slice(&[
            0x83,
            (len >> 16) as u8,
            (len >> 8) as u8,
            (len & 0xff) as u8,
        ]);
    }
    v.extend_from_slice(content);
    v
}

fn der_fix_outer_sequence_length(der: &mut Vec<u8>) -> anyhow::Result<()> {
    if der[0] != 0x30 {
        anyhow::bail!("DER first byte is not SEQUENCE");
    }
    let old_content_start = der_tlv_content_start(der, 0)?;
    let new_content_len = der.len() - old_content_start;

    let new_len_field = if new_content_len < 0x80 {
        vec![new_content_len as u8]
    } else if new_content_len < 0x100 {
        vec![0x81, new_content_len as u8]
    } else {
        vec![
            0x82,
            (new_content_len >> 8) as u8,
            (new_content_len & 0xff) as u8,
        ]
    };

    der.splice(1..old_content_start, new_len_field);
    Ok(())
}

// ── ClientHello 扩展解析（移植 flux）────────────────────────────────────────

fn extract_sni_from_client_hello(record: &[u8]) -> anyhow::Result<String> {
    let mut pos = SID_OFFSET + 32;
    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before cipher_suites");
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > record.len() {
        anyhow::bail!("record truncated before compression_methods");
    }
    let cm_len = record[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before extensions_length");
    }
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() {
        anyhow::bail!("extensions exceed record boundary");
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            anyhow::bail!("extension data out of boundary");
        }
        // SNI extension = 0x0000
        if ext_type == 0x0000 && ext_len >= 5 {
            let ext_data = &record[pos..pos + ext_len];
            // [2B list_len][1B name_type][2B name_len][N name]
            let name_len = u16::from_be_bytes([ext_data[3], ext_data[4]]) as usize;
            if 5 + name_len <= ext_data.len() {
                return Ok(String::from_utf8_lossy(&ext_data[5..5 + name_len]).to_string());
            }
        }
        pos += ext_len;
    }
    anyhow::bail!("SNI extension (0x0000) not found")
}

fn extract_x25519_from_key_share(record: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut pos = SID_OFFSET + 32;

    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before cipher_suites");
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > record.len() {
        anyhow::bail!("record truncated before compression_methods");
    }
    let cm_len = record[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > record.len() {
        anyhow::bail!("record truncated before extensions_length");
    }
    let ext_total = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > record.len() {
        anyhow::bail!("extensions exceed record boundary");
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([record[pos], record[pos + 1]]);
        let ext_len = u16::from_be_bytes([record[pos + 2], record[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end {
            anyhow::bail!("extension data out of boundary");
        }
        if ext_type == 0x0033 {
            return parse_x25519_key_share(&record[pos..pos + ext_len]);
        }
        pos += ext_len;
    }
    anyhow::bail!("key_share extension (0x0033) not found")
}

fn parse_x25519_key_share(data: &[u8]) -> anyhow::Result<[u8; 32]> {
    if data.len() < 2 {
        anyhow::bail!("key_share data too short");
    }
    let shares_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos = 2;
    let end = (2 + shares_len).min(data.len());

    // 两遍扫描：优先 x25519 (0x001d)，兼容 X25519MLKEM768 (0x11ec) 末尾的 x25519
    // （与 Xray tls.go 行为一致）
    let mut mlkem_x25519: Option<[u8; 32]> = None;

    while pos + 4 <= end {
        let group = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ke_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ke_len > end {
            anyhow::bail!("key_share entry out of boundary");
        }
        if group == 0x001d && ke_len == 32 {
            let mut pub_key = [0u8; 32];
            pub_key.copy_from_slice(&data[pos..pos + 32]);
            return Ok(pub_key);
        }
        if group == 0x11ec && ke_len >= 1088 + 32 {
            let x25519_offset = ke_len - 32;
            let mut pub_key = [0u8; 32];
            pub_key.copy_from_slice(&data[pos + x25519_offset..pos + x25519_offset + 32]);
            mlkem_x25519 = Some(pub_key);
        }
        pos += ke_len;
    }
    if let Some(key) = mlkem_x25519 {
        return Ok(key);
    }
    anyhow::bail!("x25519 (0x001d) / X25519MLKEM768 (0x11ec) not found in key_share")
}

// ── AES/ChaCha20 选择 ────────────────────────────────────────────────────────

fn cipher_suite_prefers_aes(record: &[u8]) -> bool {
    let pos = SID_OFFSET + 32;
    if pos + 2 > record.len() {
        return true;
    }
    let cs_len = u16::from_be_bytes([record[pos], record[pos + 1]]) as usize;
    let cs_start = pos + 2;
    if cs_start + cs_len > record.len() || cs_len < 2 {
        return true;
    }
    let mut i = cs_start;
    while i + 1 < cs_start + cs_len {
        let suite = u16::from_be_bytes([record[i], record[i + 1]]);
        match suite {
            0x1301 | 0x1302 | 0x009c | 0x009d | 0xc02b | 0xc02c | 0xc02f | 0xc030 => return true,
            0x1303 | 0xcca8 | 0xcca9 => return false,
            _ => {}
        }
        i += 2;
    }
    true
}

// ── x25519 DH ────────────────────────────────────────────────────────────────

fn x25519_dh(server_private: &[u8; 32], client_public: &[u8; 32]) -> [u8; 32] {
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(*server_private);
    let public = PublicKey::from(*client_public);
    secret.diffie_hellman(&public).to_bytes()
}

// ── 回落转发 ─────────────────────────────────────────────────────────────────

async fn forward_to_dest<S>(inbound: S, cfg: &RealityServer)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some(dest) = cfg.dest.clone() else {
        debug!("reality: no handshake dest configured, dropping non-reality client");
        return;
    };
    let mut inbound = inbound;
    let mut outbound = match tokio::net::TcpStream::connect(&dest).await {
        Ok(s) => s,
        Err(e) => {
            warn!("reality: connect dest {dest} failed: {e}");
            return;
        }
    };
    let (mut in_r, mut in_w) = tokio::io::split(&mut inbound);
    let (mut out_r, mut out_w) = outbound.split();
    let _ = tokio::join!(
        tokio::io::copy(&mut in_r, &mut out_w),
        tokio::io::copy(&mut out_r, &mut in_w),
    );
    let _ = inbound.shutdown().await;
}

// ── base64 解码（base64url 优先，兼容标准 base64）───────────────────────────

pub fn base64_url_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    let s = s.trim();
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s) {
        return Ok(v);
    }
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode failed")
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_variants() {
        // base64url 无填充（Xray 生成 private_key 的格式）
        assert_eq!(base64_url_decode("aGVsbG8").unwrap(), b"hello");
        // 标准 base64 带填充
        assert_eq!(base64_url_decode("aGVsbG8=").unwrap(), b"hello");
        assert!(base64_url_decode("!!!").is_err());
    }

    #[test]
    fn der_signature_replacement_roundtrip() {
        // 构造最小 X.509 结构：SEQ { SEQ{...}, SEQ{OID}, BIT STRING }
        let tbs = vec![0x30, 0x03, 0x02, 0x01, 0x01]; // SEQ{INTEGER 1}
        let alg = vec![0x30, 0x02, 0x06, 0x00]; // SEQ{OID empty}
        let sig = vec![0xAAu8; 64];
        let mut bit_content = vec![0x00u8];
        bit_content.extend_from_slice(&sig);

        let mut content = Vec::new();
        content.extend_from_slice(&der_encode_tlv(0x30, &tbs));
        content.extend_from_slice(&der_encode_tlv(0x30, &alg));
        content.extend_from_slice(&der_encode_tlv(0x03, &bit_content));
        let mut der = der_encode_tlv(0x30, &content);

        let new_sig = vec![0xBBu8; 64];
        replace_signature_in_cert_der(&mut der, &new_sig).unwrap();

        // 外层长度仍正确
        let (outer_total, _) = der_tlv_lens(&der, 0).unwrap();
        assert_eq!(outer_total, der.len());

        // 解析第三个字段确认替换成功
        let mut pos = der_tlv_content_start(&der, 0).unwrap();
        for _ in 0..2 {
            let (total, _) = der_tlv_lens(&der, pos).unwrap();
            pos += total;
        }
        assert_eq!(der[pos], 0x03);
        let (_total, content_len) = der_tlv_lens(&der, pos).unwrap();
        let content_start = der_tlv_content_start(&der, pos).unwrap();
        assert_eq!(content_len, 1 + 64);
        assert_eq!(der[content_start], 0x00); // unused bits
        assert_eq!(&der[content_start + 1..content_start + 65], &new_sig[..]);
    }

    #[test]
    fn verify_rejects_non_tls_record() {
        let cfg = RealityServer {
            server_name: "example.com".into(),
            private_key: [7u8; 32],
            short_ids: vec![],
            dest: None,
            max_time_diff: 60,
        };
        // 非 0x16 record → 快速拒绝
        let record = vec![0x48u8; 128];
        assert!(verify_reality_client(&record, &cfg).is_err());
        // 太短
        assert!(verify_reality_client(&[0x16u8; 10], &cfg).is_err());
    }
}
