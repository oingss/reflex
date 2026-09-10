use base64::Engine;
use tracing::{debug, warn};

use crate::config::outbound::OutboundECHOptions;

// ── ECH 扩展类型 / 版本常量 ──────────────────────────────────────────────────

/// TLS 扩展类型：encrypted_client_hello（ECH）。
/// 见 RFC 9460 §6（原 draft-ietf-tls-esni 中的 0xff0a 已废弃，使用 0xfe0d）。
pub const TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;

/// ECH 配置版本（draft ECH，目前唯一版本）。
pub const ECH_CONFIG_VERSION_DRAFT: u16 = 0xfe0d;

/// HPKE KEM ID：DHKEM_X25519_HKDF_SHA256（RFC 9180，唯一被 ECH 广泛支持的 KEM）。
pub const HPKE_KEM_X25519_HKDF_SHA256: u16 = 0x0020;
/// HPKE KDF ID：HKDF-SHA256。
pub const HPKE_KDF_HKDF_SHA256: u16 = 0x0001;
/// HPKE AEAD ID：AES-128-GCM。
pub const HPKE_AEAD_AES_128_GCM: u16 = 0x0001;
/// HPKE AEAD ID：AES-256-GCM。
pub const HPKE_AEAD_AES_256_GCM: u16 = 0x0002;
/// HPKE AEAD ID：ChaCha20Poly1305。
pub const HPKE_AEAD_CHACHA20_POLY1305: u16 = 0x0003;

/// DNS HTTPS RR (SvcParamKey = 5) 中的 "ech" 参数键名。
/// 见 RFC 9460 §7（DNS SVCB/HTTPS Service Parameter for ECH）。
const SVCB_KEY_ECH: u16 = 5;

// ── ECHConfig 二进制解析（RFC 9460 §4）─────────────────────────────────────

/// 解析后的单个 ECHConfig 条目（RFC 9460 §4 `ECHConfig`）。
///
/// ```text
/// struct {
///     uint16 version;          // 0xfe0d
///     uint16 length;           // 后续 contents 长度
///     ECHConfigContents contents;
/// } ECHConfig;
/// ```
#[derive(Debug, Clone)]
pub struct EchConfig {
    /// ECH 版本，目前仅 `0xfe0d`。
    pub version: u16,
    /// 配置 ID（0~255），由服务端分配，用于在 ECHConfigList 中选择一条。
    pub config_id: u8,
    /// HPKE KEM ID（如 `0x0020` = DHKEM_X25519_HKDF_SHA256）。
    pub kem_id: u16,
    /// HPKE 公钥（KEM 决定长度，X25519 为 32 字节）。
    pub public_key: Vec<u8>,
    /// 支持的 (KDF, AEAD) 组合列表。
    pub cipher_suites: Vec<EchCipherSuite>,
    /// outer ClientHello 中 SNI 的最大长度（用于 padding 对齐）。
    pub maximum_name_length: u8,
    /// outer ClientHello 中可见的公开域名（cover name）。
    pub public_name: String,
    /// 原始 ECHConfig 字节（包含 version + length 前缀），供 HPKE 层直接使用。
    pub raw: Vec<u8>,
}

/// ECHConfig 中的一个 (KDF, AEAD) 组合。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchCipherSuite {
    pub kdf_id: u16,
    pub aead_id: u16,
}

/// 解析 ECHConfigList 二进制（PEM `ECH CONFIGS` 块的 raw bytes）。
///
/// ECHConfigList 结构（RFC 9460 §4）：
/// ```text
/// opaque ECHConfigList<1..2^16-1>;
/// ```
/// 即 2 字节总长前缀 + 0 或多个连续的 ECHConfig。
///
/// 与 Go `crypto/tls` 中 `Config.EncryptedClientHelloConfigList` 期望的
/// 原始字节格式完全一致。
pub fn parse_ech_config_list(data: &[u8]) -> anyhow::Result<Vec<EchConfig>> {
    if data.len() < 2 {
        anyhow::bail!("ECHConfigList too short: {} bytes", data.len());
    }
    let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + total_len {
        anyhow::bail!(
            "ECHConfigList truncated: declared {total_len} bytes, got {}",
            data.len() - 2
        );
    }
    let body = &data[2..2 + total_len];

    let mut configs = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        if pos + 4 > body.len() {
            anyhow::bail!("ECHConfig header truncated at offset {pos}");
        }
        let version = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let contents_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        let config_total = 4 + contents_len;
        if pos + config_total > body.len() {
            anyhow::bail!("ECHConfig contents truncated at offset {pos}");
        }
        let raw = body[pos..pos + config_total].to_vec();
        let contents = &body[pos + 4..pos + config_total];

        let config = parse_ech_config_contents(version, contents, raw)?;
        configs.push(config);
        pos += config_total;
    }

    if configs.is_empty() {
        anyhow::bail!("ECHConfigList is empty");
    }
    Ok(configs)
}

/// 解析单个 ECHConfigContents（RFC 9460 §4）。
fn parse_ech_config_contents(
    version: u16,
    contents: &[u8],
    raw: Vec<u8>,
) -> anyhow::Result<EchConfig> {
    if version != ECH_CONFIG_VERSION_DRAFT {
        anyhow::bail!(
            "unsupported ECHConfig version: 0x{:04x} (only 0x{:04x} is supported)",
            version,
            ECH_CONFIG_VERSION_DRAFT
        );
    }
    let mut pos = 0;
    let config_id = take_u8(contents, &mut pos)?;
    let kem_id = take_u16(contents, &mut pos)?;
    let pub_key_len = take_u16(contents, &mut pos)? as usize;
    let public_key = take_vec(contents, &mut pos, pub_key_len)?;
    let suites_len = take_u16(contents, &mut pos)? as usize;
    if !suites_len.is_multiple_of(4) {
        anyhow::bail!("ECH cipher_suites length {suites_len} not a multiple of 4");
    }
    let suites_end = pos + suites_len;
    let mut cipher_suites = Vec::new();
    while pos < suites_end {
        let kdf_id = take_u16(contents, &mut pos)?;
        let aead_id = take_u16(contents, &mut pos)?;
        cipher_suites.push(EchCipherSuite { kdf_id, aead_id });
    }
    let maximum_name_length = take_u8(contents, &mut pos)?;
    let public_name_len = take_u8(contents, &mut pos)? as usize;
    let public_name_bytes = take_vec(contents, &mut pos, public_name_len)?;
    let public_name = String::from_utf8(public_name_bytes)
        .map_err(|e| anyhow::anyhow!("ECH public_name is not valid UTF-8: {e}"))?;
    // extensions（目前忽略未知扩展，但仍校验长度）
    if pos < contents.len() {
        let _ext_len = take_u16(contents, &mut pos)? as usize;
        let ext_end = pos + _ext_len;
        if ext_end > contents.len() {
            anyhow::bail!("ECHConfig extensions truncated");
        }
        // 不解析具体扩展，跳过
    }

    Ok(EchConfig {
        version,
        config_id,
        kem_id,
        public_key,
        cipher_suites,
        maximum_name_length,
        public_name,
        raw,
    })
}

// ── PEM 解析 ────────────────────────────────────────────────────────────────

/// 解析 PEM 格式的 ECH 配置（块类型 `ECH CONFIGS`）。
///
/// 与 sing-box `parseECHClientConfig` 中 `pem.Decode` + 校验 `block.Type == "ECH CONFIGS"`
/// 的行为一致。要求恰好包含一个 `ECH CONFIGS` PEM 块，否则报错。
///
/// 返回的 `Vec<u8>` 是 PEM 块的 raw bytes（即 ECHConfigList），可直接用于
/// ECH 握手或通过 [`parse_ech_config_list`] 进一步解析。
pub fn parse_ech_config_pem(pem_text: &str) -> anyhow::Result<Vec<u8>> {
    let begin = "-----BEGIN ECH CONFIGS-----";
    let end = "-----END ECH CONFIGS-----";

    let start = pem_text
        .find(begin)
        .ok_or_else(|| anyhow::anyhow!("PEM ECH CONFIGS block not found"))?;
    let body_start = start + begin.len();
    let end_pos = pem_text[body_start..]
        .find(end)
        .ok_or_else(|| anyhow::anyhow!("PEM ECH CONFIGS block not terminated"))?;
    let b64_body = &pem_text[body_start..body_start + end_pos];

    // PEM 标准格式每 64 字符插入一个换行，body 中可能含有 \n、\r、空格等空白。
    // base64 STANDARD 引擎不容忍这些字符，需要先全部去除再解码。
    // 兼容 Rust < 1.80（trim_ascii_end 在 1.80 才稳定）。
    let b64_clean: String = b64_body
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&b64_clean)
        .map_err(|e| anyhow::anyhow!("decode ECH CONFIGS base64: {e}"))?;

    // 与 sing-box 一致：要求恰好一个 PEM 块（rest 为空）
    if pem_text[body_start + end_pos + end.len()..].contains("-----BEGIN ECH CONFIGS-----") {
        anyhow::bail!("multiple ECH CONFIGS PEM blocks found, expected exactly one");
    }
    Ok(decoded)
}

// ── 配置解析入口 ─────────────────────────────────────────────────────────────

/// 从 [`OutboundECHOptions`] 解析出 ECHConfigList 原始字节。
///
/// 优先级与 sing-box `parseECHClientConfig` 一致：
/// 1. `options.config`（PEM 字符串列表，按 `\n` 拼接后 PEM 解码）
/// 2. `options.config_path`（PEM 文件路径）
///
/// 若两者均未提供，返回 `Ok(None)`，表示应由调用方通过 DNS HTTPS RR 获取
/// （对应 sing-box 中 `ECHClientConfig` 的 DNS 查询路径）。
pub fn resolve_ech_config_list(options: &OutboundECHOptions) -> anyhow::Result<Option<Vec<u8>>> {
    if !options.config.is_empty() {
        let joined = options.config.join("\n");
        let bytes = parse_ech_config_pem(&joined)?;
        // 校验可解析
        let parsed = parse_ech_config_list(&bytes)?;
        debug!(
            config_count = parsed.len(),
            first_public_name = %parsed.first().map(|c| c.public_name.as_str()).unwrap_or(""),
            "ECH: loaded ECHConfigList from inline config"
        );
        return Ok(Some(bytes));
    }
    if let Some(path) = &options.config_path {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read ECH config_path '{path}': {e}"))?;
        let bytes = parse_ech_config_pem(&content)?;
        let parsed = parse_ech_config_list(&bytes)?;
        debug!(
            config_count = parsed.len(),
            first_public_name = %parsed.first().map(|c| c.public_name.as_str()).unwrap_or(""),
            "ECH: loaded ECHConfigList from {}", path
        );
        return Ok(Some(bytes));
    }
    Ok(None)
}

// ── DNS HTTPS RR 查询 ────────────────────────────────────────────────────────

/// 通过 DNS HTTPS RR（type 65）获取 ECHConfigList。
///
/// 对应 sing-box `ECHClientConfig.fetchAndHandshake` 中通过 DNSRouter 查询
/// `TypeHTTPS` 并解析 `ech` SVCB 参数的部分。
///
/// 流程：
/// 1. 向 `resolver` 发起 HTTPS RR 查询（qtype = 65）
/// 2. 遍历响应中的 HTTPS 记录，提取 SVCB `ech` 参数（key = 5）
/// 3. Base64 解码得到 ECHConfigList 原始字节
///
/// 返回 `Ok(Some(bytes))` 表示成功获取；`Ok(None)` 表示 DNS 应答中没有 ECH 参数。
pub async fn fetch_ech_config_from_dns(
    resolver: &crate::dns::DnsResolver,
    server_name: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let query_name = server_name.trim_end_matches('.');
    let resp = resolver
        .resolve_raw(query_name, 65)
        .await
        .map_err(|e| anyhow::anyhow!("ECH: DNS HTTPS query for '{query_name}' failed: {e}"))?;

    let ech_b64 = extract_ech_param_from_https_response(&resp, query_name);
    match ech_b64 {
        Some(b64) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&b64)
                .map_err(|e| anyhow::anyhow!("ECH: decode DNS 'ech' param base64: {e}"))?;
            debug!(
                server_name = %query_name,
                bytes_len = bytes.len(),
                "ECH: fetched ECHConfigList from DNS HTTPS RR"
            );
            Ok(Some(bytes))
        }
        None => {
            warn!(
                server_name = %query_name,
                "ECH: no 'ech' param found in DNS HTTPS RR"
            );
            Ok(None)
        }
    }
}

/// 从 DNS 应答报文中提取 HTTPS RR 中的 `ech` SVCB 参数（base64 字符串）。
///
/// HTTPS RR (type 65) RDATA 结构（RFC 9460 / RFC 9460 §7）：
/// ```text
/// SvcPriority (2B)
/// TargetName (domain name, possibly compressed)
/// SvcParams:
///   [SvcParamKey (2B)][SvcParamLen (2B)][SvcParamValue ...]
///   ...
/// ```
fn extract_ech_param_from_https_response(resp: &[u8], _query_name: &str) -> Option<String> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    if ancount == 0 {
        return None;
    }
    let mut pos = 12usize;
    // 跳过 Question 段
    for _ in 0..u16::from_be_bytes([resp[4], resp[5]]) {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?; // qtype(2) + qclass(2)
    }
    // 遍历 Answer 段
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        if pos + 10 > resp.len() {
            return None;
        }
        let rr_type = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > resp.len() {
            return None;
        }
        if rr_type == 65 {
            // HTTPS RR
            let rdata = &resp[pos..pos + rdlength];
            if let Some(v) = parse_svcb_ech_param(rdata, resp) {
                return Some(v);
            }
        }
        pos += rdlength;
    }
    None
}

/// 解析 HTTPS RR RDATA 中的 SVCB 参数，找到 `ech` (key=5)。
fn parse_svcb_ech_param(rdata: &[u8], full_msg: &[u8]) -> Option<String> {
    if rdata.len() < 2 {
        return None;
    }
    let _priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let mut pos = 2usize;
    // TargetName（可能是压缩指针）
    pos = skip_name_in(rdata, pos, full_msg)?;
    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + len > rdata.len() {
            return None;
        }
        if key == SVCB_KEY_ECH {
            let val = &rdata[pos..pos + len];
            return std::str::from_utf8(val).ok().map(|s| s.to_string());
        }
        pos += len;
    }
    None
}

/// 跳过 DNS 报文中的域名（支持压缩指针），返回下一个字段的位置。
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // 压缩指针（2 字节）
            return Some(pos + 2);
        }
        pos = pos.checked_add(1 + len)?;
    }
}

/// 跳过 SVCB RDATA 内的域名（可能使用相对于整条 DNS 报文的压缩指针）。
fn skip_name_in(rdata: &[u8], mut pos: usize, full_msg: &[u8]) -> Option<usize> {
    loop {
        if pos >= rdata.len() {
            return None;
        }
        let len = rdata[pos] as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // 压缩指针：偏移量相对于 full_msg，但我们在 rdata 内只需跳过 2 字节
            let _ = full_msg; // 实际偏移量解析对跳过无影响
            return Some(pos + 2);
        }
        pos = pos.checked_add(1 + len)?;
    }
}

// ── ECH 握手入口 ─────────────────────────────────────────────────────────────

/// 在已建立的 TCP 流上执行 ECH 握手。
///
/// 当前 rustls 0.23 尚未原生支持 ECH。ECH 要求 inner/outer ClientHello 分裂、
/// HPKE 密封以及 ECH 接受确认验证，无法通过简单的 ClientHello patch 在 rustls
/// 之上实现——必须完整自实现 TLS 1.3 握手（类似 [`crate::outbound::tls::reality`]）。
///
/// 当 `tls.ech.enabled = true` 且成功解析出 ECHConfigList 时，本函数会返回
/// 明确错误，避免静默降级为不安全的非 ECH 连接（与 sing-box 在 ECH 启用但
/// 握手失败时的行为一致）。
pub async fn connect_ech(
    tcp: tokio::net::TcpStream,
    server_name: &str,
    tls: &crate::config::outbound::TlsConfig,
    ech_config_list: Vec<u8>,
) -> anyhow::Result<crate::outbound::tls::TlsStreamBox> {
    debug!(
        server_name = %server_name,
        ech_config_list_len = ech_config_list.len(),
        utls_enabled = tls.utls.as_ref().is_some_and(|u| u.enabled),
        "ECH: handshake requested"
    );
    // 验证 ECHConfigList 可解析，便于提前暴露配置错误。
    let configs = parse_ech_config_list(&ech_config_list)?;
    let public_names: Vec<&str> = configs.iter().map(|c| c.public_name.as_str()).collect();
    debug!(
        config_count = configs.len(),
        public_names = ?public_names,
        "ECH: ECHConfigList validated"
    );

    // rustls 0.23 不支持 ECH：完整实现需要自定义 TLS 1.3 客户端。
    // 这里返回明确错误，避免静默降级。
    // `tcp` 在 ECH 握手实现后将用于在其上执行 inner/outer ClientHello 交换，
    // 当前保留所有权以保持 API 稳定，便于后续无缝接入。
    let _ = tcp;
    anyhow::bail!(
        "ECH handshake is not yet supported by the built-in TLS stack \
         (rustls 0.23 does not natively support ECH). \
         The ECH configuration was parsed successfully ({} config(s), public_name(s): {:?}), \
         but the actual ECH handshake requires either native rustls ECH support \
         or a custom TLS 1.3 implementation. \
         Disable tls.ech.enabled to fall back to plain TLS.",
        configs.len(),
        public_names
    );
}

// ── 小工具 ───────────────────────────────────────────────────────────────────

fn take_u8(input: &[u8], pos: &mut usize) -> anyhow::Result<u8> {
    let v = *input
        .get(*pos)
        .ok_or_else(|| anyhow::anyhow!("ECH parser: unexpected end of input"))?;
    *pos += 1;
    Ok(v)
}

fn take_u16(input: &[u8], pos: &mut usize) -> anyhow::Result<u16> {
    let b = input
        .get(*pos..*pos + 2)
        .ok_or_else(|| anyhow::anyhow!("ECH parser: unexpected end of input"))?;
    *pos += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn take_vec(input: &[u8], pos: &mut usize, len: usize) -> anyhow::Result<Vec<u8>> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("ECH parser: length overflow"))?;
    let v = input
        .get(*pos..end)
        .ok_or_else(|| anyhow::anyhow!("ECH parser: truncated input"))?
        .to_vec();
    *pos = end;
    Ok(v)
}

// ── 测试 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个最小的合法 ECHConfigList 字节（仅用于解析测试）。
    fn build_test_ech_config_list(public_name: &str) -> Vec<u8> {
        // ECHConfigContents:
        //   config_id(1) + kem_id(2) + pub_key_len(2) + pub_key(32)
        //   + suites_len(2) + suites(4*1)
        //   + max_name_len(1) + public_name_len(1) + public_name
        //   + ext_len(2)
        let pub_key = vec![0x42u8; 32];
        let mut contents = Vec::new();
        contents.push(0x01); // config_id
        contents.extend_from_slice(&HPKE_KEM_X25519_HKDF_SHA256.to_be_bytes());
        contents.extend_from_slice(&(pub_key.len() as u16).to_be_bytes());
        contents.extend_from_slice(&pub_key);
        // 1 个 cipher suite: (HKDF_SHA256, AES_128_GCM)
        let suite = [
            HPKE_KDF_HKDF_SHA256.to_be_bytes(),
            HPKE_AEAD_AES_128_GCM.to_be_bytes(),
        ]
        .concat();
        contents.extend_from_slice(&(suite.len() as u16).to_be_bytes());
        contents.extend_from_slice(&suite);
        contents.push(0); // maximum_name_length
        contents.push(public_name.len() as u8);
        contents.extend_from_slice(public_name.as_bytes());
        contents.extend_from_slice(&0u16.to_be_bytes()); // extensions length = 0

        // ECHConfig: version(2) + length(2) + contents
        let mut ech_config = Vec::new();
        ech_config.extend_from_slice(&ECH_CONFIG_VERSION_DRAFT.to_be_bytes());
        ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        ech_config.extend_from_slice(&contents);

        // ECHConfigList: length(2) + ech_config
        let mut list = Vec::new();
        list.extend_from_slice(&(ech_config.len() as u16).to_be_bytes());
        list.extend_from_slice(&ech_config);
        list
    }

    #[test]
    fn parse_ech_config_list_basic() {
        let list_bytes = build_test_ech_config_list("cloudflare-ech.com");
        let configs = parse_ech_config_list(&list_bytes).expect("parse");
        assert_eq!(configs.len(), 1);
        let c = &configs[0];
        assert_eq!(c.version, ECH_CONFIG_VERSION_DRAFT);
        assert_eq!(c.config_id, 1);
        assert_eq!(c.kem_id, HPKE_KEM_X25519_HKDF_SHA256);
        assert_eq!(c.public_key, vec![0x42u8; 32]);
        assert_eq!(c.cipher_suites.len(), 1);
        assert_eq!(
            c.cipher_suites[0],
            EchCipherSuite {
                kdf_id: HPKE_KDF_HKDF_SHA256,
                aead_id: HPKE_AEAD_AES_128_GCM,
            }
        );
        assert_eq!(c.public_name, "cloudflare-ech.com");
        // raw 包含 version + length 前缀
        assert!(c.raw.len() > 4);
        assert_eq!(
            u16::from_be_bytes([c.raw[0], c.raw[1]]),
            ECH_CONFIG_VERSION_DRAFT
        );
    }

    #[test]
    fn parse_ech_config_list_multiple() {
        let mut list = Vec::new();
        let cfg1 = build_test_ech_config_list("a.example");
        let cfg2 = build_test_ech_config_list("b.example");
        // 拼接两个 ECHConfigList 的内部 ECHConfig 部分
        let body1 = &cfg1[2..]; // 去掉 list 长度前缀
        let body2 = &cfg2[2..];
        let combined: Vec<u8> = body1.iter().chain(body2.iter()).copied().collect();
        list.extend_from_slice(&(combined.len() as u16).to_be_bytes());
        list.extend_from_slice(&combined);

        let configs = parse_ech_config_list(&list).expect("parse");
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].public_name, "a.example");
        assert_eq!(configs[1].public_name, "b.example");
    }

    #[test]
    fn parse_ech_config_list_rejects_empty() {
        let empty = vec![0x00, 0x00]; // 长度 = 0
        assert!(parse_ech_config_list(&empty).is_err());
    }

    #[test]
    fn parse_ech_config_list_rejects_truncated() {
        let truncated = vec![0x00, 0x10]; // 声明 16 字节但没有 body
        assert!(parse_ech_config_list(&truncated).is_err());
    }

    #[test]
    fn parse_ech_config_pem_roundtrip() {
        let list_bytes = build_test_ech_config_list("example.com");
        let pem = pem_encode_ech_configs(&list_bytes);
        let decoded = parse_ech_config_pem(&pem).expect("parse pem");
        assert_eq!(decoded, list_bytes);
    }

    #[test]
    fn parse_ech_config_pem_rejects_wrong_type() {
        let pem = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----";
        assert!(parse_ech_config_pem(pem).is_err());
    }

    #[test]
    fn parse_ech_config_pem_rejects_missing_end() {
        let pem = "-----BEGIN ECH CONFIGS-----\nZm9v\n";
        assert!(parse_ech_config_pem(pem).is_err());
    }

    #[test]
    fn resolve_ech_config_list_from_inline_config() {
        let list_bytes = build_test_ech_config_list("inline.test");
        let pem = pem_encode_ech_configs(&list_bytes);
        let opts = OutboundECHOptions {
            enabled: true,
            config: vec![pem],
            config_path: None,
            query_server_name: None,
        };
        let resolved = resolve_ech_config_list(&opts).expect("resolve");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap(), list_bytes);
    }

    #[test]
    fn resolve_ech_config_list_returns_none_when_no_source() {
        let opts = OutboundECHOptions::default();
        let resolved = resolve_ech_config_list(&opts).expect("resolve");
        assert!(resolved.is_none());
    }

    #[test]
    fn extract_ech_param_from_https_response_none_when_empty() {
        // 空 DNS 应答（仅 header）
        let resp = vec![0u8; 12];
        assert!(extract_ech_param_from_https_response(&resp, "test").is_none());
    }

    /// 测试用：将 ECHConfigList 字节编码为 PEM `ECH CONFIGS` 块。
    fn pem_encode_ech_configs(bytes: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
        let mut out = String::from("-----BEGIN ECH CONFIGS-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap());
            out.push('\n');
        }
        out.push_str("-----END ECH CONFIGS-----\n");
        out
    }

    /// 验证 PEM 解析能容忍块末尾的多余空白（\n、空格等）。
    #[test]
    fn parse_ech_config_pem_handles_trailing_whitespace() {
        let list_bytes = build_test_ech_config_list("ws.test");
        let mut pem = pem_encode_ech_configs(&list_bytes);
        pem.push_str("\n\n"); // trailing newlines
        let decoded = parse_ech_config_pem(&pem).expect("parse pem");
        assert_eq!(decoded, list_bytes);
    }
}
