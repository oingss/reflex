use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use russh::{
    client::{self, Handle, KeyboardInteractiveAuthResponse, Msg},
    keys::ssh_key,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use crate::{
    config::outbound::{SshOutboundConfig, TotpOption},
    dns::DnsResolver,
    inbound::{InboundTcpStream, InboundUdpPacket, Target},
    outbound::{resolve_server_addr, Outbound, OutboundStatus},
};

// ── russh client::Handler 实现 ──────────────────────────────────────────────

/// SSH 客户端事件处理器，负责校验服务端公钥。
///
/// - 未配置 `host_key` 时接受任何服务端公钥（不安全，仅调试用）。
/// - 配置了 `host_key` 时只接受匹配的公钥，否则返回 `UnknownKey` 错误。
pub(crate) struct SshClientHandler {
    /// 用户期望的服务端公钥列表（OpenSSH 格式解析后）
    expected_keys: Vec<ssh_key::PublicKey>,
}

impl client::Handler for SshClientHandler {
    type Error = russh::Error;

    /// 校验服务端公钥：未配置期望列表时一律接受，否则要求精确匹配。
    fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        let matches = if self.expected_keys.is_empty() {
            true
        } else {
            self.expected_keys.iter().any(|k| k == server_public_key)
        };
        async move {
            if matches {
                Ok(true)
            } else {
                Err(russh::Error::UnknownKey)
            }
        }
    }
}

// ── SshOutbound ──────────────────────────────────────────────────────────────

pub struct SshOutbound {
    config: SshOutboundConfig,
    resolver: Option<Arc<DnsResolver>>,
}

impl SshOutbound {
    pub fn new(config: SshOutboundConfig) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            resolver: None,
        })
    }

    pub fn with_resolver(mut self, resolver: Arc<DnsResolver>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// 解析 host_key 字段（OpenSSH 格式字符串列表 → PublicKey 列表）。
    /// 解析失败的条目会被跳过并记录警告。
    fn parse_host_keys(&self) -> Vec<ssh_key::PublicKey> {
        self.config
            .host_key
            .as_ref()
            .map(|keys| {
                keys.iter()
                    .filter_map(|s| match ssh_key::PublicKey::from_openssh(s) {
                        Ok(k) => Some(k),
                        Err(e) => {
                            warn!(key = %s, err = %e, "ssh host_key: failed to parse, skipping");
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 加载本地私钥：若字符串包含 `"PRIVATE KEY"` 视为内联 PEM；否则视为文件路径。
    /// 路径以 `~` 开头时展开为 home 目录。
    fn load_private_key(&self) -> anyhow::Result<Option<russh::keys::PrivateKey>> {
        let Some(raw) = self.config.private_key.as_ref() else {
            return Ok(None);
        };
        let passphrase = self.config.private_key_passphrase.as_deref();

        if raw.contains("PRIVATE KEY") {
            // 内联 PEM 内容
            let key = russh::keys::decode_secret_key(raw, passphrase)
                .map_err(|e| anyhow::anyhow!("failed to decode inline private key: {e}"))?;
            return Ok(Some(key));
        }

        // 文件路径：展开 ~ 为 home 目录
        let expanded = expand_tilde(raw);
        let key = russh::keys::load_secret_key(&expanded, passphrase)
            .map_err(|e| anyhow::anyhow!("failed to load private key from '{expanded}': {e}"))?;
        Ok(Some(key))
    }

    /// 构造 TOTP 生成器（仅在配置了 totp_opt 时）。
    fn build_totp(&self) -> anyhow::Result<Option<totp_rs::TOTP>> {
        let Some(opt) = self.config.totp_opt.clone() else {
            return Ok(None);
        };
        match opt {
            TotpOption::OtpAuth { secret } => {
                let rfc6238 = totp_rs::Rfc6238::with_defaults(
                    totp_rs::Secret::Encoded(secret.clone())
                        .to_bytes()
                        .map_err(|e| {
                            anyhow::anyhow!("ssh totp: invalid otpauth secret '{secret}': {e:?}")
                        })?,
                )
                .map_err(|e| anyhow::anyhow!("ssh totp: invalid rfc6238: {e}"))?;
                let totp = totp_rs::TOTP::from_rfc6238(rfc6238)
                    .map_err(|e| anyhow::anyhow!("ssh totp: invalid otpauth: {e}"))?;
                Ok(Some(totp))
            }
            TotpOption::Common(cfg) => {
                let algorithm = match cfg.algorithm.to_ascii_lowercase().as_str() {
                    "sha1" => totp_rs::Algorithm::SHA1,
                    "sha256" => totp_rs::Algorithm::SHA256,
                    "sha512" => totp_rs::Algorithm::SHA512,
                    other => anyhow::bail!("ssh totp: unsupported algorithm '{other}'"),
                };
                let secret_bytes = totp_rs::Secret::Encoded(cfg.secret.clone())
                    .to_bytes()
                    .map_err(|e| anyhow::anyhow!("ssh totp: invalid secret: {e:?}"))?;
                let totp = totp_rs::TOTP::new(algorithm, cfg.digits, 1, cfg.step, secret_bytes)
                    .map_err(|e| anyhow::anyhow!("ssh totp: invalid config: {e}"))?;
                Ok(Some(totp))
            }
        }
    }

    /// 建立 SSH 会话：解析地址 → 连接 → 认证。
    /// 返回已认证的 `Handle<SshClientHandler>`，调用方据此打开 direct-tcpip channel。
    async fn connect_session(&self) -> anyhow::Result<Handle<SshClientHandler>> {
        let server = &self.config.server;
        let port = self.config.server_port;

        let addr = resolve_server_addr(server, port, self.resolver.as_ref())
            .await
            .map_err(|e| anyhow::anyhow!("DNS failed for {server}: {e}"))?;

        let expected_keys = self.parse_host_keys();
        let handler = SshClientHandler { expected_keys };

        let config = Arc::new(client::Config::default());
        debug!(tag = %self.config.tag, server = %server, port = %port, "ssh: connecting");

        // connect 前绑定物理网卡（Windows IP_UNICAST_IF / macOS IP_BOUND_IF），
        // 避免 auto_route 接管默认路由后 SSH 出站被 TUN 截获环回；
        // russh 提供 connect_stream 接收外部已建立的 TcpStream。
        let stream = crate::outbound::connect_tcp_interface(addr)
            .await
            .map_err(|e| anyhow::anyhow!("ssh: tcp connect to {server}:{port} failed: {e}"))?;
        let mut session = client::connect_stream(config, stream, handler)
            .await
            .map_err(|e| anyhow::anyhow!("ssh: connect to {server}:{port} failed: {e}"))?;

        self.authenticate(&mut session).await?;
        Ok(session)
    }

    /// 按顺序尝试认证方法：公钥 → 密码 → 键盘交互（含 TOTP）。
    /// 服务端拒绝当前方法后，根据其返回的 `remaining_methods` 选择下一个方法。
    async fn authenticate(&self, session: &mut Handle<SshClientHandler>) -> anyhow::Result<()> {
        let username = &self.config.username;

        // 1. 公钥认证
        if let Ok(Some(private_key)) = self.load_private_key() {
            // best_supported_rsa_hash 返回 Result<Option<Option<HashAlg>>, Error>，
            // PrivateKeyWithHashAlg::new 期望 Option<HashAlg>。
            let hash = session
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            let key_with_hash =
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(private_key), hash);
            match session
                .authenticate_publickey(username, key_with_hash)
                .await
            {
                Ok(res) if res.success() => {
                    debug!(tag = %self.config.tag, "ssh: publickey auth succeeded");
                    return Ok(());
                }
                Ok(_) => {
                    debug!(tag = %self.config.tag, "ssh: publickey auth rejected, trying next method");
                }
                Err(e) => {
                    warn!(tag = %self.config.tag, err = %e, "ssh: publickey auth error, trying next method");
                }
            }
        }

        // 2. 密码认证
        if let Some(password) = self.config.password.as_ref() {
            match session.authenticate_password(username, password).await {
                Ok(res) if res.success() => {
                    debug!(tag = %self.config.tag, "ssh: password auth succeeded");
                    return Ok(());
                }
                Ok(_) => {
                    debug!(tag = %self.config.tag, "ssh: password auth rejected, trying keyboard-interactive");
                }
                Err(e) => {
                    warn!(tag = %self.config.tag, err = %e, "ssh: password auth error, trying keyboard-interactive");
                }
            }
        }

        // 3. 键盘交互（含 TOTP）
        let totp = self.build_totp()?;
        let password = self.config.password.clone();
        self.keyboard_interactive(session, username, password, totp)
            .await?;

        Ok(())
    }

    /// 键盘交互认证：循环响应服务端的 prompts。
    /// - prompt 含 `"Password: "` → 回填 password
    /// - prompt 含 `"Verification code: "` → 调用 TOTP 生成当前验证码
    async fn keyboard_interactive(
        &self,
        session: &mut Handle<SshClientHandler>,
        username: &str,
        password: Option<String>,
        totp: Option<totp_rs::TOTP>,
    ) -> anyhow::Result<()> {
        const PASSWORD_PROMPT: &str = "Password: ";
        const VERIFICATION_CODE_PROMPT: &str = "Verification code: ";

        let mut resp = session
            .authenticate_keyboard_interactive_start(username, None)
            .await
            .map_err(|e| anyhow::anyhow!("ssh: keyboard-interactive start failed: {e}"))?;

        for _ in 0..5 {
            match resp {
                KeyboardInteractiveAuthResponse::Success => {
                    debug!(tag = %self.config.tag, "ssh: keyboard-interactive auth succeeded");
                    return Ok(());
                }
                KeyboardInteractiveAuthResponse::Failure { .. } => {
                    anyhow::bail!("ssh: keyboard-interactive auth rejected by server");
                }
                KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                    let responses: Vec<String> = prompts
                        .iter()
                        .map(|p| {
                            if p.prompt.contains(PASSWORD_PROMPT) {
                                password.clone().unwrap_or_default()
                            } else if p.prompt.contains(VERIFICATION_CODE_PROMPT) {
                                totp.as_ref()
                                    .and_then(|t| t.generate_current().ok())
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            }
                        })
                        .collect();
                    resp = session
                        .authenticate_keyboard_interactive_respond(responses)
                        .await
                        .map_err(|e| {
                            anyhow::anyhow!("ssh: keyboard-interactive respond failed: {e}")
                        })?;
                }
            }
        }
        anyhow::bail!("ssh: keyboard-interactive auth exceeded retry limit")
    }

    /// 打开 direct-tcpip channel 转发到目标地址，返回可作为字节流使用的 channel。
    async fn open_channel(&self, target: &Target) -> anyhow::Result<SshChannelStream> {
        let session = self.connect_session().await?;

        let (host, port) = match target {
            Target::Domain(h, p) => (h.clone(), *p),
            Target::Socket(a) => (a.ip().to_string(), a.port()),
        };

        debug!(tag = %self.config.tag, host = %host, port = port, "ssh: opening direct-tcpip channel");
        let channel = session
            .channel_open_direct_tcpip(host.clone(), port as u32, "0.0.0.0".to_string(), 0)
            .await
            .map_err(|e| anyhow::anyhow!("ssh: open direct-tcpip to {host}:{port} failed: {e}"))?;

        Ok(SshChannelStream::new(channel, session))
    }
}

// ── russh 0.51 ChannelStream 类型别名 ───────────────────────────────────────
//
// russh 0.51 的 `ChannelStream<S>` 要求 `S: From<(ChannelId, ChannelMsg)>`，
// 在客户端场景下 `S` 应为 `russh::client::Msg`（clash-rs 0.61 中简化为 `Msg`）。
// 此处通过类型别名显式指定泛型参数，避免在每个使用点重复书写。
type ClientChannelStream = russh::ChannelStream<Msg>;

#[async_trait]
impl Outbound for SshOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "SSH".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        debug!(
            tag = %self.config.tag,
            target = %conn.target,
            server = %self.config.server,
            port = self.config.server_port,
            "ssh tcp relay"
        );

        let channel = self.open_channel(&conn.target).await?;
        Ok(crate::outbound::relay(conn.stream, channel).await)
    }

    async fn handle_udp(&self, _packet: InboundUdpPacket) -> anyhow::Result<()> {
        // SSH UDP 转发未实现（与 clash-rs 行为一致）
        anyhow::bail!(
            "ssh outbound '{}' does not support UDP forwarding",
            self.config.tag
        );
    }

    /// 通过 SSH 隧道建立到 (host, port) 的 TCP 连接，供 DNS-over-TCP detour 使用。
    async fn connect_tcp(
        &self,
        host: &str,
        port: u16,
    ) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
        let target = Target::Domain(host.to_string(), port);
        let channel = self.open_channel(&target).await?;
        Ok(Box::new(channel))
    }
}

// ── SshChannelStream ────────────────────────────────────────────────────────

/// 包装 russh `Channel<Msg>` 为 `AsyncRead + AsyncWrite`。
///
/// `into_stream()` 已将 channel 转为字节流，但为了在底层 `Channel` 关闭时
/// 通知 `Handle` 退出（避免悬挂），同时持有 `Handle` 守卫。
pub struct SshChannelStream {
    /// russh channel 字节流（已转换为 AsyncRead+AsyncWrite）
    stream: ClientChannelStream,
    /// 持有 Handle 防止 SSH 会话被提前释放；Channel 关闭后即可丢弃。
    _session: Handle<SshClientHandler>,
}

impl SshChannelStream {
    pub(crate) fn new(channel: russh::Channel<Msg>, session: Handle<SshClientHandler>) -> Self {
        Self {
            stream: channel.into_stream(),
            _session: session,
        }
    }
}

impl AsyncRead for SshChannelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SshChannelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

// ── 辅助：展开 `~` 为 home 目录 ────────────────────────────────────────────

fn expand_tilde(path: &str) -> String {
    if !path.starts_with('~') {
        return path.to_string();
    }
    let home = dirs::home_dir().map(|p| p.to_string_lossy().to_string());
    match home {
        Some(h) => {
            if path == "~" {
                h
            } else if let Some(rest) = path.strip_prefix("~/") {
                format!("{h}/{rest}")
            } else {
                // 形如 `~user/...` 的扩展暂不支持，原样返回
                path.to_string()
            }
        }
        None => path.to_string(),
    }
}
