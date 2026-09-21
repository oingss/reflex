//! NaiveProxy 服务端入站（对齐 sing-box `protocol/naive` inbound 的行为面，
//! 配置格式与 [`NaiveInboundConfig`] 一致；握手逻辑参考 flux-master naiveproxy）。
//!
//! ## 协议（wire format 详见 `crate::protocol::naive`）
//! 1. TLS accept（ALPN 期望 h2；`tls.enabled = false` 时记 warn 并以 h2
//!    prior knowledge 明文服务，与 flux 无 TLS 分支一致）。
//! 2. HTTP/2 服务端连接：每条 TLS 连接跑一个 h2 connection，逐个处理
//!    stream 上的请求。
//! 3. CONNECT 请求：校验 `Proxy-Authorization: Basic base64(user:pass)`
//!    是否命中 `config.users`；成功则回 200 并把该 h2 stream 包装为
//!    [`SniffedStream::from_encrypted`] 交给 dispatcher 路由（target =
//!    CONNECT authority，IP 字面量映射为 [`Target::Socket`]，否则为
//!    [`Target::Domain`]）。非 CONNECT / 鉴权失败回 404（debug 日志），
//!    authority 缺失或无法解析（未知目标）回 502。
//! 4. 可选 padding：`config.padding` 开启 **且** 客户端 CONNECT 请求带
//!    `padding` 头时，响应同样携带 `padding` 头，隧道流用
//!    [`NaiveStream`]（前 8 次读/写分帧）；否则用明文隧道流。
//!
//! ## 交付模型
//! 仅 TCP：认证成功的 h2 stream 装箱投递 `InboundTcpStream`
//! （`sniffed_protocol: None`）；UDP 不支持（naive 协议为纯 TCP 隧道）。

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use h2::server::SendResponse;
use h2::RecvStream;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::inbound::NaiveInboundConfig;
use crate::inbound::proxy_common::bind_dual_stack_listener;
use crate::inbound::{
    display_sockaddr, parse_listen_addr, InboundTcpStream, SniffedStream, Target,
};
use crate::outbound::AsyncReadWrite;
use crate::protocol::naive::{
    generate_padding_header, parse_basic_auth, parse_connect_authority, verify_basic_auth, ALPN_H2,
    NaiveStream, PADDING_HEADER_NAME, PROXY_AUTHORIZATION_HEADER,
};

// ── 入站入口 ─────────────────────────────────────────────────────────────────

pub struct NaiveInbound {
    config: NaiveInboundConfig,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
}

impl NaiveInbound {
    pub fn new(config: NaiveInboundConfig, tcp_tx: mpsc::Sender<InboundTcpStream>) -> Self {
        Self { config, tcp_tx }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind = parse_listen_addr(&self.config.listen, self.config.listen_port)?;
        let tag = Arc::new(self.config.tag.clone());

        if self.config.users.is_empty() {
            warn!(tag = %tag, "naive inbound: no users configured, every request will be rejected (404)");
        }
        let users: Arc<Vec<(String, String)>> = Arc::new(
            self.config
                .users
                .iter()
                .map(|u| (u.username.clone(), u.password.clone()))
                .collect(),
        );

        // TLS（naiveproxy 真实使用必须 TLS；disabled 时退化为明文 h2 prior
        // knowledge，仅便于本地测试，与 flux 无 TLS 分支一致）
        if !self.config.tls.enabled {
            warn!(tag = %tag, "naive inbound: tls disabled, serving plaintext h2 (prior knowledge) — NOT for production");
        }
        let acceptor = if self.config.tls.enabled {
            Some(Arc::new(crate::inbound::tls_server::build_acceptor(
                &self.config.tls,
            )?))
        } else {
            None
        };

        let listener = bind_dual_stack_listener(bind).await?;
        info!(
            tag = %tag,
            addr = %bind,
            tls = acceptor.is_some(),
            padding = self.config.padding,
            users = users.len(),
            "naive inbound starting"
        );

        let tcp_tx = self.tcp_tx;
        let padding = self.config.padding;

        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(err = %e, "naive inbound accept error");
                    continue;
                }
            };

            let tcp_tx = tcp_tx.clone();
            let tag = tag.clone();
            let users = users.clone();
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_conn(stream, peer, users, padding, acceptor, tcp_tx, tag).await
                {
                    debug!(
                        peer = %display_sockaddr(peer),
                        err = %e,
                        "naive inbound conn error"
                    );
                }
            });
        }
    }
}

// ── 连接处理：TLS accept → h2 connection 循环 ────────────────────────────────

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    users: Arc<Vec<(String, String)>>,
    padding_enabled: bool,
    acceptor: Option<Arc<tokio_rustls::TlsAcceptor>>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) -> anyhow::Result<()> {
    // TLS accept 前克隆原始 TCP 流（保留 Drop-RST / reject RST 语义）
    let raw_tcp = crate::inbound::proxy_common::duplicate_tcp_stream(&stream).ok();

    let io: Box<dyn AsyncReadWrite> = match acceptor {
        Some(acc) => {
            let tls = acc
                .accept(stream)
                .await
                .map_err(|e| anyhow::anyhow!("naive tls handshake: {e}"))?;
            // ALPN 检查：协商到非 h2（如 http/1.1）说明不是 naiveproxy 客户端
            // （浏览器直访 / 探测），安静关闭（对齐 flux 的非 h2 分支）
            if let Some(alpn) = crate::inbound::tls_server::negotiated_alpn(tls.get_ref().1) {
                if alpn != ALPN_H2 {
                    debug!(
                        peer = %display_sockaddr(peer),
                        tag = %tag,
                        alpn = %alpn,
                        "naive inbound: non-h2 ALPN, closing"
                    );
                    return Ok(());
                }
            }
            Box::new(tls)
        }
        None => Box::new(stream),
    };

    let mut h2_conn = h2::server::handshake(io)
        .await
        .map_err(|e| anyhow::anyhow!("naive: h2 handshake failed: {e}"))?;

    while let Some(result) = h2_conn.accept().await {
        let (request, respond) = match result {
            Ok(v) => v,
            Err(e) => {
                debug!(peer = %display_sockaddr(peer), tag = %tag, err = %e, "naive: h2 accept ended");
                break;
            }
        };

        let users = users.clone();
        let tcp_tx = tcp_tx.clone();
        let tag = tag.clone();
        // raw_tcp 可复制则每条 stream 各持有一份；多 stream 共享连接时
        // 语义等价（Drop-RST 作用于同一底层 socket）
        let raw_tcp = raw_tcp
            .as_ref()
            .and_then(|s| crate::inbound::proxy_common::duplicate_tcp_stream(s).ok());

        tokio::spawn(handle_request(
            request, respond, peer, users, padding_enabled, raw_tcp, tcp_tx, tag,
        ));
    }

    Ok(())
}

// ── 单请求处理：Basic Auth → 200/404/502 → 装箱投递 ─────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
    users: Arc<Vec<(String, String)>>,
    padding_enabled: bool,
    raw_tcp: Option<TcpStream>,
    tcp_tx: mpsc::Sender<InboundTcpStream>,
    tag: Arc<String>,
) {
    let authed = verify_basic_auth(request.headers().get(PROXY_AUTHORIZATION_HEADER), &users);

    // 非 CONNECT、或鉴权失败 → 404（可选关闭；对齐 flux masquerade-404 思路，
    // 不回 407 以免向主动探测者暴露代理属性）
    if !authed || request.method() != Method::CONNECT {
        let user = parse_basic_auth(request.headers().get(PROXY_AUTHORIZATION_HEADER))
            .map(|(u, _)| u)
            .unwrap_or_default();
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .expect("static 404 response");
        let _ = respond.send_response(resp, true);
        debug!(
            peer = %display_sockaddr(peer),
            tag = %tag,
            method = %request.method(),
            user = %user,
            authed,
            "naive: rejected non-CONNECT or bad auth (404)"
        );
        return;
    }

    // 解析 CONNECT authority → target；缺失/非法（未知目标）→ 502
    let target = request
        .uri()
        .authority()
        .and_then(parse_connect_authority)
        .map(|(host, port)| match host.parse::<IpAddr>() {
            Ok(ip) => Target::Socket(SocketAddr::new(ip, port)),
            Err(_) => Target::Domain(host, port),
        });
    let Some(target) = target else {
        let resp = Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .body(())
            .expect("static 502 response");
        let _ = respond.send_response(resp, true);
        debug!(
            peer = %display_sockaddr(peer),
            tag = %tag,
            uri = %request.uri(),
            "naive: CONNECT without valid authority (502)"
        );
        return;
    };

    // padding 协商：服务端开启 且 客户端带了 padding 头才启用
    let wants_padding =
        padding_enabled && request.headers().contains_key(PADDING_HEADER_NAME);

    let mut resp_builder = Response::builder().status(StatusCode::OK);
    if wants_padding {
        resp_builder = resp_builder.header(PADDING_HEADER_NAME, generate_padding_header());
    }
    let response = match resp_builder.body(()) {
        Ok(r) => r,
        Err(e) => {
            debug!(peer = %display_sockaddr(peer), tag = %tag, err = %e, "naive: build 200 response failed");
            return;
        }
    };

    let send_stream = match respond.send_response(response, false) {
        Ok(s) => s,
        Err(e) => {
            debug!(peer = %display_sockaddr(peer), tag = %tag, err = %e, "naive: send 200 response failed");
            return;
        }
    };

    info!(
        peer = %display_sockaddr(peer),
        tag = %tag,
        target = %target,
        padding = wants_padding,
        "naive CONNECT tunnel established"
    );

    let recv_stream = request.into_body();
    let tunnel = if wants_padding {
        NaiveStream::new(send_stream, recv_stream)
    } else {
        NaiveStream::new_plain(send_stream, recv_stream)
    };

    // 装箱交给 dispatcher 路由（peer 为 TLS accept 前捕获的真实客户端地址）
    let sniffed = SniffedStream::from_encrypted(Box::new(tunnel), peer, raw_tcp);

    let _ = tcp_tx
        .send(InboundTcpStream {
            stream: sniffed,
            target,
            inbound_tag: (*tag).clone(),
            sniffed_protocol: None,
            sniffed_domain: None,
        })
        .await;
}
