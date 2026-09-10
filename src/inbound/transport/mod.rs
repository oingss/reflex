//! inbound 传输栈：TLS/REALITY 加密层 + v2ray 传输层（tcp/ws/grpc/xhttp）的
//! 统一分层与 accept 循环。VLESS/VMess/Trojan inbound 共用。
//!
//! 分层顺序（由外到内）：TCP → [TLS | REALITY] → [transport] → 协议握手。
//! 其中 XHTTP 因 session 表跨 TCP 连接共享，accept 循环结构与其它传输不同
//! （feed 模式），由 [`serve_inbound`] 内部分派。

pub mod grpc;
pub mod reality;
pub mod ws;
pub mod xhttp;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

use crate::config::inbound::{InboundTlsConfig, InboundTransportConfig};
use crate::outbound::AsyncReadWrite;

// ── 分层定义 ─────────────────────────────────────────────────────────────────

enum TlsLayer {
    None,
    Tls(Arc<tokio_rustls::TlsAcceptor>),
    Reality(Arc<reality::RealityServer>),
}

enum TransportLayer {
    Tcp,
    Ws(ws::WsServerOptions),
    Grpc(grpc::GrpcServerOptions),
    Xhttp(xhttp::XhttpServer),
}

/// inbound 传输栈（每个 inbound 实例一个）
pub struct InboundStack {
    tls: TlsLayer,
    transport: TransportLayer,
}

impl InboundStack {
    /// 从配置构建传输栈。校验错误（如 reality key 非法）在此返回。
    pub fn build(
        tls_cfg: &InboundTlsConfig,
        transport_cfg: Option<&InboundTransportConfig>,
    ) -> anyhow::Result<Self> {
        let tls = if let Some(r) = &tls_cfg.reality {
            if r.enabled {
                TlsLayer::Reality(Arc::new(reality::RealityServer::from_config(
                    r,
                    tls_cfg.server_name.as_deref(),
                )?))
            } else if tls_cfg.enabled {
                TlsLayer::Tls(Arc::new(crate::inbound::tls_server::build_acceptor(tls_cfg)?))
            } else {
                TlsLayer::None
            }
        } else if tls_cfg.enabled {
            TlsLayer::Tls(Arc::new(crate::inbound::tls_server::build_acceptor(tls_cfg)?))
        } else {
            TlsLayer::None
        };

        let transport = match transport_cfg {
            None | Some(InboundTransportConfig::Tcp) => TransportLayer::Tcp,
            Some(InboundTransportConfig::Ws(c)) => TransportLayer::Ws(ws::WsServerOptions::from_config(c)),
            Some(InboundTransportConfig::Grpc(c)) => {
                TransportLayer::Grpc(grpc::GrpcServerOptions::from_config(c))
            }
            Some(InboundTransportConfig::Xhttp(c)) => TransportLayer::Xhttp(xhttp::XhttpServer::new(
                xhttp::XhttpServerOptions::from_config(c),
            )),
        };

        Ok(Self { tls, transport })
    }

    pub fn is_xhttp(&self) -> bool {
        matches!(self.transport, TransportLayer::Xhttp(_))
    }

    /// 传输层/加密层描述（日志用）
    pub fn describe(&self) -> String {
        let tls = match &self.tls {
            TlsLayer::None => "none",
            TlsLayer::Tls(_) => "tls",
            TlsLayer::Reality(_) => "reality",
        };
        let tr = match &self.transport {
            TransportLayer::Tcp => "tcp",
            TransportLayer::Ws(_) => "ws",
            TransportLayer::Grpc(_) => "grpc",
            TransportLayer::Xhttp(_) => "xhttp",
        };
        format!("transport={tr}, tls={tls}")
    }

    /// 接受一条 TCP 连接并完成全部握手（TLS/Reality + 传输层）。
    ///
    /// 返回 (协议层字节流, 原始 TCP 副本)。原始副本供协议层 Drop-RST 语义使用；
    /// xhttp 传输不适用本方法（用 [`InboundStack::accept_feed_xhttp`]）。
    pub async fn accept(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> anyhow::Result<(Box<dyn AsyncReadWrite>, Option<TcpStream>)> {
        // TLS 握手前克隆原始 TCP（供 RST 语义使用）
        let raw_tcp = crate::inbound::proxy_common::duplicate_tcp_stream(&stream).ok();

        // ── 加密层 ────────────────────────────────────────────────────────
        let io: Box<dyn AsyncReadWrite> = match &self.tls {
            TlsLayer::None => Box::new(stream),
            TlsLayer::Tls(acc) => Box::new(
                acc.accept(stream)
                    .await
                    .map_err(|e| anyhow::anyhow!("tls handshake: {e}"))?,
            ),
            TlsLayer::Reality(cfg) => reality::accept(stream, peer, cfg).await?,
        };

        // ── 传输层 ────────────────────────────────────────────────────────
        let io = match &self.transport {
            TransportLayer::Tcp => io,
            TransportLayer::Ws(opts) => Box::new(
                ws::accept(io, opts)
                    .await
                    .map_err(|e| anyhow::anyhow!("ws handshake: {e}"))?,
            ) as Box<dyn AsyncReadWrite>,
            TransportLayer::Grpc(opts) => grpc::accept(io, opts).await?,
            TransportLayer::Xhttp(_) => {
                anyhow::bail!("xhttp transport must use accept_feed_xhttp");
            }
        };

        Ok((io, raw_tcp))
    }

    /// xhttp 路径：完成 TLS/Reality 握手后把 HTTP 流交给共享 XhttpServer。
    /// 逻辑连接随后经 [`InboundStack::xhttp_accept`] 取出。
    pub async fn accept_feed_xhttp(&self, stream: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
        let io: Box<dyn AsyncReadWrite> = match &self.tls {
            TlsLayer::None => Box::new(stream),
            TlsLayer::Tls(acc) => Box::new(
                acc.accept(stream)
                    .await
                    .map_err(|e| anyhow::anyhow!("tls handshake: {e}"))?,
            ),
            TlsLayer::Reality(cfg) => reality::accept(stream, peer, cfg).await?,
        };

        match &self.transport {
            TransportLayer::Xhttp(srv) => {
                srv.feed_tls(io, peer);
                Ok(())
            }
            _ => anyhow::bail!("accept_feed_xhttp called for non-xhttp transport"),
        }
    }

    /// 取出下一个就绪的 xhttp 逻辑连接
    pub async fn xhttp_accept(&self) -> Option<Box<dyn AsyncReadWrite>> {
        match &self.transport {
            TransportLayer::Xhttp(srv) => {
                srv.accept().await.map(|s| Box::new(s) as Box<dyn AsyncReadWrite>)
            }
            _ => None,
        }
    }
}

// ── 共享 accept 循环 ─────────────────────────────────────────────────────────

/// 单条连接的处理闭包类型：(协议层流, peer, 原始 TCP 副本)
pub type InboundConnHandler = Arc<
    dyn Fn(
            Box<dyn AsyncReadWrite>,
            SocketAddr,
            Option<TcpStream>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<()>> + Send>>
        + Send
        + Sync,
>;

/// inbound 主 accept 循环：按传输栈完成握手后把逻辑连接交给 handler。
/// xhttp 传输自动切换为 feed/accept 双任务结构。
pub async fn serve_inbound(
    listener: TcpListener,
    stack: Arc<InboundStack>,
    handler: InboundConnHandler,
) -> anyhow::Result<()> {
    if stack.is_xhttp() {
        // ── 任务1：接受 TCP 连接 → TLS/Reality → feed 给 XhttpServer ─────
        let stack_feeder = stack.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let st = stack_feeder.clone();
                        tokio::spawn(async move {
                            if let Err(e) = st.accept_feed_xhttp(stream, peer).await {
                                debug!(peer = %peer, err = %e, "inbound xhttp feed error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(err = %e, "inbound accept error");
                    }
                }
            }
        });

        // ── 任务2：从 XhttpServer 取完整逻辑连接，交给 handler ───────────
        let placeholder: SocketAddr = "0.0.0.0:0".parse().expect("static addr");
        loop {
            let Some(io) = stack.xhttp_accept().await else {
                break;
            };
            let h = handler.clone();
            tokio::spawn(async move {
                if let Err(e) = h(io, placeholder, None).await {
                    debug!(err = %e, "inbound xhttp conn error");
                }
            });
        }
        return Ok(());
    }

    // ── 其它传输：per-TCP-connection ─────────────────────────────────────
    loop {
        let (stream, peer) = listener.accept().await?;
        let st = stack.clone();
        let h = handler.clone();
        tokio::spawn(async move {
            match st.accept(stream, peer).await {
                Ok((io, raw_tcp)) => {
                    if let Err(e) = h(io, peer, raw_tcp).await {
                        debug!(peer = %peer, err = %e, "inbound conn error");
                    }
                }
                Err(e) => {
                    debug!(peer = %peer, err = %e, "inbound transport accept error");
                }
            }
        });
    }
}
