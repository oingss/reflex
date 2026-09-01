use std::{sync::Arc, time::Duration};

use tokio::time;
use tracing::{debug, warn};

use crate::{
    app::clash_api::DelayHistory, config::provider::HealthCheckConfig,
    outbound::common::group::OutboundRegistry,
};

use super::ProviderManager;

/// 启动 provider 的健康检测循环。
///
/// 启动后延迟 10 秒首次检测，然后按 `config.interval` 定时循环。
pub fn start_health_check(
    provider_tag: String,
    config: HealthCheckConfig,
    manager: Arc<ProviderManager>,
    registry: OutboundRegistry,
    history: Arc<DelayHistory>,
) {
    let interval = config
        .interval_duration()
        .unwrap_or(Duration::from_secs(600));
    let timeout = config.timeout_duration().unwrap_or(Duration::from_secs(5));
    let url = config.url.clone();

    tokio::spawn(async move {
        // 延迟首次检测，等节点和 registry 都就绪
        time::sleep(Duration::from_secs(10)).await;

        let mut ticker = time::interval(interval);
        loop {
            ticker.tick().await;
            run_health_check(&provider_tag, &url, timeout, &manager, &registry, &history).await;
        }
    });
}

async fn run_health_check(
    provider_tag: &str,
    url: &str,
    timeout: Duration,
    manager: &ProviderManager,
    registry: &OutboundRegistry,
    history: &DelayHistory,
) {
    let nodes = manager.nodes_snapshot(provider_tag);
    if nodes.is_empty() {
        return;
    }

    let (probe_host, probe_port) = match parse_probe_url(url) {
        Ok(p) => p,
        Err(e) => {
            warn!(provider = %provider_tag, err = %e, "health_check: invalid url");
            return;
        }
    };
    let probe_path = parse_probe_path(url);
    let url = url.to_string();

    let futs: Vec<_> = nodes
        .into_iter()
        .map(|(tag, _)| {
            let registry = registry.clone();
            let host = probe_host.clone();
            let path = probe_path.clone();
            let url = url.clone();
            async move {
                let outbound = match registry.get().and_then(|m| m.get(&tag)).cloned() {
                    Some(ob) => ob,
                    None => {
                        debug!(node = %tag, "health_check: outbound not registered yet");
                        return (tag, None);
                    }
                };
                let started = std::time::Instant::now();
                let result = tokio::time::timeout(
                    timeout,
                    probe_via_outbound(outbound.as_ref(), &host, probe_port, &path, &url),
                )
                .await;
                let latency_ms = match result {
                    Ok(Ok(())) => Some(started.elapsed().as_millis() as u64),
                    Ok(Err(e)) => {
                        debug!(node = %tag, err = %e, "health_check: probe failed");
                        None
                    }
                    Err(_) => {
                        debug!(node = %tag, "health_check: probe timeout");
                        None
                    }
                };
                (tag, latency_ms)
            }
        })
        .collect();

    let results = futures_util::future::join_all(futs).await;
    for (tag, latency) in results {
        match latency {
            Some(ms) => {
                history.store(&tag, ms);
                debug!(node = %tag, latency_ms = ms, "health_check: ok");
            }
            None => {
                // 探测失败时删除历史记录，使该节点在 Clash API 中显示为无延迟
                // （等同不可用）。旧实现仅跳过，导致曾经健康的节点即使已宕机
                // 仍保留旧的低延迟值，永远不会被降级。
                history.delete(&tag);
                debug!(node = %tag, "health_check: failed, cleared stale delay");
            }
        }
    }
}

async fn probe_via_outbound(
    outbound: &dyn crate::outbound::Outbound,
    host: &str,
    port: u16,
    path: &str,
    url: &str,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = outbound.connect_tcp(host, port).await?;
    let request = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: reflex/1.0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await?;
    anyhow::ensure!(n > 0, "empty response from {url}");
    anyhow::ensure!(
        buf[..n].starts_with(b"HTTP/"),
        "non-HTTP response from {url}"
    );
    Ok(())
}

fn parse_probe_url(url: &str) -> anyhow::Result<(String, u16)> {
    let (default_port, rest) = if let Some(r) = url.strip_prefix("https://") {
        (443u16, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (80u16, r)
    } else {
        anyhow::bail!("health_check url must start with http:// or https://");
    };
    let authority = rest.split('/').next().unwrap_or(rest);

    // 正确处理 IPv6 地址（RFC 3986：[IPv6]:port）。
    // 旧实现用 rsplit_once(':') 在无端口的 IPv6 上会错误地把地址内的冒号
    // 当作 host:port 分隔符（如 "[::1]" 被切成 host=":" port="1]"），
    // 且即使切对了也保留了方括号，传给 outbound.connect_tcp 会解析失败。
    if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 字面量
        let close = stripped
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("health_check url: unterminated IPv6 literal"))?;
        let host = stripped[..close].to_string();
        let after = &stripped[close + 1..];
        let port = if let Some(p) = after.strip_prefix(':') {
            p.parse::<u16>()
                .map_err(|_| anyhow::anyhow!("health_check url: invalid IPv6 port"))?
        } else {
            default_port
        };
        anyhow::ensure!(!host.is_empty(), "health_check url missing host");
        return Ok((host, port));
    }

    // 普通 host（域名或 IPv4）
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        (h.to_string(), p.parse()?)
    } else {
        (authority.to_string(), default_port)
    };
    anyhow::ensure!(!host.is_empty(), "health_check url missing host");
    Ok((host, port))
}

fn parse_probe_path(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let path_start = rest.find('/').unwrap_or(rest.len());
    let path = &rest[path_start..];
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}
