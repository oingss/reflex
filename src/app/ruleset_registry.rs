use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::{
    config::route::{RouteConfig, RuleSetType},
    router::RuleSetMeta,
};

// ── 公开结构 ──────────────────────────────────────────────────────────────────

pub struct RuleSetRegistry {
    inner: RwLock<RegistryInner>,
    /// 原始配置，供 reload 时查找 url / path
    route_config: RouteConfig,
}

struct RegistryInner {
    /// tag → 元数据
    meta: std::collections::HashMap<String, RuleSetMeta>,
}

impl RuleSetRegistry {
    /// 从 Router 的 ruleset_meta 初始化
    pub fn from_router_meta(
        route_config: RouteConfig,
        meta: std::collections::HashMap<String, RuleSetMeta>,
    ) -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(RegistryInner { meta }),
            route_config,
        })
    }

    /// 返回所有规则集的元数据快照（克隆，开销低）
    pub async fn snapshot(&self) -> std::collections::HashMap<String, RuleSetMeta> {
        self.inner.read().await.meta.clone()
    }

    /// 启动规则集热更新后台任务：
    /// - 对每个 `type = local` 的规则集，用 `notify` 监听其 `path` 父目录
    ///   （监听目录而非文件本身是为了支持 `mv`/`vim` 等原子替换写法），
    ///   文件变更时触发重编译并刷新元数据。
    /// - 对每个 `type = remote` 且配置了 `update_interval` 的规则集，启动
    ///   定时器周期调用 `reload_remote()`。
    ///
    /// 调用方应将返回的 `JoinSet` 保留在 `App::tasks` 中，随进程生命周期存活。
    pub fn start_watchers(self: &Arc<Self>) -> Vec<tokio::task::JoinHandle<()>> {
        let mut handles = Vec::new();

        for rs_ref in &self.route_config.rule_set {
            let tag = rs_ref.tag.clone();
            match rs_ref.r#type {
                RuleSetType::Local => {
                    let Some(path) = rs_ref.path.clone() else {
                        debug!(tag = %tag, "ruleset(local): no path, skip watcher");
                        continue;
                    };
                    let registry = self.clone();
                    let tag_clone = tag.clone();
                    let path_clone = path.clone();
                    let format = rs_ref.format.clone();
                    handles.push(tokio::spawn(async move {
                        registry
                            .run_local_watcher(tag_clone, path_clone, format)
                            .await;
                    }));
                }
                RuleSetType::Remote => {
                    let Some(interval_str) = rs_ref.update_interval.clone() else {
                        debug!(tag = %tag, "ruleset(remote): no update_interval, skip auto-refresh");
                        continue;
                    };
                    let Some(interval_dur) = parse_duration(&interval_str) else {
                        warn!(tag = %tag, interval = %interval_str, "ruleset(remote): invalid update_interval, skip auto-refresh");
                        continue;
                    };
                    let registry = self.clone();
                    let tag_clone = tag.clone();
                    handles.push(tokio::spawn(async move {
                        registry.run_remote_timer(tag_clone, interval_dur).await;
                    }));
                }
            }
        }

        if !handles.is_empty() {
            info!(
                count = handles.len(),
                "ruleset: hot-reload watchers started"
            );
        }
        handles
    }

    /// 本地规则集文件监听循环：使用 `notify` crate 监听父目录变更。
    /// 收到与目标文件相关的事件后，等待 200ms 去抖动（编辑器多次写），
    /// 然后重新编译并刷新元数据。
    async fn run_local_watcher(
        self: Arc<Self>,
        tag: String,
        path: String,
        format: crate::config::route::RuleSetFormat,
    ) {
        use notify::{event::EventKind, RecommendedWatcher, RecursiveMode, Watcher};
        use std::path::Path;

        let p = Path::new(&path);
        let watch_dir = match p.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => Path::new(".").to_path_buf(),
        };
        let file_name = p.file_name().map(|n| n.to_os_string()).unwrap_or_default();

        // notify 的 callback 是同步 FnMut，事件通过 mpsc 通道投递到异步侧
        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(32);

        let mut watcher = match RecommendedWatcher::new(
            move |res: notify::Result<notify::Event>| {
                if let Ok(ev) = res {
                    if !matches!(
                        ev.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        return;
                    }
                    // 只关心目标文件本身的事件
                    let affects_target = ev.paths.iter().any(|pp| {
                        pp.file_name()
                            .map(|n| n == file_name.as_os_str())
                            .unwrap_or(false)
                    });
                    if affects_target {
                        // 通道满时丢弃事件（去抖动会兜底）
                        let _ = tx.blocking_send(());
                    }
                }
            },
            notify::Config::default(),
        ) {
            Ok(w) => w,
            Err(e) => {
                warn!(tag = %tag, path = %path, err = %e, "ruleset: notify watcher init failed");
                return;
            }
        };

        if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
            warn!(tag = %tag, dir = ?watch_dir, err = %e, "ruleset: notify watch failed");
            return;
        }

        info!(tag = %tag, path = %path, "ruleset: local file watcher started");

        // 把 watcher 守住，否则 drop 后会停止监听
        let _watcher_guard = watcher;

        loop {
            // 收到首个事件后等 200ms 去抖动，合并连续写
            if rx.recv().await.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            // 抽干积压事件
            while rx.try_recv().is_ok() {}

            match self.reload_local(&tag, &path, format.clone()).await {
                Ok(count) => info!(tag = %tag, rule_count = count, "ruleset: local file reloaded"),
                Err(e) => warn!(tag = %tag, err = %e, "ruleset: local reload failed"),
            }
        }
    }

    /// 远程规则集周期更新循环：每隔 `interval` 调用 `reload_remote()`。
    /// 首次启动立即跑一次（如果想要启动时也下载，可由调用方控制）。
    async fn run_remote_timer(self: Arc<Self>, tag: String, interval: Duration) {
        info!(tag = %tag, ?interval, "ruleset: remote auto-refresh timer started");
        let mut ticker = tokio::time::interval(interval);
        // 第一个 tick 立即触发，跳过首次（启动时已经下载过了）
        ticker.tick().await;
        loop {
            ticker.tick().await;
            debug!(tag = %tag, "ruleset: remote timer fired, reloading");
            if let Err(e) = self.reload_remote(&tag).await {
                warn!(tag = %tag, err = %e, "ruleset: remote auto-refresh failed");
            }
        }
    }

    /// 重新加载本地规则集文件：读取磁盘 → 编译 → 刷新 Registry 元数据。
    /// 不修改 Router 内的 rulesets（需要重启生效），但元数据立即更新，
    /// Clash API 查询能反映最新状态。
    pub async fn reload_local(
        &self,
        tag: &str,
        path: &str,
        format: crate::config::route::RuleSetFormat,
    ) -> anyhow::Result<usize> {
        let path_owned = path.to_string();
        let tag_owned = tag.to_string();
        // 文件 IO + 编译放到 spawn_blocking
        let rule_count = tokio::task::spawn_blocking(move || load_and_count(&path_owned, &format))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking panicked: {e}"))??;

        let updated_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        {
            let mut guard = self.inner.write().await;
            guard.meta.insert(
                tag_owned.clone(),
                RuleSetMeta {
                    rule_count,
                    updated_at_ms,
                },
            );
        }

        let _ = tag_owned; // 已被 move
        Ok(rule_count)
    }

    /// 触发指定 remote 规则集重新下载，更新本地缓存文件，并刷新元数据。
    /// 支持 `format = "binary"`（默认）和 `format = "source"`（sing-box JSON/文本）。
    /// 失败时返回错误描述。
    pub async fn reload_remote(&self, tag: &str) -> anyhow::Result<()> {
        let rs_ref = self
            .route_config
            .rule_set
            .iter()
            .find(|r| r.tag == tag)
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}' not found"))?
            .clone();

        if rs_ref.r#type != RuleSetType::Remote {
            anyhow::bail!("rule_set '{tag}' is not remote, cannot update");
        }

        let url = rs_ref
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("rule_set '{tag}': missing url"))?
            .to_string();

        let tag_owned = tag.to_string();
        let path = rs_ref.path.clone();
        let format = rs_ref.format.clone();

        // 阻塞下载放到专用线程池
        let data = tokio::task::spawn_blocking(move || download_bytes(&url, &tag_owned))
            .await
            .map_err(|e| anyhow::anyhow!("spawn_blocking panicked: {e}"))??;

        use crate::config::route::RuleSetFormat;
        let rule_count = if format == RuleSetFormat::Source {
            // source 格式：编译并缓存原始文本
            let src = String::from_utf8(data).map_err(|e| {
                anyhow::anyhow!("rule_set '{tag}': downloaded source is not UTF-8: {e}")
            })?;
            if let Some(ref p) = path {
                if let Some(parent) = std::path::Path::new(p).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(p, src.as_bytes()) {
                    tracing::warn!(tag, path = p, err = %e, "rule_set: failed to write source cache");
                } else {
                    tracing::debug!(tag, path = p, "rule_set: source cache updated");
                }
            }
            // 编译计算规则数（直接从 CompiledRuleSet 构建，省 serialize→from_bytes 往返）
            let trimmed = src.trim_start();
            let compiled = if trimmed.starts_with('{') {
                crate::ruleset::compiler::CompiledRuleSet::from_singbox_json(trimmed)
                    .map_err(|e| anyhow::anyhow!("rule_set '{tag}': source parse error: {e}"))?
            } else if looks_like_mihomo_yaml(trimmed) {
                // mihomo / Clash `payload:` 规则集 yaml
                crate::ruleset::compiler::CompiledRuleSet::from_mihomo_yaml(trimmed, None).map_err(
                    |e| anyhow::anyhow!("rule_set '{tag}': mihomo yaml parse error: {e}"),
                )?
            } else {
                crate::ruleset::compiler::CompiledRuleSet::from_text(trimmed)
                    .map_err(|e| anyhow::anyhow!("rule_set '{tag}': source parse error: {e}"))?
            };
            let loaded = crate::ruleset::LoadedRuleSet::from_compiled(compiled)
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': internal error: {e}"))?;
            crate::ruleset::RuleSet::from_loaded(loaded)
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': load error: {e}"))?
                .rule_count()
        } else {
            // binary 格式：覆盖磁盘缓存
            if let Some(ref p) = path {
                if let Some(parent) = std::path::Path::new(p).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Err(e) = std::fs::write(p, &data) {
                    tracing::warn!(tag, path = p, err = %e, "rule_set: failed to write disk cache");
                } else {
                    tracing::debug!(tag, path = p, "rule_set: disk cache updated");
                }
            }
            let loaded = crate::ruleset::LoadedRuleSet::from_bytes(&data)
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': parse error: {e}"))?;
            crate::ruleset::RuleSet::from_loaded(loaded)
                .map_err(|e| anyhow::anyhow!("rule_set '{tag}': compile error: {e}"))?
                .rule_count()
        };

        let updated_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        {
            let mut guard = self.inner.write().await;
            guard.meta.insert(
                tag.to_string(),
                RuleSetMeta {
                    rule_count,
                    updated_at_ms,
                },
            );
        }

        tracing::info!(tag, rule_count, "rule_set: remote reload done");
        Ok(())
    }
}

// ── 下载辅助（同步，供 spawn_blocking 使用）──────────────────────────────────

fn download_bytes(url: &str, tag: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    use std::time::Duration;
    // 旧实现无超时：慢速/挂起的服务器会无限阻塞 spawn_blocking 线程。
    // 设置 30s 总超时（含连接阶段），防止资源长期占用。
    let resp = ureq::get(url)
        .timeout(Duration::from_secs(30))
        .call()
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': download failed from '{url}': {e}"))?;
    let mut buf = Vec::new();
    resp.into_reader()
        .read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("rule_set '{tag}': failed to read response body: {e}"))?;
    Ok(buf)
}

/// 探测给定文本是否是 mihomo / Clash 风格的 yaml 规则集。
///
/// 判别规则：trim 后首行以 `payload:` 或 `payload :` 开头（忽略大小写）。
/// 这种启发式足够覆盖 Loyalsoldier、Hackl0us 等主流规则仓库的发布格式。
fn looks_like_mihomo_yaml(src: &str) -> bool {
    let first_line = src.lines().next().unwrap_or("").trim_start();
    let lower = first_line.to_ascii_lowercase();
    lower.starts_with("payload:") || lower.starts_with("payload :")
}

/// 读取本地规则集文件并返回编译后的规则数量。
/// 用于 `reload_local` 的 spawn_blocking 闭包内，避免阻塞异步运行时。
fn load_and_count(
    path: &str,
    format: &crate::config::route::RuleSetFormat,
) -> anyhow::Result<usize> {
    use crate::config::route::RuleSetFormat;
    let data = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("rule_set: failed to read '{path}': {e}"))?;
    match format {
        RuleSetFormat::Binary => {
            let loaded = crate::ruleset::LoadedRuleSet::from_bytes(&data)
                .map_err(|e| anyhow::anyhow!("rule_set: parse error: {e}"))?;
            let rs = crate::ruleset::RuleSet::from_loaded(loaded)
                .map_err(|e| anyhow::anyhow!("rule_set: load error: {e}"))?;
            Ok(rs.rule_count())
        }
        RuleSetFormat::Source => {
            let src = String::from_utf8(data)
                .map_err(|e| anyhow::anyhow!("rule_set: source is not UTF-8: {e}"))?;
            let trimmed = src.trim_start();
            let compiled = if trimmed.starts_with('{') {
                crate::ruleset::compiler::CompiledRuleSet::from_singbox_json(trimmed)?
            } else if looks_like_mihomo_yaml(trimmed) {
                crate::ruleset::compiler::CompiledRuleSet::from_mihomo_yaml(trimmed, None)?
            } else {
                crate::ruleset::compiler::CompiledRuleSet::from_text(trimmed)?
            };
            Ok(compiled.total_entries())
        }
    }
}

/// 解析配置中的时长字符串：支持 `"1h"`/`"30m"`/`"1d"`/`"3600s"`/`"3600"` 等格式。
/// 与 provider 的 `update_interval` 解析逻辑保持一致。
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // 纯数字 → 秒
    if let Ok(secs) = s.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let (num_str, suffix) = s.split_at(
        s.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(s.len()),
    );
    let num: f64 = num_str.parse().ok()?;
    let secs = match suffix {
        "s" => num,
        "m" => num * 60.0,
        "h" => num * 3600.0,
        "d" => num * 86400.0,
        "w" => num * 86400.0 * 7.0,
        _ => return None,
    };
    if secs.is_finite() && secs > 0.0 {
        Some(Duration::from_secs(secs as u64))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_variants() {
        assert_eq!(parse_duration("3600"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("3600s"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("30m"), Some(Duration::from_secs(1800)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_duration("1w"), Some(Duration::from_secs(86400 * 7)));
        assert_eq!(parse_duration("1.5h"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("10x"), None);
    }

    #[test]
    fn looks_like_mihomo_yaml_variants() {
        assert!(looks_like_mihomo_yaml("payload:\n  - DOMAIN,example.com"));
        assert!(looks_like_mihomo_yaml("Payload: foo"));
        assert!(looks_like_mihomo_yaml("payload :"));
        assert!(!looks_like_mihomo_yaml("[\"DOMAIN,example.com\"]"));
        assert!(!looks_like_mihomo_yaml(""));
    }
}
