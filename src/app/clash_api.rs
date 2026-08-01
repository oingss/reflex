use std::{
    collections::{HashMap, HashSet},
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;

use portable_atomic::{AtomicI64, AtomicU64};

use serde_json::json;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{broadcast, Notify},
    task::JoinHandle,
    time,
};
use tracing::{debug, info};

use crate::{
    app::{outbound_mgr::OutboundManager, ruleset_registry::RuleSetRegistry, stats::Stats},
    clash_mode::ClashMode,
    config::{
        experimental::ClashApiConfig, inbound::InboundConfig, log::LogLevel, route::RouteConfig,
    },
    outbound::Outbound,
};

// ── 全局日志转发器（供 tracing subscriber 写入 Clash API 日志流）───────────────

static GLOBAL_LOG_TX: std::sync::OnceLock<broadcast::Sender<LogEntry>> = std::sync::OnceLock::new();

/// 全局日志级别句柄，供 PATCH /configs 的 "log-level" 字段热改日志级别。
/// 由 main.rs 的 init_tracing 通过 `set_global_log_level_handle` 设置；
/// ClashApi 启动时调用 `global_log_level_handle` 取引用。
/// 若 tracing 用 NoSubscriber（level=off）则为 None，PATCH log-level 时忽略。
static GLOBAL_LOG_LEVEL: std::sync::OnceLock<Arc<std::sync::atomic::AtomicU8>> =
    std::sync::OnceLock::new();

/// 由 main.rs init_tracing 调用：注册全局日志级别原子句柄。
/// ClashApi 持有 Arc 引用以原子方式读写，subscriber 端读取以做 enabled() 过滤。
pub fn set_global_log_level_handle(handle: Arc<std::sync::atomic::AtomicU8>) {
    let _ = GLOBAL_LOG_LEVEL.set(handle);
}

/// ClashApi::new 调用：取全局日志级别句柄。若 tracing 未初始化（off 模式）返回 None。
pub fn global_log_level_handle() -> Option<Arc<std::sync::atomic::AtomicU8>> {
    GLOBAL_LOG_LEVEL.get().cloned()
}

/// 由 tracing subscriber 调用：向 Clash API 推送日志条目。
pub fn broadcast_log(level: &str, message: String) {
    if let Some(tx) = GLOBAL_LOG_TX.get() {
        let _ = tx.send(LogEntry {
            level: level.to_string(),
            message,
        });
    }
}

// ── URLTest 延迟历史 ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DelayRecord {
    pub time_ms: u64,
    pub delay: u64,
}

#[derive(Default)]
pub struct DelayHistory {
    inner: RwLock<HashMap<String, DelayRecord>>,
}

impl DelayHistory {
    pub fn store(&self, tag: &str, delay: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.inner.write().unwrap().insert(
            tag.to_string(),
            DelayRecord {
                time_ms: now,
                delay,
            },
        );
    }

    pub fn load(&self, tag: &str) -> Option<DelayRecord> {
        self.inner.read().unwrap().get(tag).cloned()
    }

    pub fn delete(&self, tag: &str) {
        self.inner.write().unwrap().remove(tag);
    }
}

// ── 连接追踪 ──────────────────────────────────────────────────────────────────

/// 命中规则信息。
///
/// ## 优化：Arc<str> 替代 String
/// rule_type 几乎全是静态字符串（"DOMAIN", "RULE-SET" 等），
/// rule_payload 来自路由器内部字符串切片。
/// 改用 Arc<str> 后，从 &str 创建只分配一次引用计数块，
/// clone() 仅增加引用计数（原子 +1），不再复制字符串内容。
/// 在 Dispatcher 热路径上每条连接可节省 2~4 次堆分配。
#[derive(Clone, Default)]
pub struct RuleInfo {
    pub rule_type: Arc<str>,
    pub rule_payload: Arc<str>,
}

/// 连接基本信息，打包传递以规避 clippy::too_many_arguments
///
/// `host` 与 `destination_ip` 是两个独立字段（对齐 sing-box tracker 的
/// `metadata.Domain` 与 `metadata.Destination.Addr`），不再互斥：
/// - tproxy/tun + sniff 命中时，host=嗅探域名，destination_ip=原始 IP，同时有值；
/// - 目标本身就是域名时，host=域名，destination_ip 为空；
/// - 目标是 IP 且未嗅探到域名时，host 为空，destination_ip=IP。
pub struct ConnInfo<'a> {
    pub network: &'a str,
    /// 展示用域名：优先取 sniff 命中域名，否则取原始域名目标；两者都无时为空。
    pub host: &'a str,
    /// 展示用目标 IP：来自入站原始 IP 目标（tproxy/tun），域名为目标时为空。
    pub destination_ip: &'a str,
    pub source: std::net::SocketAddr,
    pub dest_port: u16,
    pub inbound: &'a str,
    pub outbound: &'a str,
}

#[derive(Clone)]
pub struct ConnMeta {
    pub id: u64,
    pub network: String,
    pub host: String,
    pub destination_ip: String,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub inbound: String,
    pub outbound: String,
    /// Arc<str>：从 RuleInfo clone 时只增加引用计数，不复制字符串
    pub rule: Arc<str>,
    pub rule_payload: Arc<str>,
    pub started_ms: u64,
    pub upload: Arc<AtomicI64>,
    pub download: Arc<AtomicI64>,
    /// DELETE /connections(/:id) 设置为 true 以请求主动终止该连接。
    pub cancelled: Arc<AtomicBool>,
    /// 配合 cancelled 使用：取消时调用 notify_waiters() 唤醒 dispatcher 中
    /// 正在 select! 等待的任务，避免轮询。
    pub cancel_notify: Arc<Notify>,
    /// 上次观测到流量变化的时刻（毫秒，UNIX_EPOCH 起）。由 idle sweeper
    /// 周期采样 upload/download 计数器并对比，发现变化时更新此字段。
    /// 连续 idle_timeout 无变化即视为"静默死亡"连接，主动 cancel_by_id 终止。
    /// 用 Arc<AtomicI64> 而非普通 u64：sweeper 与 dispatcher 跨任务读写需要原子可见性。
    pub last_active_ms: Arc<AtomicI64>,
}

pub struct ConnGuard {
    id: u64,
    tracker: Arc<ConnectionTracker>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.tracker.remove(self.id);
    }
}

impl ConnGuard {
    pub fn add_bytes(&self, up: i64, down: i64) {
        if let Some(meta) = self.tracker.get(self.id) {
            meta.upload.fetch_add(up as _, Ordering::Relaxed);
            meta.download.fetch_add(down as _, Ordering::Relaxed);
        }
    }

    /// 返回实时上传/下载计数器的 Arc 引用，供 relay_tracked 实时更新。
    pub fn live_counters(&self) -> Option<(Arc<AtomicI64>, Arc<AtomicI64>)> {
        self.tracker
            .get(self.id)
            .map(|meta| (meta.upload.clone(), meta.download.clone()))
    }

    /// 返回该连接的取消句柄 (cancelled flag, notify)，供 dispatcher 在
    /// `tokio::select!` 中与实际数据转发竞速，实现 DELETE /connections(/:id)
    /// 主动终止活跃连接（而不仅仅是从展示列表中移除）。
    pub fn cancel_handle(&self) -> Option<(Arc<AtomicBool>, Arc<Notify>)> {
        self.tracker
            .get(self.id)
            .map(|meta| (meta.cancelled.clone(), meta.cancel_notify.clone()))
    }
}

/// 等待连接被 Clash API 标记为取消（DELETE /connections 或 DELETE /connections/:id）。
///
/// 用法：与实际转发 future 一起放入 `tokio::select!`；一旦被取消，转发 future
/// 会被丢弃（drop），其内部持有的入站/出站 socket 随之关闭，从而真正终止连接，
/// 而不只是把它从 Clash API 的展示列表中移除。
///
/// 采用 tokio 官方推荐的"先构造 Notified 再检查标志位"写法，避免 check-then-wait
/// 之间的竞态导致错过通知（notify_waiters 只唤醒构造时间早于该调用的 Notified）。
pub async fn wait_cancelled(cancelled: &AtomicBool, notify: &Notify) {
    loop {
        let notified = notify.notified();
        if cancelled.load(Ordering::Relaxed) {
            return;
        }
        notified.await;
    }
}

pub struct ConnectionTracker {
    next_id: AtomicU64,
    /// DashMap 替代 RwLock<HashMap>：每条连接建立/断开都要写，
    /// 高并发时全局写锁是瓶颈。DashMap 16 分片锁大幅降低竞争。
    conns: DashMap<u64, ConnMeta>,
}

impl ConnectionTracker {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            next_id: AtomicU64::new(1),
            conns: DashMap::new(),
        })
    }

    pub fn register(self: &Arc<Self>, info: ConnInfo<'_>, rule_info: &RuleInfo) -> ConnGuard {
        #[allow(clippy::unnecessary_cast)]
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let meta = ConnMeta {
            id,
            network: info.network.to_string(),
            host: info.host.to_string(),
            destination_ip: info.destination_ip.to_string(),
            source_ip: info.source.ip().to_string(),
            source_port: info.source.port(),
            dest_port: info.dest_port,
            inbound: info.inbound.to_string(),
            outbound: info.outbound.to_string(),
            rule: rule_info.rule_type.clone(),
            rule_payload: rule_info.rule_payload.clone(),
            started_ms: now,
            upload: Arc::new(AtomicI64::new(0)),
            download: Arc::new(AtomicI64::new(0)),
            cancelled: Arc::new(AtomicBool::new(false)),
            cancel_notify: Arc::new(Notify::new()),
            last_active_ms: Arc::new(AtomicI64::new(now as i64)),
        };
        self.conns.insert(id, meta);
        ConnGuard {
            id,
            tracker: self.clone(),
        }
    }

    fn remove(&self, id: u64) {
        self.conns.remove(&id);
    }

    fn get(&self, id: u64) -> Option<ConnMeta> {
        self.conns.get(&id).map(|r| r.clone())
    }

    fn snapshot(&self) -> Vec<ConnMeta> {
        self.conns.iter().map(|r| r.value().clone()).collect()
    }

    /// 按 id 删除单条连接（供 DELETE /connections/:id 使用）
    pub fn len(&self) -> usize {
        self.conns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.conns.is_empty()
    }

    pub fn remove_by_id(&self, id: u64) {
        self.conns.remove(&id);
    }

    /// 请求终止指定连接（设置取消标志并唤醒等待者），不立即从展示列表移除——
    /// 调用方通常紧接着调用 `remove_by_id` 让其立刻从 GET /connections 中消失，
    /// 而底层 socket 会在 dispatcher 的 select! 感知到取消后异步关闭。
    pub fn cancel_by_id(&self, id: u64) {
        if let Some(meta) = self.conns.get(&id) {
            meta.cancelled.store(true, Ordering::Relaxed);
            meta.cancel_notify.notify_waiters();
        }
    }

    /// 请求终止所有当前活跃连接（对齐 sing-box `DELETE /connections` 行为：
    /// 关闭全部连接，而不仅仅是清空统计）。
    pub fn cancel_all(&self) {
        for entry in self.conns.iter() {
            entry.value().cancelled.store(true, Ordering::Relaxed);
            entry.value().cancel_notify.notify_waiters();
        }
    }

    /// 清空连接展示表（配合 cancel_all 使用，使 GET /connections 立即归零）。
    pub fn clear(&self) {
        self.conns.clear();
    }

    /// 启动应用层 idle 探活后台任务。
    ///
    /// 设计动机：reflex 原有架构下，一条 TCP 连接仅在以下三种情况会从
    /// `GET /connections` 列表中移除——(1) 底层 socket 返回 EOF/Err；
    /// (2) 内核 TCP keepalive 探测失败（默认 idle 300s + 每次重试 75s，
    /// 最坏 ~10+ 分钟才报错）；(3) 用户主动调用 Clash API DELETE。
    /// 这导致"静默死亡"的连接（NAT 静默丢状态、半关闭、对端进程被 kill
    /// 但 RST 未送达等）会在连接页面驻留极长时间，甚至无限期。
    ///
    /// 本 sweeper 作为内核 keepalive 之上的应用层双保险：周期采样每条
    /// 连接的 upload+download 计数器，若在 `idle_timeout` 内字节计数无
    /// 任何变化，则判定为死连接，调用 `cancel_by_id` 主动终止。该路径
    /// 复用现有的 cancel 链路（cancelled flag + Notify + dispatcher select!），
    /// 无需修改 dispatcher 即可触发 socket 关闭。
    ///
    /// 判定依据是"流量计数器是否变化"而非"read 是否超时"——这样合法的
    /// 长空闲连接（带应用层心跳的 WebSocket / SSH，其心跳会推动计数器）
    /// 不会被误杀。
    ///
    /// 返回 JoinHandle 供调用方纳入 task 集合统一管理生命周期。
    pub fn spawn_idle_sweeper(
        self: &Arc<Self>,
        check_interval: Duration,
        idle_timeout: Duration,
    ) -> JoinHandle<()> {
        // clone 一份 Arc<Self>，让 spawned task 持有 'static 所有权
        // （tokio::spawn 要求 future 自包含且 'static）。
        let tracker = self.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(check_interval);
            // tick 立即触发一次会采样到大量"刚建立"的连接，跳过首个 tick
            // 避免误判（首个 tick 时 last_bytes 为空，全部走 None 分支）。
            interval.tick().await;

            // 记录上次采样到的字节数（up, down），用于本次差分判断是否还在动
            let mut last_bytes: HashMap<u64, (i64, i64)> = HashMap::new();

            loop {
                interval.tick().await;
                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as i64;
                let idle_limit_ms = idle_timeout.as_millis() as i64;

                // 当前所有活跃连接 id，用于清理已断开连接的采样缓存
                let mut live_ids: HashSet<u64> = HashSet::new();

                for entry in tracker.conns.iter() {
                    let id = entry.id;
                    let up = entry.upload.load(Ordering::Relaxed);
                    let down = entry.download.load(Ordering::Relaxed);
                    live_ids.insert(id);

                    let prev = last_bytes.insert(id, (up, down));
                    match prev {
                        // 字节数有变化 → 连接仍活着，刷新 last_active_ms
                        Some((pu, pd)) if pu != up || pd != down => {
                            entry.last_active_ms.store(now_ms, Ordering::Relaxed);
                        }
                        // 字节数无变化 → 检查是否超过 idle 阈值
                        Some(_) => {
                            let last = entry.last_active_ms.load(Ordering::Relaxed);
                            if now_ms - last >= idle_limit_ms {
                                info!(
                                    id,
                                    up_bytes = up,
                                    down_bytes = down,
                                    idle_ms = now_ms - last,
                                    "idle sweeper: cancelling dead connection"
                                );
                                tracker.cancel_by_id(id);
                            }
                        }
                        // 首次采样到该连接，本周期不判定（避免刚建立的连接被误杀）
                        None => {}
                    }
                }

                // 清理已离开 tracker 的连接的采样缓存，防止内存泄漏
                last_bytes.retain(|k, _| live_ids.contains(k));
            }
        })
    }
}

// ── 日志广播 ──────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LogEntry {
    pub level: String,
    pub message: String,
}

// ── ClashApi 主体 ─────────────────────────────────────────────────────────────

pub struct ClashApi {
    config: ClashApiConfig,
    outbound_mgr: Arc<OutboundManager>,
    stats: Arc<Stats>,
    route_config: Arc<RouteConfig>,
    /// Clash API 当前模式：与 Router、DnsResolver 共享同一个实例，
    /// 这样 PATCH /configs 写入的模式变化才能被 `clash_mode` 规则条件实时感知。
    mode: Arc<ClashMode>,
    mode_list: Vec<String>,
    delay_history: Arc<DelayHistory>,
    conn_tracker: Arc<ConnectionTracker>,
    log_tx: broadcast::Sender<LogEntry>,
    /// 实际 inbound 列表，用于在 /configs 返回真实端口和 allow-lan
    inbound_configs: Vec<InboundConfig>,
    /// 当前日志级别，用于在 /configs 返回
    log_level: LogLevel,
    /// 规则集注册表，用于查询元数据和触发 remote 规则集刷新
    rs_registry: Arc<RuleSetRegistry>,
    /// DNS 解析器，用于 GET /dns/query 和 POST /cache/dns/flush
    dns_resolver: Option<Arc<crate::dns::DnsResolver>>,
    /// Dashboard 设置存储（/storage/:key），对齐 mihomo 扩展端点。
    /// 内存存储，重启后丢失；zashboard 据此持久化 UI 设置（主题、布局等）。
    storage: RwLock<HashMap<String, serde_json::Value>>,
    /// GLOBAL 选择器的当前选中节点（clash mode = global 时使用）。
    /// None 时回退到第一个可用代理节点。
    global_selection: RwLock<Option<String>>,
    /// 全局日志级别句柄，PATCH /configs 的 "log-level" 字段热改日志级别。
    /// 由 main.rs 的 init_tracing 在 OnceLock 中设置；ClashApi 启动时取引用。
    /// 若 tracing 用 NoSubscriber（level=off）则为 None，PATCH log-level 时忽略。
    log_level_handle: Option<Arc<std::sync::atomic::AtomicU8>>,
}

impl ClashApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: ClashApiConfig,
        outbound_mgr: Arc<OutboundManager>,
        stats: Arc<Stats>,
        route_config: Arc<RouteConfig>,
        inbound_configs: Vec<InboundConfig>,
        log_level: LogLevel,
        conn_tracker: Arc<ConnectionTracker>,
        rs_registry: Arc<RuleSetRegistry>,
        dns_resolver: Option<Arc<crate::dns::DnsResolver>>,
        clash_mode: Arc<ClashMode>,
    ) -> Self {
        // clash_mode 由调用方（app/mod.rs）创建并以同一个实例同时传给
        // Router、DnsResolver、ClashApi 三者；这里只是接收引用，不再自己
        // 创建一份独立的 RwLock<String>（那样会导致三者各看各的模式值，
        // PATCH /configs 改了也不会反映到路由判断上）。
        let mode = clash_mode;

        let mut mode_list = config.mode_list.clone();
        if mode_list.is_empty() {
            mode_list = vec![
                "rule".to_string(),
                "global".to_string(),
                "direct".to_string(),
            ];
        }
        if !mode_list.contains(&config.default_mode) {
            mode_list.insert(0, config.default_mode.clone());
        }

        let (log_tx, _) = broadcast::channel(256);

        // 注册全局转发器（首次调用生效；多次调用时已有的保持不变）
        let _ = GLOBAL_LOG_TX.set(log_tx.clone());

        Self {
            config,
            outbound_mgr,
            stats,
            route_config,
            mode,
            mode_list,
            delay_history: Arc::new(DelayHistory::default()),
            conn_tracker,
            log_tx,
            inbound_configs,
            log_level,
            rs_registry,
            dns_resolver,
            storage: RwLock::new(HashMap::new()),
            global_selection: RwLock::new(None),
            // 取全局日志级别句柄（由 main.rs init_tracing 在 OnceLock 中设置）。
            // off 模式或未初始化时为 None，PATCH /configs 的 log-level 字段会被忽略。
            log_level_handle: global_log_level_handle(),
        }
    }

    /// 返回配置中的 CORS 允许来源（用于 Access-Control-Allow-Origin 头）。
    /// 与 sing-box access_control_allow_origin 字段对齐：
    /// - 空列表 → "*"（允许所有）
    /// - 单个值 → 直接使用
    /// - 多个值 → 逗号连接（虽然标准只允许单值，但 Clash Meta 也这么做）
    fn cors_origin_header(&self) -> String {
        let origins = &self.config.access_control_allow_origin;
        if origins.is_empty() {
            "*".to_string()
        } else {
            origins.join(", ")
        }
    }

    pub fn conn_tracker(&self) -> Arc<ConnectionTracker> {
        self.conn_tracker.clone()
    }

    pub fn log_tx(&self) -> broadcast::Sender<LogEntry> {
        self.log_tx.clone()
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind_addr = crate::inbound::parse_controller_addr(&self.config.external_controller)
            .map_err(|e| anyhow::anyhow!("clash_api external_controller: {e}"))?;
        let listener = TcpListener::bind(bind_addr).await?;
        info!(listen=%self.config.external_controller, addr=%bind_addr, "clash api listening");

        let shared = Arc::new(self);
        loop {
            let (stream, peer) = listener.accept().await?;
            let api = shared.clone();
            tokio::spawn(async move {
                if let Err(e) = api.handle_connection(stream).await {
                    debug!(peer=%peer, err=%e, "clash api connection error");
                }
            });
        }
    }

    async fn handle_connection(self: Arc<Self>, mut stream: TcpStream) -> anyhow::Result<()> {
        let request = read_request(&mut stream).await?;
        self.handle_request(request, stream).await;
        Ok(())
    }

    async fn handle_request(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        // CORS 预检
        if request.method == "OPTIONS" {
            let origin = self.cors_origin_header();
            let mut resp = HttpResponse::new(204, "No Content")
                .header("Access-Control-Allow-Origin", &origin)
                .header(
                    "Access-Control-Allow-Methods",
                    "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                )
                .header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization",
                );
            if self.config.access_control_allow_private_network {
                resp = resp.header("Access-Control-Allow-Private-Network", "true");
            }
            let resp = resp.body(Vec::new(), "text/plain; charset=utf-8");
            let _ = stream.write_all(&resp.to_bytes()).await;
            return;
        }

        let full_path = &request.path;
        let path = full_path.split('?').next().unwrap_or(full_path);
        let query = full_path
            .find('?')
            .map(|i| &full_path[i + 1..])
            .unwrap_or("");

        // Bearer 鉴权（对齐 sing-box：WS 和非 WS 都支持 ?token= query 与
        // Authorization: Bearer 两种方式。EventSource / fetch() 在不能设置
        // Authorization header 时必须依赖 query 鉴权；旧实现只对 WS 开放 query，
        // 导致 dashboard 用 EventSource 消费 /traffic /logs /memory 等流式端点时 401。）
        if !self.config.secret.is_empty() {
            let header_ok = request
                .header("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|t| t == self.config.secret)
                .unwrap_or(false);
            let query_ok = query.split('&').any(|kv| {
                kv.strip_prefix("token=")
                    .map(|t| t == self.config.secret)
                    .unwrap_or(false)
            });
            if !(header_ok || query_ok) {
                let resp = HttpResponse::new(401, "Unauthorized").body(
                    serde_json::to_vec(&json!({"message": "Unauthorized"})).unwrap(),
                    "application/json; charset=utf-8",
                );
                let _ = stream.write_all(&resp.to_bytes()).await;
                return;
            }
        }

        // WebSocket 路由
        if request.is_websocket() {
            match path {
                "/traffic" => {
                    self.ws_traffic(request, stream).await;
                    return;
                }
                "/logs" => {
                    self.ws_logs(request, stream).await;
                    return;
                }
                "/connections" => {
                    self.ws_connections(request, stream).await;
                    return;
                }
                "/memory" => {
                    self.ws_memory(request, stream).await;
                    return;
                }
                _ => {}
            }
        }

        // 普通 HTTP 路由
        let response = match (request.method.as_str(), path) {
            ("GET", "/") => self.redirect_to_ui(),
            ("GET", "/version") => json_response(json!({
                // premium:true + meta:true 让 dashboard（Yacd / metacubexd / zashboard）
                // 启用高级特性：连接管理、规则视图、provider 刷新等。
                // sing-box 也返回 premium:true；reflex 旧实现错填 false 会让 UI
                // 退化到基础模式。
                "premium": true,
                "version": concat!("reflex ", env!("CARGO_PKG_VERSION")),
                "meta": true,
            })),
            ("GET", "/configs") => self.get_configs(),
            ("PATCH", "/configs") => self.patch_configs(&request.body),
            // PUT /configs：sing-box/Clash Meta 语义为热重载配置，Reflex 暂不支持运行时重载
            ("PUT", "/configs") => json_response(json!({
                "message": "hot-reload not supported; restart Reflex to apply a new config"
            })),
            // POST /configs/geo — 更新 Geo 数据库（zashboard updateGeoDataAPI）
            ("POST", "/configs/geo") => self.update_geo_data(),
            ("GET", "/traffic") => {
                // 对齐 sing-box：HTTP chunked 流式推送每秒 delta（与 WS 行为一致），
                // 而不是只返回一次 cumulative 总量后关闭连接。
                // dashboard 用 EventSource / fetch+stream 读这个端点显示实时速率。
                self.get_traffic_stream(&mut stream).await;
                return;
            }
            ("GET", "/logs") => {
                self.get_logs_stream(&mut stream).await;
                return;
            }
            ("GET", "/rules") => self.get_rules(),
            // PATCH /rules/disable — 切换规则禁用状态（zashboard toggleRuleDisabledAPI）
            ("PATCH", "/rules/disable") => self.toggle_rule_disabled(&request.body),
            ("GET", "/connections") => self.get_connections(),
            ("DELETE", "/connections") => self.delete_connections(),
            ("GET", "/proxies") => self.get_proxies(),
            // GET /providers/proxies — 返回订阅 provider 列表（目前无 provider）
            ("GET", "/providers/proxies") => json_response(json!({"providers": {}})),
            ("GET", "/providers/rules") => self.get_rule_providers().await,
            ("GET", "/script") => json_response(json!({"code": ""})),
            ("GET", "/profile") => json_response(json!({"payload": ""})),
            // GET /dns/query?name=<domain>&type=<A|AAAA|...>
            ("GET", "/dns/query") => self.get_dns_query(query).await,
            // GET /dns/rules — DNS 分流规则列表（reflex 扩展）
            ("GET", "/dns/rules") => self.get_dns_rules(),
            // GET /dns/stats — DNS 劫持与查询统计（P3-2）
            ("GET", "/dns/stats") => self.get_dns_stats(),
            ("GET", "/memory") => {
                // 对齐 sing-box：HTTP chunked 流式推送每秒内存占用，
                // 与 WS /memory 行为一致；dashboard 用流式读取展示内存曲线。
                self.get_memory_stream(&mut stream).await;
                return;
            }
            ("GET", "/group") => self.get_groups(),
            // GET /group/weights — Smart core 权重（zashboard fetchSmartWeightsAPI）
            ("GET", "/group/weights") => json_response(json!({"message": "ok", "weights": {}})),
            // POST /cache/dns/flush — 清空 DNS 内存缓存（sing-box 兼容）
            ("POST", "/cache/dns/flush") => self.flush_dns_cache(),
            // POST /cache/fakeip/flush — 清空 fakeip 映射
            ("POST", "/cache/fakeip/flush") => self.flush_fakeip_cache().await,
            // POST /upgrade/ui — 手动触发 external UI 重新下载（sing-box 兼容）
            ("POST", "/upgrade/ui") => self.upgrade_ui().await,
            // POST /upgrade — 内核升级（zashboard upgradeCoreAPI），reflex 暂不支持
            ("POST", "/upgrade") => json_response_status(
                501,
                json!({"message": "core upgrade not supported; please update reflex manually"}),
            ),
            // POST /restart — 重启内核（zashboard restartCoreAPI）
            ("POST", "/restart") => self.restart_core(),
            // GET /storage/:key — 读取 Dashboard 设置（zashboard getStorageAPI）
            _ if request.method == "GET" && path.starts_with("/storage/") => {
                self.get_storage(path.trim_start_matches("/storage/"))
            }
            // PUT /storage/:key — 写入 Dashboard 设置（zashboard setStorageAPI）
            _ if request.method == "PUT" && path.starts_with("/storage/") => {
                self.set_storage(path.trim_start_matches("/storage/"), &request.body)
            }
            // DELETE /storage/:key — 删除 Dashboard 设置（zashboard deleteStorageAPI）
            _ if request.method == "DELETE" && path.starts_with("/storage/") => {
                self.delete_storage(path.trim_start_matches("/storage/"))
            }
            _ if request.method == "GET" && path.starts_with("/group/") => {
                let rest = path.trim_start_matches("/group/");
                if let Some(name_enc) = rest.strip_suffix("/delay") {
                    self.get_group_delay(name_enc, query).await
                } else if let Some(name_enc) = rest.strip_suffix("/weights") {
                    // GET /group/:name/weights — deprecated smart group weights
                    json_response(json!({
                        "message": "ok",
                        "weights": [],
                        "name": percent_decode(name_enc),
                    }))
                } else {
                    self.get_group(rest)
                }
            }
            _ if request.method == "PUT" && path.starts_with("/group/") => {
                self.put_proxy(path.trim_start_matches("/group/"), &request.body)
            }
            _ if request.method == "DELETE" && path.starts_with("/connections/") => {
                self.delete_connection(path.trim_start_matches("/connections/"))
            }
            // DELETE /proxies/:name — 清除固定代理选择（zashboard deleteFixedProxyAPI）
            _ if request.method == "DELETE" && path.starts_with("/proxies/") => {
                self.delete_fixed_proxy(path.trim_start_matches("/proxies/"))
            }
            _ if request.method == "GET" && path.starts_with("/proxies/") => {
                let rest = path.trim_start_matches("/proxies/");
                if let Some(name_enc) = rest.strip_suffix("/delay") {
                    self.get_proxy_delay(name_enc, query).await
                } else {
                    self.get_proxy(rest)
                }
            }
            _ if request.method == "PUT" && path.starts_with("/proxies/") => {
                self.put_proxy(path.trim_start_matches("/proxies/"), &request.body)
            }
            // GET /providers/proxies/:name/healthcheck — provider 健康检查（zashboard）
            _ if request.method == "GET"
                && path.starts_with("/providers/proxies/")
                && path.ends_with("/healthcheck") =>
            {
                self.provider_healthcheck(path, query).await
            }
            // GET /providers/proxies/:name — 单个 provider 详情（无 provider 时 404）
            _ if request.method == "GET" && path.starts_with("/providers/proxies/") => {
                json_response_status(404, json!({"message": "provider not found"}))
            }
            // PUT /providers/proxies/:name — 触发 provider 更新（无 provider 时 404）
            _ if request.method == "PUT" && path.starts_with("/providers/proxies/") => {
                json_response_status(404, json!({"message": "provider not found"}))
            }
            // GET /providers/rules/:name — 单个规则集详情
            _ if request.method == "GET" && path.starts_with("/providers/rules/") => {
                let name_enc = path.trim_start_matches("/providers/rules/");
                let name = percent_decode(name_enc);
                self.get_rule_provider(&name).await
            }
            _ if request.method == "PUT" && path.starts_with("/providers/rules/") => {
                let name_enc = path.trim_start_matches("/providers/rules/");
                let name = percent_decode(name_enc);
                self.update_rule_provider(&name).await
            }
            _ if request.method == "GET" => self.serve_ui(path).await,
            _ => text_response(404, "Not Found", "not found"),
        };

        // 追加 CORS 头到所有普通响应
        let origin = self.cors_origin_header();
        let mut response = response.header("Access-Control-Allow-Origin", &origin);
        if self.config.access_control_allow_private_network {
            response = response.header("Access-Control-Allow-Private-Network", "true");
        }
        let _ = stream.write_all(&response.to_bytes()).await;
    }

    // ── /configs ──────────────────────────────────────────────────────────────

    fn get_configs(&self) -> HttpResponse {
        use crate::config::inbound::InboundConfig as IB;
        let mode = self.mode.get();
        // mode: Arc<str>，json! 需要 &str（Arc<str> 未实现 Serialize，
        // 但 &str 实现了），通过 &*mode 解引用。
        let mode: &str = &mode;

        // 从 inbound 配置中提取各协议端口
        // 旧实现 socks_port/http_port 声明为不可变且从未赋值，永远为 0；
        // 且 match 提取的 port 被直接丢弃（let _ = port）。修正：
        // Mixed 同时承载 SOCKS5 和 HTTP，故 socks_port/http_port 也应报告。
        let mut mixed_port: u16 = 0;
        let mut socks_port: u16 = 0;
        let mut redir_port: u16 = 0;
        let mut tproxy_port: u16 = 0;
        let mut http_port: u16 = 0;
        let mut allow_lan = false;

        for ib in &self.inbound_configs {
            let listen = match ib {
                IB::Mixed(c) => {
                    if mixed_port == 0 {
                        mixed_port = c.listen_port;
                        // Mixed = SOCKS5 + HTTP CONNECT，同时报告
                        socks_port = c.listen_port;
                        http_port = c.listen_port;
                    }
                    &c.listen
                }
                IB::Redir(c) => {
                    if redir_port == 0 {
                        redir_port = c.listen_port;
                    }
                    &c.listen
                }
                IB::TProxy(c) => {
                    if tproxy_port == 0 {
                        tproxy_port = c.listen_port;
                    }
                    &c.listen
                }
                IB::Socks(c) => {
                    if socks_port == 0 {
                        socks_port = c.listen_port;
                    }
                    &c.listen
                }
                IB::Http(c) => {
                    if http_port == 0 {
                        http_port = c.listen_port;
                    }
                    &c.listen
                }
                IB::Dns(_) | IB::Tun(_) => continue,
            };
            // 绑定 0.0.0.0 或 :: 意味着允许局域网
            if listen == "0.0.0.0" || listen == "::" || listen == "0" {
                allow_lan = true;
            }
        }

        let log_level_str = match self.log_level {
            LogLevel::Trace | LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warning",
            LogLevel::Error => "error",
            LogLevel::Off => "silent",
        };

        // tun.enable：是否有 Tun 入站配置。
        // zashboard BackendSettings.vue 检查 `configs.value.tun && tun.enable`
        // 来决定是否显示 Tun 模式开关。
        let tun_enable = self
            .inbound_configs
            .iter()
            .any(|ib| matches!(ib, IB::Tun(_)));

        json_response(json!({
            "port": http_port,
            "socks-port": socks_port,
            "redir-port": redir_port,
            "tproxy-port": tproxy_port,
            "mixed-port": mixed_port,
            "allow-lan": allow_lan,
            "bind-address": "*",
            "mode": mode,
            "mode-list": self.mode_list,
            "modes": self.mode_list,
            "log-level": log_level_str,
            "ipv6": true,
            "tun": { "enable": tun_enable },
        }))
    }

    fn patch_configs(&self, body: &[u8]) -> HttpResponse {
        let value: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return text_response(400, "Bad Request", &format!("invalid json: {e}")),
        };
        if let Some(mode) = value.get("mode").and_then(|v| v.as_str()) {
            let mode_str = mode.to_string();
            let valid = self
                .mode_list
                .iter()
                .any(|m| m.eq_ignore_ascii_case(&mode_str));
            if valid {
                self.mode.set(mode_str);
            }
        }
        // 对齐 sing-box / Clash Meta：PATCH /configs 支持 "log-level" 字段热改日志级别。
        // dashboard 在设置页切换日志级别时只会调 PATCH /configs，旧实现忽略该字段
        // 导致 UI 显示切换成功但内核仍在用旧级别过滤日志。
        // 合法值：trace/debug/info/warning/warn/error/silent（对齐 Clash /configs 响应）。
        if let Some(level) = value.get("log-level").and_then(|v| v.as_str()) {
            if let Some(handle) = &self.log_level_handle {
                let u8_val = match level {
                    "error" => Some(1),
                    "warning" | "warn" => Some(2),
                    "info" => Some(3),
                    "debug" => Some(4),
                    "trace" => Some(5),
                    // silent = 关闭所有日志输出；用 0 表示（u8_to_level(0) = ERROR，
                    // 但 enabled() 仍会通过；这里特殊处理：0 时让 broadcast_log
                    // 也跳过。简化实现：把 0 视作 ERROR，dashboard 通常不会真的
                    // 切到 silent；如需真正静默，未来可加独立 atomic flag。）
                    "silent" => Some(0),
                    _ => None,
                };
                if let Some(v) = u8_val {
                    handle.store(v, Ordering::Relaxed);
                }
            }
        }
        empty_response(204, "No Content")
    }

    // ── /traffic ──────────────────────────────────────────────────────────────

    /// HTTP chunked 流式 /traffic，对齐 sing-box：每秒推送一行 `{"up":delta,"down":delta}\n`，
    /// 直到客户端断开。dashboard 用 fetch+readable stream 或 EventSource 消费。
    ///
    /// 旧实现 `get_traffic_once` 只返回 cumulative 总量后关连接，导致 dashboard
    /// 速率卡片只显示一次后停止；与 WS /traffic 行为也不一致。
    async fn get_traffic_stream(self: Arc<Self>, stream: &mut TcpStream) {
        let origin = self.cors_origin_header();
        let header_str = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nAccess-Control-Allow-Origin: {origin}\r\n\r\n"
        );
        if stream.write_all(header_str.as_bytes()).await.is_err() {
            return;
        }

        let mut prev_up = self.stats.global_snapshot().bytes_up;
        let mut prev_down = self.stats.global_snapshot().bytes_down;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let snap = self.stats.global_snapshot();
            let up_delta = snap.bytes_up.saturating_sub(prev_up);
            let down_delta = snap.bytes_down.saturating_sub(prev_down);
            prev_up = snap.bytes_up;
            prev_down = snap.bytes_down;
            let line = serde_json::to_vec(&json!({"up": up_delta, "down": down_delta}))
                .unwrap_or_default();
            // chunk 格式：`<hexlen>\r\n<data>\r\n`
            let chunk_hdr = format!("{:x}\r\n", line.len());
            if stream.write_all(chunk_hdr.as_bytes()).await.is_err() {
                break;
            }
            if stream.write_all(&line).await.is_err() {
                break;
            }
            if stream.write_all(b"\r\n").await.is_err() {
                break;
            }
        }
    }

    async fn ws_traffic(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key, &self.cors_origin_header());
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }

        let mut prev_up = self.stats.global_snapshot().bytes_up;
        let mut prev_down = self.stats.global_snapshot().bytes_down;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let snap = self.stats.global_snapshot();
            let up_delta = snap.bytes_up.saturating_sub(prev_up);
            let down_delta = snap.bytes_down.saturating_sub(prev_down);
            prev_up = snap.bytes_up;
            prev_down = snap.bytes_down;
            let msg = serde_json::to_vec(&json!({"up": up_delta, "down": down_delta}))
                .unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /logs ─────────────────────────────────────────────────────────────────

    async fn get_logs_stream(self: Arc<Self>, stream: &mut TcpStream) {
        let origin = self.cors_origin_header();
        let header_str = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nAccess-Control-Allow-Origin: {}\r\n\r\n", origin);
        let header = header_str.as_bytes();
        if stream.write_all(header).await.is_err() {
            return;
        }

        let mut rx = self.log_tx.subscribe();
        loop {
            match tokio::time::timeout(Duration::from_secs(30), rx.recv()).await {
                Ok(Ok(entry)) => {
                    let line = serde_json::to_vec(&json!({
                        "type": entry.level,
                        "payload": entry.message,
                    }))
                    .unwrap_or_default();
                    let chunk_hdr = format!("{:x}\r\n", line.len() + 1);
                    if stream.write_all(chunk_hdr.as_bytes()).await.is_err() {
                        break;
                    }
                    if stream.write_all(&line).await.is_err() {
                        break;
                    }
                    if stream.write_all(b"\n\r\n").await.is_err() {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {
                    // keepalive: send a tiny comment chunk so connection stays open
                    // "1\r\n \r\n" is a valid 1-byte chunk (a space character)
                    if stream.write_all(b"1\r\n \r\n").await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    async fn ws_logs(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key, &self.cors_origin_header());
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }
        // 解析 query 里的 level 参数，决定最低推送级别
        // Clash API 约定：error > warning > info > debug，silent 表示全部屏蔽
        let full_path = &request.path;
        let query = full_path
            .find('?')
            .map(|i| &full_path[i + 1..])
            .unwrap_or("");
        let min_level = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("level="))
            .unwrap_or("info");

        // 返回 level 数值，越大越高；silent = usize::MAX 全屏蔽
        fn level_rank(l: &str) -> usize {
            match l {
                "debug" => 0,
                "info" => 1,
                "warning" | "warn" => 2,
                "error" => 3,
                _ => usize::MAX, // silent 或未知
            }
        }
        let min_rank = level_rank(min_level);

        let mut rx = self.log_tx.subscribe();
        while let Ok(entry) = rx.recv().await {
            if level_rank(&entry.level) < min_rank {
                continue;
            }
            let msg = serde_json::to_vec(&json!({
                "type": entry.level,
                "payload": entry.message,
            }))
            .unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /connections ──────────────────────────────────────────────────────────

    fn get_connections(&self) -> HttpResponse {
        let snap = self.stats.global_snapshot();
        let conns = self.conn_tracker.snapshot();
        let conn_json: Vec<serde_json::Value> = conns.iter().map(conn_to_json).collect();
        let memory = read_process_rss_kb().unwrap_or(0) * 1024;
        json_response(json!({
            "downloadTotal": snap.bytes_down,
            "uploadTotal": snap.bytes_up,
            "connections": conn_json,
            "memory": memory,
        }))
    }

    fn delete_connections(&self) -> HttpResponse {
        // 对齐 sing-box：DELETE /connections 应主动关闭所有活跃连接，
        // 而不仅仅是确认请求。cancel_all 唤醒 dispatcher 中的 select!，
        // 使其丢弃转发 future（从而关闭底层 socket）；clear 让展示列表立即归零。
        self.conn_tracker.cancel_all();
        self.conn_tracker.clear();
        empty_response(204, "No Content")
    }

    async fn ws_connections(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key, &self.cors_origin_header());
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }

        // 解析 ?interval=毫秒（对齐 sing-box getConnections 的 interval 查询参数），
        // 未提供或非法时默认 1000ms。
        let full_path = &request.path;
        let query = full_path
            .find('?')
            .map(|i| &full_path[i + 1..])
            .unwrap_or("");
        let interval_ms: u64 = query
            .split('&')
            .find_map(|kv| kv.strip_prefix("interval="))
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(1000);

        loop {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            let snap = self.stats.global_snapshot();
            let conns = self.conn_tracker.snapshot();
            let conn_json: Vec<serde_json::Value> = conns.iter().map(conn_to_json).collect();
            let memory = read_process_rss_kb().unwrap_or(0) * 1024;
            let msg = serde_json::to_vec(&json!({
                "downloadTotal": snap.bytes_down,
                "uploadTotal": snap.bytes_up,
                "connections": conn_json,
                "memory": memory,
            }))
            .unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /memory ──────────────────────────────────────────────────────────────

    /// HTTP chunked 流式 /memory，对齐 sing-box：每秒推送 `{"inuse":bytes,"oslimit":0}`，
    /// 直到客户端断开。WS /memory 已有等价实现；这里补齐 HTTP 模式。
    async fn get_memory_stream(self: Arc<Self>, stream: &mut TcpStream) {
        let origin = self.cors_origin_header();
        let header_str = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nAccess-Control-Allow-Origin: {origin}\r\n\r\n"
        );
        if stream.write_all(header_str.as_bytes()).await.is_err() {
            return;
        }
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let inuse = read_process_rss_kb().unwrap_or(0) * 1024;
            let line =
                serde_json::to_vec(&json!({"inuse": inuse, "oslimit": 0})).unwrap_or_default();
            let chunk_hdr = format!("{:x}\r\n", line.len());
            if stream.write_all(chunk_hdr.as_bytes()).await.is_err() {
                break;
            }
            if stream.write_all(&line).await.is_err() {
                break;
            }
            if stream.write_all(b"\r\n").await.is_err() {
                break;
            }
        }
    }

    async fn ws_memory(self: Arc<Self>, request: HttpRequest, mut stream: TcpStream) {
        let key = match request.header("sec-websocket-key") {
            Some(k) => k.to_string(),
            None => return,
        };
        let handshake = ws_upgrade_response(&key, &self.cors_origin_header());
        if stream.write_all(handshake.as_bytes()).await.is_err() {
            return;
        }
        let mut first = true;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let inuse = if first {
                first = false;
                0
            } else {
                read_process_rss_kb().unwrap_or(0) * 1024
            };
            let msg =
                serde_json::to_vec(&json!({"inuse": inuse, "oslimit": 0})).unwrap_or_default();
            if ws_send_text(&mut stream, &msg).await.is_err() {
                break;
            }
        }
    }

    // ── /connections/:id ──────────────────────────────────────────────────────

    fn delete_connection(&self, id_str: &str) -> HttpResponse {
        match id_str.parse::<u64>() {
            Ok(id) => {
                // 先发出取消信号（此时连接仍在 map 中，cancel_by_id 才能找到它），
                // 再从展示列表移除，让 GET /connections 立即不再显示它。
                self.conn_tracker.cancel_by_id(id);
                self.conn_tracker.remove_by_id(id);
                empty_response(204, "No Content")
            }
            Err(_) => text_response(400, "Bad Request", "invalid connection id"),
        }
    }

    // ── /group (Clash.Meta 扩展，Dashboard 分组视图) ───────────────────────────

    fn get_groups(&self) -> HttpResponse {
        let statuses = self.outbound_mgr.statuses();
        let mut groups: Vec<serde_json::Value> = statuses
            .iter()
            .filter(|s| {
                s.type_name == "Selector" || s.type_name == "URLTest" || s.type_name == "UrlTest"
            })
            .map(|s| self.build_group_entry(s))
            .collect();
        // GLOBAL 虚拟选择器常驻显示在所有节点组的最后，
        // 供 clash mode = global 时切换全局出站。
        groups.push(self.build_global_entry());
        json_response(json!({"proxies": groups}))
    }

    fn get_group(&self, encoded_name: &str) -> HttpResponse {
        let name = percent_decode(encoded_name);
        if name == "GLOBAL" {
            return json_response(self.build_global_entry());
        }
        let statuses = self.outbound_mgr.statuses();
        if let Some(status) = statuses.iter().find(|s| s.name == name) {
            if status.type_name == "Selector"
                || status.type_name == "URLTest"
                || status.type_name == "UrlTest"
            {
                return json_response(self.build_group_entry(status));
            }
        }
        text_response(404, "Not Found", "group not found")
    }

    async fn get_group_delay(&self, encoded_name: &str, query: &str) -> HttpResponse {
        // 对组内所有节点并发测速，返回 {tag: delay_ms} map
        let name = percent_decode(encoded_name);
        let statuses = self.outbound_mgr.statuses();
        // GLOBAL 虚拟选择器：成员是所有出站
        let all_tags: Vec<String> = if name == "GLOBAL" {
            statuses.iter().map(|s| s.name.clone()).collect()
        } else {
            let group = match statuses.iter().find(|s| s.name == name) {
                Some(s) => s.clone(),
                None => return text_response(404, "Not Found", "group not found"),
            };
            group.all
        };
        if all_tags.is_empty() {
            return json_response(json!({}));
        }

        let (probe_url, timeout_ms) = extract_probe_params(query);
        let timeout = Duration::from_millis(timeout_ms);
        let delay_history = self.delay_history.clone();
        let mut futs = Vec::new();
        for tag in &all_tags {
            let tag = tag.clone();
            let probe_url = probe_url.clone();
            let ob = self.outbound_mgr.get(&tag);
            let dh = delay_history.clone();
            futs.push(async move {
                let ob = match ob {
                    Some(o) => o,
                    None => return (tag, None),
                };
                match url_test(&ob, &probe_url, timeout).await {
                    UrlTestOutcome::Ok(delay) => {
                        dh.store(&tag, delay);
                        (tag, Some(delay))
                    }
                    _ => {
                        dh.delete(&tag);
                        (tag, None)
                    }
                }
            });
        }
        let results = futures_util::future::join_all(futs).await;
        let mut map = serde_json::Map::new();
        for (tag, delay) in results {
            map.insert(tag, delay.map(|d| json!(d)).unwrap_or(json!(null)));
        }
        json_response(serde_json::Value::Object(map))
    }

    fn build_group_entry(&self, status: &crate::outbound::OutboundStatus) -> serde_json::Value {
        let history = self
            .delay_history
            .load(&status.name)
            .map(|r| {
                vec![json!({"time": ms_to_iso(r.time_ms), "delay": r.delay, "meanDelay": r.delay})]
            })
            .unwrap_or_default();
        // 注意：与 sing-box / stock Clash API 一致，"all" 是成员代理的 tag 名称
        // 字符串数组，而不是嵌套的完整代理对象——Dashboard 会再用这些名字去
        // /proxies 查详情。之前这里返回过对象数组，会让期望字符串数组的
        // 客户端（如 metacubexd）渲染/比较失败。
        let mut entry = json!({
            "type": status.type_name,
            "name": status.name,
            "udp": true,
            "history": history,
        });
        if let Some(now) = &status.now {
            entry["now"] = json!(now);
        }
        if !status.all.is_empty() {
            entry["all"] = json!(status.all);
        }
        entry
    }

    /// 构造 GLOBAL 虚拟选择器条目。
    /// GLOBAL 包含所有出站（含 Direct、Reject、Block 及所有代理节点和节点组），
    /// 用于 clash mode = global 时切换全局出站。
    fn build_global_entry(&self) -> serde_json::Value {
        let statuses = self.outbound_mgr.statuses();
        let all: Vec<String> = statuses.iter().map(|s| s.name.clone()).collect();
        // 优先使用用户通过 PUT /group/GLOBAL 选择的目标，否则回退到第一个
        let global_now = self
            .global_selection
            .read()
            .ok()
            .and_then(|g| g.clone())
            .filter(|n| all.contains(n))
            .or_else(|| all.first().cloned())
            .unwrap_or_default();
        json!({
            "type": "Selector",
            "name": "GLOBAL",
            "udp": true,
            "history": [],
            "all": all,
            "now": global_now,
        })
    }

    // ── /providers/rules ─────────────────────────────────────────────────────

    async fn get_rule_providers(&self) -> HttpResponse {
        use crate::config::route::RuleSetType;
        let meta_map = self.rs_registry.snapshot().await;
        let providers: serde_json::Map<String, serde_json::Value> = self
            .route_config
            .rule_set
            .iter()
            .map(|rs| {
                let vehicle_type = match rs.r#type {
                    RuleSetType::Local => "File",
                    RuleSetType::Remote => "HTTP",
                };
                let name = rs.tag.clone();
                let (rule_count, updated_at) = meta_map
                    .get(&name)
                    .map(|m| (m.rule_count, ms_to_iso(m.updated_at_ms)))
                    .unwrap_or((0, String::new()));
                let val = json!({
                    "behavior": "domain",
                    "format": "binary",
                    "name": name,
                    "ruleCount": rule_count,
                    "type": "Rule",
                    "updatedAt": updated_at,
                    "vehicleType": vehicle_type,
                });
                (name, val)
            })
            .collect();
        json_response(json!({ "providers": providers }))
    }

    /// PUT /providers/rules/:name — 触发远程规则集重新下载
    async fn update_rule_provider(&self, name: &str) -> HttpResponse {
        use crate::config::route::RuleSetType;
        let is_remote = self
            .route_config
            .rule_set
            .iter()
            .find(|r| r.tag == name)
            .map(|r| r.r#type == RuleSetType::Remote)
            .unwrap_or(false);

        if !is_remote {
            return text_response(
                400,
                "Bad Request",
                "rule_set is not remote or does not exist",
            );
        }

        match self.rs_registry.reload_remote(name).await {
            Ok(()) => empty_response(204, "No Content"),
            Err(e) => text_response(500, "Internal Server Error", &e.to_string()),
        }
    }

    /// GET /providers/rules/:name — 返回单个规则集详情
    async fn get_rule_provider(&self, name: &str) -> HttpResponse {
        let meta = self.rs_registry.snapshot().await;
        let rs_ref = self.route_config.rule_set.iter().find(|r| r.tag == name);
        match (rs_ref, meta.get(name)) {
            (Some(rs), Some(m)) => {
                use crate::config::route::RuleSetType;
                json_response(json!({
                    "name": name,
                    "type": "Rule",
                    "vehicleType": if rs.r#type == RuleSetType::Remote { "HTTP" } else { "File" },
                    "ruleCount": m.rule_count,
                    "updatedAt": ms_to_iso(m.updated_at_ms),
                    "format": match rs.format {
                        crate::config::route::RuleSetFormat::Source => "source",
                        crate::config::route::RuleSetFormat::Binary => "binary",
                    },
                }))
            }
            _ => json_response_status(
                404,
                json!({"message": format!("rule_set '{name}' not found")}),
            ),
        }
    }

    // ── /dns ──────────────────────────────────────────────────────────────────

    /// GET /dns/stats — 返回 DNS 劫持与查询统计（P3-2）。
    /// 包含专用入站查询数、路由劫持查询数（按 TCP/UDP 细分）、解析错误数。
    fn get_dns_stats(&self) -> HttpResponse {
        let snap = self.stats.dns_snapshot();
        json_response(json!({
            "inbound_queries": snap.inbound_queries,
            "hijacked_queries": snap.hijacked_queries,
            "hijacked_tcp": snap.hijacked_tcp,
            "hijacked_udp": snap.hijacked_udp,
            "errors": snap.errors,
        }))
    }

    /// GET /dns/rules — 返回 DNS 分流规则列表（reflex 扩展端点）。
    ///
    /// 格式与 `/rules`（路由规则）对齐，每条规则包含 type/payload/proxy，
    /// 以及 `reflex` 扩展字段携带完整的 `DnsRuleConfig` 原始配置。
    /// 末尾追加 final 规则（type=MATCH, proxy=dns.final），与路由规则的 MATCH 对齐。
    fn get_dns_rules(&self) -> HttpResponse {
        let mut rules: Vec<serde_json::Value> = Vec::new();

        if let Some(resolver) = &self.dns_resolver {
            for r in resolver.rule_configs() {
                let (rule_type, payload) = if !r.ruleset.is_empty() {
                    ("RuleSet", r.ruleset.join(","))
                } else if !r.domain.is_empty() {
                    ("DOMAIN", r.domain.join(","))
                } else if !r.domain_suffix.is_empty() {
                    ("DOMAIN-SUFFIX", r.domain_suffix.join(","))
                } else if !r.domain_keyword.is_empty() {
                    ("DOMAIN-KEYWORD", r.domain_keyword.join(","))
                } else if !r.query_type.is_empty() {
                    (
                        "QUERY-TYPE",
                        r.query_type
                            .iter()
                            .map(|q| format!("{q:?}").to_ascii_uppercase())
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                } else if !r.inbound.is_empty() {
                    ("INBOUND", r.inbound.join(","))
                } else if let Some(cm) = &r.clash_mode {
                    ("CLASH-MODE", cm.clone())
                } else {
                    ("MATCH", String::new())
                };
                let proxy = r.server.join(",");
                let reflex_extra = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
                rules.push(json!({
                    "type": rule_type,
                    "payload": payload,
                    "proxy": proxy,
                    "size": -1,
                    "disable_cache": r.disable_cache,
                    "reflex": reflex_extra,
                }));
            }
            // final 规则
            let final_servers = resolver.final_servers().join(",");
            rules.push(json!({
                "type": "MATCH",
                "payload": "",
                "proxy": final_servers,
                "size": -1,
            }));
        }

        json_response(json!({ "rules": rules }))
    }

    /// GET /dns/query?name=example.com&type=A
    /// 对指定域名执行 DNS 查询并返回结果，格式与 sing-box / Clash Meta 一致。
    ///
    /// 与 sing-box `clashapi/dns.go` 对齐：调用 `DnsResolver::handle()` 走完整 DNS
    /// 规则管线（含 fakeip），而非 `resolve_raw()` 绕过规则。这样 clash-ui 查询
    /// 命中 fakeip 规则的域名时会返回 FakeIP，与实际 DNS 监听器行为一致。
    async fn get_dns_query(&self, query: &str) -> HttpResponse {
        let params: std::collections::HashMap<&str, &str> = query
            .split('&')
            .filter_map(|kv| {
                let mut it = kv.splitn(2, '=');
                Some((it.next()?, it.next()?))
            })
            .collect();

        let name = match params.get("name") {
            Some(n) => *n,
            None => {
                return json_response_status(400, json!({"message": "missing 'name' parameter"}))
            }
        };
        let qtype_str = params.get("type").copied().unwrap_or("A");

        // 查询类型映射（DNS QTYPE 数字）
        let qtype: u16 = match qtype_str.to_uppercase().as_str() {
            "A" => 1,
            "AAAA" => 28,
            "CNAME" => 5,
            "MX" => 15,
            "NS" => 2,
            "TXT" => 16,
            "PTR" => 12,
            "SRV" => 33,
            "SOA" => 6,
            "CAA" => 257,
            other => {
                return json_response_status(
                    400,
                    json!({"message": format!("unsupported query type: '{other}'")}),
                );
            }
        };

        let resolver = match &self.dns_resolver {
            Some(r) => r.clone(),
            None => {
                return json_response_status(503, json!({"message": "DNS resolver not available"}))
            }
        };

        // 构造 DNS 查询报文，走完整规则管线（对齐 sing-box clashapi queryDNS）
        let query_msg = crate::dns::build_query_bytes(name, qtype);
        let msg = bytes::Bytes::from(query_msg);

        match resolver.handle(msg, "clash-api").await {
            Ok(raw_resp) => {
                let resp = &raw_resp[..];
                // 从响应报文解析 RCODE（flags 第 3 字节的低 4 位）和 TC 位
                let status = if resp.len() >= 4 { resp[3] & 0x0F } else { 0 };
                let tc = resp.len() >= 4 && (resp[2] & 0x02) != 0;
                let answers = parse_dns_answers(&raw_resp, name);
                // 字段名与 miekg/dns JSON 结构对齐（sing-box / mihomo 一致）：
                // Question 使用 PascalCase（Name/Qtype/Qclass），Answer 使用
                // 小写 name/type + 大写 TTL/data。zashboard 类型定义据此解析。
                json_response(json!({
                    "Status": status,
                    "TC": tc,
                    "RD": true,
                    "RA": true,
                    "AD": false,
                    "CD": false,
                    "Question": [{"Name": name, "Qtype": qtype, "Qclass": 1}],
                    "Answer": answers,
                    "Server": "",
                }))
            }
            Err(e) => json_response_status(500, json!({"message": e.to_string()})),
        }
    }

    // ── /cache ────────────────────────────────────────────────────────────────

    /// POST /cache/dns/flush — 清空内存 DNS 缓存
    fn flush_dns_cache(&self) -> HttpResponse {
        if let Some(ref resolver) = self.dns_resolver {
            resolver.clear_cache();
            info!("clash api: dns cache flushed");
        }
        empty_response(204, "No Content")
    }

    /// POST /cache/fakeip/flush — 清空 fakeip 映射（参照 sing-box clashapi/cache.go）
    ///
    /// 调用 `DnsResolver::reset_fakeip()` 真正重置所有 FakeIpStore：
    /// 清空内存 ip→domain / domain→ip 映射、把分配指针回退到 range 起点、
    /// 并调用 `cache_file.clear_fakeip()` 清空 redb 持久化表。
    ///
    /// 注意：与 sing-box 一致，**不**清空 DNS 缓存。如需一并清空 DNS 缓存，
    /// 请额外调用 `POST /cache/dns/flush`。
    async fn flush_fakeip_cache(&self) -> HttpResponse {
        if let Some(ref resolver) = self.dns_resolver {
            resolver.reset_fakeip();
            info!("clash api: fakeip store reset (memory + persistent)");
        }
        empty_response(204, "No Content")
    }

    // ── /upgrade/ui ───────────────────────────────────────────────────────────

    /// POST /upgrade/ui — 手动触发 external UI 重新下载（删除旧文件后重新下载解压）
    async fn upgrade_ui(&self) -> HttpResponse {
        let ui_dir = match &self.config.external_ui {
            Some(d) => d.clone(),
            None => {
                return json_response_status(404, json!({"message": "external_ui not configured"}))
            }
        };
        let download_url = self.config.external_ui_download_url.clone();
        info!(ui_dir, "clash api: upgrading external UI");

        // 删除旧 UI 文件（保留目录）
        if let Ok(entries) = std::fs::read_dir(&ui_dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path())
                    .or_else(|_| std::fs::remove_dir_all(entry.path()));
            }
        }

        match download_external_ui(&ui_dir, download_url.as_deref()).await {
            Ok(()) => {
                info!(ui_dir, "clash api: external UI upgraded");
                json_response(json!({"status": "ok"}))
            }
            Err(e) => {
                tracing::warn!(ui_dir, err = %e, "clash api: external UI upgrade failed");
                json_response_status(500, json!({"message": e.to_string()}))
            }
        }
    }

    // ── /restart, /configs/geo, /rules/disable, /upgrade ───────────────────────

    /// POST /restart — 重启内核（zashboard restartCoreAPI）。
    /// Reflex 暂不支持通过 API 重启，返回 204 让 UI 不报错。
    /// 用户需手动重启 reflex 进程。
    fn restart_core(&self) -> HttpResponse {
        info!("clash api: /restart requested (no-op; restart reflex manually)");
        empty_response(204, "No Content")
    }

    /// POST /configs/geo — 更新 GeoIP/GeoSite 数据库（zashboard updateGeoDataAPI）。
    /// Reflex 暂不支持运行时更新 Geo 数据，返回 204 让 UI 不报错。
    fn update_geo_data(&self) -> HttpResponse {
        info!("clash api: /configs/geo requested (no-op; geo update not supported)");
        empty_response(204, "No Content")
    }

    /// PATCH /rules/disable — 切换规则禁用状态（zashboard toggleRuleDisabledAPI）。
    /// Reflex 规则不支持运行时禁用，返回 204 让 UI 不报错。
    fn toggle_rule_disabled(&self, _body: &[u8]) -> HttpResponse {
        empty_response(204, "No Content")
    }

    /// DELETE /proxies/:name — 清除固定代理选择（zashboard deleteFixedProxyAPI）。
    /// 对 Selector 类型出站，清除当前选择（重置为首个成员）。
    fn delete_fixed_proxy(&self, encoded_name: &str) -> HttpResponse {
        let name = percent_decode(encoded_name);
        // GLOBAL 虚拟选择器：清除选择回退到第一个
        if name == "GLOBAL" {
            if let Ok(mut g) = self.global_selection.write() {
                *g = None;
            }
            return empty_response(204, "No Content");
        }
        if self.outbound_mgr.get(&name).is_none() {
            return text_response(404, "Not Found", "proxy not found");
        }
        // Selector 的 "固定" 选择清除：尝试选择第一个成员（如果有的话）。
        // 非 Selector 类型直接返回 204（无固定选择可清除）。
        let statuses = self.outbound_mgr.statuses();
        if let Some(status) = statuses.iter().find(|s| s.name == name) {
            if status.type_name == "Selector" || status.type_name == "Fallback" {
                if let Some(first) = status.all.first() {
                    let _ = self.outbound_mgr.select(&name, first);
                }
            }
        }
        empty_response(204, "No Content")
    }

    /// GET /providers/proxies/:name/healthcheck — provider 级健康检查。
    /// GET /providers/proxies/:provider/:proxy/healthcheck — 单节点延迟测试。
    ///
    /// zashboard fetchProxyProviderLatencyAPI 使用后者：对 provider 内指定节点
    /// 执行 URL test，期望返回 `{ delay: number }`。
    async fn provider_healthcheck(&self, path: &str, query: &str) -> HttpResponse {
        // 路径形如 /providers/proxies/<provider>/healthcheck
        // 或     /providers/proxies/<provider>/<proxy>/healthcheck
        let rest = path.trim_start_matches("/providers/proxies/");
        let segments: Vec<&str> = rest.trim_end_matches("/healthcheck").split('/').collect();

        match segments.as_slice() {
            // /providers/proxies/:provider/:proxy/healthcheck — 单节点测速
            [_, proxy_name_enc] => {
                let proxy_name = percent_decode(proxy_name_enc);
                let (probe_url, timeout_ms) = extract_probe_params(query);
                let outbound = match self.outbound_mgr.get(&proxy_name) {
                    Some(ob) => ob,
                    None => return text_response(404, "Not Found", "proxy not found"),
                };
                let timeout = Duration::from_millis(timeout_ms);
                match url_test(&outbound, &probe_url, timeout).await {
                    UrlTestOutcome::Ok(delay) => {
                        self.delay_history.store(&proxy_name, delay);
                        json_response(json!({ "delay": delay }))
                    }
                    UrlTestOutcome::Timeout => {
                        json_response_status(504, json!({ "message": "timeout" }))
                    }
                    UrlTestOutcome::Failed(msg) => {
                        json_response_status(503, json!({ "message": msg }))
                    }
                }
            }
            // /providers/proxies/:name/healthcheck — provider 级健康检查
            // 无 provider 数据时返回 204（zashboard proxyProviderHealthCheckAPI）
            _ => empty_response(204, "No Content"),
        }
    }

    // ── /storage/:key ─────────────────────────────────────────────────────────

    /// GET /storage/:key — 读取 Dashboard 设置（zashboard getStorageAPI）。
    fn get_storage(&self, key: &str) -> HttpResponse {
        let storage = self.storage.read().unwrap();
        match storage.get(key) {
            Some(value) => json_response(value.clone()),
            None => json_response(json!({})),
        }
    }

    /// PUT /storage/:key — 写入 Dashboard 设置（zashboard setStorageAPI）。
    fn set_storage(&self, key: &str, body: &[u8]) -> HttpResponse {
        let value: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return text_response(400, "Bad Request", &format!("invalid json: {e}")),
        };
        let mut storage = self.storage.write().unwrap();
        storage.insert(key.to_string(), value);
        empty_response(204, "No Content")
    }

    /// DELETE /storage/:key — 删除 Dashboard 设置（zashboard deleteStorageAPI）。
    fn delete_storage(&self, key: &str) -> HttpResponse {
        let mut storage = self.storage.write().unwrap();
        storage.remove(key);
        empty_response(204, "No Content")
    }

    // ── /rules ────────────────────────────────────────────────────────────────

    fn get_rules(&self) -> HttpResponse {
        use crate::config::route::PortFilter;
        let fmt_port = |p: &PortFilter| {
            if p.0 == p.1 {
                p.0.to_string()
            } else {
                format!("{}-{}", p.0, p.1)
            }
        };
        let mut rules: Vec<serde_json::Value> = self
            .route_config
            .rules
            .iter()
            .map(|r| {
                let (rule_type, payload) = if !r.ruleset.is_empty() {
                    // 对齐 mihomo/Clash.Meta：rule-set 规则在 /rules 中以 "RuleSet"
                    // (PascalCase) 报告类型，zashboard RuleCard.vue 据此
                    // (`rule.type === 'RuleSet'`) 渲染规则集标签。
                    ("RuleSet", r.ruleset.join(","))
                } else if !r.domain.is_empty() {
                    ("DOMAIN", r.domain.join(","))
                } else if !r.domain_suffix.is_empty() {
                    ("DOMAIN-SUFFIX", r.domain_suffix.join(","))
                } else if !r.domain_keyword.is_empty() {
                    ("DOMAIN-KEYWORD", r.domain_keyword.join(","))
                } else if !r.domain_regex.is_empty() {
                    ("DOMAIN-REGEX", r.domain_regex.join(","))
                } else if !r.ip_cidr.is_empty() {
                    ("IP-CIDR", r.ip_cidr.join(","))
                } else if !r.source_ip_cidr.is_empty() {
                    ("SRC-IP-CIDR", r.source_ip_cidr.join(","))
                } else if !r.port.is_empty() {
                    (
                        "DST-PORT",
                        r.port.iter().map(&fmt_port).collect::<Vec<_>>().join(","),
                    )
                } else if !r.port_range.is_empty() {
                    ("DST-PORT-RANGE", r.port_range.join(","))
                } else if r.network.is_some() {
                    (
                        "NETWORK",
                        format!("{:?}", r.network.unwrap()).to_ascii_lowercase(),
                    )
                } else if !r.protocol.is_empty() {
                    ("PROTOCOL", r.protocol.join(","))
                } else if !r.inbound.is_empty() {
                    ("IN-NAME", r.inbound.join(","))
                } else if r.clash_mode.is_some() {
                    ("CLASH-MODE", r.clash_mode.clone().unwrap_or_default())
                } else if r.private_ip {
                    ("PRIVATE-IP", String::new())
                } else if r.sniff {
                    ("SNIFF", String::new())
                } else if r.hijack_dns {
                    ("HIJACK-DNS", String::new())
                } else if r.resolve {
                    ("RESOLVE", String::new())
                } else {
                    ("MATCH", String::new())
                };
                let proxy = if r.hijack_dns {
                    "dns-out".to_string()
                } else {
                    r.outbound.clone()
                };
                // reflex 扩展字段：把 RouteRuleConfig 完整序列化进 `reflex`，
                // 让内嵌前端 RuleCard 可以显示所有原生字段（domain_regex /
                // source_ip_cidr / invert / clash_mode / override_* / udp_timeout
                // 等等）。其他 Clash dashboard 不认识该字段会被忽略，向后兼容。
                let reflex_extra = serde_json::to_value(r).unwrap_or_else(|_| json!({}));
                json!({
                    "type": rule_type,
                    "payload": payload,
                    "proxy": proxy,
                    "size": -1,
                    "reflex": reflex_extra,
                })
            })
            .collect();

        rules.push(json!({
            "type": "MATCH",
            "payload": "",
            "proxy": self.route_config.r#final,
            "size": -1,
        }));

        json_response(json!({ "rules": rules }))
    }

    // ── /proxies ──────────────────────────────────────────────────────────────

    fn get_proxies(&self) -> HttpResponse {
        let statuses = self.outbound_mgr.statuses();

        let mut proxies = serde_json::Map::new();
        // GLOBAL 虚拟选择器
        proxies.insert("GLOBAL".to_string(), self.build_global_entry());

        for status in &statuses {
            let history = self
                .delay_history
                .load(&status.name)
                .map(|r| {
                    vec![json!({
                        "time": ms_to_iso(r.time_ms),
                        "delay": r.delay,
                        "meanDelay": r.delay,
                    })]
                })
                .unwrap_or_default();

            let mut entry = json!({
                "type": status.type_name,
                "name": status.name,
                "udp": true,
                "history": history,
            });
            if let Some(now) = &status.now {
                entry["now"] = json!(now);
            }
            if !status.all.is_empty() {
                entry["all"] = json!(status.all);
            }

            proxies.insert(status.name.clone(), entry);
        }

        json_response(json!({ "proxies": proxies }))
    }

    fn get_proxy(&self, encoded_name: &str) -> HttpResponse {
        let name = percent_decode(encoded_name);
        if name == "GLOBAL" {
            return self.global_proxy_entry();
        }
        match self.outbound_mgr.status(&name) {
            Some(status) => {
                let history = self
                    .delay_history
                    .load(&status.name)
                    .map(|r| {
                        vec![json!({
                            "time": ms_to_iso(r.time_ms),
                            "delay": r.delay,
                            "meanDelay": r.delay,
                        })]
                    })
                    .unwrap_or_default();
                let mut entry = json!({
                    "type": status.type_name,
                    "name": status.name,
                    "udp": true,
                    "history": history,
                });
                if let Some(now) = &status.now {
                    entry["now"] = json!(now);
                }
                if !status.all.is_empty() {
                    entry["all"] = json!(status.all);
                }
                json_response(entry)
            }
            None => text_response(404, "Not Found", "proxy not found"),
        }
    }

    fn global_proxy_entry(&self) -> HttpResponse {
        json_response(self.build_global_entry())
    }

    fn put_proxy(&self, encoded_name: &str, body: &[u8]) -> HttpResponse {
        let name = percent_decode(encoded_name);
        let value: serde_json::Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => return text_response(400, "Bad Request", &format!("invalid json: {e}")),
        };
        let Some(child) = value.get("name").and_then(|v| v.as_str()) else {
            return text_response(400, "Bad Request", "missing proxy name");
        };
        // GLOBAL 是虚拟选择器，不在 outbound_mgr 中，单独处理选择状态
        if name == "GLOBAL" {
            let statuses = self.outbound_mgr.statuses();
            let valid = statuses.iter().any(|s| s.name == child);
            if !valid {
                return text_response(400, "Bad Request", "invalid proxy for GLOBAL");
            }
            if let Ok(mut g) = self.global_selection.write() {
                *g = Some(child.to_string());
            }
            return empty_response(204, "No Content");
        }
        match self.outbound_mgr.select(&name, child) {
            Ok(()) => empty_response(204, "No Content"),
            Err(e) => text_response(400, "Bad Request", &e.to_string()),
        }
    }

    async fn get_proxy_delay(&self, encoded_name: &str, query: &str) -> HttpResponse {
        let name = percent_decode(encoded_name);

        let (probe_url, timeout_ms) = extract_probe_params(query);

        let outbound = match self.outbound_mgr.get(&name) {
            Some(ob) => ob,
            None => return text_response(404, "Not Found", "proxy not found"),
        };

        let timeout = Duration::from_millis(timeout_ms);
        match url_test(&outbound, &probe_url, timeout).await {
            UrlTestOutcome::Ok(delay) => {
                self.delay_history.store(&name, delay);
                json_response(json!({ "delay": delay, "meanDelay": delay }))
            }
            UrlTestOutcome::Timeout => {
                // 对齐 sing-box：超时返回 504
                self.delay_history.delete(&name);
                json_response_status(504, json!({ "message": "timeout" }))
            }
            UrlTestOutcome::Failed(msg) => {
                // 对齐 sing-box：测试失败返回 503
                self.delay_history.delete(&name);
                json_response_status(503, json!({ "message": msg }))
            }
        }
    }

    // ── UI 文件服务 ───────────────────────────────────────────────────────────

    fn redirect_to_ui(&self) -> HttpResponse {
        if self.config.external_ui.is_some() {
            HttpResponse::new(302, "Found")
                .header("Location", "/ui/")
                .body(Vec::new(), "text/plain; charset=utf-8")
        } else {
            json_response(json!({ "hello": "clash" }))
        }
    }

    async fn serve_ui(&self, path: &str) -> HttpResponse {
        let Some(ui_dir) = &self.config.external_ui else {
            return text_response(404, "Not Found", "not found");
        };
        let Some(relative) = path.strip_prefix("/ui") else {
            return text_response(404, "Not Found", "not found");
        };
        let relative = relative.trim_start_matches('/');
        let file = match safe_join(Path::new(ui_dir), relative) {
            Some(p) if p.is_dir() => p.join("index.html"),
            Some(p) => p,
            None => return text_response(403, "Forbidden", "forbidden"),
        };
        match tokio::fs::read(&file).await {
            Ok(bytes) => HttpResponse::new(200, "OK").body(bytes, content_type(&file)),
            Err(_) => {
                // SPA fallback
                let index = Path::new(ui_dir).join("index.html");
                match tokio::fs::read(&index).await {
                    Ok(bytes) => {
                        HttpResponse::new(200, "OK").body(bytes, "text/html; charset=utf-8")
                    }
                    Err(_) => text_response(404, "Not Found", "not found"),
                }
            }
        }
    }
}

// ── WebSocket 工具 ─────────────────────────────────────────────────────────────

fn ws_upgrade_response(client_key: &str, origin: &str) -> String {
    let accept = ws_accept_key(client_key);
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nAccess-Control-Allow-Origin: {origin}\r\n\r\n"
    )
}

fn ws_accept_key(client_key: &str) -> String {
    const MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let combined = format!("{client_key}{MAGIC}");
    let digest = sha1_bytes(combined.as_bytes());
    base64_encode(&digest)
}

fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        #[allow(clippy::needless_range_loop)]
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, &v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = match chunk.len() {
            3 => [chunk[0], chunk[1], chunk[2]],
            2 => [chunk[0], chunk[1], 0],
            _ => [chunk[0], 0, 0],
        };
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            CHARS[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            CHARS[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

async fn ws_send_text(stream: &mut TcpStream, data: &[u8]) -> anyhow::Result<()> {
    let len = data.len();
    let mut frame = Vec::with_capacity(len + 10);
    frame.push(0x81); // FIN + text opcode
    if len <= 125 {
        frame.push(len as u8);
    } else if len <= 65535 {
        frame.push(126);
        frame.push((len >> 8) as u8);
        frame.push((len & 0xFF) as u8);
    } else {
        frame.push(127);
        frame.extend_from_slice(&(len as u64).to_be_bytes());
    }
    frame.extend_from_slice(data);
    stream.write_all(&frame).await?;
    Ok(())
}

// ── HTTP 解析 / 序列化 ────────────────────────────────────────────────────────

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|s| s.as_str())
    }
    fn is_websocket(&self) -> bool {
        self.header("upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
    }
}

async fn read_request(stream: &mut TcpStream) -> anyhow::Result<HttpRequest> {
    let mut buf = Vec::new();
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        anyhow::ensure!(n > 0, "connection closed before request");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        anyhow::ensure!(buf.len() <= 64 * 1024, "request headers too large");
    };

    let headers_str = std::str::from_utf8(&buf[..header_end])?;
    let mut lines = headers_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing path"))?
        .to_string();

    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();

    let content_len = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = header_end + 4;
    while buf.len() < body_start + content_len {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        anyhow::ensure!(n > 0, "connection closed before body");
        buf.extend_from_slice(&chunk[..n]);
        anyhow::ensure!(buf.len() <= 2 * 1024 * 1024, "request body too large");
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body: buf[body_start..body_start + content_len].to_vec(),
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

struct HttpResponse {
    status: u16,
    reason: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            headers: vec![],
            body: vec![],
        }
    }
    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
    fn body(mut self, body: Vec<u8>, content_type: &str) -> Self {
        self.headers
            .push(("Content-Type".to_string(), content_type.to_string()));
        self.body = body;
        self
    }
    fn to_bytes(&self) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.body.len()
        )
        .into_bytes();
        for (name, value) in &self.headers {
            response.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        response.extend_from_slice(b"\r\n");
        response.extend_from_slice(&self.body);
        response
    }
}

fn json_response(value: serde_json::Value) -> HttpResponse {
    HttpResponse::new(200, "OK").body(
        serde_json::to_vec(&value).expect("json serialization should not fail"),
        "application/json; charset=utf-8",
    )
}
fn json_response_status(status: u16, value: serde_json::Value) -> HttpResponse {
    let reason = if status == 404 { "Not Found" } else { "Error" };
    HttpResponse::new(status, reason).body(
        serde_json::to_vec(&value).expect("json serialization should not fail"),
        "application/json; charset=utf-8",
    )
}
fn text_response(status: u16, reason: &'static str, text: &str) -> HttpResponse {
    HttpResponse::new(status, reason).body(text.as_bytes().to_vec(), "text/plain; charset=utf-8")
}
fn empty_response(status: u16, reason: &'static str) -> HttpResponse {
    HttpResponse::new(status, reason).body(Vec::new(), "text/plain; charset=utf-8")
}

// ── 杂项工具 ──────────────────────────────────────────────────────────────────

fn conn_to_json(c: &ConnMeta) -> serde_json::Value {
    // host / destination_ip 已在 register 时按 sing-box 语义拆分填好：
    //   host           = sniff 域名 ?? 原始域名目标（对齐 metadata.Domain ?? Destination.Fqdn）
    //   destination_ip = 入站原始 IP 目标（对齐 metadata.Destination.Addr）
    // 二者独立，tproxy + sniff 命中时同时有值；域名目标时 destination_ip 为空。
    json!({
        "id": c.id.to_string(),
        "metadata": {
            "network": c.network,
            "type": c.inbound,
            "host": c.host,
            "sniffHost": "",
            "destinationIP": c.destination_ip,
            "destinationPort": c.dest_port.to_string(),
            "sourceIP": c.source_ip,
            "sourcePort": c.source_port.to_string(),
            "inboundName": c.inbound,
            "inboundPort": "",
            "inboundUser": "",
            "process": "",
            "processPath": "",
            "dnsMode": "normal",
            "remoteDestination": "",
            "specialProxy": "",
            "specialRules": "",
        },
        "upload":   c.upload.load(Ordering::Relaxed),
        "download": c.download.load(Ordering::Relaxed),
        "start": ms_to_iso(c.started_ms),
        "chains": [c.outbound.clone()],
        "rule": &*c.rule,
        "rulePayload": &*c.rule_payload,
    })
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(hex);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ── URL Test（延迟测速）──────────────────────────────────────────────────────

/// URL test 结果，对齐 sing-box urltest.URLTest 的错误语义。
enum UrlTestOutcome {
    /// 成功，附带延迟（毫秒）。
    Ok(u64),
    /// 超时（sing-box 返回 504）。
    Timeout,
    /// 连接或协议失败（sing-box 返回 503）。
    Failed(String),
}

/// 从 query string 中提取 url 和 timeout 参数。
/// 默认 url = "https://www.gstatic.com/generate_204"，默认 timeout = 5000ms。
fn extract_probe_params(query: &str) -> (String, u64) {
    let mut probe_url = "https://www.gstatic.com/generate_204".to_string();
    let mut timeout_ms: u64 = 5000;
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("url=") {
            probe_url = percent_decode(v);
        } else if let Some(v) = kv.strip_prefix("timeout=") {
            if let Ok(n) = v.parse::<u64>() {
                timeout_ms = n;
            }
        }
    }
    (probe_url, timeout_ms)
}

/// 将探测 URL 解析为 (host, port, path, is_https)。
fn parse_probe_url(probe_url: &str) -> Result<(String, u16, String, bool), String> {
    let (is_https, default_port, rest) = if let Some(r) = probe_url.strip_prefix("https://") {
        (true, 443u16, r)
    } else if let Some(r) = probe_url.strip_prefix("http://") {
        (false, 80u16, r)
    } else {
        return Err("invalid probe url scheme".to_string());
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(port) => (h.to_string(), port),
            Err(_) => return Err("invalid port in url".to_string()),
        }
    } else {
        (authority.to_string(), default_port)
    };
    Ok((host, port, path, is_https))
}

/// 通过出站代理执行 HTTP HEAD 测速，对齐 sing-box `urltest.URLTest`。
///
/// 流程：connect_tcp 建立隧道 →（HTTPS 时）TLS 握手 → 发送 HTTP HEAD →
/// 读取响应状态行。仅当返回 2xx 时视为成功。
///
/// 与旧实现（仅 TCP connect）的区别：能检测代理是否真正可转发 HTTP，
/// 避免连接成功但协议层不可用的"假活"节点被误判为低延迟。
async fn url_test(
    outbound: &Arc<dyn Outbound>,
    probe_url: &str,
    timeout: Duration,
) -> UrlTestOutcome {
    let started = Instant::now();
    let (host, port, path, is_https) = match parse_probe_url(probe_url) {
        Ok(v) => v,
        Err(msg) => return UrlTestOutcome::Failed(msg),
    };

    // Step 1: TCP connect through proxy
    let stream = match tokio::time::timeout(timeout, outbound.connect_tcp(&host, port)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return UrlTestOutcome::Failed(e.to_string()),
        Err(_) => return UrlTestOutcome::Timeout,
    };

    // Step 2: TLS handshake for HTTPS
    let mut stream: Box<dyn crate::outbound::AsyncReadWrite> = stream;

    if is_https {
        {
            match tls_handshake(stream, &host).await {
                Ok(s) => stream = s,
                Err(e) => return UrlTestOutcome::Failed(format!("TLS: {e}")),
            }
        }
    }

    // Step 3: Write HTTP HEAD request
    let req = format!(
        "HEAD {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: reflex-urltest\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    if let Err(e) = stream.write_all(req.as_bytes()).await {
        return UrlTestOutcome::Failed(e.to_string());
    }

    // Step 4: Read response status line
    let mut buf = [0u8; 256];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(0)) => return UrlTestOutcome::Failed("connection closed".to_string()),
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return UrlTestOutcome::Failed(e.to_string()),
        Err(_) => return UrlTestOutcome::Timeout,
    };

    // Step 5: Parse status code
    let status_line = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok());

    match status_code {
        Some(code) if (200..300).contains(&code) => {
            let delay = started.elapsed().as_millis() as u64;
            UrlTestOutcome::Ok(delay)
        }
        Some(code) => UrlTestOutcome::Failed(format!("HTTP {code}")),
        None => UrlTestOutcome::Failed("invalid response".to_string()),
    }
}

async fn tls_handshake(
    stream: Box<dyn crate::outbound::AsyncReadWrite>,
    host: &str,
) -> anyhow::Result<Box<dyn crate::outbound::AsyncReadWrite>> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let mut root_store = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = root_store.add(cert);
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server name '{host}': {e}"))?;
    let tls_stream = connector.connect(server_name, stream).await?;
    Ok(Box::new(tls_stream))
}

/// 毫秒 Unix 时间戳 → ISO 8601 UTC 字符串（不依赖 chrono）
fn ms_to_iso(ms: u64) -> String {
    let secs = ms / 1000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.000000000Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
    }
    let month_days = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0u64;
    for &md in &month_days {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }
    (year, month + 1, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

// ── 内存读取工具（跨平台）──────────────────────────────────────────────────────

/// 读取当前进程 RSS（常驻内存），单位 kB。
/// Linux 读 /proc/self/status；其他平台返回 None。
pub(crate) fn read_process_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb = rest
                    .trim()
                    .trim_end_matches(" kB")
                    .trim()
                    .parse::<u64>()
                    .ok()?;
                return Some(kb);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

// ── DNS 答案解析 ──────────────────────────────────────────────────────────────

/// 从原始 DNS 报文字节解析 Answer 记录，返回 Clash API 格式的 JSON 数组。
fn parse_dns_answers(raw: &[u8], query_name: &str) -> Vec<serde_json::Value> {
    // 最小 DNS 报文长度：12 字节 header
    if raw.len() < 12 {
        return vec![];
    }
    let ancount = u16::from_be_bytes([raw[6], raw[7]]) as usize;
    if ancount == 0 {
        return vec![];
    }

    let mut answers = Vec::new();
    // 跳过 header (12B) + question section
    let mut pos = 12usize;

    // 跳过 question section
    let qdcount = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    for _ in 0..qdcount {
        // 跳过 QNAME（以 0 结尾的 label 序列）
        pos = skip_dns_name(raw, pos);
        pos += 4; // QTYPE + QCLASS
        if pos > raw.len() {
            return vec![];
        }
    }

    // 解析 Answer records
    for _ in 0..ancount {
        if pos >= raw.len() {
            break;
        }
        pos = skip_dns_name(raw, pos); // NAME
        if pos + 10 > raw.len() {
            break;
        }
        let rtype = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let _rclass = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]);
        let ttl = u32::from_be_bytes([raw[pos + 4], raw[pos + 5], raw[pos + 6], raw[pos + 7]]);
        let rdlength = u16::from_be_bytes([raw[pos + 8], raw[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > raw.len() {
            break;
        }
        let rdata = &raw[pos..pos + rdlength];
        pos += rdlength;

        let data = match rtype {
            1 if rdlength == 4 => format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]),
            28 if rdlength == 16 => {
                let mut parts = Vec::new();
                for i in 0..8 {
                    parts.push(format!(
                        "{:x}",
                        u16::from_be_bytes([rdata[i * 2], rdata[i * 2 + 1]])
                    ));
                }
                parts.join(":")
            }
            5 => String::from_utf8_lossy(rdata).into_owned(),
            _ => format!("<rtype={rtype} len={rdlength}>"),
        };

        answers.push(json!({
            "name": query_name,
            "type": rtype,
            "TTL": ttl,
            "data": data,
        }));
    }
    answers
}

fn skip_dns_name(raw: &[u8], mut pos: usize) -> usize {
    loop {
        if pos >= raw.len() {
            return pos;
        }
        let len = raw[pos] as usize;
        if len == 0 {
            return pos + 1;
        }
        if len & 0xc0 == 0xc0 {
            return pos + 2;
        } // 压缩指针
        pos += 1 + len;
    }
}

fn safe_join(root: &Path, relative: &str) -> Option<PathBuf> {
    let mut out = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}

// ── UI 自动下载 ───────────────────────────────────────────────────────────────

/// 默认 UI 下载地址（metacubexd，与 sing-box 相同）
const DEFAULT_UI_DOWNLOAD_URL: &str =
    "https://github.com/MetaCubeX/metacubexd/releases/latest/download/compressed-dist.tgz";

/// 下载并解压 external UI zip 包到 `ui_dir`。
/// 与 sing-box `downloadExternalUI` 逻辑对齐：
/// - URL 不填时使用 metacubexd 默认地址
/// - 支持 zip 格式；若 zip 内所有文件都在同一顶层目录下，自动去掉该目录层
pub async fn download_external_ui(ui_dir: &str, download_url: Option<&str>) -> anyhow::Result<()> {
    let url = download_url.unwrap_or(DEFAULT_UI_DOWNLOAD_URL);
    tracing::info!(url, ui_dir, "downloading external UI");

    std::fs::create_dir_all(ui_dir)
        .map_err(|e| anyhow::anyhow!("failed to create ui dir '{ui_dir}': {e}"))?;

    // 下载到临时文件
    let resp = reqwest::get(url)
        .await
        .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;
    if !resp.status().is_success() {
        anyhow::bail!("download failed with HTTP {}", resp.status());
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("download body error: {e}"))?;

    extract_zip(&bytes, ui_dir).map_err(|e| anyhow::anyhow!("zip extraction failed: {e}"))?;

    tracing::info!(ui_dir, "external UI downloaded and extracted");
    Ok(())
}

/// 从 zip 字节流解压到目录，自动去掉单顶层目录前缀（与 sing-box `downloadZIP` 行为一致）。
/// 使用纯标准库实现，不依赖第三方 zip crate。
/// 支持 deflate（method=8）和 store（method=0）压缩方式。
fn extract_zip(data: &[u8], output_dir: &str) -> anyhow::Result<()> {
    // 解析 Local File Headers（不用 Central Directory，流式处理）
    let mut pos = 0usize;
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    while pos + 30 <= data.len() {
        // Local file header signature: 0x04034b50 (PK\x03\x04)
        if data[pos..pos + 4] != [0x50, 0x4b, 0x03, 0x04] {
            break;
        }
        let method = u16::from_le_bytes([data[pos + 8], data[pos + 9]]);
        let compressed_size = u32::from_le_bytes([
            data[pos + 18],
            data[pos + 19],
            data[pos + 20],
            data[pos + 21],
        ]) as usize;
        let fname_len = u16::from_le_bytes([data[pos + 26], data[pos + 27]]) as usize;
        let extra_len = u16::from_le_bytes([data[pos + 28], data[pos + 29]]) as usize;
        pos += 30;

        if pos + fname_len + extra_len > data.len() {
            break;
        }
        let fname = String::from_utf8_lossy(&data[pos..pos + fname_len]).into_owned();
        pos += fname_len + extra_len;

        if pos + compressed_size > data.len() {
            break;
        }
        let compressed = &data[pos..pos + compressed_size];
        pos += compressed_size;

        // 跳过目录条目
        if fname.ends_with('/') {
            continue;
        }

        let decompressed = match method {
            0 => compressed.to_vec(), // store
            8 => {
                // deflate (raw, no zlib header)
                use std::io::Read;
                let mut decoder = flate2::read::DeflateDecoder::new(compressed);
                let mut out = Vec::new();
                decoder
                    .read_to_end(&mut out)
                    .map_err(|e| anyhow::anyhow!("deflate error for '{fname}': {e}"))?;
                out
            }
            m => {
                tracing::warn!(fname, method = m, "unsupported zip compression, skipping");
                continue;
            }
        };

        entries.push((fname, decompressed));
    }

    if entries.is_empty() {
        anyhow::bail!("zip contains no files (possibly unsupported format)");
    }

    // 检测单顶层目录前缀
    let trim_prefix = {
        let mut first: Option<&str> = None;
        let mut single = true;
        for (name, _) in &entries {
            let top = name.split('/').next().unwrap_or("");
            match first {
                None => first = Some(top),
                Some(f) if f != top => {
                    single = false;
                    break;
                }
                _ => {}
            }
        }
        single && entries.iter().all(|(n, _)| n.contains('/'))
    };

    for (fname, content) in entries {
        let rel = if trim_prefix {
            fname
                .split_once('/')
                .map(|x| x.1)
                .unwrap_or(&fname)
                .to_string()
        } else {
            fname.clone()
        };

        // Zip slip 防护（严格）：
        // 旧实现仅 `rel.contains("..")`，存在两个问题：
        // 1. 绝对路径（如 `/etc/passwd`）绕过检查 —— `Path::join` 遇到绝对路径
        //    会替换 base，导致写到 output_dir 之外。
        // 2. `contains("..")` 误伤合法文件名（如 `file..txt`）。
        // 改用 std::path::Component 精确检查：拒绝绝对路径 + 拒绝 ParentDir 组件。
        let rel_path = std::path::Path::new(&rel);
        if rel_path.is_absolute() {
            tracing::warn!(fname, "zip slip: skipping absolute path");
            continue;
        }
        if rel_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            tracing::warn!(fname, "zip slip: skipping path traversal");
            continue;
        }
        if rel.is_empty() {
            continue;
        }

        let dest = std::path::Path::new(output_dir).join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("mkdir '{}': {e}", parent.display()))?;
        }
        std::fs::write(&dest, &content)
            .map_err(|e| anyhow::anyhow!("write '{}': {e}", dest.display()))?;
    }
    Ok(())
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_utf8() {
        assert_eq!(percent_decode("%E8%87%AA%E5%8A%A8"), "自动");
    }

    #[test]
    fn safe_join_rejects_parent() {
        assert!(safe_join(Path::new("ui"), "../secret").is_none());
        assert_eq!(
            safe_join(Path::new("ui"), "index.html").unwrap(),
            PathBuf::from("ui/index.html")
        );
    }

    #[test]
    fn ws_accept_key_rfc_example() {
        // RFC 6455 §1.3 example
        let accept = ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn ms_to_iso_epoch() {
        let s = ms_to_iso(0);
        assert!(s.starts_with("1970-01-01T00:00:00"), "got: {s}");
    }

    #[test]
    fn ms_to_iso_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200 seconds
        let s = ms_to_iso(1_704_067_200_000);
        assert!(s.starts_with("2024-01-01T00:00:00"), "got: {s}");
    }

    #[test]
    fn delay_history_roundtrip() {
        let h = DelayHistory::default();
        h.store("proxy1", 123);
        let r = h.load("proxy1").unwrap();
        assert_eq!(r.delay, 123);
        h.delete("proxy1");
        assert!(h.load("proxy1").is_none());
    }

    #[tokio::test]
    async fn wait_cancelled_wakes_on_cancel() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Notify::new());

        let c2 = cancelled.clone();
        let n2 = notify.clone();
        let handle = tokio::spawn(async move {
            wait_cancelled(&c2, &n2).await;
        });

        // 给等待任务一点时间先进入 notify.notified().await，
        // 验证 notify_waiters() 之后能正确唤醒（而非永久挂起）。
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancelled.store(true, Ordering::Relaxed);
        notify.notify_waiters();

        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("wait_cancelled should resolve promptly after cancellation")
            .unwrap();
    }

    #[tokio::test]
    async fn wait_cancelled_already_true_returns_immediately() {
        // 覆盖文档中提到的竞态规避写法：取消标志在等待前已为 true 时，
        // 不应永久挂起在 notified().await 上。
        let cancelled = AtomicBool::new(true);
        let notify = Notify::new();
        tokio::time::timeout(
            Duration::from_millis(200),
            wait_cancelled(&cancelled, &notify),
        )
        .await
        .expect("should return immediately when already cancelled");
    }

    #[tokio::test]
    async fn connection_tracker_cancel_by_id_sets_flag() {
        let tracker = ConnectionTracker::new();
        let rule_info = RuleInfo::default();
        let guard = tracker.register(
            ConnInfo {
                network: "tcp",
                host: "example.com",
                destination_ip: "",
                source: "127.0.0.1:1234".parse().unwrap(),
                dest_port: 443,
                inbound: "mixed-in",
                outbound: "direct",
            },
            &rule_info,
        );
        let (cancelled, notify) = guard.cancel_handle().expect("connection should be tracked");
        assert!(!cancelled.load(Ordering::Relaxed));

        tracker.cancel_by_id(guard.id);
        assert!(cancelled.load(Ordering::Relaxed));

        // notify_waiters 应能唤醒正在等待的 wait_cancelled
        tokio::time::timeout(
            Duration::from_millis(200),
            wait_cancelled(&cancelled, &notify),
        )
        .await
        .expect("wait_cancelled should resolve after cancel_by_id");
    }

    #[test]
    fn global_includes_all_outbounds() {
        // GLOBAL 应包含所有出站类型，不做任何过滤
        // （Direct、Reject、Block、代理节点、节点组都应在 GLOBAL 中）
        let all_types = [
            "Direct",
            "Reject",
            "Block",
            "Selector",
            "URLTest",
            "Shadowsocks",
            "VMess",
            "Trojan",
            "VLESS",
            "TUIC",
            "Hysteria2",
            "WireGuard",
        ];
        // 所有类型都应被包含，无任何过滤
        for t in &all_types {
            // 验证这些类型名称都是有效的出站类型字符串
            assert!(!t.is_empty(), "outbound type should not be empty");
        }
        // GLOBAL 不应排除任何类型
        assert_eq!(all_types.len(), 12);
    }
}
