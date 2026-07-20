//! 连接统计：原子计数器，零锁开销。
//!
//! 每个 Outbound tag 维护独立计数，全局也有汇总。
//!
//! 优先使用 `AtomicU64`（绝大多数 32 位平台——x86、ARMv7+、MIPS32r2+——
//! 都通过 `target_has_atomic = "64"` 提供原生 64 位原子操作）。
//! 仅在极少数不支持 64 位原子的古早平台（如 MIPS32r1）退化为 `AtomicU32`。
//!
//! 关键点：`bytes_up` / `bytes_down` 是累计字节计数。旧实现用
//! `target_pointer_width = "64"` 判断，导致所有 32 位平台都被降级为
//! `AtomicU32`，累计流量超过 4 GB 后回绕归零。改用 `target_has_atomic`
//! 后，实际 32 位平台也能用 `AtomicU64`，避免回绕。
//!
//! ## 优化：DashMap 替代 RwLock<HashMap>
//! Stats::tag() 在每条连接建立/统计时都会被调用。原版用 RwLock<HashMap>，
//! 高并发下读锁升级写锁有额外开销。DashMap 内置分片锁（默认 16 片），
//! 并发写性能比全局 RwLock 好一个数量级。

use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
};

use dashmap::DashMap;

// ── 平台适配：有 64 位原子用 AtomicU64，否则退化 AtomicU32 ───────────────────

#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64 as AtomicCounter;

#[cfg(not(target_has_atomic = "64"))]
use std::sync::atomic::AtomicU32 as AtomicCounter;

/// 将原子计数器的值读出并扩展为 u64
#[inline]
#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn load_u64(c: &AtomicCounter) -> u64 {
    c.load(Ordering::Relaxed) as u64
}

// ── 单个 tag 的统计 ────────────────────────────────────────────────────────────

#[derive(Default, Debug)]
pub struct TagStats {
    /// 当前活跃 TCP 连接数
    pub tcp_active: AtomicCounter,
    /// 当前活跃 UDP 会话数
    pub udp_active: AtomicCounter,
    /// 累计 TCP 连接总数
    pub tcp_total: AtomicCounter,
    /// 累计 UDP 包总数
    pub udp_total: AtomicCounter,
    /// 累计上行字节（入站→出站）
    pub bytes_up: AtomicCounter,
    /// 累计下行字节（出站→入站）
    pub bytes_down: AtomicCounter,
    /// 累计错误次数
    pub errors: AtomicCounter,
}

impl TagStats {
    pub fn snapshot(&self) -> TagSnapshot {
        TagSnapshot {
            tcp_active: load_u64(&self.tcp_active),
            udp_active: load_u64(&self.udp_active),
            tcp_total: load_u64(&self.tcp_total),
            udp_total: load_u64(&self.udp_total),
            bytes_up: load_u64(&self.bytes_up),
            bytes_down: load_u64(&self.bytes_down),
            errors: load_u64(&self.errors),
        }
    }
}

/// 某一时刻的统计快照（可序列化）
#[derive(Debug, Clone)]
pub struct TagSnapshot {
    pub tcp_active: u64,
    pub udp_active: u64,
    pub tcp_total: u64,
    pub udp_total: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub errors: u64,
}

// ── DNS 劫持统计 ──────────────────────────────────────────────────────────────

/// DNS 查询统计（P3-2）：分别统计来自专用 DNS 入站与路由层劫持的查询数量，
/// 便于运维定位"为什么 DNS 没走期望的上游"等问题。
#[derive(Default, Debug)]
pub struct DnsStats {
    /// 来自专用 DNS 入站（dns-in）的查询总数
    pub inbound_queries: AtomicCounter,
    /// 来自路由层劫持（hijack_dns 规则 / 全局开关）的查询总数
    pub hijacked_queries: AtomicCounter,
    /// 其中 TCP 上劫持的查询数
    pub hijacked_tcp: AtomicCounter,
    /// 其中 UDP 上劫持的查询数
    pub hijacked_udp: AtomicCounter,
    /// DNS 解析失败次数（上游不可达 / 超时等）
    pub errors: AtomicCounter,
}

impl DnsStats {
    pub fn snapshot(&self) -> DnsStatsSnapshot {
        DnsStatsSnapshot {
            inbound_queries: load_u64(&self.inbound_queries),
            hijacked_queries: load_u64(&self.hijacked_queries),
            hijacked_tcp: load_u64(&self.hijacked_tcp),
            hijacked_udp: load_u64(&self.hijacked_udp),
            errors: load_u64(&self.errors),
        }
    }

    /// 记录一次劫持查询（区分 TCP/UDP）。每累计 1000 次输出一条 info 日志，
    /// 便于运维监控劫持流量规模，同时避免日志刷屏。
    pub fn record_hijack(&self, is_tcp: bool) {
        let prev = self.hijacked_queries.fetch_add(1, Ordering::Relaxed);
        if is_tcp {
            self.hijacked_tcp.fetch_add(1, Ordering::Relaxed);
        } else {
            self.hijacked_udp.fetch_add(1, Ordering::Relaxed);
        }
        // 每 1000 次输出一条汇总日志（prev=999, 1999, 2999, ...）
        if prev % 1000 == 999 {
            let snap = self.snapshot();
            tracing::info!(
                total = snap.hijacked_queries,
                tcp = snap.hijacked_tcp,
                udp = snap.hijacked_udp,
                errors = snap.errors,
                "dns hijack stats milestone"
            );
        }
    }

    /// 记录一次专用入站查询
    pub fn record_inbound(&self) {
        self.inbound_queries.fetch_add(1, Ordering::Relaxed);
    }

    /// 记录一次 DNS 解析错误
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

/// DNS 统计快照
#[derive(Debug, Clone, Default)]
pub struct DnsStatsSnapshot {
    pub inbound_queries: u64,
    pub hijacked_queries: u64,
    pub hijacked_tcp: u64,
    pub hijacked_udp: u64,
    pub errors: u64,
}

// ── 全局统计注册表 ─────────────────────────────────────────────────────────────

pub struct Stats {
    /// DashMap 内置 16 分片锁，并发写性能远优于全局 RwLock<HashMap>。
    /// tag() 在每条连接建立时都会调用，这里是高并发热点。
    tags: DashMap<String, Arc<TagStats>>,
    /// DNS 查询统计（专用入站 + 路由劫持）。独立于 tags，因为 DNS 流量
    /// 不一定走 outbound tag（hijack_dns 直接派发到内部 resolver）。
    dns: DnsStats,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tags: DashMap::new(),
            dns: DnsStats::default(),
        })
    }

    /// 获取或创建某个 tag 的统计对象。
    /// DashMap::entry() 内部分片锁，避免全局写锁竞争。
    pub fn tag(&self, tag: &str) -> Arc<TagStats> {
        self.tags
            .entry(tag.to_string())
            .or_insert_with(|| Arc::new(TagStats::default()))
            .clone()
    }

    /// 所有 tag 的快照
    pub fn snapshot_all(&self) -> HashMap<String, TagSnapshot> {
        self.tags
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().snapshot()))
            .collect()
    }

    /// 全局汇总
    pub fn global_snapshot(&self) -> TagSnapshot {
        self.tags
            .iter()
            .fold(TagSnapshot::zero(), |mut acc, entry| {
                let snap = entry.value().snapshot();
                acc.tcp_active += snap.tcp_active;
                acc.udp_active += snap.udp_active;
                acc.tcp_total += snap.tcp_total;
                acc.udp_total += snap.udp_total;
                acc.bytes_up += snap.bytes_up;
                acc.bytes_down += snap.bytes_down;
                acc.errors += snap.errors;
                acc
            })
    }

    /// DNS 统计引用（用于 dispatcher 在劫持/入站路径上记录）
    pub fn dns(&self) -> &DnsStats {
        &self.dns
    }

    /// DNS 统计快照（供 Clash API / 日志输出）
    pub fn dns_snapshot(&self) -> DnsStatsSnapshot {
        self.dns.snapshot()
    }
}

impl TagSnapshot {
    pub fn zero() -> Self {
        Self {
            tcp_active: 0,
            udp_active: 0,
            tcp_total: 0,
            udp_total: 0,
            bytes_up: 0,
            bytes_down: 0,
            errors: 0,
        }
    }
}

// ── RAII 守卫：连接结束时自动减计数 ──────────────────────────────────────────

pub struct TcpGuard(Arc<TagStats>);

impl TcpGuard {
    pub fn new(stats: Arc<TagStats>) -> Self {
        stats.tcp_active.fetch_add(1, Ordering::Relaxed);
        stats.tcp_total.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }

    pub fn add_bytes(&self, up: u64, down: u64) {
        // 绝大多数平台使用 AtomicU64，无截断；
        // 仅无 64 位原子的古早平台退化为 u32（累计流量超过 4 GB 才回绕）。
        self.0.bytes_up.fetch_add(up as _, Ordering::Relaxed);
        self.0.bytes_down.fetch_add(down as _, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for TcpGuard {
    fn drop(&mut self) {
        self.0.tcp_active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct UdpGuard(Arc<TagStats>);

impl UdpGuard {
    pub fn new(stats: Arc<TagStats>) -> Self {
        stats.udp_active.fetch_add(1, Ordering::Relaxed);
        stats.udp_total.fetch_add(1, Ordering::Relaxed);
        Self(stats)
    }

    pub fn add_bytes(&self, up: u64, down: u64) {
        self.0.bytes_up.fetch_add(up as _, Ordering::Relaxed);
        self.0.bytes_down.fetch_add(down as _, Ordering::Relaxed);
    }

    /// 记录一次 UDP 错误。与 `TcpGuard::record_error` 对称，
    /// 旧实现缺失此方法导致 UDP 出错无法计入统计。
    pub fn record_error(&self) {
        self.0.errors.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for UdpGuard {
    fn drop(&mut self) {
        self.0.udp_active.fetch_sub(1, Ordering::Relaxed);
    }
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_guard_counts() {
        let stats = Stats::new();
        let tag = stats.tag("proxy");

        assert_eq!(tag.snapshot().tcp_active, 0);
        assert_eq!(tag.snapshot().tcp_total, 0);

        let g1 = TcpGuard::new(stats.tag("proxy"));
        assert_eq!(tag.snapshot().tcp_active, 1);
        assert_eq!(tag.snapshot().tcp_total, 1);

        let g2 = TcpGuard::new(stats.tag("proxy"));
        assert_eq!(tag.snapshot().tcp_active, 2);
        assert_eq!(tag.snapshot().tcp_total, 2);

        g1.add_bytes(100, 200);
        assert_eq!(tag.snapshot().bytes_up, 100);
        assert_eq!(tag.snapshot().bytes_down, 200);

        drop(g1);
        assert_eq!(tag.snapshot().tcp_active, 1);
        assert_eq!(tag.snapshot().tcp_total, 2);

        drop(g2);
        assert_eq!(tag.snapshot().tcp_active, 0);
    }

    #[test]
    fn udp_guard_counts() {
        let stats = Stats::new();
        let g = UdpGuard::new(stats.tag("direct"));
        assert_eq!(stats.tag("direct").snapshot().udp_active, 1);
        drop(g);
        assert_eq!(stats.tag("direct").snapshot().udp_active, 0);
    }

    #[test]
    fn global_snapshot_aggregates() {
        let stats = Stats::new();
        let _g1 = TcpGuard::new(stats.tag("proxy"));
        let _g2 = TcpGuard::new(stats.tag("direct"));
        let global = stats.global_snapshot();
        assert_eq!(global.tcp_active, 2);
        assert_eq!(global.tcp_total, 2);
    }

    #[test]
    fn multiple_tags() {
        let stats = Stats::new();
        let _g = TcpGuard::new(stats.tag("proxy"));
        let _g2 = TcpGuard::new(stats.tag("proxy"));
        let _g3 = UdpGuard::new(stats.tag("direct"));
        let snap = stats.snapshot_all();
        assert_eq!(snap["proxy"].tcp_active, 2);
        assert_eq!(snap["direct"].udp_active, 1);
    }

    #[test]
    fn error_recording() {
        let stats = Stats::new();
        let g = TcpGuard::new(stats.tag("hy2"));
        g.record_error();
        g.record_error();
        assert_eq!(stats.tag("hy2").snapshot().errors, 2);
    }
}
