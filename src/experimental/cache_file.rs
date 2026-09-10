use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use bytes::Bytes;
use redb::{Database, ReadableTable, TableDefinition};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ── redb 表定义 ───────────────────────────────────────────────────────────────

const FAKEIP_TABLE: TableDefinition<&str, (u64, &str)> = TableDefinition::new("fakeip");
const DNS_TABLE: TableDefinition<&[u8], (u64, &[u8])> = TableDefinition::new("dns_cache");
/// key = selector tag，value = 上次选中的 outbound tag
const SELECTED_TABLE: TableDefinition<&str, &str> = TableDefinition::new("selected");
/// key = ruleset tag，value = 原始规则集字节（type=remote 且无 path 时使用）
const RULESET_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("ruleset_cache");
/// 元数据表：key = 固定标识符（如 "fakeip_range"），value = 字符串。
/// 与 SELECTED_TABLE 隔离，避免 selector group tag 与内部元数据键冲突。
const META_TABLE: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// META_TABLE 中存储 fakeip 分配指针（inet4_current/inet6_current）的键。
/// value 格式："v4_str|v6_str"，空字符串表示对应 family 未配置/未初始化。
/// 参照 sing-box `adapter.FakeIPMetadata.Inet4Current/Inet6Current`：
/// sing-box 将指针随 metadata 持久化到 bbolt；reflex 用独立 META 键实现等价语义，
/// 在重启时直接恢复指针，避免仅靠 max(record)+1 重建导致 crash race 下指针回退。
const META_KEY_FAKEIP_POINTERS: &str = "fakeip_pointers";

// ── 写操作消息 ────────────────────────────────────────────────────────────────

#[allow(dead_code)]
enum WriteOp {
    StoreFakeip {
        ip: String,
        domain: String,
        last_seen: u64,
    },
    TouchFakeip {
        ip: String,
        last_seen: u64,
    },
    SaveDns {
        key: Vec<u8>,
        expire_at: u64,
        raw: Vec<u8>,
    },
    /// 持久化 selector 选中记录：group_tag → selected_tag
    StoreSelected {
        group: String,
        selected: String,
    },
    /// 持久化远程规则集字节（type=remote 且无 path 时）
    StoreRuleset {
        tag: String,
        data: Vec<u8>,
    },
    /// 写入元数据（如 fakeip_range 标记），与 SELECTED_TABLE 隔离
    StoreMeta {
        key: String,
        value: String,
    },
    /// 持久化 fakeip 分配指针（参照 sing-box FakeIPSaveMetadataAsync）。
    /// value 格式："v4_str|v6_str"，空串表示该 family 未配置。
    StoreFakeipPointers {
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
    },
    /// 参照 sing-box FakeIPReset()：fakeip range 发生变化时清空持久化表，
    /// 防止旧 range 的 IP 记录污染新 range 的分配。
    ClearFakeip,
    Cleanup,
    Shutdown,
}

// ── 写句柄（跨 task 共享） ────────────────────────────────────────────────────

pub struct CacheFile {
    write_tx: mpsc::UnboundedSender<WriteOp>,
    pub store_fakeip: bool,
    pub store_dns: bool,
}

impl CacheFile {
    pub fn store_fakeip_entry(&self, ip: IpAddr, domain: &str) {
        if !self.store_fakeip {
            return;
        }
        let _ = self.write_tx.send(WriteOp::StoreFakeip {
            ip: ip.to_string(),
            domain: domain.to_string(),
            last_seen: unix_now(),
        });
    }

    pub fn touch_fakeip_entry(&self, ip: IpAddr) {
        if !self.store_fakeip {
            return;
        }
        let _ = self.write_tx.send(WriteOp::TouchFakeip {
            ip: ip.to_string(),
            last_seen: unix_now(),
        });
    }

    /// 持久化 Selector 选中节点（非阻塞）
    pub fn store_selected(&self, group: &str, selected: &str) {
        let _ = self.write_tx.send(WriteOp::StoreSelected {
            group: group.to_string(),
            selected: selected.to_string(),
        });
    }

    /// 持久化远程规则集字节（非阻塞，type=remote 且无 path 时调用）
    pub fn store_ruleset_entry(&self, tag: &str, data: Vec<u8>) {
        if self
            .write_tx
            .send(WriteOp::StoreRuleset {
                tag: tag.to_string(),
                data,
            })
            .is_err()
        {
            tracing::warn!(
                tag,
                "cache_file: write channel closed, ruleset cache store failed (write task may have exited)"
            );
        }
    }

    /// 参照 sing-box FakeIPReset()：清空 fakeip 持久化表（非阻塞）。
    /// 当检测到 fakeip range 配置变化时调用，避免旧 IP 映射污染新分配。
    pub fn clear_fakeip(&self) {
        if !self.store_fakeip {
            return;
        }
        let _ = self.write_tx.send(WriteOp::ClearFakeip);
    }

    /// 持久化 fakeip range 标记，供下次启动时做 range 变化检测。
    /// 使用 META_TABLE 而非 SELECTED_TABLE，避免与用户定义的 selector group tag 冲突。
    pub fn store_fakeip_range_tag(&self, tag: &str) {
        if !self.store_fakeip {
            return;
        }
        let _ = self.write_tx.send(WriteOp::StoreMeta {
            key: "fakeip_range".to_string(),
            value: tag.to_string(),
        });
    }

    /// 持久化 fakeip 分配指针（参照 sing-box `FakeIPSaveMetadataAsync`）。
    ///
    /// 在每次 allocate_v4/v6 成功后调用，将最新指针写入 META_TABLE，
    /// 供下次启动时直接恢复，避免仅靠 max(record)+1 重建导致 race 下指针回退。
    /// 写入通过 write_tx 异步串行化，不阻塞查询路径。
    pub fn store_fakeip_pointers(&self, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) {
        if !self.store_fakeip {
            return;
        }
        let _ = self.write_tx.send(WriteOp::StoreFakeipPointers { v4, v6 });
    }

    /// 异步写入 DNS 缓存（非阻塞）
    pub fn save_dns_cache_async(
        &self,
        transport: &str,
        qname: &str,
        qtype: u16,
        raw: Bytes,
        expire_at_secs: u64,
    ) {
        if !self.store_dns {
            return;
        }
        let _ = self.write_tx.send(WriteOp::SaveDns {
            key: encode_dns_key(transport, qname, qtype),
            expire_at: expire_at_secs,
            raw: raw.to_vec(),
        });
    }
}

// ── 读句柄（持有 Arc<Database>，可并发只读） ──────────────────────────────────

pub struct CacheFileReader {
    db: Arc<Database>,
    pub store_dns: bool,
}

impl CacheFileReader {
    /// 读取 Selector 上次选中的 outbound tag；未找到时返回 None。
    pub fn load_selected(&self, group: &str) -> Option<String> {
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(SELECTED_TABLE).ok()?;
        let guard = table.get(group).ok()??;
        Some(guard.value().to_string())
    }

    /// 读取已缓存的远程规则集原始字节；未找到时返回 None。
    pub fn load_ruleset_cache(&self, tag: &str) -> Option<Vec<u8>> {
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(RULESET_TABLE).ok()?;
        let guard = table.get(tag).ok()??;
        Some(guard.value().to_vec())
    }

    /// 读取 DNS 缓存，返回 (raw_response, expire_at_unix_secs)。
    /// 不检查是否过期，由调用方（DnsCache）决策。
    pub fn load_dns_cache(&self, transport: &str, qname: &str, qtype: u16) -> Option<(Bytes, u64)> {
        if !self.store_dns {
            return None;
        }
        let key = encode_dns_key(transport, qname, qtype);
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(DNS_TABLE).ok()?;
        let guard = table.get(key.as_slice()).ok()??;
        let (expire_at, raw_bytes) = guard.value();
        let raw = Bytes::copy_from_slice(raw_bytes);
        Some((raw, expire_at))
    }

    /// 启动时恢复内存 fakeip 映射。
    /// 若表不存在（如 ClearFakeip 删除后尚未重建），返回空列表而非报错。
    pub fn load_all_fakeip(&self) -> anyhow::Result<Vec<(IpAddr, String)>> {
        let rtx = self.db.begin_read()?;
        // ClearFakeip 会 delete_table，此后读事务 open_table 会失败。
        // 这是正常状态（表为空），返回空列表即可。
        let table = match rtx.open_table(FAKEIP_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut result = Vec::new();
        for item in table.iter()? {
            let (k, v) = item?;
            let ip_str = k.value();
            let (_, domain) = v.value();
            match ip_str.parse::<IpAddr>() {
                Ok(ip) => result.push((ip, domain.to_string())),
                Err(e) => warn!(ip=%ip_str, err=%e, "invalid ip in fakeip table, skipping"),
            }
        }
        Ok(result)
    }

    /// 读取上次持久化的 fakeip range 标记（inet4_range|inet6_range 拼接字符串）。
    /// 参照 sing-box Store.Start()：range 变化时需重置持久化数据。
    /// 优先从 META_TABLE 读取；若不存在则回退到旧版 SELECTED_TABLE（向后兼容）。
    pub fn load_fakeip_range_tag(&self) -> Option<String> {
        let rtx = self.db.begin_read().ok()?;
        // 新版：META_TABLE
        if let Ok(table) = rtx.open_table(META_TABLE) {
            if let Ok(Some(guard)) = table.get("fakeip_range") {
                return Some(guard.value().to_string());
            }
        }
        // 旧版回退：SELECTED_TABLE 中的 "__fakeip_range__" 键
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(SELECTED_TABLE).ok()?;
        let guard = table.get("__fakeip_range__").ok()??;
        Some(guard.value().to_string())
    }

    /// 读取上次持久化的 fakeip 分配指针（inet4_current/inet6_current）。
    /// 参照 sing-box `Store.Start()`：range 匹配时从 metadata 恢复指针。
    /// 返回 `(v4, v6)`，对应 family 未配置或未持久化时为 None。
    /// 解析失败（格式错误、IP 不合法）时整体返回 None，由调用方回退到 max+1 重建。
    pub fn load_fakeip_pointers(&self) -> Option<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let rtx = self.db.begin_read().ok()?;
        let table = rtx.open_table(META_TABLE).ok()?;
        let guard = table.get(META_KEY_FAKEIP_POINTERS).ok()??;
        let value = guard.value();
        // 格式："v4_str|v6_str"
        let mut parts = value.splitn(2, '|');
        let v4_str = parts.next()?;
        let v6_str = parts.next().unwrap_or("");
        let v4 = if v4_str.is_empty() {
            None
        } else {
            v4_str.parse().ok()
        };
        let v6 = if v6_str.is_empty() {
            None
        } else {
            v6_str.parse().ok()
        };
        Some((v4, v6))
    }
}

// ── 工厂函数：同时返回写句柄和读句柄 ─────────────────────────────────────────

pub fn open_cache_file(
    path: impl AsRef<Path>,
    store_fakeip: bool,
    fakeip_ttl_days: u32,
    store_dns: bool,
    dns_cleanup_secs: u64,
) -> anyhow::Result<(Arc<CacheFile>, Arc<CacheFileReader>)> {
    let db = Arc::new(
        Database::create(path.as_ref())
            .with_context(|| format!("failed to open redb: {}", path.as_ref().display()))?,
    );

    // 建表（幂等）
    {
        let wtx = db.begin_write()?;
        wtx.open_table(FAKEIP_TABLE)?;
        wtx.open_table(DNS_TABLE)?;
        wtx.open_table(SELECTED_TABLE)?;
        wtx.open_table(RULESET_TABLE)?;
        wtx.open_table(META_TABLE)?;
        wtx.commit()?;
    }

    // 启动时清理
    if store_fakeip && fakeip_ttl_days > 0 {
        let cutoff = unix_now().saturating_sub(fakeip_ttl_days as u64 * 86400);
        match purge_stale_fakeip(&db, cutoff) {
            Ok(n) if n > 0 => info!(count = n, "purged stale fakeip on startup"),
            Err(e) => warn!(err=%e, "purge stale fakeip failed"),
            _ => {}
        }
    }
    if store_dns {
        match purge_expired_dns(&db, unix_now()) {
            Ok(n) if n > 0 => info!(count = n, "purged expired dns cache on startup"),
            Err(e) => warn!(err=%e, "purge expired dns failed"),
            _ => {}
        }
    }

    let (write_tx, write_rx) = mpsc::unbounded_channel::<WriteOp>();
    let interval = if dns_cleanup_secs > 0 {
        dns_cleanup_secs
    } else {
        3600
    };
    let db_write = db.clone();
    tokio::spawn(write_loop(db_write, write_rx, interval, fakeip_ttl_days));

    let writer = Arc::new(CacheFile {
        write_tx,
        store_fakeip,
        store_dns,
    });
    let reader = Arc::new(CacheFileReader { db, store_dns });
    Ok((writer, reader))
}

// ── 后台写循环 ────────────────────────────────────────────────────────────────

async fn write_loop(
    db: Arc<Database>,
    mut rx: mpsc::UnboundedReceiver<WriteOp>,
    cleanup_interval_secs: u64,
    fakeip_ttl_days: u32,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(cleanup_interval_secs));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // 当所有 CacheFile 写句柄被 drop（write_tx 关闭）时，
            // rx.recv() 返回 None，此时应退出写循环以释放 db 句柄，
            // 避免数据库文件锁泄漏（影响测试中 reopen 同一文件等场景）。
            op = rx.recv() => {
                match op {
                    None | Some(WriteOp::Shutdown) => break,
                    Some(WriteOp::Cleanup) => do_cleanup(&db, fakeip_ttl_days),
                    Some(op) => {
                        if let Err(e) = apply_op(&db, op) {
                            warn!(err=%e, "cache write failed");
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                do_cleanup(&db, fakeip_ttl_days);
            }
        }
    }
}

fn do_cleanup(db: &Arc<Database>, fakeip_ttl_days: u32) {
    let now = unix_now();
    match purge_expired_dns(db, now) {
        Ok(n) if n > 0 => debug!(count = n, "dns cache cleanup"),
        Err(e) => warn!(err=%e, "dns cleanup error"),
        _ => {}
    }
    if fakeip_ttl_days > 0 {
        let cutoff = now.saturating_sub(fakeip_ttl_days as u64 * 86400);
        match purge_stale_fakeip(db, cutoff) {
            Ok(n) if n > 0 => debug!(count = n, "fakeip cleanup"),
            Err(e) => warn!(err=%e, "fakeip cleanup error"),
            _ => {}
        }
    }
}

fn apply_op(db: &Database, op: WriteOp) -> anyhow::Result<()> {
    match op {
        WriteOp::StoreFakeip {
            ip,
            domain,
            last_seen,
        } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(FAKEIP_TABLE)?
                    .insert(ip.as_str(), (last_seen, domain.as_str()))?;
            }
            wtx.commit()?;
        }
        WriteOp::TouchFakeip { ip, last_seen } => {
            let wtx = db.begin_write()?;
            {
                let mut table = wtx.open_table(FAKEIP_TABLE)?;
                let existing_domain: Option<String> = {
                    let result = table.get(ip.as_str())?;
                    result.map(|g| {
                        let (_, domain) = g.value();
                        domain.to_string()
                    })
                };
                if let Some(domain) = existing_domain {
                    table.insert(ip.as_str(), (last_seen, domain.as_str()))?;
                }
            }
            wtx.commit()?;
        }
        WriteOp::SaveDns {
            key,
            expire_at,
            raw,
        } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(DNS_TABLE)?
                    .insert(key.as_slice(), (expire_at, raw.as_slice()))?;
            }
            wtx.commit()?;
        }
        WriteOp::StoreSelected { group, selected } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(SELECTED_TABLE)?
                    .insert(group.as_str(), selected.as_str())?;
            }
            wtx.commit()?;
        }
        WriteOp::StoreRuleset { tag, data } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(RULESET_TABLE)?
                    .insert(tag.as_str(), data.as_slice())?;
            }
            wtx.commit()?;
        }
        WriteOp::StoreMeta { key, value } => {
            let wtx = db.begin_write()?;
            {
                wtx.open_table(META_TABLE)?
                    .insert(key.as_str(), value.as_str())?;
            }
            wtx.commit()?;
        }
        WriteOp::StoreFakeipPointers { v4, v6 } => {
            let v4_str = v4.map(|ip| ip.to_string()).unwrap_or_default();
            let v6_str = v6.map(|ip| ip.to_string()).unwrap_or_default();
            let value = format!("{v4_str}|{v6_str}");
            let wtx = db.begin_write()?;
            {
                wtx.open_table(META_TABLE)?
                    .insert(META_KEY_FAKEIP_POINTERS, value.as_str())?;
            }
            wtx.commit()?;
        }
        WriteOp::Cleanup | WriteOp::Shutdown => {}
        WriteOp::ClearFakeip => {
            let wtx = db.begin_write()?;
            // delete_table 删除整个表结构。旧实现仅删除不重建，
            // 导致后续读事务 open_table(FAKEIP_TABLE) 报 TableDoesNotExist，
            // load_all_fakeip / purge_stale_fakeip 均会失败。
            // 修复：删除后立即在同一写事务内重建空表。
            wtx.delete_table(FAKEIP_TABLE).map(|_| ())?;
            wtx.open_table(FAKEIP_TABLE)?;
            // 同步清除 fakeip_pointers 元数据（range_tag 保留，range 未变）。
            // 参照 sing-box FakeIPReset()：reset 时连 metadata 一起清掉，
            // 下次 Start() 检测到无 metadata 时把指针回退到 start+1。
            {
                let mut meta = wtx.open_table(META_TABLE)?;
                meta.remove(META_KEY_FAKEIP_POINTERS)?;
            }
            wtx.commit()?;
        }
    }
    Ok(())
}

// ── 清理辅助 ──────────────────────────────────────────────────────────────────

fn purge_expired_dns(db: &Database, now_secs: u64) -> anyhow::Result<usize> {
    let rtx = db.begin_read()?;
    let expired: Vec<Vec<u8>> = {
        let table = rtx.open_table(DNS_TABLE)?;
        table
            .iter()?
            .filter_map(|item| {
                let (k, v) = item.ok()?;
                let (expire_at, _) = v.value();
                if expire_at <= now_secs {
                    Some(k.value().to_vec())
                } else {
                    None
                }
            })
            .collect()
    };
    drop(rtx);
    if expired.is_empty() {
        return Ok(0);
    }
    let count = expired.len();
    let wtx = db.begin_write()?;
    {
        let mut t = wtx.open_table(DNS_TABLE)?;
        for k in &expired {
            t.remove(k.as_slice())?;
        }
    }
    wtx.commit()?;
    Ok(count)
}

fn purge_stale_fakeip(db: &Database, cutoff_secs: u64) -> anyhow::Result<usize> {
    let rtx = db.begin_read()?;
    let stale: Vec<String> = {
        let table = rtx.open_table(FAKEIP_TABLE)?;
        table
            .iter()?
            .filter_map(|item| {
                let (k, v) = item.ok()?;
                let (last_seen, _) = v.value();
                if last_seen < cutoff_secs {
                    Some(k.value().to_string())
                } else {
                    None
                }
            })
            .collect()
    };
    drop(rtx);
    if stale.is_empty() {
        return Ok(0);
    }
    let count = stale.len();
    let wtx = db.begin_write()?;
    {
        let mut t = wtx.open_table(FAKEIP_TABLE)?;
        for k in &stale {
            t.remove(k.as_str())?;
        }
    }
    wtx.commit()?;
    Ok(count)
}

// ── 编码辅助 ──────────────────────────────────────────────────────────────────

/// key 格式：[transport_len(2 BE) | transport_bytes | qname_lower | 0x00 | qtype(2 BE)]
fn encode_dns_key(transport: &str, qname: &str, qtype: u16) -> Vec<u8> {
    let t = transport.as_bytes();
    let q = qname.to_ascii_lowercase();
    let qb = q.as_bytes();
    let mut key = Vec::with_capacity(2 + t.len() + qb.len() + 3);
    key.extend_from_slice(&(t.len() as u16).to_be_bytes());
    key.extend_from_slice(t);
    key.extend_from_slice(qb);
    key.push(0x00);
    key.extend_from_slice(&qtype.to_be_bytes());
    key
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── 测试 ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::NamedTempFile;

    async fn open_temp(
        sf: bool,
        sd: bool,
    ) -> (Arc<CacheFile>, Arc<CacheFileReader>, NamedTempFile) {
        let f = NamedTempFile::new().unwrap();
        let (cf, rd) = open_cache_file(f.path(), sf, 7, sd, 3600).unwrap();
        (cf, rd, f)
    }

    #[tokio::test]
    async fn fakeip_store_and_load() {
        let (cf, rd, _f) = open_temp(true, false).await;
        let ip: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));
        cf.store_fakeip_entry(ip, "example.com");
        tokio::time::sleep(Duration::from_millis(60)).await;
        let records = rd.load_all_fakeip().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].1, "example.com");
    }

    #[tokio::test]
    async fn dns_cache_roundtrip() {
        let (cf, rd, _f) = open_temp(false, true).await;
        let raw = Bytes::from(vec![0xAB, 0xCD, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0]);
        let expire_at = unix_now() + 300;
        cf.save_dns_cache_async("up1", "example.com", 1, raw.clone(), expire_at);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (loaded, exp) = rd.load_dns_cache("up1", "example.com", 1).unwrap();
        assert_eq!(loaded, raw);
        assert_eq!(exp, expire_at);
    }

    #[tokio::test]
    async fn dns_transport_isolation() {
        let (cf, rd, _f) = open_temp(false, true).await;
        let r1 = Bytes::from(vec![0x01; 12]);
        let r2 = Bytes::from(vec![0x02; 12]);
        let exp = unix_now() + 300;
        cf.save_dns_cache_async("ta", "x.com", 1, r1.clone(), exp);
        cf.save_dns_cache_async("tb", "x.com", 1, r2.clone(), exp);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(rd.load_dns_cache("ta", "x.com", 1).unwrap().0, r1);
        assert_eq!(rd.load_dns_cache("tb", "x.com", 1).unwrap().0, r2);
    }

    #[tokio::test]
    async fn dns_key_case_insensitive() {
        let (cf, rd, _f) = open_temp(false, true).await;
        let raw = Bytes::from(vec![0xAA; 12]);
        cf.save_dns_cache_async("t", "Example.COM", 1, raw.clone(), unix_now() + 300);
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(rd.load_dns_cache("t", "example.com", 1).is_some());
    }

    /// 验证 fakeip 分配指针的持久化与读取（参照 sing-box FakeIPSaveMetadata）。
    #[tokio::test]
    async fn fakeip_pointers_roundtrip() {
        let (cf, rd, _f) = open_temp(true, false).await;
        // 初始为 None
        assert!(rd.load_fakeip_pointers().is_none());

        // 写入 (v4, v6)
        cf.store_fakeip_pointers(
            Some(Ipv4Addr::new(198, 18, 0, 100)),
            Some(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0x64)),
        );
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (v4, v6) = rd.load_fakeip_pointers().unwrap();
        assert_eq!(v4, Some(Ipv4Addr::new(198, 18, 0, 100)));
        assert_eq!(v6, Some(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0x64)));

        // 仅 v4：v6 应为 None（持久化为空串）
        cf.store_fakeip_pointers(Some(Ipv4Addr::new(198, 18, 0, 200)), None);
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (v4, v6) = rd.load_fakeip_pointers().unwrap();
        assert_eq!(v4, Some(Ipv4Addr::new(198, 18, 0, 200)));
        assert_eq!(v6, None);

        // 仅 v6：v4 应为 None
        cf.store_fakeip_pointers(None, Some(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0xc8)));
        tokio::time::sleep(Duration::from_millis(60)).await;
        let (v4, v6) = rd.load_fakeip_pointers().unwrap();
        assert_eq!(v4, None);
        assert_eq!(v6, Some(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0xc8)));
    }

    /// 验证 `clear_fakeip()` 同步清除指针（参照 sing-box FakeIPReset 连 metadata 一起清掉）。
    /// range_tag 不应被清除（range 未变）。
    #[tokio::test]
    async fn fakeip_clear_also_clears_pointers() {
        let (cf, rd, _f) = open_temp(true, false).await;
        cf.store_fakeip_pointers(Some(Ipv4Addr::new(198, 18, 0, 100)), None);
        cf.store_fakeip_range_tag("198.18.0.0/16|");
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(rd.load_fakeip_pointers().is_some());
        assert!(rd.load_fakeip_range_tag().is_some());

        cf.clear_fakeip();
        tokio::time::sleep(Duration::from_millis(60)).await;

        // 指针应被清除
        assert!(rd.load_fakeip_pointers().is_none());
        // range_tag 应保留（range 未变，仅 reset 映射）
        assert!(rd.load_fakeip_range_tag().is_some());
    }
}
