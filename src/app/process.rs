use std::net::SocketAddr;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

#[cfg(target_os = "linux")]
use tokio::sync::RwLock;

/// 查找到的进程信息
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// 进程名：可执行文件路径的 basename（如 "chrome"），对齐 sing-box
    /// `filepath.Base(metadata.ProcessInfo.ProcessPath)`（见
    /// route/rule/rule_item_process_name.go:32）。
    ///
    /// 注意：sing-box 在 `ProcessPath == ""` 时直接返回不匹配。
    /// 这里在 exe 路径不可读（权限不足等）时回退到 `/proc/<pid>/comm`，
    /// 兼顾内核 comm 截断（TASK_COMM_LEN=15）场景下的可用性。
    pub name: String,
    /// 完整可执行路径（如 "/usr/bin/chrome"），来自 `/proc/<pid>/exe`
    /// 获取失败时为 None
    pub path: Option<String>,
}

/// 网络协议类型（用于查找 /proc/net/{tcp,udp} 表）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetProtocol {
    Tcp,
    Udp,
}

/// 进程查找的公共入口
pub struct ProcessResolver {
    #[cfg(target_os = "linux")]
    cache: RwLock<lru::LruCache<CacheKey, (ProcessInfo, Instant)>>,
    /// 缓存 TTL：相同五元组在 TTL 内复用结果（仅 Linux 缓存路径使用）
    #[cfg(target_os = "linux")]
    ttl: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct CacheKey {
    src: SocketAddr,
    dst: SocketAddr,
    proto: NetProtocol,
}

impl Default for ProcessResolver {
    fn default() -> Self {
        Self::new(Duration::from_secs(5))
    }
}

impl ProcessResolver {
    pub fn new(ttl: Duration) -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                cache: RwLock::new(lru::LruCache::new(
                    std::num::NonZeroUsize::new(1024).unwrap(),
                )),
                ttl,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ttl; // 非 Linux 无缓存路径，TTL 不使用（保持 API 一致）
            Self {}
        }
    }

    /// 查找指定连接对应的本地进程信息。
    ///
    /// - `src`：连接的**本地**地址（即客户端的真实地址，不是 reflex 监听的 0.0.0.0）
    /// - `dst`：连接的**远端**地址（即目标地址）
    /// - `proto`：TCP 或 UDP
    ///
    /// 返回 None 表示未找到（不支持的平台、/proc 读取失败、缓存未命中且查不到）。
    pub async fn lookup(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        proto: NetProtocol,
    ) -> Option<ProcessInfo> {
        let key = CacheKey { src, dst, proto };

        // 先查缓存
        #[cfg(target_os = "linux")]
        {
            {
                let mut cache = self.cache.write().await;
                if let Some((info, ts)) = cache.get(&key) {
                    if ts.elapsed() < self.ttl {
                        return Some(info.clone());
                    }
                    // 过期，从缓存移除并重新查找
                    cache.pop(&key);
                }
            }

            // 查找：放在 spawn_blocking 里，避免阻塞异步运行时
            let info = tokio::task::spawn_blocking(move || lookup_proc_linux(&src, &proto))
                .await
                .ok()
                .flatten()?;

            // 写回缓存
            let mut cache = self.cache.write().await;
            cache.put(key, (info.clone(), Instant::now()));

            Some(info)
        }

        #[cfg(not(target_os = "linux"))]
        {
            // 非 Linux 平台暂不支持进程查找
            let _ = (src, dst, proto, key);
            None
        }
    }
}

// ── Linux 实现 ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn lookup_proc_linux(local: &SocketAddr, proto: &NetProtocol) -> Option<ProcessInfo> {
    // 1. 从 /proc/net/{tcp,tcp6,udp,udp6} 找到匹配 local_address 的 inode
    let inode = find_inode_in_proc_net(local, proto)?;

    // 2. 遍历 /proc/<pid>/fd/* 找到引用该 inode 的进程
    let pid = find_pid_by_inode(inode)?;

    // 3. 读 /proc/<pid>/exe 取完整路径（可能因权限不足失败，所以是 Option）
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());

    // 4. 进程名 = exe 路径的 basename（对齐 sing-box filepath.Base(ProcessPath)）。
    //    路径不可读时回退到 /proc/<pid>/comm（被内核截断到 15 字节，仅作兜底）。
    let name = path
        .as_ref()
        .and_then(|p| {
            std::path::Path::new(p)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|s| s.trim_end_matches('\n').to_string())
                .unwrap_or_default()
        });

    Some(ProcessInfo { name, path })
}

#[cfg(target_os = "linux")]
fn find_inode_in_proc_net(local: &SocketAddr, proto: &NetProtocol) -> Option<u64> {
    let path = match (proto, local) {
        (NetProtocol::Tcp, SocketAddr::V4(_)) => "/proc/net/tcp",
        (NetProtocol::Tcp, SocketAddr::V6(_)) => "/proc/net/tcp6",
        (NetProtocol::Udp, SocketAddr::V4(_)) => "/proc/net/udp",
        (NetProtocol::Udp, SocketAddr::V6(_)) => "/proc/net/udp6",
    };

    let content = std::fs::read_to_string(path).ok()?;
    let target = format_local_addr_for_proc(local);

    // /proc/net/tcp 格式（每行）：
    //   sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ...
    //   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 ...
    // local_address 是 little-endian hex（IPv4）或 32 字符 hex（IPv6）
    for line in content.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let _sl = parts.next()?; // 序号
        let local_field = parts.next()?;
        if local_field.eq_ignore_ascii_case(&target) {
            // 跳过 rem_address / st / tx_queue:rx_queue / tr:tm->when / retrnsmt / uid / timeout
            for _ in 0..6 {
                parts.next()?;
            }
            let inode_str = parts.next()?;
            return inode_str.parse::<u64>().ok();
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn format_local_addr_for_proc(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => {
            // IPv4：4 字节 little-endian hex + ':' + port big-endian hex
            let octets = v4.ip().octets();
            format!(
                "{:02X}{:02X}{:02X}{:02X}:{:04X}",
                octets[3],
                octets[2],
                octets[1],
                octets[0],
                v4.port()
            )
        }
        SocketAddr::V6(v6) => {
            // IPv6：16 字节 little-endian hex（32 字符）+ ':' + port big-endian hex
            let octets = v6.ip().octets();
            let mut hex = String::with_capacity(32);
            for chunk in octets.as_chunks::<4>().0 {
                // 每个 32-bit word little-endian
                hex.push_str(&format!(
                    "{:02X}{:02X}{:02X}{:02X}",
                    chunk[3], chunk[2], chunk[1], chunk[0]
                ));
            }
            format!("{hex}:{:04X}", v6.port())
        }
    }
}

#[cfg(target_os = "linux")]
fn find_pid_by_inode(inode: u64) -> Option<u32> {
    let proc_dir = std::fs::read_dir("/proc").ok()?;
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // 遍历 /proc/<pid>/fd/*
        let fd_dir = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for fd_entry in fd_dir.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                // socket:[<inode>]
                let link_str = link.to_string_lossy();
                if let Some(rest) = link_str.strip_prefix("socket:[") {
                    if let Some(end) = rest.strip_suffix(']') {
                        if let Ok(entry_inode) = end.parse::<u64>() {
                            if entry_inode == inode {
                                return Some(pid);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// ── 测试 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn format_ipv4_addr_for_proc() {
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let formatted = format_local_addr_for_proc(&addr);
        // 127.0.0.1 → 0100007F，8080 → 1F90
        assert_eq!(formatted, "0100007F:1F90");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn format_ipv6_loopback_for_proc() {
        let addr: SocketAddr = "[::1]:53".parse().unwrap();
        let formatted = format_local_addr_for_proc(&addr);
        // ::1 → 16 字节，唯一非零字节是最后 1 字节=0x01，word 0..3 全 0
        // little-endian：每 word 4 字节倒序，所以 hex 是 00000000 ×3 + 01000000
        assert!(formatted.starts_with("00000000000000000000000001000000:0035"));
    }

    #[tokio::test]
    async fn resolver_does_not_panic_on_unsupported_platform() {
        let resolver = ProcessResolver::default();
        // 在非 Linux 平台上应返回 None
        let result = resolver
            .lookup(
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:9090".parse().unwrap(),
                NetProtocol::Tcp,
            )
            .await;
        #[cfg(target_os = "linux")]
        {
            // Linux 上可能找到也可能找不到（取决于测试运行环境），但不应 panic
            let _ = result;
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(result.is_none());
        }
    }
}
