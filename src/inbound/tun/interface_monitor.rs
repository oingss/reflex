#![allow(dead_code)]

use std::collections::HashSet;
use tokio::sync::Mutex;
use tracing::info;

static INTERFACE_MONITOR: once_cell::sync::Lazy<Mutex<InterfaceMonitorInner>> =
    once_cell::sync::Lazy::new(|| Mutex::new(InterfaceMonitorInner::default()));

#[derive(Default)]
#[allow(clippy::type_complexity)]
struct InterfaceMonitorInner {
    callbacks: Vec<(usize, Box<dyn Fn(&InterfaceEvent) + Send + Sync>)>,
    next_id: usize,
    task_running: bool,
}

/// 接口事件。
#[derive(Debug, Clone)]
pub struct InterfaceEvent {
    pub name: String,
    pub index: u32,
    pub up: bool,
    pub mtu: u32,
    pub addresses: Vec<std::net::IpAddr>,
    /// Android：系统 VPN 是否启用（通过 0x20000 fwmark 检测）。
    #[cfg(target_os = "android")]
    pub android_vpn_enabled: bool,
}

/// 注册接口变更回调。返回回调 ID，可用于取消注册。
pub async fn register<F>(cb: F) -> usize
where
    F: Fn(&InterfaceEvent) + Send + Sync + 'static,
{
    let mut monitor = INTERFACE_MONITOR.lock().await;
    let id = monitor.next_id;
    monitor.next_id += 1;
    monitor.callbacks.push((id, Box::new(cb)));

    if !monitor.task_running {
        monitor.task_running = true;
        tokio::spawn(monitor_task());
    }

    id
}

/// 取消注册回调。
pub async fn unregister(id: usize) {
    let mut monitor = INTERFACE_MONITOR.lock().await;
    monitor.callbacks.retain(|(i, _)| *i != id);
}

/// 手动触发接口扫描（通常在路由更新时调用）。
pub async fn scan_and_notify() {
    let events = scan_interfaces();
    let monitor = INTERFACE_MONITOR.lock().await;
    for event in &events {
        for (_, cb) in &monitor.callbacks {
            cb(event);
        }
    }
}

// ── 平台相关的监控实现 ────────────────────────────────────────────────────────

/// 扫描当前所有网络接口。
fn scan_interfaces() -> Vec<InterfaceEvent> {
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(unused_mut))]
    let mut events = Vec::new();

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let index = read_uint_file(&entry.path().join("ifindex")).unwrap_or(0) as u32;
                let up = read_string_file(&entry.path().join("operstate"))
                    .map(|s| s.trim() == "up")
                    .unwrap_or(false);
                let mtu = read_uint_file(&entry.path().join("mtu")).unwrap_or(1500) as u32;
                let addresses = Vec::new();

                events.push(InterfaceEvent {
                    name,
                    index,
                    up,
                    mtu,
                    addresses,
                    #[cfg(target_os = "android")]
                    android_vpn_enabled: check_android_vpn_active(),
                });
            }
        }

        #[cfg(target_os = "android")]
        // Android: 额外添加虚拟 VPN 状态事件
        if !events.iter().any(|e| e.name == "__android_vpn__") {
            events.push(InterfaceEvent {
                name: "__android_vpn__".to_string(),
                index: 0,
                up: false,
                mtu: 0,
                addresses: vec![],
                android_vpn_enabled: check_android_vpn_active(),
            });
        }
    }

    events
}

/// Android：检测系统 VPN 是否启用（通过 0x20000 fwmark 规则）。
#[cfg(target_os = "android")]
fn check_android_vpn_active() -> bool {
    use std::process::Command;
    let out = Command::new("ip").args(["rule", "show"]).output().ok();
    match out {
        Some(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout
                .lines()
                .any(|line| line.contains("fwmark") && line.contains("0x20000"))
        }
        _ => false,
    }
}

/// 比较两组接口事件，返回新增、移除、变更的事件。
pub fn diff_events(old: &[InterfaceEvent], new: &[InterfaceEvent]) -> Vec<InterfaceEvent> {
    let old_set: HashSet<&str> = old.iter().map(|e| e.name.as_str()).collect();
    let new_set: HashSet<&str> = new.iter().map(|e| e.name.as_str()).collect();

    let mut changes = Vec::new();

    for event in new {
        if !old_set.contains(event.name.as_str()) {
            changes.push(event.clone());
        } else if let Some(old_event) = old.iter().find(|e| e.name == event.name) {
            if old_event.up != event.up || old_event.mtu != event.mtu {
                changes.push(event.clone());
            }
        }
    }

    for event in old {
        if !new_set.contains(event.name.as_str()) {
            let mut removed = event.clone();
            removed.up = false;
            changes.push(removed);
        }
    }

    changes
}

/// 监控后台任务。
async fn monitor_task() {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    let mut last_events: Vec<InterfaceEvent> = Vec::new();

    info!("interface monitor: started (polling every 5s)");

    loop {
        interval.tick().await;
        let current = scan_interfaces();

        // 检查是否有变化（简化为全部重新通知）
        let changed = if last_events.len() != current.len() {
            true
        } else {
            last_events
                .iter()
                .zip(current.iter())
                .any(|(a, b)| a.up != b.up || a.name != b.name || a.mtu != b.mtu)
        };

        if changed {
            let monitor = INTERFACE_MONITOR.lock().await;
            for event in &current {
                for (_, cb) in &monitor.callbacks {
                    cb(event);
                }
            }
            last_events = current;
        }
    }
}

// ── 文件辅助 ──────────────────────────────────────────────────────────────────

fn read_uint_file(path: &std::path::Path) -> Option<u64> {
    let content = std::fs::read_to_string(path).ok()?;
    content.trim().parse().ok()
}

fn read_string_file(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}
