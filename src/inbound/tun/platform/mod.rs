//! 平台相关的 TUN auto_route / strict_route 原生实现。
//!
//! Linux: rtnetlink 直连 + nftables autoRedirect + 接口监控
//! macOS: AF_ROUTE socket 原生操作
//! Windows: WFP WinAPI + winipcfg
//! Android: VPN 框架 + iptables + 包名→UID 映射
//! 其他: 存根

use crate::config::inbound::TunInboundConfig;

/// Setup 返回值，供 teardown 精确清理。
#[derive(Debug, Default)]
pub struct SetupState {
    pub routes_v4: Vec<String>,
    pub routes_v6: Vec<String>,
    pub rule_priorities: Vec<u32>,
    pub wfp_session: usize,
    pub monitor_id: usize,
}

pub async fn setup(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    #[cfg(target_os = "android")]
    return android::setup(cfg, if_name).await;

    #[cfg(target_os = "linux")]
    return linux::setup(cfg, if_name).await;

    #[cfg(target_os = "macos")]
    return macos::setup(cfg, if_name);

    #[cfg(target_os = "windows")]
    return windows::setup(cfg, if_name);

    #[cfg(not(any(target_os = "android", target_os = "linux", target_os = "macos", target_os = "windows")))]
    stub::setup(cfg, if_name)
}

pub async fn teardown(cfg: &TunInboundConfig, if_name: &str, state: &SetupState) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    return android::teardown(cfg, if_name, state).await;

    #[cfg(target_os = "linux")]
    return linux::teardown(cfg, if_name, state).await;

    #[cfg(target_os = "macos")]
    return macos::teardown(cfg, if_name, state);

    #[cfg(target_os = "windows")]
    return windows::teardown(cfg, if_name, state);

    #[cfg(not(any(target_os = "android", target_os = "linux", target_os = "macos", target_os = "windows")))]
    stub::teardown(cfg, if_name, state)
}

// ── Windows 帮助函数 ─────────────────────────────────────────────────────────
// 由 mod.rs 主 TUN 流程调用。条件编译确保只有 Windows 平台可调用。

#[cfg(target_os = "windows")]
pub use windows::resolve_actual_interface_name;

#[cfg(target_os = "windows")]
pub use windows::wait_for_tun_address;

// ── Android 帮助函数 ──────────────────────────────────────────────────────────
// TUN 设备路径 /dev/tun 及接口名解析。

#[cfg(target_os = "android")]
pub use android::resolve_tun_interface;

#[allow(unreachable_code)]
pub fn update_routes(cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    return android::update_routes(cfg, if_name);

    #[cfg(target_os = "linux")]
    return linux::update_routes(cfg, if_name);

    #[cfg(target_os = "windows")]
    return windows::update_routes(cfg, if_name);

    Ok(())
}

// ── 子模块 ──────────────────────────────────────────────────────────────────

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(not(any(target_os = "android", target_os = "linux", target_os = "macos", target_os = "windows")))]
mod stub;
