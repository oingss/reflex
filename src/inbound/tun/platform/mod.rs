use crate::config::inbound::TunInboundConfig;

/// Setup 返回值，供 teardown 精确清理。
#[derive(Debug, Default, Clone)]
pub struct SetupState {
    pub routes_v4: Vec<String>,
    pub routes_v6: Vec<String>,
    /// Windows：exclude 路由（route_exclude_address，走物理网关 metric=0）。
    /// 记录为 "cidr|gateway" 字符串（NextHop 必须与创建时一致才能删除），
    /// teardown 时精确删除。
    pub exclude_routes_v4: Vec<String>,
    pub exclude_routes_v6: Vec<String>,
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

    #[cfg(not(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    stub::setup(cfg, if_name)
}

pub async fn teardown(
    cfg: &TunInboundConfig,
    if_name: &str,
    state: &SetupState,
) -> anyhow::Result<()> {
    #[cfg(target_os = "android")]
    return android::teardown(cfg, if_name, state).await;

    #[cfg(target_os = "linux")]
    return linux::teardown(cfg, if_name, state).await;

    #[cfg(target_os = "macos")]
    return macos::teardown(cfg, if_name, state);

    // Windows：teardown 是同步函数，内部大量调用 powershell/netsh/ipconfig 子进程
    // （remove_reflex_bypass 两次 PowerShell 冷启动 + 多次 netsh 删路由/WFP/防火墙），
    // 单次 PowerShell 冷启动 1-3s，累积可达 5-10s。直接在 async 上下文调用会
    // 阻塞 tokio worker 线程，导致：① shutdown 信号无法被其他任务 poll；
    // ② main 的 5s grace 超时后 JoinSet abort 无法干净取消（同步代码不响应
    // cancel）；③ 进程退出时 teardown 被强制中断 → 路由/WFP 残留，网络瘫痪。
    // 放到 spawn_blocking 线程池执行，async worker 不被阻塞，await 点可被正常
    // 调度；main 增大 grace period 给 blocking 任务足够时间完成。
    #[cfg(target_os = "windows")]
    #[allow(clippy::needless_return)] // cfg 分支结构需要 return 保持跨平台类型一致
    {
        let cfg = cfg.clone();
        let if_name = if_name.to_string();
        let state = state.clone();
        return tokio::task::spawn_blocking(move || {
            windows::teardown(&cfg, &if_name, &state)
        })
        .await
        .map_err(|e| anyhow::anyhow!("teardown blocking task join error: {e}"))?;
    }

    #[cfg(not(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    stub::teardown(cfg, if_name, state)
}

// ── Windows 帮助函数 ─────────────────────────────────────────────────────────
// 由 mod.rs 主 TUN 流程调用。条件编译确保只有 Windows 平台可调用。

#[cfg(target_os = "windows")]
pub use windows::resolve_actual_interface_name;

#[cfg(target_os = "windows")]
pub use windows::wait_for_tun_address;

#[cfg(target_os = "windows")]
pub use windows::extract_embedded_wintun;

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

    #[cfg(target_os = "macos")]
    return macos::update_routes(cfg, if_name);

    #[cfg(target_os = "windows")]
    return windows::update_routes(cfg, if_name);

    Ok(())
}

/// 查询当前系统默认网关 (v4, v6)。默认路由变化监控用。
#[allow(unreachable_code)]
pub async fn current_default_gateways() -> (Option<std::net::IpAddr>, Option<std::net::IpAddr>) {
    #[cfg(target_os = "android")]
    return android::current_default_gateways().await;

    #[cfg(target_os = "linux")]
    return linux::current_default_gateways().await;

    #[cfg(target_os = "macos")]
    return macos::current_default_gateways().await;

    #[cfg(target_os = "windows")]
    return windows::current_default_gateways().await;

    #[cfg(not(any(
        target_os = "android",
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    stub::current_default_gateways().await
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

#[cfg(not(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos",
    target_os = "windows"
)))]
mod stub;
