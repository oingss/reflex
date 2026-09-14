//! 全局优雅关闭信号（Ctrl+C / SIGTERM → 任务自然退出 → 各自执行清理）。
//!
//! 此前 main 收到信号后直接返回，`App`（JoinSet）被 drop 时 **abort 所有任务**
//! ——TUN 运行任务的清理代码（`platform::teardown`：删除 auto_route 路由、
//! 恢复接口 DNS、关闭 WFP 会话）位于任务循环之后，永远没有机会执行。
//! Windows 上的表现为：进程退出后路由/WFP 状态全部残留，网络瘫痪直到手动
//! 重启或手动清路由。现在长运行任务 `subscribe()` 后在主循环上 `select`
//! 关闭信号，信号到达 → 循环 break → 任务自然收尾（含 teardown）→ main
//! 在宽限期（5s）内 `app.wait()` 等它们全部退出。

use tokio::sync::watch;
use std::sync::OnceLock;

static TX: OnceLock<watch::Sender<bool>> = OnceLock::new();
static RX: OnceLock<watch::Receiver<bool>> = OnceLock::new();

fn ensure_init() -> (&'static watch::Sender<bool>, &'static watch::Receiver<bool>) {
    if let (Some(tx), Some(rx)) = (TX.get(), RX.get()) {
        return (tx, rx);
    }
    let (tx, rx) = watch::channel(false);
    // set 可能与其他线程竞争失败，失败时以已注册的一侧为准
    let _ = TX.set(tx);
    let _ = RX.set(rx.clone());
    (TX.get().expect("shutdown TX"), RX.get().expect("shutdown RX"))
}

/// 初始化（幂等）。main 启动时调用一次；`subscribe` 内部也会兜底初始化。
pub fn init() {
    ensure_init();
}

/// 广播关闭信号（幂等，重复调用无副作用）。
pub fn signal() {
    let (tx, _) = ensure_init();
    tx.send_if_modified(|v| {
        let changed = !*v;
        *v = true;
        changed
    });
}

/// 订阅关闭信号。搭配 [`wait_shutdown`] 使用。
pub fn subscribe() -> watch::Receiver<bool> {
    let (_, rx) = ensure_init();
    rx.clone()
}

/// 等待关闭信号：若信号已发出（含订阅前已发出的情况）立即返回，
/// 否则挂起直到 `signal()` 被调用。select 分支里直接用。
pub async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    if *rx.borrow_and_update() {
        return;
    }
    // 静态 sender 与进程同生命周期，不会 drop，这里只会因 signal() 返回
    let _ = rx.changed().await;
}

/// 当前是否已处于关闭状态（非阻塞查询）。
pub fn is_shutdown() -> bool {
    let (_, rx) = ensure_init();
    *rx.borrow()
}
