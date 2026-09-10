use std::process::Command;

fn main() {
    // 设置 rerun-if-changed 让 build script 在 Cargo.toml 变更时重新执行
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");

    // 获取 rustc 版本号
    if let Some(ver) = rustc_version() {
        println!("cargo:rustc-env=REFLEX_RUSTC_VERSION={ver}");
    }

    // 编译时刻（UTC RFC3339）
    let now = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=REFLEX_BUILD_TIME={now}");
}

/// 调用 `rustc -v` 解析 rustc 版本号。
/// 失败时返回 None（main.rs 回退到 "unknown"）。
fn rustc_version() -> Option<String> {
    let out = Command::new("rustc").arg("-V").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // 输出形如：`rustc 1.82.0 (f20xxcc...)
    s.split_whitespace().nth(1).map(|s| s.to_string())
}
