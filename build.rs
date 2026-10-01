use std::env;
use std::path::Path;
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

    embed_bpf_objects();
}

/// 调用 `rustc -v` 解析 rustc 版本号。
/// 失败时返回 None（main.rs 回退到 "unknown"）。
fn rustc_version() -> Option<String> {
    let out = Command::new("rustc").arg("-V").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // 输出形如：`rustc 1.82.0 (f20xxcc...)`
    s.split_whitespace().nth(1).map(|s| s.to_string())
}

// ── eBPF 对象内嵌（类比 Windows 端内置 wintun.dll）─────────────────────────
//
// 构建时在固定位置查找 reflex-bpf 的构建产物（eBPF 对象），找到则通过
// `cargo:rustc-env=REFLEX_EMBEDDED_BPF_*` 交给 `include_bytes!` 编译进
// 二进制。运行时 loader 按目标端序选取 el/eb 版本，`Ebpf::load` 直接从
// 内存装载——不再需要随二进制分发独立的 .o 文件，也无需配置 bpf_object。
//
// 查找顺序（仅 Linux 目标执行；非 Linux 嵌入纯属浪费体积）：
// 1. 环境变量 `REFLEX_BPF_OBJECT_EL` / `REFLEX_BPF_OBJECT_EB`（显式指定）；
// 2. 项目根 `bpf/reflex.bpf.el.o` / `bpf/reflex.bpf.eb.o`（CI 产物约定位置）。
//
// el = little-endian（x86_64 / aarch64），eb = big-endian（mips 等）。
// 两者独立查找、独立嵌入：只放一个文件也允许构建（另一端序运行时报错）。
// 未找到时保持静默——loader 运行时对缺省 bpf_object 给出明确报错，
// 不影响非 ebpf 场景的构建。
fn embed_bpf_objects() {
    // 自定义 cfg 声明，避免 unexpected_cfgs lint（Rust 1.80+）。
    println!("cargo::rustc-check-cfg=cfg(reflex_embedded_bpf_el)");
    println!("cargo::rustc-check-cfg=cfg(reflex_embedded_bpf_eb)");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    embed_one(
        "REFLEX_BPF_OBJECT_EL",
        "REFLEX_EMBEDDED_BPF_EL",
        "reflex_embedded_bpf_el",
        "bpf/reflex.bpf.el.o",
    );
    embed_one(
        "REFLEX_BPF_OBJECT_EB",
        "REFLEX_EMBEDDED_BPF_EB",
        "reflex_embedded_bpf_eb",
        "bpf/reflex.bpf.eb.o",
    );
}

/// 查找单个 bpf 对象并登记内嵌：命中即输出 rustc-env + rustc-cfg。
fn embed_one(env_var: &str, embed_env: &str, cfg_name: &str, default_rel: &str) {
    println!("cargo:rerun-if-env-changed={env_var}");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let candidates = [
        env::var(env_var).ok(),
        Some(
            Path::new(&manifest_dir)
                .join(default_rel)
                .to_string_lossy()
                .into_owned(),
        ),
    ];
    let Some(path) = candidates.into_iter().flatten().find(|p| Path::new(p).is_file())
    else {
        return;
    };

    println!("cargo:rerun-if-changed={path}");
    println!("cargo:rustc-env={embed_env}={path}");
    println!("cargo:rustc-cfg={cfg_name}");
    println!("cargo:warning=reflex: embedding eBPF object: {path}");
}
