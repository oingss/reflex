use anyhow::Context as _;
use reflex::app::App;
use reflex::config::log::LogLevel;
use std::{
    env, fs,
    net::IpAddr,
    process,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
};
use tracing::{info, warn};

use reflex::ruleset::{AdGuardConvertReport, CompiledRuleSet, LoadedRuleSet, MatchTarget, RuleSet};

// 分配器选择：tikv-jemallocator 在 Windows 端不可用（需要特殊构建的 jemalloc C 库，
// MSVC/GNU 工具链下构建与运行均有兼容性问题），Windows 端改用 mimalloc；
// 其余平台仍用 jemalloc。
// Windows 上两条构建路径都能拿到 mimalloc：默认 feature（jemalloc 在
// Windows 下自动换用 mimalloc）或 win.yml 的 --features mimalloc。
#[cfg(all(target_os = "windows", any(feature = "jemalloc", feature = "mimalloc")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(unix)]
fn raise_nofile_limit() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 {
            let target = rl.rlim_max.min(1 << 20);
            if rl.rlim_cur < target {
                rl.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &rl) != 0 {
                    let e = std::io::Error::last_os_error();
                    eprintln!("[warn] setrlimit RLIMIT_NOFILE failed: {e}");
                }
            }
        }
    }
}

fn parse_output_flag(args: &[String]) -> anyhow::Result<Option<String>> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "-o" {
            return Ok(Some(
                iter.next()
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("'-o' requires an argument"))?,
            ));
        }
        if let Some(val) = a.strip_prefix("-o=") {
            return Ok(Some(val.to_string()));
        }
    }
    Ok(None)
}

fn default_output_path(input: &str) -> String {
    let path = std::path::Path::new(input);
    path.with_extension("rrs").to_string_lossy().into_owned()
}

fn parse_type_flag(args: &[String]) -> anyhow::Result<Option<String>> {
    let mut iter = args.iter().peekable();
    while let Some(a) = iter.next() {
        if a == "-t" || a == "--type" {
            return Ok(Some(iter.next().cloned().ok_or_else(|| {
                anyhow::anyhow!("'-t/--type' requires an argument")
            })?));
        }
        if let Some(val) = a.strip_prefix("-t=") {
            return Ok(Some(val.to_string()));
        }
        if let Some(val) = a.strip_prefix("--type=") {
            return Ok(Some(val.to_string()));
        }
    }
    Ok(None)
}

/// 打印 AdGuardHome/AdBlock 转换统计信息（解析行数 / 跳过行数）。
fn print_adguard_report(report: &AdGuardConvertReport) {
    if report.ignored_lines > 0 {
        eprintln!(
            "[adguard] parsed {}/{} lines ({} unsupported lines skipped: exceptions/cosmetic/path rules etc.)",
            report.total_lines - report.ignored_lines,
            report.total_lines,
            report.ignored_lines
        );
    }
}

fn cmd_ruleset(args: &[String]) -> anyhow::Result<()> {
    // args[0] == "ruleset"/"rs", args[1] == input, rest contains -o / -t
    if args.len() < 2 {
        eprintln!(
            "usage: reflex ruleset <input.yaml|input.json|input.txt> [-o <output.rrs>] [-t adguard|yaml]"
        );
        eprintln!(
            "       reflex rs <input> [-o <output.rrs>] [-t adguard|yaml]  (rs = ruleset 简写)"
        );
        process::exit(1);
    }
    let input = &args[1];
    let rest = &args[2..];
    let output = parse_output_flag(rest)?.unwrap_or_else(|| default_output_path(input));
    let forced_type = parse_type_flag(rest)?;

    let src =
        fs::read_to_string(input).map_err(|e| anyhow::anyhow!("cannot read '{}': {}", input, e))?;

    let compiled = match forced_type.as_deref() {
        // 显式指定 -t adguard：按 AdGuardHome / AdBlock 风格解析
        Some("adguard") => {
            let report = CompiledRuleSet::from_adguard_text(&src)?;
            print_adguard_report(&report);
            report.ruleset
        }
        // 显式指定 -t yaml：按 mihomo / Clash yaml 规则集解析
        // 可附加 :behavior，例如 `-t yaml:domain` / `-t yaml:ipcidr` / `-t yaml:classical`
        Some(t) if t == "yaml" || t.starts_with("yaml:") => {
            let behavior = t.strip_prefix("yaml:").and_then(|s| {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            });
            CompiledRuleSet::from_mihomo_yaml(&src, behavior)?
        }
        Some(other) => {
            return Err(anyhow::anyhow!(
                "unsupported source type '{}': available: adguard, yaml[:behavior]",
                other
            ));
        }
        None => {
            let ext = lowercase_extension(input);
            match ext.as_deref() {
                // .json → sing-box rule-set（Source Rule Set）
                Some("json") => CompiledRuleSet::from_singbox_json(&src)?,
                // .yaml / .yml → mihomo / Clash `payload:` 规则集
                Some("yaml") | Some("yml") => CompiledRuleSet::from_mihomo_yaml(&src, None)?,
                // .txt → AdGuardHome / AdBlock 风格过滤规则
                Some("txt") => {
                    let report = CompiledRuleSet::from_adguard_text(&src)?;
                    print_adguard_report(&report);
                    report.ruleset
                }
                // 扩展名缺失或不是上述三种：回退到原有的内容嗅探逻辑
                _ => {
                    if src.trim_start().starts_with('{') {
                        CompiledRuleSet::from_singbox_json(&src)?
                    } else if looks_like_mihomo_yaml(&src) {
                        CompiledRuleSet::from_mihomo_yaml(&src, None)?
                    } else {
                        match CompiledRuleSet::from_text(&src) {
                            Ok(c) => c,
                            Err(_) => {
                                eprintln!(
                                    "[info] '{}' 不是 reflex 原生文本规则格式，按 AdGuardHome/AdBlock 规则解析",
                                    input
                                );
                                let report = CompiledRuleSet::from_adguard_text(&src)?;
                                print_adguard_report(&report);
                                report.ruleset
                            }
                        }
                    }
                }
            }
        }
    };

    let total = compiled.total_entries();
    let mut buf = Vec::new();
    compiled.serialize(&mut buf)?;
    fs::write(&output, &buf)?;

    println!(
        "compiled {} entries → {} ({} bytes)",
        total,
        output,
        buf.len()
    );
    Ok(())
}

fn looks_like_mihomo_yaml(src: &str) -> bool {
    let first_line = src.trim_start().lines().next().unwrap_or("");
    let lower = first_line.to_ascii_lowercase();
    lower.starts_with("payload:") || lower.starts_with("payload :")
}

/// 取文件名的小写扩展名（不含点），例如 "geosite-ads.YAML" → Some("yaml")。
fn lowercase_extension(input: &str) -> Option<String> {
    std::path::Path::new(input)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
}

/// `reflex inspect <input.rrs>` — 查看二进制规则集统计
fn cmd_inspect(args: &[String]) -> anyhow::Result<()> {
    if args.len() < 2 {
        eprintln!("usage: reflex inspect <input.rrs>");
        process::exit(1);
    }
    let path = &args[1];
    let data = fs::read(path)?;
    let loaded = LoadedRuleSet::from_bytes(&data)?;

    let domain_fst_count = if loaded.domain_fst.is_empty() {
        0
    } else {
        fst::Set::new(loaded.domain_fst.clone())
            .map(|s| s.len())
            .unwrap_or(0)
    };
    let domain_suffix_fst_count = if loaded.domain_suffix_fst.is_empty() {
        0
    } else {
        fst::Set::new(loaded.domain_suffix_fst.clone())
            .map(|s| s.len())
            .unwrap_or(0)
    };

    let domain_count = loaded.domains.len() + domain_fst_count;
    let domain_suffix_count = loaded.domain_suffixes.len() + domain_suffix_fst_count;

    println!("file:            {}", path);
    println!("domains:         {}", domain_count);
    println!("domain-suffixes: {}", domain_suffix_count);
    println!("domain-keywords: {}", loaded.domain_keywords.len());
    println!("domain-regexes:  {}", loaded.domain_regexes.len());
    println!("ipv4-cidrs:      {}", loaded.ipv4_cidrs.len());
    println!("ipv6-cidrs:      {}", loaded.ipv6_cidrs.len());
    println!("ports:           {}", loaded.ports.len());

    let total = domain_count
        + domain_suffix_count
        + loaded.domain_keywords.len()
        + loaded.domain_regexes.len()
        + loaded.ipv4_cidrs.len()
        + loaded.ipv6_cidrs.len()
        + loaded.ports.len();
    println!("total:           {}", total);
    Ok(())
}

/// `reflex test-rule <input.rrs> <domain|ip|port>` — 测试规则集匹配
fn cmd_test_rule(args: &[String]) -> anyhow::Result<()> {
    if args.len() < 3 {
        eprintln!("usage: reflex test-rule <input.rrs> <domain|ip|port>");
        process::exit(1);
    }
    let path = &args[1];
    let query = &args[2];

    let data = fs::read(path)?;
    let loaded = LoadedRuleSet::from_bytes(&data)?;
    let rs = RuleSet::from_loaded(loaded)?;

    let target = parse_match_target(query)?;
    let hit = rs.matches(&target);

    if hit {
        println!("MATCH    {}", query);
    } else {
        println!("NO MATCH {}", query);
    }
    process::exit(if hit { 0 } else { 1 });
}

fn parse_match_target(s: &str) -> anyhow::Result<MatchTarget<'static>> {
    if let Ok(port) = s.parse::<u16>() {
        return Ok(MatchTarget::Port(port));
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(MatchTarget::Ip(ip));
    }
    let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
    Ok(MatchTarget::Domain(leaked))
}

// ── main ───────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    // 首个参数若为子命令则分发，否则走代理运行模式
    if args.len() >= 2 {
        match args[1].as_str() {
            // ── ruleset 编译器子命令（rs 为 ruleset 的简写别名）──────────────
            "ruleset" | "rs" => {
                return cmd_ruleset(&args[1..]);
            }
            "inspect" => {
                return cmd_inspect(&args[1..]);
            }
            "test-rule" => {
                return cmd_test_rule(&args[1..]);
            }
            // ── config 检测子命令 ─────────────────────────────────────────
            "check" => {
                // `reflex check <config.json|config.yaml>`
                // `reflex check -d /etc/reflex`
                let config_path = args.get(2).map(|s| s.as_str()).unwrap_or("config.json");
                return cmd_check(config_path);
            }
            // ── config 格式互转子命令 ────────────────────────────────────
            "convert" => {
                // `reflex convert <input.json|input.yaml> -o <output.yaml|output.json>`
                return cmd_convert(&args[1..]);
            }
            // ── 版本信息子命令 ──────────────────────────────────────────────
            // `reflex version` / `reflex -v` / `reflex --version` 都输出完整版本信息。
            "version" | "-v" | "--version" => {
                print_version();
                return Ok(());
            }
            "run" => {
                return run_proxy(&args[2..]).await;
            }
            _ => {}
        }
    }

    // ── 代理运行模式（无子命令前缀，向后兼容） ──────────────────────────────
    // 例如：`reflex -d /etc/reflex` / `reflex -C config.json`
    run_proxy(&args[1..]).await
}

fn cmd_convert(args: &[String]) -> anyhow::Result<()> {
    use reflex::config::ConfigFormat;

    // args[0] == "convert", args[1] == input, rest contains -o
    if args.len() < 4 {
        eprintln!("usage: reflex convert <input.json|input.yaml> -o <output.yaml|output.json>");
        process::exit(1);
    }
    let input = &args[1];
    let output = parse_output_flag(&args[2..])?
        .ok_or_else(|| anyhow::anyhow!("missing required flag: -o <output.yaml|output.json>"))?;

    let input_path = std::path::Path::new(input);
    let output_path = std::path::Path::new(&output);

    let in_fmt = ConfigFormat::from_path(input_path);
    let out_fmt = ConfigFormat::from_path(output_path);

    if in_fmt == out_fmt {
        eprintln!(
            "[warn] input and output have the same format ({}); \
             conversion is a no-op but will still rewrite the file",
            in_fmt
        );
    }

    // 读入 → 解析为 Config（含校验）→ 按目标格式序列化
    let config = reflex::config::Config::from_file(input_path)?;

    let out_str = match out_fmt {
        ConfigFormat::Json => serde_json::to_string_pretty(&config)
            .map_err(|e| anyhow::anyhow!("JSON serialize error: {e}"))?,
        ConfigFormat::Yaml => serde_yaml::to_string(&config)
            .map_err(|e| anyhow::anyhow!("YAML serialize error: {e}"))?,
    };

    std::fs::write(&output, out_str)?;
    println!(
        "converted {} ({}) → {} ({})",
        input, in_fmt, output, out_fmt
    );
    Ok(())
}

fn cmd_check(config_path: &str) -> anyhow::Result<()> {
    use std::path::Path;
    let path = Path::new(config_path);
    let base_dir = path.parent().unwrap_or(Path::new("."));
    let mut config = reflex::config::Config::from_file(path)?;
    config.resolve_paths(base_dir);
    println!("config OK: {}", config_path);
    Ok(())
}

fn resolve_config_and_base(
    config_arg: Option<String>,
    dir_arg: Option<std::path::PathBuf>,
) -> anyhow::Result<(String, std::path::PathBuf)> {
    use std::path::{Path, PathBuf};

    match (config_arg, dir_arg) {
        // -d 指定了目录，自动在目录里找 config
        (None, Some(dir)) => {
            let config_path = find_config_in_dir(&dir)?;
            Ok((config_path.to_string_lossy().into_owned(), dir))
        }
        // 只有 -c，base_dir = config 所在目录
        (Some(cfg), None) => {
            let p = PathBuf::from(&cfg);
            let base = p
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            Ok((cfg, base))
        }
        // -d 和 -c 都给了：config 路径相对于 base_dir 解析（已是绝对路径则直接用）
        (Some(cfg), Some(dir)) => {
            let p = Path::new(&cfg);
            let resolved = if p.is_absolute() {
                p.to_path_buf()
            } else {
                dir.join(p)
            };
            Ok((resolved.to_string_lossy().into_owned(), dir))
        }
        // 什么都没给：cwd + config.json
        (None, None) => {
            let cwd = std::env::current_dir()?;
            let p = cwd.join("config.json");
            Ok((p.to_string_lossy().into_owned(), cwd))
        }
    }
}

fn find_config_in_dir(dir: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    for name in &["config.json", "config.yaml"] {
        let p = dir.join(name);
        if p.is_file() {
            return Ok(p);
        }
    }

    let mut json_files = Vec::new();
    let mut yaml_files = Vec::new();
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read directory '{}'", dir.display()))?;
    for entry in entries {
        let p = entry?.path();
        if !p.is_file() {
            continue;
        }
        match p.extension().and_then(|e| e.to_str()) {
            Some("json") => json_files.push(p),
            Some("yaml") | Some("yml") => yaml_files.push(p),
            _ => {}
        }
    }

    if json_files.len() == 1 {
        return Ok(json_files.into_iter().next().unwrap());
    }
    if json_files.is_empty() && yaml_files.len() == 1 {
        return Ok(yaml_files.into_iter().next().unwrap());
    }

    let total = json_files.len() + yaml_files.len();
    if total == 0 {
        anyhow::bail!(
            "no config file (.json/.yaml/.yml) found in '{}'",
            dir.display()
        );
    }
    anyhow::bail!(
        "multiple config files found in '{}' ({} .json + {} .yaml/.yml) and no config.json/config.yaml; \
         please specify the file explicitly with -c",
        dir.display(),
        json_files.len(),
        yaml_files.len()
    );
}

async fn run_proxy(args: &[String]) -> anyhow::Result<()> {
    use std::path::PathBuf;

    #[cfg(unix)]
    raise_nofile_limit();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let mut config_path: Option<String> = None;
    let mut base_dir: Option<PathBuf> = None;
    let mut log_level = None::<String>;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" | "-C" => {
                i += 1;
                config_path = args.get(i).cloned();
            }
            "--dir" | "-d" | "-D" => {
                i += 1;
                let dir = args
                    .get(i)
                    .map(PathBuf::from)
                    .ok_or_else(|| anyhow::anyhow!("'-d/-D' requires a directory path"))?;
                if !dir.is_dir() {
                    anyhow::bail!("'{}' is not a directory", dir.display());
                }
                base_dir = Some(dir);
            }
            "--log" | "-l" => {
                i += 1;
                log_level = args.get(i).cloned();
            }
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--version" | "-v" => {
                print_version();
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                process::exit(1);
            }
        }
        i += 1;
    }

    let no_config_flag = config_path.is_none() && base_dir.is_none();
    let (resolved_config, resolved_base) = resolve_config_and_base(config_path, base_dir)?;

    let mut config = if no_config_flag && !std::path::Path::new(&resolved_config).exists() {
        info!(
            "no config file found at {}, starting with default configuration \
             (mixed inbound 127.0.0.1:7890 + direct outbound)",
            resolved_config
        );
        reflex::config::Config::default()
    } else {
        reflex::config::Config::from_file(&resolved_config)?
    };
    config.resolve_paths(&resolved_base);

    let level = if let Some(ref l) = log_level {
        l.as_str()
    } else {
        match config.log.level {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
            LogLevel::Off => "off",
        }
    };
    init_tracing(level);

    info!(version=env!("CARGO_PKG_VERSION"), config=%resolved_config, "reflex starting");

    let app = App::start_with_config(config).await?;

    // 优雅关闭：收到 Ctrl+C/SIGTERM 后广播 shutdown 信号，TUN 等长运行任务
    // 自然退出并执行各自的清理（TUN teardown 会删除 auto_route 路由、恢复
    // 接口 DNS、关闭 WFP 会话）。修复：旧实现在信号到达后立即返回，JoinSet
    // drop 时 abort 全部任务，清理代码永不执行——Windows 上表现为路由残留、
    // 网络瘫痪直到手动重启。
    reflex::app::shutdown::init();
    let mut app_wait = Box::pin(app.wait());
    tokio::select! {
        _ = signal_shutdown() => {
            info!("shutdown signal received, waiting for graceful teardown");
            reflex::app::shutdown::signal();
            // Windows 上 teardown 通过 powershell/netsh/ipconfig 子进程清理
            // 路由/WFP/DNS，PowerShell 冷启动 1-3s，多次 netsh 累积可达 5-10s+。
            // 旧的 5s grace 不够，超时后进程退出会强制中断 teardown → 路由残留。
            // 放大到 30s 确保 blocking 线程上的清理完整执行（teardown 已通过
            // spawn_blocking 移出 async worker，不会阻塞其他任务退出）。
            const GRACE: std::time::Duration = std::time::Duration::from_secs(30);
            match tokio::time::timeout(GRACE, &mut app_wait).await {
                Ok(_) => info!("all tasks exited gracefully"),
                Err(_) => warn!(
                    timeout_secs = GRACE.as_secs(),
                    "graceful shutdown timed out; aborting remaining tasks"
                ),
            }
        }
        r = &mut app_wait => {
            info!("all tasks exited");
            if let Err(e) = r {
                tracing::error!(err = %e, "app exited with error");
            }
        }
    }
    Ok(())
}

fn init_tracing(level: &str) {
    use std::sync::OnceLock;
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let max = match level {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "warn" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            "off" => {
                tracing::subscriber::set_global_default(
                    tracing::subscriber::NoSubscriber::default(),
                )
                .ok();
                return;
            }
            _ => tracing::Level::INFO,
        };
        // max_level 用 Arc<AtomicU8> 存储以支持运行时热改（PATCH /configs 的
        // "log-level" 字段）；level_to_u8 / u8_to_level 是无损双向映射。
        let atomic = Arc::new(AtomicU8::new(level_to_u8(max)));
        // 注册到 lib crate 的全局 OnceLock，ClashApi::new 时取引用以原子方式更新。
        reflex::app::clash_api::set_global_log_level_handle(atomic.clone());
        tracing::subscriber::set_global_default(SimpleSubscriber { max_level: atomic }).ok();
    });
}

/// tracing::Level ↔ u8 无损映射（顺序按 ERROR < WARN < INFO < DEBUG < TRACE）。
fn level_to_u8(l: tracing::Level) -> u8 {
    match l {
        tracing::Level::ERROR => 1,
        tracing::Level::WARN => 2,
        tracing::Level::INFO => 3,
        tracing::Level::DEBUG => 4,
        tracing::Level::TRACE => 5,
    }
}
fn u8_to_level(v: u8) -> tracing::Level {
    match v {
        0 | 1 => tracing::Level::ERROR,
        2 => tracing::Level::WARN,
        3 => tracing::Level::INFO,
        4 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    }
}

struct SimpleSubscriber {
    max_level: Arc<AtomicU8>,
}
impl tracing::Subscriber for SimpleSubscriber {
    fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
        let cur = u8_to_level(self.max_level.load(Ordering::Relaxed));
        m.level() <= &cur
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let meta = event.metadata();
        let mut msg = String::new();
        event.record(&mut SV(&mut msg));
        eprintln!("[{:<5}] {}: {msg}", meta.level(), meta.target());
        let level_str = match *meta.level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warning",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG => "debug",
            tracing::Level::TRACE => "debug",
        };
        reflex::app::clash_api::broadcast_log(level_str, msg);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
struct SV<'a>(&'a mut String);
impl tracing::field::Visit for SV<'_> {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        if f.name() == "message" {
            self.0.push_str(&format!("{v:?}"));
        } else {
            self.0.push_str(&format!(" {}={v:?}", f.name()));
        }
    }
    fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
        if f.name() == "message" {
            self.0.push_str(v);
        } else {
            self.0.push_str(&format!(" {}={v}", f.name()));
        }
    }
}

async fn signal_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut st = signal(SignalKind::terminate()).expect("SIGTERM");
        let mut si = signal(SignalKind::interrupt()).expect("SIGINT");
        tokio::select! { _ = st.recv() => {} _ = si.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.expect("ctrl-c");
    }
}

fn print_version() {
    // 版本行（sing-box 风格：`<name> version <version>`）
    println!("reflex version {}", env!("CARGO_PKG_VERSION"));

    // 空行分隔的环境信息块
    println!();
    println!(
        "Environment: rustc {} {}/{} ({})",
        rustc_version(),
        std::env::consts::OS,
        std::env::consts::ARCH,
        libc_name(),
    );

    // 启用的 Cargo features（便于排查特性相关的编译问题）
    let features = enabled_features();
    if !features.is_empty() {
        println!("Features: {}", features.join(", "));
    }

    // 编译时间戳与 profile（便于区分不同构建产物）
    if let Some(built) = option_env!("REFLEX_BUILD_TIME") {
        println!("Built: {built}");
    }
    println!("Profile: {}", build_profile());
}

/// 返回 rustc 版本字符串（编译期常量，由 build script 或 env 注入；
/// 若未注入则回退到运行时无法获取的占位）。
fn rustc_version() -> &'static str {
    // 优先使用 build script 注入的 REFLEX_RUSTC_VERSION；
    // 回退到编译期内置的 option_env!（CI 可通过 RUSTC_VERSION 环境变量注入）。
    option_env!("REFLEX_RUSTC_VERSION")
        .or_else(|| option_env!("RUSTC_VERSION"))
        .unwrap_or("unknown")
}

fn libc_name() -> &'static str {
    if cfg!(target_env = "musl") {
        "musl"
    } else if cfg!(target_env = "gnu") {
        "glibc"
    } else if cfg!(target_env = "msvc") {
        "msvc"
    } else if cfg!(target_os = "macos") {
        "system"
    } else {
        "unknown"
    }
}

/// 返回当前编译的 cargo profile（debug / release）。
fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

/// 返回本次编译启用的特性列表（按字母序）。
fn enabled_features() -> Vec<&'static str> {
    let mut feats = Vec::new();
    // feature 名仍叫 jemalloc，但 Windows 端实际启用的分配器是 mimalloc
    if cfg!(all(target_os = "windows", any(feature = "jemalloc", feature = "mimalloc"))) {
        feats.push("mimalloc");
    } else if cfg!(feature = "jemalloc") {
        feats.push("jemalloc");
    }
    // 这里只列举影响运行时行为的主要特性；其余未启用的不会出现。
    feats
}

fn print_usage() {
    eprintln!(
        r#"reflex {ver}

PROXY MODE:
  reflex [run] [OPTIONS]
    可选的 `run` 子命令前缀与不带前缀完全等价（`reflex run -d /path` ≡ `reflex -d /path`）。
    -d, -D, --dir <DIR>       working directory; config and relative paths are resolved here
                                 auto-finds config.json, then config.yaml, then the sole
                                 .json / .yaml / .yml file in the directory
    -c, -C, --config <PATH>   config file path (relative to -d if given) [default: config.json]
                                 supported formats: .json (JSONC comments allowed), .yaml, .yml
    -l, --log <LEVEL>         log level (trace/debug/info/warn/error/off)
    -v, --version
    -h, --help

RULESET COMMANDS:
  reflex ruleset <input.yaml|input.json|input.txt> [-o <output.rrs>] [-t adguard|yaml]
  reflex rs      <input.yaml|input.json|input.txt> [-o <output.rrs>] [-t adguard|yaml]
        (rs 是 ruleset 的简写别名，二者完全等价)
        Compile a mihomo/Clash yaml rule-set, sing-box JSON rule-set,
        reflex text rule-set, or AdGuardHome/AdBlock-style .txt filter
        list to binary .rrs.
        Format auto-detected from file extension (.yaml/.yml/.json/.txt);
        use -t yaml[:behavior] or -t adguard to force it.
        -o is optional: if omitted, output defaults to the input path
        with its extension replaced by .rrs (same directory, same name).

  reflex check <config.json|config.yaml>
        Validate config file without starting the proxy

  reflex convert <input.json|input.yaml> -o <output.yaml|output.json>
        Convert config between JSON and YAML (format inferred from extension)
        JSON → YAML loses comments (JSON has no native comments);
        YAML → JSON also loses comments (JSON has no native comments).

  reflex inspect <input.rrs>
        Show statistics of a compiled .rrs binary

  reflex test-rule <input.rrs> <domain|ip|port>
        Test whether a query matches a compiled rule set

EXAMPLES:
  reflex -d /etc/reflex                   # auto-find config in /etc/reflex/
  reflex run -d /etc/reflex               # 同上（显式 run 子命令）
  reflex -d /etc/reflex -c myconf.yaml    # use /etc/reflex/myconf.yaml
  reflex -D /etc/reflex -C myconf.yaml    # 同上（大写别名）
  reflex -c /etc/reflex/config.json       # absolute config path
  reflex run -C xx.json                   # 等价于 reflex -c xx.json
  reflex ruleset geosite-cn.json -o rules/geosite-cn.rrs
  reflex ruleset rules/cn.txt    -o rules/cn.rrs
  reflex ruleset adguard-base.txt -o rules/adguard-base.rrs -t adguard
  reflex ruleset geosite-ads.yaml          # 等价于 -o geosite-ads.rrs
  reflex rs geosite-ads.yaml               # rs 与 ruleset 完全等价
  reflex check   config.yaml
  reflex convert config.json -o config.yaml
  reflex convert config.yaml -o config.json
  reflex inspect rules/geosite-cn.rrs
  reflex test-rule rules/geosite-cn.rrs www.baidu.com
"#,
        ver = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// 最小可用的 JSON 配置（无 `//` 注释，便于往返比较）。
    const MINIMAL_JSON: &str = r#"{
  "inbounds": [
    { "type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 7890 }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block"  }
  ],
  "route": { "final": "direct", "rules": [], "rule_set": [] }
}"#;

    /// `reflex convert a.json -o b.yaml` 应成功生成可被 `Config::from_file` 读回的 YAML。
    #[test]
    fn convert_json_to_yaml_roundtrips() {
        let dir = tempdir().unwrap();
        let json_path = dir.path().join("in.json");
        let yaml_path = dir.path().join("out.yaml");
        fs::write(&json_path, MINIMAL_JSON).unwrap();

        let args = vec![
            "convert".to_string(),
            json_path.to_string_lossy().into_owned(),
            "-o".to_string(),
            yaml_path.to_string_lossy().into_owned(),
        ];
        cmd_convert(&args).expect("json → yaml conversion should succeed");

        // 输出文件存在且可被重新解析
        let cfg = reflex::config::Config::from_file(&yaml_path)
            .expect("converted YAML should be parseable");
        assert_eq!(cfg.outbounds.len(), 2);
        assert_eq!(cfg.inbounds.len(), 1);
    }

    /// JSON → YAML → JSON 应得到语义等价的配置。
    #[test]
    fn convert_json_yaml_json_equivalent() {
        let dir = tempdir().unwrap();
        let j1 = dir.path().join("a.json");
        let y = dir.path().join("b.yaml");
        let j2 = dir.path().join("c.json");
        fs::write(&j1, MINIMAL_JSON).unwrap();

        // JSON → YAML
        cmd_convert(&[
            "convert".into(),
            j1.to_string_lossy().into_owned(),
            "-o".into(),
            y.to_string_lossy().into_owned(),
        ])
        .unwrap();

        // YAML → JSON
        cmd_convert(&[
            "convert".into(),
            y.to_string_lossy().into_owned(),
            "-o".into(),
            j2.to_string_lossy().into_owned(),
        ])
        .unwrap();

        let cfg1 = reflex::config::Config::from_file(&j1).unwrap();
        let cfg2 = reflex::config::Config::from_file(&j2).unwrap();

        // 核心字段等价（不需要逐字节相同，只要语义等价）
        assert_eq!(cfg1.inbounds.len(), cfg2.inbounds.len());
        assert_eq!(cfg1.outbounds.len(), cfg2.outbounds.len());
        assert_eq!(cfg1.outbounds[0].tag(), cfg2.outbounds[0].tag());
        assert_eq!(cfg1.outbounds[1].tag(), cfg2.outbounds[1].tag());
        assert_eq!(cfg1.route.r#final, cfg2.route.r#final);
    }

    /// 输入文件不存在应返回错误（而非 panic）。
    #[test]
    fn convert_nonexistent_input_errors() {
        let dir = tempdir().unwrap();
        let bogus = dir.path().join("does-not-exist.json");
        let out = dir.path().join("out.yaml");

        let args = vec![
            "convert".to_string(),
            bogus.to_string_lossy().into_owned(),
            "-o".into(),
            out.to_string_lossy().into_owned(),
        ];
        let err = cmd_convert(&args).unwrap_err();
        assert!(format!("{err}").contains("failed to read config file"));
    }
}
