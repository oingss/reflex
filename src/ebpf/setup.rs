//! eBPF 内核面启动接线（tproxy 入站内联 `ebpf` 配置）。
//!
//! 由 `App` 启动流程调用（inbound 启动之后，规则集已随 Router 加载完毕）。
//! fail-fast 原则：任何 tproxy 入站声明了 `ebpf` 但环境不满足
//! （非 Linux / 未启用 `ebpf` feature / mark 冲突 / 规则集缺失或非纯 IP /
//! wan 模式缺 `route.default_mark`）时直接返回错误终止启动。
//!
//! 两种部署模式的校验差异：
//!
//! - **lan**（默认）：`interfaces` 必填（tc ingress 挂载点）。
//! - **wan**（本机 / Android）：`interfaces` 忽略；强制要求
//!   `route.default_mark` 非 0（内核 hook 靠它识别 reflex 自身出站连接，
//!   防引流回环），且 tproxy 入站 `routing_mark` 不得与 `default_mark`
//!   相同（出站回环）。

use crate::config::Config;
use crate::ebpf::TProxyListeners;
use crate::router::Router;

/// 检查并启动 eBPF 内核面。无任何 tproxy 入站声明 `ebpf` 时为 no-op。
///
/// `listeners`：tproxy 入站**同步创建**的监听 socket（App 在 spawn 入站前
/// 调 `prepare_listeners()` 得到，同一份句柄已 move 进 run 循环）。声明了
/// `ebpf` 时必须存在——loader 要把监听 fd 写入 `LISTEN_SOCKETS` SOCKMAP，
/// 内核面 `bpf_sk_assign` 交付引流包全靠它。
pub fn setup(
    config: &Config,
    router: &Router,
    listeners: Option<&TProxyListeners>,
) -> anyhow::Result<()> {
    // config::validate 已保证至多一个 tproxy 声明 ebpf。
    let Some((tproxy, cfg)) = config.inbounds.iter().find_map(|ib| match ib {
        crate::config::inbound::InboundConfig::TProxy(c) => {
            c.ebpf.as_ref().map(|e| (c, e))
        }
        _ => None,
    }) else {
        return Ok(());
    };

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    {
        linux_impl::start(tproxy, cfg, config, router, listeners)
    }
    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    {
        let _ = (tproxy, cfg, router, listeners);
        anyhow::bail!(
            "inbound '{}': ebpf 已声明但当前二进制未包含 eBPF 支持：\
             请用 `--features ebpf` 重新构建（Linux）",
            tproxy.tag
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tproxy, cfg, router, listeners);
        anyhow::bail!("inbound '{}': ebpf 仅支持 Linux", tproxy.tag);
    }
}

/// Linux + ebpf feature 下的实际启动逻辑（隔离 aya 相关依赖的导入）。
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux_impl {
    use anyhow::Context;
    use tracing::{error, info, warn};

    use crate::config::inbound::EbpfMode;
    use crate::config::inbound::TProxyInboundConfig;
    use crate::config::inbound::TProxyEbpfConfig;
    use crate::config::Config;
    use crate::ebpf::compiler::KernelRuleset;
    use crate::ebpf::derive_reply_mark;
    use crate::ebpf::TProxyListeners;
    use crate::router::Router;

    pub(super) fn start(
        tproxy: &TProxyInboundConfig,
        cfg: &TProxyEbpfConfig,
        config: &Config,
        router: &Router,
        listeners: Option<&TProxyListeners>,
    ) -> anyhow::Result<()> {
        // ── 1. mark 与模式校验（fwmark 用途冲突 = 策略路由回环风险）────────
        anyhow::ensure!(
            cfg.mark != 0,
            "inbound '{}': ebpf.mark 不能为 0（PROXY 裁决依赖 fwmark 引流）",
            tproxy.tag
        );
        let default_mark = config.route.default_mark.unwrap_or(0);
        anyhow::ensure!(
            default_mark != cfg.mark,
            "inbound '{}': ebpf.mark({}) 与 route.default_mark({}) 冲突：\
             reflex 出站流量会被策略路由回送 local",
            tproxy.tag,
            cfg.mark,
            default_mark
        );
        // wan 模式的 self_mark = reflex 全局出站 mark（route.default_mark，
        // App 启动时 set_global_routing_mark）：内核 hook 读 socket SO_MARK
        // 与之比对识别 reflex 自身连接，防二次引流回环。
        let self_mark = default_mark;
        match cfg.mode {
            EbpfMode::Wan => {
                anyhow::ensure!(
                    self_mark != 0,
                    "inbound '{}': wan 模式要求 route.default_mark 非 0：\
                     内核 hook 用它识别 reflex 自身连接，未配置时无法区分，\
                     只能放行全部流量（预分流失效）",
                    tproxy.tag
                );
                if !cfg.interfaces.is_empty() {
                    warn!(
                        inbound = %tproxy.tag,
                        "wan 模式忽略 ebpf.interfaces（cgroup hook 拦本机 socket，与接口无关）"
                    );
                }
            }
            EbpfMode::Lan => {
                anyhow::ensure!(
                    !cfg.interfaces.is_empty(),
                    "inbound '{}': ebpf.interfaces 不能为空（lan 模式挂载在 LAN 接口 \
                     tc ingress 上；本机/Android 模式请配置 \"mode\": \"wan\"）",
                    tproxy.tag
                );
            }
        }

        // ── 2. 本入站即 PROXY 引流目标：mark 与监听校验 ────────────────────
        let tproxy_mark = if tproxy.routing_mark == 0 {
            config.route.default_mark.unwrap_or(0)
        } else {
            tproxy.routing_mark
        };
        anyhow::ensure!(
            tproxy_mark != cfg.mark,
            "inbound '{}': ebpf.mark({}) 与 routing_mark({}) 冲突",
            tproxy.tag,
            cfg.mark,
            tproxy_mark
        );
        if cfg.mode == EbpfMode::Wan {
            // wan 下 reflex 自身出站 socket 带 self_mark；若 tproxy_mark 与
            // 之相同，出站包会命中策略路由回送 local → 引流回环。lan 下
            // reflex 出站不走挂载接口的 ingress，无此风险，允许 fallback。
            anyhow::ensure!(
                tproxy_mark != self_mark,
                "inbound '{}': wan 模式要求 routing_mark({}) 与 route.default_mark({}) 不同：\
                 相同时 reflex 出站流量会被策略路由回送 local（引流回环）。\
                 请为本 tproxy 入站显式设置独立的 routing_mark",
                tproxy.tag,
                tproxy_mark,
                self_mark
            );
        }
        // wan 模式监听侧回包 mark（listener / UDP writeback socket 的
        // SO_MARK + 第二条 fwmark 策略路由规则 + lo ingress 方向判别）。
        // 透明回环路径上回包目的地址 = 客户端 socket 伪装地址（非本机），
        // 没有专属 mark 规则时回包走主路由表从物理口发出，客户端永远收不到。
        let reply_mark = if cfg.mode == EbpfMode::Wan {
            let rm = cfg.reply_mark.unwrap_or_else(|| derive_reply_mark(cfg.mark));
            anyhow::ensure!(
                rm != 0 && rm != cfg.mark && rm != tproxy_mark && rm != default_mark,
                "inbound '{}': ebpf.reply_mark({rm:#x}) 不能为 0，且不得与 \
                 ebpf.mark({:#x}) / routing_mark({tproxy_mark:#x}) / \
                 route.default_mark({default_mark:#x}) 相同：撞值会破坏 \
                 fwmark 策略路由的方向判别，请显式配置 reply_mark",
                tproxy.tag,
                cfg.mark
            );
            Some(rm)
        } else {
            None
        };
        // eBPF 引流的包目的地址 = 客户端原始目标（IP_TRANSPARENT 才能收），
        // tproxy listener 必须监听通配地址。
        anyhow::ensure!(
            tproxy.listen == "::" || tproxy.listen == "0.0.0.0",
            "inbound '{}': ebpf 引流目标必须监听通配地址（:: 或 0.0.0.0），当前: {}",
            tproxy.tag,
            tproxy.listen
        );

        // ── 3. 解析规则集并编译内核面 ──────────────────────────────────────
        // 规则集已随 Router 加载完毕；只接受纯 IP 规则集（fail-fast）。
        let block = resolve_rulesets(&tproxy.tag, router, &cfg.block_rulesets)?;
        let direct = resolve_rulesets(&tproxy.tag, router, &cfg.direct_rulesets)?;
        // 本机地址必须直连：tc ingress 能抓到发往本机的流量（SSH/管理），
        // 不排除会被 PROXY 判决引流进 tproxy，形成自环（SSH 断连）。
        let local_addrs = crate::ebpf::netlink::collect_local_addrs()?;
        let compiled =
            crate::ebpf::compiler::compile_kernel_plane(&block, &direct, &local_addrs)?;
        info!(
            inbound = %tproxy.tag,
            block_rulesets = compiled.block_rulesets,
            direct_rulesets = compiled.direct_rulesets,
            lpm_entries = compiled.lpm_total,
            local_addrs = local_addrs.len(),
            "eBPF 内核面编译完成（含内置私有网段与本机地址直连）"
        );

        // ── 4. 加载 + 挂载 ───────────────────────────────────────────────
        // 内核面 PROXY 引流 mark = ebpf.mark（cfg.mark），而非 routing_mark/
        // default_mark——后者可能为 0，fwmark 0/0 的策略规则会匹配**所有**
        // 流量，把全机应答包吞进 local 表（SSH/所有端口断连）。
        let listeners = listeners.with_context(|| {
            format!(
                "inbound '{}': ebpf 已声明但未获取 tproxy 监听 socket（App 接线错误，\
                 prepare_listeners 必须先于 ebpf::setup 执行）",
                tproxy.tag
            )
        })?;
        let mut handle = crate::ebpf::loader::start(
            cfg,
            &compiled,
            cfg.mark,
            config.route.hijack_dns,
            self_mark,
            listeners,
            reply_mark,
        )?;

        // ── 5. shutdown 清理任务：tc filter 不随进程退出自动卸载 ─────────
        let mut shutdown_rx = crate::app::shutdown::subscribe();
        tokio::spawn(async move {
            crate::app::shutdown::wait_shutdown(&mut shutdown_rx).await;
            for err in handle.teardown() {
                error!(error = %err, "eBPF teardown 错误");
            }
            info!("eBPF 内核面已卸载");
        });

        Ok(())
    }

    /// 把 ebpf 配置里声明的规则集 tag 解析为已加载的纯 IP 规则集。
    /// fail-fast：tag 不存在 / 含非 IP 条件 / 不含任何 IP 条目均报错。
    fn resolve_rulesets<'a>(
        tproxy_tag: &str,
        router: &'a Router,
        tags: &'a [String],
    ) -> anyhow::Result<Vec<KernelRuleset<'a>>> {
        tags.iter()
            .map(|tag| {
                let rs = router.rulesets.get(tag).with_context(|| {
                    format!(
                        "inbound '{tproxy_tag}': ebpf 规则集 '{tag}' 未在 route.rule_set 中声明或加载失败"
                    )
                })?;
                anyhow::ensure!(
                    rs.is_ip_only(),
                    "inbound '{tproxy_tag}': ebpf 规则集 '{tag}' 含 IP 之外的匹配条件\
                     （域名/端口），内核面仅支持纯 IP 规则集"
                );
                anyhow::ensure!(
                    rs.has_ip_matchers(),
                    "inbound '{tproxy_tag}': ebpf 规则集 '{tag}' 不含任何 IP 条目"
                );
                Ok(KernelRuleset {
                    tag,
                    ruleset: rs.as_ref(),
                })
            })
            .collect()
    }
}
