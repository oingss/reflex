//! eBPF 加载器：aya 加载 `reflex-bpf` 产物、填充 map、按部署模式挂载。
//!
//! 两种挂载形态（见 [`EbpfMode`]）：
//!
//! - **lan**（网关/旁路由）：逐接口挂 tc ingress（`reflex_tc_ingress`），
//!   处理转发流量；tc filter 不随进程退出自动卸载，shutdown 时需逐接口
//!   detach。
//! - **wan**（本机 / Android）：在 `cgroup_path` 指向的 cgroup v2 上挂
//!   4 个 sock_addr hook（connect4/6 + sendmsg4/6），拦截本机 socket；
//!   另挂 lo tc ingress（`reflex_lo_ingress`）——PROXY 包回环 local 后由
//!   它 `bpf_sk_assign` 交付进 tproxy 监听 socket。
//!
//! 两种模式都会把 tproxy 监听 fd 写入 `LISTEN_SOCKETS`（SOCKMAP）。
//!
//! 生命周期：`start()` 一次性完成编译产物装载与挂载，返回的
//! [`EbpfHandle`] 应 move 进后台清理任务——shutdown 信号到达后按挂载
//! 类型 detach，并拆除 netlink 策略路由。

use std::fs::File;

use aya::maps::lpm_trie::Key as LpmKey;
use aya::maps::Array;
use aya::maps::HashMap;
use aya::maps::LpmTrie;
use aya::maps::MapData;
use aya::maps::SockMap;
use aya::programs::cgroup_sock_addr::CgroupSockAddrLinkId;
use aya::programs::links::CgroupAttachMode;
use aya::programs::tc::SchedClassifier;
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::tc::TcAttachType;
use aya::programs::CgroupSockAddr;
use aya::Ebpf;
use anyhow::Context;
use reflex_ebpf_common as common;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::config::inbound::EbpfMode;
use crate::config::inbound::TProxyEbpfConfig;
use crate::ebpf::compiler::CompiledKernelPlane;
use crate::ebpf::TProxyListeners;

/// map 更新 flags：`BPF_ANY`（键不存在则创建，存在则覆盖）。
const BPF_ANY: u64 = 0;

/// wan 模式挂载的 cgroup 程序名（与 `reflex-bpf` 的 section 一一对应）。
const WAN_PROGRAMS: [&str; 4] = [
    "reflex_cg_connect4",
    "reflex_cg_connect6",
    "reflex_cg_sendmsg4",
    "reflex_cg_sendmsg6",
];

/// 单个挂载点记录。lan 与 wan 的挂载/detach 语义不同，用枚举分发。
enum EbpfLink {
    /// lan：接口名 + tc ingress link id。
    Tc(&'static str, SchedClassifierLinkId),
    /// wan：lo 接口 tc ingress（reflex_lo_ingress，sk_assign 交付闭环）。
    Lo(&'static str, SchedClassifierLinkId),
    /// wan：cgroup 路径 + 程序名 + cgroup sock_addr link id。
    Cgroup(String, &'static str, CgroupSockAddrLinkId),
}

/// 已挂载的 eBPF 实例。**必须在退出前调用 [`EbpfHandle::teardown`]**
/// （tc filter 与 cgroup attach 均不随进程退出自动卸载）。
pub struct EbpfHandle {
    bpf: Option<Ebpf>,
    links: Vec<EbpfLink>,
    mark: u32,
    reply_mark: Option<u32>,
}

/// 加载 bpf 对象、填充 map、按 `cfg.mode` 挂载。
///
/// 调用方（App 接线）需保证：配置校验已通过（`setup.rs`）、当前进程具备
/// `CAP_BPF`/`CAP_NET_ADMIN`（或 root）、内核 ≥ 5.17（`bpf_loop`）；
/// wan 模式还要求 cgroup v2 已挂载在 `cfg.cgroup_path`、内核 ≥ 5.12
/// （sock_addr 程序内 `setsockopt(SO_MARK)`）。
///
/// `listeners`：tproxy 监听 socket（同步创建，早于本函数）——fd 写入
/// `LISTEN_SOCKETS` SOCKMAP，内核面 `bpf_sk_assign` 据此交付引流包；缺
/// socket 的 key 不注册（对应协议族流量无法进入 tproxy，属配置意图）。
/// `reply_mark`：wan 模式回包 fwmark，注册进 CONFIG 并加配套策略路由。
pub fn start(
    cfg: &TProxyEbpfConfig,
    compiled: &CompiledKernelPlane,
    kernel_mark: u32,
    dns_hijack: bool,
    self_mark: u32,
    listeners: &TProxyListeners,
    reply_mark: Option<u32>,
) -> anyhow::Result<EbpfHandle> {
    // 1. 策略路由先就位（tproxy listener 收包依赖 fwmark → local 表）。
    //    kernel_mark = ebpf.mark（PROXY 裁决写入 skb 的 fwmark），二者必须
    //    一致；绝不能为 0——fwmark 0/0 的规则匹配所有流量，会把全机应答
    //    包吞进 local 表（SSH/所有端口断连）。
    super::netlink::ensure_policy_routing(kernel_mark, reply_mark)
        .context("fwmark 策略路由配置失败")?;

    // 2. 加载 bpf 对象（缺省用构建期内嵌对象，见 build.rs）。
    let mut bpf = load_bpf_object(cfg.bpf_object.as_deref())?;

    // 3. 填充 LPM（全部 IP 集合共享一个 trie）。
    {
        anyhow::ensure!(
            compiled.lpm_entries.len() <= common::MAX_LPM_ENTRIES as usize,
            "LPM 条目数量 {} 超过内核 map 容量 {}",
            compiled.lpm_entries.len(),
            common::MAX_LPM_ENTRIES
        );
        let mut lpm: LpmTrie<&mut MapData, [u8; common::LPM_KEY_LEN], u32> =
            LpmTrie::try_from(bpf.map_mut("LPM").expect("LPM map 缺失"))?;
        for entry in &compiled.lpm_entries {
            lpm.insert(&LpmKey::new(entry.prefix_len, entry.key), 1, BPF_ANY)
                .context("LPM 条目写入失败")?;
        }
    }

    // 4. 填充规则序列与长度（先规则后长度，保证 META 写入瞬间规则已就绪）。
    {
        let mut routing: Array<&mut MapData, common::MatchSet> =
            Array::try_from(bpf.map_mut("ROUTING").expect("ROUTING map 缺失"))?;
        anyhow::ensure!(
            compiled.match_sets.len() <= routing.len() as usize,
            "MatchSet 数量 {} 超过内核 map 容量 {}",
            compiled.match_sets.len(),
            routing.len()
        );
        for (i, ms) in compiled.match_sets.iter().enumerate() {
            routing.set(i as u32, *ms, 0).context("ROUTING 写入失败")?;
        }
        let mut meta: Array<&mut MapData, u32> =
            Array::try_from(bpf.map_mut("META").expect("META map 缺失"))?;
        meta.set(0, compiled.match_sets.len() as u32, 0)?;
    }

    // 5. 运行时配置：tproxy fwmark + 全局 DNS 劫持开关；wan 模式额外写入
    //    reflex 自身出站 mark（回环防护：内核 hook 比对 socket SO_MARK）
    //    与监听侧回包 mark（lo ingress / cgroup hook 区分包方向）。
    {
        let mut config_map: HashMap<&mut MapData, u32, u32> =
            HashMap::try_from(bpf.map_mut("CONFIG").expect("CONFIG map 缺失"))?;
        config_map.insert(common::CONFIG_KEY_MARK, kernel_mark, BPF_ANY)?;
        config_map.insert(
            common::CONFIG_KEY_DNS_HIJACK,
            u32::from(dns_hijack),
            BPF_ANY,
        )?;
        // 本机地址集合号：内核 DNS 劫持跳过"发往本机地址:53"（见 common 文档）。
        config_map.insert(
            common::CONFIG_KEY_LOCAL_SET_ID,
            u32::from(compiled.local_set_id),
            BPF_ANY,
        )?;
        if cfg.mode == EbpfMode::Wan {
            anyhow::ensure!(
                self_mark != 0,
                "wan 模式要求 route.default_mark 非 0（内核 hook 用它识别 reflex 自身连接，防引流回环）"
            );
            config_map.insert(common::CONFIG_KEY_ROUTING_MARK, self_mark, BPF_ANY)?;
            if let Some(rm) = reply_mark {
                config_map.insert(common::CONFIG_KEY_REPLY_MARK, rm, BPF_ANY)?;
            }
        }
    }

    // 5.5 监听 socket 注册（LISTEN_SOCKETS SOCKMAP）：内核面 sk_assign 的
    //     交付依据。key 与 reflex-bpf 的 LISTEN_KEY_* 对齐。
    {
        let mut listen_map: SockMap<&mut MapData> =
            SockMap::try_from(bpf.map_mut("LISTEN_SOCKETS").expect("LISTEN_SOCKETS map 缺失"))?;
        if let Some(l) = &listeners.tcp4 {
            listen_map.set(common::LISTEN_KEY_TCP4, l, BPF_ANY)?;
        }
        if let Some(u) = &listeners.udp {
            listen_map.set(common::LISTEN_KEY_UDP, u, BPF_ANY)?;
        }
        if let Some(l) = &listeners.tcp6 {
            listen_map.set(common::LISTEN_KEY_TCP6, l, BPF_ANY)?;
        }
    }

    // 6. 按部署模式挂载。
    let mut links = Vec::new();
    match cfg.mode {
        EbpfMode::Lan => {
            for iface in &cfg.interfaces {
                let program: &mut SchedClassifier = bpf
                    .program_mut("reflex_tc_ingress")
                    .expect("reflex_tc_ingress 程序缺失")
                    .try_into()?;
                program.load().context("tc 程序加载失败")?;
                let link_id = program
                    .attach(iface, TcAttachType::Ingress)
                    .with_context(|| format!("tc ingress 挂载失败: {iface}"))?;
                links.push(EbpfLink::Tc(
                    Box::leak(iface.clone().into_boxed_str()) as &'static str,
                    link_id,
                ));
            }
        }
        EbpfMode::Wan => {
            // lo ingress 必须先于 cgroup hook 就位：cgroup hook 打 mark 的包
            // 回环 lo 后全靠它 sk_assign 交付，缺失时表现为"有 mark 无流量"。
            let lo_program: &mut SchedClassifier = bpf
                .program_mut("reflex_lo_ingress")
                .expect("reflex_lo_ingress 程序缺失")
                .try_into()?;
            lo_program.load().context("lo tc 程序加载失败")?;
            let lo_link_id = lo_program
                .attach("lo", TcAttachType::Ingress)
                .context("lo tc ingress 挂载失败（lo 上已有其它 filter 时会 EEXIST）")?;
            links.push(EbpfLink::Lo("lo", lo_link_id));

            let cgroup = File::open(&cfg.cgroup_path).with_context(|| {
                format!(
                    "打开 cgroup 路径失败: {}（wan 模式要求 cgroup v2 已挂载）",
                    cfg.cgroup_path
                )
            })?;
            for name in WAN_PROGRAMS {
                let program: &mut CgroupSockAddr = bpf
                    .program_mut(name)
                    .with_context(|| format!("cgroup 程序 {name} 缺失（bpf 对象与 reflex 版本不一致）"))?
                    .try_into()?;
                program.load().with_context(|| {
                    format!("cgroup 程序 {name} 加载失败（sock_addr hook 需内核 ≥ 4.17，SO_MARK 写入需 ≥ 5.12）")
                })?;
                let link_id = program
                    .attach(&cgroup, CgroupAttachMode::Single)
                    .with_context(|| {
                        format!("cgroup attach 失败: {} / {name}", cfg.cgroup_path)
                    })?;
                links.push(EbpfLink::Cgroup(cfg.cgroup_path.clone(), name, link_id));
            }
        }
    }

    info!(
        mode = ?cfg.mode,
        interfaces = ?cfg.interfaces,
        cgroup = %cfg.cgroup_path,
        match_sets = compiled.match_sets.len(),
        lpm_entries = compiled.lpm_total,
        block_rulesets = compiled.block_rulesets,
        direct_rulesets = compiled.direct_rulesets,
        "eBPF 内核面已挂载"
    );

    Ok(EbpfHandle {
        bpf: Some(bpf),
        links,
        mark: kernel_mark,
        reply_mark,
    })
}

/// 加载 eBPF 对象：`bpf_object` 显式配置时从文件加载（调试/覆盖用途）；
/// 缺省时使用构建期内嵌对象——build.rs 把 `reflex.bpf.el.o`（小端）/
/// `reflex.bpf.eb.o`（大端）通过 `include_bytes!` 编译进二进制（类比
/// Windows 端内置 wintun.dll），按目标端序选择，运行时无需外部文件。
fn load_bpf_object(explicit: Option<&str>) -> anyhow::Result<Ebpf> {
    if let Some(path) = explicit {
        return Ebpf::load_file(path)
            .with_context(|| format!("加载 eBPF 对象失败: {path}"));
    }
    #[cfg(reflex_embedded_bpf_el)]
    {
        if cfg!(target_endian = "little") {
            let bytes = include_bytes!(env!("REFLEX_EMBEDDED_BPF_EL")).to_vec();
            return Ebpf::load(&bytes).context("加载内嵌 eBPF 对象（el）失败");
        }
    }
    #[cfg(reflex_embedded_bpf_eb)]
    {
        if cfg!(target_endian = "big") {
            let bytes = include_bytes!(env!("REFLEX_EMBEDDED_BPF_EB")).to_vec();
            return Ebpf::load(&bytes).context("加载内嵌 eBPF 对象（eb）失败");
        }
    }
    anyhow::bail!(
        "未配置 bpf_object 且二进制未内嵌 eBPF 对象：\
         构建时把 reflex.bpf.el.o / reflex.bpf.eb.o 放到项目 bpf/ 目录 \
         （或设置环境变量 REFLEX_BPF_OBJECT_EL / REFLEX_BPF_OBJECT_EB，\
         CI 产物见 .github/workflows/ebpf.yml），\
         或在 tproxy 入站 ebpf 配置中显式指定 bpf_object"
    );
}

impl EbpfHandle {
    /// 卸载全部挂载点并拆除 netlink 策略路由。
    /// 单个挂载点 detach 失败不阻断其余清理（尽力而为，错误聚合返回）。
    pub fn teardown(&mut self) -> Vec<anyhow::Error> {
        let mut errors = Vec::new();
        if let Some(bpf) = self.bpf.as_mut() {
            for link in self.links.drain(..) {
                match link {
                    EbpfLink::Tc(iface, link_id) => {
                        let program: &mut SchedClassifier = bpf
                            .program_mut("reflex_tc_ingress")
                            .expect("reflex_tc_ingress 程序缺失")
                            .try_into()
                            .expect("程序类型不变");
                        if let Err(err) = program.detach(link_id) {
                            errors.push(anyhow::anyhow!("tc ingress 卸载失败 {iface}: {err}"));
                        } else {
                            debug!(iface, "tc ingress 已卸载");
                        }
                    }
                    EbpfLink::Lo(iface, link_id) => {
                        let program: &mut SchedClassifier = bpf
                            .program_mut("reflex_lo_ingress")
                            .expect("reflex_lo_ingress 程序缺失")
                            .try_into()
                            .expect("程序类型不变");
                        if let Err(err) = program.detach(link_id) {
                            errors.push(anyhow::anyhow!(
                                "lo tc ingress 卸载失败 {iface}: {err}"
                            ));
                        } else {
                            debug!(iface, "lo tc ingress 已卸载");
                        }
                    }
                    EbpfLink::Cgroup(path, name, link_id) => {
                        let program: &mut CgroupSockAddr = bpf
                            .program_mut(name)
                            .expect("cgroup 程序缺失")
                            .try_into()
                            .expect("程序类型不变");
                        if let Err(err) = program.detach(link_id) {
                            errors.push(anyhow::anyhow!(
                                "cgroup hook 卸载失败 {path}/{name}: {err}"
                            ));
                        } else {
                            debug!(cgroup = %path, program = name, "cgroup hook 已卸载");
                        }
                    }
                }
            }
        }
        super::netlink::remove_policy_routing(self.mark, self.reply_mark);
        errors
    }
}

impl Drop for EbpfHandle {
    fn drop(&mut self) {
        // 防御：即使清理任务未运行（如 panic），drop 时也尽力卸载。
        if !self.links.is_empty() {
            for err in self.teardown() {
                warn!(error = %err, "eBPF teardown 残留错误");
            }
        } else {
            super::netlink::remove_policy_routing(self.mark, self.reply_mark);
        }
    }
}
