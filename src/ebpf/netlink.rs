//! fwmark 策略路由维护（裸 netlink，零新依赖）。
//!
//! eBPF 数据面把 PROXY 裁决的包写入 fwmark 后，依赖以下策略路由把流量
//! 送达本机 tproxy 监听（等价 dae 的启动配置）：
//!
//! ```text
//! ip  route add local default dev lo table 2023
//! ip  rule  add fwmark <mark>/<mark> table 2023
//! ip -6 route add local default dev lo table 2023
//! ip -6 rule  add fwmark <mark>/<mark> table 2023
//! ```
//!
//! 每族先路由后规则（路由会自动创建不存在的表）；系统在 lo 上禁用
//! IPv6 时跳过 IPv6 部分。
//!
//! 全部操作幂等：`EEXIST` 视为已配置（支持多实例共存于不同 mark）。

use std::io;
use std::os::fd::RawFd;

use anyhow::{anyhow, Context as _};

const NETLINK_ROUTE: i32 = libc::NETLINK_ROUTE;
const AF_NETLINK: i32 = libc::AF_NETLINK;

// 内核 UAPI 常量（libc 未全部导出，缺失处本地补齐；值与 linux/rtnetlink.h 一致）。
const RTM_NEWRULE: u16 = libc::RTM_NEWRULE;
const RTM_DELRULE: u16 = libc::RTM_DELRULE;
const RTM_NEWROUTE: u16 = libc::RTM_NEWROUTE;
const RTM_DELROUTE: u16 = libc::RTM_DELROUTE;
const NLM_F_REQUEST: u16 = libc::NLM_F_REQUEST as u16;
const NLM_F_ACK: u16 = libc::NLM_F_ACK as u16;
const NLM_F_CREATE: u16 = libc::NLM_F_CREATE as u16;
const NLM_F_EXCL: u16 = libc::NLM_F_EXCL as u16;
const NLMSG_ERROR: u16 = libc::NLMSG_ERROR as u16;
const RTA_TABLE: u16 = libc::RTA_TABLE;
const RTA_OIF: u16 = libc::RTA_OIF;
const FR_ACT_TO_TBL: u8 = 1;
const RTN_LOCAL: u8 = libc::RTN_LOCAL;
const RT_SCOPE_HOST: u8 = libc::RT_SCOPE_HOST;
const RTPROT_STATIC: u8 = libc::RTPROT_STATIC;
const RTN_UNSPEC: u8 = 0;

// ── libc 未导出的 rtnetlink UAPI（本地补齐，布局与内核头文件一致）────────
// linux/rtnetlink.h: FRA_FWMARK=10, FRA_FWMASK=11（libc 无 fib_rules.h 常量）
const FRA_FWMARK: u16 = 10;
const FRA_FWMASK: u16 = 11;

/// linux/fib_rules.h `struct fib_rule_hdr`（libc 未导出）。
#[repr(C)]
#[allow(non_camel_case_types)]
struct fib_rule_hdr {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    res1: u8,
    res2: u8,
    action: u8,
    flags: u32,
}

/// linux/rtnetlink.h `struct rtmsg`（libc 未导出）。
#[repr(C)]
#[allow(non_camel_case_types)]
struct rtmsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

/// 单个 netlink 操作错误（区分 EEXIST/ENOENT 与真实失败）。
enum NlError {
    Exists,
    NotFound,
    Io(io::Error),
}

impl From<NlError> for anyhow::Error {
    fn from(e: NlError) -> Self {
        match e {
            NlError::Exists => anyhow!("netlink: EEXIST"),
            NlError::NotFound => anyhow!("netlink: ENOENT"),
            NlError::Io(err) => anyhow!(err),
        }
    }
}

struct NlSocket(RawFd);

impl NlSocket {
    fn open() -> anyhow::Result<Self> {
        let fd = unsafe {
            libc::socket(
                AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(anyhow!(io::Error::last_os_error()).context("socket(AF_NETLINK, NETLINK_ROUTE)"));
        }
        Ok(NlSocket(fd))
    }

    fn send(&self, msg: &[u8]) -> anyhow::Result<()> {
        // sockaddr_nl 含不可命名的 libc 私有 Padding 字段，先清零再赋值。
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as libc::sa_family_t;
        let ret = unsafe {
            libc::sendto(
                self.0,
                msg.as_ptr() as *const _,
                msg.len(),
                0,
                &addr as *const _ as *const _,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(anyhow!(io::Error::last_os_error()).context("sendto(netlink)"));
        }
        Ok(())
    }

    /// 阻塞等待本次请求的应答（NLMSG_ERROR：error==0 成功，>0 为 errno）。
    /// 仅按 seq 匹配——单 socket 串行使用，kernel 回复的 nlmsg_pid 是
    /// 自动分配的本端 portid，不参与比较。
    fn wait_ack(&self, seq: u32) -> Result<(), NlError> {
        loop {
            let mut buf = [0u8; 4096];
            let n = unsafe {
                libc::recv(self.0, buf.as_mut_ptr() as *mut _, buf.len(), 0)
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(NlError::Io(err));
            }
            let n = n as usize;
            let mut offset = 0usize;
            while offset + std::mem::size_of::<libc::nlmsghdr>() <= n {
                let hdr = unsafe { &*(buf.as_ptr().add(offset) as *const libc::nlmsghdr) };
                if hdr.nlmsg_seq != seq {
                    // 非本次请求的消息，跳过。
                    offset += nlmsg_align(hdr.nlmsg_len as usize);
                    continue;
                }
                if hdr.nlmsg_type == NLMSG_ERROR {
                    let err = unsafe {
                        &*(buf.as_ptr().add(offset + std::mem::size_of::<libc::nlmsghdr>())
                            as *const libc::nlmsgerr)
                    };
                    return if err.error == 0 {
                        Ok(())
                    } else {
                        // 内核 nlmsgerr.error 为负 errno（如 -EEXIST），必须
                        // 取负还原成正 errno 再匹配，否则 EEXIST/ENOENT 永远
                        // 命中不了，且错误消息会变成无意义的
                        // "No error information (os error -19)"。
                        match -err.error {
                            libc::EEXIST => Err(NlError::Exists),
                            libc::ENOENT => Err(NlError::NotFound),
                            code => Err(NlError::Io(io::Error::from_raw_os_error(code))),
                        }
                    };
                }
                offset += nlmsg_align(hdr.nlmsg_len as usize);
            }
        }
    }
}

impl Drop for NlSocket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

fn push_header(buf: &mut Vec<u8>, ty: u16, flags: u16, seq: u32, payload_len: usize) {
    let total = (std::mem::size_of::<libc::nlmsghdr>() + payload_len) as u32;
    let hdr = libc::nlmsghdr {
        nlmsg_len: total,
        nlmsg_type: ty,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    };
    buf.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &hdr as *const _ as *const u8,
            std::mem::size_of::<libc::nlmsghdr>(),
        )
    });
}

fn push_attr_u32(buf: &mut Vec<u8>, rta_type: u16, value: u32) {
    // RTA_ALIGNTO = 4
    buf.extend_from_slice(&((4 + 4) as u16).to_ne_bytes());
    buf.extend_from_slice(&rta_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_ne_bytes());
}

/// 回填 nlmsg_len。push_header 写入的初值只含 header+固定 payload，
/// 属性是在其后追加的，必须在构造完成后按实际总长修正——否则内核
/// 按 nlmsg_len 截断，属性全部丢失（表现为 ENODEV / 规则字段缺失）。
fn fix_nlmsg_len(buf: &mut [u8]) {
    let len = buf.len() as u32;
    buf[0..4].copy_from_slice(&len.to_ne_bytes());
}

/// 追加策略路由规则：`fwmark <mark>/<mark> lookup <table>`。
/// `family`：libc::AF_INET / libc::AF_INET6。
fn rule_message(family: i32, mark: u32, add: bool, seq: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);
    let flags = if add {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    } else {
        NLM_F_REQUEST | NLM_F_ACK
    };
    push_header(
        &mut msg,
        if add { RTM_NEWRULE } else { RTM_DELRULE },
        flags,
        seq,
        std::mem::size_of::<fib_rule_hdr>(),
    );
    let hdr = fib_rule_hdr {
        family: family as u8,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: 0, // table > 255 经 RTA_TABLE 传递
        res1: 0,
        res2: 0,
        action: FR_ACT_TO_TBL,
        flags: 0,
    };
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &hdr as *const _ as *const u8,
            std::mem::size_of::<fib_rule_hdr>(),
        )
    });
    push_attr_u32(&mut msg, libc::RTA_TABLE, reflex_ebpf_common::FWMARK_TABLE_ID);
    push_attr_u32(&mut msg, FRA_FWMARK, mark);
    push_attr_u32(&mut msg, FRA_FWMASK, mark);
    fix_nlmsg_len(&mut msg);
    msg
}

/// 追加 `local default dev lo table <TABLE>` 路由。
fn local_route_message(family: i32, add: bool, seq: u32) -> anyhow::Result<Vec<u8>> {
    let lo_ifindex = unsafe { libc::if_nametoindex(c"lo".as_ptr() as *const _) };
    if lo_ifindex == 0 {
        return Err(anyhow!("netlink: loopback 接口不存在"));
    }
    let mut msg = Vec::with_capacity(128);
    let flags = if add {
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    } else {
        NLM_F_REQUEST | NLM_F_ACK
    };
    push_header(
        &mut msg,
        if add { RTM_NEWROUTE } else { RTM_DELROUTE },
        flags,
        seq,
        std::mem::size_of::<rtmsg>(),
    );
    let hdr = rtmsg {
        rtm_family: family as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: 0, // 经 RTA_TABLE 传递
        rtm_protocol: RTPROT_STATIC,
        rtm_scope: RT_SCOPE_HOST,
        // DEL 时 type 需与 NEW 一致才能精确匹配（RTM_DELROUTE 对 type 不敏感，
        // 统一写 RTN_LOCAL，保证删除命中我们创建的 local 路由）。
        rtm_type: if add { RTN_LOCAL } else { RTN_UNSPEC },
        rtm_flags: 0,
    };
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &hdr as *const _ as *const u8,
            std::mem::size_of::<rtmsg>(),
        )
    });
    push_attr_u32(&mut msg, RTA_TABLE, reflex_ebpf_common::FWMARK_TABLE_ID);
    push_attr_u32(&mut msg, RTA_OIF, lo_ifindex);
    fix_nlmsg_len(&mut msg);
    Ok(msg)
}

/// 枚举本机全部接口地址（v4 + v6，含临时/隐私地址）。
///
/// 用于内核面 DIRECT 集合：发往本机自身的流量（SSH/管理等）必须直连，
/// 否则会被 PROXY 判决引流进 tproxy 形成自环。失败时 fail-fast。
pub fn collect_local_addrs() -> anyhow::Result<Vec<std::net::IpAddr>> {
    let mut addrs = Vec::new();
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(anyhow::Error::from(std::io::Error::last_os_error()))
                .context("getifaddrs 失败（无法枚举本机地址，内核面 DIRECT 集合不完整）");
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa = &*cur;
            let sa = ifa.ifa_addr;
            if !sa.is_null() {
                match (*sa).sa_family as i32 {
                    libc::AF_INET => {
                        let sin = sa as *const libc::sockaddr_in;
                        // s_addr 为网络字节序，还原为原始 octets。
                        let octets = u32::from_be((*sin).sin_addr.s_addr).to_be_bytes();
                        addrs.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)));
                    }
                    libc::AF_INET6 => {
                        let sin6 = sa as *const libc::sockaddr_in6;
                        addrs.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                            (*sin6).sin6_addr.s6_addr,
                        )));
                    }
                    _ => {}
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    addrs.sort();
    addrs.dedup();
    Ok(addrs)
}

/// lo 的 IPv6 是否被系统禁用。
///
/// `/proc/net/if_inet6` 每行对应一个已启用 IPv6 的接口，lo 的地址恒为
/// `::1`。`net.ipv6.conf.lo.disable_ipv6=1`（或 all / boot 参数
/// `ipv6.disable=1`）时该文件不存在或没有 lo 条目。此时内核
/// `fib6_nh_init` 里 `in6_dev_get(lo)` 返回 NULL，任何
/// `ip -6 route add ... dev lo` 都会得到 ENODEV。
fn ipv6_disabled_on_lo() -> bool {
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(s) => !s
            .lines()
            .any(|l| l.starts_with("00000000000000000000000000000001")),
        Err(_) => true,
    }
}

fn family_name(family: i32) -> &'static str {
    if family == libc::AF_INET {
        "IPv4"
    } else {
        "IPv6"
    }
}

fn hex(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len() * 2);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// 幂等建立 fwmark 策略路由（v4 + v6）。EEXIST 视为已配置。
///
/// 每族**先路由后规则**：`RTM_NEWROUTE` 对不存在的表会自动建表，先路由
/// 可兼容"规则指向的表必须存在"的老内核行为。
///
/// `reply_mark`（wan 模式）：监听侧回包 mark，额外加一条同表 fwmark 规则——
/// 回包目的地址 = 客户端 socket 的伪装地址（非本机地址），没有这条规则时
/// 回包走主路由表从物理口发出，客户端永远收不到。
///
/// 系统在 lo 上禁用 IPv6 时（VPS 常见配置），IPv6 策略路由无法建立
/// （ENODEV），跳过并 warn，仅配置 IPv4；IPv6 可用时的失败仍然 fatal。
pub fn ensure_policy_routing(mark: u32, reply_mark: Option<u32>) -> anyhow::Result<()> {
    let sock = NlSocket::open()?;
    let table = reflex_ebpf_common::FWMARK_TABLE_ID;
    let mut seq = 100u32;
    for family in [libc::AF_INET, libc::AF_INET6] {
        if family == libc::AF_INET6 && ipv6_disabled_on_lo() {
            tracing::warn!(
                "系统未在 lo 上启用 IPv6（disable_ipv6），跳过 IPv6 策略路由，仅配置 IPv4"
            );
            continue;
        }
        let name = family_name(family);

        // 1. 先建 local 路由（自动创建路由表）。
        let route = local_route_message(family, true, seq)?;
        sock.send(&route)
            .with_context(|| format!("netlink: 发送 {name} 路由请求失败"))?;
        match sock.wait_ack(seq) {
            Ok(()) | Err(NlError::Exists) => {}
            Err(e) => {
                return Err(anyhow::Error::from(e)).with_context(|| {
                    format!(
                        "netlink: 添加 {name} 路由 `local default dev lo table {table}` 失败，请求报文: {}",
                        hex(&route)
                    )
                });
            }
        }
        seq += 1;

        // 2. 加 fwmark 规则（tproxy mark + reply mark 各一条）。
        for m in core::iter::once(mark).chain(reply_mark) {
            let rule = rule_message(family, m, true, seq);
            sock.send(&rule)
                .with_context(|| format!("netlink: 发送 {name} 规则请求失败"))?;
            match sock.wait_ack(seq) {
                Ok(()) | Err(NlError::Exists) => {}
                Err(e) => {
                    return Err(anyhow::Error::from(e)).with_context(|| {
                        format!(
                            "netlink: 添加 {name} 规则 `fwmark {m:#x}/{m:#x} table {table}` 失败，请求报文: {}",
                            hex(&rule)
                        )
                    });
                }
            }
            seq += 1;
        }
    }
    Ok(())
}

/// 幂等拆除策略路由（shutdown 清理）。ENOENT 视为成功。
pub fn remove_policy_routing(mark: u32, reply_mark: Option<u32>) {
    let Ok(sock) = NlSocket::open() else {
        return;
    };
    let mut seq = 300u32;
    for family in [libc::AF_INET, libc::AF_INET6] {
        if let Ok(msg) = local_route_message(family, false, seq) {
            if sock.send(&msg).is_ok() {
                let _ = sock.wait_ack(seq);
            }
        }
        seq += 1;
        for m in core::iter::once(mark).chain(reply_mark) {
            let rule = rule_message(family, m, false, seq);
            if sock.send(&rule).is_ok() {
                let _ = sock.wait_ack(seq);
            }
            seq += 1;
        }
    }
}
