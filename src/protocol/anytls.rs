//! AnyTLS 协议原语：inbound 服务端与 outbound 客户端共享的线格式编解码。
//!
//! ## 线格式（对齐 anytls-go / sing-anytls，参考 flux-master `src/anytls/`）
//!
//! ### 认证帧（TLS 握手完成后立即发送的第一个 TLS 记录负载）
//! ```text
//! [sha256(password) 32B][padding0_len 2B BE u16][padding0 padding0_len B]
//! ```
//! 服务端逐字节比对 sha256(password)；padding0 仅作流量混淆，读后丢弃。
//!
//! ### 会话帧（TLS 流内多路复用）
//! ```text
//! [CMD 1B][STREAM_ID 4B BE u32][DATA_LEN 2B BE u16][DATA DATA_LEN B]
//! ```
//! 命令字（v2 协议）：
//!
//! | 值 | 名称                    | 方向 | 含义                                       |
//! |----|-------------------------|------|--------------------------------------------|
//! | 0  | cmdWaste                | 双向 | padding 填充，数据丢弃                     |
//! | 1  | cmdSYN                  | C→S  | 打开 stream（SID 为新流 ID）               |
//! | 2  | cmdPSH                  | 双向 | 数据推送                                   |
//! | 3  | cmdFIN                  | 双向 | 关闭 stream                                |
//! | 4  | cmdSettings             | C→S  | 客户端版本/padding-md5 协商（KV 文本）     |
//! | 5  | cmdAlert                | 双向 | 致命错误，收到后关闭会话                   |
//! | 6  | cmdUpdatePaddingScheme  | 双向 | 更新 padding scheme（scheme 原文）         |
//! | 7  | cmdSYNACK               | S→C  | stream 确认；空载荷=成功，非空=拒绝原因    |
//! | 8  | cmdHeartRequest         | 双向 | 心跳，收到方应回 cmdHeartResponse          |
//! | 9  | cmdHeartResponse        | 双向 | 心跳应答                                   |
//! | 10 | cmdServerSettings       | S→C  | 服务端能力协商（`v=2`）                    |
//!
//! 单帧 DATA_LEN 上限 65535；更长的 PSH 载荷必须拆分为多个 cmdPSH 帧
//! （对齐 sing-anytls `writeDataFrame`）。
//!
//! ### Padding scheme
//! KV 文本（`stop=N` 与 `<pkt>=<lo>-<hi>[,c,...]`），md5(scheme 原文) 用于
//! 协商比对；`c` 标记表示"载荷耗尽即停止填充"。会话前 N 个写单位按 scheme
//! 切分/填充。注意 anytls-go 的 pkt 从 **1** 计数（`0=...` 规则保留给认证帧
//! padding0），Go 的 `atomic.Add` 返回新值，Rust 需 `fetch_add + 1` 对齐
//! （见 [`apply_padding`] 注释）。
//!
//! ### Stream 打开载荷（客户端 cmdSYN 后的首个 cmdPSH）
//! SOCKS5 地址：`[ATYP 1B][ADDR][PORT 2B BE]`，ATYP=0x01/0x03/0x04。
//!
//! ### UDP over session（sing UoT v2）
//! 客户端向目标为魔术地址 `sp.v2.udp-over-tcp.arpa` 的 stream 发送：
//! 1. 请求头 `[isConnect 1B][SOCKS5 ATYP 目标][PORT 2B BE]`
//!    （isConnect=0 无连接模式：每包携带目标地址；isConnect=1 连接模式）
//! 2. 每个 UDP 包（无连接模式）`[sing ATYP 1B][ADDR][PORT][LEN 2B BE][DATA]`
//!    （sing 自定义 ATYP：0x00=IPv4, 0x01=IPv6, 0x02=FQDN，**与请求头
//!    SOCKS5 ATYP 不同**；连接模式下每包为 `[LEN 2B BE][DATA]`）
//!
//! 本模块只放方向无关的纯编解码原语与服务端会话多路复用器（对齐
//! `protocol/mod.rs` 设计原则）；TLS 拨号/accept、会话池、空闲回收等角色
//! 逻辑归 `inbound/anytls.rs` 与 `outbound/anytls.rs`。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use bytes::{Bytes, BytesMut};
use md5::Md5;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::inbound::Target;

// ── 协议常量 ──────────────────────────────────────────────────────────────────

/// padding 填充帧
pub const CMD_WASTE: u8 = 0;
/// 客户端打开 stream
pub const CMD_SYN: u8 = 1;
/// 数据推送
pub const CMD_PSH: u8 = 2;
/// 关闭 stream
pub const CMD_FIN: u8 = 3;
/// 客户端能力协商（KV 文本：v / client / padding-md5）
pub const CMD_SETTINGS: u8 = 4;
/// 致命错误（文本原因），收到后关闭会话
pub const CMD_ALERT: u8 = 5;
/// 更新 padding scheme（载荷为 scheme 原文）
pub const CMD_UPDATE_PADDING: u8 = 6;
/// 服务端 stream 确认（空载荷=成功；非空=拒绝原因文本）
pub const CMD_SYNACK: u8 = 7;
/// 心跳请求
pub const CMD_HEART_REQUEST: u8 = 8;
/// 心跳应答
pub const CMD_HEART_RESPONSE: u8 = 9;
/// 服务端能力协商（`v=2`）
pub const CMD_SERVER_SETTINGS: u8 = 10;

/// 帧头开销：cmd(1) + streamId(4) + data_len(2)
pub const FRAME_HEADER_SIZE: usize = 7;

/// 单帧 payload 上限（DATA_LEN 为 u16）
pub const MAX_FRAME_DATA: usize = 0xFFFF;

/// SOCKS5 地址类型（stream 打开载荷与 UoT v2 请求头共用，标准 SOCKS5 ATYP）
pub const SOCKS_ATYP_IPV4: u8 = 0x01;
pub const SOCKS_ATYP_DOMAIN: u8 = 0x03;
pub const SOCKS_ATYP_IPV6: u8 = 0x04;

/// sing UoT v2 魔法地址（目标为此地址的 TCP 请求走 UoT v2 UDP-over-session）
pub const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub const UOT_MAGIC_PORT: u16 = 443;

/// sing UoT v2 每包地址类型（与标准 SOCKS5 不同，参考 sing/common/uot/protocol.go）
///
/// 注意：sing 的 UoT v2 协议在同一个流中使用**两套不同的 ATYP 表**：
/// - 请求头中的目标地址使用标准 SOCKS5 ATYP（0x01/0x03/0x04）
/// - 每个数据包的源/目标地址使用 sing 自定义 ATYP（0x00/0x01/0x02）
pub const UOT_ATYP_IPV4: u8 = 0x00;
pub const UOT_ATYP_IPV6: u8 = 0x01;
pub const UOT_ATYP_DOMAIN: u8 = 0x02;

/// padding 检查标记："payload 已耗尽则停止填充"
pub const PADDING_CHECK_MARK: i32 = -1;

/// 默认 Padding 方案（与 anytls-go 参考实现一致）
pub const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

// ── PaddingScheme ─────────────────────────────────────────────────────────────

/// Padding 方案：控制前 N 个 TLS 记录的填充/切分以对抗流量指纹分析。
#[derive(Clone)]
pub struct PaddingScheme {
    /// 停止 padding 的包号（不含，pkt >= stop 后原样发送）
    pub stop: u32,
    /// 原始 scheme 文本（每次需要重新随机化范围）
    pub raw: Vec<u8>,
    /// scheme 原文的小写 hex md5（协商比对用）
    pub md5_hex: String,
}

impl PaddingScheme {
    /// 从 scheme 原文解析；必须包含 `stop=` 行，否则返回 None。
    pub fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut stop = 0u32;
        let mut has_stop = false;

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, val) = line.split_once('=')?;
            if key.trim() == "stop" {
                stop = val.trim().parse().ok()?;
                has_stop = true;
            }
        }
        if !has_stop {
            return None;
        }

        let md5_hex = format!("{:x}", Md5::digest(raw));
        Some(PaddingScheme {
            stop,
            raw: raw.to_vec(),
            md5_hex,
        })
    }

    /// 为指定包号生成本次实际尺寸列表（每次调用都重新随机化）。
    /// 无对应规则的包号返回空列表（原样发送）。
    pub fn generate_sizes(&self, pkt: u32) -> Vec<i32> {
        let text = match std::str::from_utf8(&self.raw) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        let key = pkt.to_string();
        let prefix = format!("{}=", key);
        for line in text.lines() {
            if line.trim().starts_with(&prefix) {
                if let Some(val) = line.trim().get(prefix.len()..) {
                    return Self::parse_sizes(val.trim());
                }
            }
        }
        vec![]
    }

    fn parse_sizes(s: &str) -> Vec<i32> {
        let mut out = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part == "c" {
                out.push(PADDING_CHECK_MARK);
            } else if let Some((lo, hi)) = part.split_once('-') {
                let lo: i32 = lo.trim().parse().unwrap_or(0);
                let hi: i32 = hi.trim().parse().unwrap_or(0);
                let (lo, hi) = (lo.min(hi), lo.max(hi));
                if lo > 0 && hi > 0 {
                    if lo == hi {
                        out.push(lo);
                    } else {
                        let size = rand::thread_rng().gen_range(lo..hi);
                        out.push(size);
                    }
                }
            }
        }
        out
    }
}

// ── SharedPadding：可原子替换的共享 padding 方案 ─────────────────────────────

/// 线程安全、可动态更新的 padding 方案持有者（Clone 共享同一把锁）。
///
/// 双向共享同一实例：服务端在收到 cmdSettings 的 padding-md5 不匹配时，
/// 用 [`SharedPadding::update`] 下发自己的 scheme；客户端收到
/// cmdUpdatePaddingScheme 时同样更新。
#[derive(Clone)]
pub struct SharedPadding {
    scheme: Arc<RwLock<PaddingScheme>>,
}

impl SharedPadding {
    /// 使用内置默认方案创建
    pub fn new_default() -> Self {
        let scheme =
            PaddingScheme::parse(DEFAULT_PADDING_SCHEME).expect("default padding should parse");
        SharedPadding {
            scheme: Arc::new(RwLock::new(scheme)),
        }
    }

    /// 获取当前方案（克隆快照）
    pub fn get(&self) -> PaddingScheme {
        self.scheme.read().unwrap().clone()
    }

    /// 替换当前方案；scheme 非法时返回 false 且保持原方案
    pub fn update(&self, raw: &[u8]) -> bool {
        if let Some(new_scheme) = PaddingScheme::parse(raw) {
            *self.scheme.write().unwrap() = new_scheme;
            true
        } else {
            false
        }
    }

    /// 当前 scheme 原文的 md5 hex（cmdSettings 的 padding-md5 字段）
    pub fn md5(&self) -> String {
        self.scheme.read().unwrap().md5_hex.clone()
    }
}

// ── 帧编解码 ─────────────────────────────────────────────────────────────────

/// 构建单个会话帧：`[CMD][STREAM_ID 4B BE][DATA_LEN 2B BE][DATA]`。
///
/// 注意 `data.len()` 不得超过 [`MAX_FRAME_DATA`]；更长的 PSH 载荷由调用方
/// 拆分为多个帧（[`ServerStream`] 的写路径已处理）。
pub fn build_frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
    buf.push(cmd);
    buf.extend_from_slice(&sid.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// 对待发字节序列应用 padding 逻辑（参考 anytls-go proxy/session/session.go writeConn）。
///
/// - `pkt_counter`：调用方维护的写单位计数器（初值 0）。
/// - 首次调用得到 pkt=1：anytls-go 使用 `pkt = pktCounter.Add(1)`，Go 的
///   atomic.Add 返回**新值**，计数器初值 0，第一次 writeConn 得到 pkt=1
///   （对应 scheme "1=100-400"）。Rust 的 `fetch_add` 返回**旧值**，因此
///   内部 +1 对齐。scheme "0=30-30" 是认证帧 padding0 用的，不应被会话层
///   首包选中。
/// - `pkt >= stop` 或无对应规则时原样返回数据。
///
/// 返回值为若干帧的拼接：payload 切片（cmdPSH）+ cmdWaste 填充帧。
pub fn apply_padding(pkt_counter: &AtomicU32, padding: &PaddingScheme, data: Vec<u8>) -> Vec<u8> {
    let pkt = pkt_counter.fetch_add(1, Ordering::SeqCst) + 1;

    if pkt >= padding.stop {
        return data;
    }

    let sizes = padding.generate_sizes(pkt);
    if sizes.is_empty() {
        return data;
    }

    let mut out: Vec<u8> = Vec::with_capacity(data.len() + 512);
    let mut remaining = data;

    for size in sizes {
        if size == PADDING_CHECK_MARK {
            if remaining.is_empty() {
                break;
            } else {
                continue;
            }
        }
        let size = size as usize;
        let rem_len = remaining.len();

        if rem_len > size {
            // 这个包全是 payload
            out.extend_from_slice(&remaining[..size]);
            remaining = remaining[size..].to_vec();
        } else if rem_len > 0 {
            // payload 放完了，用 cmdWaste 填充到 size
            let padding_data_len = size.saturating_sub(rem_len + FRAME_HEADER_SIZE);
            out.extend_from_slice(&remaining);
            remaining.clear();
            if padding_data_len > 0 {
                // waste frame: [CMD_WASTE][streamId=0 4B][len 2B][zeros...]
                out.push(CMD_WASTE);
                out.extend_from_slice(&0u32.to_be_bytes());
                out.extend_from_slice(&(padding_data_len as u16).to_be_bytes());
                out.extend(std::iter::repeat_n(0u8, padding_data_len));
            }
        } else {
            // 纯 padding 包
            out.push(CMD_WASTE);
            out.extend_from_slice(&0u32.to_be_bytes());
            out.extend_from_slice(&(size as u16).to_be_bytes());
            out.extend(std::iter::repeat_n(0u8, size));
        }
    }

    if !remaining.is_empty() {
        out.extend_from_slice(&remaining);
    }
    out
}

// ── 认证帧编解码 ─────────────────────────────────────────────────────────────

/// 计算密码的 sha256（认证帧前 32 字节）
pub fn password_hash(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

/// 构建客户端认证帧：`[sha256(password) 32B][padding0_len 2B BE][padding0]`。
///
/// padding0 尺寸取 scheme 的 `0=...` 规则（默认 "0=30-30" → 30 字节），
/// 无规则时为 0。
pub fn build_auth_packet(password: &str, padding: &PaddingScheme) -> Vec<u8> {
    let hash = password_hash(password);
    let padding_sizes = padding.generate_sizes(0);
    let padding_len = padding_sizes.first().copied().unwrap_or(0).max(0) as usize;

    let mut out = Vec::with_capacity(32 + 2 + padding_len);
    out.extend_from_slice(&hash);
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend(std::iter::repeat_n(0u8, padding_len));
    out
}

/// 服务端读取认证帧：返回 sha256(password)（padding0 读后丢弃）。
pub async fn read_auth_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<[u8; 32]> {
    let mut head = [0u8; 34];
    reader.read_exact(&mut head).await?;
    let padding0_len = u16::from_be_bytes([head[32], head[33]]) as usize;
    if padding0_len > 0 {
        let mut discard = vec![0u8; padding0_len];
        reader.read_exact(&mut discard).await?;
    }
    Ok(head[..32].try_into().expect("32 bytes hash"))
}

// ── SOCKS5 地址编解码 ────────────────────────────────────────────────────────

/// 将目标编码为 SOCKS5 地址 `[ATYP][ADDR][PORT 2B BE]`
/// （stream 打开载荷与 UoT v2 请求头共用）。
pub fn encode_socks_addr(target: &Target) -> Vec<u8> {
    let mut buf = Vec::new();
    write_socks_addr_to(&mut buf, target);
    buf
}

/// 写入 SOCKS5 地址（标准 SOCKS5 ATYP：0x01/0x03/0x04）。
fn write_socks_addr_to(buf: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.push(SOCKS_ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(SOCKS_ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                buf.push(SOCKS_ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
}

/// 从流中读取 SOCKS5 地址（stream 打开载荷），返回解析后的目标。
pub async fn read_socks_addr<R: AsyncRead + Unpin>(reader: &mut R) -> anyhow::Result<Target> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await?;

    let target = match atyp[0] {
        SOCKS_ATYP_IPV4 => {
            let mut b = [0u8; 6]; // ip(4) + port(2)
            reader.read_exact(&mut b).await?;
            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            Target::Socket(SocketAddr::new(
                IpAddr::V4(ip),
                u16::from_be_bytes([b[4], b[5]]),
            ))
        }
        SOCKS_ATYP_IPV6 => {
            let mut b = [0u8; 18]; // ip(16) + port(2)
            reader.read_exact(&mut b).await?;
            let ip: [u8; 16] = b[..16].try_into().unwrap();
            Target::Socket(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes([b[16], b[17]]),
            ))
        }
        SOCKS_ATYP_DOMAIN => {
            let mut lb = [0u8; 1];
            reader.read_exact(&mut lb).await?;
            let mut host = vec![0u8; lb[0] as usize];
            reader.read_exact(&mut host).await?;
            let mut pb = [0u8; 2];
            reader.read_exact(&mut pb).await?;
            Target::Domain(String::from_utf8(host)?, u16::from_be_bytes(pb))
        }
        other => anyhow::bail!("anytls: unknown SOCKS ATYP 0x{other:02x}"),
    };
    Ok(target)
}

// ── sing UoT v2（UDP over session）编解码 ────────────────────────────────────

/// 判断 stream 打开载荷中的目标是否为 UoT v2 魔法地址。
pub fn is_uot_magic(target: &Target) -> bool {
    matches!(target, Target::Domain(d, _) if d == UOT_MAGIC_ADDRESS)
}

/// 构建 UoT v2 请求头：`[isConnect=0][SOCKS5 ATYP 目标][PORT]`。
///
/// 恒为无连接模式（isConnect=0，每包携带目标地址）。
pub fn build_uot_request(target: &Target) -> Vec<u8> {
    let mut buf = vec![0u8]; // isConnect = 0（无连接模式）
    write_socks_addr_to(&mut buf, target);
    buf
}

/// 构建 UoT v2 单个 UDP 包（无连接模式）：
/// `[sing ATYP][ADDR][PORT][LEN 2B BE][DATA]`。
pub fn build_uot_packet(target: &Target, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_uot_packet_addr_to(&mut buf, target);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// 写入 UoT v2 每个数据包的地址（sing 自定义 ATYP，与请求头 SOCKS5 ATYP 不同）。
fn write_uot_packet_addr_to(buf: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            buf.push(UOT_ATYP_DOMAIN);
            buf.push(host.len() as u8);
            buf.extend_from_slice(host.as_bytes());
            buf.extend_from_slice(&port.to_be_bytes());
        }
        Target::Socket(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buf.push(UOT_ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                buf.push(UOT_ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
}

/// 从流中读取一个 UoT v2 UDP 包（无连接模式），返回 (每包目标, 载荷)。
///
/// 每包地址使用 sing 自定义 ATYP（0x00/0x01/0x02），非标准 SOCKS5 ATYP。
pub async fn read_uot_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> anyhow::Result<(Target, Bytes)> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await?;

    let target = match atyp[0] {
        UOT_ATYP_IPV4 => {
            let mut buf = [0u8; 6]; // ip(4) + port(2)
            reader.read_exact(&mut buf).await?;
            let ip = std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Target::Socket(SocketAddr::new(IpAddr::V4(ip), port))
        }
        UOT_ATYP_IPV6 => {
            let mut buf = [0u8; 18]; // ip(16) + port(2)
            reader.read_exact(&mut buf).await?;
            let ip: [u8; 16] = buf[..16].try_into().unwrap();
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Target::Socket(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                port,
            ))
        }
        UOT_ATYP_DOMAIN => {
            let mut dlen = [0u8; 1];
            reader.read_exact(&mut dlen).await?;
            let mut domain = vec![0u8; dlen[0] as usize];
            reader.read_exact(&mut domain).await?;
            let mut port_buf = [0u8; 2];
            reader.read_exact(&mut port_buf).await?;
            let port = u16::from_be_bytes(port_buf);
            Target::Domain(String::from_utf8(domain)?, port)
        }
        other => anyhow::bail!("unknown UoT per-packet atyp: 0x{:02x}", other),
    };

    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let data_len = u16::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; data_len];
    reader.read_exact(&mut data).await?;

    Ok((target, Bytes::from(data)))
}

// ── 服务端会话多路复用 ───────────────────────────────────────────────────────

/// 服务端会话内的一条双向 stream。
///
/// - 读：会话读循环把 cmdPSH 载荷经 `rx` 送达（空 Vec / 通道关闭 = EOF）。
/// - 写：`poll_write` 把数据拆分为 cmdPSH 帧经共享写通道发出；**首次写之前
///   自动发送空 cmdSYNACK**（对齐 sing-anytls：拨号成功后有数据下行才回
///   SYNACK；拨号失败时本 stream 被直接丢弃，客户端只见 FIN/EOF）。
/// - Drop：尽力发送 cmdFIN 通知客户端此 stream 关闭。
pub struct ServerStream {
    /// 会话内 stream ID（cmdSYN 携带的 SID）
    pub stream_id: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::UnboundedSender<(u8, u32, Vec<u8>)>,
    buf: BytesMut,
    synack_sent: bool,
}

impl ServerStream {
    /// 发送 cmdSYNACK 携带错误信息，通知客户端拒绝打开此 stream
    /// （v2 协议；reflex 入站默认走"首写才 SYNACK"路径，本方法供
    /// 需要显式拒绝语义的实现使用）。
    pub fn handshake_failure(&self, err: &str) {
        let _ = self
            .write_tx
            .send((CMD_SYNACK, self.stream_id, err.as_bytes().to_vec()));
    }
}

impl Drop for ServerStream {
    fn drop(&mut self) {
        // 尽力发送 FIN（会话写任务已退出时 send 失败，静默忽略）。
        // poll_shutdown 后可能重复发送 FIN，客户端按 SID 幂等处理，无害。
        let _ = self.write_tx.send((CMD_FIN, self.stream_id, Vec::new()));
    }
}

impl AsyncRead for ServerStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 先消费本地缓冲（上次跨帧残留）
        if !self.buf.is_empty() {
            let n = self.buf.len().min(buf.remaining());
            buf.put_slice(&self.buf[..n]);
            let _ = self.buf.split_to(n);
            return std::task::Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    // cmdFIN / 会话结束的 EOF 信号
                    return std::task::Poll::Ready(Ok(()));
                }
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.buf.extend_from_slice(&data[n..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            // 通道关闭（会话结束、所有 stream 已收 EOF）→ 常规 EOF
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // 首次写之前先发空 cmdSYNACK（对齐 sing-anytls：有下行数据 = 拨号成功）
        if !this.synack_sent {
            this.synack_sent = true;
            let _ = this
                .write_tx
                .send((CMD_SYNACK, this.stream_id, Vec::new()));
        }

        // 对齐 sing-anytls writeDataFrame：超过单帧上限时拆分为多个 cmdPSH
        for chunk in data.chunks(MAX_FRAME_DATA) {
            if this
                .write_tx
                .send((CMD_PSH, this.stream_id, chunk.to_vec()))
                .is_err()
            {
                // 会话写任务已退出；后续读会得到 EOF，这里返回 BrokenPipe
                return std::task::Poll::Ready(Err(std::io::Error::from(
                    std::io::ErrorKind::BrokenPipe,
                )));
            }
        }
        std::task::Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // 帧经通道即时交给写任务，无需额外 flush
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let _ = this.write_tx.send((CMD_FIN, this.stream_id, Vec::new()));
        std::task::Poll::Ready(Ok(()))
    }
}

/// 解析 cmdSettings 的 KV 文本（每行 `key=value`）。
fn parse_kv(data: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(s) = std::str::from_utf8(data) {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    map
}

/// 运行 AnyTLS 服务端会话多路复用（TLS 认证通过后的主循环）。
///
/// - 收到 cmdSettings：记录对端版本；padding-md5 与本地 scheme 不匹配时下发
///   cmdUpdatePaddingScheme；对端 v2+ 时回 cmdServerSettings(`v=2`)。
/// - 收到 cmdSYN（必须先收到 cmdSettings）：为每个新 stream 调用一次
///   `on_stream`（异步任务内消费 [`ServerStream`]，读 SOCKS5 目标地址后
///   中继）。
/// - 收到 cmdAlert / 连接错误：结束会话，向所有活跃 stream 发送 EOF。
///
/// 出站方向：所有帧经单一写任务串行写出，并按共享 padding scheme 应用
/// padding（对齐 anytls-go 服务端 writeConn）。
pub async fn run_server_session<S, F, Fut>(
    conn: S,
    padding: SharedPadding,
    mut on_stream: F,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(ServerStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    // 写通道：所有 stream 共享单一写任务（unbounded，写路径在 poll 中不能阻塞）
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<(u8, u32, Vec<u8>)>();
    let (mut read_half, mut write_half) = tokio::io::split(conn);

    // ── 写任务：串行化出站帧 + 应用 padding ─────────────────────────────────
    let writer_padding = padding.clone();
    tokio::spawn(async move {
        let pkt_counter = AtomicU32::new(0);
        while let Some((cmd, sid, data)) = write_rx.recv().await {
            let frame = build_frame(cmd, sid, &data);
            let out = apply_padding(&pkt_counter, &writer_padding.get(), frame);
            if write_half.write_all(&out).await.is_err() {
                break;
            }
        }
        let _ = write_half.shutdown().await;
    });

    // ── 读循环 ───────────────────────────────────────────────────────────────
    let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut peer_version: u8 = 1;
    let mut received_settings = false;
    let mut hdr = [0u8; FRAME_HEADER_SIZE];

    loop {
        if read_half.read_exact(&mut hdr).await.is_err() {
            break;
        }

        let cmd = hdr[0];
        let sid = u32::from_be_bytes(hdr[1..5].try_into().unwrap());
        let dlen = u16::from_be_bytes([hdr[5], hdr[6]]) as usize;
        let data = if dlen > 0 {
            let mut d = vec![0u8; dlen];
            if read_half.read_exact(&mut d).await.is_err() {
                break;
            }
            d
        } else {
            vec![]
        };

        match cmd {
            CMD_WASTE => { /* padding，静默丢弃 */ }

            CMD_SETTINGS => {
                received_settings = true;
                let settings = parse_kv(&data);

                // 协议版本
                if let Some(v_str) = settings.get("v") {
                    if let Ok(v) = v_str.parse::<u8>() {
                        peer_version = v;
                    }
                }

                // padding-md5 不匹配 → 下发本地 scheme
                let client_md5 = settings
                    .get("padding-md5")
                    .map(String::as_str)
                    .unwrap_or("");
                let scheme = padding.get();
                if client_md5 != scheme.md5_hex {
                    let _ = write_tx.send((CMD_UPDATE_PADDING, 0, scheme.raw.clone()));
                }

                // 客户端 v2+ → 回 cmdServerSettings
                if peer_version >= 2 {
                    let _ = write_tx.send((CMD_SERVER_SETTINGS, 0, b"v=2".to_vec()));
                }
            }

            CMD_SYN => {
                if !received_settings {
                    warn!("anytls server: client opened a stream before sending settings");
                    let _ = write_tx.send((
                        CMD_ALERT,
                        0,
                        b"client did not send its settings before opening a stream".to_vec(),
                    ));
                    break;
                }

                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                streams.insert(sid, tx);

                let stream = ServerStream {
                    stream_id: sid,
                    rx,
                    write_tx: write_tx.clone(),
                    buf: BytesMut::new(),
                    synack_sent: false,
                };
                // SYNACK 由 ServerStream 首次写时发送（对齐 sing-anytls：
                // 拨号成功有下行数据才回 SYNACK；拨号失败客户端只见 FIN/EOF）
                tokio::spawn(on_stream(stream));
            }

            CMD_PSH => {
                let dead = match streams.get(&sid) {
                    Some(tx) => tx.send(data).await.is_err(),
                    None => false,
                };
                if dead {
                    // 接收端已消失，移除此 stream
                    streams.remove(&sid);
                }
            }

            CMD_FIN => {
                if let Some(tx) = streams.remove(&sid) {
                    // 空 Vec 作为 EOF 信号
                    let _ = tx.send(Vec::new()).await;
                }
            }

            CMD_UPDATE_PADDING => {
                if !padding.update(&data) {
                    debug!("anytls server: client sent invalid padding scheme, ignored");
                }
            }

            CMD_HEART_REQUEST => {
                let _ = write_tx.send((CMD_HEART_RESPONSE, sid, Vec::new()));
            }

            CMD_HEART_RESPONSE | CMD_SERVER_SETTINGS | CMD_SYNACK => {
                /* 服务端不应收到，忽略 */
            }

            CMD_ALERT => {
                warn!(
                    msg = %String::from_utf8_lossy(&data),
                    "anytls server: alert from client"
                );
                break;
            }

            other => {
                debug!(cmd = other, "anytls server: unknown cmd, ignored");
            }
        }
    }

    // 会话结束：向所有活跃 stream 发送 EOF
    for (_, tx) in streams.drain() {
        let _ = tx.send(Vec::new()).await;
    }
    Ok(())
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_scheme_parse_default() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        assert_eq!(scheme.stop, 8);
        assert!(!scheme.md5_hex.is_empty());
        assert_eq!(scheme.md5_hex.len(), 32);
    }

    #[test]
    fn padding_scheme_generate() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        // pkt=0: "0=30-30" → always 30
        let sizes = scheme.generate_sizes(0);
        assert_eq!(sizes.len(), 1);
        assert_eq!(sizes[0], 30);
        // pkt=8: stop=8 → out of range
        let sizes = scheme.generate_sizes(8);
        assert!(sizes.is_empty());
    }

    #[test]
    fn socks_addr_ipv4() {
        let target = Target::Socket("1.2.3.4:80".parse().unwrap());
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_IPV4);
        assert_eq!(&b[1..5], &[1, 2, 3, 4]);
        assert_eq!(u16::from_be_bytes([b[5], b[6]]), 80);
    }

    #[test]
    fn socks_addr_ipv6() {
        let target = Target::Socket("[::1]:443".parse().unwrap());
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_IPV6);
        assert_eq!(u16::from_be_bytes([b[17], b[18]]), 443);
    }

    #[test]
    fn socks_addr_domain() {
        let target = Target::Domain("example.com".into(), 443);
        let b = encode_socks_addr(&target);
        assert_eq!(b[0], SOCKS_ATYP_DOMAIN);
        assert_eq!(b[1], 11);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(u16::from_be_bytes([b[13], b[14]]), 443);
    }

    #[test]
    fn uot_request_header() {
        let target = Target::Socket("8.8.8.8:53".parse().unwrap());
        let hdr = build_uot_request(&target);
        // 首字节是 isConnect=0（无连接模式），不是 version
        assert_eq!(hdr[0], 0u8);
        // 请求头地址使用标准 SOCKS5 ATYP（0x01=IPv4）
        assert_eq!(hdr[1], SOCKS_ATYP_IPV4);
        assert_eq!(&hdr[2..6], &[8, 8, 8, 8]);
        assert_eq!(u16::from_be_bytes([hdr[6], hdr[7]]), 53);
    }

    #[test]
    fn uot_packet_build() {
        let target = Target::Socket("8.8.8.8:53".parse().unwrap());
        let data = b"dns-query";
        let pkt = build_uot_packet(&target, data);
        // 每包地址使用 sing 自定义 ATYP（0x00=IPv4），非标准 SOCKS5 ATYP
        assert_eq!(pkt[0], UOT_ATYP_IPV4);
        let data_len = u16::from_be_bytes([pkt[7], pkt[8]]) as usize;
        assert_eq!(data_len, data.len());
        assert_eq!(&pkt[9..9 + data_len], data);
    }

    #[test]
    fn uot_magic_detect() {
        assert!(is_uot_magic(&Target::Domain(UOT_MAGIC_ADDRESS.into(), UOT_MAGIC_PORT)));
        assert!(!is_uot_magic(&Target::Domain("example.com".into(), 443)));
        assert!(!is_uot_magic(&Target::Socket("8.8.8.8:443".parse().unwrap())));
    }

    #[test]
    fn frame_build_syn() {
        let f = build_frame(CMD_SYN, 42, &[]);
        assert_eq!(f[0], CMD_SYN);
        assert_eq!(u32::from_be_bytes(f[1..5].try_into().unwrap()), 42);
        assert_eq!(u16::from_be_bytes([f[5], f[6]]), 0);
        assert_eq!(f.len(), FRAME_HEADER_SIZE);
    }

    #[test]
    fn frame_build_psh() {
        let data = b"hello";
        let f = build_frame(CMD_PSH, 1, data);
        assert_eq!(f[0], CMD_PSH);
        assert_eq!(u32::from_be_bytes(f[1..5].try_into().unwrap()), 1);
        assert_eq!(u16::from_be_bytes([f[5], f[6]]), 5);
        assert_eq!(&f[7..], data);
    }

    #[test]
    fn sha256_auth() {
        let hash = password_hash("password");
        assert_eq!(hash.len(), 32);
        // sha256("password") 前 4 字节（参考 anytls-go 测试）
        assert_eq!(hash[0], 0x5e);
    }

    #[test]
    fn auth_packet_layout() {
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        let pkt = build_auth_packet("password", &scheme);
        // padding0 尺寸来自 scheme "0=30-30"
        assert_eq!(pkt.len(), 32 + 2 + 30);
        assert_eq!(&pkt[..32], &password_hash("password")[..]);
        assert_eq!(u16::from_be_bytes([pkt[32], pkt[33]]), 30);
    }

    #[test]
    fn padding_apply_noop_after_stop() {
        // pkt >= stop → 直接返回原始数据
        // 构造一个 stop=0 的 scheme（所有 pkt 都超过 stop）
        let scheme = PaddingScheme {
            stop: 0,
            raw: b"stop=0".to_vec(),
            md5_hex: "deadbeef".to_string(),
        };
        let counter = AtomicU32::new(0);
        let data = vec![1u8, 2, 3, 4];
        assert_eq!(apply_padding(&counter, &scheme, data.clone()), data);
    }

    #[test]
    fn padding_first_pkt_uses_scheme_1_not_0() {
        // 验证 anytls-go 对齐：首次 writeConn 应得到 pkt=1（scheme "1=100-400"），
        // 而非 pkt=0（scheme "0=30-30"，保留给认证帧 padding0）。
        //
        // 默认 scheme：
        //   0=30-30       → 输出 30 字节
        //   1=100-400     → 输出 100~400 字节
        //
        // 给 10 字节输入：
        //   - pkt=0 (bug) → 30 字节
        //   - pkt=1 (fix) → 100~400 字节
        let scheme = PaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        let counter = AtomicU32::new(0);
        let data = vec![0xABu8; 10];
        let out = apply_padding(&counter, &scheme, data);
        // scheme "1=100-400"：输出至少 100 字节（远大于 "0=30-30" 的 30 字节）
        assert!(
            out.len() >= 100,
            "expected pkt=1 padding (>=100 bytes), got {} bytes (pkt=0 bug?)",
            out.len()
        );
        assert!(out.len() <= 400, "expected <=400 bytes, got {}", out.len());
        // 计数器已递增到 1（fetch_add 返回旧值 0，内部值已为 1）
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
