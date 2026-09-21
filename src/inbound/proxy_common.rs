//! VLESS / VMess / Trojan 服务端入站共享工具。

use std::net::SocketAddr;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::net::TcpListener;

use crate::inbound::Target;

// ── packetaddr 分帧（VLESS / VMess UDP over TCP 共用）────────────────────────
//
// 每个 UDP 包 = 一个帧，兼容两种帧格式（自动检测，按首个上行帧记忆回包格式）：
// - sing/reflex 风格：`[ATYP][ADDR][PORT][DATA]`（无长度前缀，帧边界由一次
//   写入 / 一个解密 chunk 提供）
// - Xray/flux 风格：`[LEN 2B BE][ATYP][ADDR][PORT][DATA]`（帧首字节 0x00 触发）
//
// packetaddr ATYP 与请求头 ATYP 不同：0x01=IPv4，0x02=IPv6，不支持域名
// （对齐 sing-vmess packetaddr.AddressSerializer）。

pub const PACKETADDR_ATYP_IPV4: u8 = 0x01;
pub const PACKETADDR_ATYP_IPV6: u8 = 0x02;

/// 上行帧解析结果
pub struct UplinkFrame {
    pub target: Target,
    pub data: Bytes,
}

/// 判断请求头目标是否为 packetaddr 魔术地址（`sp.packet-addr.v2fly.arpa:443`）。
pub fn is_packetaddr_magic(target: &Target) -> bool {
    matches!(
        target,
        Target::Domain(d, p)
            if d == crate::protocol::vmess::PACKETADDR_MAGIC
                && *p == crate::protocol::vmess::PACKETADDR_MAGIC_PORT
    )
}

/// 从一次读取到的"帧单元"（无分帧协议下 = 一次 read 的内容；分块协议下 = 一个
/// 解密后的 chunk）中解析 packetaddr 帧。自动检测长度前缀（Xray 风格）。
///
/// 返回 (帧, 是否使用了 2B 长度前缀)。解析失败返回 None（跳过该帧）。
pub fn parse_packetaddr_unit(unit: &[u8]) -> Option<(UplinkFrame, bool)> {
    // Xray 风格：帧首 2 字节为长度（首字节几乎恒为 0x00，因为帧长 < 256 时
    // 高字节为 0；reflex/sing 无前缀风格首字节为 ATYP ∈ {0x01, 0x02}）
    if unit.len() >= 9 && unit[0] == 0x00 {
        let len = u16::from_be_bytes([unit[0], unit[1]]) as usize;
        if len >= 7 && unit.len() >= 2 + len {
            if let Some(f) = parse_packetaddr_body(&unit[2..2 + len]) {
                return Some((f, true));
            }
        }
    }
    // reflex/sing 风格：整段即 ATYP+ADDR+PORT+DATA
    parse_packetaddr_body(unit).map(|f| (f, false))
}

/// 解析 `[ATYP][ADDR][PORT][DATA]`（packetaddr ATYP：0x01=IPv4，0x02=IPv6）。
fn parse_packetaddr_body(body: &[u8]) -> Option<UplinkFrame> {
    let (target, hdr_len) = match body.first().copied()? {
        PACKETADDR_ATYP_IPV4 if body.len() >= 7 => {
            let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                body[1], body[2], body[3], body[4],
            ));
            let port = u16::from_be_bytes([body[5], body[6]]);
            (Target::Socket(SocketAddr::new(ip, port)), 7usize)
        }
        PACKETADDR_ATYP_IPV6 if body.len() >= 19 => {
            let ip: [u8; 16] = body[1..17].try_into().ok()?;
            let port = u16::from_be_bytes([body[17], body[18]]);
            (
                Target::Socket(SocketAddr::new(std::net::IpAddr::V6(ip.into()), port)),
                19,
            )
        }
        _ => return None,
    };
    Some(UplinkFrame {
        target,
        data: Bytes::copy_from_slice(&body[hdr_len..]),
    })
}

/// 构建下行 packetaddr 帧。
pub fn encode_packetaddr_frame(addr: SocketAddr, data: &[u8], length_prefixed: bool) -> BytesMut {
    let mut buf = BytesMut::with_capacity(24 + data.len());
    let body_len = 1 + if addr.is_ipv4() { 4 } else { 16 } + 2 + data.len();
    if length_prefixed {
        buf.put_u16(body_len as u16);
    }
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            buf.put_u8(PACKETADDR_ATYP_IPV4);
            buf.put_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            buf.put_u8(PACKETADDR_ATYP_IPV6);
            buf.put_slice(&ip.octets());
        }
    }
    buf.put_u16(addr.port());
    buf.put_slice(data);
    buf
}

/// 绑定 TCP 监听 socket。
///
/// 对 IPv6 未指定地址（`[::]:port`）显式设置 `IPV6_V6ONLY=0`，保证双栈语义
/// （Windows 默认 IPv6-only；Linux 取决于 net.ipv6.bindv6only）。IPv4 地址
/// 直接绑定。对齐 sing-box inbound 的 `::` 监听行为（同时接受 IPv4/IPv6）。
pub async fn bind_dual_stack_listener(bind: SocketAddr) -> anyhow::Result<TcpListener> {
    if bind.is_ipv6() && bind.ip().is_unspecified() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        socket.set_nonblocking(true)?;

        socket
            .set_only_v6(false)
            .map_err(|e| anyhow::anyhow!("set IPV6_V6ONLY=0 failed: {e}"))?;

        socket.bind(&bind.into())?;
        socket.listen(1024)?;

        #[cfg(unix)]
        {
            use std::os::fd::{FromRawFd, IntoRawFd};
            // socket.into() → std UnixStream 不适用；手动转换 fd
            let raw = socket.into_raw_fd();
            // SAFETY: raw fd 来自刚创建的监听 socket，所有权移交 TcpListener
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(raw) };
            Ok(TcpListener::from_std(std_listener)?)
        }
        #[cfg(not(unix))]
        {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            let raw = socket.into_raw_socket();
            // SAFETY: raw socket 来自刚创建的监听 socket，所有权移交 TcpListener
            let std_listener =
                unsafe { std::net::TcpListener::from_raw_socket(raw) };
            Ok(TcpListener::from_std(std_listener)?)
        }
    } else {
        Ok(TcpListener::bind(bind).await?)
    }
}

/// 解析 UDP 回包的分帧地址。
///
/// - 最近上行目标是 Socket（IP）→ 直接使用（packetaddr 帧只承载 IP）
/// - 目标是域名或未知 → 回退到出站层回包元组携带的伪造源地址（仅当其
///   IP 非未指定时可用；域名目标回包的伪造地址是 0.0.0.0:port 占位）
pub fn resolve_reply_addr(
    last_target: &Option<Target>,
    spoofed_src: SocketAddr,
) -> Option<SocketAddr> {
    if let Some(Target::Socket(a)) = last_target {
        return Some(*a);
    }
    if !spoofed_src.ip().is_unspecified() {
        return Some(spoofed_src);
    }
    None
}

// ── TcpStream 句柄复制 ──────────────────────────────────────────────────────
//
// tokio 1.x 移除了 `TcpStream::try_clone`；需要同一连接的第二个独立句柄时
// 手动复制底层 fd / SOCKET。典型用途：入站协议读完头后把 raw stream 原样
// 移交 dispatcher，同时保留一个句柄用于错误时发 RST（SO_LINGER=0）。

/// 复制一个 tokio TcpStream（独立的 fd/SOCKET，共享同一连接）。
pub fn duplicate_tcp_stream(
    stream: &tokio::net::TcpStream,
) -> std::io::Result<tokio::net::TcpStream> {
    #[cfg(unix)]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        // SAFETY: 仅借用 fd 做 dup，不接管原句柄所有权
        let dup_fd = unsafe { libc::dup(AsRawFd::as_raw_fd(stream)) };
        if dup_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let std_stream = unsafe {
            // SAFETY: dup 出的 fd 所有权移交 std TcpStream
            std::net::TcpStream::from_raw_fd(dup_fd)
        };
        std_stream.set_nonblocking(true)?;
        // SAFETY: 非阻塞 std stream 所有权移交 tokio
        tokio::net::TcpStream::from_std(std_stream)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
        use windows::Win32::System::Threading::GetCurrentProcess;

        let raw = stream.as_raw_socket();
        let mut dup_handle = HANDLE::default();
        // SAFETY: 复制当前进程的 socket 句柄
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                HANDLE(raw as _),
                GetCurrentProcess(),
                &mut dup_handle,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        }
        let std_stream = unsafe {
            // SAFETY: 复制出的 SOCKET 所有权移交 std TcpStream
            std::net::TcpStream::from_raw_socket(dup_handle.0 as u64)
        };
        std_stream.set_nonblocking(true)?;
        // SAFETY: 非阻塞 std stream 所有权移交 tokio
        tokio::net::TcpStream::from_std(std_stream)
    }
}
