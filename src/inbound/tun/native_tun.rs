#![allow(dead_code)]

//! NativeTun：在 tun::AsyncDevice 上叠加 virtio_net_hdr 处理与 GSO/GRO、批量 I/O。
//!
//! ## virtio_net_hdr 语义（B1 修复）
//!
//! Linux 上设备以 IFF_VNET_HDR 打开后，内核在**每个**读写数据包前都附带
//! 10 字节 virtio_net_hdr（tun crate 0.8 仅设置 flag，不做任何剥头/加头）。
//! 因此：
//! - 读方向：无论 TUNSETOFFLOAD 是否成功，只要 IFF_VNET_HDR 生效就必须剥头；
//!   仅当 hdr.gso_type != NONE（内核启用了 TSO/USO 卸载）时才按 hdr 拆分大包。
//! - 写方向：任何写入都必须在 IP 包前补一个 virtio_net_hdr（GRO 合并包由
//!   handle_gro 填写真实 hdr，普通包填全零 hdr，gso_type = NONE）。
//!
//! 参考 sing-tun tun_linux.go：`Read`/`Write` 均以 `vnetHdr` 为条件统一处理，
//! 而非以 GSO 卸载成功与否为条件；GRO 合并以 `gro`（groDisablementFlags）
//! 为条件逐包判断。
//!
//! ## 读写分离
//!
//! 读、写持有**独立**的 `Arc<Mutex<..>>`（对齐 sing-tun 的 readAccess /
//! writeAccess 双锁），避免 gvisor 栈中读循环在等待数据时阻塞写路径。

use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

/// TUN 读半部抽象：批量读取 IP 包（不含 virtio_net_hdr）。
#[async_trait::async_trait]
pub trait TunReader: Send {
    /// 批量读取数据包。返回每个包的长度列表（按 bufs 顺序填充）。
    /// 返回空 Vec 表示设备已关闭。
    async fn batch_read(&mut self, bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>>;
}

/// TUN 写半部抽象：批量写入 IP 包（不含 virtio_net_hdr）。
///
/// 实现 `AsyncWrite` 时必须自行处理 virtio_net_hdr 前置（Linux IFF_VNET_HDR），
/// 调用方传入的始终是纯 IP 包。
#[async_trait::async_trait]
pub trait TunWriter: AsyncWrite + Unpin + Send {
    /// 批量写入数据包，返回成功写入的包数。
    async fn batch_write(&mut self, packets: &[&[u8]]) -> std::io::Result<usize>;

    /// 获取前端头部预留空间（Linux IFF_VNET_HDR 模式下为 virtio_net_hdr 长度）。
    fn front_headroom(&self) -> usize {
        0
    }

    /// probeTCPGRO 探针（B10 修复，对齐 sing-tun NativeTun.probeTCPGRO）。
    ///
    /// 向 TUN 写入两个可合并的 TCP 探针段（经 userspace GRO 合并为一个
    /// GSO 包），若内核拒绝写入（部分 Android 内核 TUNSETOFFLOAD 成功但
    /// 无法处理 GSO 包），则禁用 TCP+UDP GRO 并返回 Err。
    /// 非 Linux 平台默认无操作。
    async fn probe_tcp_gro(&mut self, _probe_addr: Option<Ipv4Addr>) -> std::io::Result<()> {
        Ok(())
    }
}

/// NativeTun 封装：持有独立的读写半部。
pub struct NativeTun {
    reader: Arc<Mutex<Box<dyn TunReader + Send + 'static>>>,
    writer: Arc<Mutex<Box<dyn TunWriter + Send + 'static>>>,
    mtu: usize,
    #[cfg(target_os = "linux")]
    vnet_hdr: bool,
    #[cfg(target_os = "linux")]
    gro: super::gso::GroDisablementFlags,
}

impl NativeTun {
    /// 创建 NativeTun 实例。
    ///
    /// - `vnet_hdr`：设备是否以 IFF_VNET_HDR 打开（Linux 由 TUNGETIFF 探测；
    ///   其他平台恒为 false）。控制读写方向 virtio_net_hdr 的剥除/前置。
    /// - `gro`：GRO 合并禁用标志（TUNSETOFFLOAD 探测结果；探针失败时也会
    ///   置位，由 writer 内部持有并可变）。
    pub fn with_gso(
        dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        mtu: usize,
        vnet_hdr: bool,
        gro: super::gso::GroDisablementFlags,
    ) -> Self {
        let (reader_half, writer_half) = tokio::io::split(dev);

        #[cfg(target_os = "linux")]
        {
            let reader = linux_impl::LinuxTunReader::new(Box::pin(reader_half), vnet_hdr);
            let writer = linux_impl::LinuxTunWriter::new(Box::pin(writer_half), vnet_hdr, gro);
            Self {
                reader: Arc::new(Mutex::new(Box::new(reader))),
                writer: Arc::new(Mutex::new(Box::new(writer))),
                mtu,
                vnet_hdr,
                gro,
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (vnet_hdr, gro);
            let reader = simple_impl::SimpleTunReader::new(Box::pin(reader_half));
            let writer = simple_impl::SimpleTunWriter::new(Box::pin(writer_half));
            Self {
                reader: Arc::new(Mutex::new(Box::new(reader))),
                writer: Arc::new(Mutex::new(Box::new(writer))),
                mtu,
            }
        }
    }

    /// 获取 MTU。
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// IFF_VNET_HDR 是否生效（仅 Linux）。
    pub fn vnet_hdr(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.vnet_hdr
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// GRO 禁用标志快照（仅 Linux，探针执行前的初始值）。
    pub fn gro_flags(&self) -> super::gso::GroDisablementFlags {
        #[cfg(target_os = "linux")]
        {
            self.gro
        }
        #[cfg(not(target_os = "linux"))]
        {
            super::gso::GroDisablementFlags::default()
        }
    }

    /// 拆分 NativeTun 为读写两半（两半可并发使用，互不阻塞）。
    pub fn split(self) -> (NativeTunReader, NativeTunWriter) {
        (
            NativeTunReader { inner: self.reader },
            NativeTunWriter { inner: self.writer },
        )
    }
}

/// NativeTun 读取半部。
pub struct NativeTunReader {
    inner: Arc<Mutex<Box<dyn TunReader + Send + 'static>>>,
}

impl NativeTunReader {
    /// 读取一个 IP 包（批量接口的单包退化形式）。
    pub async fn read_packet(&mut self) -> std::io::Result<Vec<u8>> {
        let mut io = self.inner.lock().await;
        let mut buf = Vec::new();
        let sizes = io.batch_read(std::slice::from_mut(&mut buf)).await?;
        if sizes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "tun device closed",
            ));
        }
        buf.truncate(sizes[0]);
        Ok(buf)
    }

    /// 批量读取 IP 包。
    pub async fn read_batch(&mut self, bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
        let mut io = self.inner.lock().await;
        io.batch_read(bufs).await
    }
}

/// NativeTun 写入半部。
pub struct NativeTunWriter {
    inner: Arc<Mutex<Box<dyn TunWriter + Send + 'static>>>,
}

impl NativeTunWriter {
    /// 写入一个 IP 包。
    pub async fn write_packet(&self, data: &[u8]) -> std::io::Result<()> {
        let mut io = self.inner.lock().await;
        io.write_all(data).await
    }

    /// 批量写入 IP 包。
    pub async fn write_batch(&self, packets: &[&[u8]]) -> std::io::Result<usize> {
        let mut io = self.inner.lock().await;
        io.batch_write(packets).await
    }

    /// 获取前端头部预留空间（Linux IFF_VNET_HDR 模式下为 virtio_net_hdr 长度）。
    pub async fn front_headroom(&self) -> usize {
        let io = self.inner.lock().await;
        io.front_headroom()
    }

    /// 执行 probeTCPGRO 探针（B10）。失败时内部已禁用 TCP+UDP GRO。
    pub async fn probe_tcp_gro(&self, probe_addr: Option<Ipv4Addr>) -> std::io::Result<()> {
        let mut io = self.inner.lock().await;
        io.probe_tcp_gro(probe_addr).await
    }

    /// 返回内部 writer handle 的克隆。
    ///
    /// `Box<dyn TunWriter>` 实现了 `AsyncWrite + Unpin + Send`，因此
    /// `Arc<Mutex<Box<dyn TunWriter + Send>>>` 可直接用作泛型 writer 参数
    /// （如 `tun_write` / `process_ipv4` / `IcmpForwarder`）。
    /// 写入时 virtio_net_hdr 由 `LinuxTunWriter::poll_write` 自动前置。
    pub fn handle(&self) -> Arc<Mutex<Box<dyn TunWriter + Send + 'static>>> {
        self.inner.clone()
    }
}

// ── Linux 实现：virtio_net_hdr + GSO/GRO + 批量 I/O ──────────────────────────

#[cfg(target_os = "linux")]
pub mod linux_impl {
    use super::super::gso;
    use super::*;

    /// Linux TUN 读半部。
    ///
    /// - `vnet_hdr`：每次 read 返回 [virtio_net_hdr(10B)][IP包]，必须剥头。
    ///   该条件仅取决于 IFF_VNET_HDR 是否生效，与 TUNSETOFFLOAD 是否成功
    ///   无关（B1 修复：旧实现以 gso 布尔为条件，ioctl 失败时不剥头，
    ///   所有包首字节被当作 IP version 解析 → 全部丢弃）。
    /// - 读到的 hdr.gso_type != NONE 时（内核启用 TSO/USO 卸载才会出现）
    ///   拆分为多个 segment。
    pub struct LinuxTunReader {
        reader: Pin<Box<dyn AsyncRead + Unpin + Send>>,
        vnet_hdr: bool,
        /// 读缓冲：GSO 时需容纳 virtio_net_hdr + 大包（最大 GSO_MAX_SIZE）
        read_buf: Vec<u8>,
        /// GSO 拆分后的 segment 输出缓冲
        gso_out_bufs: Vec<Vec<u8>>,
        gso_sizes: Vec<usize>,
        /// 待消费的 segment 队列（GSO 拆分后逐个返回）
        pending_segments: Vec<Vec<u8>>,
        pending_idx: usize,
    }

    impl LinuxTunReader {
        pub fn new(reader: Pin<Box<dyn AsyncRead + Unpin + Send>>, vnet_hdr: bool) -> Self {
            Self {
                reader,
                vnet_hdr,
                read_buf: vec![0u8; gso::GSO_MAX_SIZE + gso::VIRTIO_NET_HDR_LEN + 64],
                gso_out_bufs: (0..gso::IDEAL_BATCH_SIZE).map(|_| Vec::new()).collect(),
                gso_sizes: vec![0; gso::IDEAL_BATCH_SIZE],
                pending_segments: Vec::new(),
                pending_idx: 0,
            }
        }

        /// 批量读取：读取一个或多个包，剥 virtio_net_hdr，GSO 拆分后返回。
        pub async fn do_batch_read(&mut self, bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
            // 先消费 pending segments（上次 GSO 拆分剩余）
            let mut result = Vec::new();
            while self.pending_idx < self.pending_segments.len() && result.len() < bufs.len() {
                let seg = std::mem::take(&mut self.pending_segments[self.pending_idx]);
                let len = seg.len();
                bufs[result.len()] = seg;
                result.push(len);
                self.pending_idx += 1;
            }
            if result.len() >= bufs.len() || bufs.is_empty() {
                return Ok(result);
            }

            // 从 TUN 设备读取
            let n = self.reader.read(&mut self.read_buf).await?;
            if n == 0 {
                return Ok(result);
            }

            if self.vnet_hdr && n > gso::VIRTIO_NET_HDR_LEN {
                // IFF_VNET_HDR：前 10 字节是 virtio_net_hdr，必须剥除。
                // 无论 TUNSETOFFLOAD 是否成功，只要 IFF_VNET_HDR 生效，
                // 内核都会在每个读到的包前附带该头（B1 修复）。
                //
                // 对齐 sing-tun handleVirtioRead（tun_linux.go:354-387）：
                // 无论是否 GSO 包都统一走 gso_split —— 非阻塞地
                // NEEDS_CSUM 的非 GSO 包（校验和卸载，gsoType=NONE，
                // 校验和字段只含伪头部和）在 gso_split 的单包路径中补
                // 全校验和；否则 smoltcp/gvisor 校验和验证会静默丢包。
                let pkt = &self.read_buf[gso::VIRTIO_NET_HDR_LEN..n];
                let mut options = match gso::VirtioNetHdr::decode(
                    &self.read_buf[..gso::VIRTIO_NET_HDR_LEN],
                )
                .and_then(|hdr| hdr.to_gso_options())
                {
                    Ok(o) => o,
                    Err(e) => {
                        // 畸形包：丢弃该包但继续读取（不应终止读循环）
                        tracing::warn!(err = %e, "tun: invalid virtio_net_hdr, dropping packet");
                        return Ok(result);
                    }
                };
                // 不信任内核 HdrLen（sing-tun tun_linux.go:367-384）
                if let Err(e) = gso::correct_gso_hdr_len(&mut options, pkt) {
                    tracing::warn!(err = %e, "tun: invalid GSO packet, dropping");
                    return Ok(result);
                }
                // 清空输出缓冲
                for b in &mut self.gso_out_bufs {
                    b.clear();
                }
                let count = match gso::gso_split(pkt, &options, &mut self.gso_out_bufs, &mut self.gso_sizes) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(err = %e, "tun: gso_split failed, dropping packet");
                        return Ok(result);
                    }
                };
                // 将 segments 放入 pending 队列
                self.pending_segments.clear();
                self.pending_idx = 0;
                for i in 0..count {
                    let seg = std::mem::take(&mut self.gso_out_bufs[i]);
                    self.pending_segments.push(seg);
                }
                // 消费到 bufs
                while self.pending_idx < self.pending_segments.len()
                    && result.len() < bufs.len()
                {
                    let seg = std::mem::take(&mut self.pending_segments[self.pending_idx]);
                    let len = seg.len();
                    bufs[result.len()] = seg;
                    result.push(len);
                    self.pending_idx += 1;
                }
            } else {
                // 非 IFF_VNET_HDR 模式：直接返回原始数据
                let pkt = self.read_buf[..n].to_vec();
                let len = pkt.len();
                bufs[result.len()] = pkt;
                result.push(len);
            }
            Ok(result)
        }
    }

    #[async_trait::async_trait]
    impl TunReader for LinuxTunReader {
        async fn batch_read(&mut self, bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
            self.do_batch_read(bufs).await
        }
    }

    /// Linux TUN 写半部。
    ///
    /// - `vnet_hdr`：每次写必须在 IP 包前补 virtio_net_hdr（普通包为全零 hdr）。
    /// - `gro`：GRO 合并禁用标志。批量写经 handle_gro 逐包判断；两类 GRO
    ///   均禁用时 handle_gro 退化为给每个包填全零 hdr。
    ///
    /// `poll_write` 使用内部 staging 缓冲处理逐包写入的 hdr 前置，
    /// 保证 `tun_write`（AsyncWrite 路径）与批量路径行为一致（B1 修复）。
    pub struct LinuxTunWriter {
        writer: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
        vnet_hdr: bool,
        /// GRO 禁用标志（TUNSETOFFLOAD 降级 / probeTCPGRO 探针失败时置位）
        gro: gso::GroDisablementFlags,
        /// GRO 表（批量写方向复用）
        tcp_gro_table: gso::TcpGroTable,
        udp_gro_table: gso::UdpGroTable,
        /// staging：[virtio_net_hdr][packet]，poll_write 逐包前置 hdr 用
        write_buf: Vec<u8>,
        /// write_buf 已写出的字节数
        write_pos: usize,
        /// 当前 staging 的 IP 包长度（不含 hdr），写完时向调用方报告
        write_total: usize,
    }

    impl LinuxTunWriter {
        pub fn new(
            writer: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
            vnet_hdr: bool,
            gro: gso::GroDisablementFlags,
        ) -> Self {
            Self {
                writer,
                vnet_hdr,
                gro,
                tcp_gro_table: gso::TcpGroTable::new(),
                udp_gro_table: gso::UdpGroTable::new(),
                write_buf: Vec::new(),
                write_pos: 0,
                write_total: 0,
            }
        }

        /// 批量写入：IFF_VNET_HDR 下统一经 handle_gro（填头 + 可选合并），
        /// 否则透传逐包写（B1 修复：所有写路径都补 virtio_net_hdr）。
        pub async fn do_batch_write(&mut self, packets: &[&[u8]]) -> std::io::Result<usize> {
            if packets.is_empty() {
                return Ok(0);
            }
            if self.vnet_hdr {
                // IFF_VNET_HDR：为每个包预留 virtio_net_hdr 空间，经 handle_gro
                // 填头（可合并的 TCP/UDP 流合并为 GSO 包，其余填全零 hdr）
                let offset = gso::VIRTIO_NET_HDR_LEN;
                let mut bufs: Vec<Vec<u8>> = packets
                    .iter()
                    .map(|p| {
                        let mut b = Vec::with_capacity(offset + p.len());
                        b.resize(offset, 0); // virtio_net_hdr 占位
                        b.extend_from_slice(p);
                        b
                    })
                    .collect();
                self.tcp_gro_table.reset();
                self.udp_gro_table.reset();
                let mut to_write = Vec::new();
                gso::handle_gro(
                    &mut bufs,
                    offset,
                    &mut self.tcp_gro_table,
                    &mut self.udp_gro_table,
                    self.gro,
                    &mut to_write,
                )?;
                let mut written = 0;
                for idx in &to_write {
                    self.writer.write_all(&bufs[*idx]).await?;
                    written += 1;
                }
                self.writer.flush().await?;
                Ok(written)
            } else {
                // 非 IFF_VNET_HDR 模式：逐包写入
                for p in packets {
                    self.writer.write_all(p).await?;
                }
                self.writer.flush().await?;
                Ok(packets.len())
            }
        }

        /// 尝试将 write_buf 剩余部分写完。
        fn flush_staged(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
            while self.write_pos < self.write_buf.len() {
                match Pin::new(&mut self.writer).poll_write(cx, &self.write_buf[self.write_pos..]) {
                    Poll::Ready(Ok(n)) => self.write_pos += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Poll::Ready(Ok(()))
        }
    }

    #[async_trait::async_trait]
    impl TunWriter for LinuxTunWriter {
        async fn batch_write(&mut self, packets: &[&[u8]]) -> std::io::Result<usize> {
            self.do_batch_write(packets).await
        }

        fn front_headroom(&self) -> usize {
            if self.vnet_hdr {
                gso::VIRTIO_NET_HDR_LEN
            } else {
                0
            }
        }

        async fn probe_tcp_gro(&mut self, probe_addr: Option<Ipv4Addr>) -> std::io::Result<()> {
            let segments = build_gro_probe_segments(probe_addr);
            let seg_refs: Vec<&[u8]> = segments.iter().map(|s| s.as_slice()).collect();
            // 经 do_batch_write 走 userspace GRO 合并后写入 TUN；
            // 内核无法处理合并后的 GSO 包时 write 返回错误。
            match self.do_batch_write(&seg_refs).await {
                Ok(_) => Ok(()),
                Err(e) => {
                    // 对齐 sing-tun Start()：探针失败同时禁用 TCP 与 UDP GRO
                    self.gro.disable_tcp();
                    self.gro.disable_udp();
                    Err(e)
                }
            }
        }
    }

    /// 构造 probeTCPGRO 探针包（对齐 sing-tun NativeTun.probeTCPGRO）。
    ///
    /// 两个同流、序号连续的 TCP 段，经 userspace GRO 合并为一个 GSO 包写入
    /// TUN；目的地址为 TUN 自身地址（或 127.0.0.1 兜底），TTL=0 防止外泄。
    fn build_gro_probe_segments(probe_addr: Option<Ipv4Addr>) -> Vec<Vec<u8>> {
        const IPH_LEN: usize = 20;
        const TCPH_LEN: usize = 20;
        let addr = probe_addr.unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
        let fingerprint: &[u8] = b"reflex-probe-tun-gro";
        let seg_size = fingerprint.len();
        let total_len = IPH_LEN + TCPH_LEN + seg_size;
        let octets = addr.octets();

        let mut segments = Vec::with_capacity(2);
        for i in 0..2u32 {
            let mut pkt = vec![0u8; total_len];
            // IPv4 头
            pkt[0] = 0x45;
            pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
            pkt[4..6].copy_from_slice(&(0x5154 + i as u16).to_be_bytes()); // ID: "TPT"
            pkt[6] = 0x40; // DF
            pkt[8] = 0; // TTL=0（尽力避免探针包外泄）
            pkt[9] = gso::IPPROTO_TCP;
            pkt[12..16].copy_from_slice(&octets); // src = 探针地址
            pkt[16..20].copy_from_slice(&octets); // dst = 探针地址
                                                  // TCP 头
            let tcp = &mut pkt[IPH_LEN..];
            tcp[0..2].copy_from_slice(&0u16.to_be_bytes()); // src port = 0
            tcp[2..4].copy_from_slice(&0u16.to_be_bytes()); // dst port = 0
            tcp[4..8].copy_from_slice(&(1 + i * seg_size as u32).to_be_bytes()); // seq 连续
            tcp[8..12].copy_from_slice(&1u32.to_be_bytes()); // ack
            tcp[12] = (TCPH_LEN as u8 / 4) << 4; // data offset
            tcp[13] = 0x10; // ACK
            tcp[14..16].copy_from_slice(&3000u16.to_be_bytes()); // window
            tcp[TCPH_LEN..].copy_from_slice(fingerprint);
            // TCP 校验和（伪头部）
            let psum = gso::pseudo_header_checksum(
                gso::IPPROTO_TCP,
                &octets,
                &octets,
                (TCPH_LEN + seg_size) as u16,
            );
            let csum = !gso::checksum(&pkt[IPH_LEN..], psum);
            pkt[IPH_LEN + 16..IPH_LEN + 18].copy_from_slice(&csum.to_be_bytes());
            // IP 校验和
            let ip_csum = !gso::checksum(&pkt[..IPH_LEN], 0);
            pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
            segments.push(pkt);
        }
        segments
    }

    impl AsyncWrite for LinuxTunWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            let this = self.get_mut();

            if !this.vnet_hdr {
                // 非 IFF_VNET_HDR 模式：透传
                return Pin::new(&mut this.writer).poll_write(cx, data);
            }

            // 1. 若上一包尚未写完（poll_write 返回 Pending 后 write_all 重试），
            //    先把 staging 缓冲冲干净。
            if this.write_pos < this.write_buf.len() {
                match this.flush_staged(cx) {
                    Poll::Ready(Ok(())) => {
                        // 上一包已完整写出。若本次 poll 的 data 与已写包一致
                        // （write_all 重试语义），向调用方报告完成；
                        // 若不一致（上一次 write 被放弃后新 write 开始），
                        // 丢弃旧状态并继续装载新包。
                        let same_packet = this.write_total == data.len()
                            && this.write_buf.len() >= gso::VIRTIO_NET_HDR_LEN
                            && data == &this.write_buf[gso::VIRTIO_NET_HDR_LEN..];
                        let total = this.write_total;
                        this.write_buf.clear();
                        this.write_pos = 0;
                        this.write_total = 0;
                        if same_packet {
                            return Poll::Ready(Ok(total));
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }

            // 2. 装载 [零 virtio_net_hdr][IP 包] 并写出。
            //    全零 hdr（gso_type = NONE）表示无卸载，内核按普通包处理。
            this.write_buf.clear();
            this.write_buf.resize(gso::VIRTIO_NET_HDR_LEN, 0);
            this.write_buf.extend_from_slice(data);
            this.write_pos = 0;
            this.write_total = data.len();

            match this.flush_staged(cx) {
                Poll::Ready(Ok(())) => {
                    this.write_buf.clear();
                    this.write_pos = 0;
                    let total = this.write_total;
                    this.write_total = 0;
                    Poll::Ready(Ok(total))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let this = self.get_mut();
            Pin::new(&mut this.writer).poll_flush(cx)
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            let this = self.get_mut();
            Pin::new(&mut this.writer).poll_shutdown(cx)
        }
    }
}

// ── 简单实现（macOS / Windows / 其他平台）─────────────────────────────────────
//
// 这些平台无 IFF_VNET_HDR / GSO：读写退化为单包模式。批量读为一次阻塞 read
// （一次 read 即一个完整 IP 包）；批量写为逐包 write。

pub mod simple_impl {
    use super::*;

    pub struct SimpleTunReader {
        reader: Pin<Box<dyn AsyncRead + Unpin + Send>>,
        read_buf: Vec<u8>,
    }

    impl SimpleTunReader {
        pub fn new(reader: Pin<Box<dyn AsyncRead + Unpin + Send>>) -> Self {
            Self {
                reader,
                read_buf: vec![0u8; 65536 + 64],
            }
        }
    }

    #[async_trait::async_trait]
    impl TunReader for SimpleTunReader {
        async fn batch_read(&mut self, bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
            if bufs.is_empty() {
                return Ok(vec![]);
            }
            let n = self.reader.read(&mut self.read_buf).await?;
            if n == 0 {
                return Ok(vec![]);
            }
            bufs[0] = self.read_buf[..n].to_vec();
            Ok(vec![n])
        }
    }

    pub struct SimpleTunWriter {
        writer: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
    }

    impl SimpleTunWriter {
        pub fn new(writer: Pin<Box<dyn AsyncWrite + Unpin + Send>>) -> Self {
            Self { writer }
        }
    }

    #[async_trait::async_trait]
    impl TunWriter for SimpleTunWriter {
        async fn batch_write(&mut self, packets: &[&[u8]]) -> std::io::Result<usize> {
            for p in packets {
                self.writer.write_all(p).await?;
            }
            self.writer.flush().await?;
            Ok(packets.len())
        }
    }

    impl AsyncWrite for SimpleTunWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.writer.as_mut().poll_write(cx, data)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            self.writer.as_mut().poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            self.writer.as_mut().poll_shutdown(cx)
        }
    }
}
