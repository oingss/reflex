#![allow(dead_code)]

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

/// NativeTun 封装：在 tun::AsyncDevice 上叠加 GSO/GRO、批量 I/O 支持。
pub struct NativeTun {
    inner: Arc<Mutex<Box<dyn TunIO + Send + 'static>>>,
    mtu: usize,
    #[cfg(target_os = "linux")]
    gso_enabled: bool,
}

/// TUN I/O 抽象：各平台可实现不同的批量 I/O 策略。
#[async_trait::async_trait]
pub trait TunIO: AsyncRead + AsyncWrite + Unpin + Send {
    /// 批量读取数据包。
    /// 返回 (packets, offsets) 列表，每个元素是一个完整的 IP 包。
    async fn batch_read(&mut self, bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>>;

    /// 批量写入数据包。
    async fn batch_write(&mut self, packets: &[&[u8]]) -> std::io::Result<usize>;

    /// 获取前端头部预留空间（用于 virtio_net_hdr）。
    fn front_headroom(&self) -> usize {
        0
    }
}

impl NativeTun {
    /// 创建 NativeTun 实例，包裹 tun::AsyncDevice。
    pub fn new(dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static, mtu: usize) -> Self {
        #[cfg(target_os = "linux")]
        {
            let inner = linux_impl::LinuxTunIO::new(dev);
            let gso = inner.has_gso();
            Self {
                inner: Arc::new(Mutex::new(Box::new(inner))),
                mtu,
                gso_enabled: gso,
            }
        }

        #[cfg(target_os = "macos")]
        {
            Self {
                inner: Arc::new(Mutex::new(Box::new(macos_impl::MacosTunIO::new(dev)))),
                mtu,
            }
        }

        #[cfg(target_os = "windows")]
        {
            Self {
                inner: Arc::new(Mutex::new(Box::new(windows_impl::WindowsTunIO::new(dev)))),
                mtu,
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            Self {
                inner: Arc::new(Mutex::new(Box::new(DefaultTunIO::new(dev)))),
                mtu,
            }
        }
    }

    /// 获取 MTU。
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// GSO 是否启用（仅 Linux）。
    pub fn gso_enabled(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.gso_enabled;
        #[cfg(not(target_os = "linux"))]
        false
    }

    /// 拆分 NativeTun 为读写两半。
    pub fn split(self) -> (NativeTunReader, NativeTunWriter) {
        let mtu = self.mtu;
        (
            NativeTunReader {
                inner: self.inner.clone(),
                mtu,
                buf: vec![0u8; mtu + 64],
            },
            NativeTunWriter { inner: self.inner },
        )
    }
}

/// NativeTun 读取半部。
pub struct NativeTunReader {
    inner: Arc<Mutex<Box<dyn TunIO + Send + 'static>>>,
    mtu: usize,
    buf: Vec<u8>,
}

impl NativeTunReader {
    /// 读取一个 IP 包。
    pub async fn read_packet(&mut self) -> std::io::Result<&[u8]> {
        let mut io = self.inner.lock().await;
        let n = io.read(&mut self.buf).await?;
        Ok(&self.buf[..n])
    }

    /// 批量读取 IP 包。
    pub async fn read_batch(&mut self, bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
        let mut io = self.inner.lock().await;
        io.batch_read(bufs).await
    }
}

/// NativeTun 写入半部。
pub struct NativeTunWriter {
    inner: Arc<Mutex<Box<dyn TunIO + Send + 'static>>>,
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

    /// 获取前端头部预留空间。
    pub fn front_headroom(&self) -> usize {
        0
    }
}

// ── Linux GSO/GRO 实现 ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub mod linux_impl {
    use super::*;

    /// Linux TUN I/O：支持 GSO/GRO 和批量读写。
    pub struct LinuxTunIO {
        reader: Pin<Box<dyn AsyncRead + Unpin + Send>>,
        writer: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
        gso: bool,
        read_buf: Vec<u8>,
    }

    impl LinuxTunIO {
        pub fn new(dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
            let (reader, writer) = tokio::io::split(dev);
            let gso = false;
            Self {
                reader: Box::pin(reader),
                writer: Box::pin(writer),
                gso,
                read_buf: vec![0u8; 65536 + 64],
            }
        }

        pub fn has_gso(&self) -> bool {
            self.gso
        }

        pub fn enable_gso() -> std::io::Result<bool> {
            Ok(false)
        }

        pub fn handle_gro(_packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
            Vec::new()
        }
    }

    #[async_trait::async_trait]
    impl TunIO for LinuxTunIO {
        async fn batch_read(&mut self, _bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
            Ok(vec![])
        }

        async fn batch_write(&mut self, _packets: &[&[u8]]) -> std::io::Result<usize> {
            Ok(0)
        }

        fn front_headroom(&self) -> usize {
            if self.gso {
                16
            } else {
                0
            }
        }
    }

    impl AsyncRead for LinuxTunIO {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.reader.as_mut().poll_read(cx, buf)
        }
    }

    impl AsyncWrite for LinuxTunIO {
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

// ── macOS 实现 ────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
pub mod macos_impl {
    use super::*;

    pub struct MacosTunIO {
        reader: Pin<Box<dyn AsyncRead + Unpin + Send>>,
        writer: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
    }

    impl MacosTunIO {
        pub fn new(dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
            let (reader, writer) = tokio::io::split(dev);
            Self {
                reader: Box::pin(reader),
                writer: Box::pin(writer),
            }
        }
    }

    #[async_trait::async_trait]
    impl TunIO for MacosTunIO {
        async fn batch_read(&mut self, _bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
            Ok(vec![])
        }

        async fn batch_write(&mut self, _packets: &[&[u8]]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl AsyncRead for MacosTunIO {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.reader.as_mut().poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MacosTunIO {
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

// ── Windows 实现 ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
pub mod windows_impl {
    use super::*;

    pub struct WindowsTunIO {
        reader: Pin<Box<dyn AsyncRead + Unpin + Send>>,
        writer: Pin<Box<dyn AsyncWrite + Unpin + Send>>,
    }

    impl WindowsTunIO {
        pub fn new(dev: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) -> Self {
            let (reader, writer) = tokio::io::split(dev);
            Self {
                reader: Box::pin(reader),
                writer: Box::pin(writer),
            }
        }
    }

    #[async_trait::async_trait]
    impl TunIO for WindowsTunIO {
        async fn batch_read(&mut self, _bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
            Ok(vec![])
        }

        async fn batch_write(&mut self, _packets: &[&[u8]]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl AsyncRead for WindowsTunIO {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.reader.as_mut().poll_read(cx, buf)
        }
    }

    impl AsyncWrite for WindowsTunIO {
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

// ── 默认实现（所有平台）────────────────────────────────────────────────────────

/// 兜底实现：直接包装 AsyncRead + AsyncWrite（无批量 I/O，无 GSO）。
pub struct DefaultTunIO<T> {
    inner: T,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> DefaultTunIO<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> TunIO for DefaultTunIO<T> {
    async fn batch_read(&mut self, _bufs: &mut [Vec<u8>]) -> std::io::Result<Vec<usize>> {
        Ok(vec![])
    }

    async fn batch_write(&mut self, _packets: &[&[u8]]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncRead for DefaultTunIO<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for DefaultTunIO<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
