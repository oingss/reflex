use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Android 包管理器。
pub struct PackageManager {
    packages_path: String,
    /// package_name → uid
    id_by_package: Arc<RwLock<HashMap<String, u32>>>,
    /// shared_user_name → uid
    shared_by_package: Arc<RwLock<HashMap<String, u32>>>,
    /// uid → package_name（首个）
    package_by_id: Arc<RwLock<HashMap<u32, String>>>,
    /// uid → shared_user_name（首个）
    shared_by_id: Arc<RwLock<HashMap<u32, String>>>,
    /// 文件 watcher 的发送端
    watcher_tx: Option<tokio::sync::mpsc::UnboundedSender<()>>,
}

impl PackageManager {
    pub fn new() -> Self {
        Self {
            packages_path: "/data/system/packages.xml".to_string(),
            id_by_package: Arc::new(RwLock::new(HashMap::new())),
            shared_by_package: Arc::new(RwLock::new(HashMap::new())),
            package_by_id: Arc::new(RwLock::new(HashMap::new())),
            shared_by_id: Arc::new(RwLock::new(HashMap::new())),
            watcher_tx: None,
        }
    }

    /// 启动包管理器：首次解析 + 启动文件监听。
    pub async fn start(&mut self) -> anyhow::Result<()> {
        self.update_packages().await?;
        self.start_watcher().await;
        Ok(())
    }

    /// 重新加载 packages.xml。
    pub async fn refresh(&mut self) -> anyhow::Result<()> {
        self.update_packages().await
    }

    /// 通过包名查询 UID。
    pub async fn id_by_package(&self, package_name: &str) -> Option<u32> {
        self.id_by_package.read().await.get(package_name).copied()
    }

    /// 通过共享用户名查询 UID。
    pub async fn id_by_shared_package(&self, shared_package: &str) -> Option<u32> {
        self.shared_by_package
            .read()
            .await
            .get(shared_package)
            .copied()
    }

    /// 通过 UID 查询包名。
    pub async fn package_by_id(&self, uid: u32) -> Option<String> {
        self.package_by_id.read().await.get(&uid).cloned()
    }

    /// 将包名列表转为 UID 结果。
    pub async fn resolve_packages(&self, packages: &[String]) -> Vec<u32> {
        let map = self.id_by_package.read().await;
        packages
            .iter()
            .filter_map(|p| map.get(p).copied())
            .collect()
    }

    async fn update_packages(&mut self) -> anyhow::Result<()> {
        let data = match std::fs::read(&self.packages_path) {
            Ok(d) => d,
            Err(e) => {
                warn!(path = %self.packages_path, err = %e, "packages.xml not readable");
                return Err(e.into());
            }
        };

        // 尝试 Android Binary XML 格式；失败后回退到普通 XML。
        let text = if let Ok(xml) = parse_abx_or_xml(&data) {
            xml
        } else {
            String::from_utf8_lossy(&data).to_string()
        };

        let mut id_by_package = HashMap::new();
        let mut shared_by_package = HashMap::new();
        let mut package_by_id: HashMap<u32, String> = HashMap::new();
        let mut shared_by_id: HashMap<u32, String> = HashMap::new();

        // 简易 SAX 风格解析：无需完整 XML 库，只提取 <package> 和 <shared-user>。
        parse_packages_xml(
            &text,
            &mut id_by_package,
            &mut shared_by_package,
            &mut package_by_id,
            &mut shared_by_id,
        );

        *self.id_by_package.write().await = id_by_package;
        *self.shared_by_package.write().await = shared_by_package;
        *self.package_by_id.write().await = package_by_id;
        *self.shared_by_id.write().await = shared_by_id;
        info!("packages.xml reloaded");
        Ok(())
    }

    async fn start_watcher(&mut self) {
        use notify::{Config, Event, EventKind, RecommendedWatcher, Watcher};
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel();
        let (tx_signal, mut rx_signal) = tokio::sync::mpsc::unbounded_channel();
        self.watcher_tx = Some(tx_signal.clone());

        let path = self.packages_path.clone();
        std::thread::spawn(move || {
            let mut watcher = match RecommendedWatcher::new(tx, Config::default()) {
                Ok(w) => w,
                Err(_) => return,
            };
            if watcher
                .watch(Path::new(&path), notify::RecursiveMode::NonRecursive)
                .is_err()
            {
                return;
            }
            for event in rx {
                if matches!(
                    event,
                    Ok(Event {
                        kind: EventKind::Modify(_),
                        ..
                    })
                ) {
                    // 通过 signal 通知 tokio 侧刷新
                    let _ = tx_signal.send(());
                }
            }
        });

        let id_by_package = self.id_by_package.clone();
        let shared_by_package = self.shared_by_package.clone();
        let package_by_id = self.package_by_id.clone();
        let shared_by_id = self.shared_by_id.clone();
        let packages_path = self.packages_path.clone();

        tokio::spawn(async move {
            while rx_signal.recv().await.is_some() {
                let data = match std::fs::read(&packages_path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let text = parse_abx_or_xml(&data)
                    .unwrap_or_else(|_| String::from_utf8_lossy(&data).to_string());
                let mut id_map = HashMap::new();
                let mut shared_map = HashMap::new();
                let mut pid_map = HashMap::new();
                let mut sid_map = HashMap::new();
                parse_packages_xml(
                    &text,
                    &mut id_map,
                    &mut shared_map,
                    &mut pid_map,
                    &mut sid_map,
                );
                *id_by_package.write().await = id_map;
                *shared_by_package.write().await = shared_map;
                *package_by_id.write().await = pid_map;
                *shared_by_id.write().await = sid_map;
                info!("packages.xml reloaded (watcher)");
            }
        });
    }
}

/// 尝试将 Android Binary XML (ABX) 转为普通 XML 文本。
///
/// ABX 是 AOSP 自定义的二进制 XML 编码（frameworks/base 的
/// `AbxUtils` / `BinaryXmlSerializer`），Android 12+ 上 `/data/system/packages.xml`
/// 默认以该格式写入。此前实现只是把二进制内容当文本返回，
/// 导致逐行解析完全提取不到任何包信息。
///
/// 线格式（对齐 AOSP `BinaryXmlSerializer` + `FastDataOutput`，大端序）：
/// - 魔数 4 字节：`0x41 0x42 0x58 0x00`（"ABX" + 协议版本号 0）
/// - 每个事件 1 字节：低 4 位为 XmlPullParser token，高 4 位为值类型
/// - token：START_DOCUMENT=0, END_DOCUMENT=1, START_TAG=2, END_TAG=3,
///   TEXT=4, ..., ATTRIBUTE=15
/// - 类型：TYPE_NULL=0x10, TYPE_STRING=0x20, TYPE_STRING_INTERNED=0x30,
///   TYPE_BYTES_HEX=0x40, TYPE_BYTES_BASE64=0x50, TYPE_INT=0x60,
///   TYPE_INT_HEX=0x70, TYPE_LONG=0x80, TYPE_LONG_HEX=0x90,
///   TYPE_FLOAT=0xA0, TYPE_DOUBLE=0xB0, TYPE_BOOLEAN_TRUE=0xC0,
///   TYPE_BOOLEAN_FALSE=0xD0
/// - 字符串：u16 大端长度 + UTF-8 字节
/// - interned 字符串：u16 引用；`0xFFFF` 表示新字符串，后跟上述字符串编码，
///   否则为首次出现顺序的索引
/// - 整型 i32/i64 大端；float/double 为 IEEE 位模式大端；布尔无操作数
fn parse_abx_or_xml(data: &[u8]) -> anyhow::Result<String> {
    // ABX 魔数："ABX" (0x41 0x42 0x58) + 1 字节协议版本号
    if data.len() < 4 || data[0] != 0x41 || data[1] != 0x42 || data[2] != 0x58 {
        anyhow::bail!("not ABX format");
    }
    if data[3] != 0 {
        anyhow::bail!("unsupported ABX protocol version: {}", data[3]);
    }
    abx_to_xml(&data[4..])
}

// ── ABX 二进制解码器 ──────────────────────────────────────────────────────────

// XmlPullParser token 常量（低 4 位）
const ABX_START_DOCUMENT: u8 = 0;
const ABX_END_DOCUMENT: u8 = 1;
const ABX_START_TAG: u8 = 2;
const ABX_END_TAG: u8 = 3;
/// 保留常量：当前解码器不消费 TEXT 节点，但保留以对齐 AOSP token 表
#[allow(dead_code)]
const ABX_TEXT: u8 = 4;
const ABX_ATTRIBUTE: u8 = 15;

// 值类型常量（高 4 位），对齐 AOSP BinaryXmlSerializer
const ABX_TYPE_NULL: u8 = 1 << 4;
const ABX_TYPE_STRING: u8 = 2 << 4;
const ABX_TYPE_STRING_INTERNED: u8 = 3 << 4;
const ABX_TYPE_BYTES_HEX: u8 = 4 << 4;
const ABX_TYPE_BYTES_BASE64: u8 = 5 << 4;
const ABX_TYPE_INT: u8 = 6 << 4;
const ABX_TYPE_INT_HEX: u8 = 7 << 4;
const ABX_TYPE_LONG: u8 = 8 << 4;
const ABX_TYPE_LONG_HEX: u8 = 9 << 4;
const ABX_TYPE_FLOAT: u8 = 10 << 4;
const ABX_TYPE_DOUBLE: u8 = 11 << 4;
const ABX_TYPE_BOOLEAN_TRUE: u8 = 12 << 4;
const ABX_TYPE_BOOLEAN_FALSE: u8 = 13 << 4;

const ABX_INTERNED_NEW: u16 = u16::MAX; // 0xFFFF：新字符串哨兵

struct AbxReader<'a> {
    data: &'a [u8],
    pos: usize,
    /// interned 字符串池（按首次出现顺序）
    strings: Vec<String>,
}

impl<'a> AbxReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            strings: Vec::new(),
        }
    }

    fn read_u8(&mut self) -> anyhow::Result<u8> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| anyhow::anyhow!("ABX data truncated"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_u16(&mut self) -> anyhow::Result<u16> {
        let hi = self.read_u8()? as u16;
        let lo = self.read_u8()? as u16;
        Ok((hi << 8) | lo)
    }

    fn read_i32(&mut self) -> anyhow::Result<i32> {
        let mut buf = [0u8; 4];
        for slot in &mut buf {
            *slot = self.read_u8()?;
        }
        Ok(i32::from_be_bytes(buf))
    }

    fn read_i64(&mut self) -> anyhow::Result<i64> {
        let mut buf = [0u8; 8];
        for slot in &mut buf {
            *slot = self.read_u8()?;
        }
        Ok(i64::from_be_bytes(buf))
    }

    fn read_f32(&mut self) -> anyhow::Result<f32> {
        Ok(f32::from_bits(self.read_i32()? as u32))
    }

    fn read_f64(&mut self) -> anyhow::Result<f64> {
        Ok(f64::from_bits(self.read_i64()? as u64))
    }

    /// 读取字符串：u16 大端长度 + UTF-8 字节。
    /// AOSP 原生实现写 modified UTF-8（NUL 编码为 0xC0 0x80），
    /// 解码前先还原；普通 UTF-8 内容同样兼容。
    fn read_utf(&mut self) -> anyhow::Result<String> {
        let len = self.read_u16()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| anyhow::anyhow!("ABX string length out of range"))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        // 将 0xC0 0x80（modified UTF-8 的 NUL）还原为 0x00
        let mut fixed = Vec::with_capacity(bytes.len());
        let mut iter = bytes.iter().copied().peekable();
        while let Some(b) = iter.next() {
            if b == 0xC0 && iter.peek() == Some(&0x80) {
                iter.next();
                fixed.push(0x00);
            } else {
                fixed.push(b);
            }
        }
        Ok(String::from_utf8_lossy(&fixed).into_owned())
    }

    /// 读取 interned 字符串：u16 引用；`0xFFFF` 表示新字符串跟随其后。
    fn read_interned_utf(&mut self) -> anyhow::Result<String> {
        let r = self.read_u16()?;
        if r == ABX_INTERNED_NEW {
            let s = self.read_utf()?;
            self.strings.push(s.clone());
            Ok(s)
        } else {
            self.strings
                .get(r as usize)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("ABX invalid string ref: {r}"))
        }
    }

    /// 按值类型读取并格式化为 XML 属性值文本。
    fn read_typed_value(&mut self, ty: u8) -> anyhow::Result<String> {
        Ok(match ty {
            ABX_TYPE_STRING => self.read_utf()?,
            ABX_TYPE_STRING_INTERNED => self.read_interned_utf()?,
            ABX_TYPE_BYTES_HEX | ABX_TYPE_BYTES_BASE64 => {
                // bytes 值以十六进制文本表示（packages.xml 中不使用）
                let len = self.read_u16()? as usize;
                let end = self
                    .pos
                    .checked_add(len)
                    .filter(|&e| e <= self.data.len())
                    .ok_or_else(|| anyhow::anyhow!("ABX bytes length out of range"))?;
                let bytes = &self.data[self.pos..end];
                self.pos = end;
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            }
            ABX_TYPE_INT => self.read_i32()?.to_string(),
            ABX_TYPE_INT_HEX => format!("0x{:x}", self.read_i32()?),
            ABX_TYPE_LONG => self.read_i64()?.to_string(),
            ABX_TYPE_LONG_HEX => format!("0x{:x}", self.read_i64()?),
            ABX_TYPE_FLOAT => self.read_f32()?.to_string(),
            ABX_TYPE_DOUBLE => self.read_f64()?.to_string(),
            ABX_TYPE_BOOLEAN_TRUE => "true".to_string(),
            ABX_TYPE_BOOLEAN_FALSE => "false".to_string(),
            ABX_TYPE_NULL => String::new(),
            _ => anyhow::bail!("ABX unknown value type: {ty:#04x}"),
        })
    }
}

/// 将 ABX token 流还原为普通 XML 文本。
fn abx_to_xml(payload: &[u8]) -> anyhow::Result<String> {
    let mut r = AbxReader::new(payload);
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    let mut pending: Option<u8> = None;

    loop {
        let token_byte = match pending.take() {
            Some(b) => b,
            None => match r.read_u8() {
                Ok(b) => b,
                // 容忍截断：返回已解析部分（packages.xml 正常都有 END_DOCUMENT）
                Err(e) => {
                    if out.contains('<') {
                        return Ok(out);
                    }
                    return Err(e);
                }
            },
        };
        let token = token_byte & 0x0F;
        let ty = token_byte & 0xF0;

        match token {
            ABX_START_DOCUMENT => {}
            ABX_END_DOCUMENT => break,
            ABX_START_TAG => {
                let name = r.read_interned_utf()?;
                // 收集属性直到遇到非 ATTRIBUTE token
                let mut attrs = String::new();
                loop {
                    let b = match r.read_u8() {
                        Ok(b) => b,
                        Err(e) => {
                            if out.contains('<') {
                                out.push('<');
                                out.push_str(&name);
                                out.push_str(&attrs);
                                out.push_str(">\n");
                                return Ok(out);
                            }
                            return Err(e);
                        }
                    };
                    if (b & 0x0F) == ABX_ATTRIBUTE {
                        let attr_name = r.read_interned_utf()?;
                        let value = r.read_typed_value(b & 0xF0)?;
                        attrs.push(' ');
                        attrs.push_str(&attr_name);
                        attrs.push_str("=\"");
                        attrs.push_str(&xml_escape(&value));
                        attrs.push('"');
                    } else {
                        pending = Some(b);
                        break;
                    }
                }
                out.push('<');
                out.push_str(&name);
                out.push_str(&attrs);
                out.push_str(">\n");
            }
            ABX_END_TAG => {
                let name = r.read_interned_utf()?;
                out.push_str("</");
                out.push_str(&name);
                out.push_str(">\n");
            }
            // TEXT 及其余 token（COMMENT/CDATA 等）按类型跳过操作数
            _ => {
                match ty {
                    ABX_TYPE_STRING => {
                        r.read_utf()?;
                    }
                    ABX_TYPE_NULL => {}
                    _ => anyhow::bail!("ABX unexpected token {token} with type {ty:#04x}"),
                }
            }
        }
    }

    if !out.contains('<') {
        anyhow::bail!("ABX contained no XML events");
    }
    Ok(out)
}

/// XML 属性值转义。
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// 简易 XML 解析：提取 `<package name="..." userId="..." />` 和
/// `<shared-user name="..." userId="..." />`。
fn parse_packages_xml(
    text: &str,
    id_by_package: &mut HashMap<String, u32>,
    shared_by_package: &mut HashMap<String, u32>,
    package_by_id: &mut HashMap<u32, String>,
    shared_by_id: &mut HashMap<u32, String>,
) {
    // 逐行扫描提取 package 和 shared-user 标签
    for line in text.lines() {
        let line = line.trim();
        if let Some(uid) = extract_tag_attr_u32(line, "package", "userId") {
            if let Some(name) = extract_tag_attr_str(line, "package", "name") {
                id_by_package.insert(name.clone(), uid);
                package_by_id.entry(uid).or_insert_with(|| name.clone());
            }
        }
        if let Some(uid) = extract_tag_attr_u32(line, "shared-user", "userId") {
            if let Some(name) = extract_tag_attr_str(line, "shared-user", "name") {
                shared_by_package.insert(name.clone(), uid);
                shared_by_id.entry(uid).or_insert_with(|| name.clone());
            }
        }
    }
}

/// 从 XML 标签中提取字符串属性值。
fn extract_tag_attr_str(line: &str, tag: &str, attr: &str) -> Option<String> {
    if !line.starts_with('<') || !line.contains(tag) {
        return None;
    }
    let needle = format!("{attr}=\"");
    let start = line.find(&needle)?;
    let value_start = start + needle.len();
    let value_end = line[value_start..].find('"')?;
    Some(line[value_start..value_start + value_end].to_string())
}

/// 从 XML 标签中提取 u32 属性值（兼容十六进制 0x 前缀）。
fn extract_tag_attr_u32(line: &str, tag: &str, attr: &str) -> Option<u32> {
    let raw = extract_tag_attr_str(line, tag, attr)?;
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        raw.parse::<u32>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tag_attr() {
        let line = r#"  <package name="com.example.app" userId="10123" />"#;
        assert_eq!(
            extract_tag_attr_str(line, "package", "name"),
            Some("com.example.app".to_string())
        );
        assert_eq!(extract_tag_attr_u32(line, "package", "userId"), Some(10123));
        assert_eq!(extract_tag_attr_u32(line, "package", "uidHex"), None);
    }

    #[test]
    fn test_extract_tag_attr_hex() {
        let line = r#"<package name="a" userId="0x279B" />"#;
        assert_eq!(extract_tag_attr_u32(line, "package", "userId"), Some(0x279B));
    }

    /// 构造一个最小 ABX 文档（对齐 AOSP BinaryXmlSerializer 线格式）：
    /// `<packages><package name="com.example" userId="10123"/></packages>`
    fn build_test_abx() -> Vec<u8> {
        let mut v = Vec::new();
        // 魔数 "ABX" + 版本 0
        v.extend_from_slice(&[0x41, 0x42, 0x58, 0x00]);
        // START_DOCUMENT | TYPE_NULL
        v.push(0x10);
        // interned 写入助手：0xFFFF 哨兵 + u16 长度 + UTF-8 字节
        let intern = |v: &mut Vec<u8>, s: &str| {
            v.extend_from_slice(&0xFFFFu16.to_be_bytes());
            v.extend_from_slice(&(s.len() as u16).to_be_bytes());
            v.extend_from_slice(s.as_bytes());
        };
        let ref_str = |v: &mut Vec<u8>, idx: u16| {
            v.extend_from_slice(&idx.to_be_bytes());
        };
        // START_TAG | TYPE_STRING_INTERNED；"packages"（pool 0）
        v.push(ABX_START_TAG | ABX_TYPE_STRING_INTERNED);
        intern(&mut v, "packages");
        // START_TAG；"package"（pool 1）
        v.push(ABX_START_TAG | ABX_TYPE_STRING_INTERNED);
        intern(&mut v, "package");
        // ATTRIBUTE | TYPE_STRING_INTERNED：name="com.example"（pool 2/3）
        v.push(ABX_ATTRIBUTE | ABX_TYPE_STRING_INTERNED);
        intern(&mut v, "name");
        intern(&mut v, "com.example");
        // ATTRIBUTE | TYPE_INT：userId=10123
        v.push(ABX_ATTRIBUTE | ABX_TYPE_INT);
        intern(&mut v, "userId");
        v.extend_from_slice(&10123i32.to_be_bytes());
        // ATTRIBUTE | TYPE_BOOLEAN_TRUE：privileged=true（无操作数）
        v.push(ABX_ATTRIBUTE | ABX_TYPE_BOOLEAN_TRUE);
        intern(&mut v, "privileged");
        // END_TAG；引用 pool 1 "package"
        v.push(ABX_END_TAG | ABX_TYPE_STRING_INTERNED);
        ref_str(&mut v, 1);
        // END_TAG；引用 pool 0 "packages"
        v.push(ABX_END_TAG | ABX_TYPE_STRING_INTERNED);
        ref_str(&mut v, 0);
        // END_DOCUMENT | TYPE_NULL
        v.push(0x11);
        v
    }

    #[test]
    fn test_abx_to_xml_roundtrip() {
        let abx = build_test_abx();
        let xml = parse_abx_or_xml(&abx).expect("ABX decode failed");
        assert!(xml.contains("<package name=\"com.example\" userId=\"10123\" privileged=\"true\">"));

        let mut id_map = HashMap::new();
        let mut shared_map = HashMap::new();
        let mut pid_map = HashMap::new();
        let mut sid_map = HashMap::new();
        parse_packages_xml(&xml, &mut id_map, &mut shared_map, &mut pid_map, &mut sid_map);
        assert_eq!(id_map.get("com.example"), Some(&10123));
        assert_eq!(pid_map.get(&10123), Some(&"com.example".to_string()));
    }

    #[test]
    fn test_parse_abx_or_xml_rejects_plain_xml() {
        assert!(parse_abx_or_xml(b"<?xml version=\"1.0\"?><packages/>").is_err());
    }

    #[test]
    fn test_parse_packages_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package name="com.android.chrome" userId="10123" codePath="/data/app/chrome" />
  <package name="com.example.app" userId="10145" codePath="/data/app/example" />
  <shared-user name="android.uid.system" userId="1000" />
</packages>"#;
        let mut id_map = HashMap::new();
        let mut shared_map = HashMap::new();
        let mut pid_map = HashMap::new();
        let mut sid_map = HashMap::new();
        parse_packages_xml(
            xml,
            &mut id_map,
            &mut shared_map,
            &mut pid_map,
            &mut sid_map,
        );
        assert_eq!(id_map.get("com.android.chrome"), Some(&10123));
        assert_eq!(id_map.get("com.example.app"), Some(&10145));
        assert_eq!(shared_map.get("android.uid.system"), Some(&1000));
        assert_eq!(pid_map.get(&10123), Some(&"com.android.chrome".to_string()));
        assert_eq!(sid_map.get(&1000), Some(&"android.uid.system".to_string()));
    }
}
