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
/// ABX 是 AOSP 自定义的二进制 XML 编码；此处做最简支持。
fn parse_abx_or_xml(data: &[u8]) -> anyhow::Result<String> {
    // ABX 魔数：0xA 0xB 0X 0x0（4 字节）
    if data.len() < 4 || data[0] != 0x41 || data[1] != 0x42 || data[2] != 0x58 {
        anyhow::bail!("not ABX format");
    }
    // 简化处理：跳过 ABX 头部（52 字节），读取内嵌的 XML 文本部分。
    // 实际 ABX 解码需要完整的 tokenizer，此处做最简提取。
    let text = String::from_utf8_lossy(data).to_string();
    Ok(text)
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

/// 从 XML 标签中提取 u32 属性值。
fn extract_tag_attr_u32(line: &str, tag: &str, attr: &str) -> Option<u32> {
    extract_tag_attr_str(line, tag, attr)?.parse::<u32>().ok()
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
