use std::sync::RwLock;

/// 线程安全的当前模式存储。内部用 `RwLock<String>`，读多写极少（只有
/// `PATCH /configs` 才写），用普通 `RwLock` 足够，没必要上更复杂的无锁结构。
pub struct ClashMode {
    current: RwLock<String>,
}

impl ClashMode {
    pub fn new(initial: impl Into<String>) -> Self {
        Self {
            current: RwLock::new(initial.into()),
        }
    }

    /// 读取当前模式。比较时调用方应使用大小写不敏感比较
    /// （`eq_ignore_ascii_case`），与 sing-box `strings.EqualFold` 行为一致。
    pub fn get(&self) -> String {
        self.current.read().map(|g| g.clone()).unwrap_or_default()
    }

    /// 写入新模式，通常由 `ClashApi`（`PATCH /configs`）调用。
    pub fn set(&self, mode: impl Into<String>) {
        if let Ok(mut g) = self.current.write() {
            *g = mode.into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_set_roundtrip() {
        let m = ClashMode::new("rule");
        assert_eq!(m.get(), "rule");
        m.set("global");
        assert_eq!(m.get(), "global");
    }

    #[test]
    fn default_via_new_into_str() {
        let m = ClashMode::new("direct".to_string());
        assert_eq!(m.get(), "direct");
    }
}
