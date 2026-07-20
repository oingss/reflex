//! Clash API 当前模式（`rule` / `global` / `direct`，或 `mode_list` 中的自定义值）
//! 的共享状态。
//!
//! `ClashApi` 在处理 `PATCH /configs` 时写入这里；`Router` 和 `DnsResolver`
//! 在匹配规则时只读这里，用来支持 sing-box 风格的 `clash_mode` 规则条件
//! （对齐 sing-box `route/rule/rule_item_clash_mode.go`）：
//! 规则里写 `"clash_mode": "global"`，只有当 Dashboard 当前选中的模式等于该值
//! 时这条规则才会命中。和 sing-box 一样，"global"/"direct" 本身没有任何硬编码
//! 行为——是否在这些模式下强制走某个 outbound，完全由用户自己在规则里写
//! `{"clash_mode": "global", "outbound": "GLOBAL-SELECTOR"}` 决定。
//!
//! 单独放一个模块（而不是塞进 `app::clash_api` 或 `router`），是因为 `Router`、
//! `DnsResolver`、`ClashApi` 三者两两之间不应该互相依赖——三方都只需要单向
//! 依赖这个几乎零开销的小类型即可。

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
