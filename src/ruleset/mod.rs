pub mod adguard;
pub mod compiler;
pub mod error;
pub mod format;
pub mod loader;
pub mod matcher;
pub mod trie;

// 顶层重导出，方便使用方不用知道内部模块结构
pub use adguard::AdGuardConvertReport;
pub use compiler::CompiledRuleSet;
pub use error::{Result, RuleSetError};
pub use loader::{ByteSource, LoadedRuleSet};
pub use matcher::{MatchTarget, RuleSet};
