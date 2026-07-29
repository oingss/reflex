//! 其他平台存根：auto_route/strict_route 无操作。

use tracing::warn;
use crate::config::inbound::TunInboundConfig;
use super::SetupState;

pub fn setup(_cfg: &TunInboundConfig, if_name: &str) -> anyhow::Result<SetupState> {
    warn!(interface = %if_name, "tun: auto_route not supported on this platform");
    Ok(SetupState::default())
}

pub fn teardown(
    _cfg: &TunInboundConfig,
    _if_name: &str,
    _state: &SetupState,
) -> anyhow::Result<()> {
    Ok(())
}
