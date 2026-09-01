use super::SetupState;
use crate::config::inbound::TunInboundConfig;
use tracing::warn;

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

/// 查询当前系统默认网关 (v4, v6)。此平台不支持。
pub async fn current_default_gateways() -> (Option<std::net::IpAddr>, Option<std::net::IpAddr>) {
    (None, None)
}
