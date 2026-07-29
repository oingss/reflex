use tracing::debug;

use crate::{
    config::outbound::BlockOutboundConfig,
    inbound::InboundTcpStream,
    outbound::{Outbound, OutboundStatus},
};

pub struct BlockOutbound {
    config: BlockOutboundConfig,
    /// `method = "drop"` 时为 true：静默丢弃，不关闭连接也不回任何数据。
    /// 对齐 sing-box reject 动作的 method 字段（`"reply"` 方式未实现，见配置注释）。
    silent_drop: bool,
}

impl BlockOutbound {
    pub fn new(config: BlockOutboundConfig) -> Self {
        let silent_drop = config
            .method
            .as_deref()
            .is_some_and(|m| m.eq_ignore_ascii_case("drop"));
        Self {
            config,
            silent_drop,
        }
    }
}

#[async_trait::async_trait]
impl Outbound for BlockOutbound {
    fn tag(&self) -> &str {
        &self.config.tag
    }

    fn status(&self) -> OutboundStatus {
        OutboundStatus {
            name: self.config.tag.clone(),
            type_name: "Reject".to_string(),
            now: None,
            all: vec![],
            history: vec![],
        }
    }

    async fn handle_tcp(&self, mut conn: InboundTcpStream) -> anyhow::Result<(u64, u64)> {
        if self.silent_drop {
            // method = "drop"：不主动关闭、不回任何数据，只把客户端发来的字节
            // 读掉丢弃，连接会一直挂着直到客户端自己放弃（或被 Clash API
            // DELETE /connections 主动终止）。比直接关闭更难被探测区分
            // "连接被拒绝" 和 "网络不通"。
            debug!(tag=%self.config.tag, target=%conn.target, "block(drop) tcp: silently discarding");
            let discarded = tokio::io::copy(&mut conn.stream, &mut tokio::io::sink())
                .await
                .unwrap_or(0);
            return Ok((0, discarded));
        }
        debug!(tag=%self.config.tag, target=%conn.target, "block tcp");
        drop(conn.stream);
        Ok((0, 0))
    }

    async fn handle_udp(&self, packet: crate::inbound::InboundUdpPacket) -> anyhow::Result<()> {
        // UDP 无连接概念，"default" 和 "drop" 在 reflex 里行为一致：都不回任何
        // 数据包。sing-box 的 "default" 方式会尝试发 ICMP port-unreachable，
        // 但那需要原始套接字权限，复杂度和收益不成正比，这里不实现。
        debug!(tag=%self.config.tag, target=%packet.target, method=?self.config.method, "block udp");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_outbound_method_drop_sets_silent_drop() {
        let ob = BlockOutbound::new(BlockOutboundConfig {
            tag: "blk".into(),
            method: Some("drop".into()),
        });
        assert!(ob.silent_drop);

        let ob_default = BlockOutbound::new(BlockOutboundConfig {
            tag: "blk".into(),
            method: None,
        });
        assert!(!ob_default.silent_drop);

        // 大小写不敏感
        let ob_caps = BlockOutbound::new(BlockOutboundConfig {
            tag: "blk".into(),
            method: Some("DROP".into()),
        });
        assert!(ob_caps.silent_drop);
    }
}
