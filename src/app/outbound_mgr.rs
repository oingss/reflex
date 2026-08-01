use std::{collections::HashMap, sync::Arc};

use crate::{
    config::outbound::OutboundConfig,
    dns::DnsResolver,
    experimental::{CacheFile, CacheFileReader},
    outbound::{
        block::BlockOutbound,
        common::group::{OutboundRegistry, SelectorOutbound, UrlTestOutbound},
        direct::DirectOutbound,
        Outbound, OutboundStatus,
    },
    provider::ProviderManager,
};

/// `OutboundManager::from_config_full` 的参数包，避免参数过多。
pub struct OutboundManagerConfig {
    pub resolver: Option<Arc<DnsResolver>>,
    pub cache_writer: Option<Arc<CacheFile>>,
    pub cache_reader: Option<Arc<CacheFileReader>>,
    pub provider_manager: Option<Arc<ProviderManager>>,
    pub routing_mark: u32,
    pub auto_detect_interface: bool,
    pub default_interface: Option<String>,
}

pub struct OutboundManager {
    map: HashMap<String, Arc<dyn Outbound>>,
}

impl OutboundManager {
    pub fn from_config(configs: &[OutboundConfig]) -> anyhow::Result<Self> {
        Self::from_config_with_resolver(configs, None)
    }

    pub fn from_config_with_resolver(
        configs: &[OutboundConfig],
        resolver: Option<Arc<DnsResolver>>,
    ) -> anyhow::Result<Self> {
        Self::from_config_full(
            configs,
            OutboundManagerConfig {
                resolver,
                cache_writer: None,
                cache_reader: None,
                provider_manager: None,
                routing_mark: 0,
                auto_detect_interface: false,
                default_interface: None,
            },
        )
    }

    /// 完整构造函数，支持 CacheFile 持久化和 ProviderManager。
    pub fn from_config_full(
        configs: &[OutboundConfig],
        cfg: OutboundManagerConfig,
    ) -> anyhow::Result<Self> {
        let OutboundManagerConfig {
            resolver,
            cache_writer,
            cache_reader,
            provider_manager,
            routing_mark,
            auto_detect_interface,
            default_interface,
        } = cfg;
        let registry: OutboundRegistry = Arc::new(std::sync::OnceLock::new());
        let mut map: HashMap<String, Arc<dyn Outbound>> = HashMap::new();

        for cfg in configs {
            let tag = cfg.tag().to_string();
            if map.contains_key(&tag) {
                anyhow::bail!("duplicate outbound tag: '{tag}'");
            }
            let ob: Arc<dyn Outbound> = match cfg {
                OutboundConfig::Direct(c) => {
                    if let Some(ref r) = resolver {
                        Arc::new(
                            DirectOutbound::with_resolver(c.clone(), r.clone())
                                .with_mark(routing_mark)
                                .with_auto_detect_interface(auto_detect_interface)
                                .with_default_interface(default_interface.clone()),
                        )
                    } else {
                        Arc::new(
                            DirectOutbound::new(c.clone())
                                .with_mark(routing_mark)
                                .with_auto_detect_interface(auto_detect_interface)
                                .with_default_interface(default_interface.clone()),
                        )
                    }
                }
                OutboundConfig::Block(c) => Arc::new(BlockOutbound::new(c.clone())),
                OutboundConfig::Socks(c) => {
                    let ob = crate::outbound::socks::SocksOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }
                OutboundConfig::Selector(c) => Arc::new(SelectorOutbound::new(
                    c.clone(),
                    registry.clone(),
                    cache_writer.clone(),
                    cache_reader.clone(),
                    provider_manager.clone(),
                )?),
                OutboundConfig::UrlTest(c) => {
                    Arc::new(UrlTestOutbound::new(c.clone(), registry.clone())?)
                }

                OutboundConfig::Shadowsocks(c) => Arc::new(
                    crate::outbound::shadowsocks::ShadowsocksOutbound::new_with_resolver(
                        c.clone(),
                        resolver.clone(),
                    )?
                    .with_mark(routing_mark),
                ),

                OutboundConfig::Trojan(c) => {
                    let ob = crate::outbound::trojan::TrojanOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Vless(c) => {
                    let ob = crate::outbound::vless::VlessOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Vmess(c) => {
                    let ob = crate::outbound::vmess::VmessOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Hysteria2(c) => {
                    let ob =
                        crate::outbound::hy2::Hy2Outbound::new(c.clone())?.with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Tuic(c) => {
                    let ob = crate::outbound::tuic::TuicOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::AnyTls(c) => {
                    let ob = crate::outbound::anytls::AnyTlsOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::ShadowQuic(c) => {
                    let ob = crate::outbound::shadowquic::ShadowQuicOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Naive(c) => {
                    let ob = crate::outbound::naive::NaiveOutbound::new(c.clone())?
                        .with_mark(routing_mark);
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::WireGuard(c) => {
                    let mut cfg = c.clone();
                    cfg.routing_mark = routing_mark;
                    Arc::new(crate::outbound::wireguard::WireGuardOutbound::new(
                        cfg,
                        resolver.clone(),
                    )?)
                }

                OutboundConfig::Ssh(c) => {
                    let ob = crate::outbound::ssh::SshOutbound::new(c.clone())?;
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }

                OutboundConfig::Tailscale(c) => {
                    let ob = crate::outbound::tailscale::TailscaleOutbound::new(c.clone())?;
                    Arc::new(if let Some(ref r) = resolver {
                        ob.with_resolver(r.clone())
                    } else {
                        ob
                    })
                }
            };
            map.insert(tag, ob);
        }

        // ── 内置 "direct" 保底 ──────────────────────────────────────────────
        // 如果用户没有在 outbounds 里声明 tag = "direct" 的出站，
        // 自动插入一个零配置的直连实例，使 `private_ip: true` 等内部路由
        // 不依赖用户显式声明即可正常工作。
        // 若用户自己声明了同名 tag，上面的循环已经插入，此处不覆盖。
        map.entry("direct".to_string()).or_insert_with(|| {
            let cfg = crate::config::outbound::DirectOutboundConfig {
                tag: "direct".to_string(),
                bind_address: None,
                ..Default::default()
            };
            if let Some(ref r) = resolver {
                Arc::new(
                    DirectOutbound::with_resolver(cfg, r.clone())
                        .with_mark(routing_mark)
                        .with_auto_detect_interface(auto_detect_interface)
                        .with_default_interface(default_interface.clone()),
                )
            } else {
                Arc::new(
                    DirectOutbound::new(cfg)
                        .with_mark(routing_mark)
                        .with_auto_detect_interface(auto_detect_interface)
                        .with_default_interface(default_interface.clone()),
                )
            }
        });

        registry
            .set(map.clone())
            .map_err(|_| anyhow::anyhow!("outbound registry already initialized"))?;

        Ok(Self { map })
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.map.get(tag).cloned()
    }

    pub fn statuses(&self) -> Vec<OutboundStatus> {
        let mut statuses = self
            .map
            .values()
            .map(|outbound| outbound.status())
            .collect::<Vec<_>>();
        statuses.sort_by(|a, b| a.name.cmp(&b.name));
        statuses
    }

    pub fn status(&self, tag: &str) -> Option<OutboundStatus> {
        self.map.get(tag).map(|outbound| outbound.status())
    }

    pub fn select(&self, tag: &str, child: &str) -> anyhow::Result<()> {
        self.map
            .get(tag)
            .ok_or_else(|| anyhow::anyhow!("outbound '{tag}' not found"))?
            .select_child(child)
    }

    pub fn as_map(&self) -> &HashMap<String, Arc<dyn Outbound>> {
        &self.map
    }

    /// 返回 OutboundRegistry（Arc<OnceLock<...>>），供 health_check 使用。
    pub fn as_registry(&self) -> OutboundRegistry {
        // 重新构造一个 registry（map 已经 set 过了）
        let registry: OutboundRegistry = Arc::new(std::sync::OnceLock::new());
        let _ = registry.set(self.map.clone());
        registry
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}
