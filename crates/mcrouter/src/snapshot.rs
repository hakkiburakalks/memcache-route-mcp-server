//! Sanitized mcrouter topology for incident snapshots.
//!
//! Pool and destination names never leave this module. They are replaced by a deterministic
//! opaque fingerprint so two snapshots can be compared without exposing configuration contents.

use diagnostics::rca::Coverage;
use diagnostics::snapshot::{DestinationSnapshot, PoolSnapshot, TopologySnapshot};

use crate::rca::DestinationObservation;
use crate::{destinations, ConfigSummary};

/// Stable 64-bit FNV-1a fingerprint rendered as 16 hex characters. This is an opaque identifier,
/// not an anonymization guarantee: low-entropy names can be guessed by brute force.
pub fn opaque_id(name: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in name.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

pub fn topology_snapshot(
    config: &ConfigSummary,
    observations: &[DestinationObservation],
    coverage: Coverage,
) -> TopologySnapshot {
    let mut pools: Vec<PoolSnapshot> = config
        .pools
        .iter()
        .map(|pool| PoolSnapshot {
            id: opaque_id(&pool.name),
            servers: pool.servers.len(),
        })
        .collect();
    pools.sort_by(|a, b| a.id.cmp(&b.id));

    let mut destinations: Vec<DestinationSnapshot> = destinations(config)
        .into_iter()
        .map(|name| {
            let id = opaque_id(&name);
            let reachable = observations
                .iter()
                .find(|o| o.id == id)
                .map(|o| o.reachable);
            DestinationSnapshot { id, reachable }
        })
        .collect();
    destinations.sort_by(|a, b| a.id.cmp(&b.id));

    TopologySnapshot {
        pools,
        destinations,
        coverage: Some(coverage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FailoverScope, Pool};
    use diagnostics::Stats;

    fn cfg() -> ConfigSummary {
        ConfigSummary {
            pools: vec![Pool {
                name: "main".into(),
                servers: vec!["mc-a:11211".into(), "mc-b:11211".into()],
            }],
            referenced_pools: vec!["main".into()],
            has_failover: false,
            failover_scope: FailoverScope::None,
        }
    }

    #[test]
    fn topology_is_deterministic_and_does_not_contain_names() {
        let observations = vec![DestinationObservation {
            id: opaque_id("mc-a:11211"),
            reachable: true,
            stats: Some(Stats::new()),
            items: Stats::new(),
            settings: Stats::new(),
        }];
        let coverage = Coverage {
            configured_destinations: 2,
            probed_destinations: 1,
            reachable_destinations: 1,
            unreachable_destinations: 0,
            unmapped_destinations: 1,
            denied_destinations: 0,
            truncated_destinations: 0,
            complete: false,
        };
        let first = topology_snapshot(&cfg(), &observations, coverage.clone());
        let second = topology_snapshot(&cfg(), &observations, coverage);
        assert_eq!(first, second);
        assert_eq!(first.pools.len(), 1);
        assert_eq!(first.destinations.len(), 2);
        assert_eq!(first.coverage.as_ref().unwrap().unmapped_destinations, 1);
        let rendered = format!("{first:?}");
        assert!(!rendered.contains("main"));
        assert!(!rendered.contains("mc-a"));
        assert_eq!(
            first
                .destinations
                .iter()
                .find(|d| d.id == opaque_id("mc-a:11211"))
                .unwrap()
                .reachable,
            Some(true)
        );
        assert!(first
            .destinations
            .iter()
            .find(|d| d.id == opaque_id("mc-b:11211"))
            .unwrap()
            .reachable
            .is_none());
    }

    #[test]
    fn opaque_ids_are_stable_and_distinct() {
        assert_eq!(opaque_id("pool-a"), opaque_id("pool-a"));
        assert_ne!(opaque_id("pool-a"), opaque_id("pool-b"));
        assert_eq!(opaque_id("pool-a").len(), 16);
    }
}
