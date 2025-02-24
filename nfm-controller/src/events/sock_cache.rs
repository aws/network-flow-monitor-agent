// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use nfm_common::{
    constants::MAX_ENTRIES_SK_PROPS_HI,
    network::{SockContext, SockKey, SockStats},
};

use hashbrown::{hash_map::Entry, HashMap};
use serde::Serialize;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct AggSockStats {
    pub stats: SockStats,
    pub cpus: Vec<u32>,
}

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct SockWrapper {
    pub context: SockContext,
    pub context_external: Option<SockContext>,
    pub agg_stats: AggSockStats,
    pub is_stale: bool,
    pub is_complete: bool,
}

impl SockWrapper {
    pub fn new(context: SockContext, agg_stats: AggSockStats) -> Self {
        Self {
            context,
            context_external: None,
            agg_stats,
            is_stale: false,
            is_complete: false,
        }
    }

    pub fn update_context(&mut self, context: SockContext, now_us: u64) {
        self.context = context;
        self.context_external = None;
        self.agg_stats.stats.last_touched_us = now_us;
        self.is_stale = false;
        self.is_complete = false;
    }

    pub fn update_status(&mut self, staleness_timestamp: u64) {
        self.is_complete = self.agg_stats.stats.is_closed() && self.context.is_valid();
        self.is_stale = self.agg_stats.stats.last_touched_us <= staleness_timestamp;
    }

    pub fn should_evict(&self) -> bool {
        self.is_complete || self.is_stale
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct SockOperationResult {
    pub completed: u64,
    pub partial: u64,
    pub failed: u64,
}

impl SockOperationResult {
    pub fn add(&mut self, other: &Self) {
        self.completed += other.completed;
        self.partial += other.partial;
        self.failed += other.failed;
    }
}

#[derive(Default)]
pub struct SockCache {
    cache: HashMap<SockKey, SockWrapper>,
    max_sock_entries: usize,
}

impl SockCache {
    pub fn new() -> Self {
        Self::with_max_entries(MAX_ENTRIES_SK_PROPS_HI.try_into().unwrap())
    }

    pub fn with_max_entries(max_sock_entries: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_sock_entries,
        }
    }

    pub fn max_entries(&self) -> usize {
        self.max_sock_entries
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&SockKey, &mut SockWrapper)> {
        self.cache.iter_mut()
    }

    pub fn get(&self, sock_key: &SockKey) -> Option<&SockWrapper> {
        self.cache.get(sock_key)
    }

    pub fn get_last_touched(&self, sock_key: &SockKey) -> u64 {
        if let Some(sock) = self.cache.get(sock_key) {
            sock.agg_stats.stats.last_touched_us
        } else {
            0
        }
    }

    // Gets the min, max, and avg number of CPUs handling each socket.
    pub fn num_cpus(&self) -> (u64, u64, f64) {
        let mut min: u64 = 0;
        let mut max: u64 = 0;
        let mut sum: u64 = 0;

        for wrapper in self.cache.values() {
            let num: u64 = 1u64.max(wrapper.agg_stats.cpus.len().try_into().unwrap());
            sum += num;
            if num > max {
                max = num;
            }
            if num < min || min == 0 {
                min = num;
            }
        }
        let len = self.len();
        let avg: f64 = if len > 0 {
            (sum as f64) / (len as f64)
        } else {
            0.0
        };

        (min, max, avg)
    }

    // Adds a socket context to this cache.
    pub fn add_context(
        &mut self,
        sock_key: SockKey,
        sock_context: SockContext,
        now_us: u64,
    ) -> SockOperationResult {
        let mut result = SockOperationResult::default();
        let num_socks = self.len();
        let cache_entry = self.cache.entry(sock_key);
        match cache_entry {
            Entry::Occupied(o) => {
                let wrapper = o.into_mut();
                wrapper.update_context(sock_context, now_us);
                result.partial += 1;
            }
            Entry::Vacant(v) => {
                if num_socks < self.max_sock_entries {
                    let agg_stat = SockStats {
                        last_touched_us: now_us,
                        ..Default::default()
                    };
                    v.insert(SockWrapper::new(
                        sock_context,
                        AggSockStats {
                            stats: agg_stat,
                            cpus: Vec::new(),
                        },
                    ));
                    result.completed += 1;
                } else {
                    result.failed += 1;
                }
            }
        };

        result
    }

    // Stores the latest stats into this cache, and places the deltas compared to prior entries
    // back into the supplied map.
    pub fn update_stats_and_get_deltas(
        &mut self,
        incoming_stats: &mut HashMap<SockKey, AggSockStats>,
        staleness_timestamp: u64,
    ) -> SockOperationResult {
        let mut result = SockOperationResult::default();

        // This iterative update approach frees us from the memory hit of copying the entire map to
        // produce deltas.
        for (sock_key, incoming) in incoming_stats.iter_mut() {
            let num_socks = self.len();
            let cache_entry = self.cache.entry(*sock_key);

            match cache_entry {
                Entry::Occupied(o) => {
                    let wrapper = o.into_mut();
                    let delta = incoming.stats.subtract(&wrapper.agg_stats.stats);

                    // Store the latest values in cache.
                    wrapper.agg_stats.stats = incoming.stats;
                    wrapper.agg_stats.cpus.clear();
                    incoming
                        .cpus
                        .iter()
                        .for_each(|cpu| wrapper.agg_stats.cpus.push(*cpu));
                    wrapper.update_status(staleness_timestamp);

                    // Store the delta onto the incoming structure.
                    incoming.stats = delta;
                    result.completed += 1;
                }
                Entry::Vacant(v) => {
                    if num_socks < self.max_sock_entries {
                        // Leave values on the incoming structure unchanged, as the whole amount is a delta.
                        let mut wrapper = SockWrapper::new(
                            SockContext::default(),
                            AggSockStats {
                                stats: incoming.stats,
                                cpus: incoming.cpus.clone(),
                            },
                        );
                        wrapper.update_status(staleness_timestamp);
                        v.insert(wrapper);

                        result.partial += 1;
                    } else {
                        result.failed += 1;
                    }
                }
            };
        }

        result
    }

    // Evicts all closed and stale sockets from this cache.  Returns a map of all evicted entries,
    // and the count of those that were stale.
    pub fn perform_eviction(&mut self) -> (HashMap<SockKey, SockWrapper>, u64) {
        let mut num_stale: u64 = 0;

        let socks_evicted = self
            .cache
            .extract_if(|_key, sock_wrap| {
                if sock_wrap.is_stale {
                    num_stale += 1;
                }

                sock_wrap.should_evict()
            })
            .collect();

        (socks_evicted, num_stale)
    }
}

#[cfg(test)]
mod test {
    use crate::events::{AggSockStats, SockCache, SockOperationResult};
    use nfm_common::network::{SockContext, SockKey, SockStateFlags, SockStats, AF_INET, AF_INET6};

    use hashbrown::HashMap;

    const STALENESS_TS: u64 = 0;

    #[test]
    fn test_sock_cache_add_context_new() {
        let sock_key: SockKey = 55;
        let context = SockContext {
            address_family: AF_INET,
            local_ipv4: 99,
            ..Default::default()
        };
        let now_us = 100;

        let mut sock_cache = SockCache::new();
        let result = sock_cache.add_context(sock_key, context, now_us);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 1,
                partial: 0,
                failed: 0,
            }
        );

        let wrapper = sock_cache.get(&sock_key).unwrap();
        assert_eq!(wrapper.context, context);
        assert_eq!(
            wrapper.agg_stats,
            AggSockStats {
                stats: SockStats {
                    last_touched_us: now_us,
                    ..Default::default()
                },
                cpus: vec![],
            }
        );
        assert_eq!(sock_cache.len(), 1);

        let (min, max, avg) = sock_cache.num_cpus();
        assert_eq!(min, 1);
        assert_eq!(max, 1);
        assert!((1.0 - avg).abs() < 0.01);
    }

    #[test]
    fn test_sock_cache_add_context_pre_existing() {
        // Add an initial context.
        let sock_key: SockKey = 55;
        let context = SockContext {
            address_family: AF_INET,
            local_ipv4: 99,
            ..Default::default()
        };
        let mut now_us = 100;
        let mut sock_cache = SockCache::new();
        sock_cache.add_context(sock_key, context, now_us);

        // Add a second context and verify it takes precedence.
        let context2 = SockContext {
            address_family: AF_INET,
            local_ipv4: context.local_ipv4 * 2,
            ..Default::default()
        };
        now_us *= 2;

        let result = sock_cache.add_context(sock_key, context2, now_us);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: 1,
                failed: 0,
            }
        );
        let wrapper = sock_cache.get(&sock_key).unwrap();
        assert_eq!(wrapper.context, context2);
        assert_eq!(
            wrapper.agg_stats,
            AggSockStats {
                stats: SockStats {
                    last_touched_us: now_us,
                    ..Default::default()
                },
                cpus: vec![],
            }
        );
        assert_eq!(sock_cache.len(), 1);
    }

    #[test]
    fn test_sock_cache_add_context_too_many() {
        let context = SockContext {
            address_family: AF_INET6,
            local_port: 217,
            ..Default::default()
        };
        let now_us = 100;

        // Fill up the sock cache.
        let mut sock_cache = SockCache::new();
        for sock_key in 0..sock_cache.max_entries() {
            let result = sock_cache.add_context(sock_key as SockKey, context, now_us);
            assert_eq!(
                result,
                SockOperationResult {
                    completed: 1,
                    partial: 0,
                    failed: 0,
                }
            );
        }
        assert_eq!(sock_cache.len(), sock_cache.max_entries());

        // Now try to add beyond the limit.
        for sock_key in sock_cache.max_entries()..sock_cache.max_entries() + 10 {
            let result = sock_cache.add_context(sock_key as SockKey, context, now_us);
            assert_eq!(
                result,
                SockOperationResult {
                    completed: 0,
                    partial: 0,
                    failed: 1,
                }
            );
        }
        assert_eq!(sock_cache.len(), sock_cache.max_entries());
    }

    #[test]
    fn test_get_sock_deltas_empty() {
        let mut sock_cache = SockCache::new();
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();

        // On empty should yield nothing.
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);
        assert_eq!(result, SockOperationResult::default());
        assert!(sock_stream.is_empty());
        assert!(sock_cache.is_empty());
    }

    #[test]
    fn test_get_sock_deltas_all_new_stats() {
        let mut sock_cache = SockCache::new();
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();

        // Create a slew of sockets in the incoming stream.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        let now_us = 2049;
        for sock_key in sock_keys.iter() {
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![*sock_key as u32 % 2, 100],
                    stats: SockStats {
                        last_touched_us: sock_key * 3,
                        bytes_delivered: sock_key * 4,
                        ..Default::default()
                    },
                },
            );

            // Also add a context in cache.
            let context = SockContext {
                address_family: AF_INET,
                ..Default::default()
            };
            let result = sock_cache.add_context(*sock_key, context, now_us);
            assert_eq!(
                result,
                SockOperationResult {
                    completed: 1,
                    partial: 0,
                    failed: 0,
                }
            );
        }

        // On nothing before should yield all of the after.
        let expected_deltas = sock_stream.clone();
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: sock_keys.len().try_into().unwrap(),
                partial: 0,
                failed: 0,
            }
        );
        assert_eq!(sock_cache.len(), sock_keys.len());
        assert_eq!(sock_stream, expected_deltas);

        let (min, max, avg) = sock_cache.num_cpus();
        assert_eq!(min, 2);
        assert_eq!(max, 2);
        assert!((2.0 - avg).abs() < 0.01);
    }

    #[test]
    fn test_get_sock_deltas_all_new_contexts() {
        let mut sock_cache = SockCache::new();
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();

        // Create a slew of sockets in the incoming stream.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        for sock_key in sock_keys.iter() {
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![*sock_key as u32 % 2, 100],
                    stats: SockStats {
                        last_touched_us: sock_key * 3,
                        bytes_delivered: sock_key * 4,
                        ..Default::default()
                    },
                },
            );
        }

        // On nothing before should yield all of the after.
        let expected_deltas = sock_stream.clone();
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: sock_keys.len().try_into().unwrap(),
                failed: 0,
            }
        );
        assert_eq!(sock_cache.len(), sock_keys.len());
        assert_eq!(sock_stream, expected_deltas);
    }

    #[test]
    fn test_get_sock_deltas_all_changed() {
        let mut sock_cache = SockCache::new();
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();

        // Create a slew of sockets in the incoming stream.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        for sock_key in sock_keys.iter() {
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![*sock_key as u32 % 2, 100],
                    stats: SockStats {
                        bytes_delivered: sock_key * 4,
                        ..Default::default()
                    },
                },
            );
        }

        // Create sock stats already in cache, but with smaller values.
        let mut old_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        for (sock_key, _val_after) in sock_stream.iter() {
            let val_before = AggSockStats {
                cpus: vec![],
                stats: SockStats {
                    bytes_delivered: *sock_key,
                    ..Default::default()
                },
            };
            old_stream.insert(*sock_key, val_before);
        }
        let result = sock_cache.update_stats_and_get_deltas(&mut old_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: sock_keys.len().try_into().unwrap(),
                failed: 0,
            }
        );

        // Validate the resultant deltas placed into the sock stream.
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: sock_keys.len().try_into().unwrap(),
                partial: 0,
                failed: 0,
            }
        );
        assert_eq!(sock_stream.len(), sock_keys.len());
        for (sock_key, actual_delta) in sock_stream.iter() {
            let expected_delta = AggSockStats {
                stats: SockStats {
                    bytes_delivered: sock_key * 3,
                    ..Default::default()
                },
                cpus: vec![*sock_key as u32 % 2, 100],
            };
            assert_eq!(*actual_delta, expected_delta);
        }
    }

    #[test]
    fn test_get_sock_deltas_new_and_changed() {
        let mut sock_cache = SockCache::new();
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();

        // Create a slew of sockets in the incoming stream.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        for sock_key in sock_keys.iter() {
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![*sock_key as u32 % 2, 100],
                    stats: SockStats {
                        bytes_delivered: sock_key * 4,
                        ..Default::default()
                    },
                },
            );
        }

        // Create sock stats already in cache, but with smaller values.
        let mut old_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        for (sock_key, _val_after) in sock_stream.iter() {
            let val_before = AggSockStats {
                cpus: vec![],
                stats: SockStats {
                    bytes_delivered: *sock_key,
                    ..Default::default()
                },
            };
            old_stream.insert(*sock_key, val_before);
        }

        // Let's say two sockets were not in the old stream, and will thus appear anew.
        old_stream.remove(&101);
        old_stream.remove(&19);
        let result = sock_cache.update_stats_and_get_deltas(&mut old_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: sock_keys.len() as u64 - 2,
                failed: 0,
            }
        );

        // Validate the resultant deltas placed into the sock stream.
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: sock_keys.len() as u64 - 2,
                partial: 2,
                failed: 0,
            }
        );
        assert_eq!(sock_stream.len(), sock_keys.len());
        for (sock_key, actual_delta) in sock_stream.iter() {
            let delta_factor: u64 = if *sock_key == 101 || *sock_key == 19 {
                4
            } else {
                3
            };
            let expected_delta = AggSockStats {
                stats: SockStats {
                    bytes_delivered: sock_key * delta_factor,
                    ..Default::default()
                },
                cpus: vec![*sock_key as u32 % 2, 100],
            };
            assert_eq!(*actual_delta, expected_delta);
        }
    }

    #[test]
    fn test_get_sock_deltas_all_partial() {
        let mut sock_cache = SockCache::new();
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();

        // Place a slew of sockets into the cache.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        for sock_key in sock_keys.iter() {
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![*sock_key as u32 % 2, 100],
                    stats: SockStats {
                        bytes_delivered: sock_key * 4,
                        ..Default::default()
                    },
                },
            );
        }
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: sock_keys.len().try_into().unwrap(),
                failed: 0,
            }
        );

        // On something before but nothing after is non-sensical, so should yield nothing.
        sock_stream.clear();
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: 0,
                failed: 0,
            }
        );
        assert!(sock_stream.is_empty());
    }

    #[test]
    fn test_get_sockets_to_evict_empty() {
        let mut sock_cache = SockCache::new();
        let (socks_evicted, num_stale) = sock_cache.perform_eviction();

        assert!(socks_evicted.is_empty());
        assert_eq!(num_stale, 0);
        assert_eq!(sock_cache.len(), 0);
    }

    #[test]
    fn test_get_sockets_to_evict_all_active() {
        let now_us = 100;
        let notrack_us = 10;
        let mut sock_cache = SockCache::new();

        // Many active sockets yields nothing.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        for sock_key in sock_keys.iter() {
            let cpu_id = *sock_key % 2;
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![cpu_id as u32],
                    stats: SockStats {
                        last_touched_us: now_us - (notrack_us / 2),
                        ..Default::default()
                    },
                },
            );
        }

        let staleness_timestamp: u64 = now_us - notrack_us;
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, staleness_timestamp);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: sock_keys.len().try_into().unwrap(),
                failed: 0,
            }
        );

        let (socks_evicted, num_stale) = sock_cache.perform_eviction();
        assert_eq!(socks_evicted.len(), 0);
        assert_eq!(num_stale, 0);
        assert_eq!(sock_cache.len(), sock_keys.len());
    }

    #[test]
    fn test_get_sockets_to_evict_some_closed() {
        let now_us = 100;
        let notrack_us = 10;
        let mut sock_cache = SockCache::new();

        // Create many active sockets.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        for sock_key in sock_keys.iter() {
            let cpu_id = *sock_key % 2;
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![cpu_id as u32],
                    stats: SockStats {
                        last_touched_us: now_us - (notrack_us / 2),
                        ..Default::default()
                    },
                },
            );

            // Also add a context in cache.
            let context = SockContext {
                address_family: AF_INET,
                ..Default::default()
            };
            sock_cache.add_context(*sock_key, context, now_us);
        }

        // Close two of them.
        sock_stream
            .get_mut(&sock_keys[0])
            .unwrap()
            .stats
            .state_flags
            .insert(SockStateFlags::CLOSED);
        sock_stream
            .get_mut(&sock_keys[1])
            .unwrap()
            .stats
            .state_flags
            .insert(SockStateFlags::CLOSED);

        // Store the full set in cache.
        let staleness_timestamp: u64 = now_us - notrack_us;
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, staleness_timestamp);
        assert_eq!(
            result,
            SockOperationResult {
                completed: sock_keys.len().try_into().unwrap(),
                partial: 0,
                failed: 0,
            }
        );

        // Perform eviction and validate.
        let (socks_evicted, num_stale) = sock_cache.perform_eviction();
        assert_eq!(socks_evicted.len(), 2);
        assert_eq!(num_stale, 0);
        assert_eq!(sock_cache.len(), sock_keys.len() - 2);
        assert_eq!(
            &socks_evicted.get(&sock_keys[0]).unwrap().agg_stats,
            sock_stream.get(&sock_keys[0]).unwrap()
        );
        assert_eq!(
            &socks_evicted.get(&sock_keys[1]).unwrap().agg_stats,
            sock_stream.get(&sock_keys[1]).unwrap()
        );
    }

    #[test]
    fn test_get_sockets_to_evict_some_inactive() {
        let now_us = 100;
        let notrack_us = 10;
        let mut sock_cache = SockCache::new();

        // Create many active sockets.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        for sock_key in sock_keys.iter() {
            let cpu_id = *sock_key % 2;
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![cpu_id as u32],
                    stats: SockStats {
                        last_touched_us: now_us - (notrack_us / 2),
                        ..Default::default()
                    },
                },
            );
        }

        // Make two of them inactive.
        sock_stream
            .get_mut(&sock_keys[2])
            .unwrap()
            .stats
            .last_touched_us = now_us - notrack_us;
        sock_stream
            .get_mut(&sock_keys[5])
            .unwrap()
            .stats
            .last_touched_us = now_us - (notrack_us * 2);

        // Store the full set in cache.
        let staleness_timestamp: u64 = now_us - notrack_us;
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, staleness_timestamp);
        assert_eq!(
            result,
            SockOperationResult {
                completed: 0,
                partial: sock_keys.len().try_into().unwrap(),
                failed: 0,
            }
        );

        // Perform eviction and validate.
        let (socks_evicted, num_stale) = sock_cache.perform_eviction();
        assert_eq!(socks_evicted.len(), 2);
        assert_eq!(num_stale, 2);
        assert_eq!(sock_cache.len(), sock_keys.len() - 2);
        assert_eq!(
            &socks_evicted.get(&sock_keys[2]).unwrap().agg_stats,
            sock_stream.get(&sock_keys[2]).unwrap()
        );
        assert_eq!(
            &socks_evicted.get(&sock_keys[5]).unwrap().agg_stats,
            sock_stream.get(&sock_keys[5]).unwrap()
        );
    }

    #[test]
    fn test_get_sockets_to_evict_all_closed() {
        let now_us = 100;
        let notrack_us = 10;
        let mut sock_cache = SockCache::new();

        // Create many sockets, all closed.
        let sock_keys: Vec<u64> = vec![99, 101, 4, 55, 19, 79];
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        for sock_key in sock_keys.iter() {
            let cpu_id = *sock_key % 2;
            sock_stream.insert(
                *sock_key,
                AggSockStats {
                    cpus: vec![cpu_id as u32],
                    stats: SockStats {
                        last_touched_us: now_us - (notrack_us / 2),
                        state_flags: SockStateFlags::CLOSED,
                        ..Default::default()
                    },
                },
            );

            // Also add a context in cache.
            let context = SockContext {
                address_family: AF_INET,
                ..Default::default()
            };
            let result = sock_cache.add_context(*sock_key, context, now_us);
            assert_eq!(
                result,
                SockOperationResult {
                    completed: 1,
                    partial: 0,
                    failed: 0,
                }
            );
        }

        // Store the full set in cache.
        let staleness_timestamp: u64 = now_us - notrack_us;
        let result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, staleness_timestamp);
        assert_eq!(
            result,
            SockOperationResult {
                completed: sock_keys.len().try_into().unwrap(),
                partial: 0,
                failed: 0,
            }
        );

        // Perform eviction and validate.
        let (socks_evicted, num_stale) = sock_cache.perform_eviction();
        assert_eq!(num_stale, 0);
        assert_eq!(sock_cache.len(), 0);

        assert_eq!(socks_evicted.len(), sock_keys.len());
        for key in sock_keys.iter() {
            assert!(socks_evicted.get(key).is_some());
        }
    }

    #[test]
    fn test_sock_cache_get_last_touched() {
        let mut sock_cache = SockCache::new();

        let sock_key1: SockKey = 1979;
        let sock_key2: SockKey = 2005;
        let sock_key_invalid: SockKey = 2553;

        let now_us = 1997;
        sock_cache.add_context(sock_key1, SockContext::default(), now_us);
        sock_cache.add_context(sock_key2, SockContext::default(), now_us + 26);

        assert_eq!(sock_cache.get_last_touched(&sock_key_invalid), 0);
        assert_eq!(sock_cache.get_last_touched(&sock_key1), now_us);
        assert_eq!(sock_cache.get_last_touched(&sock_key2), now_us + 26);
    }
}
