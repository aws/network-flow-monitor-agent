// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::events::event_provider::EventProvider;
use crate::events::nat_resolver::NatResolver;
use crate::events::network_event::{AggregateResults, FlowProperties, NetworkStats};
use crate::events::{bpf_batch, AggSockStats, SockCache, SockOperationResult, SockWrapper};
use crate::reports::{CountersOverall, ProcessCounters};
use crate::utils::Clock;
use nfm_common::constants::{
    AGG_FLOWS_MAX_ENTRIES, EBPF_PROGRAM_NAME, MAX_ENTRIES_SK_PROPS_HI, MAX_ENTRIES_SK_PROPS_LO,
    MAX_ENTRIES_SK_STATS_HI, MAX_ENTRIES_SK_STATS_LO, NFM_CONTROL_MAP_NAME, NFM_COUNTERS_MAP_NAME,
    NFM_SK_PROPS_RB_MAP_NAME, NFM_SK_STATS_MAP_NAME, SK_STATS_TO_PROPS_RATIO,
};
use nfm_common::network::{
    ControlData, CpuSockKey, EventCounters, SockKey, SockPropsEntry, SockStats,
};

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array as SharedArray, HashMap as SharedHashMap, MapData, PerCpuArray, RingBuf},
    programs::{CgroupAttachMode, SockOps},
    Ebpf, EbpfLoader, VerifierLogLevel,
};
use aya_obj::generated::BPF_ANY;
use hashbrown::{hash_map::Entry, HashMap};
use log::{debug, info};
use procfs::{Current, Meminfo};
use std::cmp::min;
use std::fs::File;
use std::mem;
use std::mem::size_of;

pub struct EventProviderEbpf<C: Clock> {
    #[allow(dead_code)]
    ebpf_handle: Ebpf,
    ebpf_sock_props_rb: RingBuf<MapData>,
    ebpf_sock_stats: SharedHashMap<MapData, CpuSockKey, SockStats>,
    ebpf_counters_map: PerCpuArray<MapData, EventCounters>,
    ebpf_control_map: SharedArray<MapData, ControlData>,
    ebpf_control_data: ControlData,
    ebpf_counters_latest: EventCounters,
    ebpf_counters_published: EventCounters,
    ebpf_allocated_mem_kb: u32,
    sock_stats_max_entries: usize,

    process_counters: ProcessCounters,
    notrack_us: u64,
    clock: C,
    agg_socks_handled: u64,

    sock_cache: SockCache,
    sock_stream: HashMap<SockKey, AggSockStats>,
    flow_cache: HashMap<FlowProperties, AggregateResults>,
}

fn instantiate_ebpf_object(
    sock_props_max_entries: u64,
    sock_stats_max_entries: u64,
) -> Result<Ebpf> {
    // Embed the eBPF raw bytes at compile time, and load them into the kernel at runtime.
    let ebpf_bytes = include_bytes_aligned!(env!("BPF_OBJECT_PATH"));
    let ringbuf_size = nfm_common::constants::ringbuf_byte_size(sock_props_max_entries);
    info!(sock_props_max_entries, sock_stats_max_entries, ringbuf_size; "Loading eBPF program");
    EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
        .set_max_entries(
            NFM_SK_STATS_MAP_NAME,
            sock_stats_max_entries.try_into().unwrap(),
        )
        .set_max_entries(NFM_SK_PROPS_RB_MAP_NAME, ringbuf_size)
        .load(ebpf_bytes)
        .context("Failed to parse eBPF program")
}

pub fn map_max_entries(mem_total_bytes: u64) -> (u64, u64) {
    // We want our two BPF maps to consume less than a certain percentage of total memory, and the
    // stats map to be a certain factor larger than the props map.

    // This divisor was chosen arbitrarily based on experimentation.
    let divisor: u64 = 5_000_000_000;
    let sock_props_max_entries = (mem_total_bytes / divisor * MAX_ENTRIES_SK_PROPS_LO)
        .clamp(MAX_ENTRIES_SK_PROPS_LO, MAX_ENTRIES_SK_PROPS_HI);

    let sock_stats_max_entries = (sock_props_max_entries * SK_STATS_TO_PROPS_RATIO)
        .clamp(MAX_ENTRIES_SK_STATS_LO, MAX_ENTRIES_SK_STATS_HI);

    (sock_props_max_entries, sock_stats_max_entries)
}

fn calculate_ebpf_memory_usage(sock_props_max_entries: u64, sock_stats_max_entries: u64) -> u32 {
    let ringbuf_size = nfm_common::constants::ringbuf_byte_size(sock_props_max_entries) as u64;
    let sock_stats_size = size_of::<CpuSockKey>() + size_of::<SockStats>();
    ((ringbuf_size + (sock_stats_max_entries * sock_stats_size as u64)) as f64 / 1000.0).ceil()
        as u32
}

impl<C: Clock> EventProvider for EventProviderEbpf<C> {
    // Aggregates results from the eBPF layer, and evicts closed sockets.
    fn perform_aggregation_cycle(&mut self, nat_resolver: &mut Box<dyn NatResolver>) {
        debug!("Aggregating across sockets");

        // Apply adaptive sampling if we're receiving events faster than we can process.
        let ebpf_delta = self.ebpf_counters();
        if ebpf_delta.map_insertion_errors > 0 {
            self.increase_sampling_interval();
        } else {
            self.decrease_sampling_interval();
        }

        // Drain socket properties from the ringbuf (zero syscalls — memory-mapped).
        let now_us = self.clock.now_us();
        let context_timestamp = now_us.saturating_sub(self.notrack_us / 2);
        let mut sock_add_result = SockOperationResult::default();
        while let Some(item) = self.ebpf_sock_props_rb.next() {
            if item.len() < size_of::<SockPropsEntry>() {
                continue;
            }
            let entry: &SockPropsEntry = unsafe { &*(item.as_ptr() as *const SockPropsEntry) };
            let result =
                self.sock_cache
                    .add_context(entry.sock_key, entry.context, context_timestamp);
            sock_add_result.add(&result);
            if result.failed > 0 {
                break;
            }
        }

        // Aggregate stats across CPU cores, then take the delta from the previous aggregation cycle.
        let stats_batch =
            bpf_batch::lookup_batch(&self.ebpf_sock_stats, self.sock_stats_max_entries);
        SocketQueries::aggregate_sock_stats(
            stats_batch.into_iter(),
            &self.sock_cache,
            &mut self.sock_stream,
        );
        let staleness_timestamp = now_us.saturating_sub(self.notrack_us);
        let sock_delta_result = self
            .sock_cache
            .update_stats_and_get_deltas(&mut self.sock_stream, staleness_timestamp);

        // Apply beyond-NAT sock properties to any NAT'd sockets.
        nat_resolver.perform_aggregation_cycle(); // call order matters. should be after reading bpf for higher accuracy
        let sock_nat_result = nat_resolver.store_beyond_nat_entries(&mut self.sock_cache);

        // Aggregate our delta stats into flows.
        let num_flows_before = self.flow_cache.len();
        let flow_aggregation_result = SocketQueries::aggregate_into_flows(
            &self.sock_stream,
            &self.sock_cache,
            &mut self.flow_cache,
        );
        self.sock_stream.clear();

        // Collect some stats before evicting entries.
        self.agg_socks_handled = self.sock_cache.len().try_into().unwrap();
        let (num_cpus_min, num_cpus_max, num_cpus_avg) = self.sock_cache.num_cpus();

        // Evict sockets.
        let (socks_to_evict, num_stale) = self.sock_cache.perform_eviction();
        let sock_eviction_result = self.perform_bpf_eviction(socks_to_evict);

        // Update counters.
        self.process_counters.sockets_added += sock_add_result.completed;
        self.process_counters.sockets_stale += num_stale;
        self.process_counters.sockets_natd += sock_nat_result.completed;

        self.process_counters.socket_deltas_completed += sock_delta_result.completed;
        self.process_counters.socket_deltas_missing_props += sock_delta_result.partial;
        self.process_counters.socket_deltas_above_limit += sock_delta_result.failed;

        self.process_counters.socket_agg_completed += flow_aggregation_result.completed;
        self.process_counters.socket_agg_missing_props += flow_aggregation_result.partial;
        self.process_counters.socket_agg_above_limit += flow_aggregation_result.failed;

        self.process_counters.socket_eviction_completed += sock_eviction_result.completed;
        self.process_counters.socket_eviction_failed += sock_eviction_result.failed;

        debug!(
            sock_add_result:serde,
            sock_delta_result:serde,
            sock_nat_result:serde,
            flow_aggregation_result:serde,
            sock_eviction_result:serde,
            control_data:serde = self.ebpf_control_data,
            sock_cache_len = self.sock_cache.len(),
            flows_before = num_flows_before,
            flows_after = self.flow_cache.len(),
            cpus_per_sock_min = num_cpus_min,
            cpus_per_sock_avg = num_cpus_avg,
            cpus_per_sock_max = num_cpus_max;
            "Aggregation complete"
        );
    }

    // Returns and resets aggregated network stats.
    fn network_stats(&mut self) -> Vec<AggregateResults> {
        let results: Vec<AggregateResults> =
            mem::take(&mut self.flow_cache).into_values().collect();
        // Pre-allocate capacity based on previous cycle to reduce rehashing.
        self.flow_cache.reserve(results.len());
        results
    }

    // Returns and resets tracked counters.
    fn counters(&mut self) -> CountersOverall {
        let ebpf_counters_delta = self
            .ebpf_counters_latest
            .subtract(&self.ebpf_counters_published);
        self.ebpf_counters_published = self.ebpf_counters_latest;

        CountersOverall {
            event_related: ebpf_counters_delta,
            process_related: self.process_counters(),
        }
    }

    // Gets the number of sockets tracked.
    fn socket_count(&self) -> u64 {
        self.agg_socks_handled
    }

    // Gets the memory usage by ebpf program, static value
    fn ebpf_allocated_mem_kb(&self) -> u32 {
        self.ebpf_allocated_mem_kb
    }
}

impl<C: Clock> EventProviderEbpf<C> {
    pub fn new(
        cgroup: &String,
        notrack_secs: u64,
        max_sock_props_override: Option<u64>,
        clock: C,
    ) -> Result<Self> {
        let cgroup_file = File::open(cgroup).context(format!("cgroup file not found: {cgroup}"))?;

        let mem_total_bytes = match Meminfo::current() {
            Ok(meminfo) => meminfo.mem_total,
            Err(e) => {
                panic!("Unable to determine total memory: {e}");
            }
        };
        let (sock_props_max_entries, sock_stats_max_entries) = match max_sock_props_override {
            Some(v) => {
                let sk_props_size = v.clamp(MAX_ENTRIES_SK_PROPS_LO, MAX_ENTRIES_SK_PROPS_HI);
                let sk_stats_size = (sk_props_size * SK_STATS_TO_PROPS_RATIO)
                    .clamp(MAX_ENTRIES_SK_STATS_LO, MAX_ENTRIES_SK_STATS_HI);
                (sk_props_size, sk_stats_size)
            }
            None => map_max_entries(mem_total_bytes),
        };
        let mut ebpf_handle =
            instantiate_ebpf_object(sock_props_max_entries, sock_stats_max_entries)?;

        let program: &mut SockOps = ebpf_handle
            .program_mut(EBPF_PROGRAM_NAME)
            .unwrap()
            .try_into()
            .context("Failed to instantiate sockops program")?;
        program
            .load()
            .context("Failed to load sockops program into the kernel")?;
        program
            .attach(cgroup_file, CgroupAttachMode::Single)
            .context(format!("Failed to attach to cgroup: {cgroup}"))?;

        let ebpf_sock_props_rb =
            RingBuf::try_from(ebpf_handle.take_map(NFM_SK_PROPS_RB_MAP_NAME).unwrap())
                .context(format!("Failed to load BPF map {NFM_SK_PROPS_RB_MAP_NAME}"))?;
        let ebpf_sock_stats =
            SharedHashMap::try_from(ebpf_handle.take_map(NFM_SK_STATS_MAP_NAME).unwrap())
                .context(format!("Failed to load BPF map {NFM_SK_STATS_MAP_NAME}"))?;
        let ebpf_counters_map =
            PerCpuArray::try_from(ebpf_handle.take_map(NFM_COUNTERS_MAP_NAME).unwrap())
                .context(format!("Failed to load BPF map {NFM_COUNTERS_MAP_NAME}"))?;
        let ebpf_control_map =
            SharedArray::try_from(ebpf_handle.take_map(NFM_CONTROL_MAP_NAME).unwrap())
                .context(format!("Failed to load BPF map {NFM_CONTROL_MAP_NAME}"))?;

        let ebpf_allocated_mem_kb =
            calculate_ebpf_memory_usage(sock_props_max_entries, sock_stats_max_entries);
        info!(ebpf_allocated_mem_kb; "Calculated BPF maps approximate memory usage");

        let mut provider = EventProviderEbpf {
            ebpf_handle,
            ebpf_sock_props_rb,
            ebpf_sock_stats,
            ebpf_counters_map,
            ebpf_control_map,
            ebpf_control_data: ControlData::default(),
            ebpf_counters_latest: EventCounters::default(),
            ebpf_counters_published: EventCounters::default(),
            ebpf_allocated_mem_kb,
            sock_stats_max_entries: sock_stats_max_entries as usize,
            process_counters: ProcessCounters {
                restarts: 1,
                ..Default::default()
            },
            notrack_us: notrack_secs * 1_000_000,
            clock,
            sock_cache: SockCache::with_max_entries(sock_props_max_entries as usize),
            sock_stream: HashMap::new(),
            flow_cache: HashMap::new(),
            agg_socks_handled: 0,
        };
        provider.increase_sampling_interval();
        Ok(provider)
    }

    fn increase_sampling_interval(&mut self) {
        // With 1000 sampling rate, the probability of picking up a new connection
        // is 1/1000.
        let max_sampling_interval = 1000;
        if self.ebpf_control_data.sampling_interval > max_sampling_interval {
            return;
        } else if self.ebpf_control_data.sampling_interval > 1 {
            self.ebpf_control_data.sampling_interval = min(
                max_sampling_interval,
                self.ebpf_control_data.sampling_interval.saturating_mul(3) / 2,
            );
        } else {
            self.ebpf_control_data.sampling_interval = 2;
        }

        self.send_control_data();
    }

    fn decrease_sampling_interval(&mut self) {
        if self.ebpf_control_data.sampling_interval > 1 {
            self.ebpf_control_data.sampling_interval -=
                self.ebpf_control_data.sampling_interval.div_ceil(7);
            self.send_control_data();
        }
    }

    fn send_control_data(&mut self) {
        self.ebpf_control_map
            .set(0, self.ebpf_control_data, BPF_ANY.into())
            .unwrap_or_else(|e| panic!("Failed to write control data: {e:?}"))
    }

    fn process_counters(&mut self) -> ProcessCounters {
        let latest_counters = self.process_counters;
        self.process_counters = ProcessCounters::default();

        latest_counters
    }

    fn ebpf_counters(&mut self) -> EventCounters {
        let mut new_counters = EventCounters::default();
        const EMPTY_FLAGS: u64 = 0;
        const KEY: u32 = 0;
        if let Ok(counters_per_cpu) = self.ebpf_counters_map.get(&KEY, EMPTY_FLAGS) {
            for counters in (*counters_per_cpu).iter() {
                new_counters.add_from(counters);
            }
        }

        // eBPF counters continue accumulating.  The difference from our last set of counters
        // represents new counts.
        let delta_counts = new_counters.subtract(&self.ebpf_counters_latest);
        self.ebpf_counters_latest = new_counters;

        delta_counts
    }

    // Evicts from the sock_stats map via single bpf batch delete syscall.
    fn perform_bpf_eviction(
        &mut self,
        to_evict: Vec<(SockKey, SockWrapper)>,
    ) -> SockOperationResult {
        let mut keys_to_delete: Vec<CpuSockKey> = Vec::new();
        for (sock_key, sock_wrap) in &to_evict {
            for cpu_id in &sock_wrap.agg_stats.cpus {
                keys_to_delete.push(CpuSockKey {
                    cpu_id: (*cpu_id).into(),
                    sock_key: *sock_key,
                });
            }
        }

        let deleted = bpf_batch::delete_batch(&mut self.ebpf_sock_stats, &keys_to_delete);
        SockOperationResult {
            completed: deleted.into(),
            failed: (keys_to_delete.len() as u64).saturating_sub(deleted.into()),
            ..Default::default()
        }
    }
}

// A private set of helper methods for running queries over collections of sockets.
struct SocketQueries;
impl SocketQueries {
    fn aggregate_sock_stats(
        sock_stats: impl Iterator<Item = (CpuSockKey, SockStats)>,
        sock_cache: &SockCache,
        agg_stats_by_sock: &mut HashMap<SockKey, AggSockStats>,
    ) {
        // Retrieve sock stats from the eBPF map and sum results across CPU cores.
        for (composite_key, new_stats) in sock_stats {
            let agg_stats = agg_stats_by_sock.entry(composite_key.sock_key).or_default();
            let sock_last_read = sock_cache.get_last_touched(&composite_key.sock_key);
            agg_stats.stats.add_from(&new_stats, sock_last_read);
            agg_stats
                .cpus
                .push(composite_key.cpu_id.try_into().unwrap());
        }
    }

    // Aggregates socket stats into stats by flow properties.
    fn aggregate_into_flows(
        sock_stats_deltas: &HashMap<SockKey, AggSockStats>,
        sock_cache: &SockCache,
        flow_cache: &mut HashMap<FlowProperties, AggregateResults>,
    ) -> SockOperationResult {
        // Reset the counts of sockets per state.
        for flow in flow_cache.values_mut() {
            flow.stats.clear_levels();
        }

        let mut result = SockOperationResult::default();
        let flow_limit: usize = AGG_FLOWS_MAX_ENTRIES.try_into().unwrap();
        for (sock_key, agg_stats) in sock_stats_deltas.iter() {
            let sock_wrapper = match sock_cache.get(sock_key) {
                Some(ctx) => ctx,
                None => {
                    result.failed += 1;
                    continue;
                }
            };

            let context_beyond_nat = sock_wrapper
                .context_external
                .unwrap_or(sock_wrapper.context);
            if let Ok(flow_props) = FlowProperties::try_from(&context_beyond_nat) {
                let flow_count = flow_cache.len();
                let flow_entry = flow_cache.entry(flow_props.clone());
                let flow_agg = match flow_entry {
                    Entry::Occupied(o) => o.into_mut(),
                    Entry::Vacant(v) => {
                        if flow_count < flow_limit {
                            // When below the flow limit, track new flows.
                            v.insert(AggregateResults {
                                flow: flow_props,
                                stats: NetworkStats::default(),
                            })
                        } else {
                            // When at the flow limit, move on to the next socket.
                            result.failed += 1;
                            continue;
                        }
                    }
                };

                flow_agg.stats.add_from(&agg_stats.stats);
                if sock_wrapper.should_evict() {
                    flow_agg.stats.sockets_completed =
                        flow_agg.stats.sockets_completed.saturating_add(1);
                }
                result.completed += 1;
            } else {
                result.partial += 1;
            }
        }

        result
    }
}

#[cfg(test)]
mod test {
    use crate::events::event_provider_ebpf::{
        calculate_ebpf_memory_usage, map_max_entries, SocketQueries,
    };
    use crate::events::network_event::{AggregateResults, FlowProperties, InetProtocol};
    use crate::events::{AggSockStats, SockCache, SockOperationResult};
    use nfm_common::constants::{
        AGG_FLOWS_MAX_ENTRIES, MAX_ENTRIES_SK_PROPS_HI, MAX_ENTRIES_SK_PROPS_LO,
        MAX_ENTRIES_SK_STATS_HI, MAX_ENTRIES_SK_STATS_LO,
    };
    use nfm_common::{
        network::{CpuSockKey, SockContext, SockKey, SockStats},
        AF_INET,
    };

    use hashbrown::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    const STALENESS_TS: u64 = 0;

    #[test]
    pub fn test_result_aggregation_into_flows() {
        let mut ebpf_sk_stats: Vec<(CpuSockKey, SockStats)> = Vec::new();

        const NUM_CPUS: usize = 16;
        let sock_keys: Vec<usize> = vec![99, 101, 4, 55, 19, 79];

        let mut sock_cache = SockCache::new();
        let now_us = 2025;
        for (index, sock_key) in sock_keys.iter().enumerate() {
            // Simulate sock properties having already been loaded.  All sockets alternate between
            // two remote ports.
            let fake_value = (index % 2 + 1) as u16 * 10;
            let sk_context = SockContext {
                is_client: true,
                address_family: AF_INET,
                local_ipv4: 1950,
                remote_ipv4: 2265,
                local_port: 1492,
                remote_port: fake_value,
                ..Default::default()
            };
            sock_cache.add_context((*sock_key).try_into().unwrap(), sk_context, now_us);

            // Simulate later socket events being handled by two different CPUs.
            let cpu_id = (sock_key + 3) % NUM_CPUS;
            let composite_key = CpuSockKey {
                cpu_id: cpu_id.try_into().unwrap(),
                sock_key: (*sock_key).try_into().unwrap(),
            };
            let sk_stats = SockStats {
                last_touched_us: now_us,
                bytes_received: fake_value as u64 * 3,
                rtt_count: fake_value as u32 * 5,
                rtt_latest_us: 99,
                ..Default::default()
            };
            ebpf_sk_stats.push((composite_key, sk_stats));

            let cpu_id = (sock_key + 4) % NUM_CPUS;
            let composite_key = CpuSockKey {
                cpu_id: cpu_id.try_into().unwrap(),
                sock_key: (*sock_key).try_into().unwrap(),
            };
            let sk_stats = SockStats {
                last_touched_us: now_us,
                bytes_received: fake_value as u64 * 4,
                rtt_count: fake_value as u32 * 6,
                rtt_latest_us: 100,
                ..Default::default()
            };
            ebpf_sk_stats.push((composite_key, sk_stats));
        }

        // Aggregate results.
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        SocketQueries::aggregate_sock_stats(
            ebpf_sk_stats.into_iter(),
            &sock_cache,
            &mut sock_stream,
        );
        let delta_result = sock_cache.update_stats_and_get_deltas(&mut sock_stream, STALENESS_TS);

        let mut flow_cache = HashMap::new();
        let agg_result =
            SocketQueries::aggregate_into_flows(&sock_stream, &sock_cache, &mut flow_cache);

        // Now validate what we got.
        assert_eq!(
            delta_result,
            SockOperationResult {
                completed: sock_keys.len().try_into().unwrap(),
                partial: 0,
                failed: 0,
            }
        );
        assert_eq!(
            agg_result,
            SockOperationResult {
                completed: sock_keys.len().try_into().unwrap(),
                partial: 0,
                failed: 0,
            }
        );
        let num_endpoints = sock_keys.len() as u32 / 2;
        assert_eq!(flow_cache.len(), 2);
        for result in flow_cache.into_values() {
            assert_eq!(result.flow.local_address, Ipv4Addr::new(0, 0, 7, 158));
            assert_eq!(result.flow.remote_address, Ipv4Addr::new(0, 0, 8, 217));
            assert_eq!(result.flow.protocol, InetProtocol::TCP);
            assert_eq!(result.flow.local_port, 0);

            let fake_value = result.flow.remote_port;
            assert!(fake_value == 10 || fake_value == 20);

            // Validate the stats summed across CPUs.
            assert_eq!(
                result.stats.bytes_received,
                fake_value as u64 * 4 * num_endpoints as u64,
            );
            assert_eq!(result.stats.rtt_us.count, num_endpoints);
        }
    }

    #[test]
    fn test_flow_aggregation_empty() {
        let sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        let sock_cache = SockCache::new();
        let mut flow_cache: HashMap<FlowProperties, AggregateResults> = HashMap::new();

        let agg_result =
            SocketQueries::aggregate_into_flows(&sock_stream, &sock_cache, &mut flow_cache);
        assert!(flow_cache.is_empty());
        assert_eq!(
            agg_result,
            SockOperationResult {
                completed: 0,
                partial: 0,
                failed: 0,
            }
        );
    }

    #[test]
    fn test_flow_aggregation_one_flow() {
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        let mut sock_cache = SockCache::with_max_entries(AGG_FLOWS_MAX_ENTRIES as usize);
        let mut flow_cache: HashMap<FlowProperties, AggregateResults> = HashMap::new();

        // Test the aggregation of many sockets into one flow.
        let now_us: u64 = 2025;
        for i in 0..AGG_FLOWS_MAX_ENTRIES {
            let sock_key = i as SockKey;
            let sock_context = SockContext {
                address_family: AF_INET,
                remote_ipv4: Ipv4Addr::from_str("44.33.22.11").unwrap().to_bits(),
                ..Default::default()
            };
            sock_cache.add_context(sock_key, sock_context, now_us);
            sock_stream.insert(
                sock_key,
                AggSockStats {
                    stats: SockStats {
                        bytes_received: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        }
        let agg_result =
            SocketQueries::aggregate_into_flows(&sock_stream, &sock_cache, &mut flow_cache);

        let expected_bytes: u64 = AGG_FLOWS_MAX_ENTRIES as u64;
        let actual_bytes: u64 = flow_cache
            .values()
            .map(|agg_flow| agg_flow.stats.bytes_received)
            .sum();
        assert_eq!(flow_cache.len(), 1);
        assert_eq!(actual_bytes, expected_bytes);
        assert_eq!(
            agg_result,
            SockOperationResult {
                completed: AGG_FLOWS_MAX_ENTRIES as u64,
                partial: 0,
                failed: 0,
            }
        );
        for flow in flow_cache.keys() {
            assert_eq!(
                flow.remote_address,
                IpAddr::from_str("44.33.22.11").unwrap()
            );
        }
    }

    #[test]
    fn test_flow_aggregation_many_flows() {
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        let mut sock_cache = SockCache::with_max_entries(AGG_FLOWS_MAX_ENTRIES as usize);
        let mut flow_cache: HashMap<FlowProperties, AggregateResults> = HashMap::new();

        // Test the aggregation of many sockets into different flows.
        let now_us = 1997;
        for i in 0..AGG_FLOWS_MAX_ENTRIES {
            let sock_key = i as SockKey;
            let sock_context = SockContext {
                address_family: AF_INET,
                remote_ipv4: i,
                ..Default::default()
            };
            sock_cache.add_context(sock_key, sock_context, now_us);
            sock_stream.insert(
                sock_key,
                AggSockStats {
                    stats: SockStats {
                        bytes_received: i as u64,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        }
        let agg_result =
            SocketQueries::aggregate_into_flows(&sock_stream, &sock_cache, &mut flow_cache);
        assert_eq!(
            agg_result,
            SockOperationResult {
                completed: AGG_FLOWS_MAX_ENTRIES as u64,
                partial: 0,
                failed: 0,
            }
        );

        let expected_bytes: u64 =
            ((AGG_FLOWS_MAX_ENTRIES - 1) * (AGG_FLOWS_MAX_ENTRIES / 2)).into();
        let actual_bytes: u64 = flow_cache
            .values()
            .map(|agg_flow| agg_flow.stats.bytes_received)
            .sum();
        assert_eq!(flow_cache.len(), AGG_FLOWS_MAX_ENTRIES as usize);
        assert_eq!(actual_bytes, expected_bytes);
    }

    #[test]
    fn test_flow_aggregation_too_many_flows() {
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        let mut sock_cache = SockCache::with_max_entries(AGG_FLOWS_MAX_ENTRIES as usize);
        let mut flow_cache: HashMap<FlowProperties, AggregateResults> = HashMap::new();

        // Test the aggregation of many sockets into *too many* flows.
        let now_us = 2342;
        for i in 0..AGG_FLOWS_MAX_ENTRIES * 2 {
            let sock_key = i as SockKey;
            let sock_context = SockContext {
                address_family: AF_INET,
                remote_ipv4: i,
                ..Default::default()
            };
            sock_cache.add_context(sock_key, sock_context, now_us);
            sock_stream.insert(
                sock_key,
                AggSockStats {
                    stats: SockStats {
                        bytes_received: i as u64,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        }
        let agg_result =
            SocketQueries::aggregate_into_flows(&sock_stream, &sock_cache, &mut flow_cache);

        let expected_bytes_min: u64 =
            ((AGG_FLOWS_MAX_ENTRIES - 1) * (AGG_FLOWS_MAX_ENTRIES / 2)).into();
        let actual_bytes: u64 = flow_cache
            .values()
            .map(|agg_flow| agg_flow.stats.bytes_received)
            .sum();
        assert_eq!(flow_cache.len(), AGG_FLOWS_MAX_ENTRIES as usize);
        assert!(actual_bytes >= expected_bytes_min);
        assert_eq!(
            agg_result,
            SockOperationResult {
                completed: AGG_FLOWS_MAX_ENTRIES as u64,
                partial: 0,
                failed: AGG_FLOWS_MAX_ENTRIES as u64,
            }
        );
    }

    #[test]
    fn test_sock_wrappers_missing_on_flow_agg() {
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        sock_stream.insert(11, AggSockStats::default());
        sock_stream.insert(22, AggSockStats::default());

        // Create an empty sock cache.
        let sock_cache = SockCache::new();

        let mut flow_cache = HashMap::new();
        let agg_result =
            SocketQueries::aggregate_into_flows(&sock_stream, &sock_cache, &mut flow_cache);
        assert_eq!(
            agg_result,
            SockOperationResult {
                completed: 0,
                partial: 0,
                failed: 2,
            }
        );
    }

    #[test]
    fn test_map_max_entries_low_mem() {
        let mem_total_bytes: u64 = 1;
        let (max_sk_props, max_sk_stats) = map_max_entries(mem_total_bytes);
        assert_eq!(max_sk_props, MAX_ENTRIES_SK_PROPS_LO);
        assert_eq!(max_sk_stats, MAX_ENTRIES_SK_STATS_LO);
    }

    #[test]
    fn test_map_max_entries_lowish_mem() {
        let mem_total_bytes: u64 = 400_000_000;
        let (max_sk_props, max_sk_stats) = map_max_entries(mem_total_bytes);
        assert_eq!(max_sk_props, MAX_ENTRIES_SK_PROPS_LO);
        assert_eq!(max_sk_stats, MAX_ENTRIES_SK_STATS_LO);
    }

    #[test]
    fn test_map_max_entries_medium_mem() {
        let mem_total_bytes: u64 = 1_000_000_000;
        let (max_sk_props, max_sk_stats) = map_max_entries(mem_total_bytes);
        assert_eq!(max_sk_props, MAX_ENTRIES_SK_PROPS_LO);
        assert_eq!(max_sk_stats, MAX_ENTRIES_SK_STATS_LO);
    }

    #[test]
    fn test_map_max_entries_highish_mem() {
        let mem_total_bytes: u64 = 34_000_000_000;
        let (max_sk_props, max_sk_stats) = map_max_entries(mem_total_bytes);
        assert!(max_sk_props > MAX_ENTRIES_SK_PROPS_LO);
        assert!(max_sk_props < MAX_ENTRIES_SK_PROPS_HI);

        assert!(max_sk_stats > MAX_ENTRIES_SK_STATS_LO);
        assert!(max_sk_stats < MAX_ENTRIES_SK_STATS_HI);
    }

    #[test]
    fn test_map_max_entries_highest_mem() {
        let mem_total_bytes: u64 = u64::MAX;
        let (max_sk_props, max_sk_stats) = map_max_entries(mem_total_bytes);
        assert_eq!(max_sk_props, MAX_ENTRIES_SK_PROPS_HI);
        assert_eq!(max_sk_stats, MAX_ENTRIES_SK_STATS_HI);
    }

    #[test]
    fn test_flow_aggregation_with_nat() {
        let mut sock_stream: HashMap<SockKey, AggSockStats> = HashMap::new();
        let mut sock_cache = SockCache::with_max_entries(AGG_FLOWS_MAX_ENTRIES as usize);
        let mut flow_cache: HashMap<FlowProperties, AggregateResults> = HashMap::new();

        // Aggregate many sockets into one flow.
        let now_us: u64 = 2025;
        for i in 0..AGG_FLOWS_MAX_ENTRIES {
            let sock_key = i as SockKey;
            let sock_context = SockContext {
                address_family: AF_INET,
                remote_ipv4: Ipv4Addr::from_str("4.3.2.1").unwrap().to_bits(),
                ..Default::default()
            };
            sock_cache.add_context(sock_key, sock_context, now_us);
            sock_stream.insert(
                sock_key,
                AggSockStats {
                    stats: SockStats {
                        bytes_received: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            );
        }

        // Apply some NAT results.
        for (_key, sock_wrap) in sock_cache.iter_mut() {
            sock_wrap.context_external = Some(SockContext {
                local_ipv4: Ipv4Addr::from_str("10.6.7.8").unwrap().to_bits(),
                remote_ipv4: Ipv4Addr::from_str("44.33.22.11").unwrap().to_bits(),
                local_port: 22,
                remote_port: 2938,
                address_family: AF_INET,
                is_client: false,
                ..Default::default()
            });
        }

        // Do some aggregation.
        let agg_result =
            SocketQueries::aggregate_into_flows(&sock_stream, &sock_cache, &mut flow_cache);
        assert_eq!(
            agg_result,
            SockOperationResult {
                completed: AGG_FLOWS_MAX_ENTRIES.into(),
                partial: 0,
                failed: 0,
            }
        );

        // Confirm the flow represents the view beyond local NAT.
        assert_eq!(flow_cache.len(), 1);
        for flow in flow_cache.keys() {
            assert_eq!(
                *flow,
                FlowProperties {
                    protocol: InetProtocol::TCP,
                    local_address: IpAddr::from_str("10.6.7.8").unwrap(),
                    remote_address: IpAddr::from_str("44.33.22.11").unwrap(),
                    local_port: 22,
                    remote_port: 0,
                    kubernetes_metadata: None,
                }
            );
        }
    }

    #[test]
    fn test_calculate_ebpf_memory_usage_max() {
        // Will deliberately break at sock struct changes and provide a manual review step
        let result = calculate_ebpf_memory_usage(MAX_ENTRIES_SK_PROPS_HI, MAX_ENTRIES_SK_STATS_HI);
        assert_eq!(result, 6809);
    }
}
