// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    testbed::TestFabric,
    verifiers::{
        report_verifier::{ReportVerifier, ReportVerifierConfig},
        utils::tolerance::within_abs_percent_tolerance,
    },
};
use nfm_agent::metadata::k8s_metadata::K8sMetadata;
use nfm_agent::{
    events::{
        host_stats_provider::HostStats,
        network_event::{AggregateResults, FlowProperties, NetworkStats},
    },
    metadata::{
        eni::{KEY_INSTANCE_ID, KEY_INSTANCE_TYPE},
        env_metadata_provider::EnvMetadata,
        runtime_environment_metadata::{ComputePlatform, KEY_COMPUTE_PLATFORM},
        service_metadata::{build::PKG_VERSION, ServiceMetadata, PROJECT_NAME},
    },
    reports::{
        report::{NfmReport, ProcessStats, ReportValue, UsageStats, REPORT_VERSION},
        CountersOverall, ProcessCounters,
    },
};
use nfm_common::EventCounters;

macro_rules! check {
	($cond:expr, $print:stmt, $result:ident) => {
		if !($cond) {
			$print
			$result = false;
		}
	};
}

/// A generic report verifier that operates on report to report basis.
/// Inspects contents of each and verifies that the stats collected by the agent are conforming to what is expected.
/// Operates on report scope only, no inter-report interactions are checked.
pub struct GenericReportVerifier {
    config: ReportVerifierConfig,
}

impl GenericReportVerifier {
    pub fn new_with(config: ReportVerifierConfig) -> Self {
        GenericReportVerifier { config }
    }
}

impl ReportVerifier for GenericReportVerifier {
    fn verify(&self, report: &NfmReport) -> bool {
        if !self.verify_network_flow_stats(&report.network_stats) {
            return false; // return eagerly without checking rest
        }
        self.verify_env_metadata(&report.env_metadata)
            && self.verify_service_metadata(&report.service_metadata)
            && self.verify_process_stats(&report.process_stats)
            && self.verify_host_stats(&report.host_stats)
            && self.verify_k8s_metadata(&report.k8s_metadata)
            && report.failed_reports == 0
            && report.report_version == REPORT_VERSION
    }
}

impl GenericReportVerifier {
    fn verify_host_stats(&self, host_stats: &HostStats) -> bool {
        let result = match self.config.test_fabric {
            TestFabric::Plain => host_stats.interface_stats.len() == 0,
            TestFabric::EC2 => host_stats.interface_stats.len() > 0,
            TestFabric::K8s => host_stats.interface_stats.len() > 0,
        };
        if !result {
            println!(
                "WARN: expected fabric {:?}, got interfaces {:?}",
                self.config.test_fabric, host_stats.interface_stats
            );
        }
        result
    }

    fn verify_k8s_metadata(&self, k8s_metadata: &K8sMetadata) -> bool {
        let result = match self.config.test_fabric {
            TestFabric::Plain => {
                k8s_metadata.cluster_name == None && k8s_metadata.node_name == None
            }
            TestFabric::EC2 => k8s_metadata.cluster_name == None && k8s_metadata.node_name == None,
            TestFabric::K8s => k8s_metadata.node_name != None,
        };
        if !result {
            println!(
                "WARN: k8s env mismatch for fabric {:?}, got cluster={:?} node={:?}",
                self.config.test_fabric, k8s_metadata.cluster_name, k8s_metadata.node_name
            );
        }
        result
    }

    fn verify_service_metadata(&self, service_metadata: &ServiceMetadata) -> bool {
        service_metadata.name == ReportValue::String(PROJECT_NAME.to_string())
            && service_metadata.version == ReportValue::String(PKG_VERSION.to_string())
    }

    fn verify_env_metadata(&self, env_metadata: &EnvMetadata) -> bool {
        let observed_compute_platform = env_metadata.get(KEY_COMPUTE_PLATFORM).unwrap();

        env_metadata.contains_key(KEY_INSTANCE_ID)
            && env_metadata.contains_key(KEY_INSTANCE_TYPE)
            && match self.config.test_fabric {
                TestFabric::Plain => {
                    observed_compute_platform
                        == &ReportValue::String(ComputePlatform::Ec2Plain.to_string())
                } // we default to Ec2Plain for non-aws
                TestFabric::EC2 => {
                    observed_compute_platform
                        == &ReportValue::String(ComputePlatform::Ec2Plain.to_string())
                }
                TestFabric::K8s => {
                    observed_compute_platform
                        == &ReportValue::String(ComputePlatform::Ec2K8sVanilla.to_string())
                        || observed_compute_platform
                            == &ReportValue::String(ComputePlatform::Ec2K8sEks.to_string())
                }
            }
    }

    fn verify_process_stats(&self, process_stats: &ProcessStats) -> bool {
        self.verify_usage_stats(&process_stats.usage[0])
            && self.verify_counters(&process_stats.counters)
    }

    fn verify_usage_stats(&self, usage_stats: &UsageStats) -> bool {
        let mut result = true;
        check!(
            usage_stats.cpu_util > 0.0 && usage_stats.cpu_util < 20.0,
            println!(
                "WARN: cpu_util {} not in range (0.0, 20.0)",
                usage_stats.cpu_util
            ),
            result
        );
        check!(
            usage_stats.mem_used_kb > 0 && usage_stats.mem_used_kb < 50_000,
            println!(
                "WARN: mem_used_kb {} not in range (0, 50000)",
                usage_stats.mem_used_kb
            ),
            result
        );
        check!(
            usage_stats.mem_used_ratio > 0.0 && usage_stats.mem_used_ratio < 10.0,
            println!(
                "WARN: mem_used_ratio {} not in range (0.0, 10.0)",
                usage_stats.mem_used_ratio
            ),
            result
        );
        check!(
            usage_stats.ebpf_allocated_mem_kb > 0 && usage_stats.ebpf_allocated_mem_kb < 20_000,
            println!(
                "WARN: ebpf_allocated_mem_kb {} not in range (0, 20000)",
                usage_stats.ebpf_allocated_mem_kb
            ),
            result
        );
        check!(
            usage_stats.sockets_tracked > 0 as u64,
            println!(
                "WARN: sockets_tracked {} must be > 0",
                usage_stats.sockets_tracked
            ),
            result
        );
        result
    }

    fn verify_counters(&self, counters_overall: &CountersOverall) -> bool {
        self.verify_event_counters(&counters_overall.event_related)
            && self.verify_process_counters(&counters_overall.process_related)
    }

    fn verify_event_counters(&self, event_counters: &EventCounters) -> bool {
        let mut result = true;
        check!(
            event_counters.active_connect_events >= self.config.expected_connection_count,
            println!(
                "WARN: active_connect_events {} should be >= {}",
                event_counters.active_connect_events, self.config.expected_connection_count
            ),
            result
        );
        check!(
            event_counters.active_established_events >= self.config.expected_connection_count,
            println!(
                "WARN: active_established_events {} should be >= {}",
                event_counters.active_established_events, self.config.expected_connection_count
            ),
            result
        );
        check!(
            event_counters.rtt_events >= self.config.expected_connection_count,
            println!(
                "WARN: rtt_events {} should be >= {}",
                event_counters.rtt_events, self.config.expected_connection_count
            ),
            result
        );
        check!(
            event_counters.state_change_events >= self.config.expected_connection_count,
            println!(
                "WARN: state_change_events {} should be >= {}",
                event_counters.state_change_events, self.config.expected_connection_count
            ),
            result
        );
        check!(
            event_counters.passive_established_events >= self.config.expected_connection_count,
            println!(
                "WARN: passive_established_events {} should be >= {}",
                event_counters.passive_established_events, self.config.expected_connection_count
            ),
            result
        );
        check!(
            event_counters.socket_events > 0,
            println!(
                "WARN: socket_events {} should be > 0",
                event_counters.socket_events
            ),
            result
        );
        check!(
            event_counters.map_insertion_errors == 0,
            println!(
                "WARN: map_insertion_errors {} should be 0",
                event_counters.map_insertion_errors
            ),
            result
        );
        check!(
            event_counters.other_errors == 0,
            println!(
                "WARN: other_errors {} should be 0",
                event_counters.other_errors
            ),
            result
        );
        check!(
            event_counters.set_flags_errors == 0,
            println!(
                "WARN: set_flags_errors {} should be 0",
                event_counters.set_flags_errors
            ),
            result
        );
        check!(
            event_counters.sockets_invalid == 0,
            println!(
                "WARN: sockets_invalid {} should be 0",
                event_counters.sockets_invalid
            ),
            result
        );
        result
    }

    fn verify_process_counters(&self, process_counters: &ProcessCounters) -> bool {
        let mut result = true;
        check!(
            process_counters.sockets_added >= self.config.expected_connection_count as u64,
            println!(
                "WARN: sockets_added {} should be >= {}",
                process_counters.sockets_added, self.config.expected_connection_count
            ),
            result
        );
        check!(
            process_counters.remote_nat_reversal_errors == 0,
            println!(
                "WARN: remote_nat_reversal_errors {} should be 0",
                process_counters.remote_nat_reversal_errors
            ),
            result
        );
        check!(
            process_counters.restarts == 0,
            println!("WARN: restarts {} should be 0", process_counters.restarts),
            result
        );
        check!(
            process_counters.socket_agg_completed > 0,
            println!(
                "WARN: socket_agg_completed {} should be > 0",
                process_counters.socket_agg_completed
            ),
            result
        );
        check!(
            process_counters.socket_deltas_completed > 0,
            println!(
                "WARN: socket_deltas_completed {} should be > 0",
                process_counters.socket_deltas_completed
            ),
            result
        );
        check!(
            process_counters.socket_deltas_above_limit == 0,
            println!(
                "WARN: socket_deltas_above_limit {} should be 0",
                process_counters.socket_deltas_above_limit
            ),
            result
        );
        if self.config.test_fabric == TestFabric::K8s {
            check!(
                process_counters.sockets_natd > 0,
                println!(
                    "WARN: sockets_natd {} should be > 0 for K8s",
                    process_counters.sockets_natd
                ),
                result
            );
        } else {
            check!(
                process_counters.sockets_natd == 0,
                println!(
                    "WARN: sockets_natd {} should be 0 for non-K8s",
                    process_counters.sockets_natd
                ),
                result
            );
        }
        check!(
            process_counters.socket_eviction_failed == 0,
            println!(
                "WARN: socket_eviction_failed {} should be 0",
                process_counters.socket_eviction_failed
            ),
            result
        );
        result
    }

    fn verify_network_flow_stats(&self, aggregate_results: &Vec<AggregateResults>) -> bool {
        let mut local_verified = false;
        let mut remote_verified = false;
        for network_stat in aggregate_results {
            let flow = &network_stat.flow;
            let stats = &network_stat.stats;

            // verify stats for local/client initiated connection
            if flow.local_address == self.config.local_ip_port_under_test.ip_address
                && flow.remote_address == self.config.remote_ip_port_under_test.ip_address
                && flow.remote_port == self.config.remote_ip_port_under_test.port
            {
                if !local_verified {
                    local_verified = self.verify_local_client_flow_stats(&flow, &stats);
                }
            }

            // verify stats for remote/server side connection handling the local one
            if flow.local_address == self.config.local_ip_port_under_test.ip_address
                && flow.remote_address == self.config.remote_ip_port_under_test.ip_address
                && flow.local_port == self.config.local_ip_port_under_test.port
            {
                if !remote_verified {
                    remote_verified = self.verify_remote_server_flow_stats(&flow, &stats);
                }
            }
        }
        local_verified && remote_verified
    }

    /**
     * With a given loss percentage, return how many extra requests must be done
     * per 100 requests to make it across.
     * i.e. with 50% loss, extra 100 requests would have been made on average
     */
    fn get_tolerance(&self) -> f64 {
        // Since packet loss % is pure luck, it can easily go above the given value. So adding some leeway
        // Also, in a connection chain there are multiple packet exchanges that has to succeed, which makes the loss percent apply exponentially
        let packet_success_chance = (100 - self.config.expected_loss_percent) as f64 / 100.0; // <1.0, example: 0.9
        let successive_packets_required = 6.0; // 3 (syn/syn-ack/ack) + 3 for guard rail
        let connection_success_rate = packet_success_chance.powf(successive_packets_required);
        // Calculate extra requests needed: if success rate is 0.8, we need 1/0.8 = 1.25x requests, so 25% extra
        let extra_requests_multiplier = 1.0 / connection_success_rate;
        (extra_requests_multiplier - 1.0) * 100.0
    }

    fn within_tolerance(&self, observed: u64) -> bool {
        within_abs_percent_tolerance(
            observed,
            self.config.expected_connection_count as u64,
            self.get_tolerance(),
        )
    }

    fn verify_local_client_flow_stats(
        &self,
        flow: &FlowProperties,
        network_stats: &NetworkStats,
    ) -> bool {
        let mut result = true;
        // when theres loss, more than required attempts might be made, resulting in more rtt samples
        check!(
            self.within_tolerance(network_stats.segments_delivered),
            println!(
                "WARN: segments_delivered {} should have been {}±{}% for client flow {:?}",
                network_stats.segments_delivered,
                self.config.expected_connection_count,
                self.get_tolerance(),
                flow
            ),
            result
        );
        check!(
            self.within_tolerance(network_stats.connect_attempts as u64),
            println!(
                "WARN: connect_attempts {} should have been {}±{}% for client flow {:?}",
                network_stats.connect_attempts,
                self.config.expected_connection_count,
                self.get_tolerance(),
                flow
            ),
            result
        );
        check!(
            self.within_tolerance(network_stats.connect_us.count as u64),
            println!(
                "WARN: connect_us.count {} should have been {}±{}% for client flow {:?}",
                network_stats.connect_us.count,
                self.config.expected_connection_count,
                self.get_tolerance(),
                flow
            ),
            result
        );

        check!(
            network_stats.connect_us.min >= self.config.expected_minimum_latency,
            println!(
                "WARN: connect_us.min {} should have been >{} for client flow {:?}",
                network_stats.connect_us.min, self.config.expected_minimum_latency, flow
            ),
            result
        );
        check!(
            network_stats.connect_us.max >= self.config.expected_minimum_latency,
            println!(
                "WARN: connect_us.max {} should have been >{} for client flow {:?}",
                network_stats.connect_us.max, self.config.expected_minimum_latency, flow
            ),
            result
        );
        check!(
            network_stats.connect_us.sum >= self.config.expected_minimum_latency as u64,
            println!(
                "WARN: connect_us.sum {} should have been >{} for client flow {:?}",
                network_stats.connect_us.sum, self.config.expected_minimum_latency, flow
            ),
            result
        );

        result && self.verify_flow_stats_common(flow, network_stats, "client")
    }

    fn verify_remote_server_flow_stats(
        &self,
        flow: &FlowProperties,
        network_stats: &NetworkStats,
    ) -> bool {
        let mut result = true;
        check!(
            self.within_tolerance(network_stats.segments_received),
            println!(
                "WARN: segments_received {} should have been {}±{}% for server flow {:?}",
                network_stats.segments_received,
                self.config.expected_connection_count,
                self.get_tolerance(),
                flow
            ),
            result
        );
        check!(
            network_stats.connect_attempts == 0,
            println!(
                "WARN: connect_attempts {} should have been 0 for server flow {:?}",
                network_stats.connect_attempts, flow
            ),
            result
        );
        check!(
            network_stats.connect_us.count == 0,
            println!(
                "WARN: connect_us.count {} should have been 0 for server flow {:?}",
                network_stats.connect_us.count, flow
            ),
            result
        );
        check!(
            network_stats.connect_us.min == 0,
            println!(
                "WARN: connect_us.min {} should have been 0 for server flow {:?}",
                network_stats.connect_us.min, flow
            ),
            result
        );
        check!(
            network_stats.connect_us.max == 0,
            println!(
                "WARN: connect_us.max {} should have been 0 for server flow {:?}",
                network_stats.connect_us.max, flow
            ),
            result
        );
        check!(
            network_stats.connect_us.sum == 0,
            println!(
                "WARN: connect_us.sum {} should have been 0 for server flow {:?}",
                network_stats.connect_us.sum, flow
            ),
            result
        );

        result && self.verify_flow_stats_common(flow, network_stats, "server")
    }

    fn verify_flow_stats_common(
        &self,
        flow: &FlowProperties,
        network_stats: &NetworkStats,
        flow_type: &str,
    ) -> bool {
        let mut result = true;
        check!(
            self.within_tolerance(network_stats.rtt_smoothed_us.count as u64),
            println!(
                "WARN: rtt_smoothed_us.count {} should have been {}±{}% for {} flow {:?}",
                network_stats.rtt_smoothed_us.count,
                self.config.expected_connection_count,
                self.get_tolerance(),
                flow_type,
                flow
            ),
            result
        );
        check!(
            self.within_tolerance(network_stats.rtt_us.count as u64),
            println!(
                "WARN: rtt_us.count {} should have been {}±{}% for {} flow {:?}",
                network_stats.rtt_us.count,
                self.config.expected_connection_count,
                self.get_tolerance(),
                flow_type,
                flow
            ),
            result
        );
        check!(
            network_stats.bytes_delivered > 0,
            println!(
                "WARN: bytes_delivered {} should have been >0 for {} flow {:?}",
                network_stats.bytes_delivered, flow_type, flow
            ),
            result
        );
        check!(
            network_stats.bytes_received > 0,
            println!(
                "WARN: bytes_received {} should have been >0 for {} flow {:?}",
                network_stats.bytes_delivered, flow_type, flow
            ),
            result
        );
        check!(
            network_stats.rtt_smoothed_us.min >= self.config.expected_minimum_latency,
            println!(
                "WARN: rtt_smoothed_us.min {} should have been >{} for {} flow {:?}",
                network_stats.rtt_smoothed_us.min,
                self.config.expected_minimum_latency,
                flow_type,
                flow
            ),
            result
        );
        check!(
            network_stats.rtt_smoothed_us.max >= self.config.expected_minimum_latency,
            println!(
                "WARN: rtt_smoothed_us.max {} should have been >{} for {} flow {:?}",
                network_stats.rtt_smoothed_us.max,
                self.config.expected_minimum_latency,
                flow_type,
                flow
            ),
            result
        );
        check!(
            network_stats.rtt_smoothed_us.sum >= self.config.expected_minimum_latency as u64,
            println!(
                "WARN: rtt_smoothed_us.sum {} should have been >{} for {} flow {:?}",
                network_stats.rtt_smoothed_us.sum,
                self.config.expected_minimum_latency,
                flow_type,
                flow
            ),
            result
        );
        check!(
            network_stats.rtt_us.min >= self.config.expected_minimum_latency,
            println!(
                "WARN: rtt_us.min {} should have been >{} for {} flow {:?}",
                network_stats.rtt_us.min, self.config.expected_minimum_latency, flow_type, flow
            ),
            result
        );
        check!(
            network_stats.rtt_us.max >= self.config.expected_minimum_latency,
            println!(
                "WARN: rtt_us.max {} should have been >{} for {} flow {:?}",
                network_stats.rtt_us.max, self.config.expected_minimum_latency, flow_type, flow
            ),
            result
        );
        check!(
            network_stats.rtt_us.sum >= self.config.expected_minimum_latency as u64,
            println!(
                "WARN: rtt_us.sum {} should have been >{} for {} flow {:?}",
                network_stats.rtt_us.sum, self.config.expected_minimum_latency, flow_type, flow
            ),
            result
        );
        check!(
            self.within_tolerance(network_stats.sockets_completed as u64),
            println!(
                "WARN: sockets_completed {} should have been {} for {} flow {:?}",
                network_stats.sockets_completed,
                self.config.expected_connection_count,
                flow_type,
                flow
            ),
            result
        );
        result
    }
}
