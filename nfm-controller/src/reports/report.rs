// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::metadata::k8s_metadata::K8sMetadata;
use crate::metadata::service_metadata::ServiceMetadata;
use crate::utils::report::to_value_pairs;
use crate::HostStats;
use crate::{
    events::network_event::AggregateResults, metadata::env_metadata_provider::EnvMetadata,
};
use nfm_common::network::EventCounters;

use serde::{Deserialize, Serialize};
use serde_json;

const REPORT_VERSION: &str = "1.1";

#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(test, derive(Clone))]
pub struct NfmReport {
    pub network_stats: Vec<AggregateResults>,
    pub process_stats: ProcessStats,
    pub host_stats: HostStats,
    pub env_metadata: EnvMetadata,
    pub service_metadata: ServiceMetadata,
    pub failed_reports: u32,
    pub report_version: String,
    pub k8s_metadata: K8sMetadata,
}

impl NfmReport {
    pub fn new() -> Self {
        Self {
            network_stats: vec![],
            process_stats: ProcessStats::default(),
            host_stats: HostStats::default(),
            env_metadata: EnvMetadata::default(),
            service_metadata: ServiceMetadata::default(),
            failed_reports: 0,
            report_version: REPORT_VERSION.into(),
            k8s_metadata: K8sMetadata::default(),
        }
    }

    pub fn set_network_stats(&mut self, agg_stats: Vec<AggregateResults>) {
        self.network_stats = agg_stats;
    }

    pub fn set_process_stats(&mut self, stats: ProcessStats) {
        self.process_stats = stats;
    }

    pub fn set_host_stats(&mut self, stats: HostStats) {
        self.host_stats = stats;
    }

    pub fn set_env_metadata(&mut self, metadata: EnvMetadata) {
        self.env_metadata = metadata;
    }

    pub fn set_failed_reports(&mut self, failed_reports: u32) {
        self.failed_reports = failed_reports;
    }

    pub fn set_service_metadata(&mut self, service_metadata: ServiceMetadata) {
        self.service_metadata = service_metadata;
    }

    pub fn set_k8s_metadata(&mut self, k8s_metadata: K8sMetadata) {
        self.k8s_metadata = k8s_metadata;
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, PartialOrd, Serialize)]
pub struct MetricHistogram {
    pub count: u32,
    pub min: u32,
    pub max: u32,
    pub sum: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ReportValue {
    Float(f64),
    UInt(u64),
    Int(i64),
    String(String),
    Histogram(MetricHistogram),
    Invalid,
}

impl From<&serde_json::Value> for ReportValue {
    fn from(json_val: &serde_json::Value) -> Self {
        match json_val {
            serde_json::Value::Number(num) => {
                if num.is_f64() {
                    ReportValue::Float(num.as_f64().unwrap())
                } else if num.is_i64() {
                    ReportValue::Int(num.as_i64().unwrap())
                } else if num.is_u64() {
                    ReportValue::UInt(num.as_u64().unwrap())
                } else {
                    ReportValue::Invalid
                }
            }
            serde_json::Value::String(s) => ReportValue::String(s.clone()),
            _ => ReportValue::Invalid,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct ProcessStats {
    pub counters: CountersOverall,
    pub usage: Vec<UsageStats>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct CountersOverall {
    pub event_related: EventCounters,
    pub process_related: ProcessCounters,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct ProcessCounters {
    pub restarts: u64,
    pub sockets_added: u64,
    pub sockets_natd: u64,
    pub sockets_stale: u64,

    pub socket_deltas_completed: u64,
    pub socket_deltas_missing_props: u64,
    pub socket_deltas_above_limit: u64,

    pub socket_agg_completed: u64,
    pub socket_agg_missing_props: u64,
    pub socket_agg_above_limit: u64,

    pub socket_eviction_completed: u64,
    pub socket_eviction_failed: u64,
    pub remote_nat_reversal_errors: u64,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct UsageStats {
    pub cpu_util: f64,
    pub mem_used_kb: u64,
    pub mem_used_ratio: f64,
    pub sockets_tracked: u64,
}

impl ProcessStats {
    pub fn enumerate_usage(&self) -> Vec<(String, ReportValue)> {
        match self.usage.last() {
            Some(usg) => to_value_pairs(usg),
            None => vec![],
        }
    }

    pub fn enumerate_counters(&self) -> Vec<(String, ReportValue)> {
        let mut res = vec![];
        res.extend(to_value_pairs(&self.counters.event_related));
        res.extend(to_value_pairs(&self.counters.process_related));
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::events::host_stats_provider::{GroupedInterfaceStats, NetworkInterfaceStats};
    use crate::events::network_event::{AggregateResults, FlowProperties, NetworkStats};
    use crate::metadata::env_metadata_provider::EnvMetadata;
    use crate::metadata::service_metadata::ServiceMetadata;
    use crate::reports::report::{
        MetricHistogram, NfmReport, ProcessStats, ReportValue, UsageStats,
    };
    use crate::HostStats;
    use nfm_common::network::{SockContext, AF_INET};

    use std::fs;

    #[test]
    fn test_build_report() {
        let mut report = NfmReport::new();

        let mut context = SockContext {
            is_client: false,
            address_family: AF_INET,
            local_ipv4: 16909060,
            remote_ipv4: 84281096,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 443,
            remote_port: 28015,
            ..Default::default()
        };
        let stats = NetworkStats {
            sockets_connecting: 4,
            sockets_established: 3,
            sockets_closing: 2,
            sockets_closed: 1,

            sockets_completed: 44,
            severed_connect: 2,
            severed_establish: 1,

            connect_attempts: 14,
            bytes_received: 43,
            bytes_delivered: 47,
            segments_received: 53,
            segments_delivered: 59,

            retrans_syn: 20,
            retrans_est: 19,
            retrans_close: 18,
            rtos_syn: 17,
            rtos_est: 16,
            rtos_close: 15,

            connect_us: MetricHistogram {
                count: 2,
                min: 12,
                max: 13,
                sum: 25,
            },
            rtt_us: MetricHistogram {
                count: 3,
                min: 14,
                max: 15,
                sum: 44,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 4,
                min: 16,
                max: 17,
                sum: 66,
            },
        };
        let mut process_stats = ProcessStats::default();
        process_stats.usage.push(UsageStats {
            cpu_util: 0.040,
            mem_used_kb: 512,
            mem_used_ratio: 0.06,
            sockets_tracked: 49,
        });
        let grouped_iface_stats = GroupedInterfaceStats {
            interface_id: "iface-id-1".to_string(),
            stats: NetworkInterfaceStats {
                bw_in_allowance_exceeded: 211,
                bw_out_allowance_exceeded: 223,
                conntrack_allowance_exceeded: 227,
                linklocal_allowance_exceeded: 229,
                pps_allowance_exceeded: 233,
                conntrack_allowance_available: 239,
            },
        };
        let host_stats = HostStats {
            interface_stats: vec![grouped_iface_stats],
        };

        // From the perspective of a server, the local port is the service port.
        context.is_client = false;
        let mut flow = FlowProperties::try_from(&context).unwrap();
        let mut agg_results = AggregateResults {
            flow,
            stats: stats.clone(),
        };
        let mut env_metadata = EnvMetadata::default();
        env_metadata.insert(
            "instance_id".into(),
            ReportValue::String("instance-id".into()),
        );
        report.set_network_stats(vec![agg_results]);
        report.set_process_stats(process_stats);
        report.set_host_stats(host_stats);
        report.set_env_metadata(env_metadata);
        report.set_service_metadata(ServiceMetadata::new("test-service", "1.0", "build-time"));

        let expected: NfmReport =
            serde_json::from_str(&fs::read_to_string("../test-data/report1.json").unwrap())
                .unwrap();
        assert_eq!(report, expected);

        // From the perspective of a client, the remote port is the service port.
        context.is_client = true;
        flow = FlowProperties::try_from(&context).unwrap();
        agg_results = AggregateResults { flow, stats };
        report.set_network_stats(vec![agg_results]);

        let expected: NfmReport =
            serde_json::from_str(&fs::read_to_string("../test-data/report2.json").unwrap())
                .unwrap();
        assert_eq!(report, expected);
    }
}
