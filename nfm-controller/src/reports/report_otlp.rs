// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::reports::report::NfmReport;

use log::error;
use opentelemetry_proto::tonic::{
    collector::metrics::v1::ExportMetricsServiceRequest,
    common::v1::{any_value::Value, AnyValue, InstrumentationScope, KeyValue},
    metrics::v1::{metric::Data, Metric, ResourceMetrics, ScopeMetrics},
    metrics::v1::{
        number_data_point, AggregationTemporality, Gauge, Histogram, HistogramDataPoint,
        NumberDataPoint, Sum,
    },
    resource::v1::Resource,
};
use prost::Message;

use super::report::ReportValue;

const SCOPE_NAME_NETWORK_STAT: &str = "network_stats";
const SCOPE_NAME_HOST_STAT: &str = "host_stats";
const SCOPE_NAME_PROCESS_STAT: &str = "process_stats";
const SCOPE_NAME_COUNTERS: &str = "counters";

const METADATA_SERVICE_NAME: &str = "service.name";
const METADATA_SERVICE_VERSION: &str = "service.version";
const METADATA_AGENT_BUILD_TIME: &str = "agent.build_ts";

const METADATA_K8S_NODE_NAME: &str = "k8s_node_name";
const METADATA_K8S_EKS_CLUSTER_NAME: &str = "k8s_eks_cluster_name";

pub struct NfmReportOTLP {}

impl From<ReportValue> for Value {
    fn from(report_val: ReportValue) -> Self {
        match report_val {
            ReportValue::Float(f) => Value::DoubleValue(f),
            ReportValue::UInt(u) => Value::IntValue(u.try_into().unwrap_or(0)),
            ReportValue::Int(i) => Value::IntValue(i),
            ReportValue::String(s) => Value::StringValue(s),
            ReportValue::Invalid => Value::StringValue("".to_string()),
            ReportValue::Histogram(_) => panic!("Invalid conversion: Histogram to Otel Value"),
        }
    }
}

fn build_metric_histogram(
    name: String,
    timestamp_ns: u64,
    value: ReportValue,
) -> Result<Metric, String> {
    let mut data_point = HistogramDataPoint {
        time_unix_nano: timestamp_ns,
        start_time_unix_nano: timestamp_ns,
        count: 1,
        ..Default::default()
    };

    match value {
        ReportValue::Float(value) => {
            data_point.sum = Some(value);
        }
        ReportValue::Int(value) => {
            data_point.sum = Some(value as f64);
        }
        ReportValue::UInt(value) => {
            data_point.sum = Some(value as f64);
        }
        ReportValue::Histogram(histo) => {
            data_point.count = histo.count.into();
            data_point.min = Some(histo.min.into());
            data_point.max = Some(histo.max.into());
            data_point.sum = Some(histo.sum as f64);
        }
        _ => {
            return Err(format!("Unsupported value type {:?}", value).to_string());
        }
    }

    let data = Data::Histogram(Histogram {
        data_points: vec![data_point],
        aggregation_temporality: AggregationTemporality::Delta.into(),
    });
    Ok(Metric {
        name: name.to_string(),
        data: Some(data),
        ..Default::default()
    })
}

fn build_metric_gauge(
    name: String,
    timestamp_ns: u64,
    value: ReportValue,
) -> Result<Metric, String> {
    let mut data_point = NumberDataPoint {
        time_unix_nano: timestamp_ns,
        start_time_unix_nano: timestamp_ns,
        ..Default::default()
    };

    match value {
        ReportValue::Float(value) => {
            data_point.value = Some(number_data_point::Value::AsDouble(value));
        }
        ReportValue::Int(value) => {
            data_point.value = Some(number_data_point::Value::AsInt(value));
        }
        ReportValue::UInt(value) => {
            data_point.value = Some(number_data_point::Value::AsInt(value as i64));
        }
        _ => {
            return Err(format!("Unsupported value type {:?}", value).to_string());
        }
    }

    let data = Data::Gauge(Gauge {
        data_points: vec![data_point],
    });
    Ok(Metric {
        name: name.to_string(),
        data: Some(data),
        ..Default::default()
    })
}

fn build_metric_sum(name: String, timestamp_ns: u64, value: ReportValue) -> Result<Metric, String> {
    let mut data_point = NumberDataPoint {
        time_unix_nano: timestamp_ns,
        start_time_unix_nano: timestamp_ns,
        ..Default::default()
    };

    match value {
        ReportValue::Float(value) => {
            data_point.value = Some(number_data_point::Value::AsDouble(value));
        }
        ReportValue::Int(value) => {
            data_point.value = Some(number_data_point::Value::AsInt(value));
        }
        ReportValue::UInt(value) => {
            data_point.value = Some(number_data_point::Value::AsInt(value as i64));
        }
        _ => {
            return Err(format!("Unsupported value type {:?}", value).to_string());
        }
    }

    let data = Data::Sum(Sum {
        data_points: vec![data_point],
        aggregation_temporality: AggregationTemporality::Delta.into(),
        is_monotonic: true,
    });
    Ok(Metric {
        name: name.to_string(),
        data: Some(data),
        ..Default::default()
    })
}

impl NfmReportOTLP {
    fn add_network_stats(
        report: &NfmReport,
        timestamp_ns: u64,
        resource_metrics: &mut ResourceMetrics,
    ) {
        for network_stat in &report.network_stats {
            let mut scope_metrics = ScopeMetrics::default();

            let mut scope = InstrumentationScope {
                name: SCOPE_NAME_NETWORK_STAT.to_string(),
                ..Default::default()
            };

            // Flow information will be in the scope
            for (name, value) in network_stat.flow.enumerate() {
                scope.attributes.push(KeyValue {
                    key: name.to_string(),
                    value: Some(AnyValue {
                        value: Some(value.into()),
                    }),
                });
            }

            // List of metrics for the flow
            scope_metrics.scope = Some(scope);
            for (name, value) in network_stat.stats.enumerate() {
                match build_metric_histogram(name, timestamp_ns, value) {
                    Ok(metric) => scope_metrics.metrics.push(metric),
                    Err(e) => error!(msg = e; "Error building metric"),
                }
            }

            resource_metrics.scope_metrics.push(scope_metrics);
        }
    }

    fn add_host_stats(
        report: &NfmReport,
        timestamp_ns: u64,
        resource_metrics: &mut ResourceMetrics,
    ) {
        for grouped_stats in &report.host_stats.interface_stats {
            let mut scope_metrics = ScopeMetrics::default();
            let mut scope = InstrumentationScope {
                name: SCOPE_NAME_HOST_STAT.to_string(),
                ..Default::default()
            };

            // The scope will contain the interface ID.
            scope.attributes.push(KeyValue {
                key: "interface_id".to_string(),
                value: Some(AnyValue {
                    value: Some(Value::StringValue(grouped_stats.interface_id.clone())),
                }),
            });

            // List of metrics for the flow
            scope_metrics.scope = Some(scope);
            for (name, value) in grouped_stats.stats.enumerate() {
                match build_metric_sum(name, timestamp_ns, value) {
                    Ok(metric) => scope_metrics.metrics.push(metric),
                    Err(e) => error!(msg = e; "Error building metric"),
                }
            }

            resource_metrics.scope_metrics.push(scope_metrics);
        }
    }

    fn add_process_stats(
        report: &NfmReport,
        timestamp_ns: u64,
        resource_metrics: &mut ResourceMetrics,
    ) {
        let mut scope_metrics = ScopeMetrics::default();

        let scope = InstrumentationScope {
            name: SCOPE_NAME_PROCESS_STAT.to_string(),
            ..Default::default()
        };
        scope_metrics.scope = Some(scope);

        for (name, value) in report.process_stats.enumerate_usage() {
            match build_metric_gauge(name, timestamp_ns, value) {
                Ok(metric) => scope_metrics.metrics.push(metric),
                Err(e) => error!(msg = e; "Error building metric"),
            }
        }

        resource_metrics.scope_metrics.push(scope_metrics);
    }

    fn add_counters(report: &NfmReport, timestamp_ns: u64, resource_metrics: &mut ResourceMetrics) {
        let mut scope_metrics = ScopeMetrics::default();

        let scope = InstrumentationScope {
            name: SCOPE_NAME_COUNTERS.to_string(),
            ..Default::default()
        };
        scope_metrics.scope = Some(scope);

        for (name, value) in report.process_stats.enumerate_counters() {
            match build_metric_sum(name, timestamp_ns, value) {
                Ok(metric) => scope_metrics.metrics.push(metric),
                Err(e) => error!(msg = e; "Error building metric"),
            }
        }

        match build_metric_sum(
            "publish_report_failed".to_owned(),
            timestamp_ns,
            ReportValue::UInt(report.failed_reports.into()),
        ) {
            Ok(metric) => scope_metrics.metrics.push(metric),
            Err(e) => error!(msg = e; "Error building metric"),
        }

        resource_metrics.scope_metrics.push(scope_metrics);
    }

    fn add_resource_data(report: &NfmReport, resource_metrics: &mut ResourceMetrics) {
        let mut resource = Resource::default();

        // Env data
        for (key, value) in report.env_metadata.enumerate() {
            NfmReportOTLP::add_resource_entry(key, value, &mut resource);
        }

        // Service data. See: https://opentelemetry.io/docs/specs/semconv/resource/
        NfmReportOTLP::add_resource_entry(
            METADATA_SERVICE_NAME,
            &report.service_metadata.name,
            &mut resource,
        );
        NfmReportOTLP::add_resource_entry(
            METADATA_SERVICE_VERSION,
            &report.service_metadata.version,
            &mut resource,
        );
        // Agent data
        NfmReportOTLP::add_resource_entry(
            METADATA_AGENT_BUILD_TIME,
            &report.service_metadata.build_ts,
            &mut resource,
        );
        NfmReportOTLP::add_resource_entry(
            "report.version",
            &ReportValue::String(report.report_version.clone()),
            &mut resource,
        );

        // Kubernetes metadata
        if let Some(node_name) = &report.k8s_metadata.node_name {
            NfmReportOTLP::add_resource_entry(METADATA_K8S_NODE_NAME, node_name, &mut resource);
        }
        if let Some(cluster_name) = &report.k8s_metadata.cluster_name {
            NfmReportOTLP::add_resource_entry(
                METADATA_K8S_EKS_CLUSTER_NAME,
                cluster_name,
                &mut resource,
            );
        }

        resource_metrics.resource = Some(resource);
    }

    fn add_resource_entry(key: &str, value: &ReportValue, resource: &mut Resource) {
        resource.attributes.push(KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(value.clone().into()),
            }),
        });
    }

    fn build_export(report: &NfmReport, timestamp_ns: u64) -> ExportMetricsServiceRequest {
        let mut resource_metrics = ResourceMetrics::default();
        NfmReportOTLP::add_resource_data(report, &mut resource_metrics);
        NfmReportOTLP::add_network_stats(report, timestamp_ns, &mut resource_metrics);
        NfmReportOTLP::add_process_stats(report, timestamp_ns, &mut resource_metrics);
        NfmReportOTLP::add_host_stats(report, timestamp_ns, &mut resource_metrics);
        NfmReportOTLP::add_counters(report, timestamp_ns, &mut resource_metrics);

        ExportMetricsServiceRequest {
            resource_metrics: vec![resource_metrics],
        }
    }

    pub fn build(report: &NfmReport, timestamp_us: u64) -> Result<Vec<u8>, String> {
        let export = &NfmReportOTLP::build_export(report, timestamp_us);
        let mut buf = Vec::with_capacity(export.encoded_len());

        match export.encode(&mut buf) {
            Ok(_) => Ok(buf),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::events::host_stats_provider::{GroupedInterfaceStats, NetworkInterfaceStats};
    use crate::events::network_event::{AggregateResults, FlowProperties, NetworkStats};
    use crate::kubernetes::flow_metadata::FlowMetadata;
    use crate::kubernetes::kubernetes_metadata_collector::PodInfo;
    use crate::metadata::env_metadata_provider::{EnvMetadata, EnvMetadataProvider};
    use crate::metadata::k8s_metadata::K8sMetadata;
    use crate::metadata::runtime_environment_metadata::{
        ComputePlatform, RuntimeEnvironmentMetadataProvider,
    };
    use crate::metadata::service_metadata::ServiceMetadata;
    use crate::reports::report::{
        MetricHistogram, NfmReport, ProcessCounters, ProcessStats, UsageStats,
    };
    use crate::HostStats;
    use nfm_common::network::{EventCounters, SockContext, AF_INET};

    #[test]
    fn test_build_report_from_ec2_instance() {
        build_and_save_report(ComputePlatform::Ec2Plain);
    }

    #[test]
    fn test_build_report_from_k8s_vanilla_pod() {
        build_and_save_report(ComputePlatform::Ec2K8sVanilla);
    }

    #[test]
    fn test_build_report_from_k8s_eks_pod() {
        build_and_save_report(ComputePlatform::Ec2K8sEks);
    }

    fn build_and_save_report(compute_platform: ComputePlatform) {
        let context = SockContext {
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
        process_stats.counters.event_related = EventCounters {
            active_connect_events: 1,
            active_established_events: 2,
            passive_established_events: 3,
            state_change_events: 4,
            rtt_events: 5,
            retrans_events: 6,
            rto_events: 7,
            other_events: 8,
            socket_events: 9,
            sockets_invalid: 10,
            map_insertion_errors: 18,
            rtts_invalid: 15,
            set_flags_errors: 16,
            other_errors: 17,
        };
        process_stats.counters.process_related = ProcessCounters::default();

        process_stats.usage.push(UsageStats {
            cpu_util: 0.040,
            mem_used_kb: 512,
            mem_used_ratio: 0.06,
            sockets_tracked: 100,
        });

        let iface1_stats = GroupedInterfaceStats {
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
        let mut iface2_stats = iface1_stats.clone();
        iface2_stats.interface_id = "iface-id-2".to_string();
        let host_stats = HostStats {
            interface_stats: vec![iface1_stats, iface2_stats],
        };

        let mut flow = FlowProperties::try_from(&context).unwrap();
        if compute_platform != ComputePlatform::Ec2Plain {
            flow.kubernetes_metadata = Some(FlowMetadata {
                local: Some(PodInfo {
                    name: "local-pod".to_string(),
                    namespace: "local-namespace".to_string(),
                    service_name: "local-service".to_string(),
                }),
                remote: Some(PodInfo {
                    name: "remote-pod".to_string(),
                    namespace: "remote-namespace".to_string(),
                    service_name: "remote-service".to_string(),
                }),
            });
        }
        let agg_results = AggregateResults { flow, stats };
        let mut env_metadata = EnvMetadata::default();
        env_metadata.insert(
            "instance_id".into(),
            ReportValue::String("instance-id".into()),
        );
        env_metadata.insert(
            "machine_id".into(),
            ReportValue::String("machine-id".into()),
        );
        env_metadata.extend(
            RuntimeEnvironmentMetadataProvider::from(compute_platform.clone()).get_metadata(),
        );

        let mut report = NfmReport::new();
        report.set_network_stats(vec![agg_results]);
        report.set_process_stats(process_stats);
        report.set_env_metadata(env_metadata);
        report.set_host_stats(host_stats);
        report.set_failed_reports(10);
        report.set_service_metadata(ServiceMetadata::new("agent-service", "0.1.0", "build-time"));

        match compute_platform {
            ComputePlatform::Ec2K8sEks => {
                report.set_k8s_metadata(K8sMetadata {
                    node_name: Some(ReportValue::String("k8s-node".into())),
                    cluster_name: Some(ReportValue::String("k8s-cluster".into())),
                });
            }
            ComputePlatform::Ec2K8sVanilla => {
                report.set_k8s_metadata(K8sMetadata {
                    node_name: Some(ReportValue::String("k8s-node".into())),
                    cluster_name: None,
                });
            }
            ComputePlatform::Ec2Plain => {
                report.set_k8s_metadata(K8sMetadata {
                    node_name: None,
                    cluster_name: None,
                });
            }
        }

        let timestamp_us = 1718716821050000;
        let built_report = NfmReportOTLP::build(&report, timestamp_us).unwrap();

        // Parse the OTLP request
        let actual_report = ExportMetricsServiceRequest::decode(built_report.as_slice()).unwrap();
        assert_eq!(built_report, actual_report.encode_to_vec());

        let compute_type = match compute_platform {
            ComputePlatform::Ec2Plain => "ec2",
            ComputePlatform::Ec2K8sEks => "k8s-eks",
            ComputePlatform::Ec2K8sVanilla => "k8s-vanilla",
        };
        let expected_report: ExportMetricsServiceRequest = serde_json::from_reader(
            fs::File::open(format!("../test-data/report-{compute_type}-otel.json")).unwrap(),
        )
        .unwrap();

        // Save the serialized protobuf file for external validation.
        let output_filename = format!("report-1-{compute_type}-flow.bin");
        let mut buf = Vec::new();
        actual_report.encode(&mut buf).unwrap();
        fs::create_dir_all("../target/report-samples/").unwrap();
        let mut file =
            fs::File::create(format!("../target/report-samples/{}", output_filename)).unwrap();
        std::io::Write::write_all(&mut file, &buf).unwrap();

        assert_reports_eq(actual_report, expected_report);
    }

    fn assert_reports_eq(
        mut actual_report: ExportMetricsServiceRequest,
        mut expected_report: ExportMetricsServiceRequest,
    ) {
        // Note that serde serializes an object to JSON by creating, an `Object` variant of the
        // `serde_json::Value` enum, whose contents are a `serde_json::Map`.  By default, the order
        // of iterating a map's contents is not preserved, and we end up with a flaky unit test by
        // asserting equality between actual_report and expected_report.  We could enable serde's
        // "preserve_order" feature, but that can lead to someone taking a dependency on field
        // order in production, which we don't want.  Hence we instead explicitly compare the
        // fields of the Otel reports, which includes a sort of the metrics vector.

        assert_eq!(actual_report.resource_metrics.len(), 1);
        assert_eq!(expected_report.resource_metrics.len(), 1);
        assert_eq!(
            &actual_report.resource_metrics[0].resource,
            &expected_report.resource_metrics[0].resource,
        );
        assert_eq!(
            &actual_report.resource_metrics[0].schema_url,
            &expected_report.resource_metrics[0].schema_url
        );

        let actual_len = actual_report.resource_metrics[0].scope_metrics.len();
        let expected_len = expected_report.resource_metrics[0].scope_metrics.len();
        assert_eq!(actual_len, expected_len);
        assert!(expected_len > 0);

        for i in 0..expected_len {
            let actual = &mut actual_report.resource_metrics[0].scope_metrics[i];
            let expected = &mut expected_report.resource_metrics[0].scope_metrics[i];
            actual.metrics.sort_by(|a, b| a.name.cmp(&b.name));
            expected.metrics.sort_by(|a, b| a.name.cmp(&b.name));

            assert_eq!(actual, expected, "index {}", i);
            assert!(expected.metrics.len() > 0, "index {}", i);
        }
    }
}
