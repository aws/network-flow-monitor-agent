// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    events::host_stats_provider::{HostStatsProvider, HostStatsProviderImpl},
    metadata::{
        eni::EniMetadataProvider, k8s_metadata::K8sMetadata,
        runtime_environment_metadata::ComputePlatform,
    },
    open_metrics::{
        provider::OpenMetricProvider,
        providers::{build_gauge_metric, MetricLabel},
    },
    reports::report::ReportValue,
};
use anyhow;
use log::info;
use prometheus::{IntGaugeVec, Registry};

/// System level metrics.
struct SystemMetric {
    key: SystemMetricKey,
    value: SystemMetricValues,
}

/// Metric key.
struct SystemMetricKey {
    instance: String,
    eni: String,
    node: String,
}

/// Values provided by the metrics.
struct SystemMetricValues {
    bw_in_allowance_exceeded: u64,
    bw_out_allowance_exceeded: u64,
    pps_allowance_exceeded: u64,
    conntrack_allowance_exceeded: u64,
    linklocal_allowance_exceeded: u64,
}

pub struct SystemMetricsProvider {
    compute_platform: ComputePlatform,
    eni_metadata_provider: EniMetadataProvider,
    host_stats_provider: HostStatsProviderImpl,
    node_name: String,

    bw_in_allowance_exceeded: IntGaugeVec,
    bw_out_allowance_exceeded: IntGaugeVec,
    pps_allowance_exceeded: IntGaugeVec,
    conntrack_allowance_exceeded: IntGaugeVec,
    linklocal_allowance_exceeded: IntGaugeVec,
}

impl SystemMetricsProvider {
    pub fn new(compute_platform: &ComputePlatform) -> Self {
        let node_name = match K8sMetadata::default().node_name {
            Some(ReportValue::String(node_name)) => node_name,
            _ => "unknown".to_string(),
        };

        SystemMetricsProvider {
            compute_platform: compute_platform.clone(),
            eni_metadata_provider: EniMetadataProvider::new(),
            host_stats_provider: HostStatsProviderImpl::new(),
            node_name,

            bw_in_allowance_exceeded: build_gauge_metric::<SystemMetric>(
                &compute_platform,
                "bw_in_allowance_exceeded",
                "The number of packets queued or dropped because the inbound aggregate bandwidth exceeded the maximum for the instance.",
            ),
            bw_out_allowance_exceeded: build_gauge_metric::<SystemMetric>(
                &compute_platform,
                "bw_out_allowance_exceeded",
                "The number of packets queued or dropped because the outbound aggregate bandwidth exceeded the maximum for the instance."
            ),
            pps_allowance_exceeded: build_gauge_metric::<SystemMetric>(&compute_platform, "pps_allowance_exceeded", "The number of packets queued or dropped because the bidirectional PPS exceeded the maximum for the instance."),
            conntrack_allowance_exceeded: build_gauge_metric::<SystemMetric>(
                &compute_platform,
                "conntrack_allowance_exceeded",
                "The number of packets dropped because connection tracking exceeded the maximum for the instance and new connections could not be established. This can result in packet loss for traffic to or from the instance."
            ),
            linklocal_allowance_exceeded: build_gauge_metric(
                &compute_platform,
                "linklocal_allowance_exceeded",
                "The number of packets dropped because the PPS of the traffic to local proxy services exceeded the maximum for the network interface."
            ),
        }
    }

    fn get_metrics(&mut self) -> Vec<SystemMetric> {
        self.host_stats_provider
            .set_network_devices(&self.eni_metadata_provider.get_network_devices());
        let mut metrics = vec![];
        for host_stat in self.host_stats_provider.get_stats().interface_stats {
            metrics.push(SystemMetric {
                key: SystemMetricKey {
                    instance: self.eni_metadata_provider.instance_id.clone(),
                    eni: host_stat.interface_id,
                    node: self.node_name.clone(),
                },
                value: SystemMetricValues {
                    bw_in_allowance_exceeded: host_stat.stats.bw_in_allowance_exceeded,
                    bw_out_allowance_exceeded: host_stat.stats.bw_out_allowance_exceeded,
                    pps_allowance_exceeded: host_stat.stats.pps_allowance_exceeded,
                    conntrack_allowance_exceeded: host_stat.stats.conntrack_allowance_exceeded,
                    linklocal_allowance_exceeded: host_stat.stats.linklocal_allowance_exceeded,
                },
            })
        }
        metrics
    }
}

impl SystemMetric {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str] {
        match compute_platform {
            ComputePlatform::Ec2Plain => &["instance_id", "eni"],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                &["instance_id", "eni", "node"]
            }
        }
    }

    fn label_values(&self, compute_platform: &ComputePlatform) -> Vec<&str> {
        // The order of the elements must match the labels for the trait MetricLabel
        match compute_platform {
            ComputePlatform::Ec2Plain => vec![&self.key.instance.as_str(), &self.key.eni.as_str()],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                vec![
                    &self.key.instance.as_str(),
                    &self.key.eni.as_str(),
                    &self.key.node.as_str(),
                ]
            }
        }
    }
}

impl MetricLabel for SystemMetric {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str] {
        match compute_platform {
            ComputePlatform::Ec2Plain => &["instance_id", "eni"],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => &["eni", "node"],
        }
    }
}

/// Open metric implementation. It will provide host level metrics annotated with
/// environment metadata.
impl OpenMetricProvider for SystemMetricsProvider {
    fn register_to(&self, registry: &mut Registry) {
        info!(platform = self.compute_platform.to_string(); "Registering System Metrics");

        registry
            .register(Box::new(self.bw_in_allowance_exceeded.clone()))
            .unwrap();
        registry
            .register(Box::new(self.bw_out_allowance_exceeded.clone()))
            .unwrap();
        registry
            .register(Box::new(self.pps_allowance_exceeded.clone()))
            .unwrap();
        registry
            .register(Box::new(self.conntrack_allowance_exceeded.clone()))
            .unwrap();
        registry
            .register(Box::new(self.linklocal_allowance_exceeded.clone()))
            .unwrap();
    }

    fn update_metrics(&mut self) -> Result<(), anyhow::Error> {
        info!(platform = self.compute_platform.to_string(); "Updating System Metrics");
        let metrics = self.get_metrics();

        for metric in &metrics {
            let label_values = metric.label_values(&self.compute_platform);

            self.bw_in_allowance_exceeded
                .with_label_values(&label_values)
                .set(metric.value.bw_in_allowance_exceeded as i64);
            self.bw_out_allowance_exceeded
                .with_label_values(&label_values)
                .set(metric.value.bw_out_allowance_exceeded as i64);
            self.pps_allowance_exceeded
                .with_label_values(&label_values)
                .set(metric.value.pps_allowance_exceeded as i64);
            self.conntrack_allowance_exceeded
                .with_label_values(&label_values)
                .set(metric.value.conntrack_allowance_exceeded as i64);
            self.linklocal_allowance_exceeded
                .with_label_values(&label_values)
                .set(metric.value.linklocal_allowance_exceeded as i64);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::process::ExitStatusExt,
        process::{ExitStatus, Output},
    };

    use super::*;
    use crate::{
        events::host_stats_provider::NetworkInterfaceStats,
        metadata::{
            eni::NetworkInterfaceInfo, env_metadata_provider::NetworkDevice,
            runtime_environment_metadata::ComputePlatform,
        },
        utils::FakeCommandRunner,
    };
    use aws_config::imds::Client;
    use hashbrown::{HashMap, HashSet};
    use prometheus::Registry;

    // Helper function to create a test SystemMetricsProvider
    fn create_test_provider(compute_platform: ComputePlatform) -> SystemMetricsProvider {
        SystemMetricsProvider::new(&compute_platform)
    }

    #[test]
    fn test_system_metrics_provider_new() {
        let provider = create_test_provider(ComputePlatform::Ec2Plain);

        // Verify the provider is created successfully
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2Plain);
        assert_eq!(provider.node_name, "unknown"); // Default when K8s metadata is not available
    }

    #[test]
    fn test_system_metrics_provider_new_eks() {
        let provider = create_test_provider(ComputePlatform::Ec2K8sEks);

        assert_eq!(provider.compute_platform, ComputePlatform::Ec2K8sEks);
    }

    #[test]
    fn test_system_metrics_provider_new_vanilla_k8s() {
        let provider = create_test_provider(ComputePlatform::Ec2K8sVanilla);

        assert_eq!(provider.compute_platform, ComputePlatform::Ec2K8sVanilla);
    }

    #[test]
    fn test_system_metric_get_labels_ec2_plain() {
        let labels = SystemMetric::get_labels(&ComputePlatform::Ec2Plain);
        assert_eq!(labels, &["instance_id", "eni"]);
    }

    #[test]
    fn test_system_metric_get_labels_eks() {
        let labels = SystemMetric::get_labels(&ComputePlatform::Ec2K8sEks);
        assert_eq!(labels, &["instance_id", "eni", "node"]);
    }

    #[test]
    fn test_system_metric_get_labels_vanilla_k8s() {
        let labels = SystemMetric::get_labels(&ComputePlatform::Ec2K8sVanilla);
        assert_eq!(labels, &["instance_id", "eni", "node"]);
    }

    #[test]
    fn test_system_metric_label_values_ec2_plain() {
        let metric = SystemMetric {
            key: SystemMetricKey {
                instance: "i-1234567890abcdef0".to_string(),
                eni: "eni-12345".to_string(),
                node: "test-node".to_string(),
            },
            value: SystemMetricValues {
                bw_in_allowance_exceeded: 100,
                bw_out_allowance_exceeded: 200,
                pps_allowance_exceeded: 300,
                conntrack_allowance_exceeded: 400,
                linklocal_allowance_exceeded: 500,
            },
        };

        let label_values = metric.label_values(&ComputePlatform::Ec2Plain);
        assert_eq!(label_values, vec!["i-1234567890abcdef0", "eni-12345"]);
    }

    #[test]
    fn test_system_metric_label_values_eks() {
        let metric = SystemMetric {
            key: SystemMetricKey {
                instance: "i-1234567890abcdef0".to_string(),
                eni: "eni-12345".to_string(),
                node: "test-node".to_string(),
            },
            value: SystemMetricValues {
                bw_in_allowance_exceeded: 100,
                bw_out_allowance_exceeded: 200,
                pps_allowance_exceeded: 300,
                conntrack_allowance_exceeded: 400,
                linklocal_allowance_exceeded: 500,
            },
        };

        let label_values = metric.label_values(&ComputePlatform::Ec2K8sEks);
        assert_eq!(
            label_values,
            vec!["i-1234567890abcdef0", "eni-12345", "test-node"]
        );
    }

    #[test]
    fn test_system_metric_label_values_vanilla_k8s() {
        let metric = SystemMetric {
            key: SystemMetricKey {
                instance: "i-1234567890abcdef0".to_string(),
                eni: "eni-12345".to_string(),
                node: "test-node".to_string(),
            },
            value: SystemMetricValues {
                bw_in_allowance_exceeded: 100,
                bw_out_allowance_exceeded: 200,
                pps_allowance_exceeded: 300,
                conntrack_allowance_exceeded: 400,
                linklocal_allowance_exceeded: 500,
            },
        };

        let label_values = metric.label_values(&ComputePlatform::Ec2K8sVanilla);
        assert_eq!(
            label_values,
            vec!["i-1234567890abcdef0", "eni-12345", "test-node"]
        );
    }

    #[test]
    fn test_register_to_registry() {
        let mut provider = create_test_provider(ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();

        provider.register_to(&mut registry);
        let _ = provider.update_metrics();
        let metric_families = registry.gather();

        assert_eq!(metric_families.len(), 5);

        let metric_names: Vec<String> = metric_families
            .iter()
            .map(|mf| mf.get_name().to_string())
            .collect();

        assert!(metric_names.contains(&"bw_in_allowance_exceeded".to_string()));
        assert!(metric_names.contains(&"bw_out_allowance_exceeded".to_string()));
        assert!(metric_names.contains(&"pps_allowance_exceeded".to_string()));
        assert!(metric_names.contains(&"conntrack_allowance_exceeded".to_string()));
        assert!(metric_names.contains(&"linklocal_allowance_exceeded".to_string()));
    }

    #[test]
    fn test_update_metrics_success() {
        let mut provider = create_test_provider(ComputePlatform::Ec2Plain);

        let result = provider.update_metrics();
        assert!(result.is_ok());
    }

    #[test]
    fn test_system_metric_creation() {
        let key = SystemMetricKey {
            instance: "i-1234567890abcdef0".to_string(),
            eni: "eni-12345".to_string(),
            node: "test-node".to_string(),
        };

        let value = SystemMetricValues {
            bw_in_allowance_exceeded: 100,
            bw_out_allowance_exceeded: 200,
            pps_allowance_exceeded: 300,
            conntrack_allowance_exceeded: 400,
            linklocal_allowance_exceeded: 500,
        };

        let metric = SystemMetric { key, value };

        assert_eq!(metric.key.instance, "i-1234567890abcdef0");
        assert_eq!(metric.key.eni, "eni-12345");
        assert_eq!(metric.key.node, "test-node");
        assert_eq!(metric.value.bw_in_allowance_exceeded, 100);
        assert_eq!(metric.value.bw_out_allowance_exceeded, 200);
        assert_eq!(metric.value.pps_allowance_exceeded, 300);
        assert_eq!(metric.value.conntrack_allowance_exceeded, 400);
        assert_eq!(metric.value.linklocal_allowance_exceeded, 500);
    }

    #[test]
    fn test_multiple_compute_platforms() {
        let platforms = vec![
            ComputePlatform::Ec2Plain,
            ComputePlatform::Ec2K8sEks,
            ComputePlatform::Ec2K8sVanilla,
        ];

        for platform in platforms {
            let mut provider = create_test_provider(platform.clone());
            assert_eq!(provider.compute_platform, platform);

            // Create a fresh registry for each platform to avoid conflicts
            let mut registry = Registry::new();
            provider.register_to(&mut registry);
            let _ = provider.update_metrics();
            let metric_families = registry.gather();

            // Verify we have the expected number of metric families
            assert_eq!(
                metric_families.len(),
                5,
                "Failed for platform: {:?}",
                platform
            );

            // Verify the metric names are correct
            let metric_names: Vec<String> = metric_families
                .iter()
                .map(|mf| mf.get_name().to_string())
                .collect();

            assert!(metric_names.contains(&"bw_in_allowance_exceeded".to_string()));
            assert!(metric_names.contains(&"bw_out_allowance_exceeded".to_string()));
            assert!(metric_names.contains(&"pps_allowance_exceeded".to_string()));
            assert!(metric_names.contains(&"conntrack_allowance_exceeded".to_string()));
            assert!(metric_names.contains(&"linklocal_allowance_exceeded".to_string()));
        }
    }

    #[test]
    fn test_gauge_metrics_have_correct_labels() {
        for platform in &[
            ComputePlatform::Ec2Plain,
            ComputePlatform::Ec2K8sEks,
            ComputePlatform::Ec2K8sVanilla,
        ] {
            let mut provider = create_test_provider(platform.clone());
            let mut registry = Registry::new();
            provider.register_to(&mut registry);
            let _ = provider.update_metrics();

            let metric_families = registry.gather();
            let expected_labels: HashSet<&str> =
                HashSet::from_iter(SystemMetric::get_labels(platform).iter().copied());

            // Verify we have the expected number of metric families
            assert_eq!(metric_families.len(), 5);

            for metric_family in metric_families {
                // Each metric family should have at least one metric
                assert!(!metric_family.get_metric().is_empty());

                for metric in metric_family.get_metric() {
                    let created_label: HashSet<&str> =
                        metric.get_label().iter().map(|l| l.get_name()).collect();

                    assert_eq!(created_label, expected_labels);
                }
            }
        }
    }

    macro_rules! ethtool_template {
        () => {
            r#"
	    NIC statistics:
                 total_resets: 0
                 reset_fail: 0
                 tx_timeout: 0
		 bw_in_allowance_exceeded: {}
		 bw_out_allowance_exceeded: {}
		 pps_allowance_exceeded: {}
		 conntrack_allowance_exceeded: {}
		 linklocal_allowance_exceeded: {}
		 conntrack_allowance_available: {}
		 ena_admin_q_out_of_space: 0
		 ena_admin_q_no_completion: 0
	    "#
        };
    }

    fn create_mocked_provider() -> SystemMetricsProvider {
        // Mock ENI
        let mut eni_command_runner = Box::new(FakeCommandRunner::new());
        eni_command_runner.add_expectation(
            "ip",
            &["-br", "link"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: r#"
                    lo               UNKNOWN        11:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP> 
                    eth1             UP             22:00:00:00:00:00 <BROADCAST,MULTICAST,UP,LOWER_UP> 
                    docker0          DOWN           33:00:00:00:00:00 <NO-CARRIER,BROADCAST,MULTICAST,UP> 
                    eth2             UP             44:00:00:00:00:00 <BROADCAST,MULTICAST,UP,LOWER_UP> 
                "#
                .as_bytes()
                .to_vec(),
                stderr: vec![],
            }),
        );
        let net_infos: Vec<NetworkInterfaceInfo> = vec![
            NetworkInterfaceInfo {
                mac: "22:00:00:00:00:00".to_string(),
                interface_id: "ifc-id1".to_string(),
                ..Default::default()
            },
            NetworkInterfaceInfo {
                mac: "44:00:00:00:00:00".to_string(),
                interface_id: "ifc-id2".to_string(),
                ..Default::default()
            },
        ];

        // Mock Host data
        let mut host_command_runner = Box::new(FakeCommandRunner::new());
        host_command_runner.add_expectation(
            "ethtool",
            &["-S", "eth1"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(ethtool_template!(), 5, 6, 9, 7, 8, 10)
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );
        host_command_runner.add_expectation(
            "ethtool",
            &["-S", "eth2"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(ethtool_template!(), 5, 6, 9, 7, 8, 10)
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );

        let eth1 = NetworkDevice {
            interface_id: "ifc-id1".to_string(),
            device_name: "eth1".to_string(),
        };
        let eth2 = NetworkDevice {
            interface_id: "ifc-id2".to_string(),
            device_name: "eth2".to_string(),
        };
        let mut network_intefrace_stats = HashMap::new();
        network_intefrace_stats.insert(eth1, NetworkInterfaceStats::default());
        network_intefrace_stats.insert(eth2, NetworkInterfaceStats::default());

        let compute_platform = ComputePlatform::Ec2Plain;
        SystemMetricsProvider {
            compute_platform: compute_platform.clone(),
            eni_metadata_provider: EniMetadataProvider {
                client: Client::builder().build(),
                instance_id: "inst-id1".to_string(),
                instance_type: "the-instance-type".into(),
                network: net_infos,
                command_runner: eni_command_runner,
            },
            host_stats_provider: HostStatsProviderImpl {
                network_interface_stats: network_intefrace_stats,
                command_runner: host_command_runner,
            },
            node_name: "node-name".to_string(),
            bw_in_allowance_exceeded: build_gauge_metric::<SystemMetric>(
                &compute_platform,
                "bw_in_allowance_exceeded",
                "description",
            ),
            bw_out_allowance_exceeded: build_gauge_metric::<SystemMetric>(
                &compute_platform,
                "bw_out_allowance_exceeded",
                "description",
            ),
            pps_allowance_exceeded: build_gauge_metric::<SystemMetric>(
                &compute_platform,
                "pps_allowance_exceeded",
                "description",
            ),
            conntrack_allowance_exceeded: build_gauge_metric::<SystemMetric>(
                &compute_platform,
                "conntrack_allowance_exceeded",
                "description",
            ),
            linklocal_allowance_exceeded: build_gauge_metric(
                &compute_platform,
                "linklocal_allowance_exceeded",
                "description",
            ),
        }
    }

    #[test]
    fn test_get_metrics() {
        let mut provider = create_mocked_provider();
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let metrics = provider.get_metrics();
        // 2 interfaces
        assert_eq!(metrics.len(), 2);
    }
}
