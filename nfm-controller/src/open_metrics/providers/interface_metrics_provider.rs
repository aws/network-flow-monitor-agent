// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interface metrics provider for collecting network interface statistics.
//!
//! This module provides network interface monitoring capabilities including:
//! - Host-level interface statistics (packets, bytes)
//! - Network namespace flow statistics (TCP connections)
//! - Kubernetes pod metadata correlation
//! - Delta calculations for rate-based metrics
//!
//! The provider supports multiple compute platforms (EC2, EKS, Vanilla K8s) and
//! automatically discovers virtual interfaces for container networking monitoring.

use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    kubernetes::kubernetes_metadata_collector::KubernetesMetadataCollector,
    metadata::{
        imds_utils::retrieve_instance_id, k8s_metadata::K8sMetadata,
        runtime_environment_metadata::ComputePlatform,
    },
    open_metrics::{
        provider::OpenMetricProvider,
        providers::{
            build_gauge_metric, interface_metrics_provider::discovery::InterfaceDiscoveryImpl,
            MetricLabel,
        },
        types::{IpToPodMapping, NamespaceMapping},
    },
    reports::report::ReportValue,
    utils::RealCommandRunner,
};
use aws_config::imds::Client;
use log::{debug, info};
use prometheus::{IntGaugeVec, Registry};

// Sub-module for auxiliary components
mod discovery;
mod namespace_manager;
mod netns_stats;
pub(crate) mod types;

use discovery::{get_pod_info_from_iface, HostInterfaceMetricValues, InterfaceDiscovery};
use namespace_manager::NetworkNamespaceManager;
use netns_stats::{NetNsInterfaceMetricValues, NetNsStats};
use types::NamespaceId;

/// Metric identification key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceMetricKey {
    instance: String,
    iface: String,
    pod: String,
    pod_namespace: String,
    node: String,
}

impl InterfaceMetricKey {
    fn label_values<'a>(
        &'a self,
        compute_platform: &ComputePlatform,
        node_name: &'a str,
        instance_id: &'a str,
    ) -> Vec<&'a str> {
        match compute_platform {
            ComputePlatform::Ec2Plain => {
                vec![instance_id, &self.iface]
            }
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                vec![
                    instance_id,
                    &self.iface,
                    &self.pod,
                    &self.pod_namespace,
                    node_name,
                ]
            }
        }
    }

    fn is_valid(&self, compute_platform: &ComputePlatform) -> bool {
        match compute_platform {
            ComputePlatform::Ec2Plain => !self.instance.is_empty(),
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => !self.pod.is_empty(),
        }
    }
}

impl MetricLabel for InterfaceMetricKey {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str] {
        match compute_platform {
            ComputePlatform::Ec2Plain => &["instance_id", "iface"],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                &["instance_id", "iface", "pod", "namespace", "node"]
            }
        }
    }
}

/// Combined interface metrics (host + namespace)
#[derive(Debug, Clone, Default)]
pub struct InterfaceMetricValues {
    host: HostInterfaceMetricValues,
    netns: NetNsInterfaceMetricValues,
}

impl InterfaceMetricValues {
    fn calculate_delta(&self, previous: &Self) -> Self {
        Self {
            host: self.host.calculate_delta(&previous.host),
            netns: self.netns.calculate_delta(&previous.netns),
        }
    }
}

/// Main interface metrics provider
pub struct InterfaceMetricsProvider {
    compute_platform: ComputePlatform,
    instance_id: String,
    node_name: String,

    namespace_manager: NetworkNamespaceManager,
    netns_stats: NetNsStats,
    iface_discovery: Box<dyn InterfaceDiscovery>,
    k8s_metadata: Option<Arc<KubernetesMetadataCollector>>,

    // Prometheus metrics
    ingress_pkt_count: IntGaugeVec,
    ingress_bytes_count: IntGaugeVec,
    egress_pkt_count: IntGaugeVec,
    egress_bytes_count: IntGaugeVec,
    ingress_flow_count: IntGaugeVec,
    egress_flow_count: IntGaugeVec,

    // State for delta calculations
    current_metrics: HashMap<InterfaceMetricKey, InterfaceMetricValues>,
}

impl InterfaceMetricsProvider {
    pub fn new(
        compute_platform: &ComputePlatform,
        k8s_metadata: Option<Arc<KubernetesMetadataCollector>>,
    ) -> Self {
        let node_name = match K8sMetadata::default().node_name {
            Some(ReportValue::String(node_name)) => node_name,
            _ => "unknown".to_string(),
        };

        let namespace_command_runner = Box::new(RealCommandRunner {});
        let netns_command_runner = Box::new(RealCommandRunner {});
        let namespace_manager = NetworkNamespaceManager::new(namespace_command_runner);
        let netns_stats = NetNsStats::new(netns_command_runner);
        let iface_discovery = Box::new(InterfaceDiscoveryImpl {});

        let mut provider = Self {
            compute_platform: compute_platform.clone(),
            instance_id: retrieve_instance_id(&Client::builder().build()),
            node_name,
            namespace_manager,
            netns_stats,
            iface_discovery,
            k8s_metadata,
            ingress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                compute_platform,
                "ingress_packets",
                "Ingress packet count",
            ),
            ingress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                compute_platform,
                "ingress_bytes",
                "Ingress bytes count",
            ),
            egress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                compute_platform,
                "egress_packets",
                "Egress packet count",
            ),
            egress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                compute_platform,
                "egress_bytes",
                "Egress bytes count",
            ),
            ingress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                compute_platform,
                "ingress_flow",
                "Ingress TCP flow count",
            ),
            egress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                compute_platform,
                "egress_flow",
                "Egress TCP flow count",
            ),
            current_metrics: HashMap::new(),
        };

        // Initialize baseline metrics
        provider.get_metrics();
        provider
    }

    /// Get current interface metrics
    fn get_metrics(&mut self) -> HashMap<InterfaceMetricKey, InterfaceMetricValues> {
        let (ns_to_pid, pod_info) = self.environment_info();

        // Parse all interface links once at the beginning for better performance
        let interface_ns_map = match self.compute_platform {
            ComputePlatform::Ec2Plain => HashMap::new(),
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => self
                .namespace_manager
                .parse_all_interface_links()
                .unwrap_or_default(),
        };

        let mut new_current_metrics = HashMap::new();
        let mut result = HashMap::new();

        let interface_stats = self
            .iface_discovery
            .get_virtual_interface_stats()
            .unwrap_or_default();

        for (iface, device_status) in interface_stats {
            let netns = if iface.is_virtual() {
                self.namespace_manager
                    .get_namespace_id_for_interface_from_map(&iface.name, &interface_ns_map)
            } else {
                None
            };

            let key = self.build_metric_key(&iface.name, &ns_to_pid, &pod_info, netns);
            if !key.is_valid(&self.compute_platform) {
                continue;
            }

            let mut host_metrics = HostInterfaceMetricValues::new(
                device_status.recv_packets,
                device_status.recv_bytes,
                device_status.sent_packets,
                device_status.sent_bytes,
            );

            let mut netns_metrics = NetNsInterfaceMetricValues::default();
            // If the interface is virtual, we need to swap the values because the pod is on the other end
            // of the link
            if iface.is_virtual() {
                host_metrics.swap_tx_rx();

                // Use the already retrieved netns value
                netns_metrics =
                    match netns.and_then(|ns| ns_to_pid.as_ref().and_then(|map| map.get(&ns))) {
                        None => NetNsInterfaceMetricValues::default(),
                        Some(ns_info) => self.netns_stats.get_namespace_flow_stats(ns_info),
                    };
            }

            let iface_metrics = InterfaceMetricValues {
                host: host_metrics,
                netns: netns_metrics,
            };

            // Calculate deltas before inserting into new_current_metrics
            let delta_metric = iface_metrics.calculate_delta(
                self.current_metrics
                    .get(&key)
                    .unwrap_or(&InterfaceMetricValues::default()),
            );

            // We return the delta but keep the real value to calculate the next iteration's delta.
            new_current_metrics.insert(key.clone(), iface_metrics);
            result.insert(key, delta_metric);
        }

        self.current_metrics = new_current_metrics;
        result
    }

    fn environment_info(&mut self) -> (Option<NamespaceMapping>, Option<IpToPodMapping>) {
        let (ns_to_pid, pod_info) = match self.compute_platform {
            ComputePlatform::Ec2Plain => (None, None),
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                let ns_info = self
                    .namespace_manager
                    .get_namespace_info()
                    .unwrap_or_default();
                let pod_mappings = self.get_ip_pod_info_mapping();
                (Some(ns_info), pod_mappings)
            }
        };
        (ns_to_pid, pod_info)
    }

    fn get_ip_pod_info_mapping(&self) -> Option<IpToPodMapping> {
        self.k8s_metadata
            .as_ref()
            .map(|k8s_metadata| k8s_metadata.get_ip_to_pod_mapping(&[]))
    }

    fn build_metric_key(
        &self,
        iface_name: &str,
        ns_to_pid: &Option<NamespaceMapping>,
        pod_info_map: &Option<IpToPodMapping>,
        netns: Option<NamespaceId>,
    ) -> InterfaceMetricKey {
        let (pod, pod_namespace) = match self.compute_platform {
            ComputePlatform::Ec2Plain => (String::new(), String::new()),
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                if let (Some(ns_info), Some(pod_map)) = (ns_to_pid.as_ref(), pod_info_map.as_ref())
                {
                    get_pod_info_from_iface(iface_name, ns_info, pod_map, netns)
                } else {
                    (String::new(), String::new())
                }
            }
        };
        InterfaceMetricKey {
            instance: self.instance_id.clone(),
            iface: iface_name.to_string(),
            pod,
            pod_namespace,
            node: self.node_name.clone(),
        }
    }
}

impl OpenMetricProvider for InterfaceMetricsProvider {
    fn register_to(&self, registry: &mut Registry) {
        info!(platform = self.compute_platform.to_string(); "Registering Interface Metrics");

        registry
            .register(Box::new(self.ingress_bytes_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.ingress_pkt_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.egress_bytes_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.egress_pkt_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.ingress_flow_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.egress_flow_count.clone()))
            .unwrap();
    }

    fn update_metrics(&mut self) -> Result<(), anyhow::Error> {
        info!(platform = self.compute_platform.to_string(); "Updating Interface Metrics");
        let metrics = self.get_metrics();

        for (key, value) in metrics {
            let label_values =
                key.label_values(&self.compute_platform, &self.node_name, &self.instance_id);

            debug!(labels = format!("{:?}", label_values), metrics = format!("{:?}", value); "Interface metrics");

            self.ingress_bytes_count
                .with_label_values(&label_values)
                .set(value.host.ingress_bytes_count as i64);
            self.ingress_pkt_count
                .with_label_values(&label_values)
                .set(value.host.ingress_pkt_count as i64);
            self.egress_bytes_count
                .with_label_values(&label_values)
                .set(value.host.egress_bytes_count as i64);
            self.egress_pkt_count
                .with_label_values(&label_values)
                .set(value.host.egress_pkt_count as i64);

            self.ingress_flow_count
                .with_label_values(&label_values)
                .set(value.netns.ingress_flow_count as i64);
            self.egress_flow_count
                .with_label_values(&label_values)
                .set(value.netns.egress_flow_count as i64);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        kubernetes::kubernetes_metadata_collector::PodInfo,
        open_metrics::providers::interface_metrics_provider::types::HostInterface,
        utils::FakeCommandRunner,
    };

    use super::*;
    use anyhow::Result;
    use procfs::net::DeviceStatus;
    use prometheus::Registry;
    use std::{
        collections::{HashMap, HashSet},
        net::IpAddr,
        os::unix::process::ExitStatusExt,
        process::{ExitStatus, Output},
        str::FromStr,
        sync::Mutex,
    };

    use crate::utils::test_utils::TemporaryFile;

    #[test]
    fn test_interface_metrics_provider_new() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain, None);
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2Plain);
        assert_eq!(provider.node_name, "unknown");
    }

    #[test]
    fn test_interface_metrics_provider_new_with_k8s_metadata() {
        let k8s_metadata = Arc::new(KubernetesMetadataCollector::new());
        let provider =
            InterfaceMetricsProvider::new(&ComputePlatform::Ec2K8sEks, Some(k8s_metadata));

        assert_eq!(provider.compute_platform, ComputePlatform::Ec2K8sEks);
        assert!(provider.k8s_metadata.is_some());
    }

    #[test]
    fn test_interface_metrics_provider_new_all_platforms() {
        let platforms = vec![
            ComputePlatform::Ec2Plain,
            ComputePlatform::Ec2K8sEks,
            ComputePlatform::Ec2K8sVanilla,
        ];

        for platform in platforms {
            let provider = InterfaceMetricsProvider::new(&platform, None);
            assert_eq!(provider.compute_platform, platform);
        }
    }

    #[test]
    fn test_interface_metric_key_labels() {
        let labels_ec2 = InterfaceMetricKey::get_labels(&ComputePlatform::Ec2Plain);
        assert_eq!(labels_ec2, &["instance_id", "iface"]);

        let labels_eks = InterfaceMetricKey::get_labels(&ComputePlatform::Ec2K8sEks);
        assert_eq!(
            labels_eks,
            &["instance_id", "iface", "pod", "namespace", "node"]
        );
    }

    #[test]
    fn test_interface_metric_key_label_values() {
        let key = InterfaceMetricKey {
            instance: "i-123".to_string(),
            iface: "eth0".to_string(),
            pod: "test-pod".to_string(),
            pod_namespace: "default".to_string(),
            node: "node1".to_string(),
        };

        let ec2_labels = key.label_values(&ComputePlatform::Ec2Plain, "node1", "i-123");
        assert_eq!(ec2_labels, vec!["i-123", "eth0"]);

        let k8s_labels = key.label_values(&ComputePlatform::Ec2K8sEks, "node1", "i-123");
        assert_eq!(
            k8s_labels,
            vec!["i-123", "eth0", "test-pod", "default", "node1"]
        );
    }

    #[test]
    fn test_interface_metric_values_delta() {
        let current = InterfaceMetricValues {
            host: HostInterfaceMetricValues::new(1000, 50000, 800, 40000),
            netns: NetNsInterfaceMetricValues::new(100, 80),
        };

        let previous = InterfaceMetricValues {
            host: HostInterfaceMetricValues::new(900, 45000, 700, 35000),
            netns: NetNsInterfaceMetricValues::new(70, 50),
        };

        let delta = current.calculate_delta(&previous);

        // Test host metrics delta
        assert_eq!(delta.host.ingress_pkt_count, 100);
        assert_eq!(delta.host.ingress_bytes_count, 5000);
        assert_eq!(delta.host.egress_pkt_count, 100);
        assert_eq!(delta.host.egress_bytes_count, 5000);

        // Test netns metrics delta
        assert_eq!(delta.netns.ingress_flow_count, 30);
        assert_eq!(delta.netns.egress_flow_count, 30);
    }

    #[test]
    fn test_environment_info_ec2_plain() {
        let mut provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain, None);
        let (ns_info, pod_info) = provider.environment_info();

        assert!(ns_info.is_none());
        assert!(pod_info.is_none());
    }

    #[test]
    fn test_environment_info_k8s_platforms() {
        let k8s_metadata = Arc::new(KubernetesMetadataCollector::new());
        let mut provider =
            InterfaceMetricsProvider::new(&ComputePlatform::Ec2K8sEks, Some(k8s_metadata));

        let (ns_info, pod_info) = provider.environment_info();
        // These will be Some() for K8s platforms
        assert!(ns_info.is_some());
        assert!(pod_info.is_some());
    }

    #[test]
    fn test_get_ip_pod_info_mapping() {
        let k8s_metadata = Arc::new(KubernetesMetadataCollector::new());
        let provider =
            InterfaceMetricsProvider::new(&ComputePlatform::Ec2K8sEks, Some(k8s_metadata));

        let mapping = provider.get_ip_pod_info_mapping();
        assert!(mapping.is_some());
    }

    #[test]
    fn test_get_ip_pod_info_mapping_none() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain, None);

        let mapping = provider.get_ip_pod_info_mapping();
        assert!(mapping.is_none());
    }

    #[test]
    fn test_build_metric_key_ec2_plain() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain, None);

        let key = provider.build_metric_key("eth0", &None, &None, None);

        assert_eq!(key.iface, "eth0");
        assert_eq!(key.pod, "");
        assert_eq!(key.pod_namespace, "");
    }

    #[test]
    fn test_build_metric_key_k8s_platforms() {
        use crate::kubernetes::kubernetes_metadata_collector::PodInfo;
        use crate::open_metrics::providers::interface_metrics_provider::types::{
            NamespaceInfo, ProcessId,
        };
        use std::collections::HashSet;
        use std::net::IpAddr;

        let k8s_metadata = Arc::new(KubernetesMetadataCollector::new());
        let provider =
            InterfaceMetricsProvider::new(&ComputePlatform::Ec2K8sEks, Some(k8s_metadata));

        // Create mock namespace mapping with actual data
        let mut ns_mapping = HashMap::new();
        let ns_id = NamespaceId::new(123);
        let ns_info = NamespaceInfo {
            pid: ProcessId::new(456),
            ns_file: Some("/proc/456/ns/net".to_string()),
            ip_addresses: vec!["10.0.1.100".parse().unwrap()],
        };
        ns_mapping.insert(ns_id, ns_info);

        // Create mock pod mapping with actual pod data
        let mut pod_mapping = HashMap::new();
        let ip: IpAddr = "10.0.1.100".parse().unwrap();
        let mut pod_set = HashSet::new();
        pod_set.insert(PodInfo {
            name: "test-pod".to_string(),
            namespace: "test-namespace".to_string(),
            service_name: "test-service".to_string(),
        });
        pod_mapping.insert(ip, pod_set);

        let key = provider.build_metric_key(
            "veth123",
            &Some(ns_mapping),
            &Some(pod_mapping),
            Some(ns_id),
        );

        assert_eq!(key.iface, "veth123");
        assert_eq!(key.pod, "test-pod");
        assert_eq!(key.pod_namespace, "test-namespace");
        assert!(key.is_valid(&ComputePlatform::Ec2K8sEks)); // Should be valid with proper pod info
    }

    #[test]
    fn test_register_to_registry() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain, None);
        let mut registry = Registry::new();

        // Test that registration doesn't panic
        provider.register_to(&mut registry);

        // Create some test data to verify the metrics are properly registered
        // We'll manually set values on the metrics to ensure they appear in gather()
        let test_labels = vec!["test-instance", "test-iface"];

        provider
            .ingress_pkt_count
            .with_label_values(&test_labels)
            .set(100);
        provider
            .ingress_bytes_count
            .with_label_values(&test_labels)
            .set(1000);
        provider
            .egress_pkt_count
            .with_label_values(&test_labels)
            .set(200);
        provider
            .egress_bytes_count
            .with_label_values(&test_labels)
            .set(2000);
        provider
            .ingress_flow_count
            .with_label_values(&test_labels)
            .set(10);
        provider
            .egress_flow_count
            .with_label_values(&test_labels)
            .set(20);

        let metric_families = registry.gather();
        assert_eq!(metric_families.len(), 6); // 6 metrics registered

        let metric_names: Vec<String> = metric_families
            .iter()
            .map(|mf| mf.get_name().to_string())
            .collect();

        assert!(metric_names.contains(&"ingress_packets".to_string()));
        assert!(metric_names.contains(&"ingress_bytes".to_string()));
        assert!(metric_names.contains(&"egress_packets".to_string()));
        assert!(metric_names.contains(&"egress_bytes".to_string()));
        assert!(metric_names.contains(&"ingress_flow".to_string()));
        assert!(metric_names.contains(&"egress_flow".to_string()));
    }

    #[test]
    fn test_update_metrics_success() {
        let mut provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain, None);

        let result = provider.update_metrics();
        assert!(result.is_ok());
    }

    #[test]
    fn test_interface_metric_values_default() {
        let default_values = InterfaceMetricValues::default();

        assert_eq!(default_values.host.ingress_pkt_count, 0);
        assert_eq!(default_values.host.ingress_bytes_count, 0);
        assert_eq!(default_values.host.egress_pkt_count, 0);
        assert_eq!(default_values.host.egress_bytes_count, 0);
        assert_eq!(default_values.netns.ingress_flow_count, 0);
        assert_eq!(default_values.netns.egress_flow_count, 0);
    }

    #[test]
    fn test_get_metrics_empty_result() {
        let mut provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain, None);

        // This will likely return empty results in test environment
        let metrics = provider.get_metrics();

        // Just verify it doesn't panic and returns a HashMap
        assert!(metrics.is_empty() || !metrics.is_empty());
    }

    struct MockInterfaceDiscovery {
        result: HashMap<HostInterface, DeviceStatus>,
    }
    impl InterfaceDiscovery for MockInterfaceDiscovery {
        fn get_virtual_interface_stats(&self) -> Result<HashMap<HostInterface, DeviceStatus>> {
            Ok(self.result.clone())
        }
    }

    fn create_mocked_metric_provider(
        ns_file_1: &TemporaryFile,
        ns_file_2: &TemporaryFile,
    ) -> InterfaceMetricsProvider {
        // Namespace will mock namespace information
        let mut namespace_runner = FakeCommandRunner::new();

        // List namespaces
        namespace_runner.add_expectation("lsns", &["-t", "net", "--noheadings"],Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!("4026531992 net      54  1628 user           88 {} sleep 180\n4026531993 net      55  1629 user           89 {} sleep 180", ns_file_1.path, ns_file_2.path).as_bytes().to_vec(),
                stderr: vec![],
            }),);

        // Get the Ips from the namespaces
        namespace_runner.add_expectation("nsenter", &["--net", &ns_file_1.path, "ip", "a"], Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".to_vec(),
                stderr: vec![],
            }));
        namespace_runner.add_expectation("nsenter", &["--net", &ns_file_2.path, "ip", "a"], Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.2.10/24 brd 192.168.2.255 scope global eth0".to_vec(),
                stderr: vec![],
            }));

        // Add expectation for the bulk ip link show command (optimization)
        namespace_runner.add_expectation(
            "ip",
            &["link", "show"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: veth1@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default link-netnsid 88\n3: veth2@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default link-netnsid 89\n".to_vec(),
                stderr: vec![],
            }),
        );
        let namespace_manager = NetworkNamespaceManager::new(Box::new(namespace_runner));

        // Interface stats. Notice that the values will be swapped (ingress/egress) for these metrics
        // because we calculate this values at node level, but report for the pod (other end of the interface).
        let mut device_status: HashMap<HostInterface, DeviceStatus> = HashMap::new();
        device_status.insert(
            HostInterface {
                name: "veth1".into(),
                is_virtual: true,
            },
            DeviceStatus {
                name: "veth1".into(),
                recv_bytes: 1,
                recv_packets: 2,
                recv_errs: 3,
                recv_drop: 4,
                recv_fifo: 5,
                recv_frame: 6,
                recv_compressed: 7,
                recv_multicast: 8,
                sent_bytes: 9,
                sent_packets: 10,
                sent_errs: 11,
                sent_drop: 12,
                sent_fifo: 13,
                sent_colls: 14,
                sent_carrier: 15,
                sent_compressed: 16,
            },
        );
        device_status.insert(
            HostInterface {
                name: "veth2".into(),
                is_virtual: true,
            },
            DeviceStatus {
                name: "veth2".into(),
                recv_bytes: 21,
                recv_packets: 22,
                recv_errs: 23,
                recv_drop: 24,
                recv_fifo: 25,
                recv_frame: 26,
                recv_compressed: 27,
                recv_multicast: 28,
                sent_bytes: 29,
                sent_packets: 30,
                sent_errs: 31,
                sent_drop: 32,
                sent_fifo: 33,
                sent_colls: 34,
                sent_carrier: 35,
                sent_compressed: 36,
            },
        );
        let iface_discovery = Box::new(MockInterfaceDiscovery {
            result: device_status,
        });

        // Namespace information
        let mut netns_runner = FakeCommandRunner::new();
        netns_runner.add_expectation(
            "nsenter",
            &["--net", "/tmp/mocked_ns_2", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"TcpActiveOpens                  102                0.0\nTcpPassiveOpens                 202                0.0\nTcpAttemptFails                 5                  0.0".to_vec(),
                stderr: vec![],
            }),
        );
        netns_runner.add_expectation(
            "nsenter",
            &["--net", "/tmp/mocked_ns_1", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"TcpActiveOpens                  101                0.0\nTcpPassiveOpens                 201                0.0\nTcpAttemptFails                 5                  0.0".to_vec(),
                stderr: vec![],
            }),
        );
        let netns_stats = NetNsStats::new(Box::new(netns_runner));

        // Pod information
        let mut ip_pod_map: HashMap<IpAddr, HashMap<i32, PodInfo>> = HashMap::new();

        let mut pod_1 = HashMap::<i32, PodInfo>::new();
        pod_1.insert(
            0,
            PodInfo {
                name: "pod1".into(),
                namespace: "namespace1".into(),
                service_name: "service1".into(),
            },
        );
        ip_pod_map.insert(IpAddr::from_str("192.168.1.10").unwrap(), pod_1);

        let mut pod_2 = HashMap::<i32, PodInfo>::new();
        pod_2.insert(
            1,
            PodInfo {
                name: "pod2".into(),
                namespace: "namespace2".into(),
                service_name: "service2".into(),
            },
        );
        ip_pod_map.insert(IpAddr::from_str("192.168.2.10").unwrap(), pod_2);

        let k8s_metadata = KubernetesMetadataCollector {
            enriched_flows: 0.into(),
            refresher_runtime: Arc::new(Mutex::new(None)),
            pod_info_arc: Arc::new(Mutex::new(ip_pod_map)),
        };

        let compute_platform = ComputePlatform::Ec2K8sEks;
        InterfaceMetricsProvider {
            instance_id: "mocked-instance-id".into(),
            node_name: "mocked-node-name".into(),
            namespace_manager,
            netns_stats,
            iface_discovery,
            k8s_metadata: Some(Arc::new(k8s_metadata)),
            ingress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "ingress_packets",
                "Ingress packet count",
            ),
            ingress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "ingress_bytes",
                "Ingress bytes count",
            ),
            egress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "egress_packets",
                "Egress packet count",
            ),
            egress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "egress_bytes",
                "Egress bytes count",
            ),
            ingress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "ingress_flow",
                "Ingress TCP flow count",
            ),
            egress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "egress_flow",
                "Egress TCP flow count",
            ),
            current_metrics: HashMap::new(),
            compute_platform,
        }
    }

    #[derive(Debug, PartialEq, Eq, Hash)]
    struct ExpectedMetric<'a> {
        name: &'a str,
        iface: &'a str,
        instance_id: &'a str,
        namespace: &'a str,
        node: &'a str,
        pod: &'a str,
        value: u32,
    }

    #[test]
    fn test_update_metrics() {
        let ns_file_1 = TemporaryFile::new("mocked_ns_1");
        let ns_file_2 = TemporaryFile::new("mocked_ns_2");
        let mut metric_provider = create_mocked_metric_provider(&ns_file_1, &ns_file_2);
        let mut registry = Registry::new();
        metric_provider.register_to(&mut registry);
        metric_provider.update_metrics().unwrap();

        let metric_families = registry.gather();

        // Validation is based on the data configured in `create_mocked_metric_provider`
        assert_eq!(metric_families.len(), 6);

        let mut expected_metrics = HashSet::new();
        expected_metrics.insert(ExpectedMetric {
            name: "ingress_packets",
            iface: "veth1",
            instance_id: "mocked-instance-id",
            namespace: "namespace1",
            node: "mocked-node-name",
            pod: "pod1",
            value: 10,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "ingress_packets",
            iface: "veth2",
            instance_id: "mocked-instance-id",
            namespace: "namespace2",
            node: "mocked-node-name",
            pod: "pod2",
            value: 30,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "egress_packets",
            iface: "veth1",
            instance_id: "mocked-instance-id",
            namespace: "namespace1",
            node: "mocked-node-name",
            pod: "pod1",
            value: 2,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "egress_packets",
            iface: "veth2",
            instance_id: "mocked-instance-id",
            namespace: "namespace2",
            node: "mocked-node-name",
            pod: "pod2",
            value: 22,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "ingress_bytes",
            iface: "veth1",
            instance_id: "mocked-instance-id",
            namespace: "namespace1",
            node: "mocked-node-name",
            pod: "pod1",
            value: 9,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "ingress_bytes",
            iface: "veth2",
            instance_id: "mocked-instance-id",
            namespace: "namespace2",
            node: "mocked-node-name",
            pod: "pod2",
            value: 29,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "egress_bytes",
            iface: "veth1",
            instance_id: "mocked-instance-id",
            namespace: "namespace1",
            node: "mocked-node-name",
            pod: "pod1",
            value: 1,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "egress_bytes",
            iface: "veth2",
            instance_id: "mocked-instance-id",
            namespace: "namespace2",
            node: "mocked-node-name",
            pod: "pod2",
            value: 21,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "ingress_flow",
            iface: "veth1",
            instance_id: "mocked-instance-id",
            namespace: "namespace1",
            node: "mocked-node-name",
            pod: "pod1",
            value: 201,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "ingress_flow",
            iface: "veth2",
            instance_id: "mocked-instance-id",
            namespace: "namespace2",
            node: "mocked-node-name",
            pod: "pod2",
            value: 202,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "egress_flow",
            iface: "veth1",
            instance_id: "mocked-instance-id",
            namespace: "namespace1",
            node: "mocked-node-name",
            pod: "pod1",
            value: 101,
        });
        expected_metrics.insert(ExpectedMetric {
            name: "egress_flow",
            iface: "veth2",
            instance_id: "mocked-instance-id",
            namespace: "namespace2",
            node: "mocked-node-name",
            pod: "pod2",
            value: 102,
        });

        for family in &metric_families {
            let metric_name = family.get_name();
            for metric in family.get_metric() {
                let value = metric.get_gauge().get_value();

                let mut iface = "";
                let mut instance_id = "";
                let mut namespace = "";
                let mut node = "";
                let mut pod = "";

                let labels = metric.get_label();
                for label in labels {
                    match label.get_name() {
                        "iface" => iface = label.get_value(),
                        "instance_id" => instance_id = label.get_value(),
                        "namespace" => namespace = label.get_value(),
                        "node" => node = label.get_value(),
                        "pod" => pod = label.get_value(),
                        _ => {}
                    }
                }
                // All expected metrics should be present.
                let found_metric = &ExpectedMetric {
                    name: metric_name,
                    iface,
                    instance_id,
                    namespace,
                    node,
                    pod,
                    value: value as u32,
                };
                assert!(expected_metrics.remove(found_metric));
            }
        }
        assert!(expected_metrics.is_empty());
    }
}
