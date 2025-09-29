// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{
    metadata::{
        imds_utils::retrieve_instance_id, k8s_metadata::K8sMetadata,
        runtime_environment_metadata::ComputePlatform,
    },
    open_metrics::{
        provider::OpenMetricProvider,
        providers::{build_gauge_metric, MetricLabel},
    },
    reports::report::ReportValue,
};
use anyhow;
use aws_config::imds::Client;
use getifaddrs::{getifaddrs, InterfaceFlags};
use log::{info, warn};
use procfs::net::{dev_status, DeviceStatus};
use prometheus::{IntGaugeVec, Registry};

/// Interface level metrics.
struct InterfaceMetric {
    key: InterfaceMetricKey,
    value: InterfaceMetricValues,
}

/// Metric key.
struct InterfaceMetricKey {
    instance: String,
    iface: String,
    pod: String,
    pod_namespace: String,
    node: String,
}

/// Values provided by the metrics.
struct InterfaceMetricValues {
    ingress_pkt_count: u64,
    ingress_bytes_count: u64,
    egress_pkt_count: u64,
    egress_bytes_count: u64,
}

impl InterfaceMetric {
    fn label_values(&self, compute_platform: &ComputePlatform) -> Vec<&str> {
        // The order of the elements must match the labels for the trait MetricLabel
        match compute_platform {
            ComputePlatform::Ec2Plain => {
                vec![&self.key.instance.as_str(), &self.key.iface.as_str()]
            }
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                vec![
                    &self.key.iface.as_str(),
                    &self.key.pod.as_str(),
                    &self.key.pod_namespace.as_str(),
                    &self.key.node.as_str(),
                ]
            }
        }
    }
}

impl MetricLabel for InterfaceMetric {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str] {
        match compute_platform {
            ComputePlatform::Ec2Plain => &["instance_id", "iface"],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                &["iface", "pod", "namespace", "node"]
            }
        }
    }
}

pub struct InterfaceMetricsProvider {
    compute_platform: ComputePlatform,
    instance_id: String,
    node_name: String,

    ingress_pkt_count: IntGaugeVec,
    ingress_bytes_count: IntGaugeVec,
    egress_pkt_count: IntGaugeVec,
    egress_bytes_count: IntGaugeVec,
}

impl InterfaceMetricsProvider {
    pub fn new(compute_platform: &ComputePlatform) -> Self {
        let node_name = match K8sMetadata::default().node_name {
            Some(ReportValue::String(node_name)) => node_name,
            _ => "unknown".to_string(),
        };

        InterfaceMetricsProvider {
            compute_platform: compute_platform.clone(),
            instance_id: retrieve_instance_id(&Client::builder().build()),
            node_name,

            ingress_pkt_count: build_gauge_metric::<InterfaceMetric>(
                &compute_platform,
                "ingress_pkt_count",
                "Ingress packet count",
            ),
            ingress_bytes_count: build_gauge_metric::<InterfaceMetric>(
                &compute_platform,
                "ingress_bytes_count",
                "Ingress bytes count",
            ),
            egress_pkt_count: build_gauge_metric::<InterfaceMetric>(
                &compute_platform,
                "egress_pkt_count",
                "Egress packet count",
            ),
            egress_bytes_count: build_gauge_metric::<InterfaceMetric>(
                &compute_platform,
                "egress_bytes_count",
                "Egress bytes count",
            ),
        }
    }

    fn get_metrics(&mut self) -> Vec<InterfaceMetric> {
        get_device_status()
            .iter()
            .map(|(interface_name, interface_stats)| InterfaceMetric {
                key: self.build_metric_key(interface_name),
                value: InterfaceMetricValues {
                    ingress_pkt_count: interface_stats.recv_packets,
                    ingress_bytes_count: interface_stats.recv_bytes,
                    egress_pkt_count: interface_stats.sent_packets,
                    egress_bytes_count: interface_stats.sent_bytes,
                },
            })
            .collect()
    }

    fn build_metric_key(&self, iface_name: &String) -> InterfaceMetricKey {
        let (pod, pod_namespace) = get_pod_info_from_iface(iface_name);
        InterfaceMetricKey {
            instance: self.instance_id.clone(),
            iface: iface_name.to_string(),
            pod,
            pod_namespace,
            node: self.node_name.clone(),
        }
    }
}

fn get_device_status() -> HashMap<String, DeviceStatus> {
    // Get interface statistics from procfs
    let interfaces = match dev_status() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            warn!(
                "Failed to read network interface statistics from procfs: {}",
                e
            );
            HashMap::new()
        }
    };

    let interface_flags = match get_interface_flags() {
        Ok(flags) => flags,
        Err(e) => {
            warn!("Failed to get interface flags using getifaddrs: {}", e);
            HashMap::new()
        }
    };

    interfaces
        .into_iter()
        .filter(|(iface_name, _device_status)| {
            if let Some(flags) = interface_flags.get(iface_name) {
                if flags.contains(InterfaceFlags::LOOPBACK) {
                    info!("Skipping loopback");
                    return false;
                }

                if !flags.contains(InterfaceFlags::UP) {
                    info!("Skipping non UP iface");
                    return false;
                }
            } else {
                info!("Interface not found {}", iface_name)
            }

            true
        })
        .collect()
}

/// Get interface flags using getifaddrs
fn get_interface_flags() -> Result<HashMap<String, InterfaceFlags>, Box<dyn std::error::Error>> {
    let mut interface_flags = HashMap::new();

    let ifaddrs = getifaddrs()?;
    for interface in ifaddrs {
        interface_flags.insert(interface.name, interface.flags);
    }

    Ok(interface_flags)
}

fn get_pod_info_from_iface(_iface_name: &String) -> (String, String) {
    ("pod_name".to_string(), "pod_namespace".to_string())
}

/// Open metric implementation. It will provide interface level metrics annotated with
/// environment and kubernetes metadata.
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
    }

    fn update_metrics(&mut self) -> Result<(), anyhow::Error> {
        info!(platform = self.compute_platform.to_string(); "Updating Interface Metrics");
        let metrics = self.get_metrics();

        for metric in &metrics {
            let label_values = metric.label_values(&self.compute_platform);

            self.ingress_bytes_count
                .with_label_values(&label_values)
                .set(metric.value.ingress_bytes_count as i64);
            self.ingress_pkt_count
                .with_label_values(&label_values)
                .set(metric.value.ingress_pkt_count as i64);
            self.egress_bytes_count
                .with_label_values(&label_values)
                .set(metric.value.egress_bytes_count as i64);
            self.egress_pkt_count
                .with_label_values(&label_values)
                .set(metric.value.egress_pkt_count as i64);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::runtime_environment_metadata::ComputePlatform;

    #[test]
    fn test_interface_metrics_provider_new() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain);
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2Plain);
        assert_eq!(provider.node_name, "unknown"); // Default when K8s metadata is not available
    }

    #[test]
    fn test_interface_metrics_provider_new_eks() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2K8sEks);
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2K8sEks);
    }

    #[test]
    fn test_interface_metric_get_labels_ec2_plain() {
        let labels = InterfaceMetric::get_labels(&ComputePlatform::Ec2Plain);
        assert_eq!(labels, &["instance_id", "iface"]);
    }

    #[test]
    fn test_interface_metric_get_labels_eks() {
        let labels = InterfaceMetric::get_labels(&ComputePlatform::Ec2K8sEks);
        assert_eq!(labels, &["iface", "pod", "namespace", "node"]);
    }

    #[test]
    fn test_interface_metric_label_values_ec2_plain() {
        let metric = InterfaceMetric {
            key: InterfaceMetricKey {
                instance: "i-1234567890abcdef0".to_string(),
                iface: "eth0".to_string(),
                pod: "".to_string(),
                pod_namespace: "".to_string(),
                node: "test-node".to_string(),
            },
            value: InterfaceMetricValues {
                ingress_pkt_count: 100,
                ingress_bytes_count: 1000,
                egress_pkt_count: 200,
                egress_bytes_count: 2000,
            },
        };

        let label_values = metric.label_values(&ComputePlatform::Ec2Plain);
        assert_eq!(label_values, vec!["i-1234567890abcdef0", "eth0"]);
    }

    #[test]
    fn test_interface_metric_label_values_eks() {
        let metric = InterfaceMetric {
            key: InterfaceMetricKey {
                instance: "i-1234567890abcdef0".to_string(),
                iface: "eth0".to_string(),
                pod: "test-pod".to_string(),
                pod_namespace: "default".to_string(),
                node: "test-node".to_string(),
            },
            value: InterfaceMetricValues {
                ingress_pkt_count: 100,
                ingress_bytes_count: 1000,
                egress_pkt_count: 200,
                egress_bytes_count: 2000,
            },
        };

        let label_values = metric.label_values(&ComputePlatform::Ec2K8sEks);
        assert_eq!(
            label_values,
            vec!["eth0", "test-pod", "default", "test-node"]
        );
    }

    #[test]
    fn test_get_metrics_returns_vector() {
        let mut provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain);
        let metrics = provider.get_metrics();
        // Should return a vector (may be empty if no interfaces are available in test environment)
        panic!("Implement test")
    }
}
