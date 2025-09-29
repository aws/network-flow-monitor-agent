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
use prometheus::{IntGaugeVec, Opts, Registry};

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

pub struct InterfaceMetricsProvider {
    compute_platform: ComputePlatform,
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
        // 1 - Get interfaces
        // 2 - Get pod information from curl -s http://localhost:61679/v1/enis
        // 3 - Find each PID per interface using lsns -t
        // 4 - Get the metrics per interface using nsenter -t <PID> -n ip a

        //
        vec![]
    }
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
mod tests {}
