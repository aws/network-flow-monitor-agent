// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    events::host_stats_provider::{HostStatsProvider, HostStatsProviderImpl},
    metadata::{
        eni::EniMetadataProvider, k8s_metadata::K8sMetadata,
        runtime_environment_metadata::ComputePlatform,
    },
    open_metrics::provider::OpenMetricProvider,
    reports::report::ReportValue,
};
use anyhow;
use log::info;
use prometheus::{IntGaugeVec, Opts, Registry};

/// System level metrics.
struct SystemMetric {
    key: SystemMetricKey,
    value: SystemMetricValues,
}

/// Metric key. Pod and node will be availble only on EKS environments.
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
            node_name: node_name,

            bw_in_allowance_exceeded: build_gauge_metric(
                compute_platform,
                "bw_in_allowance_exceeded",
                "The number of packets queued or dropped because the inbound aggregate bandwidth exceeded the maximum for the instance.",
            ),
            bw_out_allowance_exceeded: build_gauge_metric(
                compute_platform,
                "bw_out_allowance_exceeded",
                "The number of packets queued or dropped because the outbound aggregate bandwidth exceeded the maximum for the instance."
            ),
            pps_allowance_exceeded: build_gauge_metric(&compute_platform, "pps_allowance_exceeded", "The number of packets queued or dropped because the bidirectional PPS exceeded the maximum for the instance."),
            conntrack_allowance_exceeded: build_gauge_metric(
                &compute_platform,
                "conntrack_allowance_exceeded",
                "The number of packets dropped because connection tracking exceeded the maximum for the instance and new connections could not be established. This can result in packet loss for traffic to or from the instance."
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
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => &["eni", "node"],
        }
    }

    fn label_values(&self, compute_platform: &ComputePlatform) -> Vec<&str> {
        // The order of the elements must match the labels in SystemMetric::get_labels
        match compute_platform {
            ComputePlatform::Ec2Plain => vec![&self.key.instance.as_str(), &self.key.eni.as_str()],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                vec![&self.key.eni.as_str(), &self.key.node.as_str()]
            }
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
        }

        Ok(())
    }
}

fn build_gauge_metric(
    compute_platform: &ComputePlatform,
    metric_name: &str,
    description: &str,
) -> IntGaugeVec {
    IntGaugeVec::new(
        Opts::new(metric_name, description),
        SystemMetric::get_labels(compute_platform),
    )
    .unwrap()
}
