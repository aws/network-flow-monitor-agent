// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    metadata::runtime_environment_metadata::ComputePlatform,
    open_metrics::provider::OpenMetricProvider,
};
use anyhow;
use log::info;
use prometheus::{IntGaugeVec, Opts, Registry};

pub struct SystemMetricsProvider {
    compute_platform: ComputePlatform,

    ingress_flow_count: IntGaugeVec,
    ingress_pkt_count: IntGaugeVec,
    ingress_bytes_count: IntGaugeVec,

    egress_flow_count: IntGaugeVec,
    egress_pkt_count: IntGaugeVec,
    egress_bytes_count: IntGaugeVec,

    bw_in_allowance_exceeded: IntGaugeVec,
    bw_out_allowance_exceeded: IntGaugeVec,
    pps_allowance_exceeded: IntGaugeVec,
    conntrack_allowance_exceeded: IntGaugeVec,
}

impl SystemMetricsProvider {
    pub fn new(compute_platform: &ComputePlatform) -> Self {
        SystemMetricsProvider {
            compute_platform: compute_platform.clone(),

            ingress_flow_count: build_gauge_metric(
                compute_platform,
                "ingress_flow_count",
                "Ingress flow count",
            ),
            ingress_pkt_count: build_gauge_metric(
                compute_platform,
                "ingress_pkt_count",
                "Ingress packet count",
            ),
            ingress_bytes_count: build_gauge_metric(
                compute_platform,
                "ingress_bytes_count",
                "Ingress bytes count",
            ),

            egress_flow_count: build_gauge_metric(
                compute_platform,
                "egress_flow_count",
                "Egress flow count",
            ),
            egress_pkt_count: build_gauge_metric(
                compute_platform,
                "egress_pkt_count",
                "Egress packet count",
            ),
            egress_bytes_count: build_gauge_metric(
                compute_platform,
                "egress_bytes_count",
                "Egress bytes count",
            ),

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

    fn get_metrics(&self) -> Vec<SystemMetric> {
        vec![SystemMetric {
            key: SystemMetricKey {
                instance: "dummy-instance-id".into(),
                eni: "dummy-eni".into(),
                pod: "dummy-pod".into(),
                node: "dummy-node".into(),
            },
            value: SystemMetricValues {
                ingress_flow_count: 99,
                ingress_pkt_count: 0,
                ingress_bytes_count: 0,
                egress_flow_count: 0,
                egress_pkt_count: 0,
                egress_bytes_count: 0,
                bw_in_allowance_exceeded: 0,
                bw_out_allowance_exceeded: 0,
                pps_allowance_exceeded: 0,
                conntrack_allowance_exceeded: 0,
            },
        }]
    }

    fn update_ec2_metrics(&self) -> Result<(), anyhow::Error> {
        panic!("update_ec2_metrics not implemented")
    }

    fn update_eks_metrics(&self) -> Result<(), anyhow::Error> {
        panic!("update_eks_metrics not implemented")
    }
}

struct SystemMetric {
    key: SystemMetricKey,
    value: SystemMetricValues,
}

impl SystemMetric {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str] {
        match compute_platform {
            ComputePlatform::Ec2Plain => &["instance_id", "eni"],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => &["eni", "pod", "node"],
        }
    }

    fn label_values(&self, compute_platform: &ComputePlatform) -> Vec<&str> {
        match compute_platform {
            ComputePlatform::Ec2Plain => vec![&self.key.instance.as_str(), &self.key.eni.as_str()],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                vec![
                    &self.key.eni.as_str(),
                    &self.key.pod.as_str(),
                    &self.key.node.as_str(),
                ]
            }
        }
    }
}

/// Metric key. Pod and node will be availble only on EKS environments.
struct SystemMetricKey {
    instance: String,
    eni: String,
    pod: String,
    node: String,
}

struct SystemMetricValues {
    ingress_flow_count: u32,
    ingress_pkt_count: u32,
    ingress_bytes_count: u32,

    egress_flow_count: u32,
    egress_pkt_count: u32,
    egress_bytes_count: u32,

    bw_in_allowance_exceeded: u32,
    bw_out_allowance_exceeded: u32,
    pps_allowance_exceeded: u32,
    conntrack_allowance_exceeded: u32,
}

/// Open metric implementation. It will provide host level metrics annotated with
/// environment metadata.
impl OpenMetricProvider for SystemMetricsProvider {
    fn register(&self, registry: &mut Registry) {
        info!(platform = self.compute_platform.to_string(); "Registering System Metrics");

        registry
            .register(Box::new(self.ingress_flow_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.ingress_pkt_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.ingress_bytes_count.clone()))
            .unwrap();

        registry
            .register(Box::new(self.egress_flow_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.egress_pkt_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.egress_bytes_count.clone()))
            .unwrap();

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

    fn update_metrics(&self) -> Result<(), anyhow::Error> {
        info!(platform = self.compute_platform.to_string(); "Updating System Metrics");
        let metrics = self.get_metrics();

        for metric in &metrics {
            self.ingress_flow_count
                .with_label_values(&metric.label_values(&self.compute_platform))
                .set(metric.value.ingress_flow_count as i64);
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
