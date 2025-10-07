// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Providers for OpenMetrics/Prometheus metrics.

use prometheus::{IntGaugeVec, Opts};

use crate::metadata::runtime_environment_metadata::ComputePlatform;

mod eks_utils;
pub mod interface_metrics_provider;
pub mod system_metrics_provider;

trait MetricLabel {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str];
}

fn build_gauge_metric<T: MetricLabel>(
    compute_platform: &ComputePlatform,
    metric_name: &str,
    description: &str,
) -> IntGaugeVec {
    IntGaugeVec::new(
        Opts::new(metric_name, description),
        T::get_labels(compute_platform),
    )
    .unwrap()
}
