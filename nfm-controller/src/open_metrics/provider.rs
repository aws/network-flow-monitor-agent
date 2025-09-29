// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.

use prometheus::Registry;

use crate::{
    metadata::runtime_environment_metadata::ComputePlatform,
    open_metrics::providers::{
        interface_metrics_provider::InterfaceMetricsProvider,
        system_metrics_provider::SystemMetricsProvider,
    },
};

pub fn get_open_metric_providers(
    compute_platform: ComputePlatform,
) -> Vec<Box<dyn OpenMetricProvider>> {
    vec![
        Box::new(SystemMetricsProvider::new(&compute_platform)),
        Box::new(InterfaceMetricsProvider::new(&compute_platform)),
    ]
}

pub trait OpenMetricProvider {
    /// Registers the metrics provided by the object.
    fn register_to(&self, registry: &mut Registry);
    /// Updates the registered values with the new values.
    fn update_metrics(&mut self) -> Result<(), anyhow::Error>;
}
