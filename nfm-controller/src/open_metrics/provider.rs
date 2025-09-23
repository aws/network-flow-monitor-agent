// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.

use prometheus::{CounterVec, GaugeVec, Opts, Registry};

use crate::{
    metadata::runtime_environment_metadata::ComputePlatform,
    open_metrics::providers::system_metrics_provider::SystemMetricsProvider,
};

pub fn get_open_metric_providers(
    compute_platform: ComputePlatform,
) -> Vec<Box<dyn OpenMetricProvider>> {
    vec![
        Box::new(DummyOpenMetricProvider::new()),
        Box::new(SystemMetricsProvider::new(&compute_platform)),
    ]
}

pub trait OpenMetricProvider {
    /// Registers the metrics provided by the object.
    fn register_to(&self, registry: &mut Registry);
    /// Updates the registered values with the new values.
    fn update_metrics(&self) -> Result<(), anyhow::Error>;
}

/// Dummy metric provider as an example to integrate with the prometheus client
/// No tests since will be removed later.
pub struct DummyOpenMetricProvider {
    gauge: GaugeVec,
    counter: CounterVec,
}

impl DummyOpenMetricProvider {
    pub fn new() -> Self {
        // Create a gauge with two labels
        let gauge = GaugeVec::new(
            Opts::new(
                "nfm_sample_metric",
                "A sample metric with labels for NFM agent",
            ),
            &["service", "environment"],
        )
        .unwrap();

        // Create a counter with two different labels
        let counter = CounterVec::new(
            Opts::new(
                "nfm_request_count",
                "A sample counter metric with labels for NFM agent",
            ),
            &["increment_by"],
        )
        .unwrap();

        DummyOpenMetricProvider {
            gauge: gauge,
            counter: counter,
        }
    }
}

impl OpenMetricProvider for DummyOpenMetricProvider {
    fn register_to(&self, registry: &mut Registry) {
        // Register the metrics with the registry
        registry.register(Box::new(self.gauge.clone())).unwrap();
        registry.register(Box::new(self.counter.clone())).unwrap();
    }

    fn update_metrics(&self) -> Result<(), anyhow::Error> {
        // Update gauge metric
        self.gauge
            .with_label_values(&["nfm-agent", "development"])
            .set(42.0);
        // Update counter metric
        self.counter.with_label_values(&["one"]).inc();
        self.counter.with_label_values(&["two"]).inc_by(2.0);

        Ok(())
    }
}
