// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.
//!
//! This module provides a basic HTTP server that returns a fixed dummy metric
//! in Prometheus format on the /metrics endpoint.

use prometheus::{GaugeVec, Opts, Registry};
use std::cell::RefCell;

pub trait OpenMetricProvider {
    /// Registers the metrics provided
    fn register(&self, registry: &mut Registry);
    /// Updates the metrics registered.
    fn update_metrics(&self) -> Result<(), anyhow::Error>;
}

pub fn get_open_metric_providers() -> Vec<Box<dyn OpenMetricProvider>> {
    vec![Box::new(DummyOpenMetricProvider::new())]
}

pub struct DummyOpenMetricProvider {
    gauge: RefCell<Option<GaugeVec>>,
    counter: RefCell<Option<GaugeVec>>, // Using GaugeVec for simplicity, could be CounterVec in real usage
}

impl DummyOpenMetricProvider {
    pub fn new() -> Self {
        DummyOpenMetricProvider {
            gauge: RefCell::new(None),
            counter: RefCell::new(None),
        }
    }
}

impl OpenMetricProvider for DummyOpenMetricProvider {
    fn register(&self, registry: &mut Registry) {
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
        let counter = GaugeVec::new(
            Opts::new(
                "nfm_request_count",
                "A sample counter metric with labels for NFM agent",
            ),
            &["endpoint", "status"],
        )
        .unwrap();

        // Register the metrics with the registry
        registry.register(Box::new(gauge.clone())).unwrap();
        registry.register(Box::new(counter.clone())).unwrap();

        // Store the metrics in self
        *self.gauge.borrow_mut() = Some(gauge);
        *self.counter.borrow_mut() = Some(counter);
    }

    fn update_metrics(&self) -> Result<(), anyhow::Error> {
        // Update gauge metric
        if let Some(gauge) = &*self.gauge.borrow() {
            // Set the metric value with two labels
            gauge
                .with_label_values(&["nfm-agent", "development"])
                .set(42.0);
        }

        // Update counter metric
        if let Some(counter) = &*self.counter.borrow() {
            // Set counter values with different label combinations
            counter
                .with_label_values(&["metrics", "success"])
                .set(100.0);
            counter.with_label_values(&["health", "success"]).set(50.0);
            counter.with_label_values(&["metrics", "error"]).set(5.0);
        }

        Ok(())
    }
}
