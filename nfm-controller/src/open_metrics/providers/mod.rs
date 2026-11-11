// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Providers for OpenMetrics/Prometheus metrics.

use std::collections::HashMap;

use prometheus::core::{Collector, Desc};
use prometheus::proto::{self, MetricFamily, MetricType};
use prometheus::{IntGaugeVec, Opts, Registry};

use crate::metadata::runtime_environment_metadata::ComputePlatform;
use crate::open_metrics::OpenMetricsMode;

pub mod efa_metrics_provider;
pub mod interface_metrics_provider;
pub mod system_metrics_provider;

pub trait MetricLabel {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str];
}

pub fn build_gauge_metric<T: MetricLabel>(
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

/// Registers a metric as a gauge in delta mode, or as a `<name>_total` counter in absolute mode.
pub fn register_metric(registry: &mut Registry, metric: &IntGaugeVec, mode: OpenMetricsMode) {
    match mode {
        OpenMetricsMode::Delta => registry.register(Box::new(metric.clone())).unwrap(),
        OpenMetricsMode::Absolute => registry
            .register(Box::new(CounterView::new(metric.clone())))
            .unwrap(),
    }
}

/// Exposes an `IntGaugeVec` holding cumulative values as a Prometheus counter.
///
/// The prometheus crate counters can only be incremented, while our values are read as totals
/// from the host, so they are stored in a gauge and converted when collected.
struct CounterView {
    desc: Desc,
    inner: IntGaugeVec,
}

impl CounterView {
    fn new(inner: IntGaugeVec) -> Self {
        let gauge_desc = inner.desc()[0];
        let desc = Desc::new(
            format!("{}_total", gauge_desc.fq_name),
            gauge_desc.help.clone(),
            gauge_desc.variable_labels.clone(),
            HashMap::new(),
        )
        .unwrap();
        Self { desc, inner }
    }
}

impl Collector for CounterView {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let mut families = self.inner.collect();
        for family in families.iter_mut() {
            family.set_name(self.desc.fq_name.clone());
            family.set_field_type(MetricType::COUNTER);
            for metric in family.mut_metric() {
                let mut counter = proto::Counter::default();
                counter.set_value(metric.get_gauge().value());
                metric.set_counter(counter);
                metric.gauge = Default::default();
            }
        }
        families
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Encoder, TextEncoder};

    struct TestLabel;
    impl MetricLabel for TestLabel {
        fn get_labels(_: &ComputePlatform) -> &[&str] {
            &["iface"]
        }
    }

    fn render(mode: OpenMetricsMode) -> String {
        let gauge = build_gauge_metric::<TestLabel>(&ComputePlatform::Ec2Plain, "rx_bytes", "help");
        gauge.with_label_values(&["eth0"]).set(42);

        let mut registry = Registry::new();
        register_metric(&mut registry, &gauge, mode);

        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buffer)
            .unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn test_register_metric_delta_is_gauge() {
        let text = render(OpenMetricsMode::Delta);
        assert!(text.contains("# TYPE rx_bytes gauge"), "{text}");
        assert!(text.contains("rx_bytes{iface=\"eth0\"} 42"), "{text}");
    }

    #[test]
    fn test_register_metric_absolute_is_counter() {
        let text = render(OpenMetricsMode::Absolute);
        assert!(text.contains("# TYPE rx_bytes_total counter"), "{text}");
        assert!(text.contains("rx_bytes_total{iface=\"eth0\"} 42"), "{text}");
        assert!(!text.contains("gauge"), "{text}");
    }
}
