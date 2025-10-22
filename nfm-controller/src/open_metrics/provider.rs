// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.

use prometheus::Registry;

use std::sync::Arc;

use crate::{
    kubernetes::kubernetes_metadata_collector::KubernetesMetadataCollector,
    metadata::runtime_environment_metadata::ComputePlatform,
    open_metrics::providers::{
        interface_metrics_provider::InterfaceMetricsProvider,
        system_metrics_provider::SystemMetricsProvider,
    },
};

pub fn get_open_metric_providers(
    compute_platform: ComputePlatform,
    k8s_collector: Option<Arc<KubernetesMetadataCollector>>,
) -> Vec<Box<dyn OpenMetricProvider>> {
    vec![
        Box::new(SystemMetricsProvider::new(&compute_platform)),
        Box::new(InterfaceMetricsProvider::new(
            &compute_platform,
            k8s_collector.clone(),
        )),
    ]
}

pub trait OpenMetricProvider {
    /// Registers the metrics provided by the object.
    fn register_to(&self, registry: &mut Registry);
    /// Updates the registered values with the new values.
    fn update_metrics(&mut self) -> Result<(), anyhow::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::runtime_environment_metadata::ComputePlatform;
    use std::sync::Arc;

    #[test]
    fn test_get_open_metric_providers_all_platforms() {
        let platforms = vec![
            ComputePlatform::Ec2Plain,
            ComputePlatform::Ec2K8sEks,
            ComputePlatform::Ec2K8sVanilla,
        ];

        for platform in platforms {
            let providers = get_open_metric_providers(platform.clone(), None);
            assert_eq!(providers.len(), 2, "Failed for platform: {:?}", platform);
            // Verify we get both SystemMetricsProvider and InterfaceMetricsProvider
        }
    }

    #[test]
    fn test_get_open_metric_providers_with_k8s_collector() {
        use crate::kubernetes::kubernetes_metadata_collector::KubernetesMetadataCollector;

        let compute_platform = ComputePlatform::Ec2K8sEks;
        let k8s_collector = Arc::new(KubernetesMetadataCollector::new());
        let providers = get_open_metric_providers(compute_platform, Some(k8s_collector));

        assert_eq!(providers.len(), 2);
        // Verify providers are created with k8s collector
    }

    #[test]
    fn test_providers_implement_trait() {
        let compute_platform = ComputePlatform::Ec2Plain;
        let mut providers = get_open_metric_providers(compute_platform, None);

        // Test that providers implement the trait methods
        let mut registry = Registry::new();

        for provider in &providers {
            provider.register_to(&mut registry);
        }

        // Test update_metrics doesn't panic
        for provider in &mut providers {
            let _ = provider.update_metrics();
        }
    }
}
