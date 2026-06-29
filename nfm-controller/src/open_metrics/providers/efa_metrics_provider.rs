// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::{
    kubernetes::efa_pod_resources::EfaDeviceToPodMap,
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
use aws_config::imds::Client;
use log::{debug, info, warn};
use prometheus::{IntGaugeVec, Registry};

const INFINIBAND_SYSFS_PATH: &str = "/sys/class/infiniband";
const PORTS_SUBDIR: &str = "ports";
const HW_COUNTERS_DIR: &str = "hw_counters";

const STANDARD_METRICS: &[(&str, &str)] = &[
    (
        "efa_tx_bytes",
        "Bytes transmitted via EFA device since last scrape",
    ),
    (
        "efa_rx_bytes",
        "Bytes received via EFA device since last scrape",
    ),
    (
        "efa_tx_pkts",
        "Packets transmitted via EFA device since last scrape",
    ),
    (
        "efa_rx_pkts",
        "Packets received via EFA device since last scrape",
    ),
    (
        "efa_rx_drops",
        "Receive drops on EFA device since last scrape",
    ),
    (
        "efa_send_bytes",
        "RDMA send bytes on EFA device since last scrape",
    ),
    (
        "efa_recv_bytes",
        "RDMA recv bytes on EFA device since last scrape",
    ),
    (
        "efa_send_wrs",
        "RDMA send work requests on EFA device since last scrape",
    ),
    (
        "efa_recv_wrs",
        "RDMA recv work requests on EFA device since last scrape",
    ),
    (
        "efa_rdma_read_wrs",
        "RDMA read work requests on EFA device since last scrape",
    ),
    (
        "efa_rdma_read_bytes",
        "RDMA read bytes on EFA device since last scrape",
    ),
    (
        "efa_rdma_write_wrs",
        "RDMA write work requests on EFA device since last scrape",
    ),
    (
        "efa_rdma_write_bytes",
        "RDMA write bytes on EFA device since last scrape",
    ),
    (
        "efa_rdma_read_wr_err",
        "RDMA read work request errors on EFA device since last scrape",
    ),
    (
        "efa_rdma_write_wr_err",
        "RDMA write work request errors on EFA device since last scrape",
    ),
    (
        "efa_rdma_read_resp_bytes",
        "RDMA read response bytes on EFA device since last scrape",
    ),
    (
        "efa_rdma_write_recv_bytes",
        "RDMA write received bytes on EFA device since last scrape",
    ),
];

const SRD_METRICS: &[(&str, &str)] = &[
    (
        "efa_retrans_bytes",
        "SRD retransmitted bytes on EFA device since last scrape (Nitro v4+)",
    ),
    (
        "efa_retrans_pkts",
        "SRD retransmitted packets on EFA device since last scrape (Nitro v4+)",
    ),
    (
        "efa_retrans_timeout_events",
        "SRD retransmission timeout events on EFA device since last scrape (Nitro v4+)",
    ),
    (
        "efa_impaired_remote_conn_events",
        "Impaired remote connection events on EFA device since last scrape (Nitro v4+)",
    ),
    (
        "efa_unresponsive_remote_events",
        "Unresponsive remote events on EFA device since last scrape (Nitro v4+)",
    ),
];

struct EfaMetric;

impl MetricLabel for EfaMetric {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str] {
        match compute_platform {
            ComputePlatform::Ec2Plain => &["instance_id", "device", "port"],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                &["instance_id", "device", "port", "node", "pod", "namespace"]
            }
        }
    }
}

pub struct EfaMetricsProvider {
    compute_platform: ComputePlatform,
    instance_id: String,
    node_name: String,
    sysfs_base: PathBuf,

    standard_gauges: Vec<IntGaugeVec>,
    srd_gauges: Vec<IntGaugeVec>,
    srd_available: bool,

    /// Cached previous sysfs counter values per (device, metric_index).
    /// Used to compute per-scrape deltas via wrapping_sub.
    previous_values: HashMap<String, Vec<u64>>,

    /// Shared mapping from EFA device IDs to pod info, populated by the
    /// EfaPodResourcesWatcher when the EFA device plugin is present.
    device_to_pod_map: Option<Arc<Mutex<EfaDeviceToPodMap>>>,
}

impl EfaMetricsProvider {
    pub fn efa_devices_present() -> bool {
        Self::efa_devices_present_at(Path::new(INFINIBAND_SYSFS_PATH))
    }

    fn efa_devices_present_at(path: &Path) -> bool {
        match fs::read_dir(path) {
            Ok(entries) => entries.into_iter().any(|e| e.is_ok()),
            Err(_) => false,
        }
    }

    pub fn new(
        compute_platform: &ComputePlatform,
        device_to_pod_map: Option<Arc<Mutex<EfaDeviceToPodMap>>>,
    ) -> Self {
        Self::with_sysfs_base(
            compute_platform,
            PathBuf::from(INFINIBAND_SYSFS_PATH),
            device_to_pod_map,
        )
    }

    fn with_sysfs_base(
        compute_platform: &ComputePlatform,
        sysfs_base: PathBuf,
        device_to_pod_map: Option<Arc<Mutex<EfaDeviceToPodMap>>>,
    ) -> Self {
        let node_name = match K8sMetadata::default().node_name {
            Some(ReportValue::String(node_name)) => node_name,
            _ => "unknown".to_string(),
        };

        let srd_available = Self::detect_srd_support(&sysfs_base);

        let standard_gauges = STANDARD_METRICS
            .iter()
            .map(|(name, desc)| build_gauge_metric::<EfaMetric>(compute_platform, name, desc))
            .collect();

        let srd_gauges = if srd_available {
            SRD_METRICS
                .iter()
                .map(|(name, desc)| build_gauge_metric::<EfaMetric>(compute_platform, name, desc))
                .collect()
        } else {
            Vec::new()
        };

        let mut provider = EfaMetricsProvider {
            compute_platform: compute_platform.clone(),
            instance_id: retrieve_instance_id(&Client::builder().build()),
            node_name,
            sysfs_base,
            standard_gauges,
            srd_gauges,
            srd_available,
            previous_values: HashMap::new(),
            device_to_pod_map,
        };

        // Seed the cache with current sysfs values so the first scrape produces
        // clean deltas instead of a large historical spike.
        provider.seed_cache();
        provider
    }

    fn total_metrics_count(&self) -> usize {
        STANDARD_METRICS.len()
            + if self.srd_available {
                SRD_METRICS.len()
            } else {
                0
            }
    }

    fn seed_cache(&mut self) {
        for (device, port) in self.discover_device_ports() {
            let key = cache_key(&device, &port);
            let values = self.read_all_counters(&device, &port);
            self.previous_values.insert(key, values);
        }
    }

    fn read_all_counters(&self, device: &str, port: &str) -> Vec<u64> {
        let mut values = Vec::with_capacity(self.total_metrics_count());

        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            values.push(self.read_counter(device, port, sysfs_name).unwrap_or(0));
        }

        if self.srd_available {
            for (metric_name, _) in SRD_METRICS {
                let sysfs_name = strip_efa_prefix(metric_name);
                values.push(self.read_counter(device, port, sysfs_name).unwrap_or(0));
            }
        }

        values
    }

    fn detect_srd_support(sysfs_base: &Path) -> bool {
        let Ok(devices) = fs::read_dir(sysfs_base) else {
            return false;
        };

        let first_srd_metric = strip_efa_prefix(SRD_METRICS[0].0);
        for device_entry in devices.flatten() {
            let ports_path = device_entry.path().join(PORTS_SUBDIR);
            let Ok(ports) = fs::read_dir(&ports_path) else {
                continue;
            };
            for port_entry in ports.flatten() {
                let counters_path = port_entry.path().join(HW_COUNTERS_DIR);
                if counters_path.join(first_srd_metric).exists() {
                    return true;
                }
            }
        }
        false
    }

    fn discover_device_ports(&self) -> Vec<(String, String)> {
        let Ok(devices) = fs::read_dir(&self.sysfs_base) else {
            warn!("Failed to read EFA devices from {:?}", self.sysfs_base);
            return Vec::new();
        };

        let mut result = Vec::new();
        for device_entry in devices.flatten() {
            let device_name = match device_entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };
            let ports_path = device_entry.path().join(PORTS_SUBDIR);
            let Ok(ports) = fs::read_dir(&ports_path) else {
                continue;
            };
            for port_entry in ports.flatten() {
                let port_name = match port_entry.file_name().into_string() {
                    Ok(name) => name,
                    Err(_) => continue,
                };
                let counters_path = port_entry.path().join(HW_COUNTERS_DIR);
                if counters_path.is_dir() {
                    result.push((device_name.clone(), port_name));
                }
            }
        }
        result
    }

    fn read_counter(&self, device: &str, port: &str, metric_name: &str) -> Option<u64> {
        let path = self
            .sysfs_base
            .join(device)
            .join(PORTS_SUBDIR)
            .join(port)
            .join(HW_COUNTERS_DIR)
            .join(metric_name);

        match fs::read_to_string(&path) {
            Ok(content) => match content.trim().parse::<u64>() {
                Ok(value) => Some(value),
                Err(e) => {
                    warn!("Failed to parse EFA metric {:?}: {}", path, e);
                    None
                }
            },
            Err(e) => {
                debug!("Failed to read EFA metric {:?}: {}", path, e);
                None
            }
        }
    }

    fn label_values(&self, device: &str, port: &str) -> Vec<String> {
        match self.compute_platform {
            ComputePlatform::Ec2Plain => {
                vec![self.instance_id.clone(), device.to_string(), port.to_string()]
            }
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                let (pod_name, pod_namespace) = self.resolve_pod_for_device(device);
                vec![
                    self.instance_id.clone(),
                    device.to_string(),
                    port.to_string(),
                    self.node_name.clone(),
                    pod_name,
                    pod_namespace,
                ]
            }
        }
    }

    fn resolve_pod_for_device(&self, device: &str) -> (String, String) {
        let Some(map_arc) = &self.device_to_pod_map else {
            return ("unknown".to_string(), "unknown".to_string());
        };
        let map = map_arc.lock().unwrap();
        map.get(device)
            .map(|info| (info.pod_name.clone(), info.pod_namespace.clone()))
            .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()))
    }
}

fn strip_efa_prefix(prefixed_name: &str) -> &str {
    prefixed_name.strip_prefix("efa_").unwrap_or(prefixed_name)
}

fn cache_key(device: &str, port: &str) -> String {
    format!("{}/{}", device, port)
}

/// Computes the delta between two counter readings. If the counter appears to
/// have reset (current < previous), returns the current value assuming the
/// counter restarted from 0.
fn compute_delta(current: u64, previous: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

impl OpenMetricProvider for EfaMetricsProvider {
    fn register_to(&self, registry: &mut Registry) {
        info!(
            platform = self.compute_platform.to_string(),
            srd_available = self.srd_available;
            "Registering EFA Metrics"
        );

        for gauge in &self.standard_gauges {
            registry
                .register(Box::new(gauge.clone()))
                .expect("EFA metric registration");
        }

        for gauge in &self.srd_gauges {
            registry
                .register(Box::new(gauge.clone()))
                .expect("EFA metric registration");
        }
    }

    fn update_metrics(&mut self) -> Result<(), anyhow::Error> {
        let device_ports = self.discover_device_ports();
        let active_keys: Vec<String> = device_ports.iter().map(|(d, p)| cache_key(d, p)).collect();

        // Remove stale entries for device/port combos that no longer exist.
        self.previous_values.retain(|k, _| active_keys.contains(k));

        for (device, port) in &device_ports {
            let key = cache_key(device, port);
            let current_values = self.read_all_counters(device, port);
            let previous = self
                .previous_values
                .get(&key)
                .cloned()
                .unwrap_or_else(|| vec![0; self.total_metrics_count()]);

            let label_values = self.label_values(device, port);
            let label_refs: Vec<&str> = label_values.iter().map(|s| s.as_str()).collect();

            for (i, _) in STANDARD_METRICS.iter().enumerate() {
                let delta = compute_delta(current_values[i], previous[i]);
                self.standard_gauges[i]
                    .with_label_values(&label_refs)
                    .set(delta as i64);
            }

            if self.srd_available {
                let offset = STANDARD_METRICS.len();
                for (i, _) in SRD_METRICS.iter().enumerate() {
                    let delta = compute_delta(current_values[offset + i], previous[offset + i]);
                    self.srd_gauges[i]
                        .with_label_values(&label_refs)
                        .set(delta as i64);
                }
            }

            self.previous_values.insert(key, current_values);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::Registry;
    use std::fs;
    use tempfile::TempDir;

    const TEST_PORT: &str = "1";

    fn hw_counters_path(base: &Path, device: &str, port: &str) -> PathBuf {
        base.join(device)
            .join(PORTS_SUBDIR)
            .join(port)
            .join(HW_COUNTERS_DIR)
    }

    fn create_mock_sysfs(with_srd: bool) -> TempDir {
        let tmp = TempDir::new().unwrap();
        let counters = hw_counters_path(tmp.path(), "rdmap0s31", TEST_PORT);
        fs::create_dir_all(&counters).unwrap();

        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            fs::write(counters.join(sysfs_name), "42\n").unwrap();
        }

        if with_srd {
            for (metric_name, _) in SRD_METRICS {
                let sysfs_name = strip_efa_prefix(metric_name);
                fs::write(counters.join(sysfs_name), "7\n").unwrap();
            }
        }

        tmp
    }

    fn create_provider_with_mock(tmp: &TempDir, platform: ComputePlatform) -> EfaMetricsProvider {
        create_provider_with_mock_and_pod_map(tmp, platform, None)
    }

    fn create_provider_with_mock_and_pod_map(
        tmp: &TempDir,
        platform: ComputePlatform,
        device_to_pod_map: Option<Arc<Mutex<EfaDeviceToPodMap>>>,
    ) -> EfaMetricsProvider {
        let sysfs_base = tmp.path().to_path_buf();
        let srd_available = EfaMetricsProvider::detect_srd_support(&sysfs_base);

        let standard_gauges = STANDARD_METRICS
            .iter()
            .map(|(name, desc)| build_gauge_metric::<EfaMetric>(&platform, name, desc))
            .collect();

        let srd_gauges = if srd_available {
            SRD_METRICS
                .iter()
                .map(|(name, desc)| build_gauge_metric::<EfaMetric>(&platform, name, desc))
                .collect()
        } else {
            Vec::new()
        };

        let mut provider = EfaMetricsProvider {
            compute_platform: platform,
            instance_id: "i-1234567890abcdef0".to_string(),
            node_name: "test-node".to_string(),
            sysfs_base,
            standard_gauges,
            srd_gauges,
            srd_available,
            previous_values: HashMap::new(),
            device_to_pod_map,
        };

        provider.seed_cache();
        provider
    }

    fn write_counters(tmp: &TempDir, device: &str, standard_val: u64, srd_val: Option<u64>) {
        let counters = hw_counters_path(tmp.path(), device, TEST_PORT);
        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            fs::write(counters.join(sysfs_name), format!("{}\n", standard_val)).unwrap();
        }
        if let Some(val) = srd_val {
            for (metric_name, _) in SRD_METRICS {
                let sysfs_name = strip_efa_prefix(metric_name);
                fs::write(counters.join(sysfs_name), format!("{}\n", val)).unwrap();
            }
        }
    }

    #[test]
    fn test_efa_devices_present_with_devices() {
        let tmp = create_mock_sysfs(false);
        assert!(EfaMetricsProvider::efa_devices_present_at(tmp.path()));
    }

    #[test]
    fn test_efa_devices_present_empty_dir() {
        let tmp = TempDir::new().unwrap();
        assert!(!EfaMetricsProvider::efa_devices_present_at(tmp.path()));
    }

    #[test]
    fn test_efa_devices_present_no_dir() {
        assert!(!EfaMetricsProvider::efa_devices_present_at(Path::new(
            "/nonexistent/path"
        )));
    }

    #[test]
    fn test_detect_srd_support_present() {
        let tmp = create_mock_sysfs(true);
        assert!(EfaMetricsProvider::detect_srd_support(tmp.path()));
    }

    #[test]
    fn test_detect_srd_support_absent() {
        let tmp = create_mock_sysfs(false);
        assert!(!EfaMetricsProvider::detect_srd_support(tmp.path()));
    }

    #[test]
    fn test_discover_device_ports() {
        let tmp = create_mock_sysfs(false);
        let provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let device_ports = provider.discover_device_ports();
        assert_eq!(
            device_ports,
            vec![("rdmap0s31".to_string(), "1".to_string())]
        );
    }

    #[test]
    fn test_read_counter_success() {
        let tmp = create_mock_sysfs(false);
        let provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let value = provider.read_counter("rdmap0s31", TEST_PORT, "tx_bytes");
        assert_eq!(value, Some(42));
    }

    #[test]
    fn test_read_counter_missing_file() {
        let tmp = create_mock_sysfs(false);
        let provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let value = provider.read_counter("rdmap0s31", TEST_PORT, "nonexistent_metric");
        assert_eq!(value, None);
    }

    #[test]
    fn test_register_standard_metrics_only() {
        let tmp = create_mock_sysfs(false);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);
        let _ = provider.update_metrics();

        let metric_families = registry.gather();
        assert_eq!(metric_families.len(), STANDARD_METRICS.len());
    }

    #[test]
    fn test_register_with_srd_metrics() {
        let tmp = create_mock_sysfs(true);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);
        let _ = provider.update_metrics();

        let metric_families = registry.gather();
        assert_eq!(
            metric_families.len(),
            STANDARD_METRICS.len() + SRD_METRICS.len()
        );
    }

    #[test]
    fn test_first_scrape_returns_zero_delta() {
        let tmp = create_mock_sysfs(false);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let result = provider.update_metrics();
        assert!(result.is_ok());

        let metric_families = registry.gather();
        for mf in &metric_families {
            for metric in mf.get_metric() {
                assert_eq!(
                    metric.get_gauge().get_value(),
                    0.0,
                    "First scrape should return 0 delta for {}",
                    mf.get_name()
                );
            }
        }
    }

    #[test]
    fn test_delta_after_counter_increment() {
        let tmp = create_mock_sysfs(false);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let _ = provider.update_metrics();

        write_counters(&tmp, "rdmap0s31", 100, None);

        let _ = provider.update_metrics();
        let metric_families = registry.gather();
        for mf in &metric_families {
            for metric in mf.get_metric() {
                assert_eq!(
                    metric.get_gauge().get_value(),
                    58.0,
                    "Delta should be 58 for {}",
                    mf.get_name()
                );
            }
        }
    }

    #[test]
    fn test_delta_returns_zero_when_idle() {
        let tmp = create_mock_sysfs(false);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let _ = provider.update_metrics();
        let _ = provider.update_metrics();

        let metric_families = registry.gather();
        for mf in &metric_families {
            for metric in mf.get_metric() {
                assert_eq!(metric.get_gauge().get_value(), 0.0);
            }
        }
    }

    #[test]
    fn test_delta_with_counter_reset_returns_current() {
        let tmp = create_mock_sysfs(false);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let _ = provider.update_metrics();

        write_counters(&tmp, "rdmap0s31", 1000, None);
        let _ = provider.update_metrics();

        write_counters(&tmp, "rdmap0s31", 5, None);
        let _ = provider.update_metrics();

        let metric_families = registry.gather();
        for mf in &metric_families {
            for metric in mf.get_metric() {
                assert_eq!(
                    metric.get_gauge().get_value(),
                    5.0,
                    "Counter reset should return current value for {}",
                    mf.get_name()
                );
            }
        }
    }

    #[test]
    fn test_delta_with_srd_metrics() {
        let tmp = create_mock_sysfs(true);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let _ = provider.update_metrics();

        write_counters(&tmp, "rdmap0s31", 52, Some(17));
        let _ = provider.update_metrics();

        let metric_families = registry.gather();
        let srd_names: Vec<&str> = SRD_METRICS.iter().map(|(name, _)| *name).collect();

        for mf in &metric_families {
            for metric in mf.get_metric() {
                assert_eq!(
                    metric.get_gauge().get_value(),
                    10.0,
                    "Delta should be 10 for {}",
                    mf.get_name()
                );
            }
        }

        let reported_names: Vec<&str> = metric_families.iter().map(|mf| mf.get_name()).collect();
        for srd_name in &srd_names {
            assert!(reported_names.contains(srd_name));
        }
    }

    #[test]
    fn test_labels_ec2_plain() {
        let labels = EfaMetric::get_labels(&ComputePlatform::Ec2Plain);
        assert_eq!(labels, &["instance_id", "device", "port"]);
    }

    #[test]
    fn test_labels_k8s() {
        for platform in &[ComputePlatform::Ec2K8sEks, ComputePlatform::Ec2K8sVanilla] {
            let labels = EfaMetric::get_labels(platform);
            assert_eq!(labels, &["instance_id", "device", "port", "node", "pod", "namespace"]);
        }
    }

    #[test]
    fn test_label_values_ec2() {
        let tmp = create_mock_sysfs(false);
        let provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let values = provider.label_values("rdmap0s31", "1");
        assert_eq!(values, vec!["i-1234567890abcdef0", "rdmap0s31", "1"]);
    }

    #[test]
    fn test_label_values_k8s() {
        let tmp = create_mock_sysfs(false);
        let provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2K8sEks);
        let values = provider.label_values("rdmap0s31", "1");
        assert_eq!(
            values,
            vec!["i-1234567890abcdef0", "rdmap0s31", "1", "test-node", "unknown", "unknown"]
        );
    }

    #[test]
    fn test_multiple_devices_delta() {
        let tmp = TempDir::new().unwrap();
        let dev1_counters = hw_counters_path(tmp.path(), "rdmap0s31", TEST_PORT);
        let dev2_counters = hw_counters_path(tmp.path(), "rdmap1s32", TEST_PORT);
        fs::create_dir_all(&dev1_counters).unwrap();
        fs::create_dir_all(&dev2_counters).unwrap();

        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            fs::write(dev1_counters.join(sysfs_name), "100\n").unwrap();
            fs::write(dev2_counters.join(sysfs_name), "200\n").unwrap();
        }

        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let _ = provider.update_metrics();

        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            fs::write(dev1_counters.join(sysfs_name), "110\n").unwrap();
            fs::write(dev2_counters.join(sysfs_name), "250\n").unwrap();
        }

        let result = provider.update_metrics();
        assert!(result.is_ok());

        let metric_families = registry.gather();
        for mf in &metric_families {
            assert_eq!(mf.get_metric().len(), 2, "Should have 2 devices");
            let values: Vec<f64> = mf
                .get_metric()
                .iter()
                .map(|m| m.get_gauge().get_value())
                .collect();
            let mut sorted = values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            assert_eq!(sorted, vec![10.0, 50.0]);
        }
    }

    #[test]
    fn test_multiple_ports_on_single_device() {
        let tmp = TempDir::new().unwrap();
        let port1_counters = hw_counters_path(tmp.path(), "rdmap0s31", "1");
        let port2_counters = hw_counters_path(tmp.path(), "rdmap0s31", "2");
        fs::create_dir_all(&port1_counters).unwrap();
        fs::create_dir_all(&port2_counters).unwrap();

        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            fs::write(port1_counters.join(sysfs_name), "100\n").unwrap();
            fs::write(port2_counters.join(sysfs_name), "300\n").unwrap();
        }

        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let _ = provider.update_metrics();

        // Increment port1 by 20, port2 by 40.
        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            fs::write(port1_counters.join(sysfs_name), "120\n").unwrap();
            fs::write(port2_counters.join(sysfs_name), "340\n").unwrap();
        }

        let _ = provider.update_metrics();

        let metric_families = registry.gather();
        for mf in &metric_families {
            assert_eq!(mf.get_metric().len(), 2, "Should have 2 port entries");
            let values: Vec<f64> = mf
                .get_metric()
                .iter()
                .map(|m| m.get_gauge().get_value())
                .collect();
            let mut sorted = values.clone();
            sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
            assert_eq!(sorted, vec![20.0, 40.0]);
        }
    }

    #[test]
    fn test_metric_names_have_efa_prefix() {
        let tmp = create_mock_sysfs(true);
        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        let mut registry = Registry::new();
        provider.register_to(&mut registry);

        let _ = provider.update_metrics();
        let metric_families = registry.gather();

        for mf in &metric_families {
            assert!(
                mf.get_name().starts_with("efa_"),
                "Metric name '{}' does not start with 'efa_'",
                mf.get_name()
            );
        }
    }

    #[test]
    fn test_compute_delta_normal() {
        assert_eq!(compute_delta(100, 42), 58);
    }

    #[test]
    fn test_compute_delta_same_value() {
        assert_eq!(compute_delta(42, 42), 0);
    }

    #[test]
    fn test_compute_delta_reset_returns_current() {
        assert_eq!(compute_delta(5, 1000), 5);
    }

    #[test]
    fn test_stale_device_cleanup() {
        let tmp = TempDir::new().unwrap();
        let dev1_counters = hw_counters_path(tmp.path(), "rdmap0s31", TEST_PORT);
        let dev2_counters = hw_counters_path(tmp.path(), "rdmap1s32", TEST_PORT);
        fs::create_dir_all(&dev1_counters).unwrap();
        fs::create_dir_all(&dev2_counters).unwrap();

        for (metric_name, _) in STANDARD_METRICS {
            let sysfs_name = strip_efa_prefix(metric_name);
            fs::write(dev1_counters.join(sysfs_name), "100\n").unwrap();
            fs::write(dev2_counters.join(sysfs_name), "200\n").unwrap();
        }

        let mut provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2Plain);
        assert_eq!(provider.previous_values.len(), 2);

        // Remove device2 from sysfs.
        fs::remove_dir_all(tmp.path().join("rdmap1s32")).unwrap();

        let _ = provider.update_metrics();

        assert_eq!(provider.previous_values.len(), 1);
        assert!(provider.previous_values.contains_key("rdmap0s31/1"));
        assert!(!provider.previous_values.contains_key("rdmap1s32/1"));
    }

    #[test]
    fn test_label_values_k8s_with_pod_map() {
        use crate::kubernetes::efa_pod_resources::EfaPodInfo;

        let tmp = create_mock_sysfs(false);
        let mut device_map = EfaDeviceToPodMap::new();
        device_map.insert(
            "rdmap0s31".to_string(),
            EfaPodInfo {
                pod_name: "training-job-worker-0".to_string(),
                pod_namespace: "ml".to_string(),
            },
        );
        let pod_map = Arc::new(Mutex::new(device_map));

        let provider = create_provider_with_mock_and_pod_map(
            &tmp,
            ComputePlatform::Ec2K8sEks,
            Some(pod_map),
        );
        let values = provider.label_values("rdmap0s31", "1");
        assert_eq!(
            values,
            vec![
                "i-1234567890abcdef0",
                "rdmap0s31",
                "1",
                "test-node",
                "training-job-worker-0",
                "ml"
            ]
        );
    }

    #[test]
    fn test_label_values_k8s_with_pod_map_device_not_found() {
        let tmp = create_mock_sysfs(false);
        let device_map = EfaDeviceToPodMap::new();
        let pod_map = Arc::new(Mutex::new(device_map));

        let provider = create_provider_with_mock_and_pod_map(
            &tmp,
            ComputePlatform::Ec2K8sEks,
            Some(pod_map),
        );
        let values = provider.label_values("rdmap0s31", "1");
        assert_eq!(
            values,
            vec!["i-1234567890abcdef0", "rdmap0s31", "1", "test-node", "unknown", "unknown"]
        );
    }

    #[test]
    fn test_label_values_k8s_without_pod_map() {
        let tmp = create_mock_sysfs(false);
        let provider = create_provider_with_mock(&tmp, ComputePlatform::Ec2K8sEks);
        let values = provider.label_values("rdmap0s31", "1");
        assert_eq!(
            values,
            vec!["i-1234567890abcdef0", "rdmap0s31", "1", "test-node", "unknown", "unknown"]
        );
    }
}
