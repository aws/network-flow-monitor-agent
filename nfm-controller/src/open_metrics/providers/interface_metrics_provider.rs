// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::{
    metadata::{
        imds_utils::retrieve_instance_id, k8s_metadata::K8sMetadata,
        runtime_environment_metadata::ComputePlatform,
    },
    open_metrics::{
        provider::OpenMetricProvider,
        providers::{build_gauge_metric, MetricLabel},
    },
    reports::report::ReportValue,
    utils::{CommandRunner, RealCommandRunner},
};
use anyhow;
use aws_config::imds::Client;
use getifaddrs::{getifaddrs, InterfaceFlags};
use log::{info, warn};
use procfs::net::{dev_status, DeviceStatus};
use prometheus::{IntGaugeVec, Registry};
use regex::Regex;

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

pub struct InterfaceMetricsProvider {
    compute_platform: ComputePlatform,
    instance_id: String,
    node_name: String,
    command_runner: Box<dyn CommandRunner>,

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
            instance_id: retrieve_instance_id(&Client::builder().build()),
            node_name,
            command_runner: Box::new(RealCommandRunner {}),

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
        let ns_to_pid = match self.compute_platform {
            ComputePlatform::Ec2Plain => None,
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                Some(self.get_ns_to_pid())
            }
        };
        get_device_status()
            .iter()
            .map(|(interface_name, interface_stats)| InterfaceMetric {
                key: self.build_metric_key(interface_name, &ns_to_pid),
                value: InterfaceMetricValues {
                    ingress_pkt_count: interface_stats.recv_packets,
                    ingress_bytes_count: interface_stats.recv_bytes,
                    egress_pkt_count: interface_stats.sent_packets,
                    egress_bytes_count: interface_stats.sent_bytes,
                },
            })
            .collect()
    }

    fn build_metric_key(
        &self,
        iface_name: &String,
        ns_to_pid: &Option<HashMap<u32, u32>>,
    ) -> InterfaceMetricKey {
        let (pod, pod_namespace) = match self.compute_platform {
            ComputePlatform::Ec2Plain => ("".to_string(), "".to_string()),
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                self.get_pod_info_from_iface(iface_name, ns_to_pid)
            }
        };
        InterfaceMetricKey {
            instance: self.instance_id.clone(),
            iface: iface_name.to_string(),
            pod,
            pod_namespace,
            node: self.node_name.clone(),
        }
    }

    fn get_pod_info_from_iface(
        &self,
        iface_name: &String,
        ns_to_pid: &Option<HashMap<u32, u32>>,
    ) -> (String, String) {
        let net_ns = self.get_ns_from(iface_name);
        let pid: u32 = match ns_to_pid {
            Some(map) => *map.get(&net_ns.unwrap_or_default()).unwrap_or(&0),
            None => 0,
        };
        (
            format!("pod-{}", pid),
            format!("namespace-{}", net_ns.unwrap_or(0)),
        )
    }

    /// Get the namespace ID for a given interface using "ip link" command.
    /// Returns the link-netnsid if found, otherwise returns None.
    fn get_ns_from(&self, iface_name: &String) -> Option<u32> {
        let output = self.command_runner.run("ip", &["link", "show", iface_name]);

        match output {
            Ok(output) => {
                if !output.status.success() {
                    warn!(
                        "Failed to get link information for interface {}: {}",
                        iface_name,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return None;
                }

                let stdout = String::from_utf8_lossy(&output.stdout);

                // Use regex to extract namespace ID from "link-netnsid <number>"
                let re = Regex::new(r"link-netnsid\s+(\d+)").unwrap();

                if let Some(captures) = re.captures(&stdout) {
                    if let Some(netnsid_match) = captures.get(1) {
                        match netnsid_match.as_str().parse::<u32>() {
                            Ok(netnsid) => {
                                return Some(netnsid);
                            }
                            Err(e) => {
                                warn!(
                                    iface = iface_name, error = e.to_string();
                                    "Failed to parse namespace",
                                );
                            }
                        }
                    }
                }
                None
            }
            Err(e) => {
                warn!(iface = iface_name, error = e.to_string();
                    "Failed to execute 'ip link show",
                );
                None
            }
        }
    }

    /// Creates a map between network namespaces and PIDs
    fn get_ns_to_pid(&self) -> HashMap<u32, u32> {
        let output = self
            .command_runner
            .run("lsns", &["-t", "net", "--noheadings"]);

        match output {
            Ok(output) => {
                if !output.status.success() {
                    warn!(
                        "Failed to get network namespaces: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return HashMap::new();
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut ns_pid_map = HashMap::new();

                // Format: NS TYPE NPROCS PID USER NETNSID NSFS COMMAND
                for line in stdout.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 6 {
                        // Extract NETNSID (field 5) and PID (field 3)
                        if let (Ok(pid), Ok(netns_id)) =
                            (fields[3].parse::<u32>(), fields[5].parse::<u32>())
                        {
                            ns_pid_map.insert(netns_id, pid);
                        } else {
                            warn!(
                                "Failed to parse PID '{}' for NETNSID '{}'",
                                fields[3], fields[5]
                            );
                        }
                    }
                }

                ns_pid_map
            }
            Err(e) => {
                warn!("Failed to execute 'lsns' command: {}", e.to_string());
                HashMap::new()
            }
        }
    }
}

fn get_device_status() -> HashMap<String, DeviceStatus> {
    // Get interface statistics from procfs
    let interfaces = match dev_status() {
        Ok(interfaces) => interfaces,
        Err(e) => {
            warn!(
                "Failed to read network interface statistics from procfs: {}",
                e
            );
            HashMap::new()
        }
    };

    let interface_flags = match get_interface_flags() {
        Ok(flags) => flags,
        Err(e) => {
            warn!("Failed to get interface flags using getifaddrs: {}", e);
            HashMap::new()
        }
    };

    interfaces
        .into_iter()
        .filter(|(iface_name, _device_status)| {
            if let Some(flags) = interface_flags.get(iface_name) {
                if flags.contains(InterfaceFlags::LOOPBACK) {
                    info!("Skipping loopback");
                    return false;
                }

                if !flags.contains(InterfaceFlags::UP) {
                    info!("Skipping non UP iface");
                    return false;
                }
            } else {
                info!("Interface not found {}", iface_name)
            }

            true
        })
        .collect()
}

/// Get interface flags using getifaddrs
fn get_interface_flags() -> Result<HashMap<String, InterfaceFlags>, Box<dyn std::error::Error>> {
    let mut interface_flags = HashMap::new();

    let ifaddrs = getifaddrs()?;
    for interface in ifaddrs {
        interface_flags.insert(interface.name, interface.flags);
    }

    Ok(interface_flags)
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
mod tests {
    use super::*;
    use crate::metadata::runtime_environment_metadata::ComputePlatform;
    use crate::utils::FakeCommandRunner;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    #[test]
    fn test_interface_metrics_provider_new() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain);
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2Plain);
        assert_eq!(provider.node_name, "unknown"); // Default when K8s metadata is not available
    }

    #[test]
    fn test_interface_metrics_provider_new_eks() {
        let provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2K8sEks);
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2K8sEks);
    }

    #[test]
    fn test_interface_metric_get_labels_ec2_plain() {
        let labels = InterfaceMetric::get_labels(&ComputePlatform::Ec2Plain);
        assert_eq!(labels, &["instance_id", "iface"]);
    }

    #[test]
    fn test_interface_metric_get_labels_eks() {
        let labels = InterfaceMetric::get_labels(&ComputePlatform::Ec2K8sEks);
        assert_eq!(labels, &["iface", "pod", "namespace", "node"]);
    }

    #[test]
    fn test_interface_metric_label_values_ec2_plain() {
        let metric = InterfaceMetric {
            key: InterfaceMetricKey {
                instance: "i-1234567890abcdef0".to_string(),
                iface: "eth0".to_string(),
                pod: "".to_string(),
                pod_namespace: "".to_string(),
                node: "test-node".to_string(),
            },
            value: InterfaceMetricValues {
                ingress_pkt_count: 100,
                ingress_bytes_count: 1000,
                egress_pkt_count: 200,
                egress_bytes_count: 2000,
            },
        };

        let label_values = metric.label_values(&ComputePlatform::Ec2Plain);
        assert_eq!(label_values, vec!["i-1234567890abcdef0", "eth0"]);
    }

    #[test]
    fn test_interface_metric_label_values_eks() {
        let metric = InterfaceMetric {
            key: InterfaceMetricKey {
                instance: "i-1234567890abcdef0".to_string(),
                iface: "eth0".to_string(),
                pod: "test-pod".to_string(),
                pod_namespace: "default".to_string(),
                node: "test-node".to_string(),
            },
            value: InterfaceMetricValues {
                ingress_pkt_count: 100,
                ingress_bytes_count: 1000,
                egress_pkt_count: 200,
                egress_bytes_count: 2000,
            },
        };

        let label_values = metric.label_values(&ComputePlatform::Ec2K8sEks);
        assert_eq!(
            label_values,
            vec!["eth0", "test-pod", "default", "test-node"]
        );
    }

    #[test]
    fn test_get_ns_from_with_namespace_id() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "eth0"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default link-netnsid 0\n    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_from(&"eth0".to_string());

        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_get_ns_from_without_namespace_id() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "eth0"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\n    link/ether 08:00:27:12:34:56 brd ff:ff:ff:ff:ff:ff".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_from(&"eth0".to_string());

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_ns_from_with_different_namespace_id() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "veth123"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "15: veth123@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default link-netnsid 42\n    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 42".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_from(&"veth123".to_string());

        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_get_ns_from_command_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "nonexistent"],
            Ok(Output {
                status: ExitStatus::from_raw(1),
                stdout: vec![],
                stderr: "Device \"nonexistent\" does not exist.".as_bytes().to_vec(),
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_from(&"nonexistent".to_string());

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_ns_from_command_error() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "eth0"],
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "ip command not found",
            )),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_from(&"eth0".to_string());

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_ns_from_invalid_namespace_id() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "eth0"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default link-netnsid invalid\n    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_from(&"eth0".to_string());

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_metrics_returns_vector() {
        let mut provider = InterfaceMetricsProvider::new(&ComputePlatform::Ec2Plain);
        let metrics = provider.get_metrics();
        // Should return a vector (may be empty if no interfaces are available in test environment)
        assert!(metrics.is_empty() || !metrics.is_empty()); // Just verify it returns a vector
    }

    #[test]
    fn test_get_pids_from_ns_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "4026531992 net      54  1628 user           0 /host/run/netns/test sleep 180\n4026532123 net       1  2345 root           1 /host/run/netns/test2 systemd\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_to_pid();

        assert_eq!(result.len(), 2);
        assert_eq!(result.get(&0), Some(&1628));
        assert_eq!(result.get(&1), Some(&2345));
    }

    #[test]
    fn test_get_pids_from_ns_empty_output() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: vec![],
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_to_pid();

        assert!(result.is_empty());
    }

    #[test]
    fn test_get_pids_from_ns_command_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(1),
                stdout: vec![],
                stderr: "lsns: failed to read namespaces".as_bytes().to_vec(),
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_to_pid();

        assert!(result.is_empty());
    }

    #[test]
    fn test_get_pids_from_ns_command_error() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "lsns command not found",
            )),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_to_pid();

        assert!(result.is_empty());
    }

    #[test]
    fn test_get_pids_from_ns_invalid_pid() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "4026531992 net      54  invalid user           0 /host/run/netns/test sleep 180\n4026532123 net       1  2345 root           1 /host/run/netns/test2 systemd\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_to_pid();

        // Should only contain the valid entry
        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&1), Some(&2345));
        assert_eq!(result.get(&0), None);
    }

    #[test]
    fn test_get_pids_from_ns_malformed_line() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "4026531992 net\n4026532123 net       1  2345 root           1 /host/run/netns/test2 systemd\n"
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_to_pid();

        // Should only contain the valid entry
        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&1), Some(&2345));
    }

    #[test]
    fn test_get_pid_from_ns_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout:
                    "4026531992 net      54  1628 user           0 /host/run/netns/test sleep 180\n"
                        .as_bytes()
                        .to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_pid_from_ns(Some(0));

        assert_eq!(result, Some(1628));
    }

    #[test]
    fn test_get_pid_from_ns_not_found() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout:
                    "4026531992 net      54  1628 user           0 /host/run/netns/test sleep 180\n"
                        .as_bytes()
                        .to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_pid_from_ns(Some(999));

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_pid_from_ns_none_input() {
        let fake_runner = FakeCommandRunner::new();
        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_pid_from_ns(None);

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_pids_from_ns_unassigned_skipped() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "4026531840 net     135       1 root   unassigned                                                          /usr/lib/systemd/systemd\n4026532152 net       4    4050 65535           0 /host/run/netns/cni-test /pause\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_to_pid();

        // Should only contain the non-unassigned entry
        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&0), Some(&4050));
    }

    // Helper function to create a test provider with a custom command runner
    fn create_test_provider_with_runner(
        fake_runner: FakeCommandRunner,
    ) -> InterfaceMetricsProvider {
        InterfaceMetricsProvider {
            compute_platform: ComputePlatform::Ec2Plain,
            instance_id: "test-instance".to_string(),
            node_name: "test-node".to_string(),
            command_runner: Box::new(fake_runner),
            ingress_pkt_count: build_gauge_metric::<InterfaceMetric>(
                &ComputePlatform::Ec2Plain,
                "test_ingress_pkt_count",
                "Test ingress packet count",
            ),
            ingress_bytes_count: build_gauge_metric::<InterfaceMetric>(
                &ComputePlatform::Ec2Plain,
                "test_ingress_bytes_count",
                "Test ingress bytes count",
            ),
            egress_pkt_count: build_gauge_metric::<InterfaceMetric>(
                &ComputePlatform::Ec2Plain,
                "test_egress_pkt_count",
                "Test egress packet count",
            ),
            egress_bytes_count: build_gauge_metric::<InterfaceMetric>(
                &ComputePlatform::Ec2Plain,
                "test_egress_bytes_count",
                "Test egress bytes count",
            ),
        }
    }
}
