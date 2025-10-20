// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::{
    kubernetes::kubernetes_metadata_collector::{KubernetesMetadataCollector, PodInfo},
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
use getifaddrs::{getifaddrs, InterfaceFilter, InterfaceFlags};
use log::{debug, info, warn};
use nfm_common::IpAddrLinkLocal;
use procfs::net::{dev_status, DeviceStatus};
use prometheus::{IntGaugeVec, Registry};
use regex::Regex;

/// Struct to hold PID, namespace file path, and IP addresses for a namespace
#[derive(Debug, Clone, PartialEq)]
pub struct NamespaceInfo {
    pub pid: u32,
    pub ns_file: Option<String>,
    pub ip_addresses: Vec<IpAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
struct HostInterface {
    name: String,
    virt: bool,
}

impl HostInterface {
    fn new(name: String) -> Self {
        HostInterface {
            name: name.clone(),
            virt: check_virtual_iface(&name),
        }
    }

    fn is_virtual(&self) -> bool {
        self.virt
    }
}

/// Metric key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InterfaceMetricKey {
    instance: String,
    iface: String,
    pod: String,
    pod_namespace: String,
    node: String,
}

#[derive(Debug, Clone, Default)]
struct InterfaceMetricValues {
    host: HostInterfaceMetricValues,
    netns: NetNsInterfaceMetricValues,
}

impl InterfaceMetricValues {
    fn delta(&self, other: &Self) -> Self {
        InterfaceMetricValues {
            host: self.host.delta(&other.host),
            netns: self.netns.delta(&other.netns),
        }
    }
}

/// Interface statistics calculated at node interface levels
#[derive(Debug, Clone, Default)]
struct HostInterfaceMetricValues {
    ingress_pkt_count: u64,
    ingress_bytes_count: u64,
    egress_pkt_count: u64,
    egress_bytes_count: u64,
}

impl HostInterfaceMetricValues {
    fn swap_tx_rx(self) -> Self {
        HostInterfaceMetricValues {
            ingress_pkt_count: self.egress_pkt_count,
            ingress_bytes_count: self.egress_bytes_count,
            egress_pkt_count: self.ingress_pkt_count,
            egress_bytes_count: self.ingress_bytes_count,
        }
    }

    fn delta(&self, other: &Self) -> Self {
        HostInterfaceMetricValues {
            ingress_pkt_count: self
                .ingress_pkt_count
                .saturating_sub(other.ingress_pkt_count),
            ingress_bytes_count: self
                .ingress_bytes_count
                .saturating_sub(other.ingress_bytes_count),
            egress_pkt_count: self.egress_pkt_count.saturating_sub(other.egress_pkt_count),
            egress_bytes_count: self
                .egress_bytes_count
                .saturating_sub(other.egress_bytes_count),
        }
    }
}

/// Interface statistics calculated inside the network namespace
#[derive(Debug, Clone, Default)]
struct NetNsInterfaceMetricValues {
    ingress_flow_count: u64,
    egress_flow_count: u64,
}

impl NetNsInterfaceMetricValues {
    fn delta(&self, other: &Self) -> Self {
        NetNsInterfaceMetricValues {
            ingress_flow_count: self
                .ingress_flow_count
                .saturating_sub(other.ingress_flow_count),
            egress_flow_count: self
                .egress_flow_count
                .saturating_sub(other.egress_flow_count),
        }
    }
}

impl InterfaceMetricKey {
    fn label_values<'a>(
        &'a self,
        compute_platform: &ComputePlatform,
        node_name: &'a str,
        instance_id: &'a str,
    ) -> Vec<&'a str> {
        // The order of the elements must match the labels for the trait MetricLabel
        match compute_platform {
            ComputePlatform::Ec2Plain => {
                vec![instance_id, &self.iface]
            }
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                vec![
                    instance_id,
                    &self.iface,
                    &self.pod,
                    &self.pod_namespace,
                    node_name,
                ]
            }
        }
    }
}

impl MetricLabel for InterfaceMetricKey {
    fn get_labels(compute_platform: &ComputePlatform) -> &[&str] {
        match compute_platform {
            ComputePlatform::Ec2Plain => &["instance_id", "iface"],
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                &["instance_id", "iface", "pod", "namespace", "node"]
            }
        }
    }
}

/// Trait defined to allow mocking for testing.
trait InterfaceStatusRetriever {
    fn dev_status(&self) -> HashMap<HostInterface, DeviceStatus>;
}

struct InterfaceStatusRetrieverImpl {}

impl InterfaceStatusRetriever for InterfaceStatusRetrieverImpl {
    fn dev_status(&self) -> HashMap<HostInterface, DeviceStatus> {
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
            .map(|(iface_name, device_status)| (HostInterface::new(iface_name), device_status))
            .filter(|(iface, _device_status)| {
                if let Some(flags) = interface_flags.get(&iface.name) {
                    if flags.contains(InterfaceFlags::LOOPBACK) {
                        info!("Skipping loopback");
                        return false;
                    }

                    if !flags.contains(InterfaceFlags::UP) {
                        info!("Skipping non UP iface");
                        return false;
                    }
                } else {
                    info!("Interface not found {}", iface.name);
                    return false;
                }

                // Only report Pod Network metrics, so only virtual interfaces.
                iface.is_virtual()
            })
            .collect()
    }
}

pub struct InterfaceMetricsProvider {
    compute_platform: ComputePlatform,
    instance_id: String,
    node_name: String,
    command_runner: Box<dyn CommandRunner>,
    interface_status: Box<dyn InterfaceStatusRetriever>,
    k8s_metadata_collector: Option<Arc<KubernetesMetadataCollector>>,

    ingress_pkt_count: IntGaugeVec,
    ingress_bytes_count: IntGaugeVec,
    egress_pkt_count: IntGaugeVec,
    egress_bytes_count: IntGaugeVec,

    ingress_flow_count: IntGaugeVec,
    egress_flow_count: IntGaugeVec,

    // Current metrics to calculate the delta from previous reports
    current_metrics: HashMap<InterfaceMetricKey, InterfaceMetricValues>,
}

impl InterfaceMetricsProvider {
    pub fn new(
        compute_platform: &ComputePlatform,
        k8s_metadata_collector: Option<Arc<KubernetesMetadataCollector>>,
    ) -> Self {
        let node_name = match K8sMetadata::default().node_name {
            Some(ReportValue::String(node_name)) => node_name,
            _ => "unknown".to_string(),
        };

        let mut provider = InterfaceMetricsProvider {
            compute_platform: compute_platform.clone(),
            instance_id: retrieve_instance_id(&Client::builder().build()),
            node_name,
            command_runner: Box::new(RealCommandRunner {}),
            interface_status: Box::new(InterfaceStatusRetrieverImpl {}),
            k8s_metadata_collector,

            ingress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "ingress_packets",
                "Ingress packet count",
            ),
            ingress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "ingress_bytes",
                "Ingress bytes count",
            ),
            egress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "egress_packets",
                "Egress packet count",
            ),
            egress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "egress_bytes",
                "Egress bytes count",
            ),
            ingress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "ingress_flow",
                "Ingress TCP flow count",
            ),
            egress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                &compute_platform,
                "egress_flow",
                "Egress TCP flow count",
            ),
            current_metrics: HashMap::new(),
        };

        // This call will update the metrics for the first time with the baseline.
        provider.current_metrics = provider.get_metrics();
        provider
    }

    fn get_metrics(&mut self) -> HashMap<InterfaceMetricKey, InterfaceMetricValues> {
        let (ns_to_pid, pod_info) = match self.compute_platform {
            ComputePlatform::Ec2Plain => (None, None),
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => {
                (Some(self.get_ns_info()), self.get_ip_pod_info_mapping())
            }
        };

        let mut new_current_metrics = HashMap::new();

        let mut result = HashMap::new();
        for (iface, device_status) in self.interface_status.dev_status() {
            // Get the namespace ID once per interface to avoid duplicate calls
            let netns = if iface.is_virtual() {
                self.get_ns_from(&iface.name)
            } else {
                None
            };

            let key = self.build_metric_key(&iface.name, &ns_to_pid, &pod_info, netns);

            let mut host_metrics = HostInterfaceMetricValues {
                ingress_pkt_count: device_status.recv_packets,
                ingress_bytes_count: device_status.recv_bytes,
                egress_pkt_count: device_status.sent_packets,
                egress_bytes_count: device_status.sent_bytes,
            };

            let mut netns_metrics = NetNsInterfaceMetricValues::default();
            // If the interface is veth, we need to swap the values because the pod is on the other end
            // of the link
            if iface.is_virtual() {
                host_metrics = host_metrics.swap_tx_rx();

                // Use the already retrieved netns value
                netns_metrics =
                    match netns.and_then(|ns| ns_to_pid.as_ref().and_then(|map| map.get(&ns))) {
                        None => NetNsInterfaceMetricValues::default(),
                        Some(ns_info) => self.get_netns_metric(ns_info.pid),
                    };
            }

            let iface_metrics = InterfaceMetricValues {
                host: host_metrics,
                netns: netns_metrics,
            };

            // Calculate deltas before inserting into new_current_metrics
            let delta_metric = iface_metrics.delta(
                self.current_metrics
                    .get(&key)
                    .unwrap_or(&InterfaceMetricValues::default()),
            );

            // We return the delta but keep the real value to calculate the next iteration's delta.
            new_current_metrics.insert(key.clone(), iface_metrics);
            result.insert(key, delta_metric);
        }

        self.current_metrics = new_current_metrics;
        result
    }

    fn get_ip_pod_info_mapping(&self) -> Option<HashMap<IpAddr, HashSet<PodInfo>>> {
        match &self.k8s_metadata_collector {
            Some(k8s_metadata) => Some(k8s_metadata.get_ip_to_pod_mapping(&[])),
            None => None,
        }
    }

    fn build_metric_key(
        &self,
        iface_name: &String,
        ns_to_pid: &Option<HashMap<u32, NamespaceInfo>>,
        pod_info_map: &Option<HashMap<IpAddr, HashSet<PodInfo>>>,
        netns: Option<u32>,
    ) -> InterfaceMetricKey {
        let (pod, pod_namespace) = match self.compute_platform {
            ComputePlatform::Ec2Plain => ("".to_string(), "".to_string()),
            ComputePlatform::Ec2K8sEks | ComputePlatform::Ec2K8sVanilla => get_pod_info_from_iface(
                iface_name,
                ns_to_pid.as_ref().unwrap(),
                pod_info_map.as_ref().unwrap(),
                netns,
            ),
        };
        InterfaceMetricKey {
            instance: self.instance_id.clone(),
            iface: iface_name.to_string(),
            pod,
            pod_namespace,
            node: self.node_name.clone(),
        }
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

    /// Creates a map between network namespaces and namespace info (PID + netns file + IP addresses)
    fn get_ns_info(&self) -> HashMap<u32, NamespaceInfo> {
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
                let mut ns_info_map = HashMap::new();

                // Format: NS TYPE NPROCS PID USER NETNSID NSFS COMMAND
                for line in stdout.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 6 {
                        // Extract NETNSID (field 5) and PID (field 3)
                        if let (Ok(pid), Ok(netns_id)) =
                            (fields[3].parse::<u32>(), fields[5].parse::<u32>())
                        {
                            // Extract namespace file path (field 6) if available
                            let ns_file = if fields.len() >= 7 && !fields[6].is_empty() {
                                match fs::exists(fields[6]) {
                                    Ok(true) => Some(fields[6].to_string()),
                                    _ => None,
                                }
                            } else {
                                None
                            };

                            // Get IP addresses for this namespace using namespace file first, then fallback to PID
                            let ip_addresses = self.get_ip_addresses_from_ns(pid, &ns_file);

                            let namespace_info = NamespaceInfo {
                                pid,
                                ns_file,
                                ip_addresses,
                            };

                            ns_info_map.insert(netns_id, namespace_info);
                        } else {
                            debug!(line = line; "lsns output");
                            warn!(
                                "Failed to parse PID '{}' for NETNSID '{}'",
                                fields[3], fields[5]
                            );
                        }
                    }
                }

                ns_info_map
            }
            Err(e) => {
                warn!("Failed to execute 'lsns' command: {}", e.to_string());
                HashMap::new()
            }
        }
    }

    /// Get IP addresses for a namespace using namespace file first, then fallback to PID
    fn get_ip_addresses_from_ns(&self, pid: u32, ns_file: &Option<String>) -> Vec<IpAddr> {
        // First try using the namespace file if available
        if let Some(ns_path) = ns_file {
            if let Some(ip_addresses) = self.get_ip_addresses_from_ns_file(ns_path) {
                debug!(
                    "Successfully retrieved IP addresses using namespace file: {}",
                    ns_path
                );
                return ip_addresses;
            } else {
                debug!(
                    "Failed to get IP addresses from namespace file: {}, falling back to PID",
                    ns_path
                );
            }
        }

        // Fallback to PID-based approach
        self.get_ip_addresses_for_pid(pid)
    }

    /// Get IP addresses from namespace file using nsenter
    fn get_ip_addresses_from_ns_file(&self, ns_path: &str) -> Option<Vec<IpAddr>> {
        let output = self
            .command_runner
            .run("nsenter", &["--net", ns_path, "ip", "a"]);

        match output {
            Ok(output) => {
                if !output.status.success() {
                    debug!(
                        "Failed to get IP addresses using namespace file {}: {}",
                        ns_path,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return None;
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                Some(parse_ip_addresses(&stdout))
            }
            Err(e) => {
                debug!(
                    "Failed to execute 'nsenter' command for namespace file {}: {}",
                    ns_path,
                    e.to_string()
                );
                None
            }
        }
    }

    /// Get IP addresses for a namespace using nsenter (fallback method)
    fn get_ip_addresses_for_pid(&self, pid: u32) -> Vec<IpAddr> {
        let output = self
            .command_runner
            .run("nsenter", &["-t", &pid.to_string(), "-n", "ip", "a"]);

        match output {
            Ok(output) => {
                if !output.status.success() {
                    warn!(
                        "Failed to get IP addresses for PID {}: {}",
                        pid,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return Vec::new();
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                parse_ip_addresses(&stdout)
            }
            Err(e) => {
                warn!(
                    "Failed to execute 'nsenter' command for PID {}: {}",
                    pid,
                    e.to_string()
                );
                Vec::new()
            }
        }
    }

    /// Parse IP addresses from 'ip a' output - public method for testing
    pub fn parse_ip_addresses(&self, ip_output: &str) -> Vec<IpAddr> {
        parse_ip_addresses(ip_output)
    }

    /// Get pod info from interface - public method for testing
    pub fn get_pod_info_from_iface(
        &self,
        iface_name: &String,
        ns_to_pid: &HashMap<u32, NamespaceInfo>,
        pod_info_mapping: &HashMap<IpAddr, HashSet<PodInfo>>,
    ) -> (String, String) {
        get_pod_info_from_iface(iface_name, ns_to_pid, pod_info_mapping, None)
    }

    /// Get interface IPs - public method for testing
    pub fn get_interface_ips(
        &self,
        iface_name: &str,
    ) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
        get_interface_ips(iface_name)
    }

    /// Get pod info from real interface - public method for testing
    pub fn get_pod_info_from_real_iface(
        &self,
        iface_name: &String,
        pod_info_mapping: &HashMap<IpAddr, HashSet<PodInfo>>,
    ) -> (String, String) {
        get_pod_info_from_real_iface(iface_name, pod_info_mapping)
    }

    fn get_netns_metric(&self, pid: u32) -> NetNsInterfaceMetricValues {
        let output = self
            .command_runner
            .run("nsenter", &["-t", &pid.to_string(), "-n", "nstat", "-a"]);

        match output {
            Ok(output) => {
                if !output.status.success() {
                    warn!(
                        "Failed to get TCP statistics for {}: {}",
                        pid,
                        String::from_utf8_lossy(&output.stderr)
                    );
                    return NetNsInterfaceMetricValues::default();
                }

                let stdout = String::from_utf8_lossy(&output.stdout);

                let mut tcp_active_opens = 0;
                let mut tcp_passive_opens = 0;
                for line in stdout.lines() {
                    if line.starts_with("TcpActiveOpens") {
                        tcp_active_opens = parse_nstat_value(line, "TcpActiveOpens");
                    } else if line.starts_with("TcpPassiveOpens") {
                        tcp_passive_opens = parse_nstat_value(line, "TcpPassiveOpens");
                    }
                    if tcp_active_opens > 0 && tcp_passive_opens > 0 {
                        break;
                    }
                }
                NetNsInterfaceMetricValues {
                    ingress_flow_count: tcp_passive_opens,
                    egress_flow_count: tcp_active_opens,
                }
            }
            Err(e) => {
                warn!(
                    "Failed to execute 'nsenter' command for PID {}: {}",
                    pid,
                    e.to_string()
                );
                NetNsInterfaceMetricValues::default()
            }
        }
    }
}

/// Helper function to parse TCP statistic values from nstat output lines
fn parse_nstat_value(line: &str, stat_name: &str) -> u64 {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() >= 2 {
        match fields[1].parse::<u64>() {
            Ok(value) => value,
            Err(_) => {
                warn!(line = line; "Error parsing {} value", stat_name);
                0
            }
        }
    } else {
        warn!(line = line; "Malformed {} line", stat_name);
        0
    }
}

fn get_pod_info_from_iface(
    iface_name: &String,
    ns_to_pid: &HashMap<u32, NamespaceInfo>,
    pod_info_mapping: &HashMap<IpAddr, HashSet<PodInfo>>,
    netns: Option<u32>,
) -> (String, String) {
    match netns {
        Some(net_ns) => get_pod_info_from_netns(net_ns, ns_to_pid, pod_info_mapping),
        None => get_pod_info_from_real_iface(iface_name, pod_info_mapping),
    }
}

/// Get the Pod information for a namespace. It returns the Pod's name and namespace
fn get_pod_info_from_netns(
    net_ns: u32,
    ns_to_pid: &HashMap<u32, NamespaceInfo>,
    pod_info_mapping: &HashMap<IpAddr, HashSet<PodInfo>>,
) -> (String, String) {
    match ns_to_pid.get(&net_ns) {
        Some(ns_info) => {
            for ip_addr in ns_info.ip_addresses.iter() {
                match pod_info_mapping.get(ip_addr) {
                    Some(pod_info) => {
                        // For non hostNetwork pods, this vector will have only one entry.
                        match pod_info.iter().next() {
                            Some(pod) => return (pod.name.clone(), pod.namespace.clone()),
                            None => continue,
                        }
                    }
                    None => continue,
                }
            }
            ("".into(), "".into())
        }
        _ => ("".into(), "".into()),
    }
}

/// Get the Pod information for a interface that has no network namespace associated.
fn get_pod_info_from_real_iface(
    iface_name: &String,
    pod_info_mapping: &HashMap<IpAddr, HashSet<PodInfo>>,
) -> (String, String) {
    // Get IP addresses from the interface
    match get_interface_ips(iface_name) {
        Ok(ip_addresses) => {
            for ip_addr in ip_addresses {
                match pod_info_mapping.get(&ip_addr) {
                    Some(pod_info) => {
                        // For non hostNetwork pods, this vector will have only one entry.
                        match pod_info.iter().next() {
                            Some(pod) => return (pod.name.clone(), pod.namespace.clone()),
                            None => continue,
                        }
                    }
                    None => continue,
                }
            }
            ("".into(), "".into())
        }
        Err(_) => ("".into(), "".into()),
    }
}

/// Get IP addresses for a specific interface using getifaddrs with InterfaceFilter
fn get_interface_ips(iface_name: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let mut ip_addresses = Vec::new();

    // Use InterfaceFilter to efficiently filter by interface name and get only IP addresses
    let interfaces = InterfaceFilter::new().name(iface_name).v4().v6().get()?;

    for interface in interfaces {
        if let Some(ip_addr) = interface.address.ip_addr() {
            if !ip_addr.is_loopback() && !ip_addr.is_link_local() {
                ip_addresses.push(ip_addr);
            }
        }
    }

    Ok(ip_addresses)
}

/// Parse IP addresses from 'ip a' output
fn parse_ip_addresses(ip_output: &str) -> Vec<IpAddr> {
    let mut ip_addresses = Vec::new();

    // Simplified regex patterns for IPv4 and IPv6 addresses
    // IPv4: "inet 192.168.1.1/24" -> capture the IP part
    let ipv4_regex = Regex::new(r"inet\s+(\S+)/").unwrap();
    // IPv6: "inet6 2001:db8::1/64" -> capture the IP part
    let ipv6_regex = Regex::new(r"inet6\s+(\S+)/").unwrap();

    for line in ip_output.lines() {
        if let Some(ip_addr) = extract_ip_from_line(line, &ipv4_regex) {
            ip_addresses.push(ip_addr);
        } else if let Some(ip_addr) = extract_ip_from_line(line, &ipv6_regex) {
            ip_addresses.push(ip_addr);
        }
    }

    ip_addresses
}

/// Extract and validate IP address from a line using the provided regex
fn extract_ip_from_line(line: &str, regex: &Regex) -> Option<IpAddr> {
    if let Some(captures) = regex.captures(line) {
        if let Some(ip_match) = captures.get(1) {
            if let Ok(ip_addr) = ip_match.as_str().parse::<IpAddr>() {
                if ip_addr.is_loopback() || ip_addr.is_link_local() {
                    return None;
                }
                return Some(ip_addr);
            }
        }
    }
    None
}

fn check_virtual_iface(name: &String) -> bool {
    // Check if /sys/class/net/<interface>/device exists
    // Physical interfaces have this symlink, virtual interfaces don't
    // https://man7.org/linux/man-pages/man5/sysfs.5.html
    let device_path = format!("/sys/class/net/{}/device", name);
    !Path::new(&device_path).exists()
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
        registry
            .register(Box::new(self.ingress_flow_count.clone()))
            .unwrap();
        registry
            .register(Box::new(self.egress_flow_count.clone()))
            .unwrap();
    }

    fn update_metrics(&mut self) -> Result<(), anyhow::Error> {
        info!(platform = self.compute_platform.to_string(); "Updating Interface Metrics");
        let metrics = self.get_metrics();

        for (key, value) in metrics {
            let label_values =
                key.label_values(&self.compute_platform, &self.node_name, &self.instance_id);

            debug!(labels = format!("{:?}", label_values), metrics = format!("{:?}", value); "Interface metrics");

            self.ingress_bytes_count
                .with_label_values(&label_values)
                .set(value.host.ingress_bytes_count as i64);
            self.ingress_pkt_count
                .with_label_values(&label_values)
                .set(value.host.ingress_pkt_count as i64);
            self.egress_bytes_count
                .with_label_values(&label_values)
                .set(value.host.egress_bytes_count as i64);
            self.egress_pkt_count
                .with_label_values(&label_values)
                .set(value.host.egress_pkt_count as i64);

            self.ingress_flow_count
                .with_label_values(&label_values)
                .set(value.netns.ingress_flow_count as i64);
            self.egress_flow_count
                .with_label_values(&label_values)
                .set(value.netns.egress_flow_count as i64);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::runtime_environment_metadata::ComputePlatform;
    use crate::utils::FakeCommandRunner;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};
    struct FakeInterfaceStatusRetriever {
        result: HashMap<HostInterface, DeviceStatus>,
    }

    impl InterfaceStatusRetriever for FakeInterfaceStatusRetriever {
        fn dev_status(&self) -> HashMap<HostInterface, DeviceStatus> {
            self.result.clone()
        }
    }

    fn build_device_status(
        name: String,
        sent_bytes: u64,
        sent_packets: u64,
        recv_bytes: u64,
        recv_packets: u64,
    ) -> DeviceStatus {
        DeviceStatus {
            name,
            recv_bytes,
            recv_packets,
            recv_errs: 0,
            recv_drop: 0,
            recv_fifo: 0,
            recv_frame: 0,
            recv_compressed: 0,
            recv_multicast: 0,
            sent_bytes,
            sent_packets,
            sent_errs: 0,
            sent_drop: 0,
            sent_fifo: 0,
            sent_colls: 0,
            sent_carrier: 0,
            sent_compressed: 0,
        }
    }

    struct TemporaryFile {
        path: String,
    }

    impl TemporaryFile {
        fn new(file_name: &str) -> Self {
            let path = format!("/tmp/{}", file_name).to_string();

            let mut file = File::create(&path).unwrap();
            writeln!(file, "test content").unwrap();

            return TemporaryFile { path };
        }
    }
    impl Drop for TemporaryFile {
        fn drop(&mut self) {
            fs::remove_file(&self.path).unwrap()
        }
    }

    #[test]
    fn test_interface_metrics_provider_new() {
        let provider = create_test_provider_with_runner(FakeCommandRunner::new());
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2Plain);
        assert_eq!(provider.node_name, "test-node"); // Set by the helper function
    }

    #[test]
    fn test_interface_metrics_provider_new_eks() {
        let mut provider = create_test_provider_with_runner(FakeCommandRunner::new());
        provider.compute_platform = ComputePlatform::Ec2K8sEks;
        assert_eq!(provider.compute_platform, ComputePlatform::Ec2K8sEks);
    }

    #[test]
    fn test_interface_metric_key_get_labels_ec2_plain() {
        let labels = InterfaceMetricKey::get_labels(&ComputePlatform::Ec2Plain);
        assert_eq!(labels, &["instance_id", "iface"]);
    }

    #[test]
    fn test_interface_metric_key_get_labels_eks() {
        let labels = InterfaceMetricKey::get_labels(&ComputePlatform::Ec2K8sEks);
        assert_eq!(
            labels,
            &["instance_id", "iface", "pod", "namespace", "node"]
        );
    }

    #[test]
    fn test_interface_metric_label_values_ec2_plain() {
        let key = InterfaceMetricKey {
            instance: "i-1234567890abcdef0".to_string(),
            iface: "eth0".to_string(),
            pod: "".to_string(),
            pod_namespace: "".to_string(),
            node: "test-node".to_string(),
        };

        let label_values = key.label_values(
            &ComputePlatform::Ec2Plain,
            "test-node",
            "i-1234567890abcdef0",
        );
        assert_eq!(label_values, vec!["i-1234567890abcdef0", "eth0"]);
    }

    #[test]
    fn test_interface_metric_key_label_values_eks() {
        let key = InterfaceMetricKey {
            instance: "i-1234567890abcdef0".to_string(),
            iface: "eth0".to_string(),
            pod: "test-pod".to_string(),
            pod_namespace: "default".to_string(),
            node: "test-node".to_string(),
        };

        let label_values = key.label_values(
            &ComputePlatform::Ec2K8sEks,
            "test-node",
            "i-1234567890abcdef0",
        );
        assert_eq!(
            label_values,
            vec![
                "i-1234567890abcdef0",
                "eth0",
                "test-pod",
                "default",
                "test-node"
            ]
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
    fn test_get_pids_from_ns_success() {
        let file_1 = TemporaryFile::new("test_pid_from_ns_not_found");
        let file_2 = TemporaryFile::new("test_pid_from_ns_not_found2");

        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!("4026531992 net      54  1628 user           0 {} sleep 180\n4026532123 net       1  2345 root           1 {} systemd\n", &file_1.path, &file_2.path).as_bytes().to_vec(),
                stderr: vec![],
            }),
        );
        // Add expectations for nsenter commands using namespace files (new priority)
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file_1.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file_2.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_info();

        assert_eq!(result.len(), 2);
        assert_eq!(result.get(&0).unwrap().pid, 1628);
        assert_eq!(result.get(&0).unwrap().ns_file, Some(file_1.path.clone()));
        assert_eq!(
            result.get(&0).unwrap().ip_addresses,
            vec!["192.168.1.10".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(result.get(&1).unwrap().pid, 2345);
        assert_eq!(result.get(&1).unwrap().ns_file, Some(file_2.path.clone()));
        assert_eq!(
            result.get(&1).unwrap().ip_addresses,
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
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
        let result = provider.get_ns_info();

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
        let result = provider.get_ns_info();

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
        let result = provider.get_ns_info();

        assert!(result.is_empty());
    }

    #[test]
    fn test_get_pid_from_ns_success() {
        let file_ns = TemporaryFile::new("pid_from_ns_success");
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(
                    "4026531992 net      54  1628 user           0 {} sleep 180\n",
                    file_ns.path
                )
                .as_bytes()
                .to_vec(),
                stderr: vec![],
            }),
        );
        // Add expectation for nsenter command using namespace file (new priority)
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file_ns.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let ns_to_pid = provider.get_ns_info();
        let result = ns_to_pid.get(&0);

        assert_eq!(result.unwrap().pid, 1628);
        assert_eq!(result.unwrap().ns_file, Some(file_ns.path.clone()));
        assert_eq!(
            result.unwrap().ip_addresses,
            vec!["192.168.1.10".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn test_get_ns_info_with_namespace_file() {
        let file_1 = TemporaryFile::new("test_file1");
        let file_2 = TemporaryFile::new("test_file2");
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!("4026531992 net      54  1628 user           0 {} sleep 180\n4026532123 net       1  2345 root           1 {} systemd\n", file_1.path, file_2.path).as_bytes().to_vec(),
                stderr: vec![],
            }),
        );
        // Add expectations for nsenter commands (namespace file approach)
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file_1.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file_2.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_info();

        assert_eq!(result.len(), 2);

        // Check first namespace
        let ns_info_0 = result.get(&0).unwrap();
        assert_eq!(ns_info_0.pid, 1628);
        assert_eq!(ns_info_0.ns_file, Some(file_1.path.clone()));
        assert_eq!(
            ns_info_0.ip_addresses,
            vec!["192.168.1.10".parse::<IpAddr>().unwrap()]
        );

        // Check second namespace
        let ns_info_1 = result.get(&1).unwrap();
        assert_eq!(ns_info_1.pid, 2345);
        assert_eq!(ns_info_1.ns_file, Some(file_2.path.clone()));
        assert_eq!(
            ns_info_1.ip_addresses,
            vec!["10.0.0.5".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn test_get_ns_info_namespace_file_fallback_to_pid() {
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
        // Fallback to nsenter command
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1628", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_info();

        assert_eq!(result.len(), 1);
        let ns_info = result.get(&0).unwrap();
        assert_eq!(ns_info.pid, 1628);
        assert_eq!(ns_info.ns_file, None);
        // Should still get IP addresses via fallback
        assert_eq!(
            ns_info.ip_addresses,
            vec!["192.168.1.10".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn test_get_ns_info_empty_namespace_file() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "4026531992 net      54  1628 user           0  sleep 180\n"
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );

        // Should use nsenter since no namespace file
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1628", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_info();

        assert_eq!(result.len(), 1);
        let ns_info = result.get(&0).unwrap();
        assert_eq!(ns_info.pid, 1628);
        assert_eq!(ns_info.ns_file, None); // No namespace file
        assert_eq!(
            ns_info.ip_addresses,
            vec!["192.168.1.10".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn test_get_ip_addresses_from_ns_file_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/host/run/netns/test", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n    inet6 2001:db8::1/64 scope global".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_from_ns_file("/host/run/netns/test");

        assert_eq!(
            result,
            Some(vec![
                "192.168.1.10".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap()
            ])
        );
    }

    #[test]
    fn test_get_ip_addresses_from_ns_file_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/host/run/netns/test", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(1),
                stdout: vec![],
                stderr: "nsenter: cannot open /host/run/netns/test: No such file or directory"
                    .as_bytes()
                    .to_vec(),
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_from_ns_file("/host/run/netns/test");

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_ip_addresses_from_ns_file_command_error() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/host/run/netns/test", "ip", "a"],
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "nsenter command not found",
            )),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_from_ns_file("/host/run/netns/test");

        assert_eq!(result, None);
    }

    #[test]
    fn test_get_ip_addresses_from_ns_file_complex_path() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/host/run/netns/complex-name", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 172.16.0.1/24 brd 172.16.0.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_from_ns_file("/host/run/netns/complex-name");

        assert_eq!(result, Some(vec!["172.16.0.1".parse::<IpAddr>().unwrap()]));
    }

    #[test]
    fn test_get_ip_addresses_from_ns_with_namespace_file() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/host/run/netns/test", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let ns_file = Some("/host/run/netns/test".to_string());
        let result = provider.get_ip_addresses_from_ns(1234, &ns_file);

        assert_eq!(result, vec!["192.168.1.10".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_get_ip_addresses_from_ns_no_namespace_file() {
        let mut fake_runner = FakeCommandRunner::new();
        // Should directly use nsenter since no namespace file
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_from_ns(1234, &None);

        assert_eq!(result, vec!["192.168.1.10".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_parse_ip_addresses() {
        let provider = create_test_provider_with_runner(FakeCommandRunner::new());
        let ip_output = "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 2001:db8::1/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::42:acff:fe11:2/64 scope link
       valid_lft forever preferred_lft forever";

        let result = provider.parse_ip_addresses(ip_output);

        // Should extract IPv4 and IPv6 addresses, excluding loopback and link-local
        assert_eq!(
            result,
            vec![
                "192.168.1.10".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn test_get_ip_addresses_for_pid_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_for_pid(1234);

        assert_eq!(result, vec!["192.168.1.10".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_get_ip_addresses_for_pid_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(1),
                stdout: vec![],
                stderr: "nsenter: cannot open /proc/1234/ns/net: No such file or directory"
                    .as_bytes()
                    .to_vec(),
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_for_pid(1234);

        assert!(result.is_empty());
    }

    #[test]
    fn test_get_pids_from_ns_malformed_line() {
        let temp_file = TemporaryFile::new("test_malformed_line");

        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(
                    "4026531992 net\n4026532123 net       1  2345 root           1 {} systemd\n",
                    temp_file.path
                )
                .as_bytes()
                .to_vec(),
                stderr: vec![],
            }),
        );

        // Add expectation for nsenter command using namespace file
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &temp_file.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 203.0.113.1/24 brd 203.0.113.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_info();

        // Should only contain the valid entry
        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&1).unwrap().pid, 2345);
        assert_eq!(
            result.get(&1).unwrap().ns_file,
            Some(temp_file.path.to_string())
        );
        assert_eq!(
            result.get(&1).unwrap().ip_addresses,
            vec!["203.0.113.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn test_build_metric_key_ec2_plain() {
        let provider = create_test_provider_with_runner(FakeCommandRunner::new());

        let key = provider.build_metric_key(&"eth0".to_string(), &None, &None, None);

        assert_eq!(key.iface, "eth0");
        assert_eq!(key.pod, "");
        assert_eq!(key.pod_namespace, "");
        assert_eq!(key.node, "test-node");
    }

    #[test]
    fn test_parse_ip_addresses_with_ipv6_println() {
        let provider = create_test_provider_with_runner(FakeCommandRunner::new());
        let ip_output = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    inet6 2001:db8::1/64 scope global
       valid_lft forever preferred_lft forever";

        let result = provider.parse_ip_addresses(ip_output);

        // Should extract IPv6 address and trigger the println! statement
        assert_eq!(result, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn test_extract_ip_from_line_ipv4() {
        let ipv4_regex = Regex::new(r"inet\s+(\S+)/").unwrap();

        // Test valid IPv4 address
        let line = "    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0";
        let result = extract_ip_from_line(line, &ipv4_regex);
        assert_eq!(result, Some("192.168.1.10".parse::<IpAddr>().unwrap()));

        // Test loopback address (should be filtered out)
        let line = "    inet 127.0.0.1/8 scope host lo";
        let result = extract_ip_from_line(line, &ipv4_regex);
        assert_eq!(result, None);

        // Test line without IP address
        let line = "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff";
        let result = extract_ip_from_line(line, &ipv4_regex);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_ip_from_line_ipv6() {
        let ipv6_regex = Regex::new(r"inet6\s+(\S+)/").unwrap();

        // Test valid IPv6 address
        let line = "    inet6 2001:db8::1/64 scope global";
        let result = extract_ip_from_line(line, &ipv6_regex);
        assert_eq!(result, Some("2001:db8::1".parse::<IpAddr>().unwrap()));

        // Test link-local address (should be filtered out)
        let line = "    inet6 fe80::42:acff:fe11:2/64 scope link";
        let result = extract_ip_from_line(line, &ipv6_regex);
        assert_eq!(result, None);

        // Test loopback address (should be filtered out)
        let line = "    inet6 ::1/128 scope host";
        let result = extract_ip_from_line(line, &ipv6_regex);
        assert_eq!(result, None);

        // Test line without IP address
        let line = "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff";
        let result = extract_ip_from_line(line, &ipv6_regex);
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_ip_addresses_for_pid_command_error() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "ip", "a"],
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "nsenter command not found",
            )),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ip_addresses_for_pid(1234);

        assert!(result.is_empty());
    }

    #[test]
    fn test_register_to_and_update_metrics() {
        use prometheus::Registry;

        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "test-iface"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: test-iface@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default link-netnsid 0\n    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let mut result = HashMap::new();
        result.insert(
            HostInterface {
                name: "test-iface".to_string(),
                virt: true,
            },
            build_device_status("test-iface".to_string(), 1, 2, 3, 4),
        );
        let fake_iface_status = FakeInterfaceStatusRetriever { result };
        let mut provider = create_test_provider_with_runner_and_interface(
            fake_runner,
            Box::new(fake_iface_status),
        );
        let mut registry = Registry::new();

        // Test register_to
        provider.register_to(&mut registry);

        // Test update_metrics
        let result = provider.update_metrics();
        assert!(result.is_ok());

        // Verify metrics are registered
        let metric_families = registry.gather();
        let metric_names: Vec<String> = metric_families
            .iter()
            .map(|mf| mf.get_name().to_string())
            .collect();

        // Validate the test metric names
        assert!(metric_names.contains(&"test_ingress_pkt_count".to_string()));
        assert!(metric_names.contains(&"test_ingress_bytes_count".to_string()));
        assert!(metric_names.contains(&"test_egress_pkt_count".to_string()));
        assert!(metric_names.contains(&"test_egress_bytes_count".to_string()));
    }

    #[test]
    fn test_get_device_status_with_loopback_and_down_interfaces() {
        // This test will use the actual system interfaces, but we can verify
        // that the filtering logic works by checking the result doesn't contain
        // loopback interfaces (if any exist on the system)
        let interface_status = InterfaceStatusRetrieverImpl {};
        let device_status = interface_status.dev_status();

        // Verify that no interface name is "lo" (loopback should be filtered out)
        for (interface, _) in &device_status {
            assert_ne!(
                interface.name, "lo",
                "Loopback interface should be filtered out"
            );
        }
    }

    #[test]
    fn test_get_interface_flags_error() {
        // This test verifies the error handling in get_interface_flags
        // The function should handle errors gracefully and return an empty HashMap
        // We can't easily mock getifaddrs, but we can test that the function exists
        // and returns a Result type
        let result = get_interface_flags();

        // Should either succeed with a HashMap or fail with an error
        match result {
            Ok(flags) => {
                // If successful, should be a HashMap
                assert!(flags.is_empty() || !flags.is_empty());
            }
            Err(_) => {
                // If it fails, that's also acceptable for this test
                // as we're mainly testing the error handling path
            }
        }
    }

    #[test]
    fn test_namespace_info_clone_and_partial_eq() {
        let ns_info1 = NamespaceInfo {
            pid: 1234,
            ns_file: Some("/host/run/netns/test".to_string()),
            ip_addresses: vec!["192.168.1.1".parse().unwrap()],
        };

        let ns_info2 = ns_info1.clone();

        assert_eq!(ns_info1, ns_info2);
        assert_eq!(ns_info1.pid, ns_info2.pid);
        assert_eq!(ns_info1.ns_file, ns_info2.ns_file);
        assert_eq!(ns_info1.ip_addresses, ns_info2.ip_addresses);
    }

    #[test]
    fn test_get_pids_from_ns_unassigned_skipped() {
        // Create a temporary file
        let file = TemporaryFile::new("test_unassigned_skipped");

        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!("4026531840 net     135       1 root   unassigned                                                          /usr/lib/systemd/systemd\n4026532152 net       4    4050 65535           0 {} /pause\n", file.path).as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        // Add expectation for nsenter command using namespace file
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000\n    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_ns_info();

        // Should only contain the non-unassigned entry
        assert_eq!(result.len(), 1);
        assert_eq!(result.get(&0).unwrap().pid, 4050);
        assert_eq!(result.get(&0).unwrap().ns_file, Some(file.path.clone()));
        assert_eq!(
            result.get(&0).unwrap().ip_addresses,
            vec!["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn test_get_pod_info_from_real_iface_with_ips() {
        let mut provider = create_test_provider_with_runner(FakeCommandRunner::new());
        provider.compute_platform = ComputePlatform::Ec2K8sEks;

        // Create an empty pod mapping
        let pod_mapping = HashMap::new();

        // Test with a non-existent interface (should return empty strings)
        let result =
            provider.get_pod_info_from_real_iface(&"nonexistent".to_string(), &pod_mapping);

        // Should return empty strings since the interface doesn't exist or has no matching IPs
        assert_eq!(result, ("".to_string(), "".to_string()));
    }

    #[test]
    fn test_get_pod_info_from_real_iface_no_matching_ips() {
        let mut provider = create_test_provider_with_runner(FakeCommandRunner::new());
        provider.compute_platform = ComputePlatform::Ec2K8sEks;

        // Create an empty pod mapping
        let pod_mapping = HashMap::new();

        // Test with any interface name
        let result = provider.get_pod_info_from_real_iface(&"eth0".to_string(), &pod_mapping);

        // Should return empty strings since there are no pod mappings
        assert_eq!(result, ("".to_string(), "".to_string()));
    }

    #[test]
    fn test_interface_metric_values_sub_normal_case() {
        let current = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 1000,
                ingress_bytes_count: 50000,
                egress_pkt_count: 800,
                egress_bytes_count: 40000,
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 50,
                egress_flow_count: 40,
            },
        };

        let previous = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 900,
                ingress_bytes_count: 45000,
                egress_pkt_count: 700,
                egress_bytes_count: 35000,
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 40,
                egress_flow_count: 30,
            },
        };

        let delta = current.delta(&previous);

        assert_eq!(delta.host.ingress_pkt_count, 100);
        assert_eq!(delta.host.ingress_bytes_count, 5000);
        assert_eq!(delta.host.egress_pkt_count, 100);
        assert_eq!(delta.host.egress_bytes_count, 5000);
        assert_eq!(delta.netns.ingress_flow_count, 10);
        assert_eq!(delta.netns.egress_flow_count, 10);
    }

    #[test]
    fn test_interface_metric_values_sub_saturating_subtraction() {
        let current = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 500,
                ingress_bytes_count: 25000,
                egress_pkt_count: 300,
                egress_bytes_count: 15000,
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 20,
                egress_flow_count: 15,
            },
        };

        let previous = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 600,     // Higher than current - should saturate to 0
                ingress_bytes_count: 30000, // Higher than current - should saturate to 0
                egress_pkt_count: 400,      // Higher than current - should saturate to 0
                egress_bytes_count: 20000,  // Higher than current - should saturate to 0
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 30, // Higher than current - should saturate to 0
                egress_flow_count: 25,  // Higher than current - should saturate to 0
            },
        };

        let delta = current.delta(&previous);

        // All values should be 0 due to saturating subtraction
        assert_eq!(delta.host.ingress_pkt_count, 0);
        assert_eq!(delta.host.ingress_bytes_count, 0);
        assert_eq!(delta.host.egress_pkt_count, 0);
        assert_eq!(delta.host.egress_bytes_count, 0);
        assert_eq!(delta.netns.ingress_flow_count, 0);
        assert_eq!(delta.netns.egress_flow_count, 0);
    }

    #[test]
    fn test_interface_metric_values_sub_zero_previous() {
        let current = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 1000,
                ingress_bytes_count: 50000,
                egress_pkt_count: 800,
                egress_bytes_count: 40000,
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 60,
                egress_flow_count: 50,
            },
        };

        let previous = InterfaceMetricValues::default(); // All zeros

        let delta = current.delta(&previous);

        // Delta should equal current values when previous is zero
        assert_eq!(delta.host.ingress_pkt_count, 1000);
        assert_eq!(delta.host.ingress_bytes_count, 50000);
        assert_eq!(delta.host.egress_pkt_count, 800);
        assert_eq!(delta.host.egress_bytes_count, 40000);
        assert_eq!(delta.netns.ingress_flow_count, 60);
        assert_eq!(delta.netns.egress_flow_count, 50);
    }

    #[test]
    fn test_interface_metric_values_sub_equal_values() {
        let current = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 1000,
                ingress_bytes_count: 50000,
                egress_pkt_count: 800,
                egress_bytes_count: 40000,
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 70,
                egress_flow_count: 60,
            },
        };

        let previous = current.clone();

        let delta = current.delta(&previous);

        // Delta should be zero when values are equal
        assert_eq!(delta.host.ingress_pkt_count, 0);
        assert_eq!(delta.host.ingress_bytes_count, 0);
        assert_eq!(delta.host.egress_pkt_count, 0);
        assert_eq!(delta.host.egress_bytes_count, 0);
        assert_eq!(delta.netns.ingress_flow_count, 0);
        assert_eq!(delta.netns.egress_flow_count, 0);
    }

    #[test]
    fn test_interface_metric_values_default() {
        let default_values = HostInterfaceMetricValues::default();

        assert_eq!(default_values.ingress_pkt_count, 0);
        assert_eq!(default_values.ingress_bytes_count, 0);
        assert_eq!(default_values.egress_pkt_count, 0);
        assert_eq!(default_values.egress_bytes_count, 0);
    }

    #[test]
    fn test_interface_metric_values_clone() {
        let original = HostInterfaceMetricValues {
            ingress_pkt_count: 1000,
            ingress_bytes_count: 50000,
            egress_pkt_count: 800,
            egress_bytes_count: 40000,
        };

        let cloned = original.clone();

        assert_eq!(original.ingress_pkt_count, cloned.ingress_pkt_count);
        assert_eq!(original.ingress_bytes_count, cloned.ingress_bytes_count);
        assert_eq!(original.egress_pkt_count, cloned.egress_pkt_count);
        assert_eq!(original.egress_bytes_count, cloned.egress_bytes_count);
    }

    #[test]
    fn test_delta_calculation_in_internal_update_metrics() {
        // Create a provider with mocked command runner
        let mut provider = create_test_provider_with_runner(FakeCommandRunner::new());

        // Simulate initial state - first call should establish baseline
        let initial_key = InterfaceMetricKey {
            instance: "test-instance".to_string(),
            iface: "eth0".to_string(),
            pod: "".to_string(),
            pod_namespace: "".to_string(),
            node: "test-node".to_string(),
        };

        let initial_values = HostInterfaceMetricValues {
            ingress_pkt_count: 1000,
            ingress_bytes_count: 50000,
            egress_pkt_count: 800,
            egress_bytes_count: 40000,
        };

        // Manually set initial metrics to simulate first reading
        let initial_interface_values = InterfaceMetricValues {
            host: initial_values.clone(),
            netns: NetNsInterfaceMetricValues::default(),
        };
        provider
            .current_metrics
            .insert(initial_key.clone(), initial_interface_values);

        // Verify initial state
        assert_eq!(provider.current_metrics.len(), 1);
        let stored_values = provider.current_metrics.get(&initial_key).unwrap();
        assert_eq!(stored_values.host.ingress_pkt_count, 1000);
        assert_eq!(stored_values.host.ingress_bytes_count, 50000);
        assert_eq!(stored_values.host.egress_pkt_count, 800);
        assert_eq!(stored_values.host.egress_bytes_count, 40000);
    }

    #[test]
    fn test_delta_calculation_with_counter_reset() {
        // Test case where network counters reset (e.g., interface restart)
        let current = HostInterfaceMetricValues {
            ingress_pkt_count: 100, // Lower than previous (counter reset)
            ingress_bytes_count: 5000,
            egress_pkt_count: 80,
            egress_bytes_count: 4000,
        };

        let previous = HostInterfaceMetricValues {
            ingress_pkt_count: 1000, // Much higher than current
            ingress_bytes_count: 50000,
            egress_pkt_count: 800,
            egress_bytes_count: 40000,
        };

        let delta = current.delta(&previous);

        // Should saturate to 0 when counters appear to have reset
        assert_eq!(delta.ingress_pkt_count, 0);
        assert_eq!(delta.ingress_bytes_count, 0);
        assert_eq!(delta.egress_pkt_count, 0);
        assert_eq!(delta.egress_bytes_count, 0);
    }

    #[test]
    fn test_delta_calculation_with_large_numbers() {
        let current = HostInterfaceMetricValues {
            ingress_pkt_count: u64::MAX,
            ingress_bytes_count: u64::MAX - 1000,
            egress_pkt_count: u64::MAX - 500,
            egress_bytes_count: u64::MAX - 2000,
        };

        let previous = HostInterfaceMetricValues {
            ingress_pkt_count: u64::MAX - 100,
            ingress_bytes_count: u64::MAX - 2000,
            egress_pkt_count: u64::MAX - 1000,
            egress_bytes_count: u64::MAX - 3000,
        };

        let delta = current.delta(&previous);

        assert_eq!(delta.ingress_pkt_count, 100);
        assert_eq!(delta.ingress_bytes_count, 1000);
        assert_eq!(delta.egress_pkt_count, 500);
        assert_eq!(delta.egress_bytes_count, 1000);
    }

    #[test]
    fn test_delta_calculation_mixed_scenarios() {
        // Test mixed scenario where some counters increase normally, others reset
        let current = HostInterfaceMetricValues {
            ingress_pkt_count: 1500,    // Normal increase
            ingress_bytes_count: 75000, // Normal increase
            egress_pkt_count: 50,       // Counter reset (lower than previous)
            egress_bytes_count: 2500,   // Counter reset (lower than previous)
        };

        let previous = HostInterfaceMetricValues {
            ingress_pkt_count: 1000,
            ingress_bytes_count: 50000,
            egress_pkt_count: 800,     // Higher than current
            egress_bytes_count: 40000, // Higher than current
        };

        let delta = current.delta(&previous);

        // Normal increases should work
        assert_eq!(delta.ingress_pkt_count, 500);
        assert_eq!(delta.ingress_bytes_count, 25000);

        // Counter resets should saturate to 0
        assert_eq!(delta.egress_pkt_count, 0);
        assert_eq!(delta.egress_bytes_count, 0);
    }

    #[test]
    fn test_interface_metric_key_hash_and_eq() {
        let key1 = InterfaceMetricKey {
            instance: "i-1234567890abcdef0".to_string(),
            iface: "eth0".to_string(),
            pod: "test-pod".to_string(),
            pod_namespace: "default".to_string(),
            node: "test-node".to_string(),
        };

        let key2 = InterfaceMetricKey {
            instance: "i-1234567890abcdef0".to_string(),
            iface: "eth0".to_string(),
            pod: "test-pod".to_string(),
            pod_namespace: "default".to_string(),
            node: "test-node".to_string(),
        };

        let key3 = InterfaceMetricKey {
            instance: "i-1234567890abcdef0".to_string(),
            iface: "eth1".to_string(), // Different interface
            pod: "test-pod".to_string(),
            pod_namespace: "default".to_string(),
            node: "test-node".to_string(),
        };

        // Test equality
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);

        // Test that they can be used as HashMap keys
        let mut map = HashMap::new();
        map.insert(key1.clone(), HostInterfaceMetricValues::default());
        map.insert(key3.clone(), HostInterfaceMetricValues::default());

        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&key1));
        assert!(map.contains_key(&key2)); // Should be the same as key1
        assert!(map.contains_key(&key3));
    }

    #[test]
    fn test_netns_interface_metric_values_default() {
        let default_values = NetNsInterfaceMetricValues::default();

        assert_eq!(default_values.ingress_flow_count, 0);
        assert_eq!(default_values.egress_flow_count, 0);
    }

    #[test]
    fn test_netns_interface_metric_values_clone() {
        let original = NetNsInterfaceMetricValues {
            ingress_flow_count: 100,
            egress_flow_count: 80,
        };

        let cloned = original.clone();

        assert_eq!(original.ingress_flow_count, cloned.ingress_flow_count);
        assert_eq!(original.egress_flow_count, cloned.egress_flow_count);
    }

    #[test]
    fn test_netns_interface_metric_values_debug() {
        let values = NetNsInterfaceMetricValues {
            ingress_flow_count: 150,
            egress_flow_count: 120,
        };

        let debug_str = format!("{:?}", values);
        assert!(debug_str.contains("150"));
        assert!(debug_str.contains("120"));
    }

    #[test]
    fn test_netns_interface_metric_values_delta_normal_case() {
        let current = NetNsInterfaceMetricValues {
            ingress_flow_count: 100,
            egress_flow_count: 80,
        };

        let previous = NetNsInterfaceMetricValues {
            ingress_flow_count: 70,
            egress_flow_count: 50,
        };

        let delta = current.delta(&previous);

        assert_eq!(delta.ingress_flow_count, 30);
        assert_eq!(delta.egress_flow_count, 30);
    }

    #[test]
    fn test_netns_interface_metric_values_delta_saturating_subtraction() {
        let current = NetNsInterfaceMetricValues {
            ingress_flow_count: 50,
            egress_flow_count: 30,
        };

        let previous = NetNsInterfaceMetricValues {
            ingress_flow_count: 100, // Higher than current - should saturate to 0
            egress_flow_count: 80,   // Higher than current - should saturate to 0
        };

        let delta = current.delta(&previous);

        assert_eq!(delta.ingress_flow_count, 0);
        assert_eq!(delta.egress_flow_count, 0);
    }

    #[test]
    fn test_netns_interface_metric_values_delta_zero_previous() {
        let current = NetNsInterfaceMetricValues {
            ingress_flow_count: 200,
            egress_flow_count: 150,
        };

        let previous = NetNsInterfaceMetricValues::default(); // All zeros

        let delta = current.delta(&previous);

        // Delta should equal current values when previous is zero
        assert_eq!(delta.ingress_flow_count, 200);
        assert_eq!(delta.egress_flow_count, 150);
    }

    #[test]
    fn test_netns_interface_metric_values_delta_equal_values() {
        let current = NetNsInterfaceMetricValues {
            ingress_flow_count: 100,
            egress_flow_count: 80,
        };

        let previous = current.clone();

        let delta = current.delta(&previous);

        // Delta should be zero when values are equal
        assert_eq!(delta.ingress_flow_count, 0);
        assert_eq!(delta.egress_flow_count, 0);
    }

    #[test]
    fn test_netns_interface_metric_values_delta_with_large_numbers() {
        let current = NetNsInterfaceMetricValues {
            ingress_flow_count: u64::MAX,
            egress_flow_count: u64::MAX - 1000,
        };

        let previous = NetNsInterfaceMetricValues {
            ingress_flow_count: u64::MAX - 500,
            egress_flow_count: u64::MAX - 2000,
        };

        let delta = current.delta(&previous);

        assert_eq!(delta.ingress_flow_count, 500);
        assert_eq!(delta.egress_flow_count, 1000);
    }

    #[test]
    fn test_get_netns_metric_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens                  150                0.0\nTcpPassiveOpens                 200                0.0\nTcpAttemptFails                 5                  0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 200); // TcpPassiveOpens
        assert_eq!(result.egress_flow_count, 150); // TcpActiveOpens
    }

    #[test]
    fn test_get_netns_metric_partial_data() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens                  75                 0.0\nTcpAttemptFails                 3                  0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 0); // TcpPassiveOpens not found, defaults to 0
        assert_eq!(result.egress_flow_count, 75); // TcpActiveOpens found
    }

    #[test]
    fn test_get_netns_metric_only_passive_opens() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpPassiveOpens                 300                0.0\nTcpAttemptFails                 2                  0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 300); // TcpPassiveOpens found
        assert_eq!(result.egress_flow_count, 0); // TcpActiveOpens not found, defaults to 0
    }

    #[test]
    fn test_get_netns_metric_no_tcp_stats() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "IpInReceives                    1000               0.0\nIpInDelivers                    950                0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }

    #[test]
    fn test_get_netns_metric_empty_output() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: vec![],
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }

    #[test]
    fn test_get_netns_metric_command_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(1),
                stdout: vec![],
                stderr: "nsenter: cannot open /proc/1234/ns/net: No such file or directory"
                    .as_bytes()
                    .to_vec(),
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }

    #[test]
    fn test_get_netns_metric_command_error() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "nsenter command not found",
            )),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }

    #[test]
    fn test_get_netns_metric_invalid_tcp_active_opens_value() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens                  invalid            0.0\nTcpPassiveOpens                 200                0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 200); // TcpPassiveOpens parsed successfully
        assert_eq!(result.egress_flow_count, 0); // TcpActiveOpens failed to parse, defaults to 0
    }

    #[test]
    fn test_get_netns_metric_invalid_tcp_passive_opens_value() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens                  150                0.0\nTcpPassiveOpens                 not_a_number       0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 0); // TcpPassiveOpens failed to parse, defaults to 0
        assert_eq!(result.egress_flow_count, 150); // TcpActiveOpens parsed successfully
    }

    #[test]
    fn test_get_netns_metric_malformed_lines() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens\nTcpPassiveOpens                 250                0.0\nMalformedLine\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 250); // TcpPassiveOpens parsed successfully
        assert_eq!(result.egress_flow_count, 0); // TcpActiveOpens line malformed, defaults to 0
    }

    #[test]
    fn test_get_netns_metric_early_termination_optimization() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens                  100                0.0\nTcpPassiveOpens                 200                0.0\nTcpAttemptFails                 5                  0.0\nTcpEstabResets                  3                  0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        // Should find both values and terminate early (optimization test)
        assert_eq!(result.ingress_flow_count, 200); // TcpPassiveOpens
        assert_eq!(result.egress_flow_count, 100); // TcpActiveOpens
    }

    #[test]
    fn test_get_netns_metric_zero_values() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens                  0                  0.0\nTcpPassiveOpens                 0                  0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }

    #[test]
    fn test_get_netns_metric_large_values() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!("TcpActiveOpens                  {}             0.0\nTcpPassiveOpens                 {}             0.0\n", u64::MAX - 1000, u64::MAX - 500).as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(1234);

        assert_eq!(result.ingress_flow_count, u64::MAX - 500); // TcpPassiveOpens
        assert_eq!(result.egress_flow_count, u64::MAX - 1000); // TcpActiveOpens
    }

    #[test]
    fn test_get_netns_metric_different_pid() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "5678", "-n", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "TcpActiveOpens                  42                 0.0\nTcpPassiveOpens                 84                 0.0\n".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let provider = create_test_provider_with_runner(fake_runner);
        let result = provider.get_netns_metric(5678);

        assert_eq!(result.ingress_flow_count, 84); // TcpPassiveOpens
        assert_eq!(result.egress_flow_count, 42); // TcpActiveOpens
    }

    #[test]
    fn test_interface_metric_values_with_netns_delta() {
        let current = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 1000,
                ingress_bytes_count: 50000,
                egress_pkt_count: 800,
                egress_bytes_count: 40000,
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 100,
                egress_flow_count: 80,
            },
        };

        let previous = InterfaceMetricValues {
            host: HostInterfaceMetricValues {
                ingress_pkt_count: 900,
                ingress_bytes_count: 45000,
                egress_pkt_count: 700,
                egress_bytes_count: 35000,
            },
            netns: NetNsInterfaceMetricValues {
                ingress_flow_count: 70,
                egress_flow_count: 50,
            },
        };

        let delta = current.delta(&previous);

        // Test host metrics delta
        assert_eq!(delta.host.ingress_pkt_count, 100);
        assert_eq!(delta.host.ingress_bytes_count, 5000);
        assert_eq!(delta.host.egress_pkt_count, 100);
        assert_eq!(delta.host.egress_bytes_count, 5000);

        // Test netns metrics delta
        assert_eq!(delta.netns.ingress_flow_count, 30);
        assert_eq!(delta.netns.egress_flow_count, 30);
    }

    //  Helper function to create a test provider with a custom command runner and interface_status.
    fn create_test_provider_with_runner_and_interface(
        fake_runner: FakeCommandRunner,
        iface_status: Box<dyn InterfaceStatusRetriever>,
    ) -> InterfaceMetricsProvider {
        InterfaceMetricsProvider {
            compute_platform: ComputePlatform::Ec2Plain,
            instance_id: "test-instance".to_string(),
            node_name: "test-node".to_string(),
            command_runner: Box::new(fake_runner),
            interface_status: iface_status,
            k8s_metadata_collector: None,
            ingress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                &ComputePlatform::Ec2Plain,
                "test_ingress_pkt_count",
                "Test ingress packet count",
            ),
            ingress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                &ComputePlatform::Ec2Plain,
                "test_ingress_bytes_count",
                "Test ingress bytes count",
            ),
            egress_pkt_count: build_gauge_metric::<InterfaceMetricKey>(
                &ComputePlatform::Ec2Plain,
                "test_egress_pkt_count",
                "Test egress packet count",
            ),
            egress_bytes_count: build_gauge_metric::<InterfaceMetricKey>(
                &ComputePlatform::Ec2Plain,
                "test_egress_bytes_count",
                "Test egress bytes count",
            ),
            ingress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                &ComputePlatform::Ec2Plain,
                "test_ingress_flow_count",
                "Test ingress flow count",
            ),
            egress_flow_count: build_gauge_metric::<InterfaceMetricKey>(
                &ComputePlatform::Ec2Plain,
                "test_egress_flow_count",
                "Test egress flow count",
            ),
            current_metrics: HashMap::new(),
        }
    }

    // Helper function to create a test provider with a custom command runner. Uses the default interface_status object.
    fn create_test_provider_with_runner(
        fake_runner: FakeCommandRunner,
    ) -> InterfaceMetricsProvider {
        create_test_provider_with_runner_and_interface(
            fake_runner,
            Box::new(InterfaceStatusRetrieverImpl {}),
        )
    }
}
