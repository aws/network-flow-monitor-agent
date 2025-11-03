// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Interface discovery and filtering for interface metrics provider.

use std::collections::HashMap;

use anyhow::{Context, Result};
use getifaddrs::{getifaddrs, InterfaceFilter, InterfaceFlags};
use log::{debug, info};
use nfm_common::IpAddrLinkLocal;
use procfs::net::{dev_status, DeviceStatus};
use std::collections::HashSet;
use std::net::IpAddr;

use crate::kubernetes::kubernetes_metadata_collector::PodInfo;
use crate::open_metrics::providers::interface_metrics_provider::types::NamespaceInfo;

use super::types::HostInterface;

/// Host-level interface statistics
#[derive(Debug, Clone, Default)]
pub struct HostInterfaceMetricValues {
    pub ingress_pkt_count: u64,
    pub ingress_bytes_count: u64,
    pub egress_pkt_count: u64,
    pub egress_bytes_count: u64,
}

impl HostInterfaceMetricValues {
    pub fn new(recv_packets: u64, recv_bytes: u64, sent_packets: u64, sent_bytes: u64) -> Self {
        Self {
            ingress_pkt_count: recv_packets,
            ingress_bytes_count: recv_bytes,
            egress_pkt_count: sent_packets,
            egress_bytes_count: sent_bytes,
        }
    }

    /// Swap TX/RX for veth interfaces (pod is on the other end)
    pub fn swap_tx_rx(&mut self) {
        std::mem::swap(&mut self.ingress_pkt_count, &mut self.egress_pkt_count);
        std::mem::swap(&mut self.ingress_bytes_count, &mut self.egress_bytes_count);
    }

    pub fn calculate_delta(&self, previous: &Self) -> Self {
        Self {
            ingress_pkt_count: self
                .ingress_pkt_count
                .saturating_sub(previous.ingress_pkt_count),
            ingress_bytes_count: self
                .ingress_bytes_count
                .saturating_sub(previous.ingress_bytes_count),
            egress_pkt_count: self
                .egress_pkt_count
                .saturating_sub(previous.egress_pkt_count),
            egress_bytes_count: self
                .egress_bytes_count
                .saturating_sub(previous.egress_bytes_count),
        }
    }
}

/// Discovers and filters network interfaces
pub trait InterfaceDiscovery {
    fn get_virtual_interface_stats(&self) -> Result<HashMap<HostInterface, DeviceStatus>>;
}

pub struct InterfaceDiscoveryImpl;

impl InterfaceDiscovery for InterfaceDiscoveryImpl {
    /// Get interface statistics with filtering for virtual interfaces
    fn get_virtual_interface_stats(&self) -> Result<HashMap<HostInterface, DeviceStatus>> {
        let interfaces =
            dev_status().context("Failed to read network interface statistics from procfs")?;

        let interface_flags = get_interface_flags().context("Failed to get interface flags")?;

        let filtered_interfaces = interfaces
            .into_iter()
            .map(|(name, status)| (HostInterface::new(name), status))
            .filter(|(iface, _)| should_include_interface(iface, &interface_flags))
            .collect();

        Ok(filtered_interfaces)
    }
}

/// Check if interface should be included in metrics
pub fn should_include_interface(
    interface: &HostInterface,
    flags: &HashMap<String, InterfaceFlags>,
) -> bool {
    let Some(interface_flags) = flags.get(&interface.name) else {
        info!("Interface flags not found for {}", interface.name);
        return false;
    };

    if interface_flags.contains(InterfaceFlags::LOOPBACK) {
        debug!("Skipping loopback interface: {}", interface.name);
        return false;
    }

    if !interface_flags.contains(InterfaceFlags::UP) {
        debug!("Skipping non-UP interface: {}", interface.name);
        return false;
    }

    // Only report Pod Network metrics (virtual interfaces)
    if !interface.is_virtual() {
        debug!("Skipping non-virtual interface: {}", interface.name);
        return false;
    }

    true
}

/// Get interface flags using getifaddrs
pub fn get_interface_flags() -> Result<HashMap<String, InterfaceFlags>> {
    let mut interface_flags = HashMap::new();
    let ifaddrs = getifaddrs().context("Failed to get interface addresses")?;

    for interface in ifaddrs {
        interface_flags.insert(interface.name, interface.flags);
    }

    Ok(interface_flags)
}

/// Get IP addresses for a specific interface using getifaddrs with InterfaceFilter
pub fn get_interface_ips(iface_name: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
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

/// Get pod information for an interface
pub fn get_pod_info_from_iface(
    interface_name: &str,
    namespace_info: &HashMap<super::types::NamespaceId, super::types::NamespaceInfo>,
    pod_mappings: &HashMap<IpAddr, HashSet<PodInfo>>,
    namespace_id: Option<super::types::NamespaceId>,
) -> (String, String) {
    match namespace_id {
        Some(ns_id) => get_pod_info_from_netns(namespace_info.get(&ns_id), pod_mappings),
        None => get_pod_info_from_real_iface(interface_name, pod_mappings),
    }
}

/// Get the Pod information for a namespace. It returns the Pod's name and namespace
pub fn get_pod_info_from_netns(
    ns_info: Option<&NamespaceInfo>,
    pod_info_mapping: &HashMap<IpAddr, HashSet<PodInfo>>,
) -> (String, String) {
    match ns_info {
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
            (String::new(), String::new())
        }
        _ => (String::new(), String::new()),
    }
}

/// Get the Pod information for a interface that has no network namespace associated.
pub fn get_pod_info_from_real_iface(
    iface_name: &str,
    pod_info_mapping: &HashMap<IpAddr, HashSet<PodInfo>>,
) -> (String, String) {
    // Get IP addresses from the interface
    match get_interface_ips(iface_name) {
        Ok(ip_addresses) => {
            for ip_addr in ip_addresses {
                match pod_info_mapping.get(&ip_addr) {
                    Some(pod_info) => match pod_info.iter().next() {
                        Some(pod) => return (pod.name.clone(), pod.namespace.clone()),
                        None => continue,
                    },
                    None => continue,
                }
            }
            (String::new(), String::new())
        }
        Err(_) => (String::new(), String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_interface_metric_values_new() {
        let metrics = HostInterfaceMetricValues::new(1000, 50000, 800, 40000);
        assert_eq!(metrics.ingress_pkt_count, 1000);
        assert_eq!(metrics.ingress_bytes_count, 50000);
        assert_eq!(metrics.egress_pkt_count, 800);
        assert_eq!(metrics.egress_bytes_count, 40000);
    }

    #[test]
    fn test_host_interface_metric_values_swap_tx_rx() {
        let mut value = HostInterfaceMetricValues::new(1000, 50000, 800, 40000);
        value.swap_tx_rx();

        assert_eq!(value.ingress_pkt_count, 800);
        assert_eq!(value.ingress_bytes_count, 40000);
        assert_eq!(value.egress_pkt_count, 1000);
        assert_eq!(value.egress_bytes_count, 50000);
    }

    #[test]
    fn test_host_interface_metric_values_delta() {
        let current = HostInterfaceMetricValues::new(1000, 50000, 800, 40000);
        let previous = HostInterfaceMetricValues::new(900, 45000, 700, 35000);

        let delta = current.calculate_delta(&previous);

        assert_eq!(delta.ingress_pkt_count, 100);
        assert_eq!(delta.ingress_bytes_count, 5000);
        assert_eq!(delta.egress_pkt_count, 100);
        assert_eq!(delta.egress_bytes_count, 5000);
    }

    #[test]
    fn test_should_include_interface_logic() {
        let mut flags = HashMap::new();

        // Test interface not found in flags
        let interface = HostInterface::new("test0".to_string());
        assert!(!should_include_interface(&interface, &flags));

        // Test loopback interface (should be excluded)
        flags.insert(
            "lo".to_string(),
            InterfaceFlags::LOOPBACK | InterfaceFlags::UP,
        );
        let loopback = HostInterface::new("lo".to_string());
        assert!(!should_include_interface(&loopback, &flags));

        // Test non-UP interface (should be excluded)
        flags.insert("down0".to_string(), InterfaceFlags::empty());
        let down_interface = HostInterface::new("down0".to_string());
        assert!(!should_include_interface(&down_interface, &flags));
    }

    #[test]
    fn test_get_pod_info_from_real_iface_no_match() {
        let pod_mappings = HashMap::new();
        let result = get_pod_info_from_real_iface("eth0", &pod_mappings);
        assert_eq!(result, (String::new(), String::new()));
    }

    #[test]
    fn test_host_interface_metric_values_default() {
        let default_metrics = HostInterfaceMetricValues::default();
        assert_eq!(default_metrics.ingress_pkt_count, 0);
        assert_eq!(default_metrics.ingress_bytes_count, 0);
        assert_eq!(default_metrics.egress_pkt_count, 0);
        assert_eq!(default_metrics.egress_bytes_count, 0);
    }

    #[test]
    fn test_host_interface_metric_values_delta_saturating() {
        let current = HostInterfaceMetricValues::new(500, 25000, 400, 20000);
        let previous = HostInterfaceMetricValues::new(1000, 50000, 800, 40000); // Higher than current

        let delta = current.calculate_delta(&previous);

        // Should saturate to 0 when previous is higher than current
        assert_eq!(delta.ingress_pkt_count, 0);
        assert_eq!(delta.ingress_bytes_count, 0);
        assert_eq!(delta.egress_pkt_count, 0);
        assert_eq!(delta.egress_bytes_count, 0);
    }

    #[test]
    fn test_should_include_interface_virtual_up() {
        let mut flags = HashMap::new();

        // Test virtual interface that is UP (should be included)
        flags.insert("veth123".to_string(), InterfaceFlags::UP);
        let veth_interface = HostInterface::new("veth123".to_string());
        assert!(should_include_interface(&veth_interface, &flags));

        // Test docker interface that is UP (should be included)
        flags.insert("docker0".to_string(), InterfaceFlags::UP);
        let docker_interface = HostInterface::new("docker0".to_string());
        assert!(should_include_interface(&docker_interface, &flags));
    }

    #[test]
    fn test_should_include_interface_physical() {
        let mut flags = HashMap::new();

        // Test physical interface (should be excluded even if UP)
        flags.insert("eth0".to_string(), InterfaceFlags::UP);
        let eth_interface = HostInterface::new("eth0".to_string());
        assert!(!should_include_interface(&eth_interface, &flags));
    }

    #[test]
    fn test_get_pod_info_from_netns_found() {
        use super::super::types::{NamespaceId, NamespaceInfo, ProcessId};
        use crate::kubernetes::kubernetes_metadata_collector::PodInfo;

        let mut namespace_info = HashMap::new();
        let mut pod_mappings = HashMap::new();

        let ip_addr: IpAddr = "192.168.1.10".parse().unwrap();
        let ns_id = NamespaceId::new(42);

        // Create namespace info with IP address
        let ns_info = NamespaceInfo {
            pid: ProcessId::new(1234),
            ns_file: Some("/test/ns".to_string()),
            ip_addresses: vec![ip_addr],
        };
        namespace_info.insert(ns_id, ns_info);

        // Create pod info for the IP
        let pod_info = PodInfo {
            name: "test-pod".to_string(),
            namespace: "test-namespace".to_string(),
            service_name: "test-service".to_string(),
        };
        let mut pod_set = HashSet::new();
        pod_set.insert(pod_info);
        pod_mappings.insert(ip_addr, pod_set);

        let result = get_pod_info_from_netns(namespace_info.get(&ns_id), &pod_mappings);
        assert_eq!(
            result,
            ("test-pod".to_string(), "test-namespace".to_string())
        );
    }

    #[test]
    fn test_get_pod_info_from_netns_not_found() {
        use super::super::types::NamespaceId;

        let namespace_info: HashMap<NamespaceId, NamespaceInfo> = HashMap::new();
        let pod_mappings = HashMap::new();
        let ns_id = NamespaceId::new(42);

        let result = get_pod_info_from_netns(namespace_info.get(&ns_id), &pod_mappings);
        assert_eq!(result, (String::new(), String::new()));
    }

    #[test]
    fn test_get_pod_info_from_netns_no_pod_match() {
        use super::super::types::{NamespaceId, NamespaceInfo, ProcessId};

        let mut namespace_info = HashMap::new();
        let pod_mappings = HashMap::new();

        let ip_addr: IpAddr = "192.168.1.10".parse().unwrap();
        let ns_id = NamespaceId::new(42);

        // Create namespace info with IP address but no corresponding pod mapping
        let ns_info = NamespaceInfo {
            pid: ProcessId::new(1234),
            ns_file: Some("/test/ns".to_string()),
            ip_addresses: vec![ip_addr],
        };
        namespace_info.insert(ns_id, ns_info);

        let result = get_pod_info_from_netns(namespace_info.get(&ns_id), &pod_mappings);
        assert_eq!(result, (String::new(), String::new()));
    }

    #[test]
    fn test_get_pod_info_from_iface_with_namespace() {
        use super::super::types::{NamespaceId, NamespaceInfo, ProcessId};
        use crate::kubernetes::kubernetes_metadata_collector::PodInfo;

        let mut namespace_info = HashMap::new();
        let mut pod_mappings = HashMap::new();

        let ip_addr: IpAddr = "192.168.1.10".parse().unwrap();
        let ns_id = NamespaceId::new(42);

        // Create namespace info
        let ns_info = NamespaceInfo {
            pid: ProcessId::new(1234),
            ns_file: Some("/test/ns".to_string()),
            ip_addresses: vec![ip_addr],
        };
        namespace_info.insert(ns_id, ns_info);

        // Create pod info
        let pod_info = PodInfo {
            name: "test-pod".to_string(),
            namespace: "test-namespace".to_string(),
            service_name: "test-service".to_string(),
        };
        let mut pod_set = HashSet::new();
        pod_set.insert(pod_info);
        pod_mappings.insert(ip_addr, pod_set);

        let result =
            get_pod_info_from_iface("veth123", &namespace_info, &pod_mappings, Some(ns_id));
        assert_eq!(
            result,
            ("test-pod".to_string(), "test-namespace".to_string())
        );
    }

    #[test]
    fn test_get_pod_info_from_iface_without_namespace() {
        let namespace_info = HashMap::new();
        let pod_mappings = HashMap::new();

        let result = get_pod_info_from_iface("eth0", &namespace_info, &pod_mappings, None);
        assert_eq!(result, (String::new(), String::new()));
    }

    #[test]
    fn test_host_interface_metric_values_zero_delta() {
        let current = HostInterfaceMetricValues::new(1000, 50000, 800, 40000);
        let previous = HostInterfaceMetricValues::new(1000, 50000, 800, 40000); // Same values

        let delta = current.calculate_delta(&previous);

        assert_eq!(delta.ingress_pkt_count, 0);
        assert_eq!(delta.ingress_bytes_count, 0);
        assert_eq!(delta.egress_pkt_count, 0);
        assert_eq!(delta.egress_bytes_count, 0);
    }

    #[test]
    fn test_should_include_interface_combined_flags() {
        let mut flags = HashMap::new();

        // Test interface with multiple flags including UP
        flags.insert(
            "veth456".to_string(),
            InterfaceFlags::UP | InterfaceFlags::RUNNING | InterfaceFlags::BROADCAST,
        );
        let veth_interface = HostInterface::new("veth456".to_string());
        assert!(should_include_interface(&veth_interface, &flags));

        // Test loopback with UP flag (should still be excluded)
        flags.insert(
            "lo".to_string(),
            InterfaceFlags::LOOPBACK | InterfaceFlags::UP | InterfaceFlags::RUNNING,
        );
        let loopback = HostInterface::new("lo".to_string());
        assert!(!should_include_interface(&loopback, &flags));
    }
}
