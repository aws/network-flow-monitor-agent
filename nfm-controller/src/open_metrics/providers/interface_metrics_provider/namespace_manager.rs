// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace management for interface metrics provider.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;

use anyhow::Result;
use log::{debug, warn};
use nfm_common::IpAddrLinkLocal;
use regex::Regex;

use crate::utils::CommandRunner;

use super::types::{
    get_ipv4_regex, get_ipv6_regex, get_link_netnsid_regex, InterfaceMetricsError, NamespaceId,
    NamespaceInfo, ProcessId,
};

/// Manages network namespace operations
pub struct NetworkNamespaceManager {
    command_runner: Box<dyn CommandRunner>,
    link_regex: Regex,
}

impl NetworkNamespaceManager {
    pub fn new(command_runner: Box<dyn CommandRunner>) -> Self {
        Self {
            command_runner,
            link_regex: get_link_netnsid_regex().clone(),
        }
    }

    /// Get fresh namespace information from system
    pub fn get_namespace_info(&self) -> Result<HashMap<NamespaceId, NamespaceInfo>> {
        let output = self
            .command_runner
            .run("lsns", &["-t", "net", "--noheadings"])
            .map_err(|_| InterfaceMetricsError::CommandExecution {
                command: "lsns -t net --noheadings".to_string(),
            })?;

        if !output.status.success() {
            warn!(
                "Failed to get network namespaces: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(HashMap::new());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut namespace_info = HashMap::new();

        for line in stdout.lines() {
            if let Ok(Some(info)) = self.parse_namespace_line(line) {
                namespace_info.insert(info.0, info.1);
            }
        }

        Ok(namespace_info)
    }

    /// Parse a single line from lsns output
    fn parse_namespace_line(&self, line: &str) -> Result<Option<(NamespaceId, NamespaceInfo)>> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            return Ok(None);
        }

        // Skip unassigned namespaces
        if fields[5] == "unassigned" {
            return Ok(None);
        }

        let pid =
            fields[3]
                .parse::<u32>()
                .map_err(|_| InterfaceMetricsError::NetworkDataParsing {
                    details: format!("Invalid PID: {}", fields[3]),
                })?;

        let netns_id =
            fields[5]
                .parse::<u32>()
                .map_err(|_| InterfaceMetricsError::NetworkDataParsing {
                    details: format!("Invalid namespace ID: {}", fields[5]),
                })?;

        let ns_file = if fields.len() >= 7 && !fields[6].is_empty() {
            match fs::exists(fields[6]) {
                Ok(true) => Some(fields[6].to_string()),
                _ => None,
            }
        } else {
            None
        };

        let ip_addresses = self.get_ip_addresses_for_namespace(ProcessId::new(pid), &ns_file)?;

        let namespace_info = NamespaceInfo {
            pid: ProcessId::new(pid),
            ns_file,
            ip_addresses,
        };

        Ok(Some((NamespaceId::new(netns_id), namespace_info)))
    }

    /// Get IP addresses for a namespace using file path or PID fallback
    fn get_ip_addresses_for_namespace(
        &self,
        pid: ProcessId,
        ns_file: &Option<String>,
    ) -> Result<Vec<IpAddr>> {
        // Try namespace file first if available
        if let Some(ns_path) = ns_file {
            match self.get_ip_addresses_from_ns_file(ns_path) {
                Ok(addresses) => {
                    debug!("Retrieved IP addresses using namespace file: {}", ns_path);
                    return Ok(addresses);
                }
                Err(e) => {
                    debug!("Failed to get IP addresses from namespace file {}: {}, falling back to PID", 
                           ns_path, e);
                }
            }
        }

        // Fallback to PID-based approach
        self.get_ip_addresses_for_pid(pid)
    }

    /// Execute nsenter command and parse IP addresses
    fn execute_nsenter_and_parse_ips(&self, args: &[&str], context: &str) -> Result<Vec<IpAddr>> {
        let output = self.command_runner.run("nsenter", args).map_err(|_| {
            InterfaceMetricsError::CommandExecution {
                command: format!("nsenter {}", args.join(" ")),
            }
        })?;

        if !output.status.success() {
            return Err(InterfaceMetricsError::NamespaceOperation {
                details: format!(
                    "Failed to get IP addresses for {}: {}",
                    context,
                    String::from_utf8_lossy(&output.stderr)
                ),
            }
            .into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_ip_addresses(&stdout))
    }

    /// Get IP addresses from namespace file
    fn get_ip_addresses_from_ns_file(&self, ns_path: &str) -> Result<Vec<IpAddr>> {
        let args = &["--net", ns_path, "ip", "a"];
        let context = format!("namespace file {}", ns_path);
        self.execute_nsenter_and_parse_ips(args, &context)
    }

    /// Get IP addresses using PID (fallback method)
    fn get_ip_addresses_for_pid(&self, pid: ProcessId) -> Result<Vec<IpAddr>> {
        let pid_str = pid.as_u32().to_string();
        let args = &["-t", &pid_str, "-n", "ip", "a"];
        let context = format!("PID {}", pid.as_u32());

        self.execute_nsenter_and_parse_ips(args, &context)
            .or_else(|_| Ok(Vec::new()))
    }

    /// Parse all interface links in a single command execution for better performance.
    /// Returns a HashMap mapping interface names to their namespace IDs.
    pub fn parse_all_interface_links(&self) -> Result<HashMap<String, NamespaceId>> {
        let mut interface_ns_map = HashMap::new();

        let output = self
            .command_runner
            .run("ip", &["link", "show"])
            .map_err(|_| InterfaceMetricsError::CommandExecution {
                command: "ip link show".to_string(),
            })?;

        if !output.status.success() {
            warn!(
                "Failed to get all interface link information: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return Ok(interface_ns_map);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_iface: Option<String> = None;

        for line in stdout.lines() {
            // Check if this is an interface definition line (starts with a number)
            if let Some(first_token) = line.split_whitespace().next() {
                if first_token.ends_with(':')
                    && first_token[..first_token.len() - 1].parse::<u32>().is_ok()
                {
                    // This is an interface definition line like "15: veth123@if14: <FLAGS>"
                    if let Some(iface_match) = line.split_whitespace().nth(1) {
                        // Extract interface name: handle both "eth0:" and "veth123@if14:" formats
                        let iface_name = if iface_match.contains('@') {
                            // For cases like "veth123@if14:", extract "veth123"
                            iface_match.split('@').next().unwrap_or("")
                        } else {
                            // For cases like "eth0:", extract "eth0"
                            iface_match.trim_end_matches(':')
                        };

                        if !iface_name.is_empty() {
                            current_iface = Some(iface_name.to_string());
                        }
                    }
                }
            }

            // Look for namespace ID in any line (interface header or details)
            if let Some(captures) = self.link_regex.captures(line) {
                if let (Some(iface), Some(netnsid_match)) = (&current_iface, captures.get(1)) {
                    // Only insert if we haven't already processed this interface
                    if !interface_ns_map.contains_key(iface) {
                        match netnsid_match.as_str().parse::<u32>() {
                            Ok(netnsid) => {
                                interface_ns_map.insert(iface.clone(), NamespaceId::new(netnsid));
                            }
                            Err(e) => {
                                debug!(
                                    iface = iface, error = e.to_string();
                                    "Failed to parse namespace ID in bulk parsing"
                                );
                            }
                        }
                    }
                }
            }
        }

        debug!(
            interfaces_parsed = interface_ns_map.len();
            "Parsed interface namespace mappings"
        );

        Ok(interface_ns_map)
    }

    /// Get namespace ID for an interface (optimized version using pre-parsed data)
    pub fn get_namespace_id_for_interface_from_map(
        &self,
        interface_name: &str,
        interface_map: &HashMap<String, NamespaceId>,
    ) -> Option<NamespaceId> {
        interface_map.get(interface_name).copied()
    }

    /// Get namespace ID for an interface (individual command method)
    pub fn get_namespace_id_for_interface(
        &self,
        interface_name: &str,
    ) -> Result<Option<NamespaceId>> {
        let output = self
            .command_runner
            .run("ip", &["link", "show", interface_name])
            .map_err(|_| InterfaceMetricsError::CommandExecution {
                command: format!("ip link show {}", interface_name),
            })?;

        if !output.status.success() {
            return Err(InterfaceMetricsError::InterfaceNotFound {
                interface: interface_name.to_string(),
            }
            .into());
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        if let Some(captures) = self.link_regex.captures(&stdout) {
            if let Some(netnsid_match) = captures.get(1) {
                let netns_id = netnsid_match.as_str().parse::<u32>().map_err(|e| {
                    InterfaceMetricsError::NetworkDataParsing {
                        details: format!(
                            "Failed to parse namespace ID for interface {}: {}",
                            interface_name, e
                        ),
                    }
                })?;
                return Ok(Some(NamespaceId::new(netns_id)));
            }
        }

        Ok(None)
    }
}

/// Parse IP addresses from 'ip a' command output
pub fn parse_ip_addresses(ip_output: &str) -> Vec<IpAddr> {
    let mut ip_addresses = Vec::new();
    let ipv4_regex = get_ipv4_regex();
    let ipv6_regex = get_ipv6_regex();

    for line in ip_output.lines() {
        if let Some(ip_addr) = extract_ip_from_line(line, ipv4_regex) {
            ip_addresses.push(ip_addr);
        } else if let Some(ip_addr) = extract_ip_from_line(line, ipv6_regex) {
            ip_addresses.push(ip_addr);
        }
    }

    ip_addresses
}

/// Extract and validate IP address from a line using regex
fn extract_ip_from_line(line: &str, regex: &Regex) -> Option<IpAddr> {
    regex
        .captures(line)?
        .get(1)?
        .as_str()
        .parse::<IpAddr>()
        .ok()
        .filter(|ip| !ip.is_loopback() && !ip.is_link_local())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::FakeCommandRunner;
    use std::fs::File;
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    fn create_test_manager() -> NetworkNamespaceManager {
        let fake_runner = FakeCommandRunner::new();
        NetworkNamespaceManager::new(Box::new(fake_runner))
    }

    struct TemporaryFile {
        path: String,
    }

    impl TemporaryFile {
        fn new(file_name: &str) -> Self {
            let path = format!("/tmp/{}", file_name);
            {
                let mut file = File::create(&path).unwrap();
                file.write(b"NFM test file. Safe to remove.").unwrap();
            }
            TemporaryFile { path }
        }
    }

    impl Drop for TemporaryFile {
        fn drop(&mut self) {
            std::fs::remove_file(&self.path).unwrap();
        }
    }

    #[test]
    fn test_parse_namespace_line_valid() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1628", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: vec![],
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let line = "4026531992 net      54  1628 user           88 /host/run/netns/test sleep 180";

        let result = manager.parse_namespace_line(line);
        assert!(result.is_ok());

        if let Ok(Some((ns_id, ns_info))) = result {
            assert_eq!(ns_id.as_u32(), 88);
            assert_eq!(ns_info.pid.as_u32(), 1628);
        }
    }

    #[test]
    fn test_parse_namespace_line_unassigned() {
        let manager = create_test_manager();
        let line = "4026531840 net     135       1 root   unassigned                                                          /usr/lib/systemd/systemd";

        let result = manager.parse_namespace_line(line);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_parse_namespace_line_malformed() {
        let manager = create_test_manager();
        let line = "4026531992 net";

        let result = manager.parse_namespace_line(line);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn test_parse_ip_addresses() {
        let ip_output = "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0
    inet6 2001:db8::1/64 scope global";

        let addresses = parse_ip_addresses(ip_output);

        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&"192.168.1.10".parse().unwrap()));
        assert!(addresses.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_extract_ip_from_line_ipv4() {
        let ipv4_regex = get_ipv4_regex();

        // Test valid IPv4 address
        let line = "    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0";
        let result = extract_ip_from_line(line, ipv4_regex);
        assert_eq!(result, Some("192.168.1.10".parse().unwrap()));

        // Test loopback address (should be filtered out)
        let line = "    inet 127.0.0.1/8 scope host lo";
        let result = extract_ip_from_line(line, ipv4_regex);
        assert_eq!(result, None);
    }

    #[test]
    fn test_extract_ip_from_line_ipv6() {
        let ipv6_regex = get_ipv6_regex();

        // Test valid IPv6 address
        let line = "    inet6 2001:db8::1/64 scope global";
        let result = extract_ip_from_line(line, ipv6_regex);
        assert_eq!(result, Some("2001:db8::1".parse().unwrap()));

        // Test link-local address (should be filtered out)
        let line = "    inet6 fe80::42:acff:fe11:2/64 scope link";
        let result = extract_ip_from_line(line, ipv6_regex);
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_namespace_info_success() {
        let file_1 = TemporaryFile::new("file_get_namespace_info_success_1");
        let file_2 = TemporaryFile::new("file_get_namespace_info_success_2");
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!("4026531992 net      54  1628 user           88 {} sleep 180\n4026531993 net      55  1629 user           89 {} sleep 180", file_1.path, file_2.path).as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        // Mock nsenter calls for IP address retrieval
        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file_1.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".to_vec(),
                stderr: vec![],
            }),
        );

        fake_runner.add_expectation(
            "nsenter",
            &["--net", &file_2.path, "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.11/24 brd 192.168.1.255 scope global eth0".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_namespace_info();

        assert!(result.is_ok());
        let namespace_info = result.unwrap();
        assert_eq!(namespace_info.len(), 2);

        let ns_88 = namespace_info.get(&NamespaceId::new(88)).unwrap();
        assert_eq!(ns_88.pid.as_u32(), 1628);
        assert_eq!(ns_88.ns_file, Some(file_1.path.clone()));
        assert_eq!(ns_88.ip_addresses.len(), 1);
        assert!(ns_88
            .ip_addresses
            .contains(&"192.168.1.10".parse().unwrap()));
    }

    #[test]
    fn test_get_namespace_info_command_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Err(Error::new(ErrorKind::NotFound, "lsns not found")),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_namespace_info();

        assert!(result.is_err());
    }

    #[test]
    fn test_get_namespace_info_command_non_zero_exit() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "lsns",
            &["-t", "net", "--noheadings"],
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8), // Exit code 1
                stdout: vec![],
                stderr: b"Permission denied".to_vec(),
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_namespace_info();

        assert!(result.is_ok());
        let namespace_info = result.unwrap();
        assert!(namespace_info.is_empty());
    }

    #[test]
    fn test_get_ip_addresses_from_ns_file_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/test/ns/path", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0\n    inet6 2001:db8::1/64 scope global".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_ip_addresses_from_ns_file("/test/ns/path");

        assert!(result.is_ok());
        let addresses = result.unwrap();
        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&"192.168.1.10".parse().unwrap()));
        assert!(addresses.contains(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_get_ip_addresses_from_ns_file_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/test/ns/path", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8), // Exit code 1
                stdout: vec![],
                stderr: b"Network namespace not found".to_vec(),
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_ip_addresses_from_ns_file("/test/ns/path");

        assert!(result.is_err());
    }

    #[test]
    fn test_get_ip_addresses_for_pid_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_ip_addresses_for_pid(ProcessId::new(1234));

        assert!(result.is_ok());
        let addresses = result.unwrap();
        assert_eq!(addresses.len(), 1);
        assert!(addresses.contains(&"192.168.1.10".parse().unwrap()));
    }

    #[test]
    fn test_get_ip_addresses_for_pid_failure_returns_empty() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8), // Exit code 1
                stdout: vec![],
                stderr: b"Process not found".to_vec(),
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_ip_addresses_for_pid(ProcessId::new(1234));

        assert!(result.is_ok());
        let addresses = result.unwrap();
        assert!(addresses.is_empty());
    }

    #[test]
    fn test_get_namespace_id_for_interface_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "eth0"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0@if3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default link-netnsid 42".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_namespace_id_for_interface("eth0");

        assert!(result.is_ok());
        let ns_id = result.unwrap();
        assert_eq!(ns_id, Some(NamespaceId::new(42)));
    }

    #[test]
    fn test_get_namespace_id_for_interface_not_found() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "nonexistent"],
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8), // Exit code 1
                stdout: vec![],
                stderr: b"Device \"nonexistent\" does not exist.".to_vec(),
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_namespace_id_for_interface("nonexistent");

        assert!(result.is_err());
    }

    #[test]
    fn test_get_namespace_id_for_interface_no_netnsid() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show", "lo"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.get_namespace_id_for_interface("lo");

        assert!(result.is_ok());
        let ns_id = result.unwrap();
        assert_eq!(ns_id, None);
    }

    #[test]
    fn test_parse_namespace_line_with_missing_ns_file() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1628", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: vec![],
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let line = "4026531992 net      54  1628 user           88";

        let result = manager.parse_namespace_line(line);
        assert!(result.is_ok());

        if let Ok(Some((ns_id, ns_info))) = result {
            assert_eq!(ns_id.as_u32(), 88);
            assert_eq!(ns_info.pid.as_u32(), 1628);
            assert_eq!(ns_info.ns_file, None);
        }
    }

    #[test]
    fn test_parse_namespace_line_invalid_pid() {
        let manager = create_test_manager();
        let line = "4026531992 net      54  invalid user           88 /host/run/netns/test";

        let result = manager.parse_namespace_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_namespace_line_invalid_netns_id() {
        let manager = create_test_manager();
        let line = "4026531992 net      54  1628 user           invalid /host/run/netns/test";

        let result = manager.parse_namespace_line(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_ip_addresses_for_namespace_fallback_to_pid() {
        let mut fake_runner = FakeCommandRunner::new();

        // First call to nsenter with namespace file fails
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/nonexistent/path", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8), // Exit code 1
                stdout: vec![],
                stderr: b"Namespace file not found".to_vec(),
            }),
        );

        // Second call with PID succeeds
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "ip", "a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 192.168.1.10/24 brd 192.168.1.255 scope global eth0".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let ns_file = Some("/nonexistent/path".to_string());
        let result = manager.get_ip_addresses_for_namespace(ProcessId::new(1234), &ns_file);

        assert!(result.is_ok());
        let addresses = result.unwrap();
        assert_eq!(addresses.len(), 1);
        assert!(addresses.contains(&"192.168.1.10".parse().unwrap()));
    }

    #[test]
    fn test_parse_all_interface_links_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\n    link/ether 08:00:27:12:34:56 brd ff:ff:ff:ff:ff:ff\n15: veth123@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default link-netnsid 42\n    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 42\n17: vethab45@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default link-netnsid 7\n    link/ether 02:42:ac:11:00:05 brd ff:ff:ff:ff:ff:ff link-netnsid 7\n".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.parse_all_interface_links();

        assert!(result.is_ok());
        let interface_map = result.unwrap();

        // Should parse interfaces with namespace IDs and ignore those without
        assert_eq!(interface_map.len(), 2);
        assert_eq!(interface_map.get("veth123"), Some(&NamespaceId::new(42)));
        assert_eq!(interface_map.get("vethab45"), Some(&NamespaceId::new(7)));
        assert_eq!(interface_map.get("lo"), None); // No namespace ID
        assert_eq!(interface_map.get("eth0"), None); // No namespace ID
    }

    #[test]
    fn test_parse_all_interface_links_empty_output() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: vec![],
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.parse_all_interface_links();

        assert!(result.is_ok());
        let interface_map = result.unwrap();
        assert!(interface_map.is_empty());
    }

    #[test]
    fn test_parse_all_interface_links_command_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show"],
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8), // Exit code 1
                stdout: vec![],
                stderr: b"ip: command failed".to_vec(),
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.parse_all_interface_links();

        assert!(result.is_ok());
        let interface_map = result.unwrap();
        assert!(interface_map.is_empty());
    }

    #[test]
    fn test_parse_all_interface_links_command_error() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show"],
            Err(Error::new(ErrorKind::NotFound, "ip command not found")),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.parse_all_interface_links();

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_all_interface_links_invalid_namespace_id() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"15: veth123@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default link-netnsid invalid\n    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid invalid\n17: vethab45@if16: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default link-netnsid 7\n    link/ether 02:42:ac:11:00:05 brd ff:ff:ff:ff:ff:ff link-netnsid 7\n".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.parse_all_interface_links();

        assert!(result.is_ok());
        let interface_map = result.unwrap();

        // Should skip the interface with invalid namespace ID and parse the valid one
        assert_eq!(interface_map.len(), 1);
        assert_eq!(interface_map.get("vethab45"), Some(&NamespaceId::new(7)));
        assert_eq!(interface_map.get("veth123"), None); // Invalid namespace ID should be skipped
    }

    #[test]
    fn test_parse_all_interface_links_mixed_interfaces() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ip",
            &["link", "show"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000\n    link/ether 08:00:27:12:34:56 brd ff:ff:ff:ff:ff:ff\n15: veth123@if14: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP mode DEFAULT group default link-netnsid 0\n    link/ether 02:42:ac:11:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0\n".to_vec(),
                stderr: vec![],
            }),
        );

        let manager = NetworkNamespaceManager::new(Box::new(fake_runner));
        let result = manager.parse_all_interface_links();

        assert!(result.is_ok());
        let interface_map = result.unwrap();

        // Should only parse interfaces that have namespace IDs
        assert_eq!(interface_map.len(), 1);
        assert_eq!(interface_map.get("veth123"), Some(&NamespaceId::new(0)));
        assert_eq!(interface_map.get("lo"), None);
        assert_eq!(interface_map.get("eth0"), None);
    }

    #[test]
    fn test_get_namespace_id_for_interface_from_map() {
        let manager = create_test_manager();

        let mut interface_map = HashMap::new();
        interface_map.insert("veth123".to_string(), NamespaceId::new(42));
        interface_map.insert("veth456".to_string(), NamespaceId::new(7));

        // Test existing interface
        let result = manager.get_namespace_id_for_interface_from_map("veth123", &interface_map);
        assert_eq!(result, Some(NamespaceId::new(42)));

        // Test non-existing interface
        let result = manager.get_namespace_id_for_interface_from_map("eth0", &interface_map);
        assert_eq!(result, None);
    }
}
