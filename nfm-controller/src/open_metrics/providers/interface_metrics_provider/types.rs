// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Core data types and helper functions for interface metrics provider.

use std::fmt;
use std::net::IpAddr;
use std::sync::OnceLock;

use regex::Regex;

// Static regex patterns for performance optimization
static LINK_NETNSID_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV4_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV6_REGEX: OnceLock<Regex> = OnceLock::new();

/// Initialize static regex patterns with optimized expressions
pub fn get_link_netnsid_regex() -> &'static Regex {
    LINK_NETNSID_REGEX.get_or_init(|| {
        Regex::new(r"link-netnsid\s+(\d+)").expect("Failed to compile link-netnsid regex")
    })
}

pub fn get_ipv4_regex() -> &'static Regex {
    IPV4_REGEX.get_or_init(|| Regex::new(r"inet\s+(\S+)/").expect("Failed to compile IPv4 regex"))
}

pub fn get_ipv6_regex() -> &'static Regex {
    IPV6_REGEX.get_or_init(|| Regex::new(r"inet6\s+(\S+)/").expect("Failed to compile IPv6 regex"))
}

/// Custom error types for better error handling
#[derive(Debug)]
pub enum InterfaceMetricsError {
    CommandExecution { command: String },
    NetworkDataParsing { details: String },
    NamespaceOperation { details: String },
}

impl fmt::Display for InterfaceMetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InterfaceMetricsError::CommandExecution { command } => {
                write!(f, "Failed to execute command: {}", command)
            }
            InterfaceMetricsError::NetworkDataParsing { details } => {
                write!(f, "Failed to parse network data: {}", details)
            }
            InterfaceMetricsError::NamespaceOperation { details } => {
                write!(f, "Namespace operation failed: {}", details)
            }
        }
    }
}

impl std::error::Error for InterfaceMetricsError {}

/// Represents a process ID in the system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId(u32);

impl ProcessId {
    pub fn new(pid: u32) -> Self {
        Self(pid)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Represents a network namespace ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamespaceId(u32);

impl NamespaceId {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

/// Network namespace information with process and IP details
#[derive(Debug, Clone, PartialEq)]
pub struct NamespaceInfo {
    pub pid: ProcessId,
    pub ns_file: Option<String>,
    pub ip_addresses: Vec<IpAddr>,
}

/// Host network interface representation
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct HostInterface {
    pub name: String,
    pub is_virtual: bool,
}

impl HostInterface {
    /// Create a new HostInterface with the specified virtual status
    pub fn new(name: String, is_virtual: bool) -> Self {
        Self { name, is_virtual }
    }

    pub fn is_virtual(&self) -> bool {
        self.is_virtual
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_newtype_wrappers() {
        let pid = ProcessId::new(1234);
        assert_eq!(pid.0, 1234);

        let ns_id = NamespaceId::new(5678);
        assert_eq!(ns_id.0, 5678);
    }

    #[test]
    fn test_host_interface_virtual_detection() {
        let interface = HostInterface::new("veth123".to_string(), true);
        assert_eq!(interface.name, "veth123");
        assert_eq!(interface.is_virtual, true);
    }

    #[test]
    fn test_interface_metrics_error_display() {
        let error = InterfaceMetricsError::CommandExecution {
            command: "test command".to_string(),
        };
        assert!(error.to_string().contains("test command"));
    }
}
