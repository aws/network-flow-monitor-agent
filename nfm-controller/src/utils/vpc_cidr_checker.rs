// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use log::{info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::metadata::imds_utils;

pub trait ImdsProvider {
    fn get_metadata(&self, path: &str) -> String;
}

struct RealImdsProvider {
    client: aws_config::imds::Client,
}

impl ImdsProvider for RealImdsProvider {
    fn get_metadata(&self, path: &str) -> String {
        imds_utils::retrieve_imds_metadata(&self.client, path.to_string())
    }
}

/// Utility struct to provide functionality on whether a given IP is within current VPC CIDR
pub struct VpcCidrChecker {
    pub(crate) vpc_cidrs_v4: Vec<(u32, u32)>,
    pub(crate) vpc_cidrs_v6: Vec<(u128, u128)>,
}

impl Default for VpcCidrChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl VpcCidrChecker {
    pub fn new() -> Self {
        let client = aws_config::imds::Client::builder().build();
        let provider = RealImdsProvider { client };
        Self::with_provider(&provider)
    }

    pub fn with_provider<P: ImdsProvider>(provider: &P) -> Self {
        let (vpc_cidrs_v4, vpc_cidrs_v6) = Self::get_vpc_cidrs_with_provider(provider);
        Self {
            vpc_cidrs_v4,
            vpc_cidrs_v6,
        }
    }

    /// Returns true if given IP address is within VPC CIDR range.
    /// In general discrete CIDR ranges are relatively low < 10 so an array lookup is preferred.
    pub fn is_vpc_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from(*ipv4);
                self.vpc_cidrs_v4
                    .iter()
                    .any(|(network, mask)| (ip_u32 & mask) == *network)
            }
            IpAddr::V6(ipv6) => {
                let ip_u128 = u128::from(*ipv6);
                self.vpc_cidrs_v6
                    .iter()
                    .any(|(network, mask)| (ip_u128 & mask) == *network)
            }
        }
    }

    /// Get the VPC CIDRs using IMDS metadata from current host.
    /// We only care about current VPC where the agent runs in,
    /// As the acquired range will be used to filter addresses on SNATs.
    #[allow(clippy::type_complexity)]
    fn get_vpc_cidrs_with_provider<P: ImdsProvider>(
        provider: &P,
    ) -> (Vec<(u32, u32)>, Vec<(u128, u128)>) {
        use std::time::Instant;

        let start = Instant::now();

        let macs_str = provider.get_metadata("/latest/meta-data/network/interfaces/macs/");
        if macs_str.is_empty() {
            warn!("IMDS unavailable, VPC CIDR filtering disabled (non-EC2 environment)");
            return (vec![], vec![]);
        }

        let mac = match macs_str.lines().next() {
            Some(m) => m.trim_end_matches('/'),
            None => {
                warn!("No MAC address found in IMDS");
                return (vec![], vec![]);
            }
        };

        let v4_str = provider.get_metadata(&format!(
            "/latest/meta-data/network/interfaces/macs/{}/vpc-ipv4-cidr-blocks",
            mac
        ));
        let v6_str = provider.get_metadata(&format!(
            "/latest/meta-data/network/interfaces/macs/{}/vpc-ipv6-cidr-blocks",
            mac
        ));

        let mut cidrs_v4 = Vec::new();
        let mut cidrs_v6 = Vec::new();
        let mut cidr_strings = Vec::new();

        if !v4_str.is_empty() {
            for line in v4_str.lines() {
                if let Some((network, mask)) = Self::parse_cidr_v4(line.trim()) {
                    cidr_strings.push(line.trim().to_string());
                    cidrs_v4.push((network, mask));
                }
            }
        }

        if !v6_str.is_empty() {
            for line in v6_str.lines() {
                if let Some((network, mask)) = Self::parse_cidr_v6(line.trim()) {
                    cidr_strings.push(line.trim().to_string());
                    cidrs_v6.push((network, mask));
                }
            }
        }

        let elapsed = start.elapsed();
        info!(duration_ms = elapsed.as_millis() as u64, cidrs:serde = cidr_strings; "Loaded VPC CIDRs for NAT resolution");

        (cidrs_v4, cidrs_v6)
    }

    fn parse_cidr_v4(cidr: &str) -> Option<(u32, u32)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip: Ipv4Addr = parts[0].parse().ok()?;
        let prefix_len: u32 = parts[1].parse().ok()?;
        if prefix_len > 32 {
            return None;
        }

        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let network = u32::from(ip) & mask;
        Some((network, mask))
    }

    fn parse_cidr_v6(cidr: &str) -> Option<(u128, u128)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let ip: Ipv6Addr = parts[0].parse().ok()?;
        let prefix_len: u32 = parts[1].parse().ok()?;
        if prefix_len > 128 {
            return None;
        }

        let mask = if prefix_len == 0 {
            0
        } else {
            !0u128 << (128 - prefix_len)
        };
        let network = u128::from(ip) & mask;
        Some((network, mask))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_cidr_v4() {
        let (network, mask) = VpcCidrChecker::parse_cidr_v4("10.0.0.0/16").unwrap();
        assert_eq!(network, 0x0a000000);
        assert_eq!(mask, 0xffff0000);

        let (network, mask) = VpcCidrChecker::parse_cidr_v4("192.168.1.0/24").unwrap();
        assert_eq!(network, 0xc0a80100);
        assert_eq!(mask, 0xffffff00);
    }

    #[test]
    fn test_parse_cidr_v6() {
        let (network, mask) = VpcCidrChecker::parse_cidr_v6("2001:db8::/32").unwrap();
        assert_eq!(network, 0x20010db8_00000000_00000000_00000000);
        assert_eq!(mask, 0xffffffff_00000000_00000000_00000000);
    }

    #[test]
    fn test_is_vpc_ip_v4() {
        let checker = VpcCidrChecker {
            vpc_cidrs_v4: vec![(0x0a000000, 0xffff0000)], // 10.0.0.0/16
            vpc_cidrs_v6: vec![],
        };

        assert!(checker.is_vpc_ip(&IpAddr::from_str("10.0.1.5").unwrap()));
        assert!(checker.is_vpc_ip(&IpAddr::from_str("10.0.255.255").unwrap()));
        assert!(!checker.is_vpc_ip(&IpAddr::from_str("10.1.0.0").unwrap()));
        assert!(!checker.is_vpc_ip(&IpAddr::from_str("192.168.1.1").unwrap()));
    }

    #[test]
    fn test_is_vpc_ip_v6() {
        let checker = VpcCidrChecker {
            vpc_cidrs_v4: vec![],
            vpc_cidrs_v6: vec![(
                0x20010db8_00000000_00000000_00000000,
                0xffffffff_00000000_00000000_00000000,
            )],
        };

        assert!(checker.is_vpc_ip(&IpAddr::from_str("2001:db8::1").unwrap()));
        assert!(
            checker.is_vpc_ip(&IpAddr::from_str("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff").unwrap())
        );
        assert!(!checker.is_vpc_ip(&IpAddr::from_str("2001:db9::1").unwrap()));
    }

    #[test]
    fn test_default_no_panic() {
        let _checker = VpcCidrChecker::default();
    }

    struct MockImdsProvider {
        metadata: std::collections::HashMap<String, String>,
    }

    impl ImdsProvider for MockImdsProvider {
        fn get_metadata(&self, path: &str) -> String {
            self.metadata.get(path).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn test_with_mock_provider_v4_only() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/".to_string(),
            "00:11:22:33:44:55/\n".to_string(),
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv4-cidr-blocks"
                .to_string(),
            "10.0.0.0/16\n172.16.0.0/12\n".to_string(),
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv6-cidr-blocks"
                .to_string(),
            "".to_string(),
        );

        let provider = MockImdsProvider { metadata: metadata };
        let checker = VpcCidrChecker::with_provider(&provider);

        assert_eq!(checker.vpc_cidrs_v4.len(), 2);
        assert_eq!(checker.vpc_cidrs_v6.len(), 0);
        assert!(checker.is_vpc_ip(&IpAddr::from_str("10.0.1.1").unwrap()));
        assert!(checker.is_vpc_ip(&IpAddr::from_str("172.16.5.5").unwrap()));
        assert!(!checker.is_vpc_ip(&IpAddr::from_str("192.168.1.1").unwrap()));
    }

    #[test]
    fn test_with_mock_provider_v6_only() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/".to_string(),
            "00:11:22:33:44:55/\n".to_string(),
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv4-cidr-blocks"
                .to_string(),
            "".to_string(),
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv6-cidr-blocks"
                .to_string(),
            "2001:db8::/32\n".to_string(),
        );

        let provider = MockImdsProvider { metadata };
        let checker = VpcCidrChecker::with_provider(&provider);

        assert_eq!(checker.vpc_cidrs_v4.len(), 0);
        assert_eq!(checker.vpc_cidrs_v6.len(), 1);
        assert!(checker.is_vpc_ip(&IpAddr::from_str("2001:db8::1").unwrap()));
        assert!(!checker.is_vpc_ip(&IpAddr::from_str("2001:db9::1").unwrap()));
    }

    #[test]
    fn test_with_mock_provider_no_macs() {
        let metadata = std::collections::HashMap::new();
        let provider = MockImdsProvider { metadata };
        let checker = VpcCidrChecker::with_provider(&provider);

        assert_eq!(checker.vpc_cidrs_v4.len(), 0);
        assert_eq!(checker.vpc_cidrs_v6.len(), 0);
    }

    #[test]
    fn test_with_mock_provider_empty_mac_list() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/".to_string(),
            "".to_string(),
        );
        let provider = MockImdsProvider { metadata };
        let checker = VpcCidrChecker::with_provider(&provider);

        assert_eq!(checker.vpc_cidrs_v4.len(), 0);
        assert_eq!(checker.vpc_cidrs_v6.len(), 0);
    }

    #[test]
    fn test_with_mock_provider_broken_ipv4() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/".to_string(),
            "00:11:22:33:44:55/".to_string(),
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv4-cidr-blocks"
                .to_string(),
            "10.0.0.0/33".to_string(), // 33 prefix
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv4-cidr-blocks"
                .to_string(),
            "10.0.0.0/33/111/222/333/44".to_string(),
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv4-cidr-blocks"
                .to_string(),
            "10.0.0.0/0".to_string(), // this one is ok
        );
        let provider = MockImdsProvider { metadata };
        let checker = VpcCidrChecker::with_provider(&provider);

        assert_eq!(checker.vpc_cidrs_v4.len(), 1);
        assert_eq!(checker.vpc_cidrs_v6.len(), 0);
    }

    #[test]
    fn test_with_mock_provider_broken_ipv6() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/".to_string(),
            "00:11:22:33:44:55/".to_string(),
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv6-cidr-blocks"
                .to_string(),
            "2001:db8::/129".to_string(), // 129 prefix
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv6-cidr-blocks"
                .to_string(),
            "2001:db8::/129/123/123".to_string(), // too many slashes
        );
        metadata.insert(
            "/latest/meta-data/network/interfaces/macs/00:11:22:33:44:55/vpc-ipv6-cidr-blocks"
                .to_string(),
            "2001:db8::/0".to_string(), // this one is ok
        );
        let provider = MockImdsProvider { metadata };
        let checker = VpcCidrChecker::with_provider(&provider);

        assert_eq!(checker.vpc_cidrs_v4.len(), 0);
        assert_eq!(checker.vpc_cidrs_v6.len(), 1);
    }
}
