use std::{collections::HashMap, net::IpAddr};

use log::{debug, error};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct PodInfo {
    pub pod: String,
    pub namespace: String,
}

type PodIP = IpAddr;

#[derive(Clone)]
pub struct IPPodMapping {
    map: HashMap<PodIP, PodInfo>,
}

// JSON response structures for the ENI endpoint
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ENIResponse {
    #[serde(rename = "TotalIPs")]
    total_ips: u32,
    #[serde(rename = "AssignedIPs")]
    assigned_ips: u32,
    #[serde(rename = "ENIs")]
    enis: HashMap<String, ENIInfo>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ENIInfo {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "IsPrimary")]
    is_primary: bool,
    #[serde(rename = "IsTrunk")]
    is_trunk: bool,
    #[serde(rename = "IsEFA")]
    is_efa: bool,
    #[serde(rename = "DeviceNumber")]
    device_number: u32,
    #[serde(rename = "AvailableIPv4Cidrs")]
    available_ipv4_cidrs: HashMap<String, CidrInfo>,
    #[serde(rename = "IPv6Cidrs")]
    ipv6_cidrs: HashMap<String, CidrInfo>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CidrInfo {
    #[serde(rename = "Cidr")]
    cidr: CidrDetails,
    #[serde(rename = "IPAddresses")]
    ip_addresses: HashMap<String, IPAddressInfo>,
    #[serde(rename = "IsPrefix")]
    is_prefix: bool,
    #[serde(rename = "AddressFamily")]
    address_family: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CidrDetails {
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Mask")]
    mask: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IPAddressInfo {
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "IPAMKey")]
    ipam_key: IPAMKey,
    #[serde(rename = "IPAMMetadata")]
    ipam_metadata: IPAMMetadata,
    #[serde(rename = "AssignedTime")]
    assigned_time: String,
    #[serde(rename = "UnassignedTime")]
    unassigned_time: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct IPAMKey {
    #[serde(rename = "networkName")]
    network_name: String,
    #[serde(rename = "containerID")]
    container_id: String,
    #[serde(rename = "ifName")]
    if_name: String,
}

#[derive(Debug, Deserialize)]
struct IPAMMetadata {
    #[serde(rename = "k8sPodNamespace")]
    k8s_pod_namespace: String,
    #[serde(rename = "k8sPodName")]
    k8s_pod_name: String,
}

impl IPPodMapping {
    pub fn new() -> Self {
        let mut out = Self {
            map: HashMap::new(),
        };
        out.update();
        out
    }

    fn update(&mut self) {
        match self.fetch_eni_data() {
            Ok(eni_response) => {
                self.process_eni_response(eni_response);
            }
            Err(e) => {
                error!("Failed to update IP to POD mapping: {}", e);
            }
        }
    }

    pub fn get(&self, ip: PodIP) -> Option<&PodInfo> {
        self.map.get(&ip)
    }

    fn fetch_eni_data(&self) -> Result<ENIResponse, Box<dyn std::error::Error>> {
        debug!("Fetching ENI data from http://localhost:61679/v1/enis");

        // Should we make this configurable?
        let response = reqwest::blocking::get("http://localhost:61679/v1/enis")?;

        if !response.status().is_success() {
            return Err(format!("HTTP request failed with status: {}", response.status()).into());
        }

        let response_text = response.text()?;
        let eni_response: ENIResponse = serde_json::from_str(&response_text)?;
        debug!(
            "Successfully fetched ENI data: {} total IPs, {} assigned IPs",
            eni_response.total_ips, eni_response.assigned_ips
        );

        Ok(eni_response)
    }

    fn process_eni_response(&mut self, eni_response: ENIResponse) {
        self.map.clear();

        let mut total_processed = 0;

        for (eni_id, eni_info) in eni_response.enis {
            debug!(
                "Processing ENI: {} (Primary: {}, Device: {})",
                eni_id, eni_info.is_primary, eni_info.device_number
            );

            // Process IPv4 CIDRs
            for (_cidr, cidr_info) in eni_info.available_ipv4_cidrs {
                for (ip_address, ip_info) in cidr_info.ip_addresses {
                    // Only process assigned IPs (those with pod metadata)
                    if !ip_info.ipam_metadata.k8s_pod_name.is_empty()
                        && !ip_info.ipam_metadata.k8s_pod_namespace.is_empty()
                    {
                        let pod_info = PodInfo {
                            pod: ip_info.ipam_metadata.k8s_pod_name.clone(),
                            namespace: ip_info.ipam_metadata.k8s_pod_namespace.clone(),
                        };

                        debug!(
                            "Mapping IP {} to pod {}/{}",
                            ip_address, pod_info.namespace, pod_info.pod
                        );

                        if let Ok(parsed_ip) = ip_address.parse::<IpAddr>() {
                            self.map.insert(parsed_ip, pod_info);
                        }
                        total_processed += 1;
                    }
                }
            }

            // Process IPv6 CIDRs if needed
            for (_cidr, cidr_info) in eni_info.ipv6_cidrs {
                for (ip_address, ip_info) in cidr_info.ip_addresses {
                    if !ip_info.ipam_metadata.k8s_pod_name.is_empty()
                        && !ip_info.ipam_metadata.k8s_pod_namespace.is_empty()
                    {
                        let pod_info = PodInfo {
                            pod: ip_info.ipam_metadata.k8s_pod_name.clone(),
                            namespace: ip_info.ipam_metadata.k8s_pod_namespace.clone(),
                        };

                        debug!(
                            "Mapping IPv6 {} to pod {}/{}",
                            ip_address, pod_info.namespace, pod_info.pod
                        );

                        if let Ok(parsed_ip) = ip_address.parse::<IpAddr>() {
                            self.map.insert(parsed_ip, pod_info);
                        }
                        total_processed += 1;
                    }
                }
            }
        }

        debug!(
            "Successfully updated IP to POD mapping with {} entries",
            total_processed
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_deserialize_eni_response() {
        let json_data = r#"{
            "TotalIPs": 15,
            "AssignedIPs": 12,
            "ENIs": {
                "eni-028dec7cf061c4703": {
                    "ID": "eni-028dec7cf061c4703",
                    "IsPrimary": false,
                    "IsTrunk": false,
                    "IsEFA": false,
                    "DeviceNumber": 1,
                    "AvailableIPv4Cidrs": {
                        "172.31.16.82/32": {
                            "Cidr": {
                                "IP": "172.31.16.82",
                                "Mask": "/////w=="
                            },
                            "IPAddresses": {
                                "172.31.16.82": {
                                    "Address": "172.31.16.82",
                                    "IPAMKey": {
                                        "networkName": "aws-cni",
                                        "containerID": "d9a818271fa95a66dba0378aecb0403328433407424cdb9145229ac7b25fb821",
                                        "ifName": "eth0"
                                    },
                                    "IPAMMetadata": {
                                        "k8sPodNamespace": "monitoring",
                                        "k8sPodName": "prometheus-prometheus-kube-prometheus-prometheus-0"
                                    },
                                    "AssignedTime": "2025-09-25T10:35:38.730905251Z",
                                    "UnassignedTime": "0001-01-01T00:00:00Z"
                                }
                            },
                            "IsPrefix": false,
                            "AddressFamily": ""
                        }
                    },
                    "IPv6Cidrs": {}
                }
            }
        }"#;

        let eni_response: ENIResponse = serde_json::from_str(json_data).unwrap();

        assert_eq!(eni_response.total_ips, 15);
        assert_eq!(eni_response.assigned_ips, 12);
        assert_eq!(eni_response.enis.len(), 1);

        let eni = eni_response.enis.get("eni-028dec7cf061c4703").unwrap();
        assert_eq!(eni.id, "eni-028dec7cf061c4703");
        assert!(!eni.is_primary);
        assert_eq!(eni.device_number, 1);

        let cidr_info = eni.available_ipv4_cidrs.get("172.31.16.82/32").unwrap();
        let ip_info = cidr_info.ip_addresses.get("172.31.16.82").unwrap();

        assert_eq!(ip_info.address, "172.31.16.82");
        assert_eq!(ip_info.ipam_metadata.k8s_pod_namespace, "monitoring");
        assert_eq!(
            ip_info.ipam_metadata.k8s_pod_name,
            "prometheus-prometheus-kube-prometheus-prometheus-0"
        );
    }

    #[test]
    fn test_pod_info_clone() {
        let pod_info = PodInfo {
            pod: "test-pod".to_string(),
            namespace: "test-namespace".to_string(),
        };

        let cloned = pod_info.clone();
        assert_eq!(pod_info.pod, cloned.pod);
        assert_eq!(pod_info.namespace, cloned.namespace);
    }

    #[test]
    fn test_ip_pod_mapping_new() {
        // This will try to fetch from localhost:61679 which will fail in tests
        // but we can verify the structure is created
        let mapping = IPPodMapping::new();
        assert!(mapping.map.is_empty()); // Should be empty due to failed fetch
    }

    #[test]
    fn test_ip_pod_mapping_get() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let pod_info = PodInfo {
            pod: "test-pod".to_string(),
            namespace: "test-namespace".to_string(),
        };

        mapping.map.insert(ip, pod_info.clone());

        let result = mapping.get(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().pod, "test-pod");
        assert_eq!(result.unwrap().namespace, "test-namespace");

        let non_existent_ip: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(mapping.get(non_existent_ip).is_none());
    }

    #[test]
    fn test_process_eni_response_ipv4() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // Create test ENI response with IPv4 addresses
        let mut enis = HashMap::new();
        let mut available_ipv4_cidrs = HashMap::new();
        let mut ip_addresses = HashMap::new();

        let ip_info = IPAddressInfo {
            address: "192.168.1.10".to_string(),
            ipam_key: IPAMKey {
                network_name: "aws-cni".to_string(),
                container_id: "test-container".to_string(),
                if_name: "eth0".to_string(),
            },
            ipam_metadata: IPAMMetadata {
                k8s_pod_namespace: "default".to_string(),
                k8s_pod_name: "test-pod".to_string(),
            },
            assigned_time: "2025-01-01T00:00:00Z".to_string(),
            unassigned_time: "0001-01-01T00:00:00Z".to_string(),
        };

        ip_addresses.insert("192.168.1.10".to_string(), ip_info);

        let cidr_info = CidrInfo {
            cidr: CidrDetails {
                ip: "192.168.1.0".to_string(),
                mask: "24".to_string(),
            },
            ip_addresses,
            is_prefix: false,
            address_family: "ipv4".to_string(),
        };

        available_ipv4_cidrs.insert("192.168.1.0/24".to_string(), cidr_info);

        let eni_info = ENIInfo {
            id: "eni-12345".to_string(),
            is_primary: true,
            is_trunk: false,
            is_efa: false,
            device_number: 0,
            available_ipv4_cidrs,
            ipv6_cidrs: HashMap::new(),
        };

        enis.insert("eni-12345".to_string(), eni_info);

        let eni_response = ENIResponse {
            total_ips: 1,
            assigned_ips: 1,
            enis,
        };

        mapping.process_eni_response(eni_response);

        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        let result = mapping.get(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().pod, "test-pod");
        assert_eq!(result.unwrap().namespace, "default");
    }

    #[test]
    fn test_process_eni_response_ipv6() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // Create test ENI response with IPv6 addresses
        let mut enis = HashMap::new();
        let mut ipv6_cidrs = HashMap::new();
        let mut ip_addresses = HashMap::new();

        let ip_info = IPAddressInfo {
            address: "2001:db8::1".to_string(),
            ipam_key: IPAMKey {
                network_name: "aws-cni".to_string(),
                container_id: "test-container".to_string(),
                if_name: "eth0".to_string(),
            },
            ipam_metadata: IPAMMetadata {
                k8s_pod_namespace: "kube-system".to_string(),
                k8s_pod_name: "test-pod-ipv6".to_string(),
            },
            assigned_time: "2025-01-01T00:00:00Z".to_string(),
            unassigned_time: "0001-01-01T00:00:00Z".to_string(),
        };

        ip_addresses.insert("2001:db8::1".to_string(), ip_info);

        let cidr_info = CidrInfo {
            cidr: CidrDetails {
                ip: "2001:db8::".to_string(),
                mask: "64".to_string(),
            },
            ip_addresses,
            is_prefix: false,
            address_family: "ipv6".to_string(),
        };

        ipv6_cidrs.insert("2001:db8::/64".to_string(), cidr_info);

        let eni_info = ENIInfo {
            id: "eni-67890".to_string(),
            is_primary: false,
            is_trunk: true,
            is_efa: false,
            device_number: 1,
            available_ipv4_cidrs: HashMap::new(),
            ipv6_cidrs,
        };

        enis.insert("eni-67890".to_string(), eni_info);

        let eni_response = ENIResponse {
            total_ips: 1,
            assigned_ips: 1,
            enis,
        };

        mapping.process_eni_response(eni_response);

        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let result = mapping.get(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().pod, "test-pod-ipv6");
        assert_eq!(result.unwrap().namespace, "kube-system");
    }

    #[test]
    fn test_process_eni_response_empty_metadata() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // Create test ENI response with empty pod metadata (should be skipped)
        let mut enis = HashMap::new();
        let mut available_ipv4_cidrs = HashMap::new();
        let mut ip_addresses = HashMap::new();

        let ip_info = IPAddressInfo {
            address: "192.168.1.20".to_string(),
            ipam_key: IPAMKey {
                network_name: "aws-cni".to_string(),
                container_id: "test-container".to_string(),
                if_name: "eth0".to_string(),
            },
            ipam_metadata: IPAMMetadata {
                k8s_pod_namespace: "".to_string(), // Empty namespace
                k8s_pod_name: "".to_string(),      // Empty pod name
            },
            assigned_time: "2025-01-01T00:00:00Z".to_string(),
            unassigned_time: "0001-01-01T00:00:00Z".to_string(),
        };

        ip_addresses.insert("192.168.1.20".to_string(), ip_info);

        let cidr_info = CidrInfo {
            cidr: CidrDetails {
                ip: "192.168.1.0".to_string(),
                mask: "24".to_string(),
            },
            ip_addresses,
            is_prefix: false,
            address_family: "ipv4".to_string(),
        };

        available_ipv4_cidrs.insert("192.168.1.0/24".to_string(), cidr_info);

        let eni_info = ENIInfo {
            id: "eni-empty".to_string(),
            is_primary: true,
            is_trunk: false,
            is_efa: false,
            device_number: 0,
            available_ipv4_cidrs,
            ipv6_cidrs: HashMap::new(),
        };

        enis.insert("eni-empty".to_string(), eni_info);

        let eni_response = ENIResponse {
            total_ips: 1,
            assigned_ips: 0, // No assigned IPs due to empty metadata
            enis,
        };

        mapping.process_eni_response(eni_response);

        // Should be empty since metadata was empty
        assert!(mapping.map.is_empty());
    }

    #[test]
    fn test_process_eni_response_invalid_ip() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // Create test ENI response with invalid IP address
        let mut enis = HashMap::new();
        let mut available_ipv4_cidrs = HashMap::new();
        let mut ip_addresses = HashMap::new();

        let ip_info = IPAddressInfo {
            address: "invalid-ip-address".to_string(), // Invalid IP
            ipam_key: IPAMKey {
                network_name: "aws-cni".to_string(),
                container_id: "test-container".to_string(),
                if_name: "eth0".to_string(),
            },
            ipam_metadata: IPAMMetadata {
                k8s_pod_namespace: "default".to_string(),
                k8s_pod_name: "test-pod".to_string(),
            },
            assigned_time: "2025-01-01T00:00:00Z".to_string(),
            unassigned_time: "0001-01-01T00:00:00Z".to_string(),
        };

        ip_addresses.insert("invalid-ip-address".to_string(), ip_info);

        let cidr_info = CidrInfo {
            cidr: CidrDetails {
                ip: "192.168.1.0".to_string(),
                mask: "24".to_string(),
            },
            ip_addresses,
            is_prefix: false,
            address_family: "ipv4".to_string(),
        };

        available_ipv4_cidrs.insert("192.168.1.0/24".to_string(), cidr_info);

        let eni_info = ENIInfo {
            id: "eni-invalid".to_string(),
            is_primary: true,
            is_trunk: false,
            is_efa: false,
            device_number: 0,
            available_ipv4_cidrs,
            ipv6_cidrs: HashMap::new(),
        };

        enis.insert("eni-invalid".to_string(), eni_info);

        let eni_response = ENIResponse {
            total_ips: 1,
            assigned_ips: 1,
            enis,
        };

        mapping.process_eni_response(eni_response);

        // Should be empty since IP was invalid
        assert!(mapping.map.is_empty());
    }

    #[test]
    fn test_process_eni_response_clears_existing_map() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // Add some existing data
        let existing_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let existing_pod = PodInfo {
            pod: "existing-pod".to_string(),
            namespace: "existing-namespace".to_string(),
        };
        mapping.map.insert(existing_ip, existing_pod);

        // Process empty ENI response
        let eni_response = ENIResponse {
            total_ips: 0,
            assigned_ips: 0,
            enis: HashMap::new(),
        };

        mapping.process_eni_response(eni_response);

        // Map should be cleared
        assert!(mapping.map.is_empty());
    }

    #[test]
    fn test_fetch_eni_data_error_handling() {
        let mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // This will fail because localhost:61679 is not running in tests
        let result = mapping.fetch_eni_data();
        assert!(result.is_err());
    }

    #[test]
    fn test_update_with_fetch_error() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // Add some existing data
        let existing_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let existing_pod = PodInfo {
            pod: "existing-pod".to_string(),
            namespace: "existing-namespace".to_string(),
        };
        mapping.map.insert(existing_ip, existing_pod);

        // Update will fail to fetch but shouldn't panic
        mapping.update();

        // Map should still contain existing data since fetch failed
        assert_eq!(mapping.map.len(), 1);
    }
}
