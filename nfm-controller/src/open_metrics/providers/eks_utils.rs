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
        // Clear existing mappings
        self.map.clear();

        let mut total_processed = 0;

        // Process each ENI
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
}
