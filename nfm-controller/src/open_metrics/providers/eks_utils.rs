use std::{collections::HashMap, net::IpAddr, str::FromStr};

use k8s_openapi::api::core::v1::Pod;
use kube::{Api, Client};
use log::{debug, error, info};

use crate::{
    metadata::imds_utils::get_runtime_executor,
    utils::crypto::ensure_default_crypto_provider_exists,
};

#[derive(Debug, Clone, PartialEq)]
pub struct PodInfo {
    pub pod: String,
    pub namespace: String,
}

type PodIP = IpAddr;

#[derive(Clone)]
pub struct IPPodMapping {
    map: HashMap<PodIP, Vec<PodInfo>>,
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
        match self.fetch_pods_from_k8s() {
            Ok(()) => {
                info!("Successfully updated IP to POD mapping from Kubernetes API");
            }
            Err(e) => {
                error!(
                    "Failed to update IP to POD mapping from Kubernetes API: {}",
                    e
                );
            }
        }
    }

    /// Get the first pod info for an IP (for backward compatibility)
    pub fn get_first(&self, ip: PodIP) -> Option<&PodInfo> {
        self.map.get(&ip).and_then(|pods| pods.first())
    }

    fn fetch_pods_from_k8s(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Fetching pod data from Kubernetes API");

        match get_runtime_executor() {
            Some(executor) => executor.block_on(async { self.fetch_pods_async().await }),
            None => {
                error!("Failed to get runtime executor for Kubernetes API");
                Err("Failed to get runtime executor".into())
            }
        }
    }

    async fn fetch_pods_async(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Ensure default crypto provider exists for kube client
        ensure_default_crypto_provider_exists();

        let client = Client::try_default().await?;
        let pods: Api<Pod> = Api::all(client);

        let pod_list = pods.list(&Default::default()).await?;

        self.map.clear();
        let mut total_processed = 0;

        for pod in pod_list.items {
            if let Some(pod_status) = &pod.status {
                // Get pod IPs (both primary and additional IPs)
                let mut pod_ips = Vec::new();

                // Primary pod IP
                if let Some(pod_ip_str) = &pod_status.pod_ip {
                    if let Ok(pod_ip) = IpAddr::from_str(pod_ip_str) {
                        pod_ips.push(pod_ip);
                    }
                }

                // Additional pod IPs
                if let Some(pod_ip_list) = &pod_status.pod_ips {
                    // Skip the primary IP.
                    // https://docs.rs/k8s-openapi/latest/k8s_openapi/api/core/v1/struct.PodStatus.html
                    for pod_ip_info in pod_ip_list.iter().skip(1) {
                        if let Ok(pod_ip) = IpAddr::from_str(&pod_ip_info.ip) {
                            pod_ips.push(pod_ip);
                        }
                    }
                }

                // Create PodInfo for this pod
                let pod_info = PodInfo {
                    pod: pod.metadata.name.clone().unwrap_or_default(),
                    namespace: pod.metadata.namespace.clone().unwrap_or_default(),
                };

                // Map each IP to this pod
                for pod_ip in pod_ips {
                    debug!(
                        "Mapping IP {} to pod {}/{}",
                        pod_ip, pod_info.namespace, pod_info.pod
                    );

                    self.map
                        .entry(pod_ip)
                        .or_insert_with(Vec::new)
                        .push(pod_info.clone());

                    total_processed += 1;
                }
            }
        }

        debug!(
            "Successfully updated IP to POD mapping with {} IP-to-pod mappings",
            total_processed
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_pod_info_equality() {
        let pod_info1 = PodInfo {
            pod: "test-pod".to_string(),
            namespace: "test-namespace".to_string(),
        };

        let pod_info2 = PodInfo {
            pod: "test-pod".to_string(),
            namespace: "test-namespace".to_string(),
        };

        let pod_info3 = PodInfo {
            pod: "different-pod".to_string(),
            namespace: "test-namespace".to_string(),
        };

        assert_eq!(pod_info1, pod_info2);
        assert_ne!(pod_info1, pod_info3);
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

        mapping.map.insert(ip, vec![pod_info.clone()]);

        let result = mapping.map.get(&ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(result.unwrap()[0].pod, "test-pod");
        assert_eq!(result.unwrap()[0].namespace, "test-namespace");

        let non_existent_ip: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(mapping.map.get(&non_existent_ip).is_none());
    }

    #[test]
    fn test_ip_pod_mapping_get_first() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let pod_info1 = PodInfo {
            pod: "test-pod-1".to_string(),
            namespace: "test-namespace".to_string(),
        };
        let pod_info2 = PodInfo {
            pod: "test-pod-2".to_string(),
            namespace: "test-namespace".to_string(),
        };

        mapping
            .map
            .insert(ip, vec![pod_info1.clone(), pod_info2.clone()]);

        let result = mapping.get_first(ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().pod, "test-pod-1");
        assert_eq!(result.unwrap().namespace, "test-namespace");

        let non_existent_ip: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(mapping.get_first(non_existent_ip).is_none());
    }

    #[test]
    fn test_ip_pod_mapping_multiple_pods_per_ip() {
        let mut mapping = IPPodMapping {
            map: HashMap::new(),
        };

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let pod_info1 = PodInfo {
            pod: "test-pod-1".to_string(),
            namespace: "namespace-1".to_string(),
        };
        let pod_info2 = PodInfo {
            pod: "test-pod-2".to_string(),
            namespace: "namespace-2".to_string(),
        };

        mapping
            .map
            .insert(ip, vec![pod_info1.clone(), pod_info2.clone()]);

        let result = mapping.map.get(&ip);
        assert!(result.is_some());
        let pods = result.unwrap();
        assert_eq!(pods.len(), 2);
        assert_eq!(pods[0].pod, "test-pod-1");
        assert_eq!(pods[0].namespace, "namespace-1");
        assert_eq!(pods[1].pod, "test-pod-2");
        assert_eq!(pods[1].namespace, "namespace-2");
    }

    #[test]
    fn test_runtime_executor_usage() {
        // Test that we can create a mapping without runtime field
        let mapping = IPPodMapping {
            map: HashMap::new(),
        };

        // Verify the structure is correct
        assert!(mapping.map.is_empty());
    }
}
