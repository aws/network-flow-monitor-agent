// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Watches Kubernetes pods that use EFA devices and maps EFA device names to pods
//! by querying the Kubelet PodResources gRPC API.

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::runtime::watcher::{self, watcher as kube_watcher, Event};
use kube::runtime::WatchStreamExt;
use kube::{Api, Client};
use log::{debug, info, warn};

use super::podresources_v1::pod_resources_lister_client::PodResourcesListerClient;
use super::podresources_v1::ListPodResourcesRequest;

const KUBELET_SOCKET_PATH: &str = "/var/lib/kubelet/pod-resources/kubelet.sock";
const EFA_RESOURCE_NAME: &str = "vpc.amazonaws.com/efa";

/// Pod information associated with an EFA device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EfaPodInfo {
    pub pod_name: String,
    pub pod_namespace: String,
}

/// Maps EFA device IDs (as reported by the device plugin) to the pod using them.
pub type EfaDeviceToPodMap = HashMap<String, EfaPodInfo>;

/// Client that watches pods requesting EFA resources and maintains a device→pod mapping
/// by querying the Kubelet PodResources API.
pub struct EfaPodResourcesWatcher {
    device_map: Arc<Mutex<EfaDeviceToPodMap>>,
}

impl Default for EfaPodResourcesWatcher {
    fn default() -> Self {
        Self {
            device_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl EfaPodResourcesWatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn device_map(&self) -> Arc<Mutex<EfaDeviceToPodMap>> {
        Arc::clone(&self.device_map)
    }

    pub fn start(&self) {
        let device_map = Arc::clone(&self.device_map);
        tokio::spawn(async move {
            let node_name = match Self::node_has_efa_allocatable().await {
                Some(name) => name,
                None => {
                    info!(
                        "EFA device plugin not registered on this node, \
                         skipping PodResources watcher"
                    );
                    return;
                }
            };
            Self::watch_efa_pods(device_map, &node_name).await;
        });
        info!("EFA PodResources watcher starting");
    }

    async fn node_has_efa_allocatable() -> Option<String> {
        let node_name = match env::var("K8S_NODE_NAME") {
            Ok(name) => name,
            Err(_) => {
                warn!("K8S_NODE_NAME not set, cannot check node allocatable resources");
                return None;
            }
        };

        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to create K8s client for node check: {}", e);
                return None;
            }
        };

        let nodes: Api<Node> = Api::all(client);
        match nodes.get(&node_name).await {
            Ok(node) => {
                let has_efa = node
                    .status
                    .as_ref()
                    .and_then(|s| s.allocatable.as_ref())
                    .and_then(|alloc| alloc.get(EFA_RESOURCE_NAME))
                    .map(|q| q.0 != "0")
                    .unwrap_or(false);

                if has_efa {
                    info!(
                        "EFA device plugin detected on node (vpc.amazonaws.com/efa is allocatable)"
                    );
                    Some(node_name)
                } else {
                    debug!(
                        "Node {} does not have EFA in allocatable resources",
                        node_name
                    );
                    None
                }
            }
            Err(e) => {
                warn!("Failed to get node {}: {}", node_name, e);
                None
            }
        }
    }

    async fn watch_efa_pods(device_map: Arc<Mutex<EfaDeviceToPodMap>>, node_name: &str) {
        let client = match Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to create K8s client for EFA pod watcher: {}", e);
                return;
            }
        };

        let api: Api<Pod> = Api::all(client);
        let watcher_config = watcher::Config::default()
            .page_size(150)
            .fields(&format!("spec.nodeName={}", node_name));
        let stream = kube_watcher(api, watcher_config).default_backoff();

        stream
            .for_each(|event| {
                let device_map = Arc::clone(&device_map);
                async move {
                    match event {
                        Ok(Event::Apply(pod)) => {
                            if Self::pod_requests_efa(&pod) {
                                debug!(
                                    "EFA pod event (apply): {}/{}",
                                    pod.metadata.namespace.as_deref().unwrap_or(""),
                                    pod.metadata.name.as_deref().unwrap_or("")
                                );
                                Self::refresh_device_map(&device_map).await;
                            }
                        }
                        Ok(Event::InitApply(_)) => {}
                        Ok(Event::Delete(pod)) => {
                            if Self::pod_requests_efa(&pod) {
                                debug!(
                                    "EFA pod event (delete): {}/{}",
                                    pod.metadata.namespace.as_deref().unwrap_or(""),
                                    pod.metadata.name.as_deref().unwrap_or("")
                                );
                                Self::refresh_device_map(&device_map).await;
                            }
                        }
                        Ok(Event::Init) => {}
                        Ok(Event::InitDone) => {
                            info!("EFA pod watcher initial list complete, refreshing device map");
                            Self::refresh_device_map(&device_map).await;
                        }
                        Err(e) => {
                            warn!("EFA pod watcher error: {}", e);
                        }
                    }
                }
            })
            .await;
    }

    fn pod_requests_efa(pod: &Pod) -> bool {
        let Some(spec) = &pod.spec else {
            return false;
        };
        for container in &spec.containers {
            if let Some(resources) = &container.resources {
                if let Some(limits) = &resources.limits {
                    if limits.contains_key(EFA_RESOURCE_NAME) {
                        return true;
                    }
                }
                if let Some(requests) = &resources.requests {
                    if requests.contains_key(EFA_RESOURCE_NAME) {
                        return true;
                    }
                }
            }
        }
        false
    }

    // Pod events tell us which pod changed but not which device IDs the device plugin
    // assigned to it, only the Kubelet PodResources API has that.
    async fn refresh_device_map(device_map: &Arc<Mutex<EfaDeviceToPodMap>>) {
        match Self::query_pod_resources().await {
            Ok(new_map) => {
                let mut map = device_map.lock().unwrap();
                *map = new_map;
                debug!("EFA device map refreshed: {} entries", map.len());
            }
            Err(e) => {
                warn!("Failed to query PodResources API: {}", e);
            }
        }
    }

    async fn query_pod_resources() -> Result<EfaDeviceToPodMap, anyhow::Error> {
        let channel = Self::connect_to_kubelet().await?;
        let mut client = PodResourcesListerClient::new(channel);

        let response = client.list(ListPodResourcesRequest {}).await?;

        let mut map = EfaDeviceToPodMap::new();
        for pod_resource in &response.get_ref().pod_resources {
            let pod_info = EfaPodInfo {
                pod_name: pod_resource.name.clone(),
                pod_namespace: pod_resource.namespace.clone(),
            };

            for container in &pod_resource.containers {
                for device in &container.devices {
                    if device.resource_name == EFA_RESOURCE_NAME {
                        for device_id in &device.device_ids {
                            map.insert(device_id.clone(), pod_info.clone());
                        }
                    }
                }
            }
        }

        Ok(map)
    }

    async fn connect_to_kubelet() -> Result<tonic::transport::Channel, anyhow::Error> {
        use tokio::net::UnixStream;
        use tonic::transport::Endpoint;

        let endpoint = Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(tower::service_fn(move |_| async move {
                UnixStream::connect(KUBELET_SOCKET_PATH)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }))
            .await?;

        Ok(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{Container, PodSpec, ResourceRequirements};
    use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
    use std::collections::BTreeMap;

    fn make_pod_with_efa(name: &str, namespace: &str, efa_count: &str) -> Pod {
        let mut limits = BTreeMap::new();
        limits.insert(
            EFA_RESOURCE_NAME.to_string(),
            Quantity(efa_count.to_string()),
        );

        Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "main".to_string(),
                    resources: Some(ResourceRequirements {
                        limits: Some(limits),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn make_pod_without_efa(name: &str, namespace: &str) -> Pod {
        Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(namespace.to_string()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "main".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_pod_requests_efa_with_efa_limits() {
        let pod = make_pod_with_efa("training-pod", "ml", "4");
        assert!(EfaPodResourcesWatcher::pod_requests_efa(&pod));
    }

    #[test]
    fn test_pod_requests_efa_without_efa() {
        let pod = make_pod_without_efa("web-pod", "default");
        assert!(!EfaPodResourcesWatcher::pod_requests_efa(&pod));
    }

    #[test]
    fn test_pod_requests_efa_no_spec() {
        let pod = Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("broken".to_string()),
                ..Default::default()
            },
            spec: None,
            ..Default::default()
        };
        assert!(!EfaPodResourcesWatcher::pod_requests_efa(&pod));
    }

    #[test]
    fn test_pod_requests_efa_in_requests_field() {
        let mut requests = BTreeMap::new();
        requests.insert(EFA_RESOURCE_NAME.to_string(), Quantity("1".to_string()));

        let pod = Pod {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                name: Some("req-pod".to_string()),
                namespace: Some("ml".to_string()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "main".to_string(),
                    resources: Some(ResourceRequirements {
                        requests: Some(requests),
                        ..Default::default()
                    }),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(EfaPodResourcesWatcher::pod_requests_efa(&pod));
    }

    #[test]
    fn test_new_creates_empty_map() {
        let watcher = EfaPodResourcesWatcher::new();
        let map_arc = watcher.device_map();
        let map = map_arc.lock().unwrap();
        assert!(map.is_empty());
    }
}
