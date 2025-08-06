// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use futures::{Stream, StreamExt};
use k8s_openapi::api::core::v1::{Container, Pod};
use k8s_openapi::api::discovery::v1::{Endpoint, EndpointSlice};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::Metadata;
use k8s_openapi::Resource;
use kube::runtime::utils::StreamBackoff;
use kube::runtime::watcher::{DefaultBackoff, Error, Event};
use kube::runtime::{watcher, WatchStreamExt};
use kube::ResourceExt;
use kube::{Api, Client};
use log::info;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::fmt::Debug;
use tokio::runtime::Runtime;

use crate::events::network_event::AggregateResults;
use crate::kubernetes::flow_metadata::FlowMetadata;

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Default)]
pub struct PodInfo {
    pub name: String,
    pub namespace: String,
    pub service_name: String,
}

pub struct KubernetesMetadataCollector {
    enriched_flows: u64,
    refresher_runtime: Option<Runtime>,
    pod_info_arc: Arc<Mutex<HashMap<IpAddr, HashMap<i32, PodInfo>>>>,
}

impl Default for KubernetesMetadataCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl KubernetesMetadataCollector {
    pub fn new() -> Self {
        Self {
            enriched_flows: 0,
            refresher_runtime: None,
            pod_info_arc: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /**
     * Extract ip address from Pod object
     */
    fn get_ip_from_pod(pod: &Pod) -> Option<IpAddr> {
        match pod.status {
            Some(ref status) => status
                .pod_ip
                .as_ref()
                .and_then(|ip_str| IpAddr::from_str(ip_str.as_str()).ok()),
            None => None,
        }
    }

    /**
     * Extract pod name from Endpoint object
     */
    fn get_pod_name_from_endpoint(endpoint: &Endpoint) -> String {
        endpoint
            .target_ref
            .as_ref()
            .and_then(|object_ref| object_ref.name.clone())
            .unwrap_or_default()
    }

    /**
     * Extract what ports the service serves from, using endpoint slice.
     * We only care for TCP ports right now, in future we can add others.
     */
    fn get_tcp_ports_from_endpoint_slice(endpoint_slice: &EndpointSlice) -> Vec<i32> {
        endpoint_slice
            .ports
            .as_ref()
            .map_or_else(Vec::new, |endpoint_ports| {
                endpoint_ports
                    .iter()
                    .filter_map(|port| {
                        match port.protocol.as_deref() {
                            Some("TCP") => port.port, // can be None, but it will be filtered out in that case
                            _ => None,
                        }
                    })
                    .collect()
            })
    }

    /**
     * Get all the TCP ports this specific container serves from
     */
    fn extract_ports_from_pod_container(container: &Container) -> Vec<i32> {
        container
            .ports
            .as_ref()
            .map_or_else(Vec::new, |container_ports| {
                container_ports
                    .iter()
                    .filter_map(|container_port| {
                        match container_port.protocol.as_deref().unwrap_or_default() {
                            "TCP" => Some(container_port.container_port), // can be None, but it will be filtered out in that case
                            _ => None,
                        }
                    })
                    .collect::<Vec<i32>>()
            })
    }

    /**
     * Extract what ports the pod serves from, using Pod data
     * We only care for TCP ports right now, in future we can add others.
     */
    fn get_tcp_ports_from_pod(pod: &Pod) -> Vec<i32> {
        pod.spec
            .as_ref()
            .map(|spec| {
                spec.containers // Generally each pod contains 1 container, but can be more. They will share the same Network Namespace
                    .iter()
                    .flat_map(Self::extract_ports_from_pod_container)
                    .collect()
            })
            .unwrap_or_default()
    }

    /**
     * Purge the given pod ip and ports from pod info map.
     */
    fn purge_pod_ip_ports_from_pod_info(
        pod_info: &mut MutexGuard<'_, HashMap<IpAddr, HashMap<i32, PodInfo>>>,
        pod_ip: &IpAddr,
        ports: &Vec<i32>,
    ) {
        // Remove specific port entries, and remove whole ip port map if necessary
        if let Some(port_map) = pod_info.get_mut(pod_ip) {
            for port in ports {
                port_map.remove(port);
            }
            if port_map.is_empty() {
                pod_info.remove(pod_ip);
            }
        }
    }

    /**
     * Handle a Pod event. Pod events are sent by kubernetes api server when a new pod is added, removed or modified.
     * On add or update events we add to or replace an entry in our internal map.
     * On delete events we remove associated entry from our internal map.
     */
    fn handle_pod_event(
        pod_event_result: Result<Event<Pod>, watcher::Error>,
        pod_info_root_map: Arc<Mutex<HashMap<IpAddr, HashMap<i32, PodInfo>>>>,
    ) {
        let pod_event = match pod_event_result {
            Ok(event) => event,
            Err(err) => {
                info!(message = err.to_string(); "watcher encountered an error, will autorecover in next poll");
                return;
            }
        };

        match pod_event {
            Event::Apply(pod) | Event::InitApply(pod) => {
                let ports = Self::get_tcp_ports_from_pod(&pod);
                if let Some(pod_ip) = Self::get_ip_from_pod(&pod) {
                    let mut pod_info = pod_info_root_map.lock().unwrap();
                    for port in &ports {
                        pod_info
                            .entry(pod_ip)
                            .or_default()
                            .entry(*port)
                            .or_insert_with(||
                                // Only insert if pod info for this port doesn't exist.
                                // If its already filled by endpoint slice info, do not override it because it will contain more info.
                                // In case this pod event comes before endpoint slice event, that is alright as endpoint slice event will override it.
                                PodInfo {
                                    name: pod.name_any(),
                                    ..Default::default()
                                });
                    }
                }
            }
            Event::Delete(pod) => {
                if let Some(pod_ip) = Self::get_ip_from_pod(&pod) {
                    let ports = Self::get_tcp_ports_from_pod(&pod);
                    let mut pod_info = pod_info_root_map.lock().unwrap();
                    Self::purge_pod_ip_ports_from_pod_info(&mut pod_info, &pod_ip, &ports);
                }
            }
            _ => {}
        }
    }

    /**
     * An endpoint slice represents a group of endpoints(pod), sometimes a pod might have more than one IP
     * We associate all those IPs with the same PodInfo
     * Since we are overriding the entry, this handles both additions and updates
     */
    fn handle_endpoint_update(
        slice: EndpointSlice,
        mut pod_info_root_map: MutexGuard<'_, HashMap<IpAddr, HashMap<i32, PodInfo>>>,
    ) {
        let ports: Vec<i32> = Self::get_tcp_ports_from_endpoint_slice(&slice);
        for endpoint in &slice.endpoints {
            for address in &endpoint.addresses {
                let pod_ip = match IpAddr::from_str(address) {
                    Ok(ip) => ip,
                    Err(_) => continue, // should never happen, but if happens, we dont care
                };
                let pod_name = Self::get_pod_name_from_endpoint(endpoint);

                for port in &ports {
                    pod_info_root_map.entry(pod_ip).or_default().insert(
                        *port,
                        PodInfo {
                            name: pod_name.clone(),
                            namespace: slice.metadata.namespace.as_ref().unwrap().clone(),
                            service_name: Self::get_service_name_from_endpoint_slice(&slice),
                        },
                    );
                }
            }
        }
    }

    /**
     * An endpoint slice represents a group of endpoints(pod), sometimes a pod might have more than one IP
     * We associate all those IPs with the same PodInfo
     * We remove all those IPs from pod info map here
     */
    fn handle_endpoint_removal(
        slice: EndpointSlice,
        mut pod_info: MutexGuard<'_, HashMap<IpAddr, HashMap<i32, PodInfo>>>,
    ) {
        let ports: Vec<i32> = Self::get_tcp_ports_from_endpoint_slice(&slice);
        for endpoint in &slice.endpoints {
            for address in &endpoint.addresses {
                let pod_ip = match IpAddr::from_str(address) {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };
                Self::purge_pod_ip_ports_from_pod_info(&mut pod_info, &pod_ip, &ports);
            }
        }
    }

    /**
     * Handle a EndpointSlice event. EndpointSlice events are sent by kubernetes api server when a new EndpointSlice is added, removed or modified.
     * An EndpointSlice is a group of endpoints (thus Pods) that share the same service and port.
     * On add or update events we add to or replace an entries of relevant pods in our internal map.
     * On delete events we remove associated entries of relevant pods from our internal map.
     */
    fn handle_endpoint_slice_event(
        slice_event_result: Result<Event<EndpointSlice>, watcher::Error>,
        pod_info_arc: Arc<Mutex<HashMap<IpAddr, HashMap<i32, PodInfo>>>>,
    ) {
        let slice_event = match slice_event_result {
            Ok(event) => event,
            Err(_) => return, // a communication error might occur, stream will autorecover
        };

        match slice_event {
            Event::Apply(slice) | Event::InitApply(slice) => {
                let pod_info = pod_info_arc.lock().unwrap();
                Self::handle_endpoint_update(slice, pod_info);
            }
            Event::Delete(slice) => {
                let pod_info = pod_info_arc.lock().unwrap();
                Self::handle_endpoint_removal(slice, pod_info);
            }
            _ => {}
        }
    }

    /**
     * Convenience function, to get a watcher stream for a given resource type, like Pod or EndpointSlice
     */
    async fn create_watcher_stream<K>(
    ) -> StreamBackoff<impl Stream<Item = Result<Event<K>, Error>> + Send, DefaultBackoff>
    where
        K: Resource + Clone + DeserializeOwned + Debug + Send + 'static + Metadata<Ty = ObjectMeta>,
    {
        let client = Client::try_default()
            .await
            .expect("Failed to create Kubernetes client, perhaps you are running with '-k on' in a non kubernetes environment?");
        let api = Api::all(client);
        watcher(api, watcher::Config::default().page_size(150)).default_backoff()
    }

    /**
     * Start a watcher for pod changes. This will run forever
     */
    async fn start_pod_watcher(pod_info: Arc<Mutex<HashMap<IpAddr, HashMap<i32, PodInfo>>>>) {
        let pod_stream = Self::create_watcher_stream::<Pod>().await;
        pod_stream
            .for_each(|pod_event| async {
                Self::handle_pod_event(pod_event, Arc::clone(&pod_info))
            })
            .await;
    }

    /**
     * Start a watcher for endpoint slice changes. This will run forever
     */
    async fn start_endpoint_slice_watcher(
        pod_info: Arc<Mutex<HashMap<IpAddr, HashMap<i32, PodInfo>>>>,
    ) {
        let endpoints_stream = Self::create_watcher_stream::<EndpointSlice>().await;
        endpoints_stream
            .for_each(|slice_result| async {
                Self::handle_endpoint_slice_event(slice_result, Arc::clone(&pod_info))
            })
            .await;
    }

    /**
     * Create two tasks running forever, with main goals of listening pod and endpoint slice updates
     */
    pub fn setup_watchers(&mut self) {
        if self.refresher_runtime.is_none() {
            self.refresher_runtime = Some(tokio::runtime::Runtime::new().unwrap());
        } else {
            // the watchers are already running, no need to do anything
            return;
        }
        Self::ensure_default_crypto_provider_exists();
        let runtime = self.refresher_runtime.as_ref().unwrap();
        runtime.spawn(Self::start_pod_watcher(Arc::clone(&self.pod_info_arc)));
        runtime.spawn(Self::start_endpoint_slice_watcher(Arc::clone(
            &self.pod_info_arc,
        )));
    }

    /**
     * Make sure that a default crypto provider exists as Kube Client will depend on it.
     */
    fn ensure_default_crypto_provider_exists() {
        match rustls::crypto::CryptoProvider::get_default() {
            Some(_) => {
                info!("A default crpyto provider is already assigned to the process, skipping creation.");
            }
            None => {
                info!("No crpyto provider exists for the process, creating one.");
                let default_provider = rustls::crypto::ring::default_provider();
                rustls::crypto::CryptoProvider::install_default(default_provider)
                    .expect("Crypto Provider is empty");
            }
        }
    }

    /**
     * Get pod info associated with given IP address
     */
    fn get_pod_info<'a>(
        pod_info: &'a HashMap<IpAddr, HashMap<i32, PodInfo>>,
        address: &'a IpAddr,
    ) -> Option<&'a HashMap<i32, PodInfo>> {
        let mut pod_data = pod_info.get(address);
        if pod_data.is_none() {
            // there can be cases where reported IPs are IPv4 adresses wrapped with IPv6
            // for example "::ffff:100.64.38.124". Try to extract the underlying IPv4 for that case
            if let IpAddr::V6(ipv6) = address {
                if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                    pod_data = pod_info.get(&IpAddr::V4(ipv4));
                }
            }
        }
        pod_data
    }

    /**
     * Get given set of flows and enrich them with kubernetes metadata
     */
    pub fn enrich_flows(&mut self, agg_flows: &mut [AggregateResults]) -> u64 {
        let start = Instant::now();
        let mut enriched_this_run: u64 = 0;
        let pod_info = self.pod_info_arc.lock().unwrap().clone();

        for agg_flow in agg_flows.iter_mut() {
            let local_pod_port_map = Self::get_pod_info(&pod_info, &agg_flow.flow.local_address);
            let remote_pod_port_map = Self::get_pod_info(&pod_info, &agg_flow.flow.remote_address);

            let (mut local_pod_info, mut remote_pod_info) = (None, None);

            if agg_flow.flow.is_client_flow() {
                // if this is a client flow, we can be sure of the remote end, but we can only be sure of the local only under the case
                // when theres only one pod associated with the local IP
                if let Some(local_port_map) = local_pod_port_map {
                    if local_port_map.len() == 1 {
                        // if there is only one pod associated with this IP we can be sure that this is the pod that is initiating the connection
                        local_pod_info = local_port_map.values().next();
                    }
                }
                if let Some(remote_port_map) = remote_pod_port_map {
                    remote_pod_info = remote_port_map.get(&agg_flow.flow.remote_port.into());
                }
            } else {
                // if this is a server flow, we can be sure of the local end, but we can only be sure of the remote only under the case
                // when theres only one pod associated with the remote IP
                if let Some(remote_port_map) = remote_pod_port_map {
                    if remote_port_map.len() == 1 {
                        // if there is only one pod associated with this IP we can be sure that this is the pod that is initiating the connection
                        remote_pod_info = remote_port_map.values().next();
                    }
                }
                if let Some(local_port_map) = local_pod_port_map {
                    local_pod_info = local_port_map.get(&agg_flow.flow.local_port.into());
                }
            }

            if local_pod_info.is_some() || remote_pod_info.is_some() {
                agg_flow.flow.kubernetes_metadata = Some(FlowMetadata {
                    local: local_pod_info.cloned(),
                    remote: remote_pod_info.cloned(),
                });
                enriched_this_run += 1;
            }
        }
        self.enriched_flows += enriched_this_run;
        info!(
            duration_micro = (Instant::now() - start).as_micros(),
            total_flows = agg_flows.len(),
            enriched_flows = enriched_this_run;
            "Flow enrichment completed."
        );
        enriched_this_run
    }

    /**
     * Get the name of the service representing the endpoint slice
     */
    fn get_service_name_from_endpoint_slice(endpoint_slice: &EndpointSlice) -> String {
        // regular service names are stored under a metadata label, first try that
        let service_name_from_labels = match endpoint_slice.metadata.labels.as_ref() {
            Some(labels) => labels.get("kubernetes.io/service-name").cloned(),
            None => None,
        };

        // if not, check owner references which denotes the owner service of this endpoint
        match service_name_from_labels {
            Some(service_name) => service_name.to_string(),
            None => match endpoint_slice.owner_references().first() {
                Some(owner_reference) => owner_reference.name.clone(),
                None => "".to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        net::IpAddr,
        panic::{self, AssertUnwindSafe},
        str::FromStr,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    use crate::{
        events::network_event::{AggregateResults, FlowProperties, InetProtocol, NetworkStats},
        kubernetes::flow_metadata::FlowMetadata,
    };
    use k8s_openapi::{
        api::{
            core::v1::{ContainerPort, ObjectReference, PodSpec, PodStatus},
            discovery::v1::EndpointSlice,
        },
        apimachinery::pkg::apis::meta::v1::OwnerReference,
    };
    use kube::{api::ObjectMeta, core::ErrorResponse};

    use super::*;
    use super::{KubernetesMetadataCollector, PodInfo};

    static TEST_POD_PORT: i32 = 100;

    #[test]
    fn test_no_data() {
        assert!(true);
    }

    #[test]
    fn test_get_service_name_from_endpoint_slice() {
        let slice = EndpointSlice {
            metadata: kube::api::ObjectMeta {
                namespace: Some("test".to_string()),
                labels: Some(std::collections::BTreeMap::from([(
                    "kubernetes.io/service-name".to_string(),
                    "test-service".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        };
        let service_name =
            KubernetesMetadataCollector::get_service_name_from_endpoint_slice(&slice);
        assert_eq!(service_name, "test-service");

        // test with owner references
        let slice = EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some("test".to_string()),
                owner_references: Some(vec![OwnerReference {
                    name: "test-service-owner".to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            ..Default::default()
        };
        let service_name =
            KubernetesMetadataCollector::get_service_name_from_endpoint_slice(&slice);
        assert_eq!(service_name, "test-service-owner");
    }

    fn get_flow(agg_results: AggregateResults) -> FlowMetadata {
        agg_results.flow.kubernetes_metadata.unwrap()
    }

    #[test]
    fn test_setup_watchers_sanity() {
        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let mut collector = KubernetesMetadataCollector::new();
            collector.setup_watchers();
        }));

        assert!(
            result.is_ok(),
            "setup_watchers() must not panic under any case"
        );
    }

    fn create_pod_info(name: &str, ns: &str, srv: &str) -> PodInfo {
        PodInfo {
            name: name.to_string(),
            namespace: ns.to_string(),
            service_name: srv.to_string(),
        }
    }

    fn create_agg_results(
        local_port: u16,
        remote_port: u16,
        local_ip: Option<IpAddr>,
        remote_ip: Option<IpAddr>,
    ) -> AggregateResults {
        AggregateResults {
            flow: FlowProperties {
                local_address: local_ip.unwrap_or("255.255.255.255".parse::<IpAddr>().unwrap()),
                remote_address: remote_ip.unwrap_or("255.255.255.254".parse::<IpAddr>().unwrap()),
                local_port,
                remote_port,
                kubernetes_metadata: None,
                protocol: InetProtocol::TCP,
            },
            stats: NetworkStats {
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_enrich_flows() {
        let pod_local = IpAddr::from_str("10.0.0.1").unwrap();
        let pod_remote = IpAddr::from_str("10.0.0.2").unwrap();
        let pod_local_mapped = IpAddr::from_str("::ffff:10.0.0.1").unwrap();
        let pod_remote_mapped = IpAddr::from_str("::ffff:10.0.0.2").unwrap();
        let pod_info_local = create_pod_info("pod-1", "ns-1", "service-1");
        let pod_info_remote = create_pod_info("pod-2", "ns-2", "service-2");
        let pod_info: HashMap<IpAddr, HashMap<i32, PodInfo>> = HashMap::from([
            (pod_local, HashMap::from([(6666, pod_info_local.clone())])),
            (pod_remote, HashMap::from([(6666, pod_info_remote.clone())])),
        ]);
        let mut flows: Vec<AggregateResults> = vec![
            create_agg_results(0, 6666, Some(pod_local), Some(pod_remote)),
            create_agg_results(0, 6666, None, Some(pod_remote)),
            create_agg_results(0, 6666, Some(pod_local_mapped), None),
            create_agg_results(0, 6666, None, Some(pod_remote_mapped)),
        ];

        let mut collector = KubernetesMetadataCollector::new();
        collector.pod_info_arc = Arc::new(Mutex::new(pod_info));
        assert_eq!(collector.enrich_flows(&mut flows), 4);
        let local_flow = get_flow(flows[0].clone()).local.unwrap();
        let remote_flow = get_flow(flows[0].clone()).remote.unwrap();
        assert_eq!(local_flow, pod_info_local);
        assert_eq!(remote_flow, pod_info_remote);

        let local_flow_mapped = get_flow(flows[2].clone()).local.unwrap();
        let remote_flow_mapped = get_flow(flows[3].clone()).remote.unwrap();
        assert_eq!(local_flow_mapped, pod_info_local);
        assert_eq!(remote_flow_mapped, pod_info_remote);
    }

    /**
     * Do following verifications:
     * 1. For a client flow, the remote pod is ALWAYS resolved if we have its pod info.
     * 2. For a server flow, the local pod is ALWAYS resolved if we have its pod info.
     * 3. For a client flow, if the local ip IP has a single port registered, local pod can be resolved.
     * 4. For a server flow, if the remote ip IP has a single port registered, remote pod can be resolved.
     * 5. For a client flow, if the local ip IP has multiple ports registered, we cant resolve the local pod
     * 6. For a server flow, if the remote ip IP has multiple ports registered, we cant resolve the remote pod
     */
    #[test]
    fn test_enrich_flows_multi_scenario() {
        let mut collector = KubernetesMetadataCollector::new();
        // Scenario 1: Verify, For a client flow, the remote pod is ALWAYS resolved if we have its pod info.
        let pod_local = IpAddr::from_str("10.0.0.1").unwrap();
        let pod_remote = IpAddr::from_str("10.0.0.2").unwrap();
        let pod_info_local = create_pod_info("p-1", "ns-1", "s-1");
        let pod_info_remote = create_pod_info("p-2", "ns-2", "s-2");
        let polluter_pod_info = create_pod_info("x", "x", "x");
        let pod_info: HashMap<IpAddr, HashMap<i32, PodInfo>> = HashMap::from([(
            pod_remote,
            HashMap::from([
                // register multiple ports under this IP.
                // we should still be able to resolve the 6666 one correctly
                (6666, pod_info_remote.clone()),
                (5555, polluter_pod_info.clone()),
                (4444, polluter_pod_info.clone()),
            ]),
        )]);
        // create a single client flow towards remote pod port 6666
        let mut flows: Vec<AggregateResults> = vec![create_agg_results(
            0,
            6666,
            Some(pod_local),
            Some(pod_remote),
        )];
        collector.pod_info_arc = Arc::new(Mutex::new(pod_info));
        assert_eq!(collector.enrich_flows(&mut flows), 1);
        assert_eq!(get_flow(flows[0].clone()).remote.unwrap(), pod_info_remote);

        // Scenario 2: Verify, For a server flow, the local pod is ALWAYS resolved if we have its pod info.
        let pod_info: HashMap<IpAddr, HashMap<i32, PodInfo>> = HashMap::from([(
            pod_local,
            HashMap::from([
                // register multiple ports under this IP.
                // we should still be able to resolve the 1111 one correctly
                (1111, pod_info_local.clone()),
                (2222, polluter_pod_info.clone()),
                (3333, polluter_pod_info.clone()),
            ]),
        )]);
        // create a single client flow towards our (local) pod port 1111
        let mut flows: Vec<AggregateResults> =
            vec![create_agg_results(1111, 0, Some(pod_local), None)];
        collector.pod_info_arc = Arc::new(Mutex::new(pod_info));
        assert_eq!(collector.enrich_flows(&mut flows), 1);
        assert_eq!(get_flow(flows[0].clone()).local.unwrap(), pod_info_local);

        // Scenario 3: For a client flow, if the local ip IP has a single port registered, local pod can be resolved.
        let pod_info: HashMap<IpAddr, HashMap<i32, PodInfo>> = HashMap::from([
            (
                pod_local,
                HashMap::from([
                    // register a single port under this IP.
                    // we should still be able to resolve this one correctly in a client flow
                    // because its the only one that could originate the flow
                    (1111, pod_info_local.clone()),
                ]),
            ),
            (
                pod_remote,
                HashMap::from([
                    // register multiple ports under this IP.
                    // we should still be able to resolve the 6666 one correctly
                    (6666, pod_info_remote.clone()),
                    (5555, polluter_pod_info.clone()),
                    (4444, polluter_pod_info.clone()),
                ]),
            ),
        ]);
        // create a single client flow towards remote pod port 6666
        let mut flows: Vec<AggregateResults> = vec![create_agg_results(
            0,
            6666,
            Some(pod_local),
            Some(pod_remote),
        )];
        collector.pod_info_arc = Arc::new(Mutex::new(pod_info));
        assert_eq!(collector.enrich_flows(&mut flows), 1);
        assert_eq!(get_flow(flows[0].clone()).local.unwrap(), pod_info_local);
        assert_eq!(get_flow(flows[0].clone()).remote.unwrap(), pod_info_remote);

        // Scenario 4: For a server flow, if the remote ip IP has a single port registered, remote pod can be resolved.
        let pod_info: HashMap<IpAddr, HashMap<i32, PodInfo>> = HashMap::from([
            (
                pod_local,
                HashMap::from([
                    // register multiple ports under this IP.
                    // we should still be able to resolve the 1111 one correctly
                    (1111, pod_info_local.clone()),
                    (2222, polluter_pod_info.clone()),
                    (3333, polluter_pod_info.clone()),
                ]),
            ),
            (
                pod_remote,
                HashMap::from([
                    // register a single port under this IP.
                    // we should still be able to resolve this one correctly in a server flow
                    // because its the only one that could be on the remote end of flow
                    (6666, pod_info_remote.clone()),
                ]),
            ),
        ]);
        let mut flows: Vec<AggregateResults> = vec![create_agg_results(
            1111,
            0,
            Some(pod_local),
            Some(pod_remote),
        )];
        collector.pod_info_arc = Arc::new(Mutex::new(pod_info));
        assert_eq!(collector.enrich_flows(&mut flows), 1);
        assert_eq!(get_flow(flows[0].clone()).local.unwrap(), pod_info_local);
        assert_eq!(get_flow(flows[0].clone()).remote.unwrap(), pod_info_remote);

        // Scenario 5: For a client flow, if the local ip IP has multiple ports registered, we cant resolve the local pod
        let pod_info: HashMap<IpAddr, HashMap<i32, PodInfo>> = HashMap::from([
            (
                pod_local,
                HashMap::from([
                    // register multiple ports under this IP.
                    // Since this is a client flow,
                    // there is no way for us to know whether 1111 initiated the connection or 2222 or 3333 etc.
                    // So we shouldnt resolve local pod under this case
                    (1111, pod_info_local.clone()),
                    (2222, polluter_pod_info.clone()),
                    (3333, polluter_pod_info.clone()),
                ]),
            ),
            (
                pod_remote,
                HashMap::from([
                    // register multiple ports under this IP.
                    // we should still be able to resolve the 6666 one correctly
                    (6666, pod_info_remote.clone()),
                    (5555, polluter_pod_info.clone()),
                    (4444, polluter_pod_info.clone()),
                ]),
            ),
        ]);
        collector.pod_info_arc = Arc::new(Mutex::new(pod_info));
        let mut flows: Vec<AggregateResults> = vec![create_agg_results(
            0,
            6666,
            Some(pod_local),
            Some(pod_remote),
        )];
        assert_eq!(collector.enrich_flows(&mut flows), 1);
        assert_eq!(get_flow(flows[0].clone()).local, None);
        assert_eq!(get_flow(flows[0].clone()).remote.unwrap(), pod_info_remote);

        // Scenario 6: For a server flow, if the remote ip IP has multiple ports registered, we cant resolve the remote pod
        let mut flows: Vec<AggregateResults> = vec![create_agg_results(
            1111,
            0,
            Some(pod_local),
            Some(pod_remote),
        )];
        assert_eq!(collector.enrich_flows(&mut flows), 1);
        assert_eq!(get_flow(flows[0].clone()).local.unwrap(), pod_info_local);
        assert_eq!(get_flow(flows[0].clone()).remote, None);
    }

    fn adress_to_podname(address: IpAddr) -> String {
        format!("{}/{}", "pod-1", address.to_string())
    }

    fn create_test_pod(address: IpAddr) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(adress_to_podname(address)),
                namespace: Some("default".to_string()),
                ..Default::default()
            },
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "test-container".to_string(),
                    ports: Some(vec![
                        ContainerPort {
                            container_port: TEST_POD_PORT,
                            name: Some("test-port".to_string()),
                            protocol: Some("TCP".to_string()),
                            ..Default::default()
                        },
                        ContainerPort {
                            container_port: TEST_POD_PORT + 1,
                            name: Some("test-port".to_string()),
                            protocol: Some("UDP".to_string()), // to verify that this is ignored
                            ..Default::default()
                        },
                    ]),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: Some(PodStatus {
                pod_ip: Some(address.to_string()),
                ..Default::default()
            }),
        }
    }

    fn create_test_slice(address: IpAddr) -> EndpointSlice {
        let mut endpoints = vec![];
        endpoints.push(k8s_openapi::api::discovery::v1::Endpoint {
            addresses: vec![address.to_string()],
            conditions: None,
            hostname: None,
            target_ref: Some(ObjectReference {
                api_version: Some("v1".to_string()),
                kind: Some("pod".to_string()),
                name: Some(adress_to_podname(address)),
                namespace: Some("default".to_string()),
                ..Default::default()
            }),
            node_name: None,
            zone: None,
            hints: None,
            deprecated_topology: None,
        });

        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some("default".to_string()),
                owner_references: Some(vec![OwnerReference {
                    name: "test-service".to_string(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            address_type: "IPv4".to_string(),
            endpoints,
            ports: Some(vec![
                k8s_openapi::api::discovery::v1::EndpointPort {
                    name: Some("test-port".to_string()),
                    port: Some(TEST_POD_PORT),
                    protocol: Some("TCP".to_string()),
                    app_protocol: None,
                },
                k8s_openapi::api::discovery::v1::EndpointPort {
                    name: Some("test-port2".to_string()),
                    port: Some(TEST_POD_PORT),
                    protocol: Some("UDP".to_string()), // UDP should be disregarded, for now at least
                    app_protocol: None,
                },
                k8s_openapi::api::discovery::v1::EndpointPort {
                    name: Some("test-port2".to_string()),
                    port: Some(TEST_POD_PORT + 1),
                    protocol: Some("UDP".to_string()), // UDP should be disregarded, for now at least
                    app_protocol: None,
                },
            ]),
        }
    }

    #[test]
    fn test_handle_endpoint_slice_event() {
        let collector = KubernetesMetadataCollector::new();
        let adress = IpAddr::from_str("192.168.1.1").unwrap();
        let slice = create_test_slice(adress);

        // add the endpoint
        let event = Ok(Event::Apply(slice.clone()));
        KubernetesMetadataCollector::handle_endpoint_slice_event(
            event,
            collector.pod_info_arc.clone(),
        );

        // keep these scoped so that they unlock after using, otherwise the next "handle_endpoint_slice will wait for lock forever"
        {
            let pod_info = collector.pod_info_arc.lock().unwrap();
            assert_eq!(
                pod_info.get(&adress).unwrap().get(&TEST_POD_PORT),
                Some(&PodInfo {
                    name: adress_to_podname(adress),
                    namespace: "default".to_string(),
                    service_name: "test-service".to_string(),
                })
            );
        }

        // now delete it
        let event = Ok(Event::Delete(slice));
        KubernetesMetadataCollector::handle_endpoint_slice_event(
            event,
            collector.pod_info_arc.clone(),
        );

        {
            let pod_info = collector.pod_info_arc.lock().unwrap();
            assert!(!pod_info.contains_key(&adress));
        }

        // and do a final test to see if it is still empty after a no-op event
        KubernetesMetadataCollector::handle_endpoint_slice_event(
            Err(watcher::Error::NoResourceVersion),
            collector.pod_info_arc.clone(),
        );

        // Verify that the function returns early and doesn't modify the maps
        {
            let pod_info = collector.pod_info_arc.lock().unwrap();
            assert!(pod_info.is_empty());
        }
    }

    #[test]
    fn test_handle_pod_event() {
        let collector = KubernetesMetadataCollector::new();
        let adress = IpAddr::from_str("192.168.1.1").unwrap();
        let pod = create_test_pod(adress);

        // add the endpoint
        let event = Ok(Event::Apply(pod.clone()));
        KubernetesMetadataCollector::handle_pod_event(event, collector.pod_info_arc.clone());
        let pod_info = collector.pod_info_arc.lock().unwrap();
        assert!(!pod_info.is_empty());
        assert!(pod_info.iter().next().unwrap().1.len() == 1); // should only contain 1 port, no UDP
    }

    fn clone_resource_event<K>(event: &Result<Event<K>, Error>) -> Result<Event<K>, Error>
    where
        K: Resource + Clone + DeserializeOwned + Debug + Send + 'static + Metadata<Ty = ObjectMeta>,
    {
        match event {
            Ok(Event::Apply(pod)) => Ok(Event::Apply(pod.clone())),
            Ok(Event::Delete(pod)) => Ok(Event::Delete(pod.clone())),
            Ok(Event::InitApply(pod)) => Ok(Event::InitApply(pod.clone())),
            Ok(Event::Init) => Ok(Event::Init),
            Ok(Event::InitDone) => Ok(Event::InitDone),
            Err(_) => Err(watcher::Error::WatchError(ErrorResponse {
                code: 404,
                message: "1".to_string(),
                reason: "2".to_string(),
                status: "3".to_string(),
            })),
        }
    }

    #[test]
    fn test_both_watchers_deadlock_free() {
        let collector = KubernetesMetadataCollector::new();
        let adress = IpAddr::from_str("192.168.1.1").unwrap();
        let adress2 = IpAddr::from_str("192.168.1.2").unwrap();
        let pod = create_test_pod(adress);
        let pod2 = create_test_pod(adress2);
        let slice = create_test_slice(adress);
        let slice2 = create_test_slice(adress2);

        let duration = Duration::from_millis(400);
        let start = Instant::now();
        let is_pod_watcher_finished = Arc::new(AtomicBool::new(false));
        let is_pod_watcher_finished_clone = is_pod_watcher_finished.clone();

        // start pod watcher and run events in a loop rapidly
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let pod_event_vector = vec![
            Ok(Event::Apply(pod.clone())),
            Ok(Event::Delete(pod.clone())),
            Ok(Event::Delete(pod2.clone())),
            Ok(Event::InitApply(pod2.clone())),
            Err(watcher::Error::WatchError(ErrorResponse {
                code: 404,
                message: "1".to_string(),
                reason: "2".to_string(),
                status: "3".to_string(),
            })),
            Ok(Event::Delete(pod2.clone())),
            Ok(Event::InitApply(pod.clone())),
            Ok(Event::Apply(pod2.clone())),
            Ok(Event::Init),
            Err(watcher::Error::NoResourceVersion),
        ];
        let w1_pod_info_arc = collector.pod_info_arc.clone();
        let pod_handle = runtime.spawn(async move {
            while start.elapsed() < duration {
                for pod_event in &pod_event_vector {
                    KubernetesMetadataCollector::handle_pod_event(
                        clone_resource_event(pod_event),
                        w1_pod_info_arc.clone(),
                    );
                }
            }
            is_pod_watcher_finished.store(true, Ordering::SeqCst); // so that we can make sure slice ran after this
        });

        // start endpoint slice watcher and run events in a loop rapidly
        let slice_event_vector = vec![
            Ok(Event::Apply(slice.clone())),
            Ok(Event::Delete(slice.clone())),
            Ok(Event::Delete(slice2.clone())),
            Ok(Event::InitApply(slice2.clone())),
            Err(watcher::Error::WatchError(ErrorResponse {
                code: 404,
                message: "1".to_string(),
                reason: "2".to_string(),
                status: "3".to_string(),
            })),
            Ok(Event::Delete(slice2.clone())),
            Ok(Event::InitApply(slice.clone())),
            Ok(Event::Apply(slice2.clone())),
            Ok(Event::Init),
            Err(watcher::Error::NoResourceVersion),
        ];
        let w2_pod_info_arc = collector.pod_info_arc.clone();
        let slice_handle = runtime.spawn(async move {
            // make sure slices run one last time after pods watcher, otherwise pods watcher can remove & reinsert
            // port entries for TEST_POD_PORT, depending on order of execution. Which would remove namespace & service_name fields from pod_info
            loop {
                let last_run = is_pod_watcher_finished_clone.load(Ordering::SeqCst);
                for slice_event in &slice_event_vector {
                    KubernetesMetadataCollector::handle_endpoint_slice_event(
                        clone_resource_event(slice_event),
                        w2_pod_info_arc.clone(),
                    );
                }
                if last_run {
                    break;
                }
            }
        });

        loop {
            if pod_handle.is_finished() && slice_handle.is_finished() {
                break;
            }
        }
        // now we are sure both concluded. We can check what data remains.
        // we apply items last, so we must verify that they exist
        let pod_info = collector.pod_info_arc.lock().unwrap();
        assert_eq!(pod_info.len(), 2);
        assert_eq!(
            pod_info.get(&adress).unwrap().get(&TEST_POD_PORT),
            Some(&PodInfo {
                name: adress_to_podname(adress),
                namespace: "default".to_string(),
                service_name: "test-service".to_string(),
            })
        );
        assert_eq!(
            pod_info.get(&adress2).unwrap().get(&TEST_POD_PORT),
            Some(&PodInfo {
                name: adress_to_podname(adress2),
                namespace: "default".to_string(),
                service_name: "test-service".to_string(),
            })
        );
    }
}
