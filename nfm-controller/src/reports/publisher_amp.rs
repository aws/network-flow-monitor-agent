// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::metadata::eni::KEY_INSTANCE_ID;
use crate::reports::publisher_amp_remote_write_proto::{Label, RemoteWriteV1, Sample, TimeSeries};
use crate::reports::report::{NfmReport, ReportValue};
use crate::utils::{timespec_to_nsec, Clock};
use crate::ReportPublisher;
use aws_credential_types::provider::ProvideCredentials;
use log::{error, info, warn};
use prost::Message;
use reqwest::blocking::Client;
use reqwest::Proxy;
use tokio::time::Duration;

const APS_SERVICE: &str = "aps";

/// Publisher for Amazon Managed Prometheus service.
pub struct ReportPublisherAmazonManagedPrometheus<P, C>
where
    P: ProvideCredentials,
    C: Clock,
{
    client: Client,
    endpoint: String,
    region: String,
    credentials_provider: P,
    clock: C,
}

impl<P, C> ReportPublisherAmazonManagedPrometheus<P, C>
where
    P: ProvideCredentials,
    C: Clock,
{
    pub fn new(
        endpoint: String,
        region: String,
        credentials_provider: P,
        clock: C,
        proxy: String,
    ) -> Self {
        let mut builder = Client::builder().use_rustls_tls();

        if !proxy.is_empty() {
            let proxy_instance = Proxy::all(&proxy).expect("Invalid proxy URL provided");
            builder = builder.proxy(proxy_instance);
        }

        ReportPublisherAmazonManagedPrometheus {
            client: builder.build().unwrap(),
            endpoint,
            region,
            credentials_provider,
            clock,
        }
    }

    fn convert_to_timeseries(&self, report: &NfmReport, instance_id: String) -> Vec<TimeSeries> {
        let timestamp_ms = (timespec_to_nsec(self.clock.now()) / 1_000_000) as i64;
        let mut timeseries = Vec::new();

        // Convert network stats to Prometheus metrics
        for flow in &report.network_stats {
            let mut base_labels = vec![
                Label {
                    name: "protocol".to_string(),
                    value: format!("{:?}", flow.flow.protocol),
                },
                Label {
                    name: "local_address".to_string(),
                    value: flow.flow.local_address.to_string(),
                },
                Label {
                    name: "remote_address".to_string(),
                    value: flow.flow.remote_address.to_string(),
                },
                Label {
                    name: "local_port".to_string(),
                    value: flow.flow.local_port.to_string(),
                },
                Label {
                    name: "remote_port".to_string(),
                    value: flow.flow.remote_port.to_string(),
                },
            ];
            add_label(&mut base_labels, "instance_id", &instance_id);

            // Add Kubernetes metadata labels if available
            if let Some(ReportValue::String(ref cluster_name)) = report.k8s_metadata.cluster_name {
                add_label(&mut base_labels, "k8s_cluster", cluster_name);
            }
            if let Some(ReportValue::String(ref node_name)) = report.k8s_metadata.node_name {
                add_label(&mut base_labels, "k8s_node", node_name);
            }
            if let Some(ref pod_info) = flow.flow.kubernetes_metadata {
                // Local pod info
                if let Some(ref local_pod_info) = pod_info.local {
                    add_label(&mut base_labels, "local_pod", &local_pod_info.name);
                    add_label(
                        &mut base_labels,
                        "local_namespace",
                        &local_pod_info.namespace,
                    );
                    add_label(
                        &mut base_labels,
                        "local_service",
                        &local_pod_info.service_name,
                    );
                }

                // Remote pod info
                if let Some(ref remote_pod_info) = pod_info.remote {
                    add_label(&mut base_labels, "remote_pod", &remote_pod_info.name);
                    add_label(
                        &mut base_labels,
                        "remote_namespace",
                        &remote_pod_info.namespace,
                    );
                    add_label(
                        &mut base_labels,
                        "remote_service",
                        &remote_pod_info.service_name,
                    );
                }
            }

            // Add metrics for this flow
            let metrics = vec![
                ("nfm_bytes_received", flow.stats.bytes_received as f64),
                ("nfm_bytes_delivered", flow.stats.bytes_delivered as f64),
                ("nfm_segments_received", flow.stats.segments_received as f64),
                (
                    "nfm_segments_delivered",
                    flow.stats.segments_delivered as f64,
                ),
                ("nfm_retrans_syn", flow.stats.retrans_syn as f64),
                ("nfm_retrans_est", flow.stats.retrans_est as f64),
                ("nfm_rtos_syn", flow.stats.rtos_syn as f64),
                ("nfm_rtos_est", flow.stats.rtos_est as f64),
                (
                    "nfm_sockets_established",
                    flow.stats.sockets_established as f64,
                ),
                ("nfm_sockets_completed", flow.stats.sockets_completed as f64),
            ];

            for (metric_name, value) in metrics {
                let mut labels = base_labels.clone();
                labels.insert(
                    0,
                    Label {
                        name: "__name__".to_string(),
                        value: metric_name.to_string(),
                    },
                );

                timeseries.push(TimeSeries {
                    labels,
                    samples: vec![Sample {
                        value,
                        timestamp: timestamp_ms,
                    }],
                });
            }
        }

        timeseries
    }

    fn build_request_body(&self, report: &NfmReport) -> Vec<u8> {
        let instance_id = report
            .env_metadata
            .get(KEY_INSTANCE_ID)
            .and_then(|v| match v {
                ReportValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let timeseries = self.convert_to_timeseries(report, instance_id);
        let write_request = RemoteWriteV1 { timeseries };

        // Encode as protobuf
        let mut buf = Vec::new();
        write_request.encode(&mut buf).unwrap();

        // Snappy compress (block format)
        snap::raw::Encoder::new().compress_vec(&buf).unwrap()
    }
}

impl<P, C> ReportPublisher for ReportPublisherAmazonManagedPrometheus<P, C>
where
    P: ProvideCredentials,
    C: Clock,
{
    fn publish(&self, report: &NfmReport) -> bool {
        let timestamp_ns = timespec_to_nsec(self.clock.now());
        let request_body = self.build_request_body(report);

        // Build headers
        let datetime = chrono::DateTime::from_timestamp_nanos(timestamp_ns as i64);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-Amz-Date",
            datetime
                .format("%Y%m%dT%H%M%SZ")
                .to_string()
                .parse()
                .unwrap(),
        );

        // Extract host from endpoint URL
        let host = url::Url::parse(&self.endpoint)
            .map(|u| u.host_str().unwrap_or("").to_string())
            .unwrap_or_default();
        headers.insert("host", host.parse().unwrap());

        headers.insert("Content-Type", "application/x-protobuf".parse().unwrap());
        headers.insert("Content-Encoding", "snappy".parse().unwrap());
        headers.insert(
            "X-Prometheus-Remote-Write-Version",
            "0.1.0".parse().unwrap(),
        );

        // Get AWS credentials
        let rt = tokio::runtime::Runtime::new().unwrap();
        let credentials = match rt.block_on(self.credentials_provider.provide_credentials()) {
            Ok(credentials) => credentials,
            Err(e) => {
                error!("Error getting credentials: {e}");
                return false;
            }
        };

        if let Some(token) = credentials.session_token() {
            headers.insert("X-Amz-Security-Token", token.parse().unwrap());
        }

        // Sign with SigV4
        let aws_sign = aws_sign_v4::AwsSign::new(
            "POST",
            &self.endpoint,
            &datetime,
            &headers,
            &self.region,
            credentials.access_key_id(),
            credentials.secret_access_key(),
            APS_SERVICE,
            &request_body,
        );
        let signature = aws_sign.sign();
        headers.insert(reqwest::header::AUTHORIZATION, signature.parse().unwrap());

        // Send HTTP request
        let res = match self
            .client
            .post(&self.endpoint)
            .timeout(Duration::from_secs(20))
            .headers(headers)
            .body(request_body)
            .send()
        {
            Ok(res) => res,
            Err(e) => {
                error!("Error sending request: {e:?}");
                return false;
            }
        };

        // Check response
        let status = res.status().as_u16();
        info!(status = status; "Prometheus HTTP request complete");
        if status != 200 && status != 204 {
            warn!(body = res.text().unwrap_or("Invalid body".to_string()); "Request body");
            return false;
        }
        true
    }
}

fn add_label(labels: &mut Vec<Label>, name: &str, value: &str) {
    if !value.is_empty() {
        labels.push(Label {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::network_event::{AggregateResults, FlowProperties, NetworkStats};
    use crate::kubernetes::flow_metadata::FlowMetadata;
    use crate::kubernetes::kubernetes_metadata_collector::PodInfo;
    use crate::metadata::k8s_metadata::K8sMetadata;
    use crate::reports::report::{NfmReport, ReportValue};
    use crate::utils::clock::FakeClock;
    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_credential_types::Credentials;
    use nfm_common::network::SockContext;

    #[test]
    fn test_snappy_compression() {
        // Create a simple WriteRequest with one timeseries
        let write_request = RemoteWriteV1 {
            timeseries: vec![TimeSeries {
                labels: vec![
                    Label {
                        name: "__name__".to_string(),
                        value: "test_metric".to_string(),
                    },
                    Label {
                        name: "label1".to_string(),
                        value: "value1".to_string(),
                    },
                ],
                samples: vec![Sample {
                    value: 42.0,
                    timestamp: 1234567890000,
                }],
            }],
        };

        // Encode as protobuf
        let mut buf = Vec::new();
        write_request.encode(&mut buf).unwrap();
        println!("Protobuf size: {} bytes", buf.len());
        println!("Protobuf hex: {}", hex::encode(&buf[..buf.len().min(50)]));
        assert!(!buf.is_empty());

        // Test snappy compression
        let compressed = snap::raw::Encoder::new().compress_vec(&buf).unwrap();
        println!("Compressed size: {} bytes", compressed.len());
        println!(
            "Compressed hex: {}",
            hex::encode(&compressed[..compressed.len().min(50)])
        );
        assert!(!compressed.is_empty());

        // Verify we can decompress it
        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        assert_eq!(buf, decompressed);
    }

    #[test]
    fn test_new_without_proxy() {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock { now_us: 1000000 };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
                .to_string(),
            "us-east-1".to_string(),
            provider,
            clock,
            "".to_string(),
        );

        assert_eq!(
            publisher.endpoint,
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
        );
        assert_eq!(publisher.region, "us-east-1");
    }

    #[test]
    fn test_new_with_proxy() {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock { now_us: 1000000 };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
                .to_string(),
            "us-east-1".to_string(),
            provider,
            clock,
            "http://proxy.example.com:8080".to_string(),
        );

        assert_eq!(
            publisher.endpoint,
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
        );
        assert_eq!(publisher.region, "us-east-1");
    }

    #[test]
    fn test_convert_to_timeseries_empty_report() {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock {
            now_us: 1718716821050,
        };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
                .to_string(),
            "us-east-1".to_string(),
            provider,
            clock,
            "".to_string(),
        );

        let report = NfmReport::new();
        let timeseries =
            publisher.convert_to_timeseries(&report, "i-1234567890abcdef0".to_string());

        // Should have no timeseries since report has no network stats
        assert_eq!(timeseries.len(), 0);
    }

    #[test]
    fn test_convert_to_timeseries_with_flow() {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock {
            now_us: 1718716821050,
        };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
                .to_string(),
            "us-east-1".to_string(),
            provider,
            clock,
            "".to_string(),
        );

        let mut report = NfmReport::new();
        let context = SockContext {
            is_client: false,
            address_family: libc::AF_INET as u32,
            local_ipv4: 16909060,
            remote_ipv4: 84281096,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 443,
            remote_port: 28015,
            ..Default::default()
        };

        let stats = NetworkStats {
            bytes_received: 1000,
            bytes_delivered: 2000,
            segments_received: 10,
            segments_delivered: 20,
            retrans_syn: 1,
            retrans_est: 2,
            rtos_syn: 0,
            rtos_est: 1,
            sockets_established: 5,
            sockets_completed: 3,
            ..Default::default()
        };

        report.set_network_stats(vec![AggregateResults {
            flow: FlowProperties::try_from(&context).unwrap(),
            stats,
        }]);

        let timeseries =
            publisher.convert_to_timeseries(&report, "i-1234567890abcdef0".to_string());

        // Should have 10 metrics per flow
        assert_eq!(timeseries.len(), 10);

        // Verify metric names
        let metric_names: Vec<String> = timeseries
            .iter()
            .map(|ts| {
                ts.labels
                    .iter()
                    .find(|l| l.name == "__name__")
                    .unwrap()
                    .value
                    .clone()
            })
            .collect();

        assert!(metric_names.contains(&"nfm_bytes_received".to_string()));
        assert!(metric_names.contains(&"nfm_bytes_delivered".to_string()));
        assert!(metric_names.contains(&"nfm_segments_received".to_string()));
        assert!(metric_names.contains(&"nfm_segments_delivered".to_string()));
        assert!(metric_names.contains(&"nfm_retrans_syn".to_string()));
        assert!(metric_names.contains(&"nfm_retrans_est".to_string()));
        assert!(metric_names.contains(&"nfm_rtos_syn".to_string()));
        assert!(metric_names.contains(&"nfm_rtos_est".to_string()));
        assert!(metric_names.contains(&"nfm_sockets_established".to_string()));
        assert!(metric_names.contains(&"nfm_sockets_completed".to_string()));

        // Verify labels are present
        let first_ts = &timeseries[0];
        let label_names: Vec<String> = first_ts.labels.iter().map(|l| l.name.clone()).collect();
        assert!(label_names.contains(&"protocol".to_string()));
        assert!(label_names.contains(&"local_address".to_string()));
        assert!(label_names.contains(&"remote_address".to_string()));
        assert!(label_names.contains(&"local_port".to_string()));
        assert!(label_names.contains(&"remote_port".to_string()));
        assert!(label_names.contains(&"instance_id".to_string()));

        // Verify timestamp
        // FakeClock with now_us=1718716821050 microseconds converts to:
        // tv_sec=1718716, tv_nsec=821050000
        // timespec_to_nsec: 1718716 * 1e9 + 821050000 = 1718716821050000 ns
        // divide by 1e6 for ms: 1718716821050 ms
        assert!(first_ts.samples[0].timestamp > 0);
    }

    #[test]
    fn test_convert_to_timeseries_with_k8s_metadata() {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock {
            now_us: 1718716821050,
        };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
                .to_string(),
            "us-east-1".to_string(),
            provider,
            clock,
            "".to_string(),
        );

        let mut report = NfmReport::new();
        report.k8s_metadata = K8sMetadata {
            cluster_name: Some(ReportValue::String("test-cluster".to_string())),
            node_name: Some(ReportValue::String("test-node".to_string())),
        };

        let context = SockContext {
            is_client: false,
            address_family: libc::AF_INET as u32,
            local_ipv4: 16909060,
            remote_ipv4: 84281096,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 443,
            remote_port: 28015,
            ..Default::default()
        };

        let stats = NetworkStats {
            bytes_received: 1000,
            ..Default::default()
        };

        let mut flow = FlowProperties::try_from(&context).unwrap();
        flow.kubernetes_metadata = Some(FlowMetadata {
            local: Some(PodInfo {
                name: "nginx-pod".to_string(),
                namespace: "default".to_string(),
                service_name: "nginx-service".to_string(),
            }),
            remote: Some(PodInfo {
                name: "backend-pod".to_string(),
                namespace: "backend".to_string(),
                service_name: "backend-service".to_string(),
            }),
        });

        report.set_network_stats(vec![AggregateResults { flow, stats }]);

        let timeseries =
            publisher.convert_to_timeseries(&report, "i-1234567890abcdef0".to_string());

        assert_eq!(timeseries.len(), 10);

        // Verify K8s labels are present
        let first_ts = &timeseries[0];
        let label_names: Vec<String> = first_ts.labels.iter().map(|l| l.name.clone()).collect();
        assert!(label_names.contains(&"k8s_cluster".to_string()));
        assert!(label_names.contains(&"k8s_node".to_string()));
        assert!(label_names.contains(&"local_pod".to_string()));
        assert!(label_names.contains(&"local_namespace".to_string()));
        assert!(label_names.contains(&"local_service".to_string()));
        assert!(label_names.contains(&"remote_pod".to_string()));
        assert!(label_names.contains(&"remote_namespace".to_string()));
        assert!(label_names.contains(&"remote_service".to_string()));

        // Verify label values
        let k8s_cluster = first_ts
            .labels
            .iter()
            .find(|l| l.name == "k8s_cluster")
            .unwrap();
        assert_eq!(k8s_cluster.value, "test-cluster");

        let local_pod = first_ts
            .labels
            .iter()
            .find(|l| l.name == "local_pod")
            .unwrap();
        assert_eq!(local_pod.value, "nginx-pod");
    }

    #[test]
    fn test_build_request_body() {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock {
            now_us: 1718716821050,
        };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
                .to_string(),
            "us-east-1".to_string(),
            provider,
            clock,
            "".to_string(),
        );

        let mut report = NfmReport::new();
        report
            .env_metadata
            .insert("instance_id".into(), ReportValue::String("i-test".into()));

        let context = SockContext {
            is_client: false,
            address_family: libc::AF_INET as u32,
            local_ipv4: 16909060,
            remote_ipv4: 84281096,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 443,
            remote_port: 28015,
            ..Default::default()
        };

        let stats = NetworkStats {
            bytes_received: 1000,
            ..Default::default()
        };

        report.set_network_stats(vec![AggregateResults {
            flow: FlowProperties::try_from(&context).unwrap(),
            stats,
        }]);

        let body = publisher.build_request_body(&report);

        // Body should be compressed
        assert!(!body.is_empty());

        // Decompress and verify it's valid protobuf
        let decompressed = snap::raw::Decoder::new().decompress_vec(&body).unwrap();
        let decoded = RemoteWriteV1::decode(decompressed.as_slice()).unwrap();

        // Should have 10 timeseries (one per metric)
        assert_eq!(decoded.timeseries.len(), 10);
    }

    #[test]
    fn test_build_request_body_without_instance_id() {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock {
            now_us: 1718716821050,
        };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-123/api/v1/remote_write"
                .to_string(),
            "us-east-1".to_string(),
            provider,
            clock,
            "".to_string(),
        );

        let mut report = NfmReport::new();

        let context = SockContext {
            is_client: false,
            address_family: libc::AF_INET as u32,
            local_ipv4: 16909060,
            remote_ipv4: 84281096,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 443,
            remote_port: 28015,
            ..Default::default()
        };

        let stats = NetworkStats {
            bytes_received: 1000,
            ..Default::default()
        };

        report.set_network_stats(vec![AggregateResults {
            flow: FlowProperties::try_from(&context).unwrap(),
            stats,
        }]);

        let body = publisher.build_request_body(&report);

        // Should still work with empty instance_id
        assert!(!body.is_empty());

        let decompressed = snap::raw::Decoder::new().decompress_vec(&body).unwrap();
        let decoded = RemoteWriteV1::decode(decompressed.as_slice()).unwrap();
        assert_eq!(decoded.timeseries.len(), 10);
    }

    #[test]
    fn test_add_label_with_value() {
        let mut labels = vec![];
        add_label(&mut labels, "test_key", "test_value");

        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].name, "test_key");
        assert_eq!(labels[0].value, "test_value");
    }

    #[test]
    fn test_add_label_with_empty_value() {
        let mut labels = vec![];
        add_label(&mut labels, "test_key", "");

        // Should not add label with empty value
        assert_eq!(labels.len(), 0);
    }

    #[test]
    fn test_add_label_multiple() {
        let mut labels = vec![];
        add_label(&mut labels, "key1", "value1");
        add_label(&mut labels, "key2", "value2");
        add_label(&mut labels, "key3", "");

        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].name, "key1");
        assert_eq!(labels[1].name, "key2");
    }

    #[test]
    fn test_publish_with_k8s_metadata() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        struct MockApsService {
            listener: TcpListener,
        }

        impl MockApsService {
            async fn new(address: String) -> Option<Self> {
                match TcpListener::bind(address).await {
                    Ok(listener) => Some(MockApsService { listener }),
                    Err(_) => None,
                }
            }

            async fn respond_ok(&mut self) {
                let (mut stream, _) = self.listener.accept().await.unwrap();
                // Read the request (we don't need to parse it)
                let mut buffer = vec![0u8; 8192];
                let _ = stream.read(&mut buffer).await;
                // Send 200 OK response
                stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
            }
        }

        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut port = 9090;
        let mut port_attempts = 10;
        let mut mock_service = None;
        let mut address = String::new();

        while port_attempts > 0 {
            address = format!("127.0.0.1:{}", port);
            mock_service = rt.block_on(async { MockApsService::new(address.clone()).await });
            if mock_service.is_some() {
                break;
            }
            port_attempts -= 1;
            port += 1;
        }
        assert!(port_attempts > 0, "Failed to find an available port");

        let service_future = rt.spawn(async move { mock_service.unwrap().respond_ok().await });

        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);
        let clock = FakeClock {
            now_us: 1718716821050,
        };

        let publisher = ReportPublisherAmazonManagedPrometheus::new(
            format!("http://{}/api/v1/remote_write", address),
            "us-east-1".to_string(),
            provider,
            clock,
            "".to_string(),
        );

        let mut report = NfmReport::new();
        report
            .env_metadata
            .insert("instance_id".into(), ReportValue::String("i-test".into()));
        report.k8s_metadata = K8sMetadata {
            cluster_name: Some(ReportValue::String("test-cluster".to_string())),
            node_name: Some(ReportValue::String("test-node".to_string())),
        };

        let context = SockContext {
            is_client: false,
            address_family: libc::AF_INET as u32,
            local_ipv4: 16909060,
            remote_ipv4: 84281096,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 443,
            remote_port: 28015,
            ..Default::default()
        };

        let stats = NetworkStats {
            bytes_received: 1000,
            bytes_delivered: 2000,
            segments_received: 10,
            segments_delivered: 20,
            retrans_syn: 1,
            retrans_est: 2,
            ..Default::default()
        };

        let mut flow = FlowProperties::try_from(&context).unwrap();
        flow.kubernetes_metadata = Some(FlowMetadata {
            local: Some(PodInfo {
                name: "nginx-pod".to_string(),
                namespace: "default".to_string(),
                service_name: "nginx-service".to_string(),
            }),
            remote: Some(PodInfo {
                name: "backend-pod".to_string(),
                namespace: "backend".to_string(),
                service_name: "backend-service".to_string(),
            }),
        });

        report.set_network_stats(vec![AggregateResults { flow, stats }]);

        // Publish the report
        let result = publisher.publish(&report);
        assert!(result, "Publish should succeed with K8s metadata");

        // Wait for the mock server to respond
        rt.block_on(service_future).unwrap();
    }
}
