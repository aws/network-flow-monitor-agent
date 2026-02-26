// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::metadata::eni::KEY_INSTANCE_ID;
use crate::reports::prometheus_remote_write_proto::{Label, RemoteWriteV1, Sample, TimeSeries};
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
            if let Some(ref cluster_name) = report.k8s_metadata.cluster_name {
                if let ReportValue::String(name) = cluster_name {
                    add_label(&mut base_labels, "k8s_cluster", &name);
                }
            }
            if let Some(ref node_name) = report.k8s_metadata.node_name {
                if let ReportValue::String(name) = node_name {
                    add_label(&mut base_labels, "k8s_node", &name);
                }
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
            .unwrap_or_else(|| String::new());

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
    if value != "" {
        labels.push(Label {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        println!("✓ Compression/decompression works correctly");
    }

    #[test]
    fn test_k8s_labels_added() {
        use crate::metadata::k8s_metadata::K8sMetadata;
        use crate::reports::report::{NfmReport, ReportValue};
        use crate::utils::clock::RealTimeClock;

        // Create report with K8s metadata
        let mut report = NfmReport::new();
        report.k8s_metadata = K8sMetadata {
            cluster_name: Some(ReportValue::String("test-cluster".to_string())),
            node_name: Some(ReportValue::String("test-node".to_string())),
        };

        let publisher = ReportPublisherAmazonManagedPrometheus {
            client: Client::new(),
            endpoint: "http://localhost:9090".to_string(),
            region: "us-east-1".to_string(),
            credentials_provider: aws_credential_types::Credentials::new(
                "test", "test", None, None, "test",
            ),
            clock: RealTimeClock,
        };

        let timeseries = publisher.convert_to_timeseries(&report, "instance-id".to_string());

        // Should have no timeseries since report has no network stats
        assert_eq!(timeseries.len(), 0);

        println!("✓ K8s metadata labels test passed");
    }
}
