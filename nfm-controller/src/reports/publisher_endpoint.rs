// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::reports::report_otlp::NfmReportOTLP;
use crate::ReportPublisher;
use crate::{
    reports::report::NfmReport,
    utils::{timespec_to_nsec, Clock},
};
use aws_credential_types::provider::ProvideCredentials;
use clap::ValueEnum;
use log::{error, info, warn};
use reqwest::blocking::Client;
use serde::Serialize;
use std::fmt;
use std::io::prelude::Write;
use tokio::time::Duration;
use url::Url;

const NFM_SERVICE: &str = "networkflowmonitor";

#[derive(Clone, Copy, Debug, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ReportCompression {
    None,
    Gzip,
}

impl fmt::Display for ReportCompression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportCompression::None => write!(f, "none"),
            ReportCompression::Gzip => write!(f, "gzip"),
        }
    }
}

pub struct ReportPublisherOTLP<P, C>
where
    P: ProvideCredentials,
    C: Clock,
{
    client: Client,
    endpoint: String,
    region: String,
    credentials_provider: P,
    clock: C,
    compression: ReportCompression,
}

impl<P, C> ReportPublisherOTLP<P, C>
where
    P: ProvideCredentials,
    C: Clock,
{
    pub fn new(
        endpoint: String,
        region: String,
        credentials_provider: P,
        clock: C,
        compression: ReportCompression,
    ) -> Self {
        ReportPublisherOTLP {
            client: Client::builder().use_rustls_tls().build().unwrap(),
            endpoint,
            region,
            credentials_provider,
            clock,
            compression,
        }
    }

    fn build_headers(&self, datetime: chrono::DateTime<chrono::Utc>) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "X-Amz-Date",
            datetime
                .format("%Y%m%dT%H%M%SZ")
                .to_string()
                .parse()
                .unwrap(),
        );

        headers.insert("host", get_host(&self.endpoint).parse().unwrap());
        headers.insert("Content-Type", "application/x-protobuf".parse().unwrap());

        match self.compression {
            ReportCompression::None => {}
            ReportCompression::Gzip => {
                headers.insert("Content-Encoding", "gzip".parse().unwrap());
            }
        }

        headers
    }

    fn build_report_body(&self, report: &NfmReport) -> Vec<u8> {
        let timestamp_ns = timespec_to_nsec(self.clock.now());
        let otel_report = NfmReportOTLP::build(report, timestamp_ns).unwrap();

        match self.compression {
            ReportCompression::None => otel_report,
            ReportCompression::Gzip => {
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&otel_report).unwrap();
                encoder.finish().unwrap()
            }
        }
    }
}

impl<P, C> ReportPublisher for ReportPublisherOTLP<P, C>
where
    P: ProvideCredentials,
    C: Clock,
{
    fn publish(&self, report: &NfmReport) -> bool {
        let timestamp_ns = timespec_to_nsec(self.clock.now());
        let report_body = self.build_report_body(report);

        /* ---------- Sigv4 signature ----------------- */
        let datetime = chrono::DateTime::from_timestamp_nanos(timestamp_ns as i64);
        let mut headers = self.build_headers(datetime);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let credentials = match rt.block_on(self.credentials_provider.provide_credentials()) {
            Ok(credentials) => credentials,
            Err(e) => {
                error!("Error getting credentials: {}", e);
                return false;
            }
        };

        if let Some(token) = credentials.session_token() {
            headers.insert("X-Amz-Security-Token", token.parse().unwrap());
        }

        let aws_sign = aws_sign_v4::AwsSign::new(
            "POST",
            &self.endpoint,
            &datetime,
            &headers,
            &self.region,
            credentials.access_key_id(),
            credentials.secret_access_key(),
            NFM_SERVICE,
            &report_body,
        );
        let signature = aws_sign.sign();
        headers.insert(reqwest::header::AUTHORIZATION, signature.parse().unwrap());

        /* ------------ HTTP request --------------------- */
        let res = match self
            .client
            .post(&self.endpoint)
            .timeout(Duration::from_secs(20))
            .headers(headers.to_owned())
            .body(report_body)
            .send()
        {
            Ok(res) => res,
            Err(e) => {
                error!("Error sending request: {}", e);
                return false;
            }
        };

        /* --------- HTTP Response --------------- */
        let status = res.status().as_u16();
        info!(status = res.status().as_u16(); "HTTP request complete");
        if status != 200 {
            warn!(body = res.text().unwrap_or("Invalid body".to_string()); "Request body");
            return false;
        }
        true
    }
}

fn get_host(url: &str) -> String {
    match Url::parse(url) {
        Ok(url) => url.host().unwrap().to_string(),
        Err(e) => {
            error!("Error parsing url: {}", e);
            "".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::host_stats_provider::GroupedInterfaceStats;
    use crate::events::host_stats_provider::NetworkInterfaceStats;
    use crate::events::network_event::{AggregateResults, FlowProperties, NetworkStats};
    use crate::kubernetes::flow_metadata::FlowMetadata;
    use crate::kubernetes::kubernetes_metadata_collector::PodInfo;
    use crate::metadata::env_metadata_provider::EnvMetadata;
    use crate::metadata::k8s_metadata::K8sMetadata;
    use crate::metadata::service_metadata::ServiceMetadata;
    use crate::reports::report::{MetricHistogram, ReportValue};
    use crate::reports::report_otlp::NfmReportOTLP;
    use crate::reports::ProcessCounters;
    use crate::utils::FakeClock;
    use crate::HostStats;
    use crate::ProcessStats;
    use crate::UsageStats;
    use nfm_common::network::SockContext;
    use nfm_common::EventCounters;

    use aws_credential_types::provider::SharedCredentialsProvider;
    use aws_credential_types::Credentials;
    use libc::{AF_INET, AF_INET6};
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use prost::Message;
    use rand::rngs::ThreadRng;
    use rand::{Rng, RngCore};
    use std::collections::HashSet;
    use std::io::Read;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    struct MockService {
        listener: TcpListener,
    }

    impl MockService {
        fn new(address: String) -> Option<Self> {
            match futures::executor::block_on(TcpListener::bind(address)) {
                Ok(listener) => Some(MockService { listener }),
                Err(e) => {
                    error!("Error binding to address: {}", e);
                    None
                }
            }
        }

        // This method listen for a HTTP request and return a Vec<u8> per line.
        async fn listen_one(&mut self) -> Vec<Vec<u8>> {
            let mut request = self.listener.accept().await.unwrap();
            let mut buf_reader = BufReader::new(&mut request.0);
            let mut http_request = vec![];

            let buffer = buf_reader.fill_buf().await.unwrap();
            let mut current_line = vec![];
            let mut body_started = false;

            for char in buffer {
                if body_started {
                    current_line.push(*char);
                    continue;
                }

                if *char == b'\n' {
                    // remove the \r
                    current_line.remove(current_line.len() - 1);
                    if current_line.is_empty() {
                        body_started = true;
                    };

                    http_request.push(current_line);
                    current_line = vec![];
                    continue;
                }
                current_line.push(*char);
            }
            http_request.push(current_line);

            request
                .0
                .write_all(b"HTTP/1.1 200 OK\r\n\r\n")
                .await
                .unwrap();

            http_request
        }
    }

    #[test]
    fn test_request() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut address = String::new();
        let mut port = 8181;
        let mut port_attempts = 5;
        let mut mock_service = None;
        while port_attempts > 0 {
            address = format!("127.0.0.1:{}", port).to_string();
            mock_service = rt.block_on(async { MockService::new(address.to_string()) });
            if mock_service.is_some() {
                break;
            }
            port_attempts -= 1;
            port += 1;
        }
        assert!(port_attempts > 0, "Failed to find an available port");
        let service_future = rt.spawn(async move { mock_service.unwrap().listen_one().await });

        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);

        let mock_clock = FakeClock {
            now_us: 1718716821050,
        };

        let publisher = ReportPublisherOTLP::new(
            format!("http://{}", address),
            "us-west-1".to_string(),
            provider,
            mock_clock.clone(),
            ReportCompression::None,
        );
        let mut report = NfmReport::new();

        let context = SockContext {
            is_client: false,
            address_family: AF_INET as u32,
            local_ipv4: 16909060,
            remote_ipv4: 84281096,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 443,
            remote_port: 28015,
            ..Default::default()
        };
        let stats = NetworkStats::default();

        report.set_network_stats(vec![AggregateResults {
            flow: FlowProperties::try_from(&context).unwrap(),
            stats,
        }]);

        let timestamp_ns = timespec_to_nsec(mock_clock.now());
        let expected_body = NfmReportOTLP::build(&report, timestamp_ns).unwrap();

        publisher.publish(&report);
        let http_request_res = rt.block_on(service_future);

        let mut http_request = http_request_res.unwrap();
        let actual_body = http_request.pop().unwrap();

        assert_eq!(actual_body.len(), expected_body.len());
        assert_eq!(
            ExportMetricsServiceRequest::decode(actual_body.as_slice()).unwrap(),
            ExportMetricsServiceRequest::decode(expected_body.as_slice()).unwrap(),
        );

        // Test related to the HTTP headers.
        let mut headers_set = HashSet::<String>::new();
        for line in http_request
            .into_iter()
            .map(|vec| String::from_utf8(vec).unwrap())
        {
            headers_set.insert(line);
        }

        assert!(headers_set.contains("POST / HTTP/1.1"));
        assert!(headers_set.contains("host: 127.0.0.1"));
        assert!(headers_set.contains("content-type: application/x-protobuf"));
        assert!(headers_set.contains("x-amz-security-token: TOKEN"));

        check_header_exists("authorization", &headers_set);
    }

    fn check_header_exists(header: &str, headers: &HashSet<String>) {
        let mut found = false;
        for element in headers {
            if element.contains(header) {
                found = true;
                break;
            }
        }
        assert!(found, "header '{}' not found", header);
    }

    #[test]
    fn test_get_host() {
        assert_eq!(get_host("http://a.com/"), "a.com");
        assert_eq!(get_host("http://a.b.com/"), "a.b.com");
        assert_eq!(get_host("http://a.b.com/test"), "a.b.com");
        assert_eq!(get_host("http://a.b.com:123/"), "a.b.com");
        assert_eq!(get_host("http://a.b.com:123/test"), "a.b.com");
        assert_eq!(get_host("non host"), "");
    }

    #[test]
    fn test_compression_ec2_report_ipv4() {
        let (num_flows, include_k8s) = (500, false);
        run_compression_test(num_flows, AF_INET, include_k8s);
    }

    #[test]
    fn test_compression_k8s_report_ipv4() {
        let (num_flows, include_k8s) = (500, true);
        run_compression_test(num_flows, AF_INET, include_k8s);
    }

    #[test]
    fn test_compression_ec2_report_ipv6() {
        let (num_flows, include_k8s) = (500, false);
        run_compression_test(num_flows, AF_INET6, include_k8s);
    }

    #[test]
    fn test_compression_k8s_report_ipv6() {
        let (num_flows, include_k8s) = (500, true);
        run_compression_test(num_flows, AF_INET6, include_k8s);
    }

    fn run_compression_test(num_flows: usize, address_family: i32, include_k8s: bool) {
        let publisher_with_compression = build_publisher(ReportCompression::Gzip);
        let publisher_no_compression = build_publisher(ReportCompression::None);

        let report = build_report(num_flows, address_family, include_k8s);

        let body_no_compression = publisher_no_compression.build_report_body(&report);
        let body_with_compression = publisher_with_compression.build_report_body(&report);

        // Aiming for a min 50% compression ratio.
        assert!((body_no_compression.len() / 2) > body_with_compression.len());
        assert_eq!(
            body_no_compression,
            decompress(ReportCompression::Gzip, &body_with_compression)
        );

        // Store files for external validation.
        let addr_type = match address_family {
            AF_INET => "ipv4",
            AF_INET6 => "ipv6",
            _ => panic!("Unknown addr family: {}", address_family),
        };
        let compute_type = if include_k8s { "k8s" } else { "ec2" };
        let json_string = serde_json::to_string(&report).unwrap();
        std::fs::create_dir_all("../target/report-samples/").unwrap();
        store_sample_file(
            format!(
                "report-{}-{}-{}-flows.json",
                num_flows, addr_type, compute_type
            ),
            json_string.as_bytes(),
        );
        store_sample_file(
            format!(
                "report-{}-{}-{}-flows.bin",
                num_flows, addr_type, compute_type
            ),
            &body_no_compression,
        );
        store_sample_file(
            format!(
                "report-{}-{}-{}-flows.bin.gz",
                num_flows, addr_type, compute_type
            ),
            &body_with_compression,
        );
    }

    fn decompress(compression: ReportCompression, data: &Vec<u8>) -> Vec<u8> {
        match compression {
            ReportCompression::None => data.clone(),
            ReportCompression::Gzip => {
                let mut decoder = flate2::read::GzDecoder::new(data.as_slice());
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed).unwrap();
                decompressed
            }
        }
    }

    fn store_sample_file(file_name: String, buf: &[u8]) {
        let mut file =
            std::fs::File::create(format!("../target/report-samples/{}", file_name)).unwrap();
        std::io::Write::write_all(&mut file, buf).unwrap();
    }

    fn build_publisher(
        compression: ReportCompression,
    ) -> ReportPublisherOTLP<SharedCredentialsProvider, FakeClock> {
        let creds = Credentials::new("AKID", "SECRET", Some("TOKEN".into()), None, "test");
        let provider = SharedCredentialsProvider::new(creds);

        let mock_clock = FakeClock {
            now_us: 1718716821050,
        };

        ReportPublisherOTLP::new(
            "http://localhost".to_string(),
            "us-west-1".to_string(),
            provider,
            mock_clock.clone(),
            compression,
        )
    }

    fn build_report(num_flows: usize, address_family: i32, include_k8s: bool) -> NfmReport {
        let mut report = NfmReport::new();
        let mut aggregated_results = vec![];

        let mut rng = rand::thread_rng();
        for flow_idx in 0..num_flows {
            let context = SockContext {
                is_client: true,
                address_family: address_family as u32,
                local_ipv4: rng.next_u32(),
                remote_ipv4: rng.next_u32(),
                local_ipv6: rand_ipv6(&mut rng),
                remote_ipv6: rand_ipv6(&mut rng),
                local_port: 0,
                remote_port: rand_service_port(&mut rng),
                ..Default::default()
            };

            let stats = build_random_network_stats(&mut rng);
            let mut flow = FlowProperties::try_from(&context).unwrap();
            if include_k8s {
                let service_name_mutator = flow_idx % 5;
                let pod_name_mutator = flow_idx % 20;
                flow.kubernetes_metadata = Some(FlowMetadata {
                    local: Some(PodInfo {
                        name: format!("nginx-deployment-59f8b7dc9-bzmfn-{}", pod_name_mutator),
                        namespace: "default".to_string(),
                        service_name: format!("nginx-service-{}", service_name_mutator),
                    }),
                    remote: Some(PodInfo {
                        name: format!("nginx-doppelganger-9997cd54b-rz55s-{}", pod_name_mutator),
                        namespace: "nfm".to_string(),
                        service_name: format!("nginx-doppelganger-{}", service_name_mutator),
                    }),
                });
            }

            aggregated_results.push(AggregateResults { flow, stats });
        }

        report.set_network_stats(aggregated_results);
        report.set_service_metadata(ServiceMetadata {
            name: ReportValue::String("network-flow-monitor".into()),
            version: ReportValue::String("1.0".into()),
            build_ts: ReportValue::String("the-build-ts".into()),
        });
        report.set_env_metadata(build_env_metadata());
        report.set_process_stats(build_process_stats());
        report.set_host_stats(build_host_stats());
        if include_k8s {
            report.set_k8s_metadata(build_k8s_metadata());
        }

        report
    }

    fn build_env_metadata() -> EnvMetadata {
        let mut env_metadata = EnvMetadata::default();
        env_metadata.insert(
            "instance_id".into(),
            ReportValue::String("instance-id".into()),
        );
        env_metadata.insert(
            "machine_id".into(),
            ReportValue::String("machine-id".into()),
        );
        env_metadata
    }

    fn build_process_stats() -> ProcessStats {
        let mut process_stats = ProcessStats::default();
        process_stats.counters.event_related = EventCounters {
            active_connect_events: 1,
            active_established_events: 2,
            passive_established_events: 3,
            state_change_events: 4,
            rtt_events: 5,
            retrans_events: 6,
            rto_events: 7,
            other_events: 8,
            socket_events: 9,
            sockets_invalid: 10,
            map_insertion_errors: 18,
            rtts_invalid: 15,
            set_flags_errors: 16,
            other_errors: 17,
        };
        process_stats.counters.process_related = ProcessCounters::default();

        process_stats.usage.push(UsageStats {
            cpu_util: 0.040,
            mem_used_kb: 512,
            mem_used_ratio: 0.06,
            sockets_tracked: 100,
        });

        process_stats
    }

    fn build_host_stats() -> HostStats {
        let iface1_stats = GroupedInterfaceStats {
            interface_id: "iface-id-1".to_string(),
            stats: NetworkInterfaceStats {
                bw_in_allowance_exceeded: 211,
                bw_out_allowance_exceeded: 223,
                conntrack_allowance_exceeded: 227,
                linklocal_allowance_exceeded: 229,
                pps_allowance_exceeded: 233,
                conntrack_allowance_available: 239,
            },
        };
        let mut iface2_stats = iface1_stats.clone();
        iface2_stats.interface_id = "iface-id-2".to_string();
        HostStats {
            interface_stats: vec![iface1_stats, iface2_stats],
        }
    }

    fn build_k8s_metadata() -> K8sMetadata {
        K8sMetadata {
            node_name: Some(ReportValue::String("k8s-node".into())),
            cluster_name: Some(ReportValue::String("k8s-cluster".into())),
        }
    }

    fn build_random_network_stats(rng: &mut ThreadRng) -> NetworkStats {
        NetworkStats {
            sockets_connecting: rand_cxn_count(rng),
            sockets_established: rand_cxn_count(rng),
            sockets_closing: rand_cxn_count(rng),
            sockets_closed: rand_cxn_count(rng),
            sockets_completed: rand_cxn_count(rng),
            severed_connect: rand_cxn_count(rng),
            severed_establish: rand_cxn_count(rng),
            connect_attempts: rand_cxn_count(rng),
            bytes_received: rand_byte_segment_count(rng),
            bytes_delivered: rand_byte_segment_count(rng),
            segments_received: rand_byte_segment_count(rng),
            segments_delivered: rand_byte_segment_count(rng),
            retrans_syn: rand_retrans_count(rng),
            retrans_est: rand_retrans_count(rng),
            retrans_close: rand_retrans_count(rng),
            rtos_syn: rand_retrans_count(rng),
            rtos_est: rand_retrans_count(rng),
            rtos_close: rand_retrans_count(rng),
            connect_us: MetricHistogram {
                count: rand_cxn_count(rng),
                min: rand_duration_us(rng),
                max: rand_duration_us(rng),
                sum: rand_duration_us(rng) as u64,
            },
            rtt_us: MetricHistogram {
                count: rand_cxn_count(rng),
                min: rand_duration_us(rng),
                max: rand_duration_us(rng),
                sum: rand_duration_us(rng) as u64,
            },
            rtt_smoothed_us: MetricHistogram {
                count: rand_cxn_count(rng),
                min: rand_duration_us(rng),
                max: rand_duration_us(rng),
                sum: rand_duration_us(rng) as u64,
            },
        }
    }

    // Generate random values that are somewhat within realistic ranges we'd see in the field.

    fn rand_ipv6(rng: &mut ThreadRng) -> [u8; 16] {
        let mut bytes = [0; 16];
        for i in 0..bytes.len() / 2 {
            bytes[i] = rng.gen();
        }

        bytes
    }

    fn rand_service_port(rng: &mut ThreadRng) -> u16 {
        rng.gen_range(1..100)
    }

    fn rand_cxn_count(rng: &mut ThreadRng) -> u32 {
        rng.gen_range(0..1000000)
    }

    fn rand_duration_us(rng: &mut ThreadRng) -> u32 {
        rng.gen_range(0..1000000)
    }

    fn rand_retrans_count(rng: &mut ThreadRng) -> u32 {
        rng.gen_range(0..1000000)
    }

    fn rand_byte_segment_count(rng: &mut ThreadRng) -> u64 {
        rng.gen_range(0..10_000_000_000)
    }
}
