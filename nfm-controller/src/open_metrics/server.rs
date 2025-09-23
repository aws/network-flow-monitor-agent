// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.
//!
//! This module provides a basic HTTP server that returns a fixed dummy metric
//! in Prometheus format on the /metrics endpoint.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use hyper::http::StatusCode;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use prometheus::{Encoder, Registry, TextEncoder};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::metadata::runtime_environment_metadata::ComputePlatform;
use crate::open_metrics::provider::{get_open_metric_providers, OpenMetricProvider};

/// Configuration options for the OpenMetricsServer
pub struct OpenMetricsServerConfig {
    /// Address to bind the server to
    pub addr: SocketAddr,
}

impl Default for OpenMetricsServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:80".parse().unwrap(),
        }
    }
}

impl OpenMetricsServerConfig {
    pub fn for_addr(addr: String, port: u16) -> Self {
        let socket_addr = format!("{}:{}", addr, port)
            .parse()
            .expect("Invalid server address");
        Self {
            addr: socket_addr,
            ..OpenMetricsServerConfig::default()
        }
    }
}

/// OpenMetricsServer provides a simple HTTP server for exposing Prometheus metrics.
pub struct OpenMetricsServer {
    /// Thread handle for the server
    handle: Option<std::thread::JoinHandle<()>>,
    /// Cancellation token to gracefully terminate the server
    cancel_token: CancellationToken,
    /// Server configuration
    config: OpenMetricsServerConfig,
}

impl Default for OpenMetricsServer {
    fn default() -> Self {
        Self {
            handle: None,
            cancel_token: CancellationToken::new(),
            config: OpenMetricsServerConfig::default(),
        }
    }
}

impl OpenMetricsServer {
    /// Create a new OpenMetricsServer with custom configuration
    pub fn with_config(config: OpenMetricsServerConfig) -> Self {
        Self {
            handle: None,
            cancel_token: CancellationToken::new(),
            config,
        }
    }

    /// Start the metrics server on the configured address
    pub fn start(&mut self) -> std::io::Result<()> {
        self.start_on_addr(self.config.addr)
    }

    /// Start the metrics server on the specified address
    pub fn start_on_addr(&mut self, bind_addr: SocketAddr) -> std::io::Result<()> {
        // Check if server is already running
        if self.handle.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Server is already running",
            ));
        }

        info!(
            open_metric = "starting",
            bind_addr = bind_addr.to_string();
            "Simple Prometheus metrics server starting"
        );

        let cancel_token = self.cancel_token.clone();

        let handle = thread::spawn(move || {
            // Create a simple runtime for the server
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Failed to create Tokio runtime");

            rt.block_on(async {
                if let Err(e) = run_server(bind_addr, cancel_token).await {
                    error!(error = e.to_string(); "Metrics server error");
                }
            });
        });

        self.handle = Some(handle);
        Ok(())
    }

    /// Stop the metrics server gracefully
    pub fn stop(&mut self) -> std::io::Result<()> {
        // Check if server is running
        let handle = match self.handle.take() {
            Some(h) => h,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Server is not running",
                ));
            }
        };

        // Signal the server to shut down
        info!(open_metric = "shutdown_initiated"; "Initiating graceful shutdown of metrics server");

        self.cancel_token.cancel();
        match handle.join() {
            Ok(_) => {
                info!(open_metric = "shutdown_complete"; "Metrics server shut down gracefully")
            }
            Err(_) => error!(
                open_metric = "shutdown_failure";
                "Metrics server shut down with errors due to thread panic"
            ),
        }

        // Reset the cancellation token for potential restart
        self.cancel_token = CancellationToken::new();

        Ok(())
    }

    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        match &self.handle {
            Some(handle) => !handle.is_finished(),
            None => false,
        }
    }
}

impl Drop for OpenMetricsServer {
    fn drop(&mut self) {
        // Attempt to stop the server if it's still running
        if self.is_running() {
            let _ = self.stop();
        }
    }
}

/// Handle HTTP request and return appropriate response
async fn handle_request(
    req: Request<hyper::body::Incoming>,
    registry: Arc<Registry>,
    providers: Arc<Vec<Box<dyn OpenMetricProvider>>>,
) -> Result<Response<String>, Infallible> {
    let path = req.uri().path();
    debug!(open_metric = "incoming_request", path = path; "Received request");

    let (status, content_type, body) = match path {
        "/metrics" => {
            debug!(endpoint = "metrics"; "Serving metrics endpoint");
            (
                StatusCode::OK,
                "text/plain",
                generate_metrics_text(registry, providers),
            )
        }
        "/" => {
            let body = "Network Flow Monitor Agent Metrics Server\n\nAvailable endpoints:\n- /metrics - Prometheus metrics\n";
            debug!(endpoint = "root"; "Serving root endpoint");
            (StatusCode::OK, "text/plain", body.to_string())
        }
        _ => {
            debug!(endpoint = path; "Not found");
            (StatusCode::NOT_FOUND, "text/plain", "Not Found".to_string())
        }
    };

    let response = Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .body(body)
        .unwrap();

    Ok(response)
}

fn generate_metrics_text(
    registry: Arc<Registry>,
    providers: Arc<Vec<Box<dyn OpenMetricProvider>>>,
) -> String {
    // Update the metrics
    for provider in providers.iter() {
        match provider.update_metrics() {
            Err(e) => {
                error!(open_metric = "metric_updated", error = e.to_string(); "Error updating metric")
            }
            Ok(()) => {}
        }
    }

    // Use the registry to generate metrics
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Run the HTTP server - will terminate when cancellation token is triggered
async fn run_server(bind_addr: SocketAddr, cancel_token: CancellationToken) -> std::io::Result<()> {
    // Bind to the address
    let listener = TcpListener::bind(bind_addr).await?;

    info!(
        open_metric = "server_starting",
        bind_addr = bind_addr.to_string();
        "Metrics server listening"
    );

    let mut registry = Arc::new(Registry::new());
    let providers = Arc::new(get_open_metric_providers(ComputePlatform::Ec2K8sEks));
    providers
        .iter()
        .for_each(|provider| provider.register_to(&mut Arc::get_mut(&mut registry).unwrap()));

    // Accept connections until cancellation token is triggered
    loop {
        // Use tokio::select to either accept a connection or check cancellation token
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        let start_time = Instant::now();

                        // Handle one request at a time
                        let io = TokioIo::new(stream);

                        // Clone the Arc to use in the closure
                        let registry_clone = registry.clone();
                        let providers_clone = providers.clone();

                        // Process the connection. Single connection at a time.
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service_fn(move |req| {
                                handle_request(req, registry_clone.clone(), providers_clone.clone())
                            }))
                            .await
                        {
                            warn!(
                                error = e.to_string(),
                                addr = bind_addr.to_string();
                                "Error handling HTTP request on metrics server"
                            );
                        }
                        info!(
                            open_metric = "request_timing",
                            duration_us = start_time.elapsed().as_micros();
                            "Request processed",
                        );
                    }
                    Err(e) => {
                        error!(
                            error = e.to_string(),
                            addr = bind_addr.to_string();
                            "Failed to accept connection on metrics server"
                        );
                    }
                }
            }
            _ = cancel_token.cancelled() => {
                // Cancellation token triggered, exit the loop
                info!(
                    bind_addr = bind_addr.to_string();
                    "Metrics server shutting down due to cancellation"
                );
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::Duration;

    // Use atomic counter to generate unique ports for each test
    static NEXT_PORT: AtomicU16 = AtomicU16::new(9876);

    // Test server wrapper
    struct TestServer {
        server: OpenMetricsServer,
        port: u16,
    }

    impl TestServer {
        fn new() -> Self {
            // Get a unique port for this test instance
            let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
            let addr = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port).into();
            let config = OpenMetricsServerConfig { addr };

            let mut server = OpenMetricsServer::with_config(config);
            server.start().expect("Failed to start test server");

            Self { server, port }
        }

        fn make_request(&self, path: &str) -> (u16, String) {
            let url = format!("http://127.0.0.1:{}{}", self.port, path);
            let mut attempts = 0;
            let max_attempts = 3;

            while attempts < max_attempts {
                match reqwest::blocking::get(&url) {
                    Ok(response) => {
                        if response.status().is_success() || response.status().is_client_error() {
                            let status = response.status().as_u16();
                            let body = response.text().expect("Failed to read response body");
                            return (status, body);
                        }
                        // If we get a server error, we might retry
                        attempts += 1;
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => {
                        if attempts == max_attempts - 1 {
                            panic!(
                                "Failed to connect to server after {} attempts: {}",
                                max_attempts, e
                            );
                        }
                        attempts += 1;
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }

            panic!(
                "Failed to get a valid response after {} attempts",
                max_attempts
            );
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let _ = self.server.stop();
        }
    }

    #[test]
    fn test_server_startup() {
        let test_server = TestServer::new();
        assert!(test_server.server.is_running());
    }

    #[test]
    fn test_metrics_endpoint() {
        let test_server = TestServer::new();
        let (status, body) = test_server.make_request("/metrics");

        // Verify response
        assert_eq!(status, 200, "Expected 200 OK response");

        // Check for first metric (gauge)
        assert!(
            body.contains("nfm_sample_metric"),
            "Expected sample metric name in response"
        );
        assert!(
            body.contains("service=\"nfm-agent\""),
            "Expected service label in response"
        );
        assert!(
            body.contains("environment=\"development\""),
            "Expected environment label in response"
        );

        // Check for second metric (counter)
        assert!(
            body.contains("nfm_request_count"),
            "Expected request count metric name in response"
        );
    }

    #[test]
    fn test_root_endpoint() {
        let test_server = TestServer::new();
        let (status, body) = test_server.make_request("/");

        // Verify response
        assert_eq!(status, 200, "Expected 200 OK response");
        assert!(
            body.contains("Network Flow Monitor Agent Metrics Server"),
            "Expected welcome message in response"
        );
    }

    #[test]
    fn test_not_found() {
        let test_server = TestServer::new();
        let (status, body) = test_server.make_request("/nonexistent");

        // Verify response
        assert_eq!(status, 404, "Expected 404 Not Found response");
        assert!(
            body.contains("Not Found"),
            "Expected Not Found message in response"
        );
    }

    #[test]
    fn test_default() {
        let default_server = OpenMetricsServer::default();
        let default_config = OpenMetricsServerConfig::default();

        let expected_addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert!(
            default_server.config.addr == expected_addr,
            "server default address is wrong"
        );
        assert!(
            default_config.addr == expected_addr,
            "config default address is wrong"
        );
    }

    #[test]
    fn test_stop() {
        let mut default_server = OpenMetricsServer::default();
        default_server
            .start_on_addr("127.0.0.1:9999".parse().unwrap())
            .expect("cannot start server");
        default_server.stop().expect("cannot stop server");

        assert!(!default_server.is_running(), "server is running after stop")
    }

    #[test]
    fn test_server_config() {
        let config = OpenMetricsServerConfig::for_addr("1.1.1.1".to_string(), 99);
        let expected_address: SocketAddr = "1.1.1.1:99".parse().unwrap();
        assert!(
            config.addr == expected_address,
            "config has invalid address"
        );
    }
}
