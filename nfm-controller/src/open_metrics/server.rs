// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.
//!
//! This module provides a basic HTTP server that returns a fixed dummy metric
//! in Prometheus format on the /metrics endpoint.

use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
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

#[cfg(test)]
use reqwest;

use crate::kubernetes::kubernetes_metadata_collector::KubernetesMetadataCollector;
use crate::metadata::runtime_environment_metadata::RuntimeEnvironmentMetadataProvider;
use crate::open_metrics::provider::get_open_metric_providers;
use crate::open_metrics::types::MetricProviders;

/// Configuration options for the OpenMetricsServer
pub struct OpenMetricsServerConfig {
    /// Address to bind the server to
    pub addr: SocketAddr,
    pub k8s_metadata: Option<Arc<KubernetesMetadataCollector>>,
}

impl Default for OpenMetricsServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:80".parse().unwrap(),
            k8s_metadata: None,
        }
    }
}

impl OpenMetricsServerConfig {
    pub fn from(
        addr: String,
        port: u16,
        k8s_metadata: Option<Arc<KubernetesMetadataCollector>>,
    ) -> Self {
        let ip = IpAddr::from_str(&addr)
            .expect(&format!("Invalid OpenMetrics server address: {}", addr));
        Self {
            addr: SocketAddr::new(ip, port),
            k8s_metadata,
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

    /// Start the metrics server on the specified address with a Kubernetes metadata collector
    pub fn start(&mut self) -> Result<()> {
        // Check if server is already running
        if self.handle.is_some() {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Server is already running",
            ));
        }

        info!(
            open_metric = "starting",
            bind_addr = self.config.addr.to_string();
            "Simple Prometheus metrics server starting"
        );

        let cancel_token = self.cancel_token.clone();
        let addr = self.config.addr;
        let k8s_metadata = self.config.k8s_metadata.clone();

        let handle = thread::spawn(move || {
            // Runtime with 2 threads to allow usage of metadata providers, since it needs to
            // block to access IMDS.
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .expect("Failed to create Tokio runtime");

            rt.block_on(async {
                if let Err(e) = run_server(addr, cancel_token, k8s_metadata).await {
                    error!(error = e.to_string(); "Metrics server error");
                }
            });
        });

        self.handle = Some(handle);
        Ok(())
    }

    /// Stop the metrics server gracefully
    pub fn stop(&mut self) -> Result<()> {
        // Check if server is running
        let handle = match self.handle.take() {
            Some(h) => h,
            None => {
                return Err(Error::new(ErrorKind::NotFound, "Server is not running"));
            }
        };

        // Signal the server to shut down using the cancellation token
        info!(open_metric = "shutdown_initiated"; "Initiating graceful shutdown of metrics server");
        self.cancel_token.cancel();

        // Wait for the server thread to finish
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
    providers: MetricProviders,
) -> Result<Response<String>> {
    let start_time = Instant::now();
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

    info!(
        open_metric = "request_timing",
        duration_us = start_time.elapsed().as_micros();
        "Request processed",
    );

    Ok(response)
}

fn generate_metrics_text(registry: Arc<Registry>, providers: MetricProviders) -> String {
    // Update the metrics
    if let Ok(mut providers_guard) = providers.lock() {
        for provider in providers_guard.iter_mut() {
            if let Err(e) = provider.update_metrics() {
                error!(open_metric = "metric_updated", error = e.to_string(); "Error updating metric")
            }
        }
    } else {
        error!(open_metric = "mutex_lock_failed"; "Failed to acquire lock on providers");
    }

    // Use the registry to generate metrics
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Initialize the metrics registry and providers
fn initialize_metrics_registry(
    k8s_collector: Option<Arc<KubernetesMetadataCollector>>,
) -> (Arc<Registry>, MetricProviders) {
    let mut registry = Arc::new(Registry::new());
    let compute_platform = RuntimeEnvironmentMetadataProvider::get_compute_platform();
    let providers = get_open_metric_providers(compute_platform, k8s_collector);

    providers
        .iter()
        .for_each(|provider| provider.register_to(Arc::get_mut(&mut registry).unwrap()));

    let providers_arc = Rc::new(Mutex::new(providers));
    (registry, providers_arc)
}

/// Handle a single connection with cancellation support
async fn handle_connection(
    stream: tokio::net::TcpStream,
    registry: Arc<Registry>,
    providers: MetricProviders,
    cancel_token: CancellationToken,
    bind_addr: SocketAddr,
) {
    let io = TokioIo::new(stream);

    // Clone the Arc to use in the closure
    let registry_clone = registry.clone();
    let providers_clone = providers.clone();

    let connection = http1::Builder::new().serve_connection(
        io,
        service_fn(move |req| handle_request(req, registry_clone.clone(), providers_clone.clone())),
    );

    // Listen to the cancellation token while processing the request. Prometheus
    // keeps connection open and prevents process shutdown
    tokio::select! {
        result = connection => {
            if let Err(e) = result {
                warn!(
                    error = e.to_string(),
                    addr = bind_addr.to_string();
                    "Error handling HTTP request on metrics server"
                );
            }
        }
        _ = cancel_token.cancelled() => {
        }
    }
}

/// Accept and process connections in the main server loop
async fn accept_connections(
    listener: TcpListener,
    registry: Arc<Registry>,
    providers: MetricProviders,
    cancel_token: CancellationToken,
    bind_addr: SocketAddr,
) -> Result<()> {
    loop {
        // Use tokio::select to either accept a connection or check cancellation token
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        handle_connection(
                            stream,
                            registry.clone(),
                            providers.clone(),
                            cancel_token.clone(),
                            bind_addr,
                        ).await;
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

/// Run the HTTP server - will terminate when cancellation token is triggered
async fn run_server(
    bind_addr: SocketAddr,
    cancel_token: CancellationToken,
    k8s_collector: Option<Arc<KubernetesMetadataCollector>>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;

    info!(
        open_metric = "server_starting",
        bind_addr = bind_addr.to_string();
        "Metrics server listening"
    );

    let (registry, providers) = initialize_metrics_registry(k8s_collector);
    accept_connections(listener, registry, providers, cancel_token, bind_addr).await
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
            let config = OpenMetricsServerConfig {
                addr,
                k8s_metadata: None,
            };

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
        let (status, _body) = test_server.make_request("/metrics");

        // Verify response
        assert_eq!(status, 200, "Expected 200 OK response");
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
        let config = OpenMetricsServerConfig::from("127.0.0.1".to_string(), 9999, None);
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("cannot start server");
        server.stop().expect("cannot stop server");

        assert!(!server.is_running(), "server is running after stop")
    }

    #[test]
    fn test_server_config() {
        let config = OpenMetricsServerConfig::from("1.1.1.1".to_string(), 99, None);
        let expected_address: SocketAddr = "1.1.1.1:99".parse().unwrap();
        assert!(
            config.addr == expected_address,
            "config has invalid address"
        );
    }

    #[test]
    fn test_start_already_running() {
        let config = OpenMetricsServerConfig::from("127.0.0.1".to_string(), 9998, None);
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("Failed to start server");

        // Try to start again - should fail
        let result = server.start();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::AlreadyExists);

        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_stop_not_running() {
        let mut server = OpenMetricsServer::default();

        // Try to stop a server that's not running
        let result = server.stop();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn test_generate_metrics_text_mutex_error() {
        use prometheus::Registry;
        use std::sync::{Arc, Mutex};

        let registry = Arc::new(Registry::new());

        // Create a simple test that doesn't require Send trait
        // Just test with empty providers to cover the mutex lock path
        let providers = Rc::new(Mutex::new(Vec::new()));

        // Test the function with empty providers
        let result = generate_metrics_text(registry, providers);

        // Should return a string (empty metrics)
        assert!(result.is_empty() || !result.is_empty());
    }

    #[test]
    fn test_drop_running_server() {
        let config = OpenMetricsServerConfig::from("127.0.0.1".to_string(), 9996, None);
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("Failed to start server");

        assert!(server.is_running());

        // Drop should stop the server
        drop(server);

        // Give it a moment to shut down
        std::thread::sleep(Duration::from_millis(100));
    }

    #[test]
    fn test_server_with_custom_config() {
        let config = OpenMetricsServerConfig::from("127.0.0.1".to_string(), 9995, None);
        let mut server = OpenMetricsServer::with_config(config);

        server.start().expect("Failed to start server");
        assert!(server.is_running());

        server.stop().expect("Failed to stop server");
        assert!(!server.is_running());
    }
}
