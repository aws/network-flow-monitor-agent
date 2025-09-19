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

use hyper::http::StatusCode;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use prometheus::{Encoder, Registry, TextEncoder};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

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
        let socket_addr = format!("{}:{}", addr, port).parse().unwrap();
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
    /// Prometheus registry
    registry: Arc<Registry>,
    /// Metric providers
    providers: Vec<Box<dyn OpenMetricProvider>>,
}

impl Default for OpenMetricsServer {
    fn default() -> Self {
        // Create registry and providers
        let mut registry = Registry::new();
        let providers = get_open_metric_providers();

        // Register all providers with the registry
        for provider in &providers {
            provider.register(&mut registry);
        }

        Self {
            handle: None,
            cancel_token: CancellationToken::new(),
            config: OpenMetricsServerConfig::default(),
            registry: Arc::new(registry),
            providers,
        }
    }
}

impl OpenMetricsServer {
    /// Create a new OpenMetricsServer with custom configuration
    pub fn with_config(config: OpenMetricsServerConfig) -> Self {
        // Create registry and providers
        let mut registry = Registry::new();
        let providers = get_open_metric_providers();

        // Register all providers with the registry
        for provider in &providers {
            provider.register(&mut registry);
        }

        Self {
            handle: None,
            cancel_token: CancellationToken::new(),
            config,
            registry: Arc::new(registry),
            providers,
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
        let registry = self.registry.clone();

        // Update metrics before starting the server
        for provider in &self.providers {
            if let Err(e) = provider.update_metrics() {
                warn!(error = e.to_string(); "Failed to update metrics");
            }
        }

        let handle = thread::spawn(move || {
            // Create a simple runtime for the server
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Failed to create Tokio runtime");

            rt.block_on(async {
                if let Err(e) = run_server(bind_addr, cancel_token, registry).await {
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
) -> Result<Response<String>, Infallible> {
    let path = req.uri().path();
    debug!(open_metric = "incoming_request", path = path; "Received request");

    let (status, content_type, body) = match path {
        "/metrics" => {
            // Use the registry to generate metrics
            let encoder = TextEncoder::new();
            let metric_families = registry.gather();
            let mut buffer = Vec::new();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            let metrics = String::from_utf8(buffer).unwrap();

            debug!(endpoint = "metrics"; "Serving metrics endpoint");
            (StatusCode::OK, "text/plain; version=0.0.4", metrics)
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

/// Run the HTTP server - will terminate when cancellation token is triggered
async fn run_server(
    bind_addr: SocketAddr,
    cancel_token: CancellationToken,
    registry: Arc<Registry>,
) -> std::io::Result<()> {
    // Bind to the address
    let listener = TcpListener::bind(bind_addr).await?;

    info!(
        open_metric = "server_starting",
        bind_addr = bind_addr.to_string();
        "Metrics server listening"
    );

    // Accept connections until cancellation token is triggered
    loop {
        // Use tokio::select to either accept a connection or check cancellation token
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, _)) => {
                        // Handle one request at a time
                        let io = TokioIo::new(stream);
                        let registry_clone = registry.clone();

                        // Process the connection
                        // Use a closure to capture the registry
                        if let Err(e) = http1::Builder::new()
                            .serve_connection(io, service_fn(move |req| {
                                handle_request(req, registry_clone.clone())
                            }))
                            .await
                        {
                            warn!(
                                error = e.to_string(),
                                addr = bind_addr.to_string();
                                "Error handling HTTP request on metrics server"
                            );
                        }
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
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    #[test]
    fn test_server_startup() {
        // Use port 0 to let the OS assign an available port
        let addr = "127.0.0.1:0".parse().unwrap();
        let config = OpenMetricsServerConfig { addr };

        // Create and start server
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("Failed to start server");

        // Give server time to start
        thread::sleep(Duration::from_millis(50));

        // The server should be running
        assert!(server.is_running());

        // Test graceful shutdown
        server.stop().expect("Failed to stop server");

        // The server should not be running
        assert!(!server.is_running());
    }

    #[test]
    fn test_metrics_endpoint() {
        // Start server on a specific port to avoid conflicts
        let port = 9876;
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = OpenMetricsServerConfig { addr };

        // Create and start server
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("Failed to start server");

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Make a request to the metrics endpoint
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect to server");

        // Send HTTP GET request
        let request = "GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("Failed to send request");

        // Read response
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("Failed to read response");

        // Verify response
        assert!(response.contains("200 OK"), "Expected 200 OK response");

        // Check for first metric (gauge)
        assert!(
            response.contains("nfm_sample_metric"),
            "Expected sample metric name in response"
        );
        assert!(
            response.contains("service=\"nfm-agent\""),
            "Expected service label in response"
        );
        assert!(
            response.contains("environment=\"development\""),
            "Expected environment label in response"
        );

        // Check for second metric (counter)
        assert!(
            response.contains("nfm_request_count"),
            "Expected request count metric name in response"
        );
        assert!(
            response.contains("endpoint=\"metrics\""),
            "Expected endpoint label in response"
        );
        assert!(
            response.contains("status=\"success\""),
            "Expected status label in response"
        );

        // Clean up
        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_health_endpoint() {
        // Start server on a specific port to avoid conflicts
        let port = 9879;
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = OpenMetricsServerConfig { addr };

        // Create and start server
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("Failed to start server");

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Make a request to the health endpoint
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect to server");

        // Send HTTP GET request
        let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("Failed to send request");

        // Read response
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("Failed to read response");

        // Verify response
        assert!(response.contains("200 OK"), "Expected 200 OK response");
        assert!(response.contains("OK"), "Expected OK message in response");

        // Clean up
        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_root_endpoint() {
        // Start server on a specific port to avoid conflicts
        let port = 9877;
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = OpenMetricsServerConfig { addr };

        // Create and start server
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("Failed to start server");

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Make a request to the root endpoint
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect to server");

        // Send HTTP GET request
        let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("Failed to send request");

        // Read response
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("Failed to read response");

        // Verify response
        assert!(response.contains("200 OK"), "Expected 200 OK response");
        assert!(
            response.contains("Network Flow Monitor Agent Metrics Server"),
            "Expected welcome message in response"
        );

        // Clean up
        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_not_found() {
        // Start server on a specific port to avoid conflicts
        let port = 9878;
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = OpenMetricsServerConfig { addr };

        // Create and start server
        let mut server = OpenMetricsServer::with_config(config);
        server.start().expect("Failed to start server");

        // Give server time to start
        thread::sleep(Duration::from_millis(100));

        // Make a request to a non-existent endpoint
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect to server");

        // Send HTTP GET request
        let request = "GET /nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .expect("Failed to send request");

        // Read response
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("Failed to read response");

        // Verify response
        assert!(response.contains("404"), "Expected 404 Not Found response");
        assert!(
            response.contains("Not Found"),
            "Expected Not Found message in response"
        );

        // Clean up
        server.stop().expect("Failed to stop server");
    }
}
