// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.
//!
//! This module provides a basic HTTP server that returns a fixed dummy metric
//! in Prometheus format on the /metrics endpoint.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use hyper::http::StatusCode;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use tokio::net::TcpListener;

/// Configuration options for the OpenMetricsServer
pub struct OpenMetricsServerConfig {
    /// Address to bind the server to
    pub addr: SocketAddr,
    /// Timeout for connection operations
    pub connection_timeout: Duration,
    /// Grace period for shutdown
    pub shutdown_grace_period: Duration,
}

impl Default for OpenMetricsServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:80".parse().unwrap(),
            connection_timeout: Duration::from_millis(100),
            shutdown_grace_period: Duration::from_secs(5),
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
    /// Shutdown signal to gracefully terminate the server
    shutdown_signal: Arc<AtomicBool>,
    /// Server configuration
    config: OpenMetricsServerConfig,
}

impl Default for OpenMetricsServer {
    fn default() -> Self {
        Self {
            handle: None,
            shutdown_signal: Arc::new(AtomicBool::new(false)),
            config: OpenMetricsServerConfig::default(),
        }
    }
}

impl OpenMetricsServer {
    /// Create a new OpenMetricsServer with custom configuration
    pub fn with_config(config: OpenMetricsServerConfig) -> Self {
        Self {
            handle: None,
            shutdown_signal: Arc::new(AtomicBool::new(false)),
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
            open_metric = "starting"
            bind_addr = bind_addr.to_string();
            "Simple Prometheus metrics server starting"
        );

        let shutdown_signal_clone = Arc::clone(&self.shutdown_signal);
        let connection_timeout = self.config.connection_timeout;
        let handle = thread::spawn(move || {
            // Create a simple runtime for the server
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Failed to create Tokio runtime");

            rt.block_on(async {
                if let Err(e) =
                    run_server(bind_addr, shutdown_signal_clone, connection_timeout).await
                {
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
        self.shutdown_signal.store(true, Ordering::SeqCst);

        // Server shut down gracefully
        info!(open_metric = "shutdown_complete"; "Metrics server shut down gracefully");

        // Reset the shutdown signal for potential restart
        self.shutdown_signal = Arc::new(AtomicBool::new(false));

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
) -> Result<Response<String>, Infallible> {
    let path = req.uri().path();
    debug!(open_metric = "incoming_request", path = path; "Received request");

    let (status, content_type, body) = match path {
        "/metrics" => {
            let metrics = "# HELP nfm_test_metric A simple test metric for NFM agent\n# TYPE nfm_test_metric gauge\nnfm_test_metric 42\n";
            debug!(endpoint = "metrics"; "Serving metrics endpoint");
            (
                StatusCode::OK,
                "text/plain; version=0.0.4",
                metrics.to_string(),
            )
        }
        "/" => {
            let body = "Network Flow Monitor Agent Metrics Server\n\nAvailable endpoints:\n- /metrics - Prometheus metrics\n";
            debug!(endpoint = "root"; "Serving root endpoint");
            (StatusCode::OK, "text/plain", body.to_string())
        }
        "/health" => {
            debug!(endpoint = "health"; "Serving health endpoint");
            (StatusCode::OK, "text/plain", "OK".to_string())
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

/// Run the HTTP server - will terminate when shutdown signal is set
async fn run_server(
    bind_addr: SocketAddr,
    shutdown_signal: Arc<AtomicBool>,
    connection_timeout: Duration,
) -> std::io::Result<()> {
    // Bind to the address
    let listener = TcpListener::bind(bind_addr).await?;

    info!(
        bind_addr = bind_addr.to_string();
        "Metrics server listening"
    );

    // Accept connections until shutdown signal is received
    while !shutdown_signal.load(Ordering::Relaxed) {
        // Use tokio::select to either accept a connection or check the shutdown signal
        let accept_fut = listener.accept();

        // Use timeout to periodically check the shutdown signal
        match tokio::time::timeout(connection_timeout, accept_fut).await {
            // Connection accepted within timeout
            Ok(Ok((stream, _))) => {
                // Handle one request at a time
                let io = TokioIo::new(stream);

                // Process the connection
                if let Err(e) = http1::Builder::new()
                    .serve_connection(io, service_fn(handle_request))
                    .await
                {
                    warn!(
                        error = e.to_string(),
                        addr = bind_addr.to_string();
                        "Error handling HTTP request on metrics server"
                    );
                }
            }
            // Error accepting connection
            Ok(Err(e)) => {
                error!(
                    error = e.to_string(),
                    addr = bind_addr.to_string();
                    "Failed to accept connection on metrics server"
                );
            }
            // Timeout occurred - no connection accepted
            Err(_) => {
                // This is expected, just continue the loop to check shutdown signal
                continue;
            }
        }
    }

    info!(open_metric = "shutdown"; "Metrics server shutting down gracefully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    #[test]
    fn test_server_startup() {
        // Use port 0 to let the OS assign an available port
        let addr = "127.0.0.1:0".parse().unwrap();
        let config = OpenMetricsServerConfig {
            addr,
            connection_timeout: Duration::from_millis(50),
            shutdown_grace_period: Duration::from_secs(1),
        };

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

    /// Legacy API for backward compatibility
    #[allow(dead_code)]
    pub fn start_metrics_server(
        bind_addr: SocketAddr,
    ) -> (thread::JoinHandle<()>, Arc<AtomicBool>) {
        let shutdown_signal = Arc::new(AtomicBool::new(false));
        let connection_timeout = Duration::from_millis(100);

        let shutdown_signal_clone = Arc::clone(&shutdown_signal);
        let handle = thread::spawn(move || {
            // Create a simple runtime for the server
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Failed to create Tokio runtime");

            rt.block_on(async {
                if let Err(e) =
                    run_server(bind_addr, shutdown_signal_clone, connection_timeout).await
                {
                    error!(error = e.to_string(); "Metrics server error");
                }
            });
        });

        (handle, shutdown_signal)
    }

    #[test]
    fn test_legacy_api() {
        // Use port 0 to let the OS assign an available port
        let addr = "127.0.0.1:0".parse().unwrap();

        // Start server and get handle and shutdown signal
        let (handle, shutdown_signal) = start_metrics_server(addr);

        // Give server time to start
        thread::sleep(Duration::from_millis(50));

        // The thread should be running
        assert!(!handle.is_finished());

        // Test graceful shutdown
        info!(open_metric = "shutdown_initiated"; "Initiating graceful shutdown of metrics server");
        shutdown_signal.store(true, Ordering::SeqCst);

        // Give server time to shut down
        thread::sleep(Duration::from_millis(200));

        // The thread should have terminated
        assert!(handle.is_finished());
    }

    #[test]
    fn test_metrics_endpoint() {
        // Start server on a specific port to avoid conflicts
        let port = 9876;
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = OpenMetricsServerConfig {
            addr,
            connection_timeout: Duration::from_millis(50),
            shutdown_grace_period: Duration::from_secs(1),
        };

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
        assert!(
            response.contains("nfm_test_metric 42"),
            "Expected test metric in response"
        );

        // Clean up
        server.stop().expect("Failed to stop server");
    }

    #[test]
    fn test_health_endpoint() {
        // Start server on a specific port to avoid conflicts
        let port = 9879;
        let addr = format!("127.0.0.1:{}", port).parse().unwrap();
        let config = OpenMetricsServerConfig {
            addr,
            connection_timeout: Duration::from_millis(50),
            shutdown_grace_period: Duration::from_secs(1),
        };

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
        let config = OpenMetricsServerConfig {
            addr,
            connection_timeout: Duration::from_millis(50),
            shutdown_grace_period: Duration::from_secs(1),
        };

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
        let config = OpenMetricsServerConfig {
            addr,
            connection_timeout: Duration::from_millis(50),
            shutdown_grace_period: Duration::from_secs(1),
        };

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
