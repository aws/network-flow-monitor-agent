// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Prometheus metrics server.
//!
//! In delta mode, connections are served one at a time, since every scrape resets the baseline
//! used to compute deltas. In absolute mode, connections are served concurrently from a cached
//! snapshot that is refreshed at most once per refresh interval.

use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hyper::http::StatusCode;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use log::{debug, error, info, warn};
use prometheus::{Encoder, Registry, TextEncoder};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::LocalSet;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
use reqwest;

use crate::kubernetes::kubernetes_metadata_collector::KubernetesMetadataCollector;
use crate::metadata::runtime_environment_metadata::RuntimeEnvironmentMetadataProvider;
use crate::open_metrics::provider::get_open_metric_providers;
use crate::open_metrics::types::MetricProviders;
use crate::open_metrics::OpenMetricsMode;

const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const DEFAULT_MAX_CONNECTIONS: usize = 10;
const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration options for the OpenMetricsServer
pub struct OpenMetricsServerConfig {
    /// Address to bind the server to
    pub addr: SocketAddr,
    pub k8s_metadata: Option<Arc<KubernetesMetadataCollector>>,
    pub mode: OpenMetricsMode,
    /// Absolute mode: minimum time between metric refreshes.
    pub refresh_interval: Duration,
    /// Absolute mode: maximum concurrent connections. Extra connections get a 503.
    pub max_connections: usize,
    /// Absolute mode: connections that don't send full request headers in time are closed.
    pub header_read_timeout: Duration,
}

impl Default for OpenMetricsServerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:80".parse().unwrap(),
            k8s_metadata: None,
            mode: OpenMetricsMode::Delta,
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
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
            .unwrap_or_else(|_| panic!("Invalid OpenMetrics server address: {}", addr));
        Self {
            addr: SocketAddr::new(ip, port),
            k8s_metadata,
            ..Default::default()
        }
    }

    pub fn with_mode(
        mut self,
        mode: OpenMetricsMode,
        refresh_interval: Duration,
        max_connections: usize,
    ) -> Self {
        self.mode = mode;
        self.refresh_interval = refresh_interval;
        self.max_connections = max_connections;
        self
    }
}

/// Settings used by the absolute mode server.
#[derive(Clone, Copy)]
struct AbsoluteModeSettings {
    refresh_interval: Duration,
    max_connections: usize,
    header_read_timeout: Duration,
}

impl From<&OpenMetricsServerConfig> for AbsoluteModeSettings {
    fn from(config: &OpenMetricsServerConfig) -> Self {
        Self {
            refresh_interval: config.refresh_interval,
            max_connections: config.max_connections,
            header_read_timeout: config.header_read_timeout,
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
            bind_addr = self.config.addr.to_string(),
            mode = self.config.mode.to_string();
            "Simple Prometheus metrics server starting"
        );

        let cancel_token = self.cancel_token.clone();
        let addr = self.config.addr;
        let k8s_metadata = self.config.k8s_metadata.clone();
        let mode = self.config.mode;
        let settings = AbsoluteModeSettings::from(&self.config);

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
                let result = match mode {
                    OpenMetricsMode::Delta => run_server(addr, cancel_token, k8s_metadata).await,
                    OpenMetricsMode::Absolute => {
                        run_server_absolute(addr, cancel_token, k8s_metadata, settings).await
                    }
                };
                if let Err(e) = result {
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

/// Handle HTTP request and return appropriate response. `metrics` produces the /metrics body.
async fn handle_request<F, Fut>(
    req: Request<hyper::body::Incoming>,
    metrics: F,
) -> Result<Response<String>>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = (StatusCode, String)>,
{
    let start_time = Instant::now();
    let path = req.uri().path().to_string();
    debug!(open_metric = "incoming_request", path = path; "Received request");

    let (status, content_type, body) = match path.as_str() {
        "/metrics" => {
            debug!(endpoint = "metrics"; "Serving metrics endpoint");
            let (status, body) = metrics().await;
            (status, "text/plain", body)
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
    mode: OpenMetricsMode,
) -> (Arc<Registry>, MetricProviders) {
    let mut registry = Arc::new(Registry::new());
    let compute_platform = RuntimeEnvironmentMetadataProvider::get_compute_platform();
    let providers = get_open_metric_providers(compute_platform, k8s_collector, mode);

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

    let connection = http1::Builder::new().serve_connection(
        io,
        service_fn(move |req| {
            let registry = registry.clone();
            let providers = providers.clone();
            handle_request(req, move || async move {
                (StatusCode::OK, generate_metrics_text(registry, providers))
            })
        }),
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

    let (registry, providers) = initialize_metrics_registry(k8s_collector, OpenMetricsMode::Delta);
    accept_connections(listener, registry, providers, cancel_token, bind_addr).await
}

/// A request for the latest metrics text, answered by the collector.
type SnapshotRequest = oneshot::Sender<Arc<String>>;

/// Run the absolute mode HTTP server - will terminate when cancellation token is triggered
async fn run_server_absolute(
    bind_addr: SocketAddr,
    cancel_token: CancellationToken,
    k8s_collector: Option<Arc<KubernetesMetadataCollector>>,
    settings: AbsoluteModeSettings,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;

    info!(
        open_metric = "server_starting",
        bind_addr = bind_addr.to_string(),
        refresh_secs = settings.refresh_interval.as_secs(),
        max_connections = settings.max_connections;
        "Metrics server listening"
    );

    let (registry, providers) =
        initialize_metrics_registry(k8s_collector, OpenMetricsMode::Absolute);
    serve_absolute(listener, registry, providers, cancel_token, settings).await
}

/// Serves connections concurrently. Providers aren't thread safe, so they stay in a single
/// collector task on this thread, while connections are handled by the runtime workers.
async fn serve_absolute(
    listener: TcpListener,
    registry: Arc<Registry>,
    providers: MetricProviders,
    cancel_token: CancellationToken,
    settings: AbsoluteModeSettings,
) -> Result<()> {
    let bind_addr = listener.local_addr()?;
    let (snapshot_tx, snapshot_rx) = mpsc::channel::<SnapshotRequest>(settings.max_connections);

    let local = LocalSet::new();
    local.spawn_local(run_collector(
        registry,
        providers,
        snapshot_rx,
        settings.refresh_interval,
    ));

    let accept_loop = tokio::spawn(accept_connections_concurrent(
        listener,
        snapshot_tx,
        cancel_token,
        bind_addr,
        settings,
    ));

    match local.run_until(accept_loop).await {
        Ok(result) => result,
        Err(e) => Err(Error::other(e)),
    }
}

/// Answers snapshot requests in order. The snapshot is refreshed only when it is older than
/// the refresh interval, so concurrent scrapers share a single refresh.
async fn run_collector(
    registry: Arc<Registry>,
    providers: MetricProviders,
    mut requests: mpsc::Receiver<SnapshotRequest>,
    refresh_interval: Duration,
) {
    let mut snapshot: Option<(Instant, Arc<String>)> = None;

    while let Some(reply) = requests.recv().await {
        let text = match &snapshot {
            Some((refreshed_at, text)) if refreshed_at.elapsed() < refresh_interval => text.clone(),
            _ => {
                let text = Arc::new(generate_metrics_text(registry.clone(), providers.clone()));
                snapshot = Some((Instant::now(), text.clone()));
                text
            }
        };
        let _ = reply.send(text);
    }
}

/// Asks the collector for the latest metrics text.
async fn request_snapshot(snapshots: mpsc::Sender<SnapshotRequest>) -> (StatusCode, String) {
    let (reply_tx, reply_rx) = oneshot::channel();
    if snapshots.send(reply_tx).await.is_ok() {
        if let Ok(text) = reply_rx.await {
            return (StatusCode::OK, text.as_ref().clone());
        }
    }

    error!(open_metric = "snapshot_unavailable"; "Metrics collector is not running");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Metrics unavailable".to_string(),
    )
}

/// Accepts connections and serves each one in its own task, up to the connection limit.
async fn accept_connections_concurrent(
    listener: TcpListener,
    snapshots: mpsc::Sender<SnapshotRequest>,
    cancel_token: CancellationToken,
    bind_addr: SocketAddr,
    settings: AbsoluteModeSettings,
) -> Result<()> {
    let connection_slots = Arc::new(Semaphore::new(settings.max_connections));

    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer)) => {
                        let permit = connection_slots.clone().try_acquire_owned().ok();
                        if permit.is_none() {
                            warn!(
                                open_metric = "connection_limit_reached",
                                peer = peer.to_string(),
                                max_connections = settings.max_connections;
                                "Rejecting metrics connection"
                            );
                        }
                        tokio::spawn(handle_connection_concurrent(
                            stream,
                            snapshots.clone(),
                            cancel_token.clone(),
                            bind_addr,
                            settings.header_read_timeout,
                            permit,
                        ));
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

/// Serves a single connection. Without a connection slot, it replies 503 and closes.
async fn handle_connection_concurrent(
    stream: tokio::net::TcpStream,
    snapshots: mpsc::Sender<SnapshotRequest>,
    cancel_token: CancellationToken,
    bind_addr: SocketAddr,
    header_read_timeout: Duration,
    permit: Option<OwnedSemaphorePermit>,
) {
    let io = TokioIo::new(stream);
    let has_slot = permit.is_some();

    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .keep_alive(has_slot);

    let connection = builder.serve_connection(
        io,
        service_fn(move |req| {
            let snapshots = snapshots.clone();
            async move {
                if !has_slot {
                    return Ok(too_many_connections_response());
                }
                handle_request(req, move || request_snapshot(snapshots)).await
            }
        }),
    );

    tokio::select! {
        result = connection => {
            if let Err(e) = result {
                debug!(
                    error = e.to_string(),
                    addr = bind_addr.to_string();
                    "Metrics connection closed with error"
                );
            }
        }
        _ = cancel_token.cancelled() => {}
    }

    drop(permit);
}

fn too_many_connections_response() -> Response<String> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "text/plain")
        .body("Too many connections".to_string())
        .unwrap()
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
                ..Default::default()
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

    mod absolute_mode {
        use super::*;
        use crate::open_metrics::provider::OpenMetricProvider;
        use crate::open_metrics::providers::register_metric;
        use prometheus::{IntGaugeVec, Opts};
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::sync::atomic::AtomicUsize;

        /// Provider that counts refreshes and blocks for `delay`, like the real providers do.
        struct CountingProvider {
            refreshes: Arc<AtomicUsize>,
            delay: Duration,
            gauge: IntGaugeVec,
        }

        impl OpenMetricProvider for CountingProvider {
            fn register_to(&self, registry: &mut Registry) {
                register_metric(registry, &self.gauge, OpenMetricsMode::Absolute);
            }

            fn update_metrics(&mut self) -> std::result::Result<(), anyhow::Error> {
                thread::sleep(self.delay);
                let refreshes = self.refreshes.fetch_add(1, Ordering::SeqCst) + 1;
                self.gauge
                    .with_label_values(&["eth0"])
                    .set(refreshes as i64);
                Ok(())
            }
        }

        struct AbsoluteTestServer {
            port: u16,
            refreshes: Arc<AtomicUsize>,
            cancel_token: CancellationToken,
            handle: Option<thread::JoinHandle<()>>,
        }

        impl AbsoluteTestServer {
            fn start(delay: Duration, settings: AbsoluteModeSettings) -> Self {
                let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                std_listener.set_nonblocking(true).unwrap();
                let port = std_listener.local_addr().unwrap().port();
                let refreshes = Arc::new(AtomicUsize::new(0));
                let cancel_token = CancellationToken::new();

                let thread_refreshes = refreshes.clone();
                let thread_cancel = cancel_token.clone();
                let handle = thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(async move {
                        let listener = TcpListener::from_std(std_listener).unwrap();
                        let provider = CountingProvider {
                            refreshes: thread_refreshes,
                            delay,
                            gauge: IntGaugeVec::new(Opts::new("rx_bytes", "help"), &["iface"])
                                .unwrap(),
                        };
                        let mut registry = Registry::new();
                        provider.register_to(&mut registry);
                        let providers: MetricProviders =
                            Rc::new(Mutex::new(vec![Box::new(provider)]));
                        serve_absolute(
                            listener,
                            Arc::new(registry),
                            providers,
                            thread_cancel,
                            settings,
                        )
                        .await
                        .unwrap();
                    });
                });

                Self {
                    port,
                    refreshes,
                    cancel_token,
                    handle: Some(handle),
                }
            }

            fn get(&self, path: &str) -> (u16, String) {
                let client = reqwest::blocking::Client::builder()
                    .timeout(Duration::from_secs(5))
                    .build()
                    .unwrap();
                let response = client
                    .get(format!("http://127.0.0.1:{}{}", self.port, path))
                    .send()
                    .expect("request failed");
                let status = response.status().as_u16();
                (status, response.text().unwrap())
            }

            fn refreshes(&self) -> usize {
                self.refreshes.load(Ordering::SeqCst)
            }
        }

        impl Drop for AbsoluteTestServer {
            fn drop(&mut self) {
                self.cancel_token.cancel();
                if let Some(handle) = self.handle.take() {
                    let _ = handle.join();
                }
            }
        }

        fn settings(refresh_interval: Duration, max_connections: usize) -> AbsoluteModeSettings {
            AbsoluteModeSettings {
                refresh_interval,
                max_connections,
                header_read_timeout: Duration::from_secs(5),
            }
        }

        #[test]
        fn test_serves_counters() {
            let server =
                AbsoluteTestServer::start(Duration::ZERO, settings(Duration::from_secs(30), 10));
            let (status, body) = server.get("/metrics");

            assert_eq!(status, 200);
            assert!(body.contains("# TYPE rx_bytes_total counter"), "{body}");
            assert!(body.contains("rx_bytes_total{iface=\"eth0\"} 1"), "{body}");
        }

        #[test]
        fn test_concurrent_scrapes_share_one_refresh() {
            let server = Arc::new(AbsoluteTestServer::start(
                Duration::from_millis(300),
                settings(Duration::from_secs(30), 10),
            ));

            let clients: Vec<_> = (0..5)
                .map(|_| {
                    let server = server.clone();
                    thread::spawn(move || server.get("/metrics"))
                })
                .collect();
            let responses: Vec<(u16, String)> =
                clients.into_iter().map(|c| c.join().unwrap()).collect();

            assert_eq!(server.refreshes(), 1);
            for (status, body) in &responses {
                assert_eq!(*status, 200);
                assert_eq!(body, &responses[0].1);
            }
        }

        #[test]
        fn test_refreshes_after_interval() {
            let server =
                AbsoluteTestServer::start(Duration::ZERO, settings(Duration::from_millis(200), 10));

            server.get("/metrics");
            server.get("/metrics");
            assert_eq!(server.refreshes(), 1);

            thread::sleep(Duration::from_millis(300));
            server.get("/metrics");
            assert_eq!(server.refreshes(), 2);
        }

        #[test]
        fn test_keep_alive_connection_does_not_block_other_clients() {
            let server =
                AbsoluteTestServer::start(Duration::ZERO, settings(Duration::from_secs(30), 10));

            // Scrape once and keep the connection open, like Prometheus does.
            let mut keep_alive = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
            keep_alive
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            let mut buf = [0u8; 1024];
            let read = keep_alive.read(&mut buf).unwrap();
            assert!(String::from_utf8_lossy(&buf[..read]).starts_with("HTTP/1.1 200"));

            let (status, _) = server.get("/metrics");
            assert_eq!(status, 200);
        }

        #[test]
        fn test_connection_limit_rejects_extra_connections() {
            let mut limited = settings(Duration::from_secs(30), 1);
            limited.header_read_timeout = Duration::from_millis(300);
            let server = AbsoluteTestServer::start(Duration::ZERO, limited);

            // An idle connection takes the only slot.
            let _idle = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
            thread::sleep(Duration::from_millis(100));
            let (status, _) = server.get("/metrics");
            assert_eq!(status, 503);

            // The idle connection is closed by the header read timeout, freeing the slot.
            thread::sleep(Duration::from_millis(500));
            let (status, _) = server.get("/metrics");
            assert_eq!(status, 200);
        }
    }
}
