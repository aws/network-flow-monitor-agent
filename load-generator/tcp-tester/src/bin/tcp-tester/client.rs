mod client_socket_error;
mod socket_builder;

use crate::ebpf_loader;
use aya::util::KernelVersion;

use anyhow::Context;
use aya::maps::HashMap;
use aya::programs::tc::{self as tc, TcAttachOptions};
use aya::programs::{CgroupAttachMode, LinkOrder, SchedClassifier, SockOps, TcAttachType};
use aya::Ebpf;
use log::{debug, error, info};
use netns_rs::NetNs;
use rand::{Rng, RngExt};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::os::unix::io::IntoRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tcp_tester_common::{FlowConfig, SocketKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

use self::socket_builder::{connect_sans_tc, ClientSocketBuilder};

static CLIENT_NAMESPACE: &str = "nfm-perf-test-client";
static TCP_TESTER_NAMESPACE: &str = "nfm-perf-test-tcp-tester";

/// Closes a TCP stream with RST (no TIME_WAIT) by setting SO_LINGER=0
/// and performing a synchronous close.
fn close_with_rst(stream: TcpStream) {
    let raw_fd = stream.into_std().unwrap().into_raw_fd();
    unsafe {
        nix::libc::close(raw_fd);
    }
}

/// Reads a file containing the configuration to be applied to all flows.
fn get_config_from_file(path: &str) -> FlowConfig {
    let mut file = File::open(path).unwrap();
    let mut json = String::new();
    file.read_to_string(&mut json).unwrap();
    serde_json::from_str(&json).unwrap()
}

/// Attaches the eBPF programs for traffic control and sockops in the specified cgroup.
fn setup_ebpf(cgroup_path: &str) -> Ebpf {
    let mut bpf = ebpf_loader::load_ebpf_program().unwrap();

    let namespace = NetNs::get(TCP_TESTER_NAMESPACE).unwrap();
    namespace
        .run(|_| {
            let _ = tc::qdisc_add_clsact("i2");
            let _ = tc::qdisc_add_clsact("i3");

            let program: &mut SchedClassifier = bpf
                .program_mut("tcp_tester_tc_egress")
                .unwrap()
                .try_into()
                .unwrap();

            program.load().unwrap();

            program
                .attach_with_options(
                    "i2",
                    TcAttachType::Egress,
                    TcAttachOptions::TcxOrder(LinkOrder::default()),
                )
                .unwrap();
            program
                .attach_with_options(
                    "i3",
                    TcAttachType::Ingress,
                    TcAttachOptions::TcxOrder(LinkOrder::default()),
                )
                .unwrap();
        })
        .unwrap();

    let program: &mut SockOps = bpf
        .program_mut("tcp_tester_sockops")
        .unwrap()
        .try_into()
        .unwrap();
    program.load().unwrap();
    program
        .attach(File::open(cgroup_path).unwrap(), get_attach_mode())
        .context(format!("Failed to attach to cgroup: {}", cgroup_path))
        .unwrap();

    bpf
}

fn get_attach_mode() -> CgroupAttachMode {
    if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
        CgroupAttachMode::Single
    } else {
        CgroupAttachMode::AllowMultiple
    }
}

/// Connects with traffic shaping enabled (eBPF-based fault injection).
async fn run_shaped_client(
    addr: SocketAddr,
    send_data: bool,
    cgroup_path: &str,
    config_file_path: &str,
    counter: &AtomicU64,
) {
    let client_namespace = NetNs::get(CLIENT_NAMESPACE).unwrap();
    let mut bpf = setup_ebpf(cgroup_path);
    let map = bpf.map_mut("SOCKET_CONFIG").unwrap();
    let socket_config: HashMap<_, SocketKey, FlowConfig> = HashMap::try_from(map).unwrap();
    let mut socket_builder = ClientSocketBuilder::new(client_namespace, socket_config);
    let config = get_config_from_file(config_file_path);

    match socket_builder.connect(addr, config, config).await {
        Ok(mut stream) => {
            if send_data {
                send_random_data(&mut stream).await;
            }
            close_with_rst(stream);
            counter.fetch_add(1, Ordering::Relaxed);
        }
        Err(e) => error!("Failed to connect: {e:?}"),
    }
}

async fn send_random_data(stream: &mut TcpStream) {
    stream.set_nodelay(true).unwrap();
    let packets = rand::rng().random_range(50..150);
    let mut data = [0; 2048];

    for _ in 0..packets {
        let len = rand::rng().random_range(200..2048);
        rand::rng().fill_bytes(&mut data[..len]);

        stream.write_all(&data).await.unwrap();
        let mut response = vec![0; len];
        if let Err(e) = stream.read_exact(&mut response).await {
            debug!("Error reading response {}", e);
        }
        sleep(Duration::from_millis(10)).await;
    }
}

/// Generates connections at the specified rate.
pub async fn start_client_at_rate(
    rate: u32,
    port: u16,
    enable_traffic_shaping: bool,
    send_data: bool,
    cgroup_path: String,
    config_file_path: String,
    counter: Arc<AtomicU64>,
) {
    let client_ns = Arc::new(NetNs::get(CLIENT_NAMESPACE).unwrap());
    let addr: SocketAddr = format!("2.2.2.2:{}", port).parse().unwrap();
    let interval_duration = Duration::from_micros(1_000_000 / rate as u64);

    info!(
        "Generating requests at a rate of {rate} per sec ({interval_duration:?} between requests)"
    );

    if enable_traffic_shaping || send_data {
        // Long-lived connections: spawn a task per connection.
        let mut interval = tokio::time::interval(interval_duration);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let cgp = cgroup_path.clone();
            let cfp = config_file_path.clone();
            let counter = counter.clone();
            let ns = client_ns.clone();
            tokio::spawn(async move {
                if enable_traffic_shaping {
                    run_shaped_client(addr, send_data, &cgp, &cfp, &counter).await;
                } else {
                    // send_data without traffic shaping
                    match connect_sans_tc(&ns, addr).await {
                        Ok(mut stream) => {
                            send_random_data(&mut stream).await;
                            close_with_rst(stream);
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => error!("Failed to connect: {e:?}"),
                    }
                }
            });
        }
    } else {
        // Connect-and-close: fixed worker pool with rate limiting.
        let num_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(rate as usize);
        let rate_limiter = Arc::new(tokio::sync::Semaphore::new(0));

        let rl = rate_limiter.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                rl.add_permits(1);
            }
        });

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..num_workers {
            let ns = client_ns.clone();
            let counter = counter.clone();
            let rl = rate_limiter.clone();
            tasks.spawn(async move {
                loop {
                    let permit = rl.acquire().await.unwrap();
                    permit.forget();
                    match connect_sans_tc(&ns, addr).await {
                        Ok(stream) => {
                            close_with_rst(stream);
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => error!("Failed to connect: {e:?}"),
                    }
                }
            });
        }
        tasks.join_next().await;
    }
}
