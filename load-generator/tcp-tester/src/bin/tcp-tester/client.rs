mod client_socket_error;
mod conditioned_tcp_stream;
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
use rand::{Rng, RngCore};
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;
use tcp_tester_common::{FlowConfig, SocketKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

use self::socket_builder::{connect_sans_tc, ClientSocketBuilder};
use client_socket_error::ClientSocketError;
use conditioned_tcp_stream::ConditionedTcpStream;

static CLIENT_NAMESPACE: &str = "nfm-perf-test-client";
static TCP_TESTER_NAMESPACE: &str = "nfm-perf-test-tcp-tester";

/// Reads a file containing the configuration to be applied to all flows.
///
/// # Arguments
/// * `path` - path to the configuration file relative to tcp-tester crate root folder.
fn get_config_from_file(path: String) -> FlowConfig {
    println!("Reading config file from {}", path);
    let mut file = File::open(path).unwrap();
    let mut json = String::new();
    file.read_to_string(&mut json).unwrap();
    let result: FlowConfig = serde_json::from_str(&json).unwrap();
    result
}

/// Attaches the eBPF programs for traffic control and sockops in the specified cgroup.
///
/// # Arguments
/// * `cgroup_path` - cgroup file path where the fault injection program is going to be attached.
fn setup_ebpf(cgroup_path: String) -> Ebpf {
    let mut bpf = ebpf_loader::load_ebpf_program().unwrap();

    // Attachs the traffic control program to the respective interfaces in the middle-box.
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

    // Loads the sockops program in the kernel.
    let program: &mut SockOps = bpf
        .program_mut("tcp_tester_sockops")
        .unwrap()
        .try_into()
        .unwrap();
    program.load().unwrap();
    program
        .attach(File::open(cgroup_path.clone()).unwrap(), get_attach_mode())
        .context(format!("Failed to attach to cgroup: {}", cgroup_path))
        .unwrap();

    bpf
}

fn get_attach_mode() -> CgroupAttachMode {
    // Aya uses BPF_LINK_CREATE for Linux >= 5.7.0 (see sock_ops.rs). The only valid value
    // is 0 (CgroupAttachMode), but Kernel uses BPF_F_ALLOW_MULTI to attach the link.
    if KernelVersion::current().unwrap() >= KernelVersion::new(5, 7, 0) {
        CgroupAttachMode::Single
    } else {
        CgroupAttachMode::AllowMultiple
    }
}

/// Starts a connection to the backend and awaits until it is closed by the server.
///
/// # Arguments
///
/// * `addr` - Address and port of the server.
/// * `cgroup_path` - cgroup file path where the fault injection program is going to be attached.
/// * `config_file_path` - path to the configuration file relative to tcp-tester crate root folder.
async fn run_client(
    addr: SocketAddr,
    enable_traffic_shaping: bool,
    send_data: bool,
    cgroup_path: String,
    config_file_path: String,
) {
    let client_namespace = NetNs::get(CLIENT_NAMESPACE).unwrap();
    let stream_result: Result<ConditionedTcpStream, ClientSocketError> = if enable_traffic_shaping {
        let mut bpf = setup_ebpf(cgroup_path);
        let map = bpf.map_mut("SOCKET_CONFIG").unwrap();
        let socket_config: HashMap<_, SocketKey, FlowConfig> = HashMap::try_from(map).unwrap();
        let mut socket_builder = ClientSocketBuilder::new(client_namespace, socket_config);
        let config = get_config_from_file(config_file_path);
        socket_builder.connect(addr, config, config).await
    } else {
        connect_sans_tc(client_namespace, addr).await
    };

    match stream_result {
        Ok(mut conditioned_tcp_stream) => {
            debug!("Connected to server");

            if send_data {
                debug!("Sending data");
                send_random_data(&mut conditioned_tcp_stream.stream).await;
                debug!("Data sent");
            }

            debug!("Closing connection");
            conditioned_tcp_stream.stream.shutdown().await.unwrap();
        }
        Err(error) => {
            error!("Failed to connect: {:?}", error);
        }
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
        match stream.read_exact(&mut response).await {
            Err(e) => debug!("Error reading response {}", e),
            _ => {}
        }
        sleep(Duration::from_millis(10)).await;
    }
}

/// Generates clients (and thus connections) at the rate specified.
///
/// # Arguments
/// * `rate` - TPS.
/// * `port` - Server port.
/// * `cgroup_path` - cgroup file path where the fault injection program is going to be attached.
/// * `config_file_path` - path to the configuration file relative to tcp-tester crate root folder.
pub async fn start_client_at_rate(
    rate: u32,
    port: u16,
    enable_traffic_shaping: bool,
    send_data: bool,
    cgroup_path: String,
    config_file_path: String,
) {
    let micros_per_txn = (1_000_000 / rate) as u64;
    let duration = Duration::from_micros(micros_per_txn);
    let mut interval = tokio::time::interval(duration);
    info!(
        "Generating requests at a rate of {} per sec ({:?} between requests)",
        rate, duration
    );

    let mut num_spawned: u32 = 0;
    loop {
        let client_address = format!("2.2.2.2:{}", port).parse().unwrap();
        let cgp = cgroup_path.clone();
        let cfp = config_file_path.clone();
        tokio::spawn(async move {
            run_client(client_address, enable_traffic_shaping, send_data, cgp, cfp).await
        });

        num_spawned += 1;
        if num_spawned == rate {
            info!("Initiated {num_spawned} transactions");
            num_spawned = 0;
        }

        interval.tick().await;
    }
}
