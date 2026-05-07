mod cli;
mod client;
mod ebpf_loader;
mod server;

use clap::Parser;
use log::info;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() {
    env_logger::init();

    let params = cli::Params::parse();
    info!(params:serde; "Starting tcp-tester");

    let total_counter = Arc::new(AtomicU64::new(0));
    let total_rate = params.connection_rate;

    // Create a single approximate connections per second stat reporter for all servers
    let counter_clone = total_counter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let count = counter_clone.swap(0, Ordering::Relaxed);
            if count > 0 {
                info!("Total achieved: {count} conn/s (target: {total_rate})");
            }
        }
    });

    let mut tasks = JoinSet::new();
    for i in 0..params.servers {
        let port = params.starting_port.wrapping_add(i.into());
        tasks.spawn(server::server(port, params.response_delay_ms));

        info!("Spawning client");
        tasks.spawn(client::start_client_at_rate(
            params.connection_rate / params.servers as u32,
            port,
            params.traffic_shaping == cli::OnOff::On,
            params.send_data == cli::OnOff::On,
            params.cgroup_path.clone(),
            params.config_file_path.clone(),
            total_counter.clone(),
        ));
    }

    while let Some(res) = tasks.join_next().await {
        info!("Completed task: {}", res.is_ok())
    }
}
