mod cli;
mod client;
mod ebpf_loader;
mod server;

use clap::Parser;
use log::info;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() {
    env_logger::init();

    let params = cli::Params::parse();
    let clients_per_server = 1u8;
    info!(params:serde, clients_per_server; "Starting tcp-tester");

    let mut tasks = JoinSet::new();
    for i in 0..params.servers {
        let port = params.starting_port.wrapping_add(i.into());
        tasks.spawn(server::server(port, params.response_delay_ms));

        for _ in 0..clients_per_server {
            info!("Spawning client");
            tasks.spawn(client::start_client_at_rate(
                params.connection_rate,
                port,
                params.traffic_shaping == cli::OnOff::On,
                params.send_data == cli::OnOff::On,
                params.cgroup_path.clone(),
                params.config_file_path.clone(),
            ));
        }
    }

    while let Some(res) = tasks.join_next().await {
        info!("Completed task: {}", res.is_ok())
    }
}
