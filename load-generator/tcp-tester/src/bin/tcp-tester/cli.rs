use clap::{Parser, ValueEnum};
use serde::Serialize;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Serialize, ValueEnum)]
pub enum OnOff {
    On,
    Off,
}

impl fmt::Display for OnOff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OnOff::On => write!(f, "on"),
            OnOff::Off => write!(f, "off"),
        }
    }
}

/// TCP Tester app, used to generate traffic and network fault injection to test the Network
/// Sonar agent.
#[derive(Debug, Parser, Serialize)]
#[command(version, about, long_about = None)]
pub struct Params {
    /// Number of servers that will be handling the requests.
    #[arg(short, long, default_value_t = 1)]
    pub servers: u8,

    /// Number of connections per second that will be generated (distributed across the servers).
    #[arg(short, long, default_value_t = 1)]
    pub connection_rate: u32,

    /// The amount of time taken by the server before responding to a request.
    #[arg(short, long, default_value_t = 0)]
    pub response_delay_ms: u64,

    /// First port used for the servers, each new server port will just add 1 to the initial port.
    #[arg(short = 'p', long, default_value_t = 8080)]
    pub starting_port: u16,

    /// Controls whether traffic shaping is enabled.
    #[arg(short = 't', long, default_value_t = OnOff::Off)]
    pub traffic_shaping: OnOff,

    /// Controls whether traffic shaping is enabled.
    #[arg(short = 'd', long, default_value_t = OnOff::Off)]
    pub send_data: OnOff,

    /// Path of the cgroup where the fault injection is going to be generated.
    #[arg(short = 'g', long, default_value = "/mnt/cgroup2")]
    pub cgroup_path: String,

    /// Path of the file containing the flow configuration to be applied to all flows.
    #[arg(
        short = 'f',
        long,
        default_value = "tcp-tester/src/config/packet_loss.json"
    )]
    pub config_file_path: String,
}
