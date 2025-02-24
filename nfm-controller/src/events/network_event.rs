// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{add_histogram_to_report, utils::report::to_value_pairs};
use crate::{
    kubernetes::flow_metadata::FlowMetadata,
    reports::report::{MetricHistogram, ReportValue},
};
use nfm_common::{
    network::{SockContext, SockStats, AF_INET, AF_INET6},
    MinNonZero, SockStateFlags,
};

use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use std::{
    convert::TryFrom,
    fmt,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const ELIDED_PORT: u16 = 0;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Serialize)]
pub enum InetProtocol {
    ANY,
    TCP,
    UDP,
}

// Represents the properties by which flows are grouped. Properties aggregated across carry their
// empty value.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd)]
pub struct FlowProperties {
    pub protocol: InetProtocol,
    pub local_address: IpAddr,
    pub remote_address: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub kubernetes_metadata: Option<FlowMetadata>,
}

impl FlowProperties {
    pub fn enumerate(&self) -> Vec<(String, ReportValue)> {
        let mut values = to_value_pairs(self);
        if let Some(metadata) = self.kubernetes_metadata.as_ref() {
            values.extend(metadata.enumerate());
        }
        values
    }

    // Returns true if this flow is an aggregation of many local socket connections towards a single remote socket
    // Or, if the local party (this host) is the initiator of this flow. Check BPF_SOCK_OPS_TCP_CONNECT_CB event for details.
    pub fn is_client_flow(&self) -> bool {
        self.local_port == ELIDED_PORT
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, PartialOrd, Serialize)]
pub struct NetworkStats {
    // These are levels that represent states at a single point in time.
    pub sockets_connecting: u32,
    pub sockets_established: u32,
    pub sockets_closing: u32,
    pub sockets_closed: u32,

    // These are counters that accumulate throughout a publishing window.
    pub sockets_completed: u32,
    pub severed_connect: u32,
    pub severed_establish: u32,

    pub connect_attempts: u32,
    pub bytes_received: u64,
    pub bytes_delivered: u64,
    pub segments_received: u64,
    pub segments_delivered: u64,

    pub retrans_syn: u32,
    pub retrans_est: u32,
    pub retrans_close: u32,

    pub rtos_syn: u32,
    pub rtos_est: u32,
    pub rtos_close: u32,

    // These are timing statistics based on events across sockets within the publishing window.
    pub connect_us: MetricHistogram,
    pub rtt_us: MetricHistogram,
    pub rtt_smoothed_us: MetricHistogram,
}

#[derive(Clone, Debug, Deserialize, PartialEq, PartialOrd, Serialize)]
pub struct AggregateResults {
    // The properties by which flows have been grouped to perform aggregation.
    pub flow: FlowProperties,

    // Statistic values from aggregating over all flows matching the above flow properties.
    pub stats: NetworkStats,
}

impl NetworkStats {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_received.saturating_add(self.bytes_delivered)
    }

    pub fn retrans_total(&self) -> u32 {
        self.retrans_syn
            .saturating_add(self.retrans_est)
            .saturating_add(self.retrans_close)
    }

    pub fn rtos_total(&self) -> u32 {
        self.rtos_syn
            .saturating_add(self.rtos_est)
            .saturating_add(self.rtos_close)
    }

    pub fn quantify_loss(&self) -> u32 {
        const SCALE_FACTOR: u32 = 2;
        self.retrans_total()
            .saturating_add(self.rtos_total().saturating_mul(SCALE_FACTOR))
            .saturating_add(
                (self.severed_connect.saturating_add(self.severed_establish))
                    .saturating_mul(SCALE_FACTOR * SCALE_FACTOR),
            )
    }

    pub fn enumerate(&self) -> Vec<(String, ReportValue)> {
        let mut report = to_value_pairs(self);
        add_histogram_to_report!(self, connect_us, report);
        add_histogram_to_report!(self, rtt_us, report);
        add_histogram_to_report!(self, rtt_smoothed_us, report);

        report
    }

    // Adds a socket's stats to a flow's stats.
    pub fn add_from(&mut self, sock_stats: &SockStats) {
        self.update_sock_counters(sock_stats);

        // We're aggregating across sockets into flows, so we must be sure to sum even across
        // fields that are cumulative on the socket.
        self.connect_attempts = self
            .connect_attempts
            .saturating_add(sock_stats.connect_attempts.into());
        self.bytes_received = self
            .bytes_received
            .saturating_add(sock_stats.bytes_received);
        self.bytes_delivered = self
            .bytes_delivered
            .saturating_add(sock_stats.bytes_delivered);
        self.segments_received = self
            .segments_received
            .saturating_add(sock_stats.segments_received.into());
        self.segments_delivered = self
            .segments_delivered
            .saturating_add(sock_stats.segments_delivered.into());

        self.retrans_syn = self.retrans_syn.saturating_add(sock_stats.retrans_syn);
        self.retrans_est = self.retrans_est.saturating_add(sock_stats.retrans_est);
        self.retrans_close = self.retrans_close.saturating_add(sock_stats.retrans_close);

        self.rtos_syn = self.rtos_syn.saturating_add(sock_stats.rtos_syn);
        self.rtos_est = self.rtos_est.saturating_add(sock_stats.rtos_est);
        self.rtos_close = self.rtos_close.saturating_add(sock_stats.rtos_close);

        // Carry forward timing measurements only if the socket actually saw their corresponding
        // events during this period.
        if sock_stats.connect_successes > 0 {
            if let Some(connect_us) = sock_stats.connect_us() {
                self.connect_us.count = self
                    .connect_us
                    .count
                    .saturating_add(sock_stats.connect_successes.into());
                self.connect_us.min = self.connect_us.min.min_non_zero(connect_us);
                self.connect_us.max = self.connect_us.max.max(connect_us);
                self.connect_us.sum = self.connect_us.sum.saturating_add(connect_us.into());
            }
        }
        if sock_stats.rtt_count > 0 {
            // We're about to add one new RTT meaurement to our sum, hence the count of RTTs
            // sampled into this flow will rise by one.
            let rtt_count = 1;

            if sock_stats.rtt_latest_us > 0 {
                self.rtt_us.count = self.rtt_us.count.saturating_add(rtt_count);
                self.rtt_us.min = self.rtt_us.min.min_non_zero(sock_stats.rtt_latest_us);
                self.rtt_us.max = self.rtt_us.max.max(sock_stats.rtt_latest_us);
                self.rtt_us.sum = self
                    .rtt_us
                    .sum
                    .saturating_add(sock_stats.rtt_latest_us.into());
            }
            if sock_stats.rtt_smoothed_us > 0 {
                self.rtt_smoothed_us.count = self.rtt_smoothed_us.count.saturating_add(rtt_count);
                self.rtt_smoothed_us.min = self
                    .rtt_smoothed_us
                    .min
                    .min_non_zero(sock_stats.rtt_smoothed_us);
                self.rtt_smoothed_us.max = self.rtt_smoothed_us.max.max(sock_stats.rtt_smoothed_us);
                self.rtt_smoothed_us.sum = self
                    .rtt_smoothed_us
                    .sum
                    .saturating_add(sock_stats.rtt_smoothed_us.into());
            }
        }
    }

    pub fn clear_levels(&mut self) {
        self.sockets_connecting = 0;
        self.sockets_established = 0;
        self.sockets_closing = 0;
        self.sockets_closed = 0;
    }

    pub fn update_sock_counters(&mut self, sock_stats: &SockStats) {
        if !sock_stats
            .state_flags
            .contains(SockStateFlags::STARTED_CLOSURE)
        {
            if sock_stats
                .state_flags
                .contains(SockStateFlags::ENTERED_ESTABLISH)
            {
                self.sockets_established += 1;
            } else {
                self.sockets_connecting += 1;
            }
        } else {
            if sock_stats.state_flags.contains(SockStateFlags::CLOSED) {
                self.sockets_closed += 1;
            } else {
                self.sockets_closing += 1;
            }
            if sock_stats
                .state_flags
                .contains(SockStateFlags::TERMINATED_FROM_SYN)
            {
                self.severed_connect += 1;
            } else if sock_stats
                .state_flags
                .contains(SockStateFlags::TERMINATED_FROM_EST)
            {
                self.severed_establish += 1;
            }
        }
    }
}

impl TryFrom<&SockContext> for FlowProperties {
    type Error = String;

    fn try_from(context: &SockContext) -> Result<FlowProperties, Self::Error> {
        let (local_address, remote_address) = match context.address_family {
            AF_INET => (
                IpAddr::V4(Ipv4Addr::from(context.local_ipv4)),
                IpAddr::V4(Ipv4Addr::from(context.remote_ipv4)),
            ),
            AF_INET6 => (
                IpAddr::V6(Ipv6Addr::from(context.local_ipv6)),
                IpAddr::V6(Ipv6Addr::from(context.remote_ipv6)),
            ),
            _ => {
                return Err(format!(
                    "Unsupported address family: {}",
                    context.address_family,
                ));
            }
        };

        // We aggregate sockets into 4-tuples (across client ports), hence the client port is elided.
        let (local_port, remote_port) = if context.is_client {
            (ELIDED_PORT, context.remote_port)
        } else {
            (context.local_port, ELIDED_PORT)
        };

        Ok(FlowProperties {
            protocol: InetProtocol::TCP,
            local_address,
            remote_address,
            local_port,
            remote_port,
            kubernetes_metadata: None,
        })
    }
}

impl Serialize for FlowProperties {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FlowProperties", 5)?;
        state.serialize_field("protocol", &self.protocol.to_string())?;
        state.serialize_field("local_address", &self.local_address.to_string())?;
        state.serialize_field("remote_address", &self.remote_address.to_string())?;
        state.serialize_field("local_port", &self.local_port)?;
        state.serialize_field("remote_port", &self.remote_port)?;
        state.end()
    }
}

impl fmt::Display for InetProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InetProtocol::ANY => write!(f, "ANY"),
            InetProtocol::TCP => write!(f, "TCP"),
            InetProtocol::UDP => write!(f, "UDP"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::reports::report::MetricHistogram;
    use nfm_common::network::{SockStateFlags, SockStats};

    #[test]
    fn test_from_sock_context_v4() {
        let context = SockContext {
            address_family: AF_INET,
            local_ipv4: 16909060,
            remote_ipv4: 16909060,
            local_port: 9,
            remote_port: 10,
            is_client: true,
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            ..Default::default()
        };
        let properties = FlowProperties::try_from(&context).unwrap();
        assert_eq!(
            properties,
            FlowProperties {
                protocol: InetProtocol::TCP,
                local_address: IpAddr::V4(Ipv4Addr::from([1, 2, 3, 4])),
                remote_address: IpAddr::V4(Ipv4Addr::from([1, 2, 3, 4])),
                local_port: ELIDED_PORT,
                remote_port: 10,
                kubernetes_metadata: None,
            }
        );

        assert!(properties.is_client_flow() == true);
    }

    #[test]
    fn test_from_sock_context_v6() {
        let context = SockContext {
            address_family: AF_INET6,
            local_ipv6: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            remote_ipv6: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            local_port: 9,
            remote_port: 10,
            is_client: true,
            local_ipv4: 0,
            remote_ipv4: 0,
            ..Default::default()
        };
        let properties = FlowProperties::try_from(&context).unwrap();
        assert_eq!(
            properties,
            FlowProperties {
                protocol: InetProtocol::TCP,
                local_address: IpAddr::V6(Ipv6Addr::from([
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
                ])),
                remote_address: IpAddr::V6(Ipv6Addr::from([
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
                ])),
                local_port: ELIDED_PORT,
                remote_port: 10,
                kubernetes_metadata: None,
            }
        );
    }

    #[test]
    fn test_from_sock_context_invalid_address_family() {
        let context = SockContext {
            address_family: 99, // Any
            local_ipv6: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            remote_ipv6: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            local_port: 9,
            remote_port: 10,
            is_client: true,
            local_ipv4: 0,
            remote_ipv4: 0,
            ..Default::default()
        };
        assert!(FlowProperties::try_from(&context).is_err());
    }

    #[test]
    fn test_sock_to_flow_rtt_add() {
        // No RTT measurements taken.
        let mut net_stats = NetworkStats {
            rtt_us: MetricHistogram {
                count: 0,
                min: 0,
                max: 0,
                sum: 0,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 0,
                min: 0,
                max: 0,
                sum: 0,
            },
            ..Default::default()
        };
        let sock_stats = SockStats {
            rtt_count: 0,
            rtt_latest_us: 0,
            rtt_smoothed_us: 0,
            ..Default::default()
        };

        let expected_net_stats = NetworkStats {
            sockets_connecting: 1,
            rtt_us: MetricHistogram {
                count: 0,
                min: 0,
                max: 0,
                sum: 0,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 0,
                min: 0,
                max: 0,
                sum: 0,
            },
            ..Default::default()
        };
        net_stats.add_from(&sock_stats);
        assert_eq!(net_stats, expected_net_stats);

        // RTTs with no count.
        let sock_stats = SockStats {
            rtt_count: 0,
            rtt_latest_us: 1,
            rtt_smoothed_us: 2,
            ..Default::default()
        };
        let expected_net_stats = NetworkStats {
            sockets_connecting: 2,
            rtt_us: MetricHistogram {
                count: 0,
                min: 0,
                max: 0,
                sum: 0,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 0,
                min: 0,
                max: 0,
                sum: 0,
            },
            ..Default::default()
        };
        net_stats.add_from(&sock_stats);
        assert_eq!(net_stats, expected_net_stats);

        // A new min and max.
        let sock_stats = SockStats {
            rtt_count: 1,
            rtt_latest_us: 10,
            rtt_smoothed_us: 3,
            ..Default::default()
        };
        let expected_net_stats = NetworkStats {
            sockets_connecting: 3,
            rtt_us: MetricHistogram {
                count: 1,
                min: 10,
                max: 10,
                sum: 10,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 1,
                min: 3,
                max: 3,
                sum: 3,
            },
            ..Default::default()
        };
        net_stats.add_from(&sock_stats);
        assert_eq!(net_stats, expected_net_stats);

        // A new min, but no smoothed measurement.  Notice that multiple RTT occurrences increase
        // our sampled count by just 1.
        let sock_stats = SockStats {
            rtt_count: 12,
            rtt_latest_us: 5,
            ..Default::default()
        };
        let expected_net_stats = NetworkStats {
            sockets_connecting: 4,
            rtt_us: MetricHistogram {
                count: 2,
                min: 5,
                max: 10,
                sum: 15,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 1,
                min: 3,
                max: 3,
                sum: 3,
            },
            ..Default::default()
        };
        net_stats.add_from(&sock_stats);
        assert_eq!(net_stats, expected_net_stats);

        // A new max with multiple observations, leading to one sampled.
        let sock_stats = SockStats {
            rtt_count: 29,
            rtt_latest_us: 20,
            rtt_smoothed_us: 25,
            ..Default::default()
        };
        let expected_net_stats = NetworkStats {
            sockets_connecting: 5,
            rtt_us: MetricHistogram {
                count: 3,
                min: 5,
                max: 20,
                sum: 35,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 2,
                min: 3,
                max: 25,
                sum: 28,
            },
            ..Default::default()
        };
        net_stats.add_from(&sock_stats);
        assert_eq!(net_stats, expected_net_stats);
    }

    #[test]
    fn test_network_stats_add_from() {
        let mut net_stats = NetworkStats {
            sockets_connecting: 20,
            sockets_established: 60,
            sockets_closing: 5,
            sockets_closed: 15,

            sockets_completed: 9,
            severed_connect: 4,
            severed_establish: 2,

            connect_attempts: 56,
            bytes_received: 59,
            bytes_delivered: 61,
            segments_received: 73,
            segments_delivered: 79,

            connect_us: MetricHistogram {
                count: 57,
                min: 20,
                max: 25,
                sum: 1250,
            },
            rtt_us: MetricHistogram {
                count: 11,
                min: 29,
                max: 31,
                sum: 350,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 11,
                min: 50,
                max: 100,
                sum: 1000,
            },

            retrans_syn: 50,
            retrans_est: 51,
            retrans_close: 52,
            rtos_syn: 53,
            rtos_est: 54,
            rtos_close: 55,
        };
        let sock_stats = SockStats {
            last_touched_us: 451,
            connect_start_us: 101,
            connect_end_us: 127,
            bytes_received: 67,
            bytes_delivered: 71,
            segments_received: 83,
            segments_delivered: 89,
            state_flags: SockStateFlags::ENTERED_ESTABLISH
                | SockStateFlags::STARTED_CLOSURE
                | SockStateFlags::CLOSED,

            rtt_count: 3,
            rtt_latest_us: 25,
            rtt_smoothed_us: 40,

            retrans_syn: 10,
            retrans_est: 1,
            retrans_close: 2,
            rtos_syn: 3,
            rtos_est: 4,
            rtos_close: 5,

            connect_attempts: 6,
            connect_successes: 7,

            ..Default::default()
        };

        let expected = NetworkStats {
            sockets_connecting: 20,
            sockets_established: 60,
            sockets_closing: 5,
            sockets_closed: 16,

            sockets_completed: 9,
            severed_connect: 4,
            severed_establish: 2,

            connect_attempts: 62,
            bytes_received: 126,
            bytes_delivered: 132,
            segments_received: 156,
            segments_delivered: 168,

            connect_us: MetricHistogram {
                count: 64,
                min: 20,
                max: 26,
                sum: 1276,
            },
            rtt_us: MetricHistogram {
                count: 12,
                min: 25,
                max: 31,
                sum: 375,
            },
            rtt_smoothed_us: MetricHistogram {
                count: 12,
                min: 40,
                max: 100,
                sum: 1040,
            },

            retrans_syn: 60,
            retrans_est: 52,
            retrans_close: 54,
            rtos_syn: 56,
            rtos_est: 58,
            rtos_close: 60,
        };

        net_stats.add_from(&sock_stats);
        assert_eq!(net_stats, expected);

        net_stats.add_from(&sock_stats);
        assert_eq!(
            net_stats.bytes_delivered,
            sock_stats.bytes_delivered * 2 + 61
        );
        assert_eq!(net_stats.connect_us.max, 26);
    }

    #[test]
    fn test_quantify_loss() {
        let mut stats = NetworkStats::default();
        assert_eq!(stats.quantify_loss(), 0);

        stats.bytes_received = 100;
        assert_eq!(stats.quantify_loss(), 0);

        stats.rtt_us.count = 50;
        assert_eq!(stats.quantify_loss(), 0);

        stats.retrans_syn = 1;
        let loss_a1 = stats.quantify_loss();

        stats.retrans_syn = 0;
        stats.retrans_est = 1;
        let loss_a2 = stats.quantify_loss();

        stats.retrans_est = 0;
        stats.retrans_close = 1;
        let loss_a3 = stats.quantify_loss();

        stats.retrans_close = 0;
        stats.rtos_syn = 1;
        let loss_b1 = stats.quantify_loss();

        stats.rtos_syn = 0;
        stats.rtos_est = 1;
        let loss_b2 = stats.quantify_loss();

        stats.rtos_est = 0;
        stats.rtos_close = 1;
        let loss_b3 = stats.quantify_loss();

        stats.rtos_close = 0;
        stats.severed_connect = 1;
        let loss_c = stats.quantify_loss();

        stats.retrans_syn = 1;
        stats.rtos_syn = 1;
        stats.severed_connect = 1;
        let loss_d = stats.quantify_loss();

        assert!(loss_d > loss_c);
        assert!(loss_c > loss_b1);
        assert!(loss_b1 > loss_a1);

        assert_eq!(loss_a2, loss_a1);
        assert_eq!(loss_a3, loss_a1);
        assert_eq!(loss_b2, loss_b1);
        assert_eq!(loss_b3, loss_b1);
    }
}
