// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{utils::MinNonZero, SockOpsContext};
use bitflags::bitflags;

pub type SockKey = u64;
pub type SingletonKey = u64;
pub type Ipv6Bytes = [u8; 16];

pub const SINGLETON_KEY: u64 = 1;
pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[cfg_attr(not(feature = "bpf"), derive(serde::Serialize))]
pub struct CpuSockKey {
    pub cpu_id: u64,
    pub sock_key: SockKey,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(not(feature = "bpf"), derive(serde::Serialize))]
pub struct ControlData {
    pub sampling_interval: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, PartialOrd)]
#[cfg_attr(not(feature = "bpf"), derive(serde::Deserialize, serde::Serialize))]
pub struct EventCounters {
    // Event counters.
    pub active_connect_events: u32,
    pub active_established_events: u32,
    pub passive_established_events: u32,
    pub state_change_events: u32,
    pub rtt_events: u32,
    pub retrans_events: u32,
    pub rto_events: u32,
    pub other_events: u32,
    pub socket_events: u32,

    // Error counters.
    pub sockets_invalid: u32,
    pub map_insertion_errors: u32,
    pub rtts_invalid: u32,
    pub set_flags_errors: u32,
    pub other_errors: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(not(feature = "bpf"), derive(serde::Serialize))]
pub struct SockContext {
    pub local_ipv4: u32,
    pub remote_ipv4: u32,
    pub local_ipv6: Ipv6Bytes,
    pub remote_ipv6: Ipv6Bytes,
    pub local_port: u16,
    pub remote_port: u16,
    pub address_family: u32,
    pub is_client: bool,

    // Pad the struct length to a multiple of 8 to appease the verifier.
    pub _pad: [u8; 3],
}

bitflags! {
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[cfg_attr(not(feature = "bpf"), derive(serde::Serialize))]
    pub struct SockStateFlags: u32 {
        // Types of states the socket has been in.
        const ENTERED_ESTABLISH = 1 << 1;
        const STARTED_CLOSURE = 1 << 2;

        // Transitions the socket has gone through.
        const TERMINATED_FROM_SYN = 1 << 3;
        const TERMINATED_FROM_EST = 1 << 4;

        // Is the socket ready to be evicted (meaning in state CLOSED or LISTEN).
        const CLOSED = 1 << 5;
    }
}

// Stats directly copied from a `bpf_sock_ops` structure.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "bpf"), derive(Default))]
pub struct SockOpsStats {
    pub bytes_received: u64,
    pub bytes_acked: u64,
    pub segments_received: u32,
    pub segments_delivered: u32,
    pub srtt_us: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[cfg_attr(not(feature = "bpf"), derive(serde::Serialize))]
pub struct SockStats {
    pub last_touched_us: u64,
    pub connect_start_us: u64,
    pub connect_end_us: u64,

    pub bytes_received: u64,
    pub bytes_delivered: u64,
    pub segments_received: u32,
    pub segments_delivered: u32,

    pub rtt_count: u32,
    pub rtt_latest_us: u32,
    pub rtt_smoothed_us: u32,

    pub retrans_syn: u32,
    pub retrans_est: u32,
    pub retrans_close: u32,

    pub rtos_syn: u32,
    pub rtos_est: u32,
    pub rtos_close: u32,

    pub state_flags: SockStateFlags,

    pub connect_attempts: u8,
    pub connect_successes: u8,

    // Keep the struct size a multiple of 8 bytes to allow the eBPF verifier to confirm all bytes
    // are initialized.
    pub _pad: [u8; 6],
}

impl SockStats {
    pub fn new() -> SockStats {
        SockStats::default()
    }

    // Adds stats from one CPU core to the current stats (from another core for the same socket).
    pub fn add_from(&mut self, other: &SockStats, last_agg_timestamp: u64) {
        // If a certain core only handled this socket in the distant past, we don't want its old
        // RTT measurement to inaccurately skew results within the current aggregation window.
        // Thus, we'll accept a core's RTTs only if it has seen newer events for this socket.
        if other.last_touched_us >= last_agg_timestamp {
            if self.last_touched_us >= last_agg_timestamp {
                self.rtt_latest_us = self.rtt_latest_us.min_non_zero(other.rtt_latest_us);
                self.rtt_smoothed_us = self.rtt_smoothed_us.max(other.rtt_smoothed_us);
            } else {
                self.rtt_latest_us = other.rtt_latest_us;
                self.rtt_smoothed_us = other.rtt_smoothed_us;
            }
        }

        // Timestamps and flags represent latest observations, so we take the max or the union.
        self.last_touched_us = self.last_touched_us.max(other.last_touched_us);
        self.connect_start_us = self.connect_start_us.max(other.connect_start_us);
        self.connect_end_us = self.connect_end_us.max(other.connect_end_us);
        self.state_flags |= other.state_flags;

        // Certain counters are accumulated per socket by the kernel, so no summation needed.
        self.bytes_received = self.bytes_received.max(other.bytes_received);
        self.bytes_delivered = self.bytes_delivered.max(other.bytes_delivered);
        self.segments_received = self.segments_received.max(other.segments_received);
        self.segments_delivered = self.segments_delivered.max(other.segments_delivered);

        // Other counters are accumulated by our BPF layer, and must be summed across CPU cores.
        self.retrans_syn += other.retrans_syn;
        self.retrans_est += other.retrans_est;
        self.retrans_close += other.retrans_close;

        self.rtos_syn += other.rtos_syn;
        self.rtos_est += other.rtos_est;
        self.rtos_close += other.rtos_close;

        self.rtt_count += other.rtt_count;
        self.connect_attempts += other.connect_attempts;
        self.connect_successes += other.connect_successes;
    }

    pub fn subtract(&self, rhs: &SockStats) -> SockStats {
        SockStats {
            // Preserve values that are not counters.
            last_touched_us: self.last_touched_us,
            connect_start_us: self.connect_start_us,
            connect_end_us: self.connect_end_us,
            state_flags: self.state_flags,
            rtt_latest_us: self.rtt_latest_us,
            rtt_smoothed_us: self.rtt_smoothed_us,

            // Take the delta of all values that are counters.
            bytes_received: self.bytes_received.wrapping_sub(rhs.bytes_received),
            bytes_delivered: self.bytes_delivered.wrapping_sub(rhs.bytes_delivered),
            segments_received: self.segments_received.wrapping_sub(rhs.segments_received),
            segments_delivered: self.segments_delivered.wrapping_sub(rhs.segments_delivered),
            rtt_count: self.rtt_count.wrapping_sub(rhs.rtt_count),

            retrans_syn: self.retrans_syn.wrapping_sub(rhs.retrans_syn),
            retrans_est: self.retrans_est.wrapping_sub(rhs.retrans_est),
            retrans_close: self.retrans_close.wrapping_sub(rhs.retrans_close),

            rtos_syn: self.rtos_syn.wrapping_sub(rhs.rtos_syn),
            rtos_est: self.rtos_est.wrapping_sub(rhs.rtos_est),
            rtos_close: self.rtos_close.wrapping_sub(rhs.rtos_close),

            connect_attempts: self.connect_attempts.wrapping_sub(rhs.connect_attempts),
            connect_successes: self.connect_successes.wrapping_sub(rhs.connect_successes),

            ..Default::default()
        }
    }

    pub fn connect_us(&self) -> Option<u32> {
        if self.connect_start_us > 0 && self.connect_end_us > self.connect_start_us {
            Some((self.connect_end_us - self.connect_start_us) as u32)
        } else {
            None
        }
    }

    pub fn is_closed(&self) -> bool {
        self.state_flags.contains(SockStateFlags::CLOSED)
    }
}

impl SockContext {
    pub fn from_sock_ops(ctx: &SockOpsContext, is_client: bool) -> SockContext {
        // Note that the local port is expected to be in host byte order.
        let remote_port = u32::from_be(ctx.remote_port());
        let local_port = ctx.local_port();

        SockContext {
            is_client,
            address_family: ctx.family(),
            local_ipv4: u32::from_be(ctx.local_ip4()),
            remote_ipv4: u32::from_be(ctx.remote_ip4()),
            local_ipv6: SockContext::ipv6_to_bytes(ctx.local_ip6()),
            remote_ipv6: SockContext::ipv6_to_bytes(ctx.remote_ip6()),
            local_port: local_port.try_into().unwrap(),
            remote_port: remote_port.try_into().unwrap(),
            ..Default::default()
        }
    }

    pub fn service_port(&self) -> u16 {
        if self.is_client {
            self.remote_port
        } else {
            self.local_port
        }
    }

    pub fn ipv6_to_bytes(parts: [u32; 4]) -> Ipv6Bytes {
        let mut bytes: Ipv6Bytes = [0; 16];
        for (i, part) in parts.iter().enumerate() {
            // Copy each byte, least-significant first, into the byte array left to right.
            for j in 0..4 {
                bytes[i * 4 + j] = (part >> (8 * j)) as u8;
            }
        }

        bytes
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.address_family, AF_INET | AF_INET6)
    }
}

impl EventCounters {
    // Adds to the current set of counters.
    pub fn add_from(&mut self, other: &EventCounters) {
        self.active_connect_events = self
            .active_connect_events
            .wrapping_add(other.active_connect_events);
        self.active_established_events = self
            .active_established_events
            .wrapping_add(other.active_established_events);
        self.passive_established_events = self
            .passive_established_events
            .wrapping_add(other.passive_established_events);
        self.state_change_events = self
            .state_change_events
            .wrapping_add(other.state_change_events);
        self.rtt_events = self.rtt_events.wrapping_add(other.rtt_events);
        self.retrans_events = self.retrans_events.wrapping_add(other.retrans_events);
        self.rto_events = self.rto_events.wrapping_add(other.rto_events);
        self.other_events = self.other_events.wrapping_add(other.other_events);
        self.socket_events = self.socket_events.wrapping_add(other.socket_events);

        self.sockets_invalid = self.sockets_invalid.wrapping_add(other.sockets_invalid);
        self.map_insertion_errors = self
            .map_insertion_errors
            .wrapping_add(other.map_insertion_errors);
        self.rtts_invalid = self.rtts_invalid.wrapping_add(other.rtts_invalid);
        self.set_flags_errors = self.set_flags_errors.wrapping_add(other.set_flags_errors);
        self.other_errors = self.other_errors.wrapping_add(other.other_errors);
    }

    // Returns a new set of counters as the difference between the current set and those supplied.
    pub fn subtract(&self, rhs: &EventCounters) -> EventCounters {
        EventCounters {
            active_connect_events: self
                .active_connect_events
                .wrapping_sub(rhs.active_connect_events),
            active_established_events: self
                .active_established_events
                .wrapping_sub(rhs.active_established_events),
            passive_established_events: self
                .passive_established_events
                .wrapping_sub(rhs.passive_established_events),
            state_change_events: self
                .state_change_events
                .wrapping_sub(rhs.state_change_events),
            rtt_events: self.rtt_events.wrapping_sub(rhs.rtt_events),
            retrans_events: self.retrans_events.wrapping_sub(rhs.retrans_events),
            rto_events: self.rto_events.wrapping_sub(rhs.rto_events),
            other_events: self.other_events.wrapping_sub(rhs.other_events),
            socket_events: self.socket_events.wrapping_sub(rhs.socket_events),

            sockets_invalid: self.sockets_invalid.wrapping_sub(rhs.sockets_invalid),
            map_insertion_errors: self
                .map_insertion_errors
                .wrapping_sub(rhs.map_insertion_errors),
            rtts_invalid: self.rtts_invalid.wrapping_sub(rhs.rtts_invalid),
            set_flags_errors: self.set_flags_errors.wrapping_sub(rhs.set_flags_errors),
            other_errors: self.other_errors.wrapping_sub(rhs.other_errors),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::SockOpsContext;

    use super::{
        EventCounters, Ipv6Bytes, SockContext, SockStateFlags, SockStats, AF_INET, AF_INET6,
    };

    #[test]
    fn test_sock_context_is_valid() {
        let mut sock_ctx = SockContext::default();
        assert!(!sock_ctx.is_valid());

        sock_ctx.address_family = AF_INET;
        assert!(sock_ctx.is_valid());

        sock_ctx.address_family = AF_INET6;
        assert!(sock_ctx.is_valid());
    }

    #[test]
    fn test_sock_stats_add_with_last_agg_timestamp() {
        let stats1 = SockStats {
            last_touched_us: 100,
            rtt_count: 5,
            rtt_latest_us: 20,
            rtt_smoothed_us: 30,
            ..Default::default()
        };
        let stats2 = SockStats {
            last_touched_us: 200,
            rtt_count: 7,
            rtt_latest_us: 25,
            rtt_smoothed_us: 35,
            ..Default::default()
        };

        // Adding with an old timestamp adds 'em all.
        let last_agg_ts: u64 = 99;
        let expected = SockStats {
            last_touched_us: 200,
            rtt_count: 12,
            rtt_latest_us: 20,
            rtt_smoothed_us: 35,
            ..Default::default()
        };
        let mut actual = stats1.clone();
        actual.add_from(&stats2, last_agg_ts);
        assert_eq!(actual, expected);
        let mut actual = stats2.clone();
        actual.add_from(&stats1, last_agg_ts);
        assert_eq!(actual, expected);

        // Adding with a last-touched on the aggregation threshold also adds 'em all.
        let last_agg_ts: u64 = stats1.last_touched_us;
        let mut actual = stats1.clone();
        actual.add_from(&stats2, last_agg_ts);
        assert_eq!(actual, expected);
        let mut actual = stats2.clone();
        actual.add_from(&stats1, last_agg_ts);
        assert_eq!(actual, expected);

        // Adding with the newest timestamp adds all fields but for RTT, using only newer stats.
        let last_agg_ts: u64 = stats2.last_touched_us;
        let expected = SockStats {
            last_touched_us: 200,
            rtt_count: 12,
            rtt_latest_us: 25,
            rtt_smoothed_us: 35,
            ..Default::default()
        };
        let mut actual = stats1.clone();
        actual.add_from(&stats2, last_agg_ts);
        assert_eq!(actual, expected);
        let mut actual = stats2.clone();
        actual.add_from(&stats1, last_agg_ts);
        assert_eq!(actual, expected);

        // Adding with all old stats leaves us with the first RTT unchanged.
        let last_agg_ts: u64 = 300;
        let expected = SockStats {
            last_touched_us: 200,
            rtt_count: 12,
            rtt_latest_us: 20,
            rtt_smoothed_us: 30,
            ..Default::default()
        };
        let mut actual = stats1.clone();
        actual.add_from(&stats2, last_agg_ts);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_sock_stats_add_from() {
        let stats1 = SockStats {
            last_touched_us: 105,
            connect_start_us: 97,
            connect_end_us: 0,

            bytes_received: 59,
            bytes_delivered: 61,
            segments_received: 73,
            segments_delivered: 79,

            rtt_count: 7,
            rtt_latest_us: 31,
            rtt_smoothed_us: 23,

            retrans_syn: 11,
            retrans_est: 12,
            retrans_close: 13,

            rtos_syn: 14,
            rtos_est: 15,
            rtos_close: 16,

            connect_attempts: 17,
            connect_successes: 18,

            ..Default::default()
        };

        let stats2 = SockStats {
            last_touched_us: 415,
            connect_start_us: 0,
            connect_end_us: 101,

            bytes_received: 67,
            bytes_delivered: 71,
            segments_received: 83,
            segments_delivered: 89,

            rtt_count: 19,
            rtt_latest_us: 37,
            rtt_smoothed_us: 29,

            retrans_syn: 17,
            retrans_est: 18,
            retrans_close: 19,

            rtos_syn: 20,
            rtos_est: 21,
            rtos_close: 22,

            connect_attempts: 23,
            connect_successes: 24,

            ..Default::default()
        };

        let expected = SockStats {
            last_touched_us: 415,
            connect_start_us: 97,
            connect_end_us: 101,

            bytes_received: 67,
            bytes_delivered: 71,
            segments_received: 83,
            segments_delivered: 89,

            rtt_count: 26,
            rtt_latest_us: 31,
            rtt_smoothed_us: 29,

            retrans_syn: 28,
            retrans_est: 30,
            retrans_close: 32,

            rtos_syn: 34,
            rtos_est: 36,
            rtos_close: 38,

            connect_attempts: 40,
            connect_successes: 42,

            ..Default::default()
        };

        let last_agg_ts: u64 = 0;
        {
            let mut stats_a = stats1.clone();
            let stats_b = stats2.clone();

            stats_a.add_from(&stats_b, last_agg_ts);
            assert_eq!(stats_a, expected);
            assert_eq!(stats_a.connect_us().unwrap(), 4);

            stats_a.add_from(&stats_b, last_agg_ts);
            assert_eq!(stats_a.rtt_count, stats2.rtt_count * 2 + stats1.rtt_count);
        }

        {
            let mut stats_a = stats2.clone();
            let stats_b = stats1.clone();

            stats_a.add_from(&stats_b, last_agg_ts);
            assert_eq!(stats_a, expected);
            assert_eq!(stats_a.connect_us().unwrap(), 4);

            stats_a.add_from(&stats_b, last_agg_ts);
            assert_eq!(stats_a.rtt_count, stats1.rtt_count * 2 + stats2.rtt_count);
        }
    }

    #[test]
    fn test_event_counters_rollover() {
        // Start with values close to the edge to test rollover.
        let original = EventCounters {
            active_connect_events: u32::MAX - 1,
            active_established_events: u32::MAX - 2,
            passive_established_events: u32::MAX - 3,
            state_change_events: u32::MAX - 4,
            rtt_events: u32::MAX - 5,
            retrans_events: u32::MAX - 6,
            rto_events: u32::MAX - 7,
            other_events: u32::MAX - 8,
            socket_events: u32::MAX - 9,

            sockets_invalid: u32::MAX - 10,
            map_insertion_errors: u32::MAX - 18,
            rtts_invalid: u32::MAX - 13,
            set_flags_errors: u32::MAX - 14,
            other_errors: u32::MAX - 15,
        };
        let additions = EventCounters {
            active_connect_events: 10,
            active_established_events: 11,
            passive_established_events: 12,
            state_change_events: 13,
            rtt_events: 14,
            retrans_events: 15,
            rto_events: 16,
            other_events: 17,
            socket_events: 18,

            sockets_invalid: 19,
            map_insertion_errors: 27,
            rtts_invalid: 22,
            set_flags_errors: 23,
            other_errors: 24,
        };

        let mut new_counters = original;
        assert_eq!(new_counters, original);

        // Perform an add to cause rollover.
        new_counters.add_from(&additions);
        assert_ne!(new_counters, original);

        // Confirm subtraction still yields the values we added.
        let delta = new_counters.subtract(&original);
        assert_eq!(delta, additions);
    }

    #[test]
    fn test_sock_context_from_network_byte_order() {
        let actual_sock_ops_context = SockOpsContext {
            family: 2,
            local_port: 20,
            remote_port: 184549376,
            local_ip4: 318767104,
            remote_ip4: 1325400064,
            local_ip6: [0x01010101; 4],
            remote_ip6: [0x01010101; 4],
            ..Default::default()
        };
        let actual = SockContext::from_sock_ops(&actual_sock_ops_context, true);

        let expected = SockContext {
            is_client: true,
            address_family: 2,
            local_port: 20,

            remote_port: 11,
            local_ipv4: 19,
            remote_ipv4: 79,
            local_ipv6: [1; 16],
            remote_ipv6: [1; 16],
            ..Default::default()
        };

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_port_edge_cases() {
        let port_to_test: Vec<u16> = vec![0, 1, 500, 35_000, 65_535];
        for port in port_to_test {
            let actual_sock_ops_context = SockOpsContext {
                family: 2,
                local_port: port as u32,
                remote_port: u32::to_be(port as u32),
                local_ip4: 318767104,
                remote_ip4: 1325400064,
                local_ip6: [0x01010101; 4],
                remote_ip6: [0x01010101; 4],
                ..Default::default()
            };
            let actual = SockContext::from_sock_ops(&actual_sock_ops_context, true);
            assert_eq!(actual.local_port, port);
            assert_eq!(actual.remote_port, port);
        }
    }

    #[test]
    fn test_ipv6_to_bytes() {
        let v6_quads: [u32; 4] = [67305985, 134678021, 202050057, 269422093];

        // Expect byte values 1 thru 16.
        let mut expected: Ipv6Bytes = [0; 16];
        for (i, item) in expected.iter_mut().enumerate() {
            *item = (i + 1) as u8;
        }

        let actual = SockContext::ipv6_to_bytes(v6_quads);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_sock_stats_subtract() {
        let stats_a = SockStats {
            last_touched_us: 10,
            connect_start_us: 20,
            connect_end_us: 30,
            bytes_received: 40,
            bytes_delivered: 50,
            segments_received: 150,
            segments_delivered: 160,
            rtt_count: 60,
            rtt_latest_us: 70,
            rtt_smoothed_us: 80,
            retrans_syn: 90,
            retrans_est: 100,
            retrans_close: 110,
            rtos_syn: 120,
            rtos_est: 130,
            rtos_close: 140,
            connect_attempts: 150,
            connect_successes: 160,
            state_flags: SockStateFlags::STARTED_CLOSURE,
            ..Default::default()
        };
        let stats_b = SockStats {
            last_touched_us: 1,
            connect_start_us: 2,
            connect_end_us: 3,
            bytes_received: 4,
            bytes_delivered: 5,
            segments_received: 15,
            segments_delivered: 16,
            rtt_count: 6,
            rtt_latest_us: 7,
            rtt_smoothed_us: 8,
            retrans_syn: 9,
            retrans_est: 10,
            retrans_close: 11,
            rtos_syn: 12,
            rtos_est: 13,
            rtos_close: 14,
            connect_attempts: 15,
            connect_successes: 16,
            state_flags: SockStateFlags::ENTERED_ESTABLISH,
            ..Default::default()
        };

        // Test a typical diff.
        let expected_diff = SockStats {
            bytes_received: 36,
            bytes_delivered: 45,
            segments_received: 135,
            segments_delivered: 144,
            rtt_count: 54,
            retrans_syn: 81,
            retrans_est: 90,
            retrans_close: 99,
            rtos_syn: 108,
            rtos_est: 117,
            rtos_close: 126,
            connect_attempts: 135,
            connect_successes: 144,
            ..stats_a
        };
        let actual_diff = stats_a.subtract(&stats_b);
        assert_eq!(actual_diff, expected_diff);

        // Test values having wrapped around.
        let expected_diff_wrapped = SockStats {
            bytes_received: u64::MAX - expected_diff.bytes_received + 1,
            bytes_delivered: u64::MAX - expected_diff.bytes_delivered + 1,
            segments_received: u32::MAX - expected_diff.segments_received + 1,
            segments_delivered: u32::MAX - expected_diff.segments_delivered + 1,
            rtt_count: u32::MAX - expected_diff.rtt_count + 1,
            retrans_syn: u32::MAX - expected_diff.retrans_syn + 1,
            retrans_est: u32::MAX - expected_diff.retrans_est + 1,
            retrans_close: u32::MAX - expected_diff.retrans_close + 1,
            rtos_syn: u32::MAX - expected_diff.rtos_syn + 1,
            rtos_est: u32::MAX - expected_diff.rtos_est + 1,
            rtos_close: u32::MAX - expected_diff.rtos_close + 1,
            connect_attempts: u8::MAX - expected_diff.connect_attempts + 1,
            connect_successes: u8::MAX - expected_diff.connect_successes + 1,
            ..stats_b
        };
        let actual_diff_wrapped = stats_b.subtract(&stats_a);
        assert_eq!(actual_diff_wrapped, expected_diff_wrapped);
    }
}
