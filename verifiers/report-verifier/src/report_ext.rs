// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use nfm_agent::{
    events::network_event::NetworkStats,
    reports::{
        report::{MetricHistogram, UsageStats},
        ProcessCounters,
    },
};
use nfm_common::MinNonZero;

pub trait NetworkStatsExt {
    fn merge_from(&mut self, other: &NetworkStats);
}

impl NetworkStatsExt for NetworkStats {
    fn merge_from(&mut self, other: &NetworkStats) {
        self.bytes_delivered += other.bytes_delivered;
        self.bytes_received += other.bytes_received;
        self.segments_delivered += other.segments_delivered;
        self.segments_received += other.segments_received;
        self.connect_attempts += other.connect_attempts;

        self.sockets_completed += other.sockets_completed;
        self.severed_connect += other.severed_connect;
        self.severed_establish += other.severed_establish;

        self.sockets_connecting += other.sockets_connecting;
        self.sockets_established += other.sockets_established;
        self.sockets_closing += other.sockets_closing;
        self.sockets_closed += other.sockets_closed;

        self.connect_us.merge_from(&other.connect_us);
        self.rtt_smoothed_us.merge_from(&other.rtt_smoothed_us);
        self.rtt_us.merge_from(&other.rtt_us);
    }
}

pub trait MetricHistogramExt {
    fn merge_from(&mut self, other: &MetricHistogram);
}

impl MetricHistogramExt for MetricHistogram {
    fn merge_from(&mut self, other: &MetricHistogram) {
        self.count += other.count;
        self.sum += other.sum;
        self.min = self.min.min_non_zero(other.min);
        self.max = self.max.max(other.max);
    }
}

pub trait ProcessCountersExt {
    fn merge_from(&mut self, other: &ProcessCounters);
}

impl ProcessCountersExt for ProcessCounters {
    fn merge_from(&mut self, other: &ProcessCounters) {
        self.remote_nat_reversal_errors += other.remote_nat_reversal_errors;
        self.restarts += other.restarts;
        self.socket_agg_above_limit += other.socket_agg_above_limit;
        self.socket_agg_completed += other.socket_agg_completed;
        self.socket_agg_missing_props += other.socket_agg_missing_props;
        self.socket_deltas_above_limit += other.socket_deltas_above_limit;
        self.socket_deltas_completed += other.socket_deltas_completed;
        self.socket_deltas_missing_props += other.socket_deltas_missing_props;
        self.socket_eviction_completed += other.socket_eviction_completed;
        self.socket_eviction_failed += other.socket_eviction_failed;
        self.sockets_added += other.sockets_added;
        self.sockets_natd += other.sockets_natd;
        self.sockets_stale += other.sockets_stale;
    }
}

pub trait UsageStatsExt {
    fn merge_from(&mut self, other: &UsageStats);
}

impl UsageStatsExt for UsageStats {
    fn merge_from(&mut self, other: &UsageStats) {
        self.cpu_util = self.cpu_util.max(other.cpu_util);
        self.mem_used_ratio = self.mem_used_ratio.max(other.mem_used_ratio);
        self.mem_used_kb = self.mem_used_kb.max(other.mem_used_kb);
        self.sockets_tracked += other.sockets_tracked;
    }
}
