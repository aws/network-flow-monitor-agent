// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This module contains scaffolding used to interact with the eBPF subsystem through Aya, and is
 * excluded from compilation into user-space packages.  Everything here has counterparts within the
 * `ebpf_mocks` module.
 */

use crate::constants::{MAX_ENTRIES_SK_PROPS_LO, MAX_ENTRIES_SK_STATS_LO};
use crate::network::{
    ControlData, CpuSockKey, EventCounters, SingletonKey, SockContext, SockOpsStats, SockStats,
};

use aya_ebpf::helpers::{bpf_get_smp_processor_id, bpf_get_socket_cookie, bpf_ktime_get_boot_ns};

// These imports are flagged as public to allow them to be exported to the crate root.
pub use aya_ebpf::{
    // Constants we depend on from `aya-ebpf-bindings`.
    bindings::{BPF_ANY, BPF_EXIST, BPF_F_NO_PREALLOC, BPF_NOEXIST},
    bindings::{
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_HDR_OPT_LEN_CB,
        BPF_SOCK_OPS_PARSE_HDR_OPT_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        BPF_SOCK_OPS_RETRANS_CB, BPF_SOCK_OPS_RTO_CB, BPF_SOCK_OPS_RTT_CB, BPF_SOCK_OPS_STATE_CB,
        BPF_SOCK_OPS_TCP_CONNECT_CB,
    },
    bindings::{
        BPF_SOCK_OPS_ALL_CB_FLAGS, BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG,
        BPF_SOCK_OPS_RETRANS_CB_FLAG, BPF_SOCK_OPS_RTO_CB_FLAG, BPF_SOCK_OPS_RTT_CB_FLAG,
        BPF_SOCK_OPS_STATE_CB_FLAG, BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG,
    },
    bindings::{
        BPF_TCP_CLOSE, BPF_TCP_CLOSE_WAIT, BPF_TCP_CLOSING, BPF_TCP_ESTABLISHED, BPF_TCP_FIN_WAIT1,
        BPF_TCP_FIN_WAIT2, BPF_TCP_LAST_ACK, BPF_TCP_LISTEN, BPF_TCP_SYN_RECV, BPF_TCP_SYN_SENT,
        BPF_TCP_TIME_WAIT,
    },

    helpers::bpf_get_prandom_u32,

    // The BPF_MAP interface we depend on from `aya-ebpf`.
    macros::map,
    maps::PerCpuHashMap,

    // The context passed into our eBPF SOCK_OPS program by the kernel.
    programs::SockOpsContext,

    // The trait for the as_ptr() fn.
    EbpfContext,
};

pub type SharedHashMap<K, V> = aya_ebpf::maps::HashMap<K, V>;

// *** Instances of eBPF maps used by our program, prefixed under the "NETWORK_FLOW_MONITOR" namespace. ***

// NFM_CONTROL communicates control knobs from user-space to BPF – one writer, many readers,
// never deleted from.
#[map]
pub static NFM_CONTROL: SharedHashMap<SingletonKey, ControlData> =
    SharedHashMap::with_max_entries(1, BPF_F_NO_PREALLOC);

// NFM_COUNTERS communicates events from BPF to user-space.  It is per-CPU and contents are never
// deleted.
#[map]
pub static NFM_COUNTERS: PerCpuHashMap<SingletonKey, EventCounters> =
    PerCpuHashMap::with_max_entries(1, 0);

// SK_PROPS communicates the properties of a newly established socket to user-space.  It is used as
// a signaling channel; entries are deleted by user-space once read.
#[map]
pub static NFM_SK_PROPS: SharedHashMap<CpuSockKey, SockContext> =
    SharedHashMap::with_max_entries(MAX_ENTRIES_SK_PROPS_LO as u32, BPF_F_NO_PREALLOC);

// SK_STATS is where the BPF program writes socket statistics in response to sock_ops events for
// tracked sockets.  Entries are deleted by user-space upon socket closure.
#[map]
pub static NFM_SK_STATS: SharedHashMap<CpuSockKey, SockStats> =
    SharedHashMap::with_max_entries(MAX_ENTRIES_SK_STATS_LO as u32, BPF_F_NO_PREALLOC);

// Operations on BPF maps.
#[macro_export]
macro_rules! bpf_map_get {
    ($self:ident, $map_name:expr, $key:expr) => {
        unsafe { $map_name.get($key) }
    };
}

#[macro_export]
macro_rules! bpf_map_get_ptr_mut {
    ($self:ident, $map_name:expr, $key:expr) => {
        $map_name.get_ptr_mut($key)
    };
}

#[macro_export]
macro_rules! bpf_map_insert {
    ($self:ident, $map_name:expr, $key:expr, $val:expr, $flags:expr) => {
        $map_name.insert($key, $val, <u32 as Into<u64>>::into($flags))
    };
}

#[macro_export]
macro_rules! bpf_get_rand_u32 {
    ($self:ident) => {
        unsafe { bpf_get_prandom_u32() }
    };
}

// *** BPF helper functions, prefixed under the "nfm" namespace. ***

pub fn nfm_get_cpu_id() -> u64 {
    unsafe { bpf_get_smp_processor_id().into() }
}

pub fn nfm_now_us() -> u64 {
    unsafe { bpf_ktime_get_boot_ns() / 1000 }
}

pub fn nfm_get_sock_cookie(ctx: &SockOpsContext) -> u64 {
    unsafe { bpf_get_socket_cookie(ctx.as_ptr()) }
}

pub fn nfm_get_sock_state(ctx: &SockOpsContext) -> u32 {
    unsafe { (*ctx.ops).state }
}

pub fn nfm_get_sock_ops_stats(ctx: &SockOpsContext) -> SockOpsStats {
    unsafe {
        SockOpsStats {
            bytes_received: (*ctx.ops).bytes_received,
            bytes_acked: (*ctx.ops).bytes_acked,
            segments_received: (*ctx.ops).data_segs_in,
            segments_delivered: (*ctx.ops).data_segs_out,
            srtt_us: (*ctx.ops).srtt_us >> 3,
        }
    }
}
