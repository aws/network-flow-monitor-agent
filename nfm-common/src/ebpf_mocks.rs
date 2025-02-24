// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This module contains scaffolding used to mock out interactions with eBPF.  The purpose is to
 * enable our sock-ops logic to be unit-testable in a user-space binary, given the lack of unit
 * test support in Aya [a].  Everything here has counterparts within the `ebpf_actuals` module.
 *
 * [a] https://github.com/aya-rs/aya/issues/36 Support Unit Testing of BPF Programs
 */

use crate::constants::{MAX_ENTRIES_SK_PROPS_HI, MAX_ENTRIES_SK_STATS_HI};
use crate::network::{
    ControlData, CpuSockKey, EventCounters, SingletonKey, SockContext, SockOpsStats, SockStats,
    SINGLETON_KEY,
};

use libc::{EINVAL, ENOMEM};
use std::collections::HashMap;
use std::hash::Hash;

pub const MOCK_CPU_ID: u64 = 199;

// Constants we depend on from `aya-ebpf-bindings`.  Note that the values here do not need to match
// those within Aya.
pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1 << 1;
pub const BPF_EXIST: u64 = 1 << 2;

pub const BPF_F_NO_PREALLOC: u32 = 1;

pub const BPF_SOCK_OPS_RETRANS_CB_FLAG: u32 = 1 << 1;
pub const BPF_SOCK_OPS_RTO_CB_FLAG: u32 = 1 << 2;
pub const BPF_SOCK_OPS_RTT_CB_FLAG: u32 = 1 << 3;
pub const BPF_SOCK_OPS_STATE_CB_FLAG: u32 = 1 << 4;
pub const BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG: u32 = 1 << 5;
pub const BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG: u32 = 1 << 6;
pub const BPF_SOCK_OPS_ALL_CB_FLAGS: u32 = 1 << 7;

pub const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 1;
pub const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 2;
pub const BPF_SOCK_OPS_RETRANS_CB: u32 = 3;
pub const BPF_SOCK_OPS_RTO_CB: u32 = 4;
pub const BPF_SOCK_OPS_RTT_CB: u32 = 5;
pub const BPF_SOCK_OPS_STATE_CB: u32 = 6;
pub const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 7;
pub const BPF_SOCK_OPS_PARSE_HDR_OPT_CB: u32 = 8;
pub const BPF_SOCK_OPS_HDR_OPT_LEN_CB: u32 = 9;

pub const BPF_TCP_CLOSE: u32 = 1;
pub const BPF_TCP_CLOSE_WAIT: u32 = 2;
pub const BPF_TCP_CLOSING: u32 = 3;
pub const BPF_TCP_ESTABLISHED: u32 = 4;
pub const BPF_TCP_FIN_WAIT1: u32 = 5;
pub const BPF_TCP_FIN_WAIT2: u32 = 6;
pub const BPF_TCP_LAST_ACK: u32 = 7;
pub const BPF_TCP_LISTEN: u32 = 8;
pub const BPF_TCP_SYN_RECV: u32 = 9;
pub const BPF_TCP_SYN_SENT: u32 = 10;
pub const BPF_TCP_TIME_WAIT: u32 = 11;

// The BPF_MAP interface we depend on from `aya-ebpf`.
pub struct SharedHashMap<K, V>
where
    K: Copy + Eq + Hash,
    V: Copy,
{
    pub(crate) data: HashMap<K, V>,
    capacity: u32,
}

impl<K, V> SharedHashMap<K, V>
where
    K: Copy + Eq + Hash,
    V: Copy,
{
    pub fn with_max_entries(capacity: u32) -> SharedHashMap<K, V> {
        SharedHashMap {
            data: HashMap::new(),
            capacity,
        }
    }

    pub fn insert(&mut self, key: &K, val: &V, flags: u64) -> Result<(), i64> {
        let exists = self.data.contains_key(key);
        let should_exist = (flags & BPF_EXIST) > 0;
        let should_not_exist = (flags & BPF_NOEXIST) > 0;

        if !exists && self.data.len() >= self.capacity.try_into().unwrap() {
            Err((-ENOMEM).into())
        } else if (should_exist && !exists) || (should_not_exist && exists) {
            Err((-EINVAL).into())
        } else {
            self.data.insert(*key, *val);
            Ok(())
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }

    pub fn get_ptr_mut(&mut self, key: &K) -> Option<*mut V> {
        self.data.get_mut(key).map(|v| v as *mut V)
    }
}

pub type PerCpuHashMap<K, V> = SharedHashMap<K, V>;

// Instances of eBPF maps used by our program.  These maps are housed within a struct, instead of
// defined globally, so that the invocation of each unit test function has its own local state.
// This allows for test invocations that are free of both concurrency management and any risk of
// polluted state.
#[allow(non_snake_case)]
pub struct MockEbpfMaps {
    pub NFM_CONTROL: SharedHashMap<SingletonKey, ControlData>,
    pub NFM_COUNTERS: PerCpuHashMap<SingletonKey, EventCounters>,
    pub NFM_SK_PROPS: SharedHashMap<CpuSockKey, SockContext>,
    pub NFM_SK_STATS: SharedHashMap<CpuSockKey, SockStats>,
    pub mock_rand: u32,
}

impl MockEbpfMaps {
    pub fn new() -> Self {
        Self {
            NFM_CONTROL: SharedHashMap::<SingletonKey, ControlData>::with_max_entries(1),
            NFM_COUNTERS: PerCpuHashMap::<SingletonKey, EventCounters>::with_max_entries(1),
            NFM_SK_PROPS: SharedHashMap::<CpuSockKey, SockContext>::with_max_entries(
                MAX_ENTRIES_SK_PROPS_HI.try_into().unwrap(),
            ),
            NFM_SK_STATS: SharedHashMap::<CpuSockKey, SockStats>::with_max_entries(
                MAX_ENTRIES_SK_STATS_HI.try_into().unwrap(),
            ),
            mock_rand: 1,
        }
    }

    pub fn control_data(&self) -> &ControlData {
        self.NFM_CONTROL.data.get(&SINGLETON_KEY).unwrap()
    }

    pub fn counters(&self) -> &EventCounters {
        self.NFM_COUNTERS.data.get(&SINGLETON_KEY).unwrap()
    }

    pub fn sock_props(&self, key: &CpuSockKey) -> &SockContext {
        self.NFM_SK_PROPS.data.get(key).unwrap()
    }

    pub fn sock_stats(&self, key: &CpuSockKey) -> &SockStats {
        self.NFM_SK_STATS.data.get(key).unwrap()
    }
}

impl Default for MockEbpfMaps {
    fn default() -> Self {
        Self::new()
    }
}

// The context passed into our eBPF SOCK_OPS program by the kernel.
#[derive(Default)]
pub struct SockOpsContext {
    pub op: u32,
    pub family: u32,
    pub cb_flags: i32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub local_port: u32,
    pub remote_port: u32,
    pub args: [u32; 2],
    pub stats: SockOpsStats,
    pub cookie: u64,
    pub sock_state: u32,
}

// Match the function interfaces of an Aya SockOpsContext.
impl SockOpsContext {
    pub fn op(&self) -> u32 {
        self.op
    }

    pub fn family(&self) -> u32 {
        self.family
    }

    pub fn cb_flags(&self) -> i32 {
        self.cb_flags
    }

    pub fn set_cb_flags(&self, flags: i32) -> Result<(), i64> {
        assert!(flags as u32 & BPF_SOCK_OPS_RTT_CB_FLAG > 0);
        assert!(flags as u32 & BPF_SOCK_OPS_RTO_CB_FLAG > 0);
        assert!(flags as u32 & BPF_SOCK_OPS_STATE_CB_FLAG > 0);
        assert!(flags as u32 & BPF_SOCK_OPS_RETRANS_CB_FLAG > 0);

        // Note that without this callback, we receive no BPF events for a socket that's only
        // receiving data.  The socket would then be treated as inactive and evicted from our
        // cache.
        assert!(flags as u32 & BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG > 0);

        Ok(())
    }

    pub fn remote_ip4(&self) -> u32 {
        self.remote_ip4
    }

    pub fn local_ip4(&self) -> u32 {
        self.local_ip4
    }

    pub fn remote_ip6(&self) -> [u32; 4] {
        self.remote_ip6
    }

    pub fn local_ip6(&self) -> [u32; 4] {
        self.local_ip6
    }

    pub fn local_port(&self) -> u32 {
        self.local_port
    }

    pub fn remote_port(&self) -> u32 {
        self.remote_port
    }

    pub fn arg(&self, n: usize) -> u32 {
        self.args[n]
    }
}

// Operations on BPF maps.
#[macro_export]
macro_rules! bpf_map_get {
    ($self:ident, $map_name:ident, $key:expr) => {
        $self.mock_ebpf_maps.$map_name.get($key)
    };
}

#[macro_export]
macro_rules! bpf_map_get_ptr_mut {
    ($self:ident, $map_name:ident, $key:expr) => {
        $self
            .mock_ebpf_maps
            .as_mut()
            .unwrap()
            .$map_name
            .get_ptr_mut($key)
    };
}

#[macro_export]
macro_rules! bpf_map_insert {
    ($self:ident, $map_name:ident, $key:expr, $val:expr, $flags:expr) => {
        $self
            .mock_ebpf_maps
            .as_mut()
            .unwrap()
            .$map_name
            .insert($key, $val, $flags)
    };
}

#[macro_export]
macro_rules! bpf_get_rand_u32 {
    ($self:ident) => {
        $self.mock_ebpf_maps.mock_rand
    };
}

// BPF helper functions.
pub fn nfm_get_cpu_id() -> u64 {
    MOCK_CPU_ID
}

pub fn nfm_get_sock_cookie(ctx: &SockOpsContext) -> u64 {
    ctx.cookie
}

pub fn nfm_get_sock_state(ctx: &SockOpsContext) -> u32 {
    ctx.sock_state
}

pub fn nfm_get_sock_ops_stats(ctx: &SockOpsContext) -> SockOpsStats {
    ctx.stats
}
