// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub const SK_STATS_TO_PROPS_RATIO: u64 = 3;

pub const MAX_ENTRIES_SK_PROPS_LO: u64 = 256;
pub const MAX_ENTRIES_SK_STATS_LO: u64 = SK_STATS_TO_PROPS_RATIO * MAX_ENTRIES_SK_PROPS_LO;

pub const MAX_ENTRIES_SK_PROPS_HI: u64 = 20000;
pub const MAX_ENTRIES_SK_STATS_HI: u64 = SK_STATS_TO_PROPS_RATIO * MAX_ENTRIES_SK_PROPS_HI;

pub const AGG_FLOWS_MAX_ENTRIES: u32 = 10_000;

/// Ringbuf size for NFM_SK_PROPS_RB. Must be a power of 2 (kernel requirement - or buffer wont work!!).
/// Ringbuf pre-allocates the full buffer at map creation. The advantage over HashMap
/// is zero-syscall reads (mmap-ed) and lock-free writes from BPF.
/// This constant is used as the default in the eBPF object; at load time it is
/// overridden dynamically via `set_max_entries` based on available memory.
pub const NFM_SK_PROPS_RB_BYTE_SIZE: u32 = 1024 * 1024;

/// BPF ringbuf record header overhead (per entry).
const RINGBUF_RECORD_HEADER_SIZE: u64 = 8;

/// Size of a single ringbuf entry including the record header.
const RINGBUF_ENTRY_SIZE: u64 =
    core::mem::size_of::<crate::network::SockPropsEntry>() as u64 + RINGBUF_RECORD_HEADER_SIZE;

/// Computes the ringbuf byte size needed to hold `sock_props_max_entries` entries.
/// Returns a power-of-2 value (nearest lower power of two) as required by the kernel.
/// This will mean that the buffer will actually hold lesser entries (or equal) than 'sock_props_max_entries'.
pub fn ringbuf_byte_size(sock_props_max_entries: u64) -> u32 {
    ((RINGBUF_ENTRY_SIZE * sock_props_max_entries).next_power_of_two() / 2) as u32
}

/// Returns the number of entries that fit in the ringbuf after the power-of-2 roundup.
/// This will be used to size the sock_cache so it matches the actual ringbuf capacity.
pub fn ringbuf_entry_capacity(sock_props_max_entries: u64) -> u64 {
    ringbuf_byte_size(sock_props_max_entries) as u64 / RINGBUF_ENTRY_SIZE
}

pub const EBPF_PROGRAM_NAME: &str = "nfm_sock_ops";
pub const NFM_CONTROL_MAP_NAME: &str = "NFM_CONTROL";
pub const NFM_COUNTERS_MAP_NAME: &str = "NFM_COUNTERS";
pub const NFM_SK_PROPS_RB_MAP_NAME: &str = "NFM_SK_PROPS";
pub const NFM_SK_STATS_MAP_NAME: &str = "NFM_SK_STATS";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ringbuf_size_is_power_of_two() {
        assert!(NFM_SK_PROPS_RB_BYTE_SIZE.is_power_of_two());
    }
}
