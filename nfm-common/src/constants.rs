// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub const SK_STATS_TO_PROPS_RATIO: u64 = 3;

pub const MAX_ENTRIES_SK_PROPS_LO: u64 = 250;
pub const MAX_ENTRIES_SK_STATS_LO: u64 = SK_STATS_TO_PROPS_RATIO * MAX_ENTRIES_SK_PROPS_LO;

pub const MAX_ENTRIES_SK_PROPS_HI: u64 = 20000;
pub const MAX_ENTRIES_SK_STATS_HI: u64 = SK_STATS_TO_PROPS_RATIO * MAX_ENTRIES_SK_PROPS_HI;

pub const AGG_FLOWS_MAX_ENTRIES: u32 = 10_000;

/// Ringbuf size for NFM_SK_PROPS_RB. Must be a power of 2 (kernel requirement).
/// Ringbuf pre-allocates the full 2 MiB at map creation. The advantage over HashMap is zero-syscall reads (mmap-ed) and lock-free writes from BPF.
/// Sized to hold MAX_ENTRIES_SK_PROPS_HI (20000) entries:
///   (sizeof(SockPropsEntry) + 8-byte ringbuf header) * 20000 = 68 * 20000 = 1,360,000
///   → next power of 2 = 2,097,152 (2 MiB)
pub const NFM_SK_PROPS_RB_BYTE_SIZE: u32 = 2 * 1024 * 1024;

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
