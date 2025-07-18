// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub const SK_STATS_TO_PROPS_MIN_RATIO: u64 = 2;
pub const SK_STATS_TO_PROPS_MAX_RATIO: u64 = 24;
// actual sk_stats_to_props_ratio will be (cpu count / SK_STATS_TO_PROPS_RATIO_CPU_COUNT_DIVISOR)
// that calculated ratio cannot be lower than SK_STATS_TO_PROPS_MIN_RATIO
pub const SK_STATS_TO_PROPS_RATIO_CPU_COUNT_DIVISOR: usize = 2;

// This divisor was chosen arbitrarily based on experimentation. (5GBytes)
// Will be used to divide total memory to get a multiplier to multiply with MAX_ENTRIES_SK_STATS_LO
pub const EMPIRICAL_MEMORY_DIVISOR: u64 = 5_000_000_000;

// Example: m8g.48xlarge 192 cores 768GB mem
//   Stats: 768 / 5 * 500 -> 76.8k entries for stats (clamped to 60k))
//   Props: Ratio = (192 / 2 = 96 -> clamped to 24) -> 60k / (24) -> 2500
pub const MAX_ENTRIES_SK_STATS_LO: u64 = 500;
pub const MAX_ENTRIES_SK_STATS_HI: u64 = 60000;

pub const MAX_ENTRIES_SK_PROPS_LO: u64 = MAX_ENTRIES_SK_STATS_LO / SK_STATS_TO_PROPS_MIN_RATIO;
pub const MAX_ENTRIES_SK_PROPS_HI: u64 = MAX_ENTRIES_SK_STATS_HI / SK_STATS_TO_PROPS_MIN_RATIO;

pub const AGG_FLOWS_MAX_ENTRIES: u32 = 10_000;

pub const EBPF_PROGRAM_NAME: &str = "nfm_sock_ops";
pub const NFM_CONTROL_MAP_NAME: &str = "NFM_CONTROL";
pub const NFM_COUNTERS_MAP_NAME: &str = "NFM_COUNTERS";
pub const NFM_SK_PROPS_MAP_NAME: &str = "NFM_SK_PROPS";
pub const NFM_SK_STATS_MAP_NAME: &str = "NFM_SK_STATS";
