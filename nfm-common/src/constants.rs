// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub const SK_STATS_TO_PROPS_MIN_RATIO: u64 = 2;

pub const MAX_ENTRIES_SK_PROPS_LO: u64 = MAX_ENTRIES_SK_STATS_LO / SK_STATS_TO_PROPS_MIN_RATIO;
pub const MAX_ENTRIES_SK_PROPS_HI: u64 = MAX_ENTRIES_SK_STATS_HI / SK_STATS_TO_PROPS_MIN_RATIO;

pub const MAX_ENTRIES_SK_STATS_LO: u64 = 500;
pub const MAX_ENTRIES_SK_STATS_HI: u64 = 60000;

pub const AGG_FLOWS_MAX_ENTRIES: u32 = 10_000;

pub const EBPF_PROGRAM_NAME: &str = "nfm_sock_ops";
pub const NFM_CONTROL_MAP_NAME: &str = "NFM_CONTROL";
pub const NFM_COUNTERS_MAP_NAME: &str = "NFM_COUNTERS";
pub const NFM_SK_PROPS_MAP_NAME: &str = "NFM_SK_PROPS";
pub const NFM_SK_STATS_MAP_NAME: &str = "NFM_SK_STATS";
