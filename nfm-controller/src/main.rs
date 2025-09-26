// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use nfm_agent::{on_load, Options};

#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> Result<(), anyhow::Error> {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();
    on_load(Options::parse())
}
