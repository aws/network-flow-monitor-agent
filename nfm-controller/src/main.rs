// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use nfm_agent::{on_load, Options};

fn main() -> Result<(), anyhow::Error> {
    on_load(Options::parse())
}
