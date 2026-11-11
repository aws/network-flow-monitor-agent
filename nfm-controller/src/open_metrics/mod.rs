// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenMetrics/Prometheus metrics server module for the Network Flow Monitor agent.

use clap::ValueEnum;
use serde::Serialize;
use std::fmt;

pub mod provider;
pub mod providers;
pub mod server;
pub mod types;

/// How metric values are exposed on the OpenMetrics endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OpenMetricsMode {
    /// Gauges with the change since the previous scrape. Supports a single scraper.
    #[default]
    Delta,
    /// Counters with cumulative values. Supports concurrent scrapers.
    Absolute,
}

impl fmt::Display for OpenMetricsMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenMetricsMode::Delta => write!(f, "delta"),
            OpenMetricsMode::Absolute => write!(f, "absolute"),
        }
    }
}
