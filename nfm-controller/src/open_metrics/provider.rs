// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Simple Prometheus metrics server for testing integration.
//!
//! This module provides a basic HTTP server that returns a fixed dummy metric
//! in Prometheus format on the /metrics endpoint.
//!

use prometheus::Registry;
pub trait OpenMetricProvider {
    fn register(registy: &mut Registry);
    fn update_metrics();
}
