// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! OpenMetrics/Prometheus metrics server module for the Network Flow Monitor agent.

pub mod server;

// No need to re-export start_metrics_server as it's only used in tests
