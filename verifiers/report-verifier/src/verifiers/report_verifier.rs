// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use nfm_agent::reports::report::NfmReport;

use crate::{ip_port::IpPort, testbed::TestFabric};

pub trait ReportVerifier {
    /// Verify contents of a report and return true if it was successful.
    fn verify(&self, report: &NfmReport) -> bool;
}

#[derive(Debug, Clone)]
pub struct ReportVerifierConfig {
    pub test_fabric: TestFabric,
    pub expected_connection_count: u32,
    pub expected_minimum_latency: u32,
    pub expected_loss_percent: u8,
    pub local_ip_port_under_test: IpPort,
    pub remote_ip_port_under_test: IpPort,
}
