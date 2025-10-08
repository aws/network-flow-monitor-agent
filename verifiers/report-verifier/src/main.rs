// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod ip_port;
pub mod report_ext;
pub mod testbed;
pub mod verifiers;

use anyhow::Result;
use clap::Parser;
use nfm_agent::events::network_event::{AggregateResults, FlowProperties};
use nfm_agent::reports::report::NfmReport;
use serde_json::Value;
use std::collections::HashMap;

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::ip_port::IpPort;
use crate::report_ext::{NetworkStatsExt, ProcessCountersExt, UsageStatsExt};
use crate::testbed::TestFabric;
use crate::verifiers::generic_report_verifier::GenericReportVerifier;
use crate::verifiers::report_verifier::{ReportVerifier, ReportVerifierConfig};

#[derive(Parser)]
#[command(name = "report-verifier")]
struct Args {
    /// Report publication period
    #[arg(long)]
    publish_secs: u64,

    /// Path to agent log file
    #[arg(long)]
    log_file: PathBuf,

    /// How many connection attempts to match for given ip pair
    #[arg(long)]
    expected_connection_count: u32,

    /// What is the expected minimum latency in micros for given ip pair
    #[arg(long, default_value_t = 0)]
    expected_minimum_latency: u32,

    /// What is the expected packet loss in percents for given ip pair
    #[arg(long, default_value_t = 0)]
    expected_loss_percent: u8,

    /// IP address of local connection to match for
    #[arg(long, default_value = "127.0.0.1")]
    local_ip_under_test: String,

    /// port of local connection to match for
    #[arg(long, default_value_t = 8080)]
    local_port_under_test: u16,

    /// IP address of remote connection to match for
    #[arg(long, default_value = "127.0.0.1")]
    remote_ip_under_test: String,

    /// IP address of remote device to match for
    #[arg(long, default_value_t = 8080)]
    remote_port_under_test: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let test_fabric = infer_test_fabric();
    let test_config = ReportVerifierConfig {
        test_fabric,
        expected_connection_count: args.expected_connection_count,
        expected_minimum_latency: args.expected_minimum_latency,
        expected_loss_percent: args.expected_loss_percent,
        local_ip_port_under_test: IpPort {
            ip_address: args.local_ip_under_test.parse().unwrap(),
            port: args.local_port_under_test,
        },
        remote_ip_port_under_test: IpPort {
            ip_address: args.remote_ip_under_test.parse().unwrap(),
            port: args.remote_port_under_test,
        },
    };
    let verifier = GenericReportVerifier::new_with(test_config.clone());
    println!("Running test with config: {:#?}", &test_config);

    let timeout = args.publish_secs + 10;
    // Verify agent output. It might take up to publication period of time for a report to appear.
    // But adding 10 more seconds to accommodate for initialization delays.
    println!("Starting agent report content verification.\nWill try for up to {} seconds for reports to populate", timeout);

    let current_time = Instant::now();
    let mut file = File::open(&args.log_file)?;
    let mut merged_report = None;
    while current_time.elapsed().as_secs() < timeout {
        merged_report = read_and_merge_all_reports(&mut file);
        if merged_report.is_some() {
            if verifier.verify(&merged_report.as_ref().unwrap()) {
                println!("Agent report content verification completed successfully");
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let debug_log = match merged_report {
        Some(report) => {
            serde_json::to_string_pretty(&serde_json::to_value(&report).unwrap()).unwrap()
        }
        None => "No reports detected".to_string(),
    };
    println!("Latest merged report:\n {}", debug_log);
    anyhow::bail!(
        "Agent report content verification failed for config: [{:#?}], check report backlog",
        test_config
    );
}

/**
 * Check the agent log and parse and collect all the report logs.
 * We have to merge all the reports into a single one because the generation of traffic
 * is disjoint with publication of the reports which might cause the data to land across multiple reports.
 */
fn read_and_merge_all_reports(file: &mut File) -> Option<NfmReport> {
    let mut merged_report: Option<NfmReport> = None;
    file.seek(SeekFrom::Start(0)).ok();
    let reader = BufReader::new(&*file);
    for line in reader.lines() {
        if let Ok(line) = line {
            if let Ok(json) = serde_json::from_str::<Value>(&line) {
                if json["message"] == "Publishing report" {
                    let report: NfmReport = serde_json::from_value(json["report"].clone()).unwrap();

                    merged_report = match merged_report {
                        None => Some(report),
                        Some(merged_report) => Some(merge_reports(merged_report, report)),
                    }
                }
            }
        }
    }

    merged_report
}

fn merge_reports(mut report1: NfmReport, report2: NfmReport) -> NfmReport {
    report1.process_stats.usage[0].merge_from(&report2.process_stats.usage[0]);
    report1
        .process_stats
        .counters
        .event_related
        .add_from(&report2.process_stats.counters.event_related);
    report1
        .process_stats
        .counters
        .process_related
        .merge_from(&report2.process_stats.counters.process_related);

    // Merge network_stats by flow
    let mut flow_map: HashMap<FlowProperties, AggregateResults> = HashMap::new();

    // Add report1 network_stats to map
    for aggregate in report1.network_stats {
        flow_map.insert(aggregate.flow.clone(), aggregate);
    }

    // Merge report2 network_stats
    for aggregate in report2.network_stats {
        if let Some(existing) = flow_map.get_mut(&aggregate.flow) {
            existing.stats.merge_from(&aggregate.stats);
        } else {
            flow_map.insert(aggregate.flow.clone(), aggregate);
        }
    }

    report1.network_stats = flow_map.into_values().collect();
    report1
}

fn infer_test_fabric() -> TestFabric {
    // Check for EC2 environment using metadata service
    // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/retrieve-iid.html
    if let Ok(output) = std::process::Command::new("curl")
        .args([
            "-s",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ])
        .output()
    {
        if String::from_utf8_lossy(&output.stdout).contains("instanceType") {
            return TestFabric::EC2;
        }
    }

    // Check for Kubernetes environment
    // https://kubernetes.io/docs/tutorials/services/connect-applications-service/#environment-variables
    if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
        return TestFabric::K8s;
    }

    TestFabric::Plain
}
