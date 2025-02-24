// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod events;
pub mod kubernetes;
pub mod metadata;
pub mod reports;
pub mod utils;

use aya::util::KernelVersion;
use clap::{Parser, ValueEnum};
use kubernetes::kubernetes_metadata_collector::KubernetesMetadataCollector;
use log::{error, info};
use metadata::eni::EniMetadataProvider;
use metadata::env_metadata_provider::{MultiMetadataProvider, MultiMetadataProviderImpl};
use metadata::host::HostMetadataProvider;
use metadata::runtime_environment_metadata::RuntimeEnvironmentMetadataProvider;
use reports::publisher::MultiPublisher;
use reports::ReportCompression;
use serde::Serialize;
use signal_hook::consts::signal::{SIGINT, SIGQUIT, SIGTERM};
use std::sync::{atomic::AtomicBool, Arc};
use std::{fmt, str, time::Duration};
use structured_logger::json::new_writer;

use crate::events::{
    event_filter::EventFilter,
    event_filter_top_loss::EventFilterTopLoss,
    event_provider::EventProvider,
    event_provider_ebpf::EventProviderEbpf,
    host_stats_provider::{HostStats, HostStatsProvider, HostStatsProviderImpl},
    nat_resolver::{NatResolver, NatResolverImpl, NatResolverNoOp},
    network_event::AggregateResults,
};
use crate::reports::publisher::ReportPublisher;
use crate::reports::report::{NfmReport, ProcessStats, UsageStats};
use crate::utils::{
    event_timer, CpuUsageMonitor, EventTimer, MemoryInspector, ProcessMemoryInspector,
    SystemBootClock,
};

#[derive(Clone, Copy, Debug, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum OnOff {
    On,
    Off,
}

impl fmt::Display for OnOff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OnOff::On => write!(f, "on"),
            OnOff::Off => write!(f, "off"),
        }
    }
}

// GRCOV_STOP_COVERAGE
#[derive(Debug, Parser, Serialize)]
#[command(name = "network-flow-monitor-agent", version, about, long_about = None)]
pub struct Options {
    // `/sys/fs/cgroup/unified` is used by systemd
    // https://systemd.io/CGROUP_DELEGATION/#three-different-tree-setups-
    /// Cgroup used to capture network events
    #[clap(short, long, default_value = "/sys/fs/cgroup/unified")]
    cgroup: String,

    /// Max number of flows to report
    #[clap(short, long, default_value_t = 500)]
    top_k: usize,

    /// The amount of time after which an inactive socket will no longer be tracked.
    // A socket using a default exponential backoff count of 6 can be idle for up to 63 seconds.
    // If this config knob is not long enough, such failing sockets will be evicted as stale before
    // being observed as severed on the flow.
    #[clap(short = 'v', long, default_value_t = 65, value_parser = clap::value_parser!(u64).range(1..=600))]
    notrack_secs: u64,

    /// Includes health and performance data about the agent in published reports.
    #[clap(short, long, default_value_t = OnOff::On)]
    usage_data: OnOff,

    /// The amount of time between successive aggregation of results.
    #[clap(short, long, default_value_t = 500, value_parser = clap::value_parser!(u64).range(100..=60000))]
    aggregate_msecs: u64,

    /// The amount of time between successive publishing of results.
    #[clap(short = 's', long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
    publish_secs: u64,

    /// The amount of time by which publish periods can vary.
    #[clap(short, long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(0..=600))]
    jitter_secs: u64,

    /// Endpoint to send reports to
    #[clap(short = 'e', long, default_value = "")]
    endpoint: String,

    /// Region of the endpoint
    #[clap(short = 'r', long, default_value = "")]
    endpoint_region: String,

    /// Enable log reports
    #[clap(short = 'l', long, default_value_t = OnOff::Off)]
    log_reports: OnOff,

    /// Enable publish reports to the endpoint
    #[clap(short = 'p', long, default_value_t = OnOff::On)]
    publish_reports: OnOff,

    /// Report compression (for endpoint publishing)
    #[clap(short = 'z', long, default_value_t = ReportCompression::Gzip)]
    report_compression: ReportCompression,

    /// Include kubernetes metadata in published reports.
    #[clap(short = 'k', long, default_value_t = OnOff::Off)]
    kubernetes_metadata: OnOff,

    /// Within reports, use IP addresses that are external to locally performed NAT.
    #[clap(short = 'n', long, default_value_t = OnOff::Off)]
    resolve_nat: OnOff,
}

pub fn check_kernel_version() -> Result<(), anyhow::Error> {
    let version_actual = KernelVersion::current().unwrap();
    let version_min_expected = KernelVersion::new(5, 8, 0);
    if version_actual >= version_min_expected {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Kernel version at or above {} expected, found {}",
            version_min_expected,
            version_actual
        ))
    }
}

pub fn on_load(opt: Options) -> Result<(), anyhow::Error> {
    check_kernel_version()?;

    // Initialize logging to stdout.  Log level can be set via env var RUST_LOG, and defaults to
    // info.
    structured_logger::Builder::new()
        .with_default_writer(new_writer(std::io::stdout()))
        .init();
    info!(args:serde = opt; "Starting up");

    // Load NFM objects
    let event_provider =
        match EventProviderEbpf::new(&opt.cgroup, opt.notrack_secs, SystemBootClock {}) {
            Ok(prov) => prov,
            Err(e) => {
                return Err(e);
            }
        };
    let nat_resolver: Box<dyn NatResolver> = if opt.resolve_nat == OnOff::On {
        Box::new(NatResolverImpl::initialize())
    } else {
        Box::new(NatResolverNoOp {})
    };
    let event_filter = EventFilterTopLoss::new(opt.top_k.try_into().unwrap());
    let publisher = MultiPublisher::from_options(&opt);
    let metadata_provider = MultiMetadataProviderImpl {
        eni_metadata: EniMetadataProvider::new(),
        host_metadata: HostMetadataProvider::new(),
        runtime_env_metadata: RuntimeEnvironmentMetadataProvider::new(),
    };
    let host_stats_provider = HostStatsProviderImpl::new();

    do_work(
        event_provider,
        nat_resolver,
        event_filter,
        publisher,
        metadata_provider,
        host_stats_provider,
        opt,
    );

    Ok(())
}
// GRCOV_BEGIN_COVERAGE

fn do_work(
    mut provider: impl EventProvider,
    mut nat_resolver: Box<dyn NatResolver>,
    mut event_filter: impl EventFilter<AggregateResults>,
    publisher: impl ReportPublisher,
    mut metadata_provider: impl MultiMetadataProvider,
    mut host_stats_provider: impl HostStatsProvider,
    opt: Options,
) {
    let memory_inspector = ProcessMemoryInspector::new();
    let mut cpu_monitor = CpuUsageMonitor::start();
    let mut timer = EventTimer::new(SystemBootClock {});

    let aggregate_event = timer.add_event(
        Duration::from_millis(opt.aggregate_msecs),
        Duration::from_secs(0),
    );
    let publish_event = timer.add_event(
        Duration::from_secs(opt.publish_secs),
        Duration::from_secs(opt.jitter_secs),
    );

    // Register POSIX signals for which we want to exit gracefully.
    let should_exit = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&should_exit))
        .expect("Failed to register SIGINT handler");
    signal_hook::flag::register(SIGQUIT, Arc::clone(&should_exit))
        .expect("Failed to register SIGQUIT handler");
    signal_hook::flag::register(SIGTERM, Arc::clone(&should_exit))
        .expect("Failed to register SIGTERM handler");
    timer.set_exit_flag(should_exit);

    let enable_usage_data = opt.usage_data == OnOff::On;
    let mut failed_reports_count = 0;
    let mut usage_stats = UsageStats::default();
    let mut k8s_metadata_collector = KubernetesMetadataCollector::new();
    if opt.kubernetes_metadata == OnOff::On {
        k8s_metadata_collector.setup_watchers();
    }

    loop {
        let event_id = timer.await_next_event();
        if event_id == event_timer::EXIT_EVENT {
            info!("Exiting");
            return;
        }

        if event_id == aggregate_event {
            nat_resolver.perform_aggregation_cycle();
            provider.perform_aggregation_cycle(&nat_resolver);
            nat_resolver.perform_eviction();
        } else if event_id == publish_event {
            // Add network stats to the report.
            let mut report = NfmReport::new();
            report.set_failed_reports(failed_reports_count);

            let mut agg_flows = provider.network_stats();
            if opt.kubernetes_metadata == OnOff::On {
                k8s_metadata_collector.enrich_flows(&mut agg_flows);
            }
            report.set_network_stats(event_filter.filter_events(agg_flows));

            // Add process stats to the report.
            if enable_usage_data {
                // Compute CPU usage then restart the monitor.
                usage_stats.cpu_util = cpu_monitor.usage_ratio();
                cpu_monitor = CpuUsageMonitor::start();

                report.set_process_stats(ProcessStats {
                    counters: provider.counters(),
                    usage: vec![usage_stats],
                });

                // Reset stats for the next report.
                usage_stats = UsageStats::default();
            }

            // Add metadata
            metadata_provider.refresh();
            report.set_env_metadata(metadata_provider.get_metadata());

            host_stats_provider.set_network_devices(&metadata_provider.get_network_devices());
            report.set_host_stats(host_stats_provider.get_stats());

            if publisher.publish(&report) {
                failed_reports_count = 0;
            } else {
                failed_reports_count += 1;
            }
        } else {
            error!("Received unknown event ID: {event_id}");
        }

        // We'll publish the highest mem usage during the report period.
        if enable_usage_data {
            let (mem_used_kb, mem_used_ratio) = memory_inspector.usage();
            usage_stats.mem_used_kb = usage_stats.mem_used_kb.max(mem_used_kb);
            usage_stats.mem_used_ratio = usage_stats.mem_used_ratio.max(mem_used_ratio);
            usage_stats.sockets_tracked = usage_stats.sockets_tracked.max(provider.socket_count());
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::events::{
        host_stats_provider::HostStats, nat_resolver::NatResolver, SockCache, SockOperationResult,
    };
    use metadata::env_metadata_provider::{
        EnvMetadata, EnvMetadataProvider, MultiMetadataProvider, NetworkDevice,
    };
    use nfm_common::SockContext;
    use reports::CountersOverall;

    use std::{sync::Mutex, thread, time::Instant};

    #[derive(Clone, Default)]
    struct EventProviderNoOp {
        calls: Arc<Mutex<u8>>,
    }
    #[derive(Clone, Default)]
    struct NatResolverNoOp {
        calls: Arc<Mutex<u8>>,
    }
    #[derive(Clone, Default)]
    struct EventFilterNoOp {
        calls: Arc<Mutex<u8>>,
    }
    #[derive(Clone, Default)]
    struct PublisherNoOp {
        calls: Arc<Mutex<u8>>,
    }
    #[derive(Clone, Default)]
    struct MultiMetadataProviderNoOp {
        calls: Arc<Mutex<u8>>,
    }
    #[derive(Clone, Default)]
    struct HostStatsProviderNoOp {
        calls: Arc<Mutex<u8>>,
    }

    impl EventProvider for EventProviderNoOp {
        fn perform_aggregation_cycle(&mut self, _nat_resolver: &Box<dyn NatResolver>) {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
        }
        fn network_stats(&mut self) -> Vec<AggregateResults> {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);

            vec![]
        }
        fn counters(&mut self) -> CountersOverall {
            CountersOverall::default()
        }
        fn socket_count(&self) -> u64 {
            0
        }
    }

    impl NatResolver for NatResolverNoOp {
        fn perform_aggregation_cycle(&mut self) {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
        }
        fn perform_eviction(&mut self) {}
        fn get_beyond_nat_entry(&self, _sock_context: &SockContext) -> Option<SockContext> {
            None
        }
        fn store_beyond_nat_entries(&self, _sock_cache: &mut SockCache) -> SockOperationResult {
            SockOperationResult::default()
        }
        fn num_entries(&self) -> usize {
            0
        }
    }

    impl EventFilter<AggregateResults> for EventFilterNoOp {
        fn filter_events(&mut self, _events: Vec<AggregateResults>) -> Vec<AggregateResults> {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
            vec![]
        }
    }

    impl ReportPublisher for PublisherNoOp {
        fn publish(&self, _report: &NfmReport) -> bool {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
            true
        }
    }

    impl MultiMetadataProvider for MultiMetadataProviderNoOp {
        fn get_network_devices(&mut self) -> Vec<NetworkDevice> {
            vec![]
        }
    }

    impl EnvMetadataProvider for MultiMetadataProviderNoOp {
        fn refresh(&mut self) {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
        }
        fn get_metadata(&self) -> EnvMetadata {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
            EnvMetadata::default()
        }
    }

    impl HostStatsProvider for HostStatsProviderNoOp {
        fn set_network_devices(&mut self, _net_devices: &[NetworkDevice]) {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
        }

        fn get_stats(&mut self) -> HostStats {
            let mut calls = self.calls.lock().unwrap();
            *calls = (*calls).saturating_add(1);
            HostStats::default()
        }
    }

    #[test]
    fn test_do_work() {
        let event_provider = EventProviderNoOp::default();
        let nat_resolver = NatResolverNoOp::default();
        let event_filter = EventFilterNoOp::default();
        let publisher = PublisherNoOp::default();
        let metadata_provider = MultiMetadataProviderNoOp::default();
        let host_stats_provider = HostStatsProviderNoOp::default();

        // Clone the struct to pass it to the thread
        let event_provider_clone = event_provider.clone();
        let nat_resolver_clone = nat_resolver.clone();
        let event_filter_clone = event_filter.clone();
        let publisher_clone = publisher.clone();
        let metadata_provider_clone = metadata_provider.clone();
        let host_stats_provider_clone = host_stats_provider.clone();

        thread::spawn(move || {
            do_work(
                event_provider_clone,
                Box::new(nat_resolver_clone),
                event_filter_clone,
                publisher_clone,
                metadata_provider_clone,
                host_stats_provider_clone,
                Options {
                    log_reports: OnOff::Off,
                    publish_reports: OnOff::Off,
                    endpoint: "a".to_string(),
                    endpoint_region: "b".to_string(),
                    cgroup: "c".to_string(),
                    top_k: 100,
                    notrack_secs: 0,
                    usage_data: OnOff::On,
                    aggregate_msecs: 0,
                    publish_secs: 0,
                    jitter_secs: 0,
                    report_compression: ReportCompression::None,
                    kubernetes_metadata: OnOff::On,
                    resolve_nat: OnOff::On,
                },
            );
        });

        let duration = Duration::from_millis(2000);
        let start = Instant::now();
        while start.elapsed() < duration {
            // allow thread start to be delayed for 2sec at worst, to prevent failures at test
            if *event_provider.calls.lock().unwrap() >= 1
                && *nat_resolver.calls.lock().unwrap() >= 1
                && *event_filter.calls.lock().unwrap() >= 1
                && *publisher.calls.lock().unwrap() >= 1
                && *metadata_provider.calls.lock().unwrap() >= 1
                && *host_stats_provider.calls.lock().unwrap() >= 1
            {
                return; // success
            };
        }
        assert!(false); // failure
    }

    #[test]
    fn test_on_off_display() {
        assert_eq!(OnOff::On.to_string(), "on");
        assert_eq!(OnOff::Off.to_string(), "off");
    }
}
