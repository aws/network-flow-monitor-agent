// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    reports::report::NfmReport,
    utils::{clock::RealTimeClock, credentials::get_credentials_provider},
    OnOff, Options,
};
use log::info;

pub use super::publisher_endpoint::ReportPublisherOTLP;

pub trait ReportPublisher {
    /// Publish a report and return true if it was successful.
    fn publish(&self, report: &NfmReport) -> bool;
}

pub struct ReportPublisherLog {}

impl ReportPublisherLog {
    pub fn new() -> Self {
        ReportPublisherLog {}
    }
}

impl Default for ReportPublisherLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportPublisher for ReportPublisherLog {
    fn publish(&self, report: &NfmReport) -> bool {
        info!(report:serde = report; "Publishing report");
        true
    }
}

pub struct MultiPublisher {
    publishers: Vec<Box<dyn ReportPublisher + Send>>,
}

pub struct MultiPublisherBuilder {
    publishers: Vec<Box<dyn ReportPublisher + Send>>,
}

impl MultiPublisher {
    pub fn builder() -> MultiPublisherBuilder {
        MultiPublisherBuilder {
            publishers: Vec::new(),
        }
    }

    pub(crate) fn from_options(opt: &Options) -> Self {
        let mut publisher_builder = MultiPublisher::builder();
        if opt.log_reports == OnOff::On {
            publisher_builder.with_publisher(Box::new(ReportPublisherLog::new()));
        }
        if opt.publish_reports == OnOff::On {
            assert!(
                !opt.endpoint.is_empty() && !opt.endpoint_region.is_empty(),
                "endpoint and endpoint-region must be specified when publish-reports is on"
            );
            publisher_builder.with_publisher(Box::new(ReportPublisherOTLP::new(
                opt.endpoint.clone(),
                opt.endpoint_region.clone(),
                get_credentials_provider(),
                RealTimeClock {},
                opt.report_compression,
                opt.https_proxy.clone(),
            )));
        };
        publisher_builder.build()
    }
}

impl MultiPublisherBuilder {
    pub fn with_publisher(&mut self, publisher: Box<dyn ReportPublisher + Send>) {
        self.publishers.push(publisher);
    }

    pub fn build(self) -> MultiPublisher {
        MultiPublisher {
            publishers: self.publishers,
        }
    }
}

impl ReportPublisher for MultiPublisher {
    fn publish(&self, report: &NfmReport) -> bool {
        let mut success = true;
        for publisher in &self.publishers {
            success &= publisher.publish(report);
        }
        success
    }
}

#[cfg(test)]
mod tests {
    use log::Log;
    use std::sync::Mutex;

    use crate::{
        reports::{publisher::ReportPublisherLog, report::NfmReport, ReportCompression},
        OnOff, Options,
    };

    use super::{MultiPublisher, ReportPublisher};

    struct MockLogger {
        pub message: Mutex<String>,
    }
    impl Log for MockLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }

        fn flush(&self) {}

        fn log(&self, record: &log::Record) {
            let mut x = self.message.lock().unwrap();
            *x = record.args().to_string();
        }
    }

    #[test]
    fn test_log_publish() {
        let logger = Box::leak(Box::new(MockLogger {
            message: Mutex::new("".to_string()),
        }));

        std::env::set_var("RUST_LOG", "info");
        let _ = log::set_logger(logger);
        log::set_max_level(log::LevelFilter::Info);

        let publisher = ReportPublisherLog::default();
        publisher.publish(&NfmReport::new());

        assert_eq!(
            "Publishing report".to_string(),
            logger.message.lock().unwrap().to_string()
        );
    }

    struct MockPublisher {
        report: NfmReport,
    }

    impl ReportPublisher for MockPublisher {
        fn publish(&self, report: &NfmReport) -> bool {
            assert_eq!(report, &self.report);
            true
        }
    }

    #[test]
    fn test_multi_publish() {
        let report = NfmReport::new();
        let publisher1 = MockPublisher {
            report: report.clone(),
        };
        let publisher2 = MockPublisher {
            report: report.clone(),
        };

        let mut builder = MultiPublisher::builder();
        builder.with_publisher(Box::new(publisher1));
        builder.with_publisher(Box::new(publisher2));
        let publisher = builder.build();

        publisher.publish(&report);
    }

    #[test]
    fn test_build_multi_publisher() {
        // Only log
        let opt = create_options(OnOff::On, OnOff::Off);
        let publisher = MultiPublisher::from_options(&opt);
        assert_eq!(publisher.publishers.len(), 1);

        // Only endpoint
        let opt = create_options(OnOff::Off, OnOff::On);
        let publisher = MultiPublisher::from_options(&opt);
        assert_eq!(publisher.publishers.len(), 1);

        // Both publishers
        let opt = create_options(OnOff::On, OnOff::On);
        let publisher = MultiPublisher::from_options(&opt);
        assert_eq!(publisher.publishers.len(), 2);
    }

    fn create_options(with_log: OnOff, with_endpoint: OnOff) -> Options {
        Options {
            log_reports: with_log,
            publish_reports: with_endpoint,
            endpoint: "a".to_string(),
            endpoint_region: "b".to_string(),
            cgroup: "c".to_string(),
            https_proxy: "d".to_string(),
            top_k: 100,
            notrack_secs: 0,
            usage_data: OnOff::Off,
            aggregate_msecs: 100,
            publish_secs: 30,
            jitter_secs: 0,
            report_compression: ReportCompression::None,
            kubernetes_metadata: OnOff::On,
            resolve_nat: OnOff::On,
        }
    }
}
