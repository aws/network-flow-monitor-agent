// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use log::info;
use serde::{Deserialize, Serialize};
use shadow_rs::shadow;

use crate::reports::report::ReportValue;

shadow!(build);

const PROJECT_NAME: &str = "network-flow-monitor";

#[derive(Clone, Debug, Serialize, PartialEq, Deserialize)]
pub struct ServiceMetadata {
    pub name: ReportValue,
    pub version: ReportValue,
    pub build_ts: ReportValue,
}

impl Default for ServiceMetadata {
    fn default() -> Self {
        // See: https://github.com/baoyachi/shadow-rs/
        ServiceMetadata::new(PROJECT_NAME, build::PKG_VERSION, build::BUILD_TIME_3339)
    }
}

impl ServiceMetadata {
    pub fn new(name: &str, version: &str, build_time: &str) -> Self {
        let metadata = ServiceMetadata {
            name: ReportValue::String(name.into()),
            version: ReportValue::String(version.into()),
            build_ts: ReportValue::String(build_time.into()),
        };
        info!(metadata:serde = metadata; "Service metadata");
        metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_metadata_default() {
        let service_metadata = ServiceMetadata::default();

        assert_eq!(
            service_metadata.name,
            ReportValue::String(PROJECT_NAME.into())
        );
        assert_eq!(
            service_metadata.version,
            ReportValue::String(build::PKG_VERSION.into())
        );
        assert_eq!(
            service_metadata.build_ts,
            ReportValue::String(build::BUILD_TIME_3339.into())
        );
    }

    #[test]
    fn test_service_metadata_new() {
        let service_metadata = ServiceMetadata::new("test_name", "test_version", "test_build_ts");
        assert_eq!(
            service_metadata.name,
            ReportValue::String("test_name".into())
        );
        assert_eq!(
            service_metadata.version,
            ReportValue::String("test_version".into())
        );
        assert_eq!(
            service_metadata.build_ts,
            ReportValue::String("test_build_ts".into())
        );
    }
}
