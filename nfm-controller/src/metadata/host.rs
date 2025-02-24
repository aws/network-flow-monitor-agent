// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use crate::metadata::env_metadata_provider::{EnvMetadata, EnvMetadataProvider};
use crate::reports::report::ReportValue;

pub struct HostMetadataProvider {
    machine_id: String,
}

impl HostMetadataProvider {
    pub fn new() -> Self {
        Self {
            machine_id: get_machine_id(),
        }
    }
}

impl Default for HostMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvMetadataProvider for HostMetadataProvider {
    fn refresh(&mut self) {
        if self.machine_id.is_empty() {
            self.machine_id = get_machine_id();
        }
    }

    fn get_metadata(&self) -> EnvMetadata {
        EnvMetadata::from(vec![(
            "machine-id".into(),
            ReportValue::String(self.machine_id.clone()),
        )])
    }
}

fn get_machine_id() -> String {
    // https://man7.org/linux/man-pages/man5/machine-id.5.html
    fs::read_to_string("/etc/machine-id")
        .unwrap_or("".to_string())
        .trim()
        .to_string()
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_machine_id() {
        let mut ec2_provider = HostMetadataProvider::default();
        ec2_provider.refresh();
        let metadata = ec2_provider.get_metadata();
        assert_eq!(metadata.len(), 1);
        assert!(metadata.contains_key("machine-id"));

        assert!(metadata.enumerate().any(|(key, value)| {
            if key != "machine-id" {
                return false;
            }
            if let ReportValue::String(str_value) = value {
                return !str_value.is_empty() && !str_value.ends_with('\n');
            }
            false
        }));
    }
}
