// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

use crate::reports::report::ReportValue;

use super::kubernetes_metadata_collector::PodInfo;

// carries kubernetes metadata related to local and remote parties, when applicable
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd)]
pub struct FlowMetadata {
    pub local: Option<PodInfo>,
    pub remote: Option<PodInfo>,
}

impl FlowMetadata {
    pub fn enumerate(&self) -> Vec<(String, ReportValue)> {
        let mut values: Vec<(String, ReportValue)> = Vec::new();
        // add local and remote pod info
        if let Some(pod_info) = &self.local {
            values.push((
                "local_pod_name".to_string(),
                ReportValue::String(pod_info.name.to_string()),
            ));
            values.push((
                "local_pod_namespace".to_string(),
                ReportValue::String(pod_info.namespace.to_string()),
            ));
            values.push((
                "local_pod_service".to_string(),
                ReportValue::String(pod_info.service_name.to_string()),
            ));
        }
        if let Some(pod_info) = &self.remote {
            values.push((
                "remote_pod_name".to_string(),
                ReportValue::String(pod_info.name.to_string()),
            ));
            values.push((
                "remote_pod_namespace".to_string(),
                ReportValue::String(pod_info.namespace.to_string()),
            ));
            values.push((
                "remote_pod_service".to_string(),
                ReportValue::String(pod_info.service_name.to_string()),
            ));
        }
        values
    }
}
