// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::metadata::runtime_environment_metadata::RuntimeEnvironmentMetadataProvider;
use crate::reports::report::ReportValue;
use crate::EniMetadataProvider;
use crate::HostMetadataProvider;

use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct EnvMetadata(Vec<(String, ReportValue)>);

impl EnvMetadata {
    pub fn new() -> Self {
        EnvMetadata(Vec::new())
    }
    pub fn from(vec: Vec<(String, ReportValue)>) -> Self {
        EnvMetadata(vec)
    }
    pub fn insert(&mut self, key: String, value: ReportValue) {
        self.0.push((key, value));
    }
    pub fn enumerate(&self) -> impl Iterator<Item = &(String, ReportValue)> {
        self.0.iter()
    }
    pub fn extend(&mut self, other: EnvMetadata) {
        self.0.extend(other.0);
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    pub fn get(&self, key: &str) -> Option<&ReportValue> {
        self.0
            .iter()
            .find_map(|(k, v)| if k == key { Some(v) } else { None })
    }
}

impl Default for EnvMetadata {
    fn default() -> Self {
        Self::new()
    }
}

pub trait EnvMetadataProvider {
    fn refresh(&mut self);
    fn get_metadata(&self) -> EnvMetadata;
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct NetworkDevice {
    pub device_name: String,
    pub interface_id: String,
}

pub trait MultiMetadataProvider: EnvMetadataProvider {
    fn get_network_devices(&mut self) -> Vec<NetworkDevice>;
}

pub struct MultiMetadataProviderImpl {
    pub eni_metadata: EniMetadataProvider,
    pub host_metadata: HostMetadataProvider,
    pub runtime_env_metadata: RuntimeEnvironmentMetadataProvider,
}

impl MultiMetadataProvider for MultiMetadataProviderImpl {
    fn get_network_devices(&mut self) -> Vec<NetworkDevice> {
        self.eni_metadata.get_network_devices()
    }
}

impl EnvMetadataProvider for MultiMetadataProviderImpl {
    fn refresh(&mut self) {
        self.eni_metadata.refresh();
        self.host_metadata.refresh();
        self.runtime_env_metadata.refresh();
    }

    fn get_metadata(&self) -> EnvMetadata {
        let mut metadata = EnvMetadata::new();
        metadata.extend(self.eni_metadata.get_metadata());
        metadata.extend(self.host_metadata.get_metadata());
        metadata.extend(self.runtime_env_metadata.get_metadata());

        metadata
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::metadata::eni::NetworkInterfaceInfo;
    use crate::utils::FakeCommandRunner;
    use aws_config::imds::Client;

    #[test]
    fn test_multi_metadata_provider() {
        let eni_metadata = EniMetadataProvider {
            client: Client::builder().build(),
            instance_id: "the-instance-id".into(),
            instance_type: "the-instance-type".into(),
            network: vec![NetworkInterfaceInfo {
                mac: "the-mac".into(),
                interface_id: "the-interface-id".into(),
            }],
            command_runner: Box::new(FakeCommandRunner::new()),
        };
        let host_metadata = HostMetadataProvider::default();
        let runtime_env_metadata = RuntimeEnvironmentMetadataProvider::default();
        let mut mmp = MultiMetadataProviderImpl {
            eni_metadata,
            host_metadata,
            runtime_env_metadata,
        };

        let multi_md = mmp.get_metadata();
        assert!(multi_md.contains_key("instance-id"));
        assert!(multi_md.contains_key("machine-id"));
        assert!(multi_md.contains_key("instance-type"));
        assert!(multi_md.contains_key("compute_platform"));

        mmp.refresh();
        assert!(mmp.get_metadata().len() >= 4);
    }
}
