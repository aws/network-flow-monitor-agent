// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;

use crate::metadata::env_metadata_provider::{EnvMetadata, EnvMetadataProvider};
use crate::reports::report::ReportValue;
use std::convert::From;

const KEY_COMPUTE_PLATFORM: &str = "compute_platform";

#[derive(Debug, Clone, PartialEq)]
/// Represents the underlying hardware fabric that the agent runs on, plus orchestration platform if applicable
/// Only EC2 based right now, will contain Fargate in future
pub enum ComputePlatform {
    Ec2Plain,
    Ec2K8sEks,     // Elastic Kubernetes Service from AWS
    Ec2K8sVanilla, // Plain/vanilla Kubernetes
}

// To convert enum to string
impl std::fmt::Display for ComputePlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ComputePlatform::Ec2Plain => write!(f, "EC2_PLAIN"),
            ComputePlatform::Ec2K8sEks => write!(f, "EC2_K8S_EKS"),
            ComputePlatform::Ec2K8sVanilla => write!(f, "EC2_K8S_VANILLA"),
        }
    }
}

pub struct RuntimeEnvironmentMetadataProvider {
    compute_platform: ComputePlatform,
}

impl From<ComputePlatform> for RuntimeEnvironmentMetadataProvider {
    fn from(compute_platform: ComputePlatform) -> Self {
        RuntimeEnvironmentMetadataProvider { compute_platform }
    }
}

impl RuntimeEnvironmentMetadataProvider {
    pub fn new() -> Self {
        Self {
            compute_platform: Self::get_compute_platform(),
        }
    }

    fn get_compute_platform() -> ComputePlatform {
        if env::var(super::k8s_metadata::ENV_EKS_CLUSTER_NAME).is_ok() {
            ComputePlatform::Ec2K8sEks
        } else if env::var(super::k8s_metadata::ENV_K8S_NODE_NAME).is_ok() {
            ComputePlatform::Ec2K8sVanilla
        } else {
            ComputePlatform::Ec2Plain
        }
    }
}

impl Default for RuntimeEnvironmentMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl EnvMetadataProvider for RuntimeEnvironmentMetadataProvider {
    fn refresh(&mut self) {
        // runtime environment is static, no need to refresh
    }

    fn get_metadata(&self) -> EnvMetadata {
        EnvMetadata::from(vec![(
            KEY_COMPUTE_PLATFORM.into(),
            ReportValue::String(self.compute_platform.to_string()),
        )])
    }
}

#[cfg(test)]
mod test {

    use crate::metadata::k8s_metadata;

    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test_k8s_eks_env() {
        crate::acquire_test_lock!();

        k8s_metadata::tests::set_k8s_eks_env_vars();

        let mut rm_provider = RuntimeEnvironmentMetadataProvider::default();
        rm_provider.refresh();
        let metadata = rm_provider.get_metadata();
        assert_eq!(metadata.len(), 1);
        if let ReportValue::String(str_value) =
            metadata.get(&KEY_COMPUTE_PLATFORM.to_string()).unwrap()
        {
            assert!(str_value.eq(&ComputePlatform::Ec2K8sEks.to_string()));
        }

        k8s_metadata::tests::unset_k8s_env_vars();
    }

    #[test]
    fn test_k8s_vanilla_env() {
        crate::acquire_test_lock!();
        k8s_metadata::tests::set_k8s_vanilla_env_vars();

        let mut rm_provider = RuntimeEnvironmentMetadataProvider::default();
        rm_provider.refresh();
        let metadata = rm_provider.get_metadata();
        assert_eq!(metadata.len(), 1);
        if let ReportValue::String(str_value) =
            metadata.get(&KEY_COMPUTE_PLATFORM.to_string()).unwrap()
        {
            assert!(str_value.eq(&ComputePlatform::Ec2K8sVanilla.to_string()));
        }
        k8s_metadata::tests::unset_k8s_env_vars();
    }

    #[test]
    fn test_ec2_env() {
        crate::acquire_test_lock!();

        k8s_metadata::tests::unset_k8s_env_vars();

        let mut rm_provider = RuntimeEnvironmentMetadataProvider::default();
        rm_provider.refresh();
        let metadata = rm_provider.get_metadata();
        assert_eq!(metadata.len(), 1);
        if let ReportValue::String(str_value) =
            metadata.get(&KEY_COMPUTE_PLATFORM.to_string()).unwrap()
        {
            assert!(str_value.eq(&ComputePlatform::Ec2Plain.to_string()));
        }
    }
}
