// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::env;

use serde::{Deserialize, Serialize};

use crate::reports::report::ReportValue;

pub const ENV_K8S_NODE_NAME: &str = "K8S_NODE_NAME";
pub const ENV_EKS_CLUSTER_NAME: &str = "EKS_CLUSTER_NAME";

#[derive(Clone, Debug, Serialize, PartialEq, Deserialize)]
pub struct K8sMetadata {
    pub node_name: Option<ReportValue>,
    pub cluster_name: Option<ReportValue>,
}

impl Default for K8sMetadata {
    fn default() -> Self {
        K8sMetadata {
            node_name: {
                if let Ok(node_name) = env::var(ENV_K8S_NODE_NAME) {
                    Some(ReportValue::String(node_name))
                } else {
                    None
                }
            },
            cluster_name: {
                if let Ok(node_name) = env::var(ENV_EKS_CLUSTER_NAME) {
                    Some(ReportValue::String(node_name))
                } else {
                    None
                }
            },
        }
    }
}

impl K8sMetadata {
    pub fn new(node_name: &str, cluster_name: &str) -> Self {
        K8sMetadata {
            node_name: Some(ReportValue::String(node_name.to_string())),
            cluster_name: Some(ReportValue::String(cluster_name.to_string())),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    pub static UNIT_TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

    #[macro_export]
    macro_rules! acquire_test_lock {
        () => {
            let _lock = crate::metadata::k8s_metadata::tests::UNIT_TEST_MUTEX
                .get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap();
        };
    }

    #[test]
    fn test_no_data() {
        acquire_test_lock!();

        let k8s_metadata = K8sMetadata::default();
        assert_eq!(k8s_metadata.node_name, None);
        assert_eq!(k8s_metadata.cluster_name, None);
    }

    pub fn unset_k8s_env_vars() {
        env::remove_var(ENV_K8S_NODE_NAME);
        env::remove_var(ENV_EKS_CLUSTER_NAME);
    }

    pub fn set_k8s_eks_env_vars() {
        env::set_var(ENV_K8S_NODE_NAME, "k8s-node-name");
        env::set_var(ENV_EKS_CLUSTER_NAME, "eks-cluster-name");
    }

    pub fn set_k8s_vanilla_env_vars() {
        env::set_var(ENV_K8S_NODE_NAME, "k8s-node-name");
        env::remove_var(ENV_EKS_CLUSTER_NAME);
    }

    #[test]
    fn test_some_data() {
        acquire_test_lock!();

        set_k8s_eks_env_vars();
        let k8s_metadata = K8sMetadata::default();
        unset_k8s_env_vars();
        assert_eq!(
            k8s_metadata.node_name,
            Some(ReportValue::String("k8s-node-name".to_string()))
        );
        assert_eq!(
            k8s_metadata.cluster_name,
            Some(ReportValue::String("eks-cluster-name".to_string()))
        );
    }

    #[test]
    fn test_service_metadata_new() {
        let k8s_metadata = K8sMetadata::new("node_name", "cluster_name");
        assert_eq!(
            k8s_metadata.node_name,
            Some(ReportValue::String("node_name".into()))
        );
        assert_eq!(
            k8s_metadata.cluster_name,
            Some(ReportValue::String("cluster_name".into()))
        );
    }
}
