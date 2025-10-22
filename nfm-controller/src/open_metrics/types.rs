// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Type aliases for complex data structures used in the open_metrics module.
//!
//! This module provides readable type aliases for complex generic types to improve
//! code readability and maintainability throughout the open_metrics module.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::Mutex;

use crate::kubernetes::kubernetes_metadata_collector::PodInfo;
use crate::open_metrics::provider::OpenMetricProvider;
use crate::open_metrics::providers::interface_metrics_provider::types::{
    NamespaceId, NamespaceInfo,
};

/// Type alias for a thread-safe collection of OpenMetric providers
///
/// This encapsulates the complex `Rc<Mutex<Vec<Box<dyn OpenMetricProvider>>>>` type
/// used throughout the metrics server for managing metric providers.
pub type MetricProviders = Rc<Mutex<Vec<Box<dyn OpenMetricProvider>>>>;

/// Type alias for namespace information mapping
///
/// This encapsulates `HashMap<NamespaceId, NamespaceInfo>` used for
/// mapping network namespace IDs to their associated information.
pub type NamespaceMapping = HashMap<NamespaceId, NamespaceInfo>;

/// Type alias for IP address to pod information mapping
///
/// This encapsulates `HashMap<IpAddr, HashSet<PodInfo>>` used for
/// mapping IP addresses to sets of pod information in Kubernetes environments.
pub type IpToPodMapping = HashMap<IpAddr, HashSet<PodInfo>>;
