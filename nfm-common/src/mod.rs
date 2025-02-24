// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg_attr(feature = "bpf", no_std)]

#[cfg(feature = "bpf")]
pub mod ebpf_actuals;
#[cfg(feature = "bpf")]
pub use ebpf_actuals::*;

#[cfg(not(feature = "bpf"))]
pub mod ebpf_mocks;
#[cfg(not(feature = "bpf"))]
pub use ebpf_mocks::*;

pub mod constants;
pub use constants::*;

pub mod network;
pub use network::*;

#[cfg(not(feature = "bpf"))]
pub mod network_user;

pub mod utils;
pub use crate::utils::MinNonZero;

pub mod sock_ops_handler;
pub use sock_ops_handler::{BpfControlConveyor, TcpSockOpsHandler};
