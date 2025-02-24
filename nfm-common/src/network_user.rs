// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::network::{ControlData, CpuSockKey, EventCounters, SockContext, SockStats};

use aya::Pod;

unsafe impl Pod for ControlData {}
unsafe impl Pod for CpuSockKey {}
unsafe impl Pod for EventCounters {}
unsafe impl Pod for SockStats {}
unsafe impl Pod for SockContext {}
