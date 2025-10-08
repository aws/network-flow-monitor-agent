// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

/// A simple container to store IP:port pair
#[derive(Clone, Debug)]
pub struct IpPort {
    pub ip_address: IpAddr,
    pub port: u16,
}
