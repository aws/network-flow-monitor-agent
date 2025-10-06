// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TestFabric {
    Plain, // Any hardware not associated with ec2 or k8s
    EC2,
    K8s,
}
