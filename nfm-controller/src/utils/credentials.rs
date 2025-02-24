// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_config::BehaviorVersion;
use aws_credential_types::provider::ProvideCredentials;

pub fn get_credentials_provider() -> impl ProvideCredentials {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(aws_config::load_defaults(BehaviorVersion::latest()))
        .credentials_provider()
        .expect("error getting credential provider")
}
