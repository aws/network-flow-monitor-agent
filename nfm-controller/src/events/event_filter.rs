// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub trait EventFilter<T> {
    fn filter_events(&mut self, events: Vec<T>) -> Vec<T>;
}
