// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::events::nat_resolver::NatResolver;
use crate::events::network_event::AggregateResults;
use crate::reports::CountersOverall;

use std::vec::Vec;

pub trait EventProvider {
    #[allow(clippy::borrowed_box)]
    fn perform_aggregation_cycle(&mut self, nat_resolver: &Box<dyn NatResolver>);
    fn network_stats(&mut self) -> Vec<AggregateResults>;
    fn counters(&mut self) -> CountersOverall;
    fn socket_count(&self) -> u64;
}
