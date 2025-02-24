// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{event_filter::EventFilter, network_event::AggregateResults};
use std::cmp::Ordering;

pub(crate) struct EventFilterTopLoss {
    max_items: u32,
}

impl EventFilterTopLoss {
    pub fn new(max_items: u32) -> Self {
        Self { max_items }
    }
}

impl EventFilterTopLoss {
    fn cmp(lhs: &AggregateResults, rhs: &AggregateResults) -> Ordering {
        match lhs.stats.quantify_loss().cmp(&rhs.stats.quantify_loss()) {
            val if val != Ordering::Equal => val,
            _ => {
                // When both sides have equal loss, compare by total bytes.
                lhs.stats.total_bytes().cmp(&rhs.stats.total_bytes())
            }
        }
    }
}

impl EventFilter<AggregateResults> for EventFilterTopLoss {
    fn filter_events(&mut self, events: Vec<AggregateResults>) -> Vec<AggregateResults> {
        // Note the comparison of `b` to `a` for a reverse sort.
        let mut events = events;
        events.sort_by(|a, b| EventFilterTopLoss::cmp(b, a));
        events.truncate(self.max_items as usize);
        events
    }
}

#[cfg(test)]
mod tests {
    use super::EventFilterTopLoss;
    use crate::events::{
        event_filter::EventFilter,
        network_event::{AggregateResults, FlowProperties, InetProtocol, NetworkStats},
    };
    use std::cmp::Ordering;
    use std::net::IpAddr;

    fn empty_flow() -> FlowProperties {
        FlowProperties {
            protocol: InetProtocol::ANY,
            local_address: "0.0.0.0".parse::<IpAddr>().unwrap(),
            remote_address: "0.0.0.0".parse::<IpAddr>().unwrap(),
            local_port: 0,
            remote_port: 0,
            kubernetes_metadata: None,
        }
    }

    #[test]
    fn test_top_loss_cmp() {
        let result_all_good = AggregateResults {
            flow: empty_flow(),
            stats: Default::default(),
        };
        let result_retrans = AggregateResults {
            flow: empty_flow(),
            stats: NetworkStats {
                retrans_syn: 20,
                ..Default::default()
            },
        };
        let result_rto = AggregateResults {
            flow: empty_flow(),
            stats: NetworkStats {
                rtos_syn: 20,
                ..Default::default()
            },
        };
        let result_disconnect = AggregateResults {
            flow: empty_flow(),
            stats: NetworkStats {
                severed_establish: 20,
                ..Default::default()
            },
        };
        let result_all_good_more_bytes = AggregateResults {
            flow: empty_flow(),
            stats: NetworkStats {
                bytes_received: 1,
                ..Default::default()
            },
        };

        assert_eq!(
            EventFilterTopLoss::cmp(&result_all_good, &result_retrans),
            Ordering::Less
        );
        assert_eq!(
            EventFilterTopLoss::cmp(&result_retrans, &result_all_good),
            Ordering::Greater
        );
        assert_eq!(
            EventFilterTopLoss::cmp(&result_retrans, &result_rto),
            Ordering::Less
        );
        assert_eq!(
            EventFilterTopLoss::cmp(&result_disconnect, &result_rto),
            Ordering::Greater
        );
        assert_eq!(
            EventFilterTopLoss::cmp(&result_disconnect, &result_disconnect),
            Ordering::Equal
        );
        assert_eq!(
            EventFilterTopLoss::cmp(&result_all_good, &result_all_good),
            Ordering::Equal
        );
        assert_eq!(
            EventFilterTopLoss::cmp(&result_all_good_more_bytes, &result_all_good),
            Ordering::Greater
        );
    }

    #[test]
    fn test_top_loss_filter() {
        // Give each agg-result a flow with a unique local port so's to easily identify the flow in
        // test results.
        let empty_flow = empty_flow();
        let result_all_good = AggregateResults {
            flow: FlowProperties {
                local_port: 1,
                ..empty_flow.clone()
            },
            stats: Default::default(),
        };
        let result_retrans = AggregateResults {
            flow: FlowProperties {
                local_port: 2,
                ..empty_flow.clone()
            },
            stats: NetworkStats {
                retrans_syn: 20,
                ..Default::default()
            },
        };
        let result_rto = AggregateResults {
            flow: FlowProperties {
                local_port: 3,
                ..empty_flow.clone()
            },
            stats: NetworkStats {
                retrans_syn: 20,
                ..Default::default()
            },
        };
        let result_disconnect = AggregateResults {
            flow: FlowProperties {
                local_port: 4,
                ..empty_flow.clone()
            },
            stats: NetworkStats {
                severed_establish: 20,
                ..Default::default()
            },
        };
        let result_all_good_more_bytes = AggregateResults {
            flow: FlowProperties {
                local_port: 5,
                ..empty_flow.clone()
            },
            stats: NetworkStats {
                bytes_received: 1,
                ..Default::default()
            },
        };

        let mut event_list = vec![
            result_rto.clone(),
            result_all_good_more_bytes.clone(),
            result_disconnect.clone(),
            result_all_good.clone(),
            result_retrans.clone(),
        ];
        let mut filter = EventFilterTopLoss::new(event_list.len() as u32);
        let mut top_loss_result = filter.filter_events(event_list);

        // Confirm results are in the expected order.
        let expected_ids = vec![4, 3, 2, 5, 1];
        let actual_ids = top_loss_result
            .iter()
            .map(|r| r.flow.local_port)
            .collect::<Vec<u16>>();
        assert_eq!(actual_ids, expected_ids);

        // Test with a smaller max.
        event_list = vec![
            result_rto,
            result_all_good_more_bytes,
            result_disconnect,
            result_all_good,
            result_retrans,
        ];
        filter = EventFilterTopLoss { max_items: 3 };
        top_loss_result = filter.filter_events(event_list);

        // Confirm results are in the expected order.
        let expected_ids = vec![4, 3, 2];
        let actual_ids = top_loss_result
            .iter()
            .map(|r| r.flow.local_port)
            .collect::<Vec<u16>>();
        assert_eq!(actual_ids, expected_ids);
    }
}
