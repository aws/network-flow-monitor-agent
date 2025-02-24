// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use crate::reports::report::ReportValue;

pub fn to_value_pairs<T: Serialize>(item: &T) -> Vec<(String, ReportValue)> {
    let item_serialized = serde_json::to_value(item).unwrap();
    let key_value_map = item_serialized.as_object().unwrap();
    key_value_map
        .iter()
        .filter_map(|(k, v)| {
            // Serialize only primitive types into the report.
            if !v.is_object() && !v.is_array() {
                Some((k.clone(), v.into()))
            } else {
                None
            }
        })
        .collect()
}

#[macro_export]
macro_rules! add_histogram_to_report {
    ($self:ident, $field:ident, $vec:expr) => {
        $vec.push((
            stringify!($field).to_string(),
            ReportValue::Histogram($self.$field),
        ));
    };
}
