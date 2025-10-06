// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Check whether or not a given value is within a given percent tolerance of an expected value.
 * i.e. if the expected value is 100, and percent is 10, actual should be within 90 to 110.
 */
pub fn within_abs_percent_tolerance(actual: u64, expected: u64, percent: f64) -> bool {
    let actual_f = actual as f64;
    let expected_f = expected as f64;
    let tolerance = expected_f * (percent / 100.0);
    (actual_f - expected_f).abs() <= tolerance
}
