// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub trait MinNonZero {
    fn min_non_zero(self, other: u32) -> u32;
}

impl MinNonZero for u32 {
    fn min_non_zero(self, other: u32) -> u32 {
        if self > 0 && other > 0 {
            self.min(other)
        } else {
            self.max(other)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::MinNonZero;

    #[test]
    fn test_min_non_zero() {
        let mut a: u32 = 0;
        let mut b: u32 = 0;
        assert_eq!(a.min_non_zero(b), 0);

        (a, b) = (1, 0);
        assert_eq!(a.min_non_zero(b), 1);

        (a, b) = (0, 1);
        assert_eq!(a.min_non_zero(b), 1);

        (a, b) = (1, 2);
        assert_eq!(a.min_non_zero(b), 1);

        (a, b) = (2, 1);
        assert_eq!(a.min_non_zero(b), 1);

        (a, b) = (100, 200);
        assert_eq!(a.min_non_zero(b), 100);

        (a, b) = (u32::MAX, u32::MAX - 1);
        assert_eq!(a.min_non_zero(b), u32::MAX - 1);
    }
}
