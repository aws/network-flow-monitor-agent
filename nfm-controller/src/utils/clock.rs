// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use libc::{
    c_int, clock_gettime, timespec, CLOCK_BOOTTIME, CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME,
};
use std::mem;
use std::time::Duration;

pub trait Clock: Send {
    fn now(&self) -> timespec;

    fn now_us(&self) -> u64 {
        timespec_to_us(self.now())
    }

    fn sleep(&mut self, span: Duration) {
        std::thread::sleep(span);
    }
}

pub struct ProcessClock;
pub struct SystemBootClock;
pub struct RealTimeClock;

// A clock used to deterimistically control time in unit tests.
#[derive(Clone, Default)]
pub struct FakeClock {
    pub now_us: u64,
}

impl Clock for ProcessClock {
    fn now(&self) -> timespec {
        clock_time(CLOCK_PROCESS_CPUTIME_ID)
    }
}

impl Clock for SystemBootClock {
    fn now(&self) -> timespec {
        clock_time(CLOCK_BOOTTIME)
    }
}

impl Clock for FakeClock {
    fn now(&self) -> timespec {
        timespec {
            tv_sec: self.now_us as i64 / 1_000_000,
            tv_nsec: (self.now_us as i64 % 1_000_000) * 1000,
        }
    }

    fn now_us(&self) -> u64 {
        self.now_us
    }

    fn sleep(&mut self, span: Duration) {
        self.now_us += span.as_micros() as u64;
    }
}

impl Clock for RealTimeClock {
    fn now(&self) -> timespec {
        clock_time(CLOCK_REALTIME)
    }
}

// Gets the amount of time that has elapsed from a point in the past until the given clock's now.
const NSEC_PER_SEC: i64 = 1_000_000_000;
pub fn clock_delta<T: Clock + ?Sized>(clock: &T, past: timespec) -> timespec {
    let now = clock.now();
    let mut sec_adjustment = 0;
    let mut nsec_adjustment = 0;
    if now.tv_nsec < past.tv_nsec {
        sec_adjustment = -1;
        nsec_adjustment = NSEC_PER_SEC;
    }
    let spec = timespec {
        tv_sec: now.tv_sec - past.tv_sec + sec_adjustment,
        tv_nsec: now.tv_nsec - past.tv_nsec + nsec_adjustment,
    };
    assert!(
        spec.tv_sec >= 0 && spec.tv_nsec >= 0,
        "now: sec={} nsec={}; past: sec={} nsec={}",
        now.tv_sec,
        now.tv_nsec,
        past.tv_sec,
        past.tv_nsec,
    );

    spec
}

pub fn timespec_to_us(spec: timespec) -> u64 {
    spec.tv_sec as u64 * 1_000_000 + spec.tv_nsec as u64 / 1000
}

pub fn timespec_to_nsec(spec: timespec) -> u64 {
    (spec.tv_sec * NSEC_PER_SEC + spec.tv_nsec) as u64
}

// Gets the current time measured by the given clock type.
fn clock_time(clock_type: c_int) -> timespec {
    let mut spec: timespec = unsafe { mem::zeroed() };
    let result = unsafe { clock_gettime(clock_type, &mut spec) };
    if result != 0 {
        spec.tv_sec = 0;
        spec.tv_nsec = 0;
    }

    spec
}

#[cfg(test)]
mod test {
    use super::*;

    use libc::timespec;

    #[test]
    fn test_timespec_to_nsec() {
        let mut spec = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(timespec_to_nsec(spec), 0);

        spec.tv_nsec = 1;
        assert_eq!(timespec_to_nsec(spec), 1);

        spec.tv_nsec = 1000;
        assert_eq!(timespec_to_nsec(spec), 1000);

        spec.tv_sec = 1979;
        assert_eq!(timespec_to_nsec(spec), 1_979_000_001_000);
    }

    #[test]
    fn test_timespec_to_us() {
        let mut spec = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(timespec_to_us(spec), 0);

        spec.tv_nsec = 1;
        assert_eq!(timespec_to_us(spec), 0);

        spec.tv_nsec = 1_000_000;
        assert_eq!(timespec_to_us(spec), 1000);

        spec.tv_sec = 1979;
        assert_eq!(timespec_to_us(spec), 1_979_001_000);
    }

    #[test]
    fn test_process_clock() {
        test_clock(&ProcessClock {});
    }

    #[test]
    fn test_fake_clock() {
        test_clock(&FakeClock { now_us: 1_000_000 });
    }

    #[test]
    fn test_boot_clock() {
        let mut clock = SystemBootClock {};
        test_clock(&clock);

        let start = clock.now_us();
        clock.sleep(Duration::from_millis(100));
        let end = clock.now_us();
        assert!(
            end - start > 95,
            "Expected to sleep roughly 100 ms, slept {} ms",
            end - start
        );
    }

    #[test]
    fn test_fake_clock_sleep() {
        let mut clock = FakeClock::default();
        assert_eq!(clock.now_us(), 0);

        clock.sleep(Duration::from_micros(0));
        assert_eq!(clock.now_us(), 0);

        clock.sleep(Duration::from_micros(19));
        assert_eq!(clock.now_us(), 19);

        clock.sleep(Duration::from_micros(3));
        assert_eq!(clock.now_us(), 22);

        clock.sleep(Duration::from_micros(0));
        assert_eq!(clock.now_us(), 22);
    }

    #[test]
    fn test_real_time_clock() {
        test_clock(&RealTimeClock {});
    }

    #[test]
    fn test_real_time_clock_againts_utc() {
        assert_eq!(
            RealTimeClock {}.now().tv_sec,
            chrono::Utc::now().timestamp()
        );
    }

    fn test_clock<T: Clock>(clock: &T) {
        // Validate our clock's time is not zero, and does not decrease.
        let mut last_time = clock.now_us();
        assert!(last_time > 0);
        for _ in 1..100 {
            let new_time = clock.now_us();
            assert!(new_time >= last_time);
            last_time = new_time;
        }
    }

    #[test]
    fn test_clock_delta() {
        let past_time = timespec {
            tv_sec: 1,
            tv_nsec: 2_000_000,
        };

        let clock = FakeClock { now_us: 2001000 };
        let current_time = clock.now();

        let expected = timespec {
            tv_sec: 2,
            tv_nsec: 1_000_000,
        };
        assert_eq!(current_time.tv_sec, expected.tv_sec);
        assert_eq!(current_time.tv_nsec, expected.tv_nsec);

        // Test with a higher nanosec in the past.
        let actual = clock_delta(&clock, past_time);
        let expected = timespec {
            tv_sec: 0,
            tv_nsec: 999_000_000,
        };
        assert_eq!(actual.tv_sec, expected.tv_sec);
        assert_eq!(actual.tv_nsec, expected.tv_nsec);

        // Test with a lower nanosec in the past.
        let past_time = timespec {
            tv_sec: 1,
            tv_nsec: 900_000,
        };
        let actual = clock_delta(&clock, past_time);
        let expected = timespec {
            tv_sec: 1,
            tv_nsec: 100_000,
        };
        assert_eq!(actual.tv_sec, expected.tv_sec);
        assert_eq!(actual.tv_nsec, expected.tv_nsec);
    }

    #[test]
    #[should_panic]
    fn test_clock_delta_panic() {
        // Test with a larger time in the past, which should fail.
        let past_time = timespec {
            tv_sec: 3,
            tv_nsec: 2_000_000,
        };

        let clock = FakeClock { now_us: 2001 };
        clock_delta(&clock, past_time);
    }
}
