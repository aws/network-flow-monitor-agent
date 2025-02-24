// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::utils::Clock;

use log::debug;
use rand::Rng;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::{
    atomic::{AtomicBool, Ordering as AtomicOrd},
    Arc,
};
use std::time::Duration;

pub type EventId = u32;
pub const EXIT_EVENT: EventId = 0;
pub const UNKNOWN_EVENT: EventId = u32::MAX;

pub struct EventTimer<T: Clock> {
    clock: T,
    last_id: EventId,
    events: BinaryHeap<PeriodicEvent>,
    exit_flag: Option<Arc<AtomicBool>>,
}

impl<T: Clock> EventTimer<T> {
    pub fn new(clock: T) -> Self {
        EventTimer {
            clock,
            last_id: EXIT_EVENT,
            events: BinaryHeap::new(),
            exit_flag: None,
        }
    }

    pub fn set_exit_flag(&mut self, flag: Arc<AtomicBool>) {
        self.exit_flag = Some(flag);
    }

    fn create_event(&mut self, period: Duration, jitter: Duration) -> PeriodicEvent {
        self.last_id += 1;
        let mut event = PeriodicEvent {
            id: self.last_id,
            period_us: period.as_micros().try_into().unwrap(),
            jitter_us: jitter.as_micros().try_into().unwrap(),
            next_invocation: 0,
        };
        event.choose_next_invocation(self.clock.now_us());
        event
    }

    // Returns a new event ID to be invoked at a cadence of the given period +/- jitter. And an initial extra delay
    pub fn add_event(&mut self, period: Duration, jitter: Duration) -> EventId {
        let event = self.create_event(period, jitter);
        self.events.push(event);
        self.last_id
    }

    // Returns a new event ID to be invoked at a cadence of the given period +/- jitter. And an initial extra delay
    pub fn add_event_with_delay(
        &mut self,
        period: Duration,
        jitter: Duration,
        delay: Duration,
    ) -> EventId {
        let mut event = self.create_event(period, jitter);
        event.next_invocation += delay.as_micros() as u64;
        self.events.push(event);

        self.last_id
    }

    // Sleeps until returning the next event ID that should be invoked.
    pub fn await_next_event(&mut self) -> EventId {
        let next_event = self.events.pop();

        if let Some(mut event) = next_event {
            let event_id = event.id;

            let now = self.clock.now_us();
            if event.next_invocation > now && self.try_sleep(event.next_invocation, now).is_err() {
                return EXIT_EVENT;
            }
            event.choose_next_invocation(self.clock.now_us());
            self.events.push(event);

            event_id
        } else {
            EXIT_EVENT
        }
    }

    fn try_sleep(&mut self, until_us: u64, mut now_us: u64) -> Result<(), String> {
        let mut span = Duration::from_micros(until_us - now_us);
        debug!("Waiting {span:?} until the next event...");

        while until_us > now_us {
            let sleep_fragment_us = (until_us - now_us).min(1_000_000);
            span = Duration::from_micros(sleep_fragment_us);
            self.clock.sleep(span);

            now_us += sleep_fragment_us;
            if let Some(exit_flag) = &self.exit_flag {
                if exit_flag.load(AtomicOrd::Relaxed) {
                    return Err("should exit".to_string());
                }
            }
        }

        Ok(())
    }
}

struct PeriodicEvent {
    id: EventId,
    period_us: u64,
    jitter_us: u64,
    next_invocation: u64,
}

impl PeriodicEvent {
    /*
     * Sets this event's next invocation to be within +/- jitter one period from now.
     *
     *     now       next period
     *      v            v
     *      |------------|------------|
     *                |-----| <-- jitter range
     */
    fn choose_next_invocation(&mut self, now_us: u64) {
        let rand_jitter: u64 = if self.jitter_us > 0 {
            rand::thread_rng().gen_range(0..self.jitter_us * 2)
        } else {
            0
        };
        self.next_invocation = now_us + self.period_us - self.jitter_us + rand_jitter;
    }
}

impl Eq for PeriodicEvent {}

impl PartialEq for PeriodicEvent {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PartialOrd for PeriodicEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeriodicEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        // Order events by the time of their next invocation.
        match self.next_invocation.cmp(&other.next_invocation) {
            Ordering::Less => Ordering::Greater,
            Ordering::Equal => Ordering::Equal,
            Ordering::Greater => Ordering::Less,
        }
    }
}

#[cfg(test)]
mod test {
    use libc::timespec;
    use std::sync::{
        atomic::{AtomicBool, Ordering as AtomicOrd},
        Arc,
    };

    use super::*;
    use crate::utils::{Clock, FakeClock, SystemBootClock};

    #[test]
    fn test_event_timer() {
        let mut timer = EventTimer::new(FakeClock::default());
        let (period_us, jitter_us) = (100, 5);
        let id1 = timer.add_event(
            Duration::from_micros(period_us),
            Duration::from_micros(jitter_us),
        );
        assert!(id1 > EXIT_EVENT);

        let (period_us, jitter_us) = (40, 2);
        let id2 = timer.add_event(
            Duration::from_micros(period_us),
            Duration::from_micros(jitter_us),
        );

        let (period_us, jitter_us) = (110, 5);
        let id3 = timer.add_event(
            Duration::from_micros(period_us),
            Duration::from_micros(jitter_us),
        );

        // Confirm events are retrieved in the following order.
        let event_ids = vec![id2, id2, id1, id3, id2, id2];
        for expected_id in event_ids {
            let actual_id = timer.await_next_event();
            assert_eq!(actual_id, expected_id);
        }

        // Ensure the elapsed time is within our jitter bounds (4 periods of even #2).
        let (elapsed_min, elapsed_max) = (38 * 4, 42 * 4);
        let now = timer.clock.now_us();
        assert!(now >= elapsed_min && now <= elapsed_max);
    }

    #[test]
    fn test_event_timer_delay() {
        let mut timer = EventTimer::new(FakeClock::default());
        let start_us = timer.clock.now_us();
        let (period_us, jitter_us, delay) = (100, 0, 500);
        let id1 = timer.add_event_with_delay(
            Duration::from_micros(period_us),
            Duration::from_micros(jitter_us),
            Duration::from_micros(delay),
        );
        assert!(id1 > EXIT_EVENT);

        let found_id = timer.await_next_event();
        assert_eq!(found_id, id1);

        let elapsed_us = timer.clock.now_us() - start_us;
        assert!(elapsed_us >= 600, "Expected elapsed_us={elapsed_us} > 600");
    }

    #[test]
    fn test_event_timer_system_clock() {
        let clock = SystemBootClock {};
        let start_us = clock.now_us();

        let mut timer = EventTimer::new(SystemBootClock {});
        let (period_us, jitter_us) = (100, 0);
        let event_id = timer.add_event(
            Duration::from_micros(period_us),
            Duration::from_micros(jitter_us),
        );
        let found_id = timer.await_next_event();
        assert_eq!(found_id, event_id);

        let elapsed_us = clock.now_us() - start_us;
        assert!(elapsed_us >= 100, "Expected elapsed_us={elapsed_us} > 100");
    }

    #[test]
    fn test_event_timer_empty() {
        let mut timer = EventTimer::new(FakeClock::default());
        for _ in 0..10 {
            assert_eq!(EXIT_EVENT, timer.await_next_event());
        }
        assert_eq!(0, timer.clock.now_us());
    }

    #[test]
    fn test_next_event_invocation() {
        let mut event = PeriodicEvent {
            id: 0,
            period_us: 0,
            jitter_us: 0,
            next_invocation: 0,
        };

        let mut now_us = 0;

        // Test an empty period & jitter.
        event.choose_next_invocation(now_us);
        assert_eq!(event.next_invocation, 0);

        // Test a period with no jitter.
        event.period_us = 1979;
        event.choose_next_invocation(now_us);
        assert_eq!(event.next_invocation, 1979);

        // Test a repeat.
        event.choose_next_invocation(now_us);
        assert_eq!(event.next_invocation, 1979);

        now_us = 2049;
        event.choose_next_invocation(now_us);
        assert_eq!(event.next_invocation, 2049 + 1979);

        // Test a period with jitter.  Every result must be within jitter of the next period.
        now_us = 12300;
        event.period_us = 50;
        event.jitter_us = 5;
        for _ in 0..20 {
            event.choose_next_invocation(now_us);
            assert!(
                event.next_invocation >= 12345 && event.next_invocation <= 12355,
                "{} is outside expected bounds",
                event.next_invocation
            );
        }
    }

    struct FakeNoSleepClock {
        now_us: u64,
    }
    impl Clock for FakeNoSleepClock {
        fn now_us(&self) -> u64 {
            self.now_us
        }

        fn sleep(&mut self, _span: Duration) {
            // Ignore sleep
        }

        fn now(&self) -> timespec {
            timespec {
                tv_sec: self.now_us as i64 / 1_000_000,
                tv_nsec: (self.now_us as i64 % 1_000_000) * 1000,
            }
        }
    }

    #[test]
    fn test_event_invocation_in_the_past() {
        // Found a bug where the event is not added back to the
        // event list when event.next_invocation <= now

        const MAX_TIME_US: u64 = 1000;
        const EVENT_PERIOD: u64 = 100;
        let clock = FakeNoSleepClock {
            now_us: MAX_TIME_US,
        };

        let mut timer = EventTimer::new(clock);

        // Create an event manually to control the next execution time.
        let event_id = 1;
        let event = PeriodicEvent {
            id: event_id,
            period_us: EVENT_PERIOD,
            jitter_us: 0,
            next_invocation: 0,
        };
        timer.events.push(event);

        // Retrieve the event using the regular logic.
        let found_id = timer.await_next_event();
        assert_eq!(found_id, event_id);

        // Check that the event was added back.
        assert_eq!(timer.events.len(), 1);

        // Test the same again to validate the full flow
        let found_id = timer.await_next_event();
        assert_eq!(found_id, event_id);
        assert_eq!(timer.events.len(), 1);
    }

    #[test]
    fn test_try_sleep() {
        let mut timer = EventTimer::new(FakeClock::default());
        let should_exit = Arc::new(AtomicBool::new(false));
        timer.set_exit_flag(Arc::clone(&should_exit));

        // Confirm sleep succeeds when not interrupted.
        let now_us = timer.clock.now_us();
        let sleep_until_us = now_us + 10;
        assert!(timer.try_sleep(sleep_until_us, now_us).is_ok());

        // Confirm sleep does not succeed when we are interrupted.
        let now_us = timer.clock.now_us();
        let sleep_until_us = now_us + 10;
        should_exit.store(true, AtomicOrd::Relaxed);
        assert!(timer.try_sleep(sleep_until_us, now_us).is_err());

        // Test returning to successful sleep.
        let now_us = timer.clock.now_us();
        let sleep_until_us = now_us + 10;
        should_exit.store(false, AtomicOrd::Relaxed);
        assert!(timer.try_sleep(sleep_until_us, now_us).is_ok());

        // Confirm successful sleep when no flag is set.
        let mut timer = EventTimer::new(FakeClock::default());
        let now_us = timer.clock.now_us();
        let sleep_until_us = now_us + 10;
        assert!(timer.try_sleep(sleep_until_us, now_us).is_ok());
    }

    #[test]
    fn test_interrupted_await_next_event() {
        let mut timer = EventTimer::new(FakeClock::default());
        let should_exit = Arc::new(AtomicBool::new(true));
        timer.set_exit_flag(Arc::clone(&should_exit));

        let (period_us, jitter_us) = (100, 0);
        let _ = timer.add_event(
            Duration::from_micros(period_us),
            Duration::from_micros(jitter_us),
        );
        assert_eq!(timer.await_next_event(), EXIT_EVENT);
    }
}
