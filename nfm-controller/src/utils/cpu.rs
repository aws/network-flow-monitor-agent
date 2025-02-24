// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::utils::clock::{clock_delta, timespec_to_nsec, Clock, ProcessClock, SystemBootClock};

use libc::timespec;
use log::{error, info};
use std::fs;

// store CPU count statically instead of re-reading everytime, its not going to change, ever.
static CPU_CORE_COUNT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

fn get_core_count_from_cpuinfo() -> usize {
    let mut core_count = 1;
    if let Ok(contents) = fs::read_to_string("/proc/cpuinfo") {
        let core_count_cpuinfo = contents
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count();
        if core_count_cpuinfo > core_count {
            core_count = core_count_cpuinfo;
            info!(core_count; "Acquired processor CPU core count from /proc/cpuinfo");
        }
    }
    core_count
}

// Gets the total amount of available CPU cores across the whole physical die
pub fn get_total_cpu_core_count() -> usize {
    *CPU_CORE_COUNT.get_or_init(|| {
        match sys_info::cpu_num() {
            Ok(num_logical_cores) => {
                info!(num_logical_cores; "Acquired processor CPU core count from sys_info");
                num_logical_cores.try_into().unwrap()
            }
            Err(_) => {
                error!("Failed to acquire processor CPU core count from sys_info, falling back to /proc/cpuinfo");
                get_core_count_from_cpuinfo()
            }
        }
    })
}

pub struct CpuUsageMonitor {
    process_clock: ProcessClock,
    boot_clock: SystemBootClock,
    process_start: timespec,
    boot_start: timespec,
    num_cpus: usize,
}

impl CpuUsageMonitor {
    pub fn start() -> Self {
        let (process_clock, boot_clock) = (ProcessClock {}, SystemBootClock {});
        let (process_start, boot_start) = (process_clock.now(), boot_clock.now());
        Self {
            process_clock,
            boot_clock,
            process_start,
            boot_start,
            num_cpus: get_total_cpu_core_count(),
        }
    }

    pub fn usage_ratio(&self) -> f64 {
        let consumed = timespec_to_nsec(self.process_duration()) as f64;
        let elapsed = timespec_to_nsec(self.total_duration()) as f64;

        consumed / self.num_cpus as f64 / elapsed
    }

    // Gets the user and system time consumed by the current process across all logical cores since
    // this monitor was started.
    fn process_duration(&self) -> timespec {
        clock_delta(&self.process_clock, self.process_start)
    }

    // Gets the time that has elapsed since this monitor was started.
    fn total_duration(&self) -> timespec {
        clock_delta(&self.boot_clock, self.boot_start)
    }
}

#[cfg(test)]
mod test {
    use super::CpuUsageMonitor;
    use std::{thread, time};

    #[test]
    fn test_cpu_usage() {
        // Do no work, and validate CPU usage is less than 100%.
        let mut cpu_monitor = CpuUsageMonitor::start();
        thread::sleep(time::Duration::from_millis(1000));
        let low_usage_ratio = cpu_monitor.usage_ratio();
        assert!(
            low_usage_ratio < 1.0,
            "expected < 1.0, got {}",
            low_usage_ratio
        );

        // Do lots of work, and validate CPU usage is greater than 0%.
        cpu_monitor = CpuUsageMonitor::start();
        let mut x: f64 = 101.0;
        for _ in 0..1_000_000 {
            x = x * 107.0 / 103.0;
        }
        let high_usage_ratio = cpu_monitor.usage_ratio();
        assert!(
            high_usage_ratio > 0.0,
            "expected > 0.0, got {}",
            high_usage_ratio
        );
        assert!(
            high_usage_ratio <= 1.0,
            "expected <= 1.0, got {}",
            high_usage_ratio
        );
    }

    #[test]
    fn test_core_count_reader_cpuinfo() {
        let core_count = super::get_core_count_from_cpuinfo();
        assert!(core_count > 1 && core_count < 16384); // valid for all modern cpus, and for a foreseeable future
    }

    #[test]
    fn test_core_count_reader_sys_info() {
        let core_count = super::get_total_cpu_core_count();
        assert!(core_count > 1 && core_count < 16384); // valid for all modern cpus, and for a foreseeable future
    }
}
