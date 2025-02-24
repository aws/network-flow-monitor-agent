// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use log::{error, info};
use procfs::{process::Process, Current, Meminfo};

const BYTES_PER_KB: u64 = 1024;

pub trait MemoryInspector {
    // Returns a tuple of used KB and its ratio of total memory.
    fn usage(&self) -> (u64, f64);
}

pub struct ProcessMemoryInspector {
    pid: u32,
    total_kb: u64,
}

#[allow(clippy::new_without_default)]
impl ProcessMemoryInspector {
    pub fn new() -> Self {
        let total_kb = match Meminfo::current() {
            Ok(meminfo) => meminfo.mem_total / BYTES_PER_KB,
            Err(e) => {
                // TODO: Increment counter on mem retrieval error.
                error!(error = e.to_string(); "Failed to retrieve total memory");
                0
            }
        };
        info!(total_kb = total_kb; "Retrieved total system memory");

        Self {
            pid: std::process::id(),
            total_kb,
        }
    }
}

impl MemoryInspector for ProcessMemoryInspector {
    fn usage(&self) -> (u64, f64) {
        if let Ok(process) = Process::new(self.pid as i32) {
            let used_kb = match process.stat() {
                Ok(stat) => stat.rss * procfs::page_size() / BYTES_PER_KB,
                Err(e) => {
                    // TODO: Increment counter on mem retrieval error.
                    error!(error = e.to_string(); "Failed to retrieve process memory");
                    0
                }
            };

            (used_kb, used_kb as f64 / self.total_kb as f64)
        } else {
            (0, 0.0)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_process_memory_inspector() {
        let inspector = ProcessMemoryInspector::new();
        let (mem_used, mem_ratio_used) = inspector.usage();
        assert!(mem_used > 0);
        assert!(mem_ratio_used < 0.10);
    }
}
