// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::metadata::env_metadata_provider::NetworkDevice;
use crate::reports::report::ReportValue;
use crate::utils::report::to_value_pairs;
use crate::utils::{CommandRunner, RealCommandRunner};

use hashbrown::{HashMap, HashSet};
use log::error;
use serde::{Deserialize, Serialize};

// Statistics within this structure are used by the Network Flow Monitor back-end to gauge the status of the host
// on which the agent is running.  This allows for correlation with issues visible on the host.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct HostStats {
    pub(crate) interface_stats: Vec<GroupedInterfaceStats>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GroupedInterfaceStats {
    pub interface_id: String,
    pub stats: NetworkInterfaceStats,
}

#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NetworkInterfaceStats {
    // ENA driver stats from ethtool.
    pub bw_in_allowance_exceeded: u64,
    pub bw_out_allowance_exceeded: u64,
    pub conntrack_allowance_exceeded: u64,
    pub linklocal_allowance_exceeded: u64,
    pub pps_allowance_exceeded: u64,
    pub conntrack_allowance_available: u64,
}

impl NetworkInterfaceStats {
    pub fn subtract(&self, rhs: &NetworkInterfaceStats) -> NetworkInterfaceStats {
        NetworkInterfaceStats {
            // Subtract cumulative counters.
            bw_in_allowance_exceeded: self
                .bw_in_allowance_exceeded
                .wrapping_sub(rhs.bw_in_allowance_exceeded),
            bw_out_allowance_exceeded: self
                .bw_out_allowance_exceeded
                .wrapping_sub(rhs.bw_out_allowance_exceeded),
            conntrack_allowance_exceeded: self
                .conntrack_allowance_exceeded
                .wrapping_sub(rhs.conntrack_allowance_exceeded),
            linklocal_allowance_exceeded: self
                .linklocal_allowance_exceeded
                .wrapping_sub(rhs.linklocal_allowance_exceeded),
            pps_allowance_exceeded: self
                .pps_allowance_exceeded
                .wrapping_sub(rhs.pps_allowance_exceeded),

            // Maintain level-based stats.
            conntrack_allowance_available: self.conntrack_allowance_available,
        }
    }

    pub fn enumerate(&self) -> Vec<(String, ReportValue)> {
        to_value_pairs(&self)
    }
}

pub trait HostStatsProvider {
    fn set_network_devices(&mut self, net_devices: &[NetworkDevice]);
    fn get_stats(&mut self) -> HostStats;
}

pub struct HostStatsProviderImpl {
    pub(crate) network_interface_stats: HashMap<NetworkDevice, NetworkInterfaceStats>,

    command_runner: Box<dyn CommandRunner>,
}

impl HostStatsProvider for HostStatsProviderImpl {
    fn set_network_devices(&mut self, net_devices: &[NetworkDevice]) {
        let devices: HashSet<&NetworkDevice> = HashSet::from_iter(net_devices);

        // Purge old devices.
        self.network_interface_stats
            .retain(|key, _| devices.contains(key));

        // Add new.
        for net_dev in devices.into_iter() {
            if !self.network_interface_stats.contains_key(net_dev) {
                // Stats must be loaded now for newly added devices so that we don't treat
                // historical values as large deltas.
                let stats = self
                    .load_single_iface_stats(&net_dev.device_name)
                    .unwrap_or_default();
                self.network_interface_stats.insert(net_dev.clone(), stats);
            }
        }
    }

    fn get_stats(&mut self) -> HostStats {
        // Interface stats read from the host are cumulative.  Thus, we cache the latest values,
        // then return the deltas.

        let latest_iface_stats = self.load_all_iface_stats();
        let mut delta_iface_stats = HashMap::<NetworkDevice, NetworkInterfaceStats>::new();

        for (net_device, latest_stats) in latest_iface_stats.iter() {
            delta_iface_stats.insert(
                net_device.clone(),
                latest_stats.subtract(self.network_interface_stats.get(net_device).unwrap()),
            );
        }
        self.network_interface_stats = latest_iface_stats;

        self.build_host_stats(delta_iface_stats)
    }
}

impl Default for HostStatsProviderImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl HostStatsProviderImpl {
    pub fn new() -> Self {
        Self {
            network_interface_stats: HashMap::new(),
            command_runner: Box::new(RealCommandRunner {}),
        }
    }

    fn build_host_stats(
        &self,
        iface_stats: HashMap<NetworkDevice, NetworkInterfaceStats>,
    ) -> HostStats {
        let grouped_iface_stats = iface_stats
            .into_iter()
            .map(|(net_dev, stats)| GroupedInterfaceStats {
                interface_id: net_dev.interface_id,
                stats,
            })
            .collect();

        HostStats {
            interface_stats: grouped_iface_stats,
        }
    }

    // Loads stats for all configured network interfaces.
    fn load_all_iface_stats(&mut self) -> HashMap<NetworkDevice, NetworkInterfaceStats> {
        let mut latest_iface_stats = HashMap::<NetworkDevice, NetworkInterfaceStats>::new();
        let net_devices: Vec<NetworkDevice> =
            self.network_interface_stats.keys().cloned().collect();
        for net_device in net_devices {
            match self.load_single_iface_stats(&net_device.device_name) {
                Ok(stats) => {
                    latest_iface_stats.insert(net_device.clone(), stats);
                }
                Err(err) => {
                    error!(device:serde = net_device, error = err.to_string(); "Failed to get ethtool stats");

                    // Preserve prior stats on error.
                    let stats = self.network_interface_stats.get(&net_device).unwrap();
                    latest_iface_stats.insert(net_device.clone(), *stats);
                }
            }
        }

        latest_iface_stats
    }

    // Loads stats for a single network interface.
    fn load_single_iface_stats(
        &mut self,
        dev_name: &str,
    ) -> Result<NetworkInterfaceStats, std::io::Error> {
        let output = self.command_runner.run("ethtool", &["-S", dev_name])?;

        let mut stats = NetworkInterfaceStats::default();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
            if parts.len() != 2 {
                continue;
            }

            let val: u64 = parts[1].parse().unwrap_or_default();
            match parts[0] {
                "bw_in_allowance_exceeded:" => stats.bw_in_allowance_exceeded = val,
                "bw_out_allowance_exceeded:" => stats.bw_out_allowance_exceeded = val,
                "conntrack_allowance_exceeded:" => stats.conntrack_allowance_exceeded = val,
                "linklocal_allowance_exceeded:" => stats.linklocal_allowance_exceeded = val,
                "pps_allowance_exceeded:" => stats.pps_allowance_exceeded = val,
                "conntrack_allowance_available:" => stats.conntrack_allowance_available = val,
                _ => {
                    // No-op
                }
            };
        }

        Ok(stats)
    }
}

#[cfg(test)]
mod test {
    use crate::events::host_stats_provider::{
        GroupedInterfaceStats, HostStats, HostStatsProvider, HostStatsProviderImpl,
        NetworkInterfaceStats,
    };
    use crate::metadata::env_metadata_provider::NetworkDevice;
    use crate::utils::FakeCommandRunner;

    use hashbrown::HashMap;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    // Used to create command output for test cases.
    macro_rules! ethtool_template {
        () => {
            r#"
	    NIC statistics:
                 total_resets: 0
                 reset_fail: 0
                 tx_timeout: 0
		 bw_in_allowance_exceeded: {}
		 bw_out_allowance_exceeded: {}
		 pps_allowance_exceeded: {}
		 conntrack_allowance_exceeded: {}
		 linklocal_allowance_exceeded: {}
		 conntrack_allowance_available: {}
		 ena_admin_q_out_of_space: 0
		 ena_admin_q_no_completion: 0
	    "#
        };
    }

    #[test]
    fn test_load_single_iface_stats() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ethtool",
            &["-S", "eth0"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(ethtool_template!(), 5, 6, 9, 7, 8, 10)
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );

        let expected_stats = NetworkInterfaceStats {
            bw_in_allowance_exceeded: 5,
            bw_out_allowance_exceeded: 6,
            conntrack_allowance_exceeded: 7,
            linklocal_allowance_exceeded: 8,
            pps_allowance_exceeded: 9,
            conntrack_allowance_available: 10,
        };

        let mut host_stats_provider = HostStatsProviderImpl {
            network_interface_stats: HashMap::new(),
            command_runner: Box::new(fake_runner.clone()),
        };

        let actual_stats = host_stats_provider.load_single_iface_stats("eth0").unwrap();
        assert_eq!(actual_stats, expected_stats);
        assert!(fake_runner.expectations.lock().unwrap().is_empty());
    }

    #[test]
    fn test_load_stats_from_incompatible_driver() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ethtool",
            &["-S", "eth0"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: "NIC statistics from other driver".as_bytes().to_vec(),
                stderr: vec![],
            }),
        );

        let expected_stats = NetworkInterfaceStats {
            bw_in_allowance_exceeded: 0,
            bw_out_allowance_exceeded: 0,
            conntrack_allowance_exceeded: 0,
            linklocal_allowance_exceeded: 0,
            pps_allowance_exceeded: 0,
            conntrack_allowance_available: 0,
        };

        let mut host_stats_provider = HostStatsProviderImpl {
            network_interface_stats: HashMap::new(),
            command_runner: Box::new(fake_runner.clone()),
        };

        let actual_stats = host_stats_provider.load_single_iface_stats("eth0").unwrap();
        assert_eq!(actual_stats, expected_stats);
        assert!(fake_runner.expectations.lock().unwrap().is_empty());
    }

    #[test]
    fn test_get_host_stats() {
        // Set our command expectations.
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "ethtool",
            &["-S", "eth1"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(ethtool_template!(), 5, 6, 9, 7, 8, 10)
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );
        fake_runner.add_expectation(
            "ethtool",
            &["-S", "eth2"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(ethtool_template!(), 55, 66, 99, 77, 88, 1010)
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );

        // Build what we expect should be loaded.
        let device1 = NetworkDevice {
            interface_id: "id1".to_string(),
            device_name: "eth1".to_string(),
        };
        let device2 = NetworkDevice {
            interface_id: "id2".to_string(),
            device_name: "eth2".to_string(),
        };
        let expected_stats1 = NetworkInterfaceStats {
            bw_in_allowance_exceeded: 5,
            bw_out_allowance_exceeded: 6,
            conntrack_allowance_exceeded: 7,
            linklocal_allowance_exceeded: 8,
            pps_allowance_exceeded: 9,
            conntrack_allowance_available: 10,
        };
        let expected_stats2 = NetworkInterfaceStats {
            bw_in_allowance_exceeded: 55,
            bw_out_allowance_exceeded: 66,
            conntrack_allowance_exceeded: 77,
            linklocal_allowance_exceeded: 88,
            pps_allowance_exceeded: 99,
            conntrack_allowance_available: 1010,
        };

        // Do work.
        let mut host_stats_provider = HostStatsProviderImpl {
            network_interface_stats: HashMap::new(),
            command_runner: Box::new(fake_runner.clone()),
        };
        host_stats_provider.set_network_devices(&[device1.clone(), device2.clone()]);

        // Validate stats initially loaded.
        let mut expected_internal_stats = HashMap::<NetworkDevice, NetworkInterfaceStats>::new();
        expected_internal_stats.insert(device1, expected_stats1);
        expected_internal_stats.insert(device2, expected_stats2);
        assert_eq!(
            host_stats_provider.network_interface_stats,
            expected_internal_stats
        );

        // Mimic an error for eth1 and the linklocal value changed for eth2.
        fake_runner.add_expectation(
            "ethtool",
            &["-S", "eth1"],
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fake-error",
            )),
        );
        fake_runner.add_expectation(
            "ethtool",
            &["-S", "eth2"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: format!(ethtool_template!(), 55, 66, 99, 77, 89, 1010)
                    .as_bytes()
                    .to_vec(),
                stderr: vec![],
            }),
        );
        let mut expected_stats = HostStats {
            interface_stats: vec![
                // eth1 values show no change after command failure.
                GroupedInterfaceStats {
                    interface_id: "id1".to_string(),
                    stats: NetworkInterfaceStats {
                        conntrack_allowance_available: 10,
                        ..Default::default()
                    },
                },
                // eth2 values represent the diff on command success.
                GroupedInterfaceStats {
                    interface_id: "id2".to_string(),
                    stats: NetworkInterfaceStats {
                        linklocal_allowance_exceeded: 1,
                        conntrack_allowance_available: 1010,
                        ..Default::default()
                    },
                },
            ],
        };

        // Do work again, and validate.
        assert_eq!(
            host_stats_provider.get_stats().interface_stats.sort(),
            expected_stats.interface_stats.sort()
        );
        assert!(fake_runner.expectations.lock().unwrap().is_empty());
    }
}
