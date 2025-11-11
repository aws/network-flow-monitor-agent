// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Network namespace statistics collection for interface metrics provider.

use log::{debug, warn};
use std::fs;

use crate::{
    open_metrics::providers::interface_metrics_provider::types::NamespaceInfo, utils::CommandRunner,
};

/// Network namespace flow statistics
#[derive(Debug, Clone, Default)]
pub struct NetNsInterfaceMetricValues {
    pub ingress_flow_count: u64,
    pub egress_flow_count: u64,
}

impl NetNsInterfaceMetricValues {
    pub fn new(ingress_flows: u64, egress_flows: u64) -> Self {
        Self {
            ingress_flow_count: ingress_flows,
            egress_flow_count: egress_flows,
        }
    }

    pub fn calculate_delta(&self, previous: &Self) -> Self {
        Self {
            ingress_flow_count: self
                .ingress_flow_count
                .saturating_sub(previous.ingress_flow_count),
            egress_flow_count: self
                .egress_flow_count
                .saturating_sub(previous.egress_flow_count),
        }
    }
}

/// Collects network namespace statistics
pub struct NetNsStats {
    command_runner: Box<dyn CommandRunner>,
}

impl NetNsStats {
    pub fn new(command_runner: Box<dyn CommandRunner>) -> Self {
        Self { command_runner }
    }

    /// Get TCP flow statistics for a namespace
    pub fn get_namespace_flow_stats(
        &self,
        ns_info: &NamespaceInfo,
    ) -> Result<NetNsInterfaceMetricValues, String> {
        match &ns_info.ns_file {
            Some(ns_file) => self.execute_nsenter(
                &["--net", ns_file, "nstat", "-a"],
                &format!("File {}", ns_file),
            ),
            None => self.try_read_proc_netstat(ns_info.pid.as_u32()),
        }
    }

    fn execute_nsenter(
        &self,
        args: &[&str],
        context: &str,
    ) -> Result<NetNsInterfaceMetricValues, String> {
        let output = self.command_runner.run("nsenter", args);

        let output = output.map_err(|e| {
            warn!(context = context; "Failed to execute nsenter command");
            format!("Failed to execute nsenter command: {e}")
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                context = context;
                "Failed to get TCP statistics: {}",
                stderr
            );
            return Err(format!("nsenter command failed: {stderr}"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(self.parse_nstat_output(&stdout))
    }

    /// Try to read /proc/$pid/net/snmp directly for optimization
    fn try_read_proc_netstat(&self, pid: u32) -> Result<NetNsInterfaceMetricValues, String> {
        let proc_path = format!("/proc/{}/net/snmp", pid);

        match fs::read_to_string(&proc_path) {
            Ok(content) => {
                debug!("Successfully read {}", proc_path);
                Ok(self.parse_proc_netstat(&content))
            }
            Err(e) => {
                debug!("Failed to read {}: {}", proc_path, e);
                Err(format!("Failed to read {}: {}", proc_path, e))
            }
        }
    }

    /// Parse /proc/$pid/net/snmp format for TCP connection statistics
    fn parse_proc_netstat(&self, content: &str) -> NetNsInterfaceMetricValues {
        let mut tcp_active_opens = 0;
        let mut tcp_passive_opens = 0;

        let lines: Vec<&str> = content.lines().collect();

        // Look for Tcp section
        for i in 0..lines.len() {
            let line = lines[i];
            if line.starts_with("Tcp:") && i + 1 < lines.len() {
                let header_line = line;
                let values_line = lines[i + 1];

                match self.parse_tcp_section(header_line, values_line) {
                    Ok(stats) => {
                        tcp_active_opens = stats.egress_flow_count;
                        tcp_passive_opens = stats.ingress_flow_count;
                    }
                    Err(e) => {
                        debug!("Error parsing TCP section: {}", e);
                        // Continue with default values (0)
                    }
                }
                break;
            }
        }

        NetNsInterfaceMetricValues::new(tcp_passive_opens, tcp_active_opens)
    }

    /// Parse TCP section from /proc/net/snmp
    fn parse_tcp_section(
        &self,
        header_line: &str,
        values_line: &str,
    ) -> Result<NetNsInterfaceMetricValues, String> {
        let headers: Vec<&str> = header_line.split_whitespace().collect();
        let values: Vec<&str> = values_line.split_whitespace().collect();

        if headers.len() != values.len() {
            let error_msg = "Header and value count mismatch in /proc/net/snmp TCP section";
            warn!("{}", error_msg);
            return Err(error_msg.to_string());
        }

        let mut tcp_active_opens = 0;
        let mut tcp_passive_opens = 0;

        for (i, header) in headers.iter().enumerate() {
            match *header {
                "ActiveOpens" => {
                    tcp_active_opens = values[i].parse::<u64>().unwrap_or_else(|_| {
                        warn!("Error parsing ActiveOpens value: {}", values[i]);
                        0
                    });
                }
                "PassiveOpens" => {
                    tcp_passive_opens = values[i].parse::<u64>().unwrap_or_else(|_| {
                        warn!("Error parsing PassiveOpens value: {}", values[i]);
                        0
                    });
                }
                _ => {} // Ignore other fields
            }

            // Early termination optimization
            if tcp_active_opens > 0 && tcp_passive_opens > 0 {
                break;
            }
        }

        Ok(NetNsInterfaceMetricValues::new(
            tcp_passive_opens,
            tcp_active_opens,
        ))
    }

    /// Parse nstat output for TCP connection statistics
    fn parse_nstat_output(&self, output: &str) -> NetNsInterfaceMetricValues {
        let mut tcp_active_opens = 0;
        let mut tcp_passive_opens = 0;

        for line in output.lines() {
            if line.starts_with("TcpActiveOpens") {
                tcp_active_opens = parse_nstat_value(line, "TcpActiveOpens");
            } else if line.starts_with("TcpPassiveOpens") {
                tcp_passive_opens = parse_nstat_value(line, "TcpPassiveOpens");
            }

            // Early termination optimization
            if tcp_active_opens > 0 && tcp_passive_opens > 0 {
                break;
            }
        }

        NetNsInterfaceMetricValues::new(tcp_passive_opens, tcp_active_opens)
    }
}

/// Parse numeric value from nstat output line
pub fn parse_nstat_value(line: &str, stat_name: &str) -> u64 {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() >= 2 {
        fields[1].parse::<u64>().unwrap_or_else(|_| {
            warn!("Error parsing {} value from line: {}", stat_name, line);
            0
        })
    } else {
        warn!("Malformed {} line: {}", stat_name, line);
        0
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Error, ErrorKind},
        os::unix::process::ExitStatusExt,
        process::{ExitStatus, Output},
        vec,
    };

    use super::*;
    use crate::{
        open_metrics::providers::interface_metrics_provider::types::ProcessId,
        utils::FakeCommandRunner,
    };

    #[test]
    fn test_netns_stats_parse_nstat() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let nstat_output = "TcpActiveOpens                  150                0.0
TcpPassiveOpens                 200                0.0
TcpAttemptFails                 5                  0.0";

        let result = collector.parse_nstat_output(nstat_output);

        assert_eq!(result.ingress_flow_count, 200); // TcpPassiveOpens
        assert_eq!(result.egress_flow_count, 150); // TcpActiveOpens
    }

    #[test]
    fn test_parse_nstat_value_valid() {
        let line = "TcpActiveOpens                  150                0.0";
        let result = parse_nstat_value(line, "TcpActiveOpens");
        assert_eq!(result, 150);
    }

    #[test]
    fn test_parse_nstat_value_invalid() {
        let line = "TcpActiveOpens                  invalid            0.0";
        let result = parse_nstat_value(line, "TcpActiveOpens");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_parse_nstat_value_malformed() {
        let line = "TcpActiveOpens";
        let result = parse_nstat_value(line, "TcpActiveOpens");
        assert_eq!(result, 0);
    }

    #[test]
    fn test_netns_interface_metric_values_delta() {
        let current = NetNsInterfaceMetricValues::new(100, 80);
        let previous = NetNsInterfaceMetricValues::new(70, 50);

        let delta = current.calculate_delta(&previous);

        assert_eq!(delta.ingress_flow_count, 30);
        assert_eq!(delta.egress_flow_count, 30);
    }

    #[test]
    fn test_netns_interface_metric_values_delta_saturating() {
        let current = NetNsInterfaceMetricValues::new(50, 30);
        let previous = NetNsInterfaceMetricValues::new(100, 80); // Higher than current

        let delta = current.calculate_delta(&previous);

        assert_eq!(delta.ingress_flow_count, 0); // Should saturate to 0
        assert_eq!(delta.egress_flow_count, 0); // Should saturate to 0
    }

    #[test]
    fn test_get_namespace_flow_stats_success() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/proc/1234/ns/net", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"TcpActiveOpens                  100                0.0\nTcpPassiveOpens                 200                0.0\nTcpAttemptFails                 5                  0.0".to_vec(),
                stderr: vec![],
            }),
        );

        let collector = NetNsStats::new(Box::new(fake_runner));
        let ns_info = NamespaceInfo {
            pid: ProcessId::new(1234),
            ns_file: Some("/proc/1234/ns/net".to_string()),
            ip_addresses: vec![],
        };
        let result = collector.get_namespace_flow_stats(&ns_info).unwrap();

        assert_eq!(result.ingress_flow_count, 200); // TcpPassiveOpens
        assert_eq!(result.egress_flow_count, 100); // TcpActiveOpens
    }

    #[test]
    fn test_get_namespace_flow_stats_command_failure() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["-t", "1234", "-n", "nstat", "-a"],
            Err(Error::new(ErrorKind::NotFound, "nsenter not found")),
        );

        let collector = NetNsStats::new(Box::new(fake_runner));
        let ns_info = NamespaceInfo {
            pid: ProcessId::new(1234),
            ns_file: None,
            ip_addresses: vec![],
        };
        let result = collector.get_namespace_flow_stats(&ns_info);

        // Should return error on command failure
        assert!(result.is_err());
    }

    #[test]
    fn test_get_namespace_flow_stats_non_zero_exit() {
        let mut fake_runner = FakeCommandRunner::new();
        fake_runner.add_expectation(
            "nsenter",
            &["--net", "/proc/1234/ns/net", "nstat", "-a"],
            Ok(Output {
                status: ExitStatus::from_raw(1 << 8), // Exit code 1
                stdout: vec![],
                stderr: b"Permission denied".to_vec(),
            }),
        );

        let collector = NetNsStats::new(Box::new(fake_runner));
        let ns_info = NamespaceInfo {
            pid: ProcessId::new(1234),
            ns_file: Some("/proc/1234/ns/net".to_string()),
            ip_addresses: vec![],
        };
        let result = collector.get_namespace_flow_stats(&ns_info);

        // Should return error on command failure
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("nsenter command failed"));
    }

    #[test]
    fn test_parse_nstat_output_partial_data() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        // Test with only TcpActiveOpens
        let nstat_output = "TcpActiveOpens                  150                0.0\nTcpAttemptFails                 5                  0.0";
        let result = collector.parse_nstat_output(nstat_output);
        assert_eq!(result.ingress_flow_count, 0); // No TcpPassiveOpens
        assert_eq!(result.egress_flow_count, 150); // TcpActiveOpens

        // Test with only TcpPassiveOpens
        let nstat_output = "TcpPassiveOpens                 200                0.0\nTcpAttemptFails                 5                  0.0";
        let result = collector.parse_nstat_output(nstat_output);
        assert_eq!(result.ingress_flow_count, 200); // TcpPassiveOpens
        assert_eq!(result.egress_flow_count, 0); // No TcpActiveOpens
    }

    #[test]
    fn test_parse_nstat_output_empty() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let result = collector.parse_nstat_output("");
        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }

    #[test]
    fn test_parse_nstat_output_malformed_lines() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let nstat_output = "TcpActiveOpens\nTcpPassiveOpens invalid_value 0.0\nTcpAttemptFails                 5                  0.0";
        let result = collector.parse_nstat_output(nstat_output);

        // Should handle malformed lines gracefully
        assert_eq!(result.ingress_flow_count, 0); // TcpPassiveOpens line was malformed
        assert_eq!(result.egress_flow_count, 0); // TcpActiveOpens line was malformed
    }

    #[test]
    fn test_parse_nstat_output_early_termination() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        // Test that parsing stops early when both values are found
        let nstat_output = "TcpActiveOpens                  100                0.0
TcpPassiveOpens                 200                0.0
TcpRetransSegs                  50                 0.0
TcpInSegs                       1000               0.0";

        let result = collector.parse_nstat_output(nstat_output);
        assert_eq!(result.ingress_flow_count, 200);
        assert_eq!(result.egress_flow_count, 100);
    }

    #[test]
    fn test_netns_interface_metric_values_default() {
        let default_values = NetNsInterfaceMetricValues::default();
        assert_eq!(default_values.ingress_flow_count, 0);
        assert_eq!(default_values.egress_flow_count, 0);
    }

    #[test]
    fn test_netns_interface_metric_values_new() {
        let values = NetNsInterfaceMetricValues::new(100, 50);
        assert_eq!(values.ingress_flow_count, 100);
        assert_eq!(values.egress_flow_count, 50);
    }

    #[test]
    fn test_parse_nstat_value_edge_cases() {
        // Test with extra whitespace
        let line = "TcpActiveOpens                     150                   0.0";
        let result = parse_nstat_value(line, "TcpActiveOpens");
        assert_eq!(result, 150);

        // Test with minimum fields
        let line = "TcpActiveOpens 150";
        let result = parse_nstat_value(line, "TcpActiveOpens");
        assert_eq!(result, 150);

        // Test with zero value
        let line = "TcpActiveOpens                  0                0.0";
        let result = parse_nstat_value(line, "TcpActiveOpens");
        assert_eq!(result, 0);

        // Test with large number
        let line = "TcpActiveOpens                  18446744073709551615                0.0";
        let result = parse_nstat_value(line, "TcpActiveOpens");
        assert_eq!(result, 18446744073709551615);
    }

    #[test]
    fn test_parse_proc_netstat() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        // This is the actual format from /proc/net/snmp
        let proc_snmp_content = "Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
Ip: 1 255 34597080 0 1 9651 0 0 34587427 30845281 12 32 0 0 0 0 0 0 0
Icmp: InMsgs InErrors InCsumErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps OutAddrMasks OutAddrMaskReps
Icmp: 2304 2 0 2148 6 0 0 0 114 0 36 0 0 0 4005 0 3855 0 0 0 0 0 150 0 0 0 0
Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 100 200 5 10 2 1000 800 50 0 20 0
Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors IgnoredMulti
Udp: 2827021 5108 0 3335454 0 0 0 0";

        let result = collector.parse_proc_netstat(proc_snmp_content);
        assert_eq!(result.ingress_flow_count, 200); // PassiveOpens
        assert_eq!(result.egress_flow_count, 100); // ActiveOpens
    }

    #[test]
    fn test_parse_tcp_section() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let header_line = "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors";
        let values_line = "Tcp: 1 200 120000 -1 150 250 5 10 2 1000 800 50 0 20 0";

        let result = collector.parse_tcp_section(header_line, values_line);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert_eq!(stats.ingress_flow_count, 250); // PassiveOpens
        assert_eq!(stats.egress_flow_count, 150); // ActiveOpens
    }

    #[test]
    fn test_parse_tcp_section_mismatch() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let header_line = "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens";
        let values_line = "Tcp: 1 200 120000 -1 150"; // Missing values

        let result = collector.parse_tcp_section(header_line, values_line);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Header and value count mismatch"));
    }

    #[test]
    fn test_parse_tcp_section_invalid_values() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let header_line =
            "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails";
        let values_line = "Tcp: 1 200 120000 -1 invalid_active invalid_passive 5";

        let result = collector.parse_tcp_section(header_line, values_line);
        assert!(result.is_ok());

        let stats = result.unwrap();
        assert_eq!(stats.ingress_flow_count, 0); // PassiveOpens parsing failed
        assert_eq!(stats.egress_flow_count, 0); // ActiveOpens parsing failed
    }

    #[test]
    fn test_parse_proc_netstat_no_tcp_section() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let proc_netstat_content = "TcpExt: SyncookiesSent SyncookiesRecv
TcpExt: 0 0
IpExt: InNoRoutes InTruncatedPkts
IpExt: 0 0";

        let result = collector.parse_proc_netstat(proc_netstat_content);
        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }

    #[test]
    fn test_parse_proc_netstat_partial_tcp_data() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        // Test with only ActiveOpens in TCP section
        let proc_netstat_content =
            "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens AttemptFails
Tcp: 1 200 120000 -1 150 5";

        let result = collector.parse_proc_netstat(proc_netstat_content);
        assert_eq!(result.ingress_flow_count, 0); // No PassiveOpens
        assert_eq!(result.egress_flow_count, 150); // ActiveOpens
    }

    #[test]
    fn test_parse_proc_netstat_early_termination() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let proc_netstat_content = "Tcp: RtoAlgorithm RtoMin RtoMax MaxConn ActiveOpens PassiveOpens AttemptFails EstabResets CurrEstab InSegs OutSegs RetransSegs InErrs OutRsts InCsumErrors
Tcp: 1 200 120000 -1 100 200 5 10 2 1000 800 50 0 20 0";

        let result = collector.parse_proc_netstat(proc_netstat_content);
        assert_eq!(result.ingress_flow_count, 200); // PassiveOpens
        assert_eq!(result.egress_flow_count, 100); // ActiveOpens
    }

    #[test]
    fn test_parse_proc_netstat_empty() {
        let fake_runner = FakeCommandRunner::new();
        let collector = NetNsStats::new(Box::new(fake_runner));

        let result = collector.parse_proc_netstat("");
        assert_eq!(result.ingress_flow_count, 0);
        assert_eq!(result.egress_flow_count, 0);
    }
}
