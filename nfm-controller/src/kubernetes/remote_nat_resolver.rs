// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use log::error;
use nfm_common::{SockContext, AF_INET, AF_INET6};

// only allow reading up to certain number of entries as this is very slow
pub const CONNTRACK_MAX_TRACK_COUNT: usize = 5000;
// each conntrack entry is around 230/325 bytes (ipv4/ipv6)
pub const CONNTRACK_READER_BUF_SIZE: usize = 5000 * 325;

#[derive(Debug, Clone)]
pub struct RemoteNatEntry {
    pub remote_ip_actual: IpAddr,
    pub remote_port_actual: u16,
}

#[derive(Eq, Hash, PartialEq)]
pub struct RemoteNatLookupEntry {
    pub local_ip: IpAddr,
    pub local_port: u16,
}

pub struct RemoteNatResolver {
    remote_nat_map: HashMap<RemoteNatLookupEntry, RemoteNatEntry>,
    conntrack_file_path: String,
    pub remote_nat_entries_detected: u64,
    pub unparsable_conntrack_entries_detected: u64,
}

impl Default for RemoteNatResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl RemoteNatResolver {
    pub fn new() -> Self {
        Self {
            remote_nat_map: HashMap::new(),
            conntrack_file_path: String::from("/proc/net/nf_conntrack"),
            remote_nat_entries_detected: 0,
            unparsable_conntrack_entries_detected: 0,
        }
    }

    pub fn new_with_custom_conntrack(conntrack_path: &str) -> Self {
        Self {
            remote_nat_map: HashMap::new(),
            conntrack_file_path: String::from(conntrack_path),
            remote_nat_entries_detected: 0,
            unparsable_conntrack_entries_detected: 0,
        }
    }

    fn insert(&mut self, key: RemoteNatLookupEntry, entry: RemoteNatEntry) {
        self.remote_nat_map.insert(key, entry);
    }

    pub fn get_entry(&self, key: &RemoteNatLookupEntry) -> Option<&RemoteNatEntry> {
        self.remote_nat_map.get(key)
    }

    pub fn get_entry_from_sock_context(
        &self,
        sock_context: &SockContext,
    ) -> Option<&RemoteNatEntry> {
        let local_address = match sock_context.address_family {
            AF_INET => IpAddr::V4(Ipv4Addr::from(sock_context.local_ipv4)),
            AF_INET6 => IpAddr::V6(Ipv6Addr::from(sock_context.local_ipv6)),
            _ => return None,
        };
        self.remote_nat_map.get(&RemoteNatLookupEntry {
            local_ip: local_address,
            local_port: sock_context.local_port,
        })
    }

    pub fn build_remote_nat_map(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut entry_count = 0;
        let file = match std::fs::File::open(self.conntrack_file_path.clone()) {
            Ok(file) => file,
            Err(e) => {
                error!(file_path = self.conntrack_file_path, error = e.to_string(); "Failed to open conntrack file");
                return Err(e.into());
            }
        };
        let reader = BufReader::with_capacity(CONNTRACK_READER_BUF_SIZE, file);
        for line in reader.lines() {
            match line {
                Ok(line) => match self.parse_and_save_conntrack_line(&line) {
                    Some(()) => (),
                    None => {
                        error!(line_str = line; "Conntrack line contains an unparsable entry");
                        self.unparsable_conntrack_entries_detected += 1;
                    }
                },
                Err(e) => {
                    error!(error = e.to_string(); "Error reading conntrack line");
                    return Err(e.into());
                }
            }
            entry_count += 1;
            if entry_count >= CONNTRACK_MAX_TRACK_COUNT {
                break;
            };
        }
        Ok(())
    }

    fn string_to_ipv4(decimal_ip: &str) -> Result<IpAddr, std::net::AddrParseError> {
        let ip: std::net::Ipv4Addr = decimal_ip.parse()?;
        Ok(IpAddr::V4(ip))
    }

    fn string_to_ipv6(hex_ipv6: &str) -> Result<IpAddr, std::net::AddrParseError> {
        let ip: std::net::Ipv6Addr = hex_ipv6.parse()?;
        Ok(IpAddr::V6(ip))
    }

    // What we are looking for are entries that have unmatching remote IPs we see and what remote party sees. For instance for following entry
    // "ipv4 2 tcp 6 118 SYN_SENT src=172.19.107.118 dst=2.2.2.2 sport=33424 dport=80 src=192.168.23.16 dst=172.19.107.118 sport=80 dport=33424 mark=0 use=1"
    // we send a packet to 2.2.2.2 but we expect 192.168.23.16 to send us responses
    // for packets that we send to 2.2.2.2 netfilter changes 2.2.2.2 to 192.168.23.16 before it hits the wire
    // and for reverse direction it changes src-ip of the packets arriving from 192.168.23.16 to 2.2.2.2
    // our purpose is to detect these entries
    fn parse_and_save_conntrack_line(&mut self, line: &str) -> Option<()> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 14 {
            // safety check
            return Some(());
        }
        if parts[2] != "tcp" {
            return Some(());
        };
        if parts[10].starts_with('[') {
            // ipv4 2 tcp 6 118 SYN_SENT src=172.19.107.118 dst=2.2.2.2 sport=33424 dport=80 [UNREPLIED] src=2.2.2.2 dst=172.19.107.118 sport=80 dport=33424 mark=0 use=1
            return Some(()); // means this isnt an established connection no need to track
        }

        let ip_version = parts[0].to_string();
        let local_ip_that_sends_the_packet = parts[6].split('=').nth(1)?.to_string();
        let local_port_that_sends_the_packet = parts[8].split('=').nth(1)?.parse().ok()?;
        let remote_ip_we_think_we_send_to = parts[7].split('=').nth(1)?.to_string();
        let remote_ip_that_hits_the_wire = parts[10].split('=').nth(1)?.to_string();
        let remote_port_that_hits_the_wire = parts[12].split('=').nth(1)?.parse().ok()?;
        if remote_ip_we_think_we_send_to != remote_ip_that_hits_the_wire {
            let (local_ip, remote_ip) = match ip_version.as_str() {
                "ipv4" => (
                    Self::string_to_ipv4(&local_ip_that_sends_the_packet).unwrap(),
                    Self::string_to_ipv4(&remote_ip_that_hits_the_wire).unwrap(),
                ),
                "ipv6" => (
                    Self::string_to_ipv6(&local_ip_that_sends_the_packet).unwrap(),
                    Self::string_to_ipv6(&remote_ip_that_hits_the_wire).unwrap(),
                ),
                _ => return None,
            };
            self.insert(
                RemoteNatLookupEntry {
                    local_ip,
                    local_port: local_port_that_sends_the_packet,
                },
                RemoteNatEntry {
                    remote_ip_actual: remote_ip,
                    remote_port_actual: remote_port_that_hits_the_wire,
                },
            );
            self.remote_nat_entries_detected += 1;
        }
        Some(())
    }
}
