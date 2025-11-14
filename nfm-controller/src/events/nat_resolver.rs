// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::events::SockCache;
use crate::events::SockOperationResult;
use crate::utils::conntrack_listener::ConntrackProvider;
use crate::utils::ConntrackListener;
use nfm_common::SockContext;

use hashbrown::HashMap;
use log::error;
use netlink_packet_netfilter::nfconntrack::nlas::ConnectionProperties;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

// We use a ring buffer of maps to maintain NAT mappings beyond a single aggregation cycle.  This
// is because we're taking no reliance on which of our subsystems will be the first to see an event
// for a new socket: eBPF sock_ops vs netlink conntrack.
const RING_BUF_ENTRIES: usize = 3;

pub trait NatResolver {
    fn perform_aggregation_cycle(&mut self);
    fn perform_eviction(&mut self);
    fn get_beyond_nat_entry(&self, sock_context: &SockContext) -> Option<SockContext>;
    fn store_beyond_nat_entries(&self, sock_cache: &mut SockCache) -> SockOperationResult;
    fn num_entries(&self) -> usize;
}

#[derive(Clone, Default)]
pub struct NatResolverNoOp;

impl NatResolver for NatResolverNoOp {
    fn perform_aggregation_cycle(&mut self) {}

    fn perform_eviction(&mut self) {}

    fn get_beyond_nat_entry(&self, _sock_context: &SockContext) -> Option<SockContext> {
        None
    }

    fn store_beyond_nat_entries(&self, _sock_cache: &mut SockCache) -> SockOperationResult {
        SockOperationResult::default()
    }

    fn num_entries(&self) -> usize {
        0
    }
}

pub struct NatResolverImpl {
    conntrack_listener: Box<dyn ConntrackProvider>,
    conntrack_ringbuf:
        [HashMap<Rc<ConnectionProperties>, Rc<ConnectionProperties>>; RING_BUF_ENTRIES],
    ringbuf_index: usize,
}

impl NatResolver for NatResolverImpl {
    fn num_entries(&self) -> usize {
        self.conntrack_ringbuf.iter().map(|m| m.len()).sum()
    }

    fn perform_aggregation_cycle(&mut self) {
        let new_entries = match self.conntrack_listener.get_new_entries() {
            Ok(n) => n,
            Err(error) => {
                error!(error; "Failed to retrieve conntrack changes");
                return;
            }
        };

        let entry_cache = &mut self.conntrack_ringbuf[self.ringbuf_index];
        for new_entry in new_entries.iter() {
            // For locally-initiated connections, eBPF sock_ops sees the original flow, pre-NAT.
            // For remote-initiated connections, eBPF sees the reply flow, post-NAT.  Hence, we key
            // by both sides to allow for either lookup.
            let orig_rc = Rc::new(new_entry.original);
            let reply_rc = Rc::new(new_entry.reply);
            entry_cache.insert(orig_rc.clone(), reply_rc.clone());
            entry_cache.insert(reply_rc.clone(), orig_rc.clone());
        }
    }

    fn perform_eviction(&mut self) {
        // Advance the head to where the tail currently is, then clear that slot.
        self.ringbuf_index = (self.ringbuf_index + 1) % self.conntrack_ringbuf.len();
        self.conntrack_ringbuf[self.ringbuf_index].clear();
    }

    // Gets a socket's properties as seen beyond NAT, meaning external to the local network
    // namespace.
    fn get_beyond_nat_entry(&self, sock_context: &SockContext) -> Option<SockContext> {
        if sock_context.is_valid() {
            let internal_info = Self::sock_context_to_egress_cxn_info(sock_context).unwrap();
            for i in 0..self.conntrack_ringbuf.len() {
                if let Some(external_info) = self.conntrack_ringbuf[i].get(&internal_info) {
                    return Some(Self::ingress_cxn_info_to_sock_context(
                        external_info,
                        sock_context.is_client,
                    ));
                }
            }
        }

        None
    }

    fn store_beyond_nat_entries(&self, sock_cache: &mut SockCache) -> SockOperationResult {
        let mut result = SockOperationResult::default();

        for (_key, sock_wrap) in sock_cache.iter_mut() {
            if sock_wrap.context_external.is_none() {
                match self.get_beyond_nat_entry(&sock_wrap.context) {
                    Some(entry) => {
                        sock_wrap.context_external = Some(entry);
                        result.completed += 1;
                    }
                    _ => {
                        result.partial += 1;
                    }
                }
            }
        }

        result
    }
}

impl NatResolverImpl {
    pub fn initialize() -> Self {
        Self {
            conntrack_listener: Box::new(ConntrackListener::initialize()),
            conntrack_ringbuf: std::array::from_fn(|_i| HashMap::with_capacity(4096)), // (2 + 8 + 8) * 4096 * RING_BUF_ENTRIES = ~0.22 MB upfront
            ringbuf_index: 0,
        }
    }

    /// BPF side will report ipv4 addresses as ipv6 wrapped addresses if the applications are developed in dual-stack support in mind
    /// and use wrapped format. i.e. ::ffff:192.168.1.1 rather than 192.168.1.1.
    /// But Netlink side always reports IP addresses in non-wrapped format and we store them as is.
    /// Thus stripping the pseudo ipv6 prefix in case it exists for ipv4 adresses, as this is the map query key.
    fn ipv6_to_ipaddr(addr: &[u8; 16]) -> IpAddr {
        if addr[..10] == [0; 10] && addr[10] == 0xff && addr[11] == 0xff {
            IpAddr::from(Ipv4Addr::from([addr[12], addr[13], addr[14], addr[15]]))
        } else {
            IpAddr::from(Ipv6Addr::from(*addr))
        }
    }

    fn sock_context_to_egress_cxn_info(
        sock_context: &SockContext,
    ) -> Result<ConnectionProperties, String> {
        let (local_addr, remote_addr) = match sock_context.address_family as i32 {
            libc::AF_INET => (
                IpAddr::from(Ipv4Addr::from_bits(sock_context.local_ipv4)),
                IpAddr::from(Ipv4Addr::from_bits(sock_context.remote_ipv4)),
            ),
            libc::AF_INET6 => (
                Self::ipv6_to_ipaddr(&sock_context.local_ipv6),
                Self::ipv6_to_ipaddr(&sock_context.remote_ipv6),
            ),
            _ => {
                return Err(format!(
                    "Unhandled address family: {} for sock_context={:?}",
                    sock_context.address_family, sock_context,
                ));
            }
        };
        Ok(ConnectionProperties {
            src_ip: local_addr,
            dst_ip: remote_addr,
            src_port: sock_context.local_port,
            dst_port: sock_context.remote_port,
            protocol: libc::IPPROTO_TCP.try_into().unwrap(),
        })
    }

    fn ingress_cxn_info_to_sock_context(
        cxn_info: &ConnectionProperties,
        is_client: bool,
    ) -> SockContext {
        match (cxn_info.src_ip, cxn_info.dst_ip) {
            (IpAddr::V4(src_addr), IpAddr::V4(dst_addr)) => SockContext {
                local_ipv4: dst_addr.to_bits(),
                remote_ipv4: src_addr.to_bits(),
                local_port: cxn_info.dst_port,
                remote_port: cxn_info.src_port,
                address_family: libc::AF_INET.try_into().unwrap(),
                is_client,
                ..Default::default()
            },
            (IpAddr::V6(src_addr), IpAddr::V6(dst_addr)) => SockContext {
                local_ipv6: dst_addr.octets(),
                remote_ipv6: src_addr.octets(),
                local_port: cxn_info.dst_port,
                remote_port: cxn_info.src_port,
                address_family: libc::AF_INET6.try_into().unwrap(),
                is_client,
                ..Default::default()
            },
            _ => panic!("Found NAT entry of differing IP families: {cxn_info:?}"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::events::{nat_resolver::RING_BUF_ENTRIES, SockCache, SockOperationResult};
    use crate::utils::conntrack_listener::{ConntrackEntry, ConntrackProvider};
    use crate::{NatResolver, NatResolverImpl};
    use nfm_common::{SockContext, SockKey};

    use hashbrown::HashMap;
    use netlink_packet_netfilter::nfconntrack::nlas::ConnectionProperties;
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    struct ConntrackListenerSeeded {
        pub pending_replies: VecDeque<Vec<ConntrackEntry>>,
    }

    impl ConntrackProvider for ConntrackListenerSeeded {
        fn get_new_entries(&mut self) -> Result<Vec<ConntrackEntry>, String> {
            Ok(self.pending_replies.pop_front().unwrap())
        }
    }

    fn seeded_nat_resolver(conntrack_listener: ConntrackListenerSeeded) -> NatResolverImpl {
        NatResolverImpl {
            conntrack_listener: Box::new(conntrack_listener),
            conntrack_ringbuf: std::array::from_fn(|_i| HashMap::new()),
            ringbuf_index: 0,
        }
    }

    #[test]
    fn test_nat_resolver_aggregation() {
        // Mirror reflection means NAT was not applied.
        let ct_entry = ConntrackEntry {
            original: ConnectionProperties {
                src_ip: IpAddr::from_str("1.2.3.4").unwrap(),
                dst_ip: IpAddr::from_str("5.6.7.8").unwrap(),
                src_port: 1234,
                dst_port: 5678,
                protocol: libc::IPPROTO_TCP as u8,
            },
            reply: ConnectionProperties {
                src_ip: IpAddr::from_str("9.10.11.12").unwrap(),
                dst_ip: IpAddr::from_str("1.2.3.4").unwrap(),
                src_port: 9876,
                dst_port: 1234,
                protocol: libc::IPPROTO_TCP as u8,
            },
        };

        let conntrack_listener = ConntrackListenerSeeded {
            pending_replies: VecDeque::from([vec![ct_entry]]),
        };
        let mut nat_resolver = seeded_nat_resolver(conntrack_listener);

        // Expect a cache entry for each direction.
        // Each entry from conntrack listener fed to resolver is now always a NATed one
        nat_resolver.perform_aggregation_cycle();
        assert_eq!(nat_resolver.num_entries(), 2);

        // Now try NAT resolution.
        let sock_ctx = SockContext {
            local_ipv4: Ipv4Addr::from_str("1.2.3.4").unwrap().to_bits(),
            remote_ipv4: Ipv4Addr::from_str("5.6.7.8").unwrap().to_bits(),
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 1234,
            remote_port: 5678,
            address_family: libc::AF_INET.try_into().unwrap(),
            is_client: true,
            ..Default::default()
        };
        let actual_natd_ctx = nat_resolver.get_beyond_nat_entry(&sock_ctx).unwrap();
        let expected_natd_ctx = SockContext {
            local_ipv4: Ipv4Addr::from_str("1.2.3.4").unwrap().to_bits(),
            remote_ipv4: Ipv4Addr::from_str("9.10.11.12").unwrap().to_bits(),
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 1234,
            remote_port: 9876,
            address_family: libc::AF_INET.try_into().unwrap(),
            is_client: true,
            ..Default::default()
        };
        assert_eq!(actual_natd_ctx, expected_natd_ctx);

        // Test the resolver updating the sock cache.
        let mut sock_cache = SockCache::new();
        let sock_key: SockKey = 1979;
        let now_us = 1997;
        sock_cache.add_context(sock_key, sock_ctx, now_us);
        let store_result = nat_resolver.store_beyond_nat_entries(&mut sock_cache);
        assert_eq!(
            store_result,
            SockOperationResult {
                completed: 1,
                partial: 0,
                failed: 0,
            }
        );
        assert_eq!(
            sock_cache.get(&sock_key).unwrap().context_external.unwrap(),
            expected_natd_ctx
        );

        // After evicting everything, there's nothing more to resolve.
        for _ in 0..RING_BUF_ENTRIES {
            nat_resolver.perform_eviction();
        }
        assert!(nat_resolver.get_beyond_nat_entry(&sock_ctx).is_none());
    }

    #[test]
    fn test_sock_context_to_egress_cxn_info_ipv4() {
        let ctx = SockContext {
            local_ipv4: Ipv4Addr::from_str("1.2.3.4").unwrap().to_bits(),
            remote_ipv4: Ipv4Addr::from_str("5.6.7.8").unwrap().to_bits(),
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 99,
            remote_port: 100,
            address_family: libc::AF_INET.try_into().unwrap(),
            is_client: true,
            ..Default::default()
        };
        let expected_cxn_info = ConnectionProperties {
            src_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            dst_ip: IpAddr::from_str("5.6.7.8").unwrap(),
            src_port: 99,
            dst_port: 100,
            protocol: libc::IPPROTO_TCP.try_into().unwrap(),
        };
        let actual_cxn_info = NatResolverImpl::sock_context_to_egress_cxn_info(&ctx).unwrap();
        assert_eq!(actual_cxn_info, expected_cxn_info);
    }

    #[test]
    fn test_sock_context_to_egress_cxn_info_ipv6() {
        let ctx = SockContext {
            local_ipv4: 0,
            remote_ipv4: 0,
            local_ipv6: Ipv6Addr::from_str("fe80::1979:4bff:febb:da61")
                .unwrap()
                .octets(),
            remote_ipv6: Ipv6Addr::from_str("fe80:2160::1997:4bff:febb:da61")
                .unwrap()
                .octets(),
            local_port: 99,
            remote_port: 100,
            address_family: libc::AF_INET6.try_into().unwrap(),
            is_client: true,
            ..Default::default()
        };
        let expected_cxn_info = ConnectionProperties {
            src_ip: IpAddr::from_str("fe80::1979:4bff:febb:da61").unwrap(),
            dst_ip: IpAddr::from_str("fe80:2160::1997:4bff:febb:da61").unwrap(),
            src_port: 99,
            dst_port: 100,
            protocol: libc::IPPROTO_TCP.try_into().unwrap(),
        };
        let actual_cxn_info = NatResolverImpl::sock_context_to_egress_cxn_info(&ctx).unwrap();
        assert_eq!(actual_cxn_info, expected_cxn_info);
    }

    #[test]
    fn test_sock_context_to_egress_cxn_info_pseudo_ipv6() {
        let ctx = SockContext {
            local_ipv4: 0,
            remote_ipv4: 0,
            local_ipv6: Ipv6Addr::from_str("::ffff:1.2.3.4").unwrap().octets(),
            remote_ipv6: Ipv6Addr::from_str("::ffff:1.2.3.5").unwrap().octets(),
            local_port: 99,
            remote_port: 100,
            address_family: libc::AF_INET6.try_into().unwrap(),
            is_client: true,
            ..Default::default()
        };
        let expected_cxn_info = ConnectionProperties {
            src_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            dst_ip: IpAddr::from_str("1.2.3.5").unwrap(),
            src_port: 99,
            dst_port: 100,
            protocol: libc::IPPROTO_TCP.try_into().unwrap(),
        };
        let actual_cxn_info = NatResolverImpl::sock_context_to_egress_cxn_info(&ctx).unwrap();
        assert_eq!(actual_cxn_info, expected_cxn_info);
    }

    #[test]
    fn test_ingress_cxn_info_tp_sock_context_ipv4() {
        let cxn_info = ConnectionProperties {
            src_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            dst_ip: IpAddr::from_str("5.6.7.8").unwrap(),
            src_port: 99,
            dst_port: 100,
            protocol: libc::IPPROTO_TCP.try_into().unwrap(),
        };
        let is_client = true;
        let expected_ctx = SockContext {
            local_ipv4: Ipv4Addr::from_str("5.6.7.8").unwrap().to_bits(),
            remote_ipv4: Ipv4Addr::from_str("1.2.3.4").unwrap().to_bits(),
            local_ipv6: [0; 16],
            remote_ipv6: [0; 16],
            local_port: 100,
            remote_port: 99,
            address_family: libc::AF_INET.try_into().unwrap(),
            is_client,
            ..Default::default()
        };
        let actual_ctx = NatResolverImpl::ingress_cxn_info_to_sock_context(&cxn_info, is_client);
        assert_eq!(actual_ctx, expected_ctx);
    }

    #[test]
    fn test_ingress_cxn_info_tp_sock_context_ipv6() {
        let cxn_info = ConnectionProperties {
            src_ip: IpAddr::from_str("fe80::1979:4bff:febb:da61").unwrap(),
            dst_ip: IpAddr::from_str("fe80:2160::1997:4bff:febb:da61").unwrap(),
            src_port: 99,
            dst_port: 100,
            protocol: libc::IPPROTO_TCP.try_into().unwrap(),
        };
        let is_client = true;
        let expected_ctx = SockContext {
            local_ipv4: 0,
            remote_ipv4: 0,
            local_ipv6: Ipv6Addr::from_str("fe80:2160::1997:4bff:febb:da61")
                .unwrap()
                .octets(),
            remote_ipv6: Ipv6Addr::from_str("fe80::1979:4bff:febb:da61")
                .unwrap()
                .octets(),
            local_port: 100,
            remote_port: 99,
            address_family: libc::AF_INET6.try_into().unwrap(),
            is_client,
            ..Default::default()
        };
        let actual_ctx = NatResolverImpl::ingress_cxn_info_to_sock_context(&cxn_info, is_client);
        assert_eq!(actual_ctx, expected_ctx);
    }
}
