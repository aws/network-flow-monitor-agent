// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use log::info;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_netfilter::{
    constants::NFNLGRP_CONNTRACK_NEW,
    nfconntrack::{nlas::ConnectionProperties, ConnectionNla, NfConntrackMessage},
    NetfilterMessage, NetfilterMessageInner,
};
use netlink_sys::{constants::NETLINK_NETFILTER, Socket};
use std::convert::TryFrom;
use std::io::ErrorKind;

// 425984 Bytes of space can store 333 messages. (default for c5.4xlarge kubernetes host env / can be less or more for others)
// Meaning for 500msec agg period we can only receive up to 666 new conntrack events per second with that size.
// Setting this to target 10k connections per second -> (425984) * (10000 / 666) = 6396156 Bytes.
// Cost of reading each entry is around 2.5us, so 10k entries will cost 25ms per second (2.5% load for a single core)
// Rounding up to nearest 4096 -> 6397952, i.e. 6.4MByte-ish
const SOCKET_RX_BUF_DESIRED_SIZE: usize = 6397952;

#[derive(Clone, Debug)]
pub struct ConntrackEntry {
    pub original: ConnectionProperties,
    pub reply: ConnectionProperties,
}

impl ConntrackEntry {
    pub fn was_natd(&self) -> bool {
        Self::reverse(&self.reply) != self.original
    }

    fn reverse(cxn: &ConnectionProperties) -> ConnectionProperties {
        ConnectionProperties {
            src_ip: cxn.dst_ip,
            dst_ip: cxn.src_ip,
            src_port: cxn.dst_port,
            dst_port: cxn.src_port,
            protocol: cxn.protocol,
        }
    }
}

pub trait ConntrackProvider {
    fn get_new_entries(&mut self) -> Result<Vec<ConntrackEntry>, String>;
}

pub struct ConntrackListener {
    socket: Socket,
    rx_buf: Vec<u8>,
}

impl ConntrackListener {
    pub fn initialize() -> Self {
        // Create our non-blocking socket.
        let mut socket = Socket::new(NETLINK_NETFILTER).expect("Failed to create netlink socket");
        socket
            .set_non_blocking(true)
            .expect("Failed to set netlink socket properties");

        // Attempt to increase the receive buffer, but take what the kernel clamps us to.
        let initial_rx_buf_size = socket
            .get_rx_buf_sz()
            .expect("Failed to get buf size of netlink socket");
        let desired_rx_buf_size = SOCKET_RX_BUF_DESIRED_SIZE;

        socket
            .set_rx_buf_sz(desired_rx_buf_size)
            .expect("Failed to set netlink socket buf size");
        let actual_rx_buf_size = socket
            .get_rx_buf_sz()
            .expect("Failed to get buf size of netlink socket");

        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
        info!(page_size, initial_rx_buf_size, desired_rx_buf_size, actual_rx_buf_size; "Configured conntrack socket buffer.");

        let rx_buf: Vec<u8> = vec![0; actual_rx_buf_size];

        // Subscribe to conntrack events.
        socket.bind_auto().unwrap();
        socket.add_membership(NFNLGRP_CONNTRACK_NEW).unwrap();

        Self { socket, rx_buf }
    }

    fn parse_connection_properties(
        msg: NetlinkMessage<NetfilterMessage>,
    ) -> Result<(ConnectionProperties, ConnectionProperties), String> {
        let mut orig_opt: Option<ConnectionProperties> = None;
        let mut reply_opt: Option<ConnectionProperties> = None;

        if let NetlinkPayload::<NetfilterMessage>::InnerMessage(imsg) = msg.payload {
            if let NetfilterMessageInner::NfConntrack(NfConntrackMessage::ConnectionNew(nlas)) =
                imsg.inner
            {
                for nla in nlas {
                    match nla {
                        ConnectionNla::TupleOrig(tuple) => {
                            match ConnectionProperties::try_from(tuple) {
                                Ok(cxn) => orig_opt = Some(cxn),
                                Err(e) => {
                                    return Err(format!(
                                        "Failed to extract original connection properties: {:?}",
                                        e
                                    ));
                                }
                            }
                        }
                        ConnectionNla::TupleReply(tuple) => {
                            match ConnectionProperties::try_from(tuple) {
                                Ok(cxn) => reply_opt = Some(cxn),
                                Err(e) => {
                                    return Err(format!(
                                        "Failed to extract reply connection properties: {:?}",
                                        e
                                    ));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        match (orig_opt, reply_opt) {
            (Some(orig), Some(reply)) => Ok((orig, reply)),
            _ => Err("Connection properties not found".to_string()),
        }
    }
}

impl ConntrackProvider for ConntrackListener {
    fn get_new_entries(&mut self) -> Result<Vec<ConntrackEntry>, String> {
        let mut events = Vec::<ConntrackEntry>::new();

        loop {
            let flags: i32 = 0;
            match self.socket.recv(&mut &mut self.rx_buf[..], flags) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    break;
                }
                Err(e) => {
                    return Err(format!("Failed to read from netlink socket: {:?}", e));
                }
                _ => {}
            }

            let msg = match NetlinkMessage::<NetfilterMessage>::deserialize(&self.rx_buf[..]) {
                Ok(m) => m,
                Err(_) => {
                    // We failed to parse the netlink message.
                    // TODO: Should we track occurrences are record a throttled log messge?
                    continue;
                }
            };

            match Self::parse_connection_properties(msg) {
                Ok((original, reply)) => {
                    events.push(ConntrackEntry { original, reply });
                }
                Err(_) => {
                    // The message was not a valid pair of 5-tuples.
                    // TODO: Should we track occurrences are record a throttled log messge?
                }
            }
        }

        Ok(events)
    }
}

#[cfg(test)]
mod test {
    use crate::utils::{conntrack_listener::ConntrackEntry, ConntrackListener};

    use netlink_packet_core::NetlinkMessage;
    use netlink_packet_netfilter::{nfconntrack::nlas::ConnectionProperties, NetfilterMessage};
    use std::net::IpAddr;
    use std::str::FromStr;

    #[rustfmt::skip]
    static NL_NF_CONNTRACK_NEW_PKT: [u8; 196] = [
        // Start NetlinkHeader
        0xc4, 0x00, 0x00, 0x00,   // len
        0x00, 0x01,               // msg type NFNL_SUBSYS_* << 8 | <subtype>
                                  // e.g NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_NEW == 256
        0x00, 0x06,               // flags
        0x00, 0x00, 0x00, 0x00,   // seq num
        0x00, 0x00, 0x00, 0x00,   // port id

        // Start NfGenMsg
        0x02,                     // addr family AF_INET* (ipv4)
        0x00,                     // nf_version
        0x00, 0x00,               // resource id

        0x34, 0x00,               // len
        0x01, 0x80,               // type NLA_F_NESTED | CTA_TUPLE_ORIG

        0x14, 0x00,               // len
        0x01, 0x80,               // type NLA_F_NESTED | CTA_TUPLE_IP
        0x08, 0x00,               // len
        0x01, 0x00,               // type CTA_IP_V4_SRC
        0x01, 0x02, 0x03, 0x04,   // val ip
        0x08, 0x00,               // len
        0x02, 0x00,               // type CTA_IP_V4_DST
        0x05, 0x06, 0x07, 0x08,   // val ip

        0x1c, 0x00,               // len
        0x02, 0x80,               // type CTA_TUPLE_PROTO
        0x05, 0x00,               // len
        0x01, 0x00,               // type CTA_PROTO_NUM
        0x06,                     // val TCP
        0x00, 0x00, 0x00,         // padding
        0x06, 0x00,               // len
        0x02, 0x00,               // type CTA_PROTO_SRC_PORT
        0x16, 0x2e,               // val port
        0x00, 0x00,               // padding
        0x06, 0x00,               // len
        0x03, 0x00,               // type CTA_PROTO_DST_PORT
        0x01, 0xbb,               // val port
        0x00, 0x00,               // padding

        0x34, 0x00,               // len
        0x02, 0x80,               // type NLA_F_NESTED | CTA_TUPLE_REPLY

        0x14, 0x00,               // len
        0x01, 0x80,               // type NLA_F_NESTED | CTA_TUPLE_IP
        0x08, 0x00,               // len
        0x01, 0x00,               // type CTA_IP_V4_SRC
        0x09, 0x08, 0x07, 0x06,   // val ip
        0x08, 0x00,               // len
        0x02, 0x00,               // type CTA_IP_V4_DST
        0x05, 0x04, 0x03, 0x02,   // val ip

        0x1c, 0x00,               // len
        0x02, 0x80,               // type CTA_TUPLE_PROTO
        0x05, 0x00,               // len
        0x01, 0x00,               // type CTA_PROTO_NUM
        0x06,                     // val TCP
        0x00, 0x00, 0x00,         // padding
        0x06, 0x00,               // len
        0x02, 0x00,               // type CTA_PROTO_SRC_PORT
        0x26, 0x94,               // val port
        0x00, 0x00,               // padding
        0x06, 0x00,               // len
        0x03, 0x00,               // type CTA_PROTO_DST_PORT
        0x04, 0xd2,               // val port
        0x00, 0x00,               // padding

        0x08, 0x00,               // len
        0x0c, 0x00,               // type CTA_ID
        0x44, 0x75, 0x09, 0x81,   //

        0x08, 0x00,               // len
        0x03, 0x00,               // type CTA_STATUS
        0x00, 0x00, 0x01, 0x88,

        0x08, 0x00,               // len
        0x07, 0x00,               // type CTA_TIMEOUT
        0x00, 0x00, 0x00, 0x78,   // val 120,sec

        0x30, 0x00,               // len
        0x04, 0x80,               // type NLA_F_NESTED | CTA_PROTOINFO
        0x2c, 0x00,               // len
        0x01, 0x80,               // type NLA_F_NESTED | CTA_PROTOINFO_TCP
        0x05, 0x00,               // len
        0x01, 0x00,               // type CTA_PROTOINFO_TCP_STATE
        0x01,                     // val (syn sent)
        0x00, 0x00, 0x00,         // padding
        0x05, 0x00,               // len
        0x02, 0x00,               // type CTA_PROTOINFO_TCP_FLAGS_ORIGINAL
        0x07,                     // val
        0x00, 0x00, 0x00,         // padding
        0x05, 0x00,               // len
        0x03, 0x00,               // type CTA_PROTOINFO_TCP_FLAGS_REPLY
        0x00,                     // val
        0x00, 0x00, 0x00,

        0x06, 0x00,               // len
        0x04, 0x00,
        0x03, 0x00,
        0x00, 0x00,               // padding

        0x06, 0x00,               // len
        0x05, 0x00,
        0x00, 0x00,
        0x00, 0x00,               // padding
    ];

    #[test]
    fn test_parse_conntrack_message_new() {
        let nlnf_message =
            NetlinkMessage::<NetfilterMessage>::deserialize(&NL_NF_CONNTRACK_NEW_PKT[..]).unwrap();

        let (actual_original, actual_reply) =
            ConntrackListener::parse_connection_properties(nlnf_message).unwrap();

        let expected_original = ConnectionProperties {
            src_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            dst_ip: IpAddr::from_str("5.6.7.8").unwrap(),
            src_port: 5678,
            dst_port: 443,
            protocol: libc::IPPROTO_TCP as u8,
        };
        let expected_reply = ConnectionProperties {
            src_ip: IpAddr::from_str("9.8.7.6").unwrap(),
            dst_ip: IpAddr::from_str("5.4.3.2").unwrap(),
            src_port: 9876,
            dst_port: 1234,
            protocol: libc::IPPROTO_TCP as u8,
        };

        assert_eq!(actual_original, expected_original);
        assert_eq!(actual_reply, expected_reply);
    }

    #[test]
    fn test_netlink_deserialize_error() {
        #[rustfmt::skip]
        let mut rx_buf: [u8; 20] = [
            // Start NetlinkHeader
            0x15, 0x00, 0x00, 0x00,   // Specify a length 1 byte longer than the actual buffer
            0x00, 0x01,               // msg type
            0x00, 0x06,               // flags
            0x00, 0x00, 0x00, 0x00,   // seq num
            0x00, 0x00, 0x00, 0x00,   // port id

            // Start NfGenMsg
            0x02,                     // addr family AF_INET*
            0x00,                     // nf_version
            0x00, 0x00,               // resource id
        ];

        let nlnf_message = NetlinkMessage::<NetfilterMessage>::deserialize(&rx_buf[..]);
        assert!(nlnf_message.is_err());

        // Try again with the appropriate length.
        rx_buf[0] = rx_buf.len() as u8;
        let nlnf_message = NetlinkMessage::<NetfilterMessage>::deserialize(&rx_buf[..]);
        assert!(nlnf_message.is_ok());
    }

    #[test]
    fn test_conntrack_props_reverse() {
        let expected = ConnectionProperties {
            src_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            dst_ip: IpAddr::from_str("5.6.7.8").unwrap(),
            src_port: 1234,
            dst_port: 5678,
            protocol: libc::IPPROTO_TCP as u8,
        };

        let actual = ConntrackEntry::reverse(&ConnectionProperties {
            src_ip: IpAddr::from_str("5.6.7.8").unwrap(),
            dst_ip: IpAddr::from_str("1.2.3.4").unwrap(),
            src_port: 5678,
            dst_port: 1234,
            protocol: libc::IPPROTO_TCP as u8,
        });

        assert_eq!(actual, expected);
        assert!(ConntrackEntry::reverse(&actual) != expected);
        assert_eq!(
            ConntrackEntry::reverse(&ConntrackEntry::reverse(&actual)),
            expected
        );
    }

    #[test]
    fn test_conntrack_entry_was_natd() {
        let mut entry = ConntrackEntry {
            original: ConnectionProperties {
                src_ip: IpAddr::from_str("1.2.3.4").unwrap(),
                dst_ip: IpAddr::from_str("5.6.7.8").unwrap(),
                src_port: 1234,
                dst_port: 5678,
                protocol: libc::IPPROTO_TCP as u8,
            },
            reply: ConnectionProperties {
                src_ip: IpAddr::from_str("5.6.7.8").unwrap(),
                dst_ip: IpAddr::from_str("1.2.3.4").unwrap(),
                src_port: 5678,
                dst_port: 1234,
                protocol: libc::IPPROTO_TCP as u8,
            },
        };

        // Test the negative case, then the positive case.
        assert!(!entry.was_natd());
        entry.reply.src_port += 1;
        assert!(entry.was_natd());
    }
}
