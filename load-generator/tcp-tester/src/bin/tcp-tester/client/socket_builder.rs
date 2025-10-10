use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::{borrow::BorrowMut, os::fd::AsRawFd};

use aya::maps::{HashMap, MapData};
use netns_rs::NetNs;
use nix::sys::socket::{self as sockopt};
use tcp_tester::os;
use tcp_tester_common::{Direction, FlowConfig, SocketKey};
use tokio::net::TcpSocket;

use super::{client_socket_error::ClientSocketError, conditioned_tcp_stream::ConditionedTcpStream};

pub struct ClientSocketBuilder<T> {
    netns: NetNs,
    socket_config: HashMap<T, SocketKey, FlowConfig>,
}

// Initiates a TCP connection without traffic control.  Thus, the socket's traffic is not tracked
// by a separate sock_ops program, nor rate-limited by tc.
pub async fn connect_sans_tc(
    netns: NetNs,
    addr: SocketAddr,
) -> Result<ConditionedTcpStream, ClientSocketError> {
    let socket = netns.run(|_| TcpSocket::new_v4().unwrap())?;
    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    let stream = socket.connect(addr).await?;
    Ok(ConditionedTcpStream { stream })
}

impl<T> ClientSocketBuilder<T>
where
    T: BorrowMut<MapData>,
{
    pub fn new(netns: NetNs, socket_config: HashMap<T, SocketKey, FlowConfig>) -> Self {
        ClientSocketBuilder {
            netns,
            socket_config,
        }
    }

    pub async fn connect(
        &mut self,
        addr: SocketAddr,
        egress_config: FlowConfig,
        ingress_config: FlowConfig,
    ) -> Result<ConditionedTcpStream, ClientSocketError> {
        let socket = self.netns.run(|_| TcpSocket::new_v4().unwrap())?;
        let fd = socket.as_fd();
        let clone_fd = fd.try_clone_to_owned()?;

        // Add the configurations of the ingress/egress
        match sockopt::getsockopt(clone_fd.as_raw_fd(), os::SoCookie) {
            Ok(cookie) => {
                println!("Socket cookie: {}", cookie);
                self.socket_config
                    .insert(
                        SocketKey::new(cookie, Direction::INGRESS),
                        ingress_config,
                        0,
                    )
                    .unwrap();
                self.socket_config
                    .insert(SocketKey::new(cookie, Direction::EGRESS), egress_config, 0)
                    .unwrap();
            }
            Err(error) => return Err(ClientSocketError::SocketError(error)),
        }

        let stream = socket.connect(addr).await?;

        Ok(ConditionedTcpStream { stream })
    }
}
