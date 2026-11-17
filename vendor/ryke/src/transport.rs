//! UDP transport for IKE messages.
//!
//! Blocking `std::net::UdpSocket` — no async runtime, matching the crate's
//! dependency-light design. Port 500 today; NAT-T on 4500 (with the non-ESP
//! marker) and IKE fragmentation arrive at M3.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use thiserror::Error;

use crate::error::IkeError;

/// Largest datagram we read. IKE messages can be large (certificates), but at
/// M1 (`IKE_SA_INIT`) a few KB suffices; fragmentation reassembly lands at M3.
pub const MAX_DATAGRAM: usize = 65535;

/// Errors from the UDP driver layer: transport I/O plus protocol errors.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ike(#[from] IkeError),
}

/// A blocking UDP transport for IKE messages.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self { socket: UdpSocket::bind(addr)? })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)
    }

    /// Receive one datagram, returning exactly the bytes read and the sender.
    pub fn recv_from(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (n, from) = self.socket.recv_from(&mut buf)?;
        buf.truncate(n);
        Ok((buf, from))
    }

    pub fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(data, to)
    }
}
