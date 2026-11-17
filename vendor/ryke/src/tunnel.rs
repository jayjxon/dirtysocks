//! The ESP data-plane driver.
//!
//! A [`Tunnel`] owns a [`ChildSa`] (both ESP directions) plus a UDP transport to
//! the peer. The application feeds it inner packets with [`Tunnel::send`] and
//! reads decrypted packets with [`Tunnel::recv`]. No device, no root, no OS
//! routing — everything happens in userspace.
//!
//! Where those packets come from is the consumer's choice and out of `ryke`'s
//! scope: a kernel TUN device, a userspace network stack, a SOCKS proxy, or a
//! test harness all just call `send`/`recv`.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::esp::ChildSa;
use crate::transport::{DriverError, UdpTransport};

/// A bidirectional ESP tunnel to one peer (internal mode).
pub struct Tunnel {
    sa: ChildSa,
    transport: UdpTransport,
    peer: SocketAddr,
}

impl Tunnel {
    pub fn new(sa: ChildSa, transport: UdpTransport, peer: SocketAddr) -> Self {
        Self { sa, transport, peer }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)
    }

    /// Seal an inner packet (with the given ESP Next Header) and send it to the
    /// peer over UDP.
    pub fn send(&mut self, inner: &[u8], next_header: u8) -> Result<(), DriverError> {
        let packet = self.sa.outbound.seal(inner, next_header)?;
        self.transport.send_to(&packet, self.peer)?;
        Ok(())
    }

    /// Receive one ESP datagram from the peer and open it, returning the inner
    /// packet and its Next Header.
    pub fn recv(&mut self) -> Result<(Vec<u8>, u8), DriverError> {
        let (packet, _from) = self.transport.recv_from()?;
        Ok(self.sa.inbound.open(&packet)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esp::next_header;
    use crate::role::Role;

    /// Two ryke endpoints derive a CHILD SA from the same IKE-SA inputs and
    /// exchange encrypted packets over real UDP — no TUN device involved.
    #[test]
    fn tunnel_carries_packets_both_ways_over_udp() {
        let sk_d = [0x55u8; 32];
        let ni = [1u8; 16];
        let nr = [2u8; 16];
        let init_spi = 0xAAAA_AAAA;
        let resp_spi = 0xBBBB_BBBB;

        let a_sa = ChildSa::derive(&sk_d, &ni, &nr, Role::Initiator, init_spi, resp_spi);
        let b_sa = ChildSa::derive(&sk_d, &ni, &nr, Role::Responder, resp_spi, init_spi);

        let a_tp = UdpTransport::bind("127.0.0.1:0").unwrap();
        let b_tp = UdpTransport::bind("127.0.0.1:0").unwrap();
        a_tp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b_tp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let a_addr = a_tp.local_addr().unwrap();
        let b_addr = b_tp.local_addr().unwrap();

        let mut a = Tunnel::new(a_sa, a_tp, b_addr);
        let mut b = Tunnel::new(b_sa, b_tp, a_addr);

        // A → B
        a.send(b"ping from A", next_header::IPV4).unwrap();
        let (got, nh) = b.recv().unwrap();
        assert_eq!(got, b"ping from A");
        assert_eq!(nh, next_header::IPV4);

        // B → A
        b.send(b"pong from B", next_header::IPV4).unwrap();
        let (got, _) = a.recv().unwrap();
        assert_eq!(got, b"pong from B");
    }
}
