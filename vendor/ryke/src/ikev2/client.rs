//! A minimal blocking IKEv2 **initiator** (client) over UDP.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, CompletedSaInit, LocalSecret};
use crate::ikev2::ike_auth::{self, AuthConfig};
use crate::ikev2::payload::Identification;
use crate::role::Role;
use crate::transport::{DriverError, UdpTransport};

const NONCE_LEN: usize = 32;

/// A UDP IKEv2 initiator driven by an [`Entropy`] source.
pub struct Client<E> {
    transport: UdpTransport,
    entropy: E,
}

impl<E: Entropy> Client<E> {
    /// Bind a local socket (use `"0.0.0.0:0"` for an ephemeral source port).
    pub fn bind(addr: impl ToSocketAddrs, entropy: E) -> io::Result<Self> {
        Ok(Self { transport: UdpTransport::bind(addr)?, entropy })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)
    }

    /// Run `IKE_SA_INIT` against `server` and return our completed state. Sends
    /// our default offer, waits for the response, and derives the keys.
    pub fn sa_init(&mut self, server: SocketAddr) -> Result<CompletedSaInit, DriverError> {
        let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
        let request = initiator_request(&local, &default_offer());
        self.transport.send_to(&request, server)?;
        let (response, _from) = self.transport.recv_from()?;
        Ok(initiator_complete(&local, &request, &response)?)
    }

    /// After a completed SA_INIT, run `IKE_AUTH` (PSK) against `server`. Returns
    /// the peer's verified identity, the responder's chosen CHILD SA SPI, and the
    /// inner IPv4 the responder assigned via its Configuration Payload (if any).
    pub fn authenticate(
        &mut self,
        server: SocketAddr,
        sa: &CompletedSaInit,
        cfg: &AuthConfig,
        child_spi: u32,
    ) -> Result<(Identification, u32, Option<Ipv4Addr>), DriverError> {
        let mut iv = [0u8; 8];
        self.entropy.fill(&mut iv);
        let request = ike_auth::initiator_auth_request(sa, cfg, child_spi, &iv)?;
        self.transport.send_to(&request, server)?;
        let (response, _from) = self.transport.recv_from()?;
        Ok(ike_auth::initiator_verify_auth(sa, &response, cfg)?)
    }

    /// Full handshake: `IKE_SA_INIT` then `IKE_AUTH`. Returns the established IKE
    /// SA, the peer's verified identity, the ESP CHILD SA (data-plane keys)
    /// derived for the given `child_spi`, and the responder-assigned inner IPv4
    /// (from its Configuration Payload) if one was provided.
    pub fn connect(
        &mut self,
        server: SocketAddr,
        cfg: &AuthConfig,
        child_spi: u32,
    ) -> Result<(CompletedSaInit, Identification, ChildSa, Option<Ipv4Addr>), DriverError> {
        let sa = self.sa_init(server)?;
        let (peer, peer_child_spi, assigned_ip) = self.authenticate(server, &sa, cfg, child_spi)?;
        let child = ChildSa::derive(&sa.keys.sk_d, &sa.ni, &sa.nr, Role::Initiator, child_spi, peer_child_spi);
        Ok((sa, peer, child, assigned_ip))
    }
}
