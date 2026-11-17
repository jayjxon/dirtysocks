//! A blocking IKEv2 **responder** (server) over UDP.
//!
//! Handles the two-message handshake — `IKE_SA_INIT` then `IKE_AUTH` — keeping
//! per-SA state keyed by the SPI pair so the second message can be correlated
//! with the first. Uses pre-shared-key authentication.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev2::exchange::{responder_respond, CompletedSaInit, LocalSecret};
use crate::ikev2::ike_auth::{self, AuthConfig};
use crate::ikev2::message::{ExchangeType, IkeHeader};
use crate::ikev2::payload::Identification;
use crate::role::Role;
use crate::transport::{DriverError, UdpTransport};

/// Nonce length we generate (RFC 7296 §2.10: ≥16 and ≥ half the PRF key).
const NONCE_LEN: usize = 32;

/// What [`Server::handle_one`] did with one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// Answered an `IKE_SA_INIT`; the IKE SA is half-open awaiting `IKE_AUTH`.
    SaInit { spi_i: u64, spi_r: u64 },
    /// Completed `IKE_AUTH`; the IKE SA is established with a verified peer.
    Established { spi_i: u64, spi_r: u64, peer_id: Identification },
    /// A datagram we don't act on (unhandled exchange, or unknown SPI pair).
    Ignored,
}

/// A UDP IKEv2 responder driven by an [`Entropy`] source, authenticating peers
/// with a pre-shared key.
pub struct Server<E> {
    transport: UdpTransport,
    entropy: E,
    auth: AuthConfig,
    sessions: HashMap<(u64, u64), CompletedSaInit>,
    children: HashMap<(u64, u64), ChildSa>,
}

impl<E: Entropy> Server<E> {
    pub fn bind(addr: impl ToSocketAddrs, entropy: E, auth: AuthConfig) -> io::Result<Self> {
        Ok(Self {
            transport: UdpTransport::bind(addr)?,
            entropy,
            auth,
            sessions: HashMap::new(),
            children: HashMap::new(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)
    }

    /// The keys for an established IKE SA (for the eventual ESP data path).
    pub fn session(&self, spi_i: u64, spi_r: u64) -> Option<&CompletedSaInit> {
        self.sessions.get(&(spi_i, spi_r))
    }

    /// Borrow the established ESP CHILD SA for an IKE SA (the data-plane keys).
    pub fn child(&self, spi_i: u64, spi_r: u64) -> Option<&ChildSa> {
        self.children.get(&(spi_i, spi_r))
    }

    /// Take ownership of the established ESP CHILD SA (to run the data plane,
    /// which mutates the sequence counters).
    pub fn take_child(&mut self, spi_i: u64, spi_r: u64) -> Option<ChildSa> {
        self.children.remove(&(spi_i, spi_r))
    }

    /// Receive one datagram and advance the handshake it belongs to.
    pub fn handle_one(&mut self) -> Result<ServerEvent, DriverError> {
        let (data, from) = self.transport.recv_from()?;
        let header = IkeHeader::parse(&data)?;

        match header.exchange_type {
            ExchangeType::IkeSaInit => {
                let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
                let (response, sa) = responder_respond(&data, &local)?;
                self.transport.send_to(&response, from)?;
                let (spi_i, spi_r) = (sa.spi_i, sa.spi_r);
                self.sessions.insert((spi_i, spi_r), sa);
                Ok(ServerEvent::SaInit { spi_i, spi_r })
            }
            ExchangeType::IkeAuth => {
                let key = (header.initiator_spi, header.responder_spi);
                let Some(sa) = self.sessions.get(&key).cloned() else {
                    return Ok(ServerEvent::Ignored);
                };
                let child_spi = self.entropy.next_u64() as u32;
                let mut iv = [0u8; 8];
                self.entropy.fill(&mut iv);
                let (response, peer_id, peer_child_spi) =
                    ike_auth::responder_process_auth(&sa, &data, &self.auth, child_spi, &iv, None)?;
                self.transport.send_to(&response, from)?;
                let child = ChildSa::derive(&sa.keys.sk_d, &sa.ni, &sa.nr, Role::Responder, child_spi, peer_child_spi);
                self.children.insert(key, child);
                Ok(ServerEvent::Established { spi_i: key.0, spi_r: key.1, peer_id })
            }
            _ => Ok(ServerEvent::Ignored),
        }
    }
}
