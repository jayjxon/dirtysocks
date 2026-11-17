//! A blocking IKEv1 **responder** (server) over UDP: Aggressive Mode + Quick
//! Mode with PSK authentication. Per-client handshake state is keyed by the
//! initiator cookie so the multi-message exchanges correlate. On completion the
//! established ESP CHILD SA is available via [`Server::take_child`].

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev1::isakmp::{self, exchange, payload, IsakmpHeader};
use crate::ikev1::phase1::{respond_aggressive, Phase1Config, Phase1State};
use crate::ikev1::quick::{respond_quick, QuickResponder};
use crate::transport::{DriverError, UdpTransport};

/// What [`Server::handle_one`] did with one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// Answered Aggressive-Mode message 1; Phase 1 is half-open awaiting HASH_I.
    Phase1SaInit,
    /// Verified the initiator's HASH_I — Phase 1 is established.
    Phase1Established,
    /// Answered Quick-Mode message 1; the CHILD SA is being negotiated.
    QuickSaInit,
    /// Quick Mode completed — the ESP CHILD SA is ready (see [`Server::take_child`]).
    ChildSaEstablished { cky_i: [u8; 8] },
    /// A datagram we don't act on (unknown cookie, or unexpected exchange).
    Ignored,
}

/// Per-client handshake state, keyed by the initiator cookie.
struct Session {
    phase1: Option<Phase1State>,
    quick: Option<QuickResponder>,
}

/// A UDP IKEv1 responder driven by an [`Entropy`] source, authenticating peers
/// with a pre-shared key.
pub struct Server<E> {
    transport: UdpTransport,
    entropy: E,
    cfg: Phase1Config,
    sessions: HashMap<[u8; 8], Session>,
    children: HashMap<[u8; 8], ChildSa>,
}

impl<E: Entropy> Server<E> {
    pub fn bind(addr: impl ToSocketAddrs, entropy: E, cfg: Phase1Config) -> io::Result<Self> {
        Ok(Self {
            transport: UdpTransport::bind(addr)?,
            entropy,
            cfg,
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

    /// Borrow the established ESP CHILD SA for a given initiator cookie.
    pub fn child(&self, cky_i: [u8; 8]) -> Option<&ChildSa> {
        self.children.get(&cky_i)
    }

    /// Take ownership of the established ESP CHILD SA (to run the data plane,
    /// which mutates the sequence counters).
    pub fn take_child(&mut self, cky_i: [u8; 8]) -> Option<ChildSa> {
        self.children.remove(&cky_i)
    }

    /// Receive one datagram and advance the handshake it belongs to.
    pub fn handle_one(&mut self) -> Result<ServerEvent, DriverError> {
        let (data, from) = self.transport.recv_from()?;
        let hdr = IsakmpHeader::parse(&data)?;
        let cky_i = hdr.init_cookie;

        match hdr.exchange_type {
            exchange::AGGRESSIVE => {
                let ps = isakmp::parse_payloads(hdr.next_payload, &data[IsakmpHeader::LEN..])?;
                let has = |t: u8| ps.iter().any(|p| p.payload_type == t);
                if has(payload::SA) {
                    // Message 1 → message 2.
                    let (msg2, st) = respond_aggressive(&self.cfg, &data, &mut self.entropy)?;
                    self.transport.send_to(&msg2, from)?;
                    self.sessions.insert(cky_i, Session { phase1: Some(st), quick: None });
                    Ok(ServerEvent::Phase1SaInit)
                } else if has(payload::HASH) {
                    // Message 3 (HASH_I).
                    let Some(st) = self.sessions.get(&cky_i).and_then(|s| s.phase1.as_ref()) else {
                        return Ok(ServerEvent::Ignored);
                    };
                    st.verify_hash_i(&data)?;
                    Ok(ServerEvent::Phase1Established)
                } else {
                    Ok(ServerEvent::Ignored)
                }
            }
            exchange::QUICK => {
                let (has_phase1, quick_started) = match self.sessions.get(&cky_i) {
                    Some(s) => (s.phase1.is_some(), s.quick.is_some()),
                    None => return Ok(ServerEvent::Ignored),
                };
                if !has_phase1 {
                    return Ok(ServerEvent::Ignored);
                }
                if !quick_started {
                    // Message 1 → message 2. Clone the Phase-1 state so the
                    // session map isn't borrowed across the entropy/transport use.
                    let st = self.sessions.get(&cky_i).unwrap().phase1.clone().unwrap();
                    let (msg2, qr) = respond_quick(&st, &data, &mut self.entropy)?;
                    self.transport.send_to(&msg2, from)?;
                    self.sessions.get_mut(&cky_i).unwrap().quick = Some(qr);
                    Ok(ServerEvent::QuickSaInit)
                } else {
                    // Message 3 → CHILD SA.
                    let qr = self.sessions.get_mut(&cky_i).unwrap().quick.take().unwrap();
                    let child = qr.complete(&data)?;
                    self.children.insert(cky_i, child);
                    Ok(ServerEvent::ChildSaEstablished { cky_i })
                }
            }
            _ => Ok(ServerEvent::Ignored),
        }
    }
}
