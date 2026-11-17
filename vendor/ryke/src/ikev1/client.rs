//! A minimal blocking IKEv1 **initiator** (client) over UDP: Aggressive Mode
//! (PSK) followed by Quick Mode, establishing an ESP CHILD SA. No XAUTH /
//! Mode-Config yet — suitable for gateways configured for plain PSK (including
//! ryke's own responder).

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev1::phase1::{initiate_aggressive, InitiatorConfig, Phase1State};
use crate::ikev1::quick::initiate_quick;
use crate::transport::{DriverError, UdpTransport};

/// What a completed IKEv1 handshake yields: the Phase-1 state (for rekey / info
/// exchanges) and the established ESP CHILD SA (the data-plane keys).
pub struct Established {
    pub phase1: Phase1State,
    pub child: ChildSa,
}

/// A UDP IKEv1 initiator driven by an [`Entropy`] source.
pub struct Client<E> {
    transport: UdpTransport,
    entropy: E,
}

impl<E: Entropy> Client<E> {
    /// Bind a local socket (`"0.0.0.0:0"` for an ephemeral source port).
    pub fn bind(addr: impl ToSocketAddrs, entropy: E) -> io::Result<Self> {
        Ok(Self { transport: UdpTransport::bind(addr)?, entropy })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)
    }

    /// Run the full handshake — Aggressive Mode (msg1/msg2/msg3) then Quick Mode
    /// (msg1/msg2/msg3) — against `server`, returning the established SA.
    pub fn connect(&mut self, server: SocketAddr, cfg: &InitiatorConfig) -> Result<Established, DriverError> {
        // Phase 1: Aggressive Mode.
        let (msg1, ai) = initiate_aggressive(cfg, &mut self.entropy);
        self.transport.send_to(&msg1, server)?;
        let (msg2, _from) = self.transport.recv_from()?;
        let (msg3, phase1) = ai.complete(&msg2)?;
        self.transport.send_to(&msg3, server)?;

        // Aggressive Mode has no acknowledgement for msg3, so pause briefly before
        // Quick Mode — otherwise a fast responder can receive QM before it has
        // marked Phase 1 complete and drop it as "phase 1 incomplete".
        std::thread::sleep(std::time::Duration::from_millis(200));

        // Phase 2: Quick Mode.
        let (qm1, qi) = initiate_quick(&phase1, &mut self.entropy, cfg.ts_local, cfg.ts_remote)?;
        self.transport.send_to(&qm1, server)?;
        let (qm2, _from) = self.transport.recv_from()?;
        let (qm3, child) = qi.complete(&qm2)?;
        self.transport.send_to(&qm3, server)?;

        Ok(Established { phase1, child })
    }
}
