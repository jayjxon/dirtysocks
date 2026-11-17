//! The role an endpoint plays in an IKEv2 exchange.
//!
//! IKEv2 is peer-to-peer at the protocol level, but real deployments split into
//! a client that starts exchanges and a server that answers them. `ryke`
//! implements both sides independently, so the role is an explicit choice rather
//! than a compile-time flavor.

/// Which side of an IKEv2 exchange this endpoint plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The client: originates an exchange (sends the first `IKE_SA_INIT`).
    Initiator,
    /// The server: answers exchanges started by an initiator.
    Responder,
}

impl Role {
    pub fn is_initiator(self) -> bool {
        matches!(self, Role::Initiator)
    }

    pub fn is_responder(self) -> bool {
        matches!(self, Role::Responder)
    }

    /// The peer's role — the other side of the exchange.
    pub fn peer(self) -> Role {
        match self {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        }
    }

    /// Value of the IKE header's Initiator (I) flag for messages we originate:
    /// set only by the original initiator (RFC 7296 §3.1).
    pub fn header_initiator_flag(self) -> bool {
        self.is_initiator()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_are_symmetric() {
        assert_eq!(Role::Initiator.peer(), Role::Responder);
        assert_eq!(Role::Responder.peer().peer(), Role::Responder);
        assert!(Role::Initiator.header_initiator_flag());
        assert!(!Role::Responder.header_initiator_flag());
    }
}
