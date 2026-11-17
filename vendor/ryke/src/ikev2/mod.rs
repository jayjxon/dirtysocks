//! IKEv2 (RFC 7296) — the full initiator/responder implementation: framing,
//! PSK + certificate (RFC 7427) + EAP-MSCHAPv2 auth, NAT-T, fragmentation,
//! rekey, DELETE/DPD, and MOBIKE. Built on the shared crypto core at the crate
//! root (crypto, esp, tunnel, transport, error, entropy, role).

pub mod message;
pub mod payload;
pub mod sk;
pub mod negotiate;
pub mod exchange;
pub mod auth;
pub mod ike_auth;
pub mod sign;
pub mod eap;
pub mod mschapv2;
pub mod eap_auth;
pub mod natt;
pub mod fragment;
pub mod informational;
pub mod rekey;
pub mod ike_rekey;
pub mod mobike;
pub mod client;
pub mod server;
