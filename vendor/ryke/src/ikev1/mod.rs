//! IKEv1 (RFC 2409 / ISAKMP RFC 2408) — a self-contained implementation for the
//! Aggressive Mode + Xauth + Mode-Config + Quick Mode flow that Android's
//! built-in "IPSec Xauth PSK" client (Android ≤ 10) uses.
//!
//! This subtree deliberately shares nothing with the IKEv2 code except the
//! low-level crypto primitives (SHA/HMAC/AES/DES via RustCrypto and the MODP
//! [`crate::crypto::DhGroup`]). IKEv1's ISAKMP framing, its raw-keyed PRF (no
//! `prf+`), its CBC-with-IV-chaining encryption, and its Aggressive-Mode key
//! schedule are all structurally different from IKEv2.

pub mod client;
pub mod crypto1;
pub mod isakmp;
pub mod modecfg;
pub mod payloads;
pub mod phase1;
pub mod phase2;
pub mod quick;
pub mod server;

pub use client::{Client, Established};
pub use server::{Server, ServerEvent};
