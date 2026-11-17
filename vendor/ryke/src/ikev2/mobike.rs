//! MOBIKE (RFC 4555) — surviving IP address changes (e.g. a phone moving between
//! Wi-Fi and cellular) without renegotiating the IKE/CHILD SAs.
//!
//! `ryke` provides the signalling; the actual socket rebinding and updating a
//! [`crate::tunnel::Tunnel`]'s peer address is the consumer's job.
//!
//! - `MOBIKE_SUPPORTED` is offered in `IKE_AUTH` to enable MOBIKE.
//! - When a peer's address changes it sends an INFORMATIONAL request with
//!   `UPDATE_SA_ADDRESSES` (RFC 4555 §3.5); the receiver updates the SA's peer
//!   address to that packet's *observed* source and answers.

use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::informational::build_informational;
use crate::ikev2::message::PayloadType;
use crate::ikev2::payload::{notify_type, Notify};

/// The `MOBIKE_SUPPORTED` notify to include in `IKE_AUTH` to enable MOBIKE.
pub fn mobike_supported() -> Notify {
    Notify::status(notify_type::MOBIKE_SUPPORTED, Vec::new())
}

/// Build an INFORMATIONAL request announcing our address changed:
/// `SK { N(UPDATE_SA_ADDRESSES) }`. The receiver updates the SA's peer address to
/// this packet's observed source (RFC 4555 §3.5).
pub fn build_update_sa_addresses(sa: &CompletedSaInit, message_id: u32, iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    let notify = Notify::status(notify_type::UPDATE_SA_ADDRESSES, Vec::new());
    build_informational(sa, message_id, false, &[(PayloadType::Notify, notify.to_bytes())], iv)
}

/// Whether a decrypted INFORMATIONAL carries `UPDATE_SA_ADDRESSES` — i.e. the
/// peer moved and we should update its address to the packet's source.
pub fn contains_update_sa_addresses(inner: &[(PayloadType, Vec<u8>)]) -> bool {
    has_notify(inner, notify_type::UPDATE_SA_ADDRESSES)
}

/// Whether a decrypted message carries a `MOBIKE_SUPPORTED` notify.
pub fn peer_supports_mobike(inner: &[(PayloadType, Vec<u8>)]) -> bool {
    has_notify(inner, notify_type::MOBIKE_SUPPORTED)
}

fn has_notify(inner: &[(PayloadType, Vec<u8>)], want: u16) -> bool {
    inner.iter().any(|(t, body)| {
        *t == PayloadType::Notify && Notify::parse(body).map(|n| n.notify_type == want).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};
    use crate::ikev2::informational::{dpd_request, open_informational};

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn update_sa_addresses_is_signalled_and_detected() {
        let (init_sa, resp_sa) = sa_pair();
        let msg = build_update_sa_addresses(&init_sa, 4, &[7u8; 8]).unwrap();
        let inner = open_informational(&resp_sa, &msg).unwrap();
        assert!(contains_update_sa_addresses(&inner));

        // A plain DPD probe does not look like an address change.
        let dpd = dpd_request(&init_sa, 5, &[8u8; 8]).unwrap();
        assert!(!contains_update_sa_addresses(&open_informational(&resp_sa, &dpd).unwrap()));
    }

    #[test]
    fn mobike_supported_is_a_status_notify() {
        let n = mobike_supported();
        assert_eq!(n.notify_type, notify_type::MOBIKE_SUPPORTED);
        assert!(!n.is_error());
        assert!(peer_supports_mobike(&[(PayloadType::Notify, n.to_bytes())]));
    }
}
