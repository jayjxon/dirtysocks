//! AUTH payload computation (RFC 7296 §2.15).
//!
//! Each side proves it sent its `IKE_SA_INIT` message by signing a specific
//! octet string. M2 implements **pre-shared-key** auth (Auth Method 2);
//! certificate (RFC 7427 Digital Signature) and EAP-MSCHAPv2 auth follow in
//! later milestones.
//!
//! ```text
//! InitiatorSignedOctets = RealMessageI | NonceRData | prf(SK_pi, RestOfIDi)
//! ResponderSignedOctets = RealMessageR | NonceIData | prf(SK_pr, RestOfIDr)
//! AUTH (PSK)            = prf( prf(Shared Secret, "Key Pad for IKEv2"),
//!                             <SignedOctets> )
//! ```
//!
//! - `RealMessage*` is that side's `IKE_SA_INIT` message exactly as sent (whole
//!   datagram, including the IKE header).
//! - `NonceRData` / `NonceIData` is the *peer's* nonce bytes (no payload header).
//! - `RestOfID*` is the ID payload **body** (ID Type + RESERVED + ID data — no
//!   generic payload header), i.e. [`crate::ikev2::payload::Identification::to_bytes`].

use crate::crypto::prf;

/// The fixed pad string for PSK auth (RFC 7296 §2.15) — 17 ASCII bytes, no NUL.
const KEY_PAD: &[u8] = b"Key Pad for IKEv2";

/// Signed octets for the **initiator's** AUTH:
/// `RealMessageI | Nr | prf(SK_pi, RestOfIDi)`.
pub fn initiator_signed_octets(real_message_i: &[u8], nr: &[u8], sk_pi: &[u8], idi_body: &[u8]) -> Vec<u8> {
    signed_octets(real_message_i, nr, sk_pi, idi_body)
}

/// Signed octets for the **responder's** AUTH:
/// `RealMessageR | Ni | prf(SK_pr, RestOfIDr)`.
pub fn responder_signed_octets(real_message_r: &[u8], ni: &[u8], sk_pr: &[u8], idr_body: &[u8]) -> Vec<u8> {
    signed_octets(real_message_r, ni, sk_pr, idr_body)
}

fn signed_octets(real_message: &[u8], peer_nonce: &[u8], sk_p: &[u8], id_body: &[u8]) -> Vec<u8> {
    let maced_id = prf(sk_p, id_body);
    let mut out = Vec::with_capacity(real_message.len() + peer_nonce.len() + maced_id.len());
    out.extend_from_slice(real_message);
    out.extend_from_slice(peer_nonce);
    out.extend_from_slice(&maced_id);
    out
}

/// The pre-shared-key AUTH value:
/// `prf( prf(PSK, "Key Pad for IKEv2"), <signed_octets> )`.
pub fn psk_auth(psk: &[u8], signed_octets: &[u8]) -> Vec<u8> {
    let inner = prf(psk, KEY_PAD);
    prf(&inner, signed_octets).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_auth_is_deterministic_and_key_sensitive() {
        let octets = initiator_signed_octets(b"real message I", &[0x22; 32], &[0x11; 32], b"\x02\x00\x00\x00client");
        let a1 = psk_auth(b"secret", &octets);
        assert_eq!(a1, psk_auth(b"secret", &octets)); // deterministic
        assert_eq!(a1.len(), 32); // HMAC-SHA256
        assert_ne!(psk_auth(b"other-psk", &octets), a1); // key-sensitive
    }

    #[test]
    fn initiator_and_responder_octets_differ() {
        let i = initiator_signed_octets(b"msgI", &[2; 32], &[9; 32], b"idi");
        let r = responder_signed_octets(b"msgR", &[1; 32], &[8; 32], b"idr");
        assert_ne!(i, r);
    }

    #[test]
    fn a_verifier_recomputes_the_peer_auth() {
        // The peer sends AUTH over its signed octets; a verifier that knows the
        // same PSK and the same inputs recomputes the identical value.
        let real_msg_i = b"IKE_SA_INIT request exactly as sent";
        let nr = [0x22u8; 32];
        let sk_pi = [0xABu8; 32];
        let idi_body = b"\x02\x00\x00\x00initiator.example";

        let sent = psk_auth(b"correct horse", &initiator_signed_octets(real_msg_i, &nr, &sk_pi, idi_body));
        let verified = psk_auth(b"correct horse", &initiator_signed_octets(real_msg_i, &nr, &sk_pi, idi_body));
        assert_eq!(sent, verified);

        // A tampered RealMessage (e.g. a modified SA_INIT) changes the AUTH.
        let tampered = psk_auth(b"correct horse", &initiator_signed_octets(b"different message", &nr, &sk_pi, idi_body));
        assert_ne!(sent, tampered);
    }
}
