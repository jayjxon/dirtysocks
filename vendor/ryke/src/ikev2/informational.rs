//! The INFORMATIONAL exchange (RFC 7296 §1.4): encrypted control messages
//! carrying Notify / Delete payloads — or nothing at all, which is a Dead Peer
//! Detection (DPD) liveness probe that the peer must answer.
//!
//! Direction rule (RFC 7296 §2.14): the original initiator always encrypts with
//! `SK_ei`, the responder with `SK_er`, regardless of who is requesting.

use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::role::Role;
use crate::ikev2::sk::{build_encrypted_gcm, open_encrypted_gcm};

fn our_sk_e(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_ei,
        Role::Responder => &sa.keys.sk_er,
    }
}

fn peer_sk_e(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_er,
        Role::Responder => &sa.keys.sk_ei,
    }
}

fn informational_header(sa: &CompletedSaInit, message_id: u32, is_response: bool) -> IkeHeader {
    IkeHeader {
        initiator_spi: sa.spi_i,
        responder_spi: sa.spi_r,
        next_payload: PayloadType::NoNext, // set by build_encrypted_gcm
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::Informational,
        // The Initiator (I) flag marks messages from the original initiator.
        flags: Flags { initiator: sa.role == Role::Initiator, version: false, response: is_response },
        message_id,
        length: 0,
    }
}

/// Build an encrypted INFORMATIONAL message carrying the given inner payloads.
pub fn build_informational(
    sa: &CompletedSaInit,
    message_id: u32,
    is_response: bool,
    inner_payloads: &[(PayloadType, Vec<u8>)],
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let header = informational_header(sa, message_id, is_response);
    let first = first_payload_type(inner_payloads);
    let inner = encode_payload_chain(inner_payloads);
    build_encrypted_gcm(header, first, &inner, our_sk_e(sa), iv)
}

/// A DPD liveness check: an empty INFORMATIONAL request. A live peer must reply
/// with an (also empty) INFORMATIONAL response.
pub fn dpd_request(sa: &CompletedSaInit, message_id: u32, iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    build_informational(sa, message_id, false, &[], iv)
}

/// Decrypt an INFORMATIONAL from the peer, returning its inner payloads as
/// `(type, body)` pairs. An empty result is a DPD liveness probe/ack.
pub fn open_informational(sa: &CompletedSaInit, message: &[u8]) -> Result<Vec<(PayloadType, Vec<u8>)>, IkeError> {
    let (first, inner) = open_encrypted_gcm(message, peer_sk_e(sa))?;
    let mut out = Vec::new();
    for payload in payloads(first, &inner) {
        let payload = payload?;
        out.push((payload.payload_type, payload.data.to_vec()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};
    use crate::ikev2::payload::Delete;

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn dpd_liveness_roundtrip() {
        let (init_sa, resp_sa) = sa_pair();
        // Initiator probes; responder decrypts an empty INFORMATIONAL.
        let req = dpd_request(&init_sa, 2, &[1u8; 8]).unwrap();
        assert!(open_informational(&resp_sa, &req).unwrap().is_empty());

        // Responder answers; initiator decrypts the (empty) ack.
        let ack = build_informational(&resp_sa, 2, true, &[], &[2u8; 8]).unwrap();
        assert!(open_informational(&init_sa, &ack).unwrap().is_empty());
    }

    #[test]
    fn delete_message_roundtrips_through_sk() {
        let (init_sa, resp_sa) = sa_pair();
        let del = Delete::esp(vec![0xDEAD_BEEF]);
        let msg = build_informational(&init_sa, 3, false, &[(PayloadType::Delete, del.to_bytes())], &[3u8; 8]).unwrap();

        let got = open_informational(&resp_sa, &msg).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, PayloadType::Delete);
        assert_eq!(Delete::parse(&got[0].1).unwrap(), del);
    }

    #[test]
    fn tampered_informational_is_rejected() {
        let (init_sa, resp_sa) = sa_pair();
        let mut msg = dpd_request(&init_sa, 2, &[5u8; 8]).unwrap();
        let last = msg.len() - 1;
        msg[last] ^= 1;
        assert_eq!(open_informational(&resp_sa, &msg).unwrap_err(), IkeError::BadIntegrity);
    }
}
