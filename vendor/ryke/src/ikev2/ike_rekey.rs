//! IKE-SA rekey (RFC 7296 §2.18) via the `CREATE_CHILD_SA` exchange.
//!
//! ```text
//! Initiator → SK { SA(new IKE SPIi), Ni, KEi }
//! Responder → SK { SA(new IKE SPIr), Nr, KEr }
//! ```
//!
//! A fresh Diffie-Hellman gives a new shared secret; the new IKE keys are
//! `SKEYSEED = prf(SK_d(old), g^ir | Ni | Nr)` then `prf+` over the *new* SPIs
//! (see [`crate::crypto::derive_rekey_session_keys`]). The CHILD SAs are **not**
//! touched — they are inherited by the new IKE SA, which the consumer installs.
//! Without this, a native client (iOS refreshes its IKE SA on its ~1h lifetime)
//! fails the rekey and tears the whole tunnel down.

use crate::crypto::{self, DhGroup};
use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::negotiate;
use crate::ikev2::payload::{protocol_id, KeyExchange, SecurityAssociation};
use crate::ikev2::sk::{build_encrypted_gcm, open_encrypted_gcm};
use crate::role::Role;

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

/// Whether a decrypted CREATE_CHILD_SA is an **IKE-SA** rekey (has a KeyExchange
/// and no Traffic Selectors) rather than a CHILD-SA rekey. The consumer routes on
/// this before calling [`responder_process_ike_rekey`].
pub fn is_ike_sa_rekey(inner: &[(PayloadType, Vec<u8>)]) -> bool {
    let has_ke = inner.iter().any(|(t, _)| *t == PayloadType::KeyExchange);
    let has_ts = inner
        .iter()
        .any(|(t, _)| *t == PayloadType::TrafficSelectorInitiator || *t == PayloadType::TrafficSelectorResponder);
    has_ke && !has_ts
}

/// Responder: process an IKE-SA rekey request (SK-wrapped under the *old* IKE SA),
/// derive the new IKE SA, and build the response. `new_spi_r` is our new IKE SPI,
/// `dh_private` our fresh ephemeral DH secret, `nr` our new nonce. Returns
/// `(response_bytes, new_ike_sa)`; the caller migrates the CHILD SAs onto it and
/// retires the old IKE SA when the peer deletes it.
pub fn responder_process_ike_rekey(
    old_sa: &CompletedSaInit,
    request: &[u8],
    new_spi_r: u64,
    dh_private: &[u8],
    nr: &[u8],
    iv: &[u8; 8],
) -> Result<(Vec<u8>, CompletedSaInit), IkeError> {
    let message_id = IkeHeader::parse(request)?.message_id;
    let (first, inner) = open_encrypted_gcm(request, peer_sk_e(old_sa))?;

    let (mut sa_bytes, mut ni, mut ke_bytes) = (None, None, None);
    for p in payloads(first, &inner) {
        let p = p?;
        match p.payload_type {
            PayloadType::SecurityAssociation => sa_bytes = Some(p.data.to_vec()),
            PayloadType::Nonce => ni = Some(p.data.to_vec()),
            PayloadType::KeyExchange => ke_bytes = Some(p.data.to_vec()),
            _ => {}
        }
    }
    let sa_bytes = sa_bytes.ok_or(IkeError::MissingPayload("SA"))?;
    let ni = ni.ok_or(IkeError::MissingPayload("Nonce"))?;
    let ke = KeyExchange::parse(&ke_bytes.ok_or(IkeError::MissingPayload("KE"))?)?;

    let sa = SecurityAssociation::parse(&sa_bytes)?;
    let proposal = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    if proposal.spi.len() != 8 {
        return Err(IkeError::Crypto("expected an 8-byte IKE SPI"));
    }
    let spi_i = u64::from_be_bytes(proposal.spi[..8].try_into().unwrap());

    let suite = negotiate::select(&sa).ok_or(IkeError::NoProposalChosen)?;
    let group = DhGroup::from_transform_id(suite.dh_id).ok_or(IkeError::NoProposalChosen)?;
    if ke.dh_group != group.transform_id() {
        return Err(IkeError::DhGroupMismatch { expected: group.transform_id(), got: ke.dh_group });
    }
    let shared = group.shared(dh_private, &ke.data)?;
    let our_public = group.public(dh_private);

    let keys = crypto::derive_rekey_session_keys(
        &old_sa.keys.sk_d,
        &shared,
        &ni,
        nr,
        spi_i,
        new_spi_r,
        suite.key_lengths(),
    );

    // Response inner: SA(new IKE proposal carrying our new SPI) | Nr | KEr.
    let mut prop = suite.to_proposal();
    prop.protocol_id = protocol_id::IKE;
    prop.spi = new_spi_r.to_be_bytes().to_vec();
    let sar = SecurityAssociation { proposals: vec![prop] };
    let ke_out = KeyExchange { dh_group: suite.dh_id, data: our_public };
    let inner_out = vec![
        (PayloadType::SecurityAssociation, sar.to_bytes()),
        (PayloadType::Nonce, nr.to_vec()),
        (PayloadType::KeyExchange, ke_out.to_bytes()),
    ];
    // The rekey exchange is protected by the OLD IKE SA (its header SPIs, its keys).
    let header = IkeHeader {
        initiator_spi: old_sa.spi_i,
        responder_spi: old_sa.spi_r,
        next_payload: PayloadType::NoNext,
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::CreateChildSa,
        flags: Flags { initiator: old_sa.role == Role::Initiator, version: false, response: true },
        message_id,
        length: 0,
    };
    let first_out = first_payload_type(&inner_out);
    let bytes = encode_payload_chain(&inner_out);
    let response = build_encrypted_gcm(header, first_out, &bytes, our_sk_e(old_sa), iv)?;

    let new_sa = CompletedSaInit {
        role: Role::Responder,
        spi_i,
        spi_r: new_spi_r,
        suite,
        keys,
        ni,
        nr: nr.to_vec(),
        // Not an IKE_SA_INIT and AUTH is not re-run for a rekeyed IKE SA.
        init_message: Vec::new(),
        resp_message: Vec::new(),
        peer_signature_hashes: old_sa.peer_signature_hashes.clone(),
    };
    Ok((response, new_sa))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::exchange::{
        default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret,
    };

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn routes_only_a_ke_no_ts_message_as_ike_rekey() {
        assert!(is_ike_sa_rekey(&[
            (PayloadType::SecurityAssociation, vec![]),
            (PayloadType::Nonce, vec![]),
            (PayloadType::KeyExchange, vec![]),
        ]));
        // A CHILD rekey has TS and no KE — must NOT be treated as an IKE rekey.
        assert!(!is_ike_sa_rekey(&[
            (PayloadType::SecurityAssociation, vec![]),
            (PayloadType::Nonce, vec![]),
            (PayloadType::TrafficSelectorInitiator, vec![]),
            (PayloadType::TrafficSelectorResponder, vec![]),
        ]));
    }

    #[test]
    fn ike_rekey_initiator_and_responder_derive_matching_keys() {
        let (init_sa, resp_sa) = sa_pair();
        let suite = negotiate::select(&default_offer()).unwrap();
        let group = DhGroup::from_transform_id(suite.dh_id).unwrap();

        // Initiator builds the IKE-rekey request: SA(IKE, new SPIi) | Ni | KEi.
        let init_dh = [3u8; 32];
        let ni = vec![0x55u8; 32];
        let new_spi_i: u64 = 0xAABB_CCDD_1122_3344;
        let mut prop = suite.to_proposal();
        prop.protocol_id = protocol_id::IKE;
        prop.spi = new_spi_i.to_be_bytes().to_vec();
        let inner = vec![
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![prop] }.to_bytes()),
            (PayloadType::Nonce, ni.clone()),
            (PayloadType::KeyExchange, KeyExchange { dh_group: suite.dh_id, data: group.public(&init_dh) }.to_bytes()),
        ];
        let header = IkeHeader {
            initiator_spi: init_sa.spi_i,
            responder_spi: init_sa.spi_r,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::CreateChildSa,
            flags: Flags { initiator: true, version: false, response: false },
            message_id: 5,
            length: 0,
        };
        let request = build_encrypted_gcm(
            header,
            first_payload_type(&inner),
            &encode_payload_chain(&inner),
            our_sk_e(&init_sa),
            &[1u8; 8],
        )
        .unwrap();

        // Responder processes it and derives the new IKE SA.
        let nr = vec![0x66u8; 32];
        let new_spi_r: u64 = 0x9988_7766_5544_3322;
        let (response, new_resp) =
            responder_process_ike_rekey(&resp_sa, &request, new_spi_r, &[9u8; 32], &nr, &[2u8; 8]).unwrap();
        assert_eq!(new_resp.spi_i, new_spi_i);
        assert_eq!(new_resp.spi_r, new_spi_r);

        // Initiator completes: decrypt response, get KEr, derive the SAME keys.
        let (first, dec) = open_encrypted_gcm(&response, peer_sk_e(&init_sa)).unwrap();
        let mut ker = None;
        for p in payloads(first, &dec) {
            let p = p.unwrap();
            if p.payload_type == PayloadType::KeyExchange {
                ker = Some(KeyExchange::parse(p.data).unwrap());
            }
        }
        let shared = group.shared(&init_dh, &ker.unwrap().data).unwrap();
        let init_keys = crate::crypto::derive_rekey_session_keys(
            &init_sa.keys.sk_d,
            &shared,
            &ni,
            &nr,
            new_spi_i,
            new_spi_r,
            suite.key_lengths(),
        );
        assert_eq!(init_keys.sk_d, new_resp.keys.sk_d, "SK_d must match");
        assert_eq!(init_keys.sk_ei, new_resp.keys.sk_ei, "SK_ei must match");
        assert_eq!(init_keys.sk_er, new_resp.keys.sk_er, "SK_er must match");
    }
}
