//! CHILD SA rekey via the `CREATE_CHILD_SA` exchange (RFC 7296 §1.3.1, §2.8),
//! without PFS.
//!
//! ```text
//! Initiator → SK { N(REKEY_SA, old_spi), SA(new_spi), Ni, TSi, TSr }
//! Responder → SK { SA(new_spi), Nr, TSi, TSr }
//! ```
//!
//! The new CHILD-SA keys come from `prf+(SK_d, Ni | Nr)` with the *rekey* nonces
//! (see [`crate::esp::ChildSa::derive`]). Both sides end up with matching ESP
//! SAs on freshly chosen SPIs.

use std::net::Ipv4Addr;

use crate::error::IkeError;
use crate::esp::ChildSa;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::ike_auth::esp_offer;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::payload::{notify_type, protocol_id, Notify, SecurityAssociation, TrafficSelector, TrafficSelectors};
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

fn full_tunnel_ts() -> Vec<u8> {
    TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] }.to_bytes()
}

fn create_child_header(sa: &CompletedSaInit, message_id: u32, is_response: bool) -> IkeHeader {
    IkeHeader {
        initiator_spi: sa.spi_i,
        responder_spi: sa.spi_r,
        next_payload: PayloadType::NoNext,
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::CreateChildSa,
        flags: Flags { initiator: sa.role == Role::Initiator, version: false, response: is_response },
        message_id,
        length: 0,
    }
}

/// The ESP SPI a peer proposed in its SA payload.
fn esp_spi_from_sa(sa_bytes: &[u8]) -> Result<u32, IkeError> {
    let sa = SecurityAssociation::parse(sa_bytes)?;
    let proposal = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    if proposal.spi.len() != 4 {
        return Err(IkeError::Crypto("expected a 4-byte ESP SPI"));
    }
    Ok(u32::from_be_bytes(proposal.spi[..4].try_into().unwrap()))
}

/// Extract the (SA bytes, Nonce bytes) from a decrypted CREATE_CHILD_SA message.
fn find_sa_and_nonce(first: PayloadType, inner: &[u8]) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    let mut sa = None;
    let mut nonce = None;
    for payload in payloads(first, inner) {
        let payload = payload?;
        match payload.payload_type {
            PayloadType::SecurityAssociation => sa = Some(payload.data.to_vec()),
            PayloadType::Nonce => nonce = Some(payload.data.to_vec()),
            _ => {}
        }
    }
    Ok((sa.ok_or(IkeError::MissingPayload("SA"))?, nonce.ok_or(IkeError::MissingPayload("Nonce"))?))
}

/// Initiator: build a CHILD-SA rekey request for the CHILD SA `rekeyed_spi`,
/// proposing a new SA on `new_spi` with fresh nonce `ni`.
pub fn build_rekey_request(
    sa: &CompletedSaInit,
    message_id: u32,
    rekeyed_spi: u32,
    new_spi: u32,
    ni: &[u8],
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let rekey_notify = Notify {
        protocol_id: protocol_id::ESP,
        spi: rekeyed_spi.to_be_bytes().to_vec(),
        notify_type: notify_type::REKEY_SA,
        data: Vec::new(),
    };
    let inner = vec![
        (PayloadType::Notify, rekey_notify.to_bytes()),
        (PayloadType::SecurityAssociation, esp_offer(new_spi).to_bytes()),
        (PayloadType::Nonce, ni.to_vec()),
        (PayloadType::TrafficSelectorInitiator, full_tunnel_ts()),
        (PayloadType::TrafficSelectorResponder, full_tunnel_ts()),
    ];
    let header = create_child_header(sa, message_id, false);
    let first = first_payload_type(&inner);
    let bytes = encode_payload_chain(&inner);
    build_encrypted_gcm(header, first, &bytes, our_sk_e(sa), iv)
}

/// Responder: process a rekey request, derive the new CHILD SA, and build the
/// response. Returns `(response_bytes, ChildSa)`.
pub fn responder_process_rekey(
    sa: &CompletedSaInit,
    request: &[u8],
    new_spi: u32,
    nr: &[u8],
    iv: &[u8; 8],
    assigned_ip: Option<Ipv4Addr>,
) -> Result<(Vec<u8>, ChildSa), IkeError> {
    let message_id = IkeHeader::parse(request)?.message_id;
    let (first, inner) = open_encrypted_gcm(request, peer_sk_e(sa))?;
    let (sa_bytes, ni) = find_sa_and_nonce(first, &inner)?;
    let peer_spi = esp_spi_from_sa(&sa_bytes)?;

    // Traffic selectors: mirror exactly what IKE_AUTH did for this client. At AUTH we
    // narrow TSi to the client's assigned /32 and set TSr = full-tunnel; iOS installs
    // that policy. At rekey a native client (iOS) may re-propose a *wide* 0.0.0.0/0
    // TSi and expect the responder to re-narrow — as at AUTH. Echoing the wide TSi
    // back yields a rekeyed child whose selectors disagree with the /32 iOS holds, so
    // iOS deletes the whole IKE SA (~1s after the rekey). When we have an assignment,
    // re-narrow to that /32; with none (local egress), fall back to echoing.
    let (mut echo_tsi, mut echo_tsr) = (None, None);
    for payload in payloads(first, &inner) {
        let p = payload?;
        match p.payload_type {
            PayloadType::TrafficSelectorInitiator => echo_tsi = Some(p.data.to_vec()),
            PayloadType::TrafficSelectorResponder => echo_tsr = Some(p.data.to_vec()),
            _ => {}
        }
    }
    let (tsi, tsr) = match assigned_ip {
        Some(ip) => (
            TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(ip)] }.to_bytes(),
            full_tunnel_ts(),
        ),
        None => (
            echo_tsi.unwrap_or_else(full_tunnel_ts),
            echo_tsr.unwrap_or_else(full_tunnel_ts),
        ),
    };

    let child = ChildSa::derive(&sa.keys.sk_d, &ni, nr, Role::Responder, new_spi, peer_spi);

    let inner_out = vec![
        (PayloadType::SecurityAssociation, esp_offer(new_spi).to_bytes()),
        (PayloadType::Nonce, nr.to_vec()),
        (PayloadType::TrafficSelectorInitiator, tsi),
        (PayloadType::TrafficSelectorResponder, tsr),
    ];
    let header = create_child_header(sa, message_id, true);
    let first_out = first_payload_type(&inner_out);
    let bytes = encode_payload_chain(&inner_out);
    if std::env::var_os("RYKE_REKEY_TRACE").is_some() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("[ryke/rekeyresp] first={first_out:?} inner ({} B) = {hex}", bytes.len());
    }
    let response = build_encrypted_gcm(header, first_out, &bytes, our_sk_e(sa), iv)?;
    Ok((response, child))
}

/// Initiator: complete the rekey from the response, deriving the new CHILD SA.
/// `ni` and `new_spi` are the values used in [`build_rekey_request`].
pub fn initiator_complete_rekey(
    sa: &CompletedSaInit,
    ni: &[u8],
    new_spi: u32,
    response: &[u8],
) -> Result<ChildSa, IkeError> {
    let (first, inner) = open_encrypted_gcm(response, peer_sk_e(sa))?;
    let (sa_bytes, nr) = find_sa_and_nonce(first, &inner)?;
    let peer_spi = esp_spi_from_sa(&sa_bytes)?;
    Ok(ChildSa::derive(&sa.keys.sk_d, ni, &nr, Role::Initiator, new_spi, peer_spi))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esp::next_header;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn child_rekey_yields_matching_esp_sas() {
        let (init_sa, resp_sa) = sa_pair();
        let ni = [0x33u8; 32];
        let nr = [0x44u8; 32];
        let init_new_spi = 0x1111_1111;
        let resp_new_spi = 0x2222_2222;

        let old_child_spi = 0xDEAD_BEEF;
        let req = build_rekey_request(&init_sa, 2, old_child_spi, init_new_spi, &ni, &[1u8; 8]).unwrap();
        let (resp, mut resp_child) =
            responder_process_rekey(&resp_sa, &req, resp_new_spi, &nr, &[2u8; 8], None).unwrap();
        let mut init_child = initiator_complete_rekey(&init_sa, &ni, init_new_spi, &resp).unwrap();

        // The rekeyed SAs interoperate: initiator seals, responder opens, and back.
        let pkt = init_child.outbound.seal(b"after rekey A->B", next_header::IPV4).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"after rekey A->B");
        let pkt2 = resp_child.outbound.seal(b"after rekey B->A", next_header::IPV4).unwrap();
        assert_eq!(init_child.inbound.open(&pkt2).unwrap().0, b"after rekey B->A");
    }

    fn extract_tsi(resp: &[u8], init_sa: &CompletedSaInit) -> Vec<u8> {
        let (first, dec) = open_encrypted_gcm(resp, peer_sk_e(init_sa)).unwrap();
        for p in payloads(first, &dec) {
            let p = p.unwrap();
            if p.payload_type == PayloadType::TrafficSelectorInitiator {
                return p.data.to_vec();
            }
        }
        panic!("no TSi in the rekey response");
    }

    /// Regression (the production iOS drop): a native client narrows TSi to its
    /// assigned `/32` at IKE_AUTH, then re-proposes a *wide* `0.0.0.0/0` at rekey and
    /// expects the responder to re-narrow — exactly as AUTH did. The responder must
    /// re-narrow TSi to the assigned `/32`; echoing the wide selector back makes iOS
    /// delete the whole IKE SA ~1s later. With no assignment it falls back to echoing.
    #[test]
    fn responder_renarrows_tsi_to_assigned_at_rekey() {
        use std::net::Ipv4Addr;
        let (init_sa, resp_sa) = sa_pair();
        let assigned = Ipv4Addr::new(10, 8, 0, 7);
        let narrow =
            TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(assigned)] }.to_bytes();
        let wide_tsi = full_tunnel_ts();
        assert_ne!(narrow, wide_tsi, "the narrowed /32 must differ from full-tunnel");

        // The initiator (iOS at rekey) proposes a WIDE TSi.
        let inner = vec![
            (
                PayloadType::Notify,
                Notify {
                    protocol_id: protocol_id::ESP,
                    spi: 0xDEAD_BEEFu32.to_be_bytes().to_vec(),
                    notify_type: notify_type::REKEY_SA,
                    data: Vec::new(),
                }
                .to_bytes(),
            ),
            (PayloadType::SecurityAssociation, esp_offer(0xAAAA_AAAA).to_bytes()),
            (PayloadType::Nonce, vec![0x55u8; 32]),
            (PayloadType::TrafficSelectorInitiator, wide_tsi.clone()),
            (PayloadType::TrafficSelectorResponder, full_tunnel_ts()),
        ];
        let header = create_child_header(&init_sa, 2, false);
        let req = build_encrypted_gcm(
            header,
            first_payload_type(&inner),
            &encode_payload_chain(&inner),
            our_sk_e(&init_sa),
            &[1u8; 8],
        )
        .unwrap();

        // With an assignment: TSi comes back as the /32, NOT the wide proposal.
        let (resp, _child) =
            responder_process_rekey(&resp_sa, &req, 0xBBBB_BBBB, &[0x66u8; 32], &[2u8; 8], Some(assigned))
                .unwrap();
        assert_eq!(
            extract_tsi(&resp, &init_sa),
            narrow,
            "responder must re-narrow TSi to the assigned /32 at rekey"
        );

        // With no assignment (local egress): the initiator's TSi is echoed verbatim.
        let (resp_echo, _c) =
            responder_process_rekey(&resp_sa, &req, 0xCCCC_CCCC, &[0x77u8; 32], &[3u8; 8], None).unwrap();
        assert_eq!(
            extract_tsi(&resp_echo, &init_sa),
            wide_tsi,
            "with no assignment the responder echoes the initiator's TSi"
        );
    }
}
