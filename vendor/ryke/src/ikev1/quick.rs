//! IKEv1 Quick Mode (RFC 2409 §5.5) — negotiates an ESP CHILD SA under the
//! Phase-1 SKEYIDs. Both the initiator and responder halves are provided; PSK,
//! no PFS (no KE payload), no client IDs (the SA protects the tunnel endpoints).
//!
//! ```text
//! I → HDR*, HASH(1), SA, Ni
//! R → HDR*, HASH(2), SA, Nr
//! I → HDR*, HASH(3)
//! ```
//!
//! `HASH(1) = prf(SKEYID_a, M-ID | SA | Ni)`,
//! `HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr)`,
//! `HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`.
//!
//! The ESP keys are AES-256-GCM (RFC 4106): a 36-byte KEYMAT (32-byte key +
//! 4-byte salt) per SPI, derived from `SKEYID_d` and the Quick-Mode nonces.

use super::crypto1::{self, Prf, AES_BLOCK};
use super::isakmp::{self, exchange, payload, IsakmpHeader, Payload};
use super::payloads::{
    id_type, protocol, Attribute, Id, Proposal, SaPayload, Transform, IPSEC_DOI, SIT_IDENTITY_ONLY,
};
use super::phase1::Phase1State;
use super::phase2;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::esp::{ChildSa, EspSa};

/// AES-256-GCM ESP key material: 32-byte key + 4-byte salt (RFC 4106).
const ESP_KEYMAT_LEN: usize = 36;
/// ESP transform id for AES-GCM with a 16-octet ICV (IANA ESP transform 20,
/// RFC 4106) — the algorithm ryke actually keys (36-byte KEYMAT = 32 key + 4 salt).
const ESP_AES_GCM_16: u8 = 20;

/// IPsec ESP SA attribute types (RFC 2407 §4.5) — a *different* registry from the
/// Phase-1 IKE attributes: here KEY_LENGTH is 6, not 14.
mod esp_attr {
    pub const LIFE_TYPE: u16 = 1;
    pub const LIFE_DURATION: u16 = 2;
    pub const ENCAP_MODE: u16 = 4;
    pub const KEY_LENGTH: u16 = 6;
}
const ENCAP_TUNNEL: u16 = 1;
const LIFE_SECONDS: u16 = 1;

fn find(ps: &[Payload], t: u8) -> Option<&Payload> {
    ps.iter().find(|p| p.payload_type == t)
}

fn qm_header(cky_i: [u8; 8], cky_r: [u8; 8], msgid: u32) -> IsakmpHeader {
    IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: cky_r,
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::QUICK,
        flags: 0,
        message_id: msgid,
        length: 0,
    }
}

/// An ESP SA proposal carrying our inbound SPI: AES-GCM-16-256, tunnel mode —
/// a well-formed proposal a peer like strongSwan will select.
fn esp_sa(spi: u32) -> SaPayload {
    SaPayload {
        doi: IPSEC_DOI,
        situation: SIT_IDENTITY_ONLY,
        proposals: vec![Proposal {
            num: 1,
            protocol_id: protocol::ESP,
            spi: spi.to_be_bytes().to_vec(),
            transforms: vec![Transform {
                num: 1,
                transform_id: ESP_AES_GCM_16,
                attributes: vec![
                    Attribute::short(esp_attr::ENCAP_MODE, ENCAP_TUNNEL),
                    Attribute::short(esp_attr::LIFE_TYPE, LIFE_SECONDS),
                    Attribute::long_u32(esp_attr::LIFE_DURATION, 3600),
                    Attribute::short(esp_attr::KEY_LENGTH, 256),
                ],
            }],
        }],
    }
}

/// An ID payload body for an IPv4 subnet traffic selector (`IDci`/`IDcr`).
fn ts_id(addr: [u8; 4], mask: [u8; 4]) -> Vec<u8> {
    let mut data = addr.to_vec();
    data.extend_from_slice(&mask);
    Id { id_type: id_type::IPV4_ADDR_SUBNET, protocol: 0, port: 0, data }.to_bytes()
}

/// Read the peer's inbound ESP SPI from the SA payload of a Quick-Mode message.
fn peer_esp_spi(ps: &[Payload]) -> Result<u32, IkeError> {
    let sa_p = find(ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let sa = SaPayload::parse(&sa_p.data)?;
    let prop = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    if prop.spi.len() != 4 {
        return Err(IkeError::NoProposalChosen);
    }
    Ok(u32::from_be_bytes([prop.spi[0], prop.spi[1], prop.spi[2], prop.spi[3]]))
}

/// `HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`.
fn hash3(prf: Prf, skeyid_a: &[u8], msgid: u32, ni: &[u8], nr: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8];
    h.extend_from_slice(&msgid.to_be_bytes());
    h.extend_from_slice(ni);
    h.extend_from_slice(nr);
    prf.mac(skeyid_a, &h)
}

/// Derive the ESP CHILD SA. KEYMAT depends only on `SKEYID_d`, the Quick-Mode
/// nonces and the SPI of the *receiving* SA, so the derivation is symmetric: each
/// side stamps outbound packets with the peer's SPI and expects its own inbound.
fn derive_child(prf: Prf, skeyid_d: &[u8], ni: &[u8], nr: &[u8], local_spi: u32, peer_spi: u32) -> Result<ChildSa, IkeError> {
    let km_local = crypto1::keymat(prf, skeyid_d, protocol::ESP, &local_spi.to_be_bytes(), ni, nr, ESP_KEYMAT_LEN);
    let km_peer = crypto1::keymat(prf, skeyid_d, protocol::ESP, &peer_spi.to_be_bytes(), ni, nr, ESP_KEYMAT_LEN);
    Ok(ChildSa {
        outbound: EspSa::new(peer_spi, &km_peer)?,
        inbound: EspSa::new(local_spi, &km_local)?,
    })
}

// ---- initiator ----

/// Post-message-1 Quick-Mode initiator state.
pub struct QuickInitiator {
    prf: Prf,
    skeyid_a: Vec<u8>,
    skeyid_d: Vec<u8>,
    enc_key: Vec<u8>,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    msgid: u32,
    local_spi: u32,
    ni: Vec<u8>,
    iv1: Vec<u8>,
}

/// Build Quick-Mode message 1 (`HASH(1), SA, Ni, IDci, IDcr`) as the initiator,
/// choosing a fresh message-id and inbound ESP SPI. `ts_local`/`ts_remote` are
/// the `(address, netmask)` traffic selectors offered as IDci/IDcr.
pub fn initiate_quick(
    st: &Phase1State,
    entropy: &mut impl Entropy,
    ts_local: ([u8; 4], [u8; 4]),
    ts_remote: ([u8; 4], [u8; 4]),
) -> Result<(Vec<u8>, QuickInitiator), IkeError> {
    let mut spi_b = [0u8; 4];
    entropy.fill(&mut spi_b);
    let local_spi = u32::from_be_bytes(spi_b);
    let mut mid_b = [0u8; 4];
    entropy.fill(&mut mid_b);
    let msgid = u32::from_be_bytes(mid_b) | 1; // non-zero
    let mut ni = vec![0u8; 16];
    entropy.fill(&mut ni);

    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
    let after = [
        (payload::SA, esp_sa(local_spi).to_bytes()),
        (payload::NONCE, ni.clone()),
        (payload::ID, ts_id(ts_local.0, ts_local.1)),
        (payload::ID, ts_id(ts_remote.0, ts_remote.1)),
    ];
    let (msg1, iv1) = phase2::build_encrypted(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, &iv0, &after)?;
    Ok((msg1, QuickInitiator {
        prf: st.prf,
        skeyid_a: st.skeyid_a.clone(),
        skeyid_d: st.skeyid_d.clone(),
        enc_key: st.enc_key.clone(),
        cky_i: st.cky_i,
        cky_r: st.cky_r,
        msgid,
        local_spi,
        ni,
        iv1,
    }))
}

impl QuickInitiator {
    /// Process message 2 (`HASH(2), SA, Nr`): verify `HASH(2)`, and return message
    /// 3 (`HASH(3)`) plus the established ESP CHILD SA.
    pub fn complete(self, msg2: &[u8]) -> Result<(Vec<u8>, ChildSa), IkeError> {
        let (_hdr, ps, iv2) = phase2::decrypt_payloads(msg2, &self.enc_key, &self.iv1)?;
        let nr = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        let peer_spi = peer_esp_spi(&ps)?;

        // Verify HASH(2) = prf(SKEYID_a, M-ID | Ni_b | <payloads after HASH>).
        let got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        let after: Vec<(u8, Vec<u8>)> = ps
            .iter()
            .filter(|p| p.payload_type != payload::HASH)
            .map(|p| (p.payload_type, p.data.clone()))
            .collect();
        let (_first, body) = isakmp::encode_payloads(&after);
        let mut hi = self.msgid.to_be_bytes().to_vec();
        hi.extend_from_slice(&self.ni);
        hi.extend_from_slice(&body);
        if got != self.prf.mac(&self.skeyid_a, &hi) {
            return Err(IkeError::AuthFailed);
        }

        let h3 = hash3(self.prf, &self.skeyid_a, self.msgid, &self.ni, &nr);
        let (msg3, _) = phase2::encrypt_payloads(qm_header(self.cky_i, self.cky_r, self.msgid), &self.enc_key, &iv2, &[(payload::HASH, h3)])?;
        let child = derive_child(self.prf, &self.skeyid_d, &self.ni, &nr, self.local_spi, peer_spi)?;
        Ok((msg3, child))
    }
}

// ---- responder ----

/// Post-message-1 Quick-Mode responder state.
pub struct QuickResponder {
    prf: Prf,
    skeyid_a: Vec<u8>,
    skeyid_d: Vec<u8>,
    enc_key: Vec<u8>,
    msgid: u32,
    local_spi: u32,
    peer_spi: u32,
    ni: Vec<u8>,
    nr: Vec<u8>,
    iv2: Vec<u8>,
}

/// Process Quick-Mode message 1 (`HASH(1), SA, Ni`) and build message 2
/// (`HASH(2), SA, Nr`), choosing a fresh inbound ESP SPI.
pub fn respond_quick(st: &Phase1State, msg1: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, QuickResponder), IkeError> {
    let hdr = IsakmpHeader::parse(msg1)?;
    if hdr.exchange_type != exchange::QUICK {
        return Err(IkeError::Crypto("not a Quick Mode message"));
    }
    let msgid = hdr.message_id;
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
    let (_h, ps, iv1) = phase2::parse_encrypted(msg1, st.prf, &st.skeyid_a, &st.enc_key, &iv0)?; // verifies HASH(1)
    let ni = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
    let peer_spi = peer_esp_spi(&ps)?;

    let mut spi_b = [0u8; 4];
    entropy.fill(&mut spi_b);
    let local_spi = u32::from_be_bytes(spi_b);
    let mut nr = vec![0u8; 16];
    entropy.fill(&mut nr);

    // Echo the initiator's traffic selectors (IDci, IDcr) back in message 2.
    let mut after: Vec<(u8, Vec<u8>)> = vec![
        (payload::SA, esp_sa(local_spi).to_bytes()),
        (payload::NONCE, nr.clone()),
    ];
    for p in ps.iter().filter(|p| p.payload_type == payload::ID) {
        after.push((payload::ID, p.data.clone()));
    }
    let (msg2, iv2) = phase2::build_encrypted_prefixed(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, &iv1, &ni, &after)?;
    Ok((msg2, QuickResponder {
        prf: st.prf,
        skeyid_a: st.skeyid_a.clone(),
        skeyid_d: st.skeyid_d.clone(),
        enc_key: st.enc_key.clone(),
        msgid,
        local_spi,
        peer_spi,
        ni,
        nr,
        iv2,
    }))
}

impl QuickResponder {
    /// Process message 3 (`HASH(3)`), verify it, and return the established ESP
    /// CHILD SA.
    pub fn complete(self, msg3: &[u8]) -> Result<ChildSa, IkeError> {
        let (_hdr, ps, _iv) = phase2::decrypt_payloads(msg3, &self.enc_key, &self.iv2)?;
        let got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        if got != hash3(self.prf, &self.skeyid_a, self.msgid, &self.ni, &self.nr) {
            return Err(IkeError::AuthFailed);
        }
        derive_child(self.prf, &self.skeyid_d, &self.ni, &self.nr, self.local_spi, self.peer_spi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DhGroup;
    use crate::entropy::SeedEntropy;
    use crate::ikev1::payloads::Id;
    use crate::ikev1::phase1::{initiate_aggressive, respond_aggressive, InitiatorConfig, Phase1Config};

    #[test]
    fn ikev1_initiator_and_responder_agree_and_esp_roundtrips() {
        let psk = b"correct horse battery staple".to_vec();
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let icfg = InitiatorConfig { psk: psk.clone(), our_id: Id::ipv4([10, 1, 1, 1]), group: DhGroup::Modp1024, xauth: false, ts_local: ts, ts_remote: ts };
        let rcfg = Phase1Config { psk: psk.clone(), our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(0x1111);
        let mut re = SeedEntropy::new(0x2222);

        // Phase 1: Aggressive Mode.
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie);
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re).unwrap();
        let (msg3, istate) = ai.complete(&msg2).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        // Phase 2: Quick Mode.
        let (qm1, qi) = initiate_quick(&istate, &mut ie, ts, ts).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild) = qi.complete(&qm2).unwrap();
        let mut rchild = qr.complete(&qm3).unwrap();

        // The two CHILD SAs must interoperate: what one seals, the other opens.
        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = ichild.outbound.seal(&pkt, 4).unwrap();
        let (got, nh) = rchild.inbound.open(&sealed).unwrap();
        assert_eq!(got, pkt);
        assert_eq!(nh, 4);
        let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
        let (got_r, _) = ichild.inbound.open(&sealed_r).unwrap();
        assert_eq!(got_r, pkt);
    }

    #[test]
    fn wrong_psk_fails_phase1() {
        let ts = ([0, 0, 0, 0], [0, 0, 0, 0]);
        let icfg = InitiatorConfig { psk: b"right".to_vec(), our_id: Id::ipv4([10, 1, 1, 1]), group: DhGroup::Modp1024, xauth: false, ts_local: ts, ts_remote: ts };
        let rcfg = Phase1Config { psk: b"wrong".to_vec(), our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(1);
        let mut re = SeedEntropy::new(2);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie);
        let (msg2, _rstate) = respond_aggressive(&rcfg, &msg1, &mut re).unwrap();
        assert!(matches!(ai.complete(&msg2), Err(IkeError::AuthFailed)));
    }
}
