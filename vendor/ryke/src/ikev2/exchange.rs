//! The `IKE_SA_INIT` exchange (RFC 7296 §1.2), implemented for both roles.
//!
//! ```text
//! Initiator  →  HDR, SAi1, KEi, Ni
//! Responder  →  HDR, SAr1, KEr, Nr
//! ```
//!
//! After the round trip, both sides independently compute the same SKEYSEED and
//! SK_* set from the shared DH secret, the two nonces, and the two SPIs.
//!
//! Ephemeral inputs (DH private scalar, nonce, SPI) are supplied by the caller
//! via [`LocalSecret`] rather than drawn from an RNG inside the crate — this
//! keeps the exchange deterministic and unit-testable; production callers pass
//! OS randomness. Later exchanges (`IKE_AUTH`, `CREATE_CHILD_SA`) will join this
//! module.

use crate::crypto::{self, DhGroup, SessionKeys};
use crate::error::IkeError;
use crate::ikev2::message::{
    payloads, ExchangeType, Flags, IkeHeader, MessageBuilder, PayloadType,
};
use sha2::{Digest, Sha256};

use crate::ikev2::natt;
use crate::ikev2::negotiate::{self, ChosenSuite};
use crate::ikev2::payload::{
    notify_type, protocol_id, sighash, transform_id, transform_type, KeyExchange, Nonce, Notify,
    Proposal, SecurityAssociation, Transform,
};
use crate::role::Role;

/// The signature hashes ryke advertises (and can verify) in an RFC 7427 Digital
/// Signature AUTH. Only SHA-256 for now — every native iOS/Android client offers
/// it — so this is what we both advertise and require of a method-14 signer.
pub const SUPPORTED_SIGNATURE_HASHES: &[u16] = &[sighash::SHA2_256];

/// Our per-exchange ephemeral inputs. In production these come from the OS RNG;
/// in tests they are fixed for determinism.
#[derive(Debug, Clone)]
pub struct LocalSecret {
    /// X25519 private scalar.
    pub dh_private: [u8; 32],
    /// Our nonce (Ni if we initiate, Nr if we respond).
    pub nonce: Vec<u8>,
    /// Our SPI (SPIi if we initiate, SPIr if we respond); must be non-zero.
    pub spi: u64,
}

/// The result of a completed `IKE_SA_INIT`, from one side's perspective.
///
/// Carries everything `IKE_AUTH` needs: the derived keys, the two nonces, and
/// the two SA_INIT messages verbatim (the AUTH payload signs over them,
/// RFC 7296 §2.15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedSaInit {
    pub role: Role,
    pub spi_i: u64,
    pub spi_r: u64,
    pub suite: ChosenSuite,
    pub keys: SessionKeys,
    /// Initiator and responder nonces.
    pub ni: Vec<u8>,
    pub nr: Vec<u8>,
    /// The `IKE_SA_INIT` request and response, exactly as they went on the wire.
    pub init_message: Vec<u8>,
    pub resp_message: Vec<u8>,
    /// The RFC 7427 signature hashes the *peer* advertised in its `IKE_SA_INIT`
    /// (empty if none). A method-14 signer must pick one of these; an empty list
    /// means the peer forbids Digital Signature auth.
    pub peer_signature_hashes: Vec<u16>,
}

impl LocalSecret {
    /// Draw fresh ephemeral inputs from an entropy source. `nonce_len` must be
    /// ≥16 (RFC 7296 §2.10); 32 is a good default. The SPI is forced non-zero.
    pub fn generate(entropy: &mut impl crate::entropy::Entropy, nonce_len: usize) -> Self {
        let dh_private = entropy.next_array32();
        let mut nonce = vec![0u8; nonce_len];
        entropy.fill(&mut nonce);
        let mut spi = entropy.next_u64();
        if spi == 0 {
            spi = 1; // an SPI of zero is reserved (RFC 7296 §3.1)
        }
        LocalSecret { dh_private, nonce, spi }
    }
}

/// Our default offered proposal: AES-GCM-16-256, PRF-HMAC-SHA256, X25519.
/// (No ESN — that transform type is only valid for ESP/AH, RFC 7296 §3.3.3.)
pub fn default_offer() -> SecurityAssociation {
    SecurityAssociation {
        proposals: vec![Proposal {
            num: 1,
            protocol_id: protocol_id::IKE,
            spi: Vec::new(),
            transforms: vec![
                Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_GCM_16, key_length: Some(256) },
                Transform { transform_type: transform_type::PRF, transform_id: transform_id::PRF_HMAC_SHA2_256, key_length: None },
                Transform { transform_type: transform_type::DH, transform_id: transform_id::X25519, key_length: None },
            ],
        }],
    }
}

/// The payloads an `IKE_SA_INIT` message carries that we act on.
struct SaInitPayloads {
    sa: SecurityAssociation,
    ke: KeyExchange,
    nonce: Nonce,
    /// The peer's advertised RFC 7427 signature hashes (empty if it sent none).
    signature_hashes: Vec<u16>,
    /// A COOKIE notify the initiator echoed back (RFC 7296 §2.6), if any.
    cookie: Option<Vec<u8>>,
}

/// Decode a `SIGNATURE_HASH_ALGORITHMS` notify's data — a bare list of 16-bit
/// hash identifiers. A trailing odd byte is ignored (defensive).
fn parse_signature_hashes(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect()
}

fn parse_sa_init(header: &IkeHeader, body: &[u8]) -> Result<SaInitPayloads, IkeError> {
    let mut sa = None;
    let mut ke = None;
    let mut nonce = None;
    let mut signature_hashes = Vec::new();
    let mut cookie = None;
    for payload in payloads(header.next_payload, body) {
        let payload = payload?;
        match payload.payload_type {
            PayloadType::SecurityAssociation => sa = Some(SecurityAssociation::parse(payload.data)?),
            PayloadType::KeyExchange => ke = Some(KeyExchange::parse(payload.data)?),
            PayloadType::Nonce => nonce = Some(Nonce::parse(payload.data)),
            PayloadType::Notify => {
                if let Ok(n) = Notify::parse(payload.data) {
                    if n.notify_type == notify_type::SIGNATURE_HASH_ALGORITHMS {
                        signature_hashes = parse_signature_hashes(&n.data);
                    } else if n.notify_type == notify_type::COOKIE {
                        cookie = Some(n.data);
                    }
                }
            }
            // Other notifies / VendorId / CertReq are not acted on here.
            _ => {}
        }
    }
    Ok(SaInitPayloads {
        sa: sa.ok_or(IkeError::MissingPayload("SA"))?,
        ke: ke.ok_or(IkeError::MissingPayload("KE"))?,
        nonce: nonce.ok_or(IkeError::MissingPayload("Nonce"))?,
        signature_hashes,
        cookie,
    })
}

/// The `SIGNATURE_HASH_ALGORITHMS` notify (RFC 7427 §4) advertising the hashes
/// ryke can verify — required in `IKE_SA_INIT` before Digital Signature auth.
fn sighash_notify() -> Notify {
    let mut data = Vec::with_capacity(2 * SUPPORTED_SIGNATURE_HASHES.len());
    for h in SUPPORTED_SIGNATURE_HASHES {
        data.extend_from_slice(&h.to_be_bytes());
    }
    Notify::status(notify_type::SIGNATURE_HASH_ALGORITHMS, data)
}

fn base_header(spi_i: u64, spi_r: u64, flags: Flags) -> IkeHeader {
    IkeHeader {
        initiator_spi: spi_i,
        responder_spi: spi_r,
        next_payload: PayloadType::NoNext, // filled in by MessageBuilder
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::IkeSaInit,
        flags,
        message_id: 0,
        length: 0, // filled in by MessageBuilder
    }
}

fn build_sa_init(header: IkeHeader, sa: &SecurityAssociation, dh_group: u16, dh_public: &[u8], nonce: &[u8], extra_notifies: &[Notify]) -> Vec<u8> {
    let ke = KeyExchange { dh_group, data: dh_public.to_vec() };
    let mut b = MessageBuilder::new(header)
        .push(PayloadType::SecurityAssociation, sa.to_bytes())
        .push(PayloadType::KeyExchange, ke.to_bytes())
        .push(PayloadType::Nonce, Nonce { data: nonce.to_vec() }.to_bytes())
        .push(PayloadType::Notify, sighash_notify().to_bytes());
    for n in extra_notifies {
        b = b.push(PayloadType::Notify, n.to_bytes());
    }
    b.build()
}

/// The peer's public value, checked against the negotiated group's ID + length.
fn dh_peer(ke: &KeyExchange, group: DhGroup) -> Result<&[u8], IkeError> {
    if ke.dh_group != group.transform_id() {
        return Err(IkeError::DhGroupMismatch { expected: group.transform_id(), got: ke.dh_group });
    }
    if ke.data.len() != group.public_len() {
        return Err(IkeError::BadKeyExchange { group: ke.dh_group, len: ke.data.len() });
    }
    Ok(&ke.data)
}

/// The DH group our own offer advertises (its first proposal's DH transform).
fn offer_dh_group(offer: &SecurityAssociation) -> DhGroup {
    offer
        .proposals
        .first()
        .and_then(|p| p.transforms.iter().find(|t| t.transform_type == transform_type::DH))
        .and_then(|t| DhGroup::from_transform_id(t.transform_id))
        .unwrap_or(DhGroup::X25519)
}

/// Initiator step 1: build the `IKE_SA_INIT` request from our offer.
pub fn initiator_request(local: &LocalSecret, offer: &SecurityAssociation) -> Vec<u8> {
    let group = offer_dh_group(offer);
    let public = group.public(&local.dh_private);
    let header = base_header(local.spi, 0, Flags { initiator: true, version: false, response: false });
    build_sa_init(header, offer, group.transform_id(), &public, &local.nonce, &[])
}

/// A COOKIE challenge policy (RFC 7296 §2.6) — return-routability against
/// spoofed-source `IKE_SA_INIT` floods. When `required`, the responder answers a
/// request lacking the matching cookie with a COOKIE notify only (no Diffie-
/// Hellman, no half-open state), so an attacker who can't receive at the claimed
/// source address can never make it do work.
pub struct CookiePolicy<'a> {
    /// A responder-private secret, rotated periodically.
    pub secret: &'a [u8],
    /// The observed source address of the request (its bytes), bound into the
    /// cookie so a cookie is only valid from the address it was issued to.
    pub peer: &'a [u8],
    /// Whether to demand a cookie right now (e.g. when half-open SAs are high).
    pub required: bool,
}

/// The IKEv2 COOKIE value: `SHA-256(secret | SPIi | Ni | peer_addr)`.
pub fn ike_cookie(secret: &[u8], spi_i: u64, ni: &[u8], peer: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(secret);
    h.update(spi_i.to_be_bytes());
    h.update(ni);
    h.update(peer);
    h.finalize().to_vec()
}

/// A bare `IKE_SA_INIT` response carrying only a COOKIE notify.
fn build_cookie_challenge(spi_i: u64, cookie: &[u8]) -> Vec<u8> {
    let header = base_header(spi_i, 0, Flags { initiator: false, version: false, response: true });
    let notify = Notify::status(notify_type::COOKIE, cookie.to_vec());
    MessageBuilder::new(header).push(PayloadType::Notify, notify.to_bytes()).build()
}

/// The outcome of responding to an `IKE_SA_INIT` request.
// Short-lived: returned and immediately matched by the caller, so the size gap
// between variants costs nothing — boxing would only add a pointless allocation.
#[allow(clippy::large_enum_variant)]
pub enum SaInitResult {
    /// The SA is half-open: send `response` and keep `sa` awaiting `IKE_AUTH`.
    Established { response: Vec<u8>, sa: CompletedSaInit },
    /// The initiator's Key Exchange payload was for a Diffie-Hellman group we did
    /// not select; send `response` (an `INVALID_KE_PAYLOAD` notify naming `group`)
    /// and keep NO state — the initiator resends `IKE_SA_INIT` with the right KE
    /// (RFC 7296 §1.2 / §2.7). Native clients (iOS/Android) rely on this.
    InvalidKe { response: Vec<u8>, group: u16 },
    /// A cookie is required (anti-DoS): send `response` (a COOKIE notify) and keep
    /// NO state; the initiator resends `IKE_SA_INIT` echoing the cookie.
    CookieRequired { response: Vec<u8> },
}

/// Responder: consume the request, choose a suite, derive keys, and build the
/// response. Returns the response bytes and our completed state.
pub fn responder_respond(request: &[u8], local: &LocalSecret) -> Result<(Vec<u8>, CompletedSaInit), IkeError> {
    match responder_respond_inner(request, local, None, None)? {
        SaInitResult::Established { response, sa } => Ok((response, sa)),
        // Unreachable for the non-NAT path: it returns DhGroupMismatch instead,
        // and never requests a cookie (no policy passed).
        SaInitResult::InvalidKe { group, .. } => {
            Err(IkeError::DhGroupMismatch { expected: group, got: group })
        }
        SaInitResult::CookieRequired { .. } => Err(IkeError::NoProposalChosen),
    }
}

/// SA_INIT responder **with NAT traversal + DH-group renegotiation**: like
/// [`responder_respond`], but also emits `NAT_DETECTION_SOURCE_IP` /
/// `NAT_DETECTION_DESTINATION_IP` notifies so a native (NAT'd) client detects the
/// NAT and floats IKE + ESP to UDP 4500 (RFC 7296 §2.23), and returns an
/// [`SaInitResult::InvalidKe`] (rather than erroring) when the client guessed the
/// wrong DH group, so it can retry. `our_addr` is our address as the peer reaches
/// us; `peer_addr` is the address we observed the request coming from.
pub fn responder_respond_natt(
    request: &[u8],
    local: &LocalSecret,
    our_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
    cookie: Option<CookiePolicy>,
) -> Result<SaInitResult, IkeError> {
    responder_respond_inner(request, local, Some((our_addr, peer_addr)), cookie)
}

/// Build a bare `IKE_SA_INIT` response carrying only an `INVALID_KE_PAYLOAD`
/// notify naming the DH group we want the initiator to use.
fn build_invalid_ke(spi_i: u64, group: u16) -> Vec<u8> {
    let header = base_header(spi_i, 0, Flags { initiator: false, version: false, response: true });
    let notify = Notify::status(notify_type::INVALID_KE_PAYLOAD, group.to_be_bytes().to_vec());
    MessageBuilder::new(header).push(PayloadType::Notify, notify.to_bytes()).build()
}

fn responder_respond_inner(
    request: &[u8],
    local: &LocalSecret,
    natt: Option<(std::net::SocketAddr, std::net::SocketAddr)>,
    cookie: Option<CookiePolicy>,
) -> Result<SaInitResult, IkeError> {
    let header = IkeHeader::parse(request)?;
    let payloads = parse_sa_init(&header, &request[IkeHeader::LEN..])?;

    // Anti-DoS cookie check (RFC 7296 §2.6), BEFORE any Diffie-Hellman: a spoofed
    // source that can't receive the challenge never makes us do the expensive DH
    // or hold half-open state.
    if let Some(pol) = &cookie {
        if pol.required {
            let expected = ike_cookie(pol.secret, header.initiator_spi, &payloads.nonce.data, pol.peer);
            if payloads.cookie.as_deref() != Some(expected.as_slice()) {
                return Ok(SaInitResult::CookieRequired {
                    response: build_cookie_challenge(header.initiator_spi, &expected),
                });
            }
        }
    }

    let suite = negotiate::select(&payloads.sa).ok_or(IkeError::NoProposalChosen)?;
    let group = DhGroup::from_transform_id(suite.dh_id).ok_or(IkeError::NoProposalChosen)?;

    // The initiator sends a KE payload for its best-guess group; if we selected a
    // different one (it offered several, we support a different subset), tell it
    // to retry with ours. Real clients propose e.g. ECP groups we don't have and
    // fall back to MODP-2048 only when asked.
    if payloads.ke.dh_group != group.transform_id() {
        match natt {
            Some(_) => {
                let response = build_invalid_ke(header.initiator_spi, group.transform_id());
                return Ok(SaInitResult::InvalidKe { response, group: group.transform_id() });
            }
            None => {
                return Err(IkeError::DhGroupMismatch {
                    expected: group.transform_id(),
                    got: payloads.ke.dh_group,
                })
            }
        }
    }
    let peer_public = dh_peer(&payloads.ke, group)?;

    let our_public = group.public(&local.dh_private);
    let shared = group.shared(&local.dh_private, peer_public)?;

    let spi_i = header.initiator_spi;
    let spi_r = local.spi;
    let keys = crypto::derive_session_keys(
        &shared,
        &payloads.nonce.data, // Ni
        &local.nonce,         // Nr
        spi_i,
        spi_r,
        suite.key_lengths(),
    );

    // NAT-detection notifies (RFC 7296 §2.23): SOURCE = hash of our own address,
    // DESTINATION = hash of the peer's address as we observed it. A client behind
    // NAT sees the DESTINATION hash disagree with its local address and floats to
    // UDP 4500.
    let mut extra_notifies = Vec::new();
    if let Some((our_addr, peer_addr)) = natt {
        extra_notifies.push(natt::source_ip_notify(spi_i, spi_r, our_addr.ip(), our_addr.port()));
        extra_notifies.push(natt::destination_ip_notify(spi_i, spi_r, peer_addr.ip(), peer_addr.port()));
    }

    let response_header = base_header(spi_i, spi_r, Flags { initiator: false, version: false, response: true });
    let sar1 = SecurityAssociation { proposals: vec![suite.to_proposal()] };
    let response = build_sa_init(response_header, &sar1, suite.dh_id, &our_public, &local.nonce, &extra_notifies);

    let completed = CompletedSaInit {
        role: Role::Responder,
        spi_i,
        spi_r,
        suite,
        keys,
        ni: payloads.nonce.data.clone(),
        nr: local.nonce.clone(),
        init_message: request.to_vec(),
        resp_message: response.clone(),
        peer_signature_hashes: payloads.signature_hashes,
    };
    Ok(SaInitResult::Established { response, sa: completed })
}

/// Initiator step 2: consume the response and derive keys. `request` is the
/// bytes returned by [`initiator_request`] (retained for the AUTH payload).
pub fn initiator_complete(local: &LocalSecret, request: &[u8], response: &[u8]) -> Result<CompletedSaInit, IkeError> {
    let header = IkeHeader::parse(response)?;
    let payloads = parse_sa_init(&header, &response[IkeHeader::LEN..])?;

    // Interpret the responder's chosen proposal; it must be a suite we support.
    let suite = negotiate::select(&payloads.sa).ok_or(IkeError::NoProposalChosen)?;
    let group = DhGroup::from_transform_id(suite.dh_id).ok_or(IkeError::NoProposalChosen)?;
    let peer_public = dh_peer(&payloads.ke, group)?;
    let shared = group.shared(&local.dh_private, peer_public)?;

    let spi_i = local.spi;
    let spi_r = header.responder_spi;
    let keys = crypto::derive_session_keys(
        &shared,
        &local.nonce,         // Ni
        &payloads.nonce.data, // Nr
        spi_i,
        spi_r,
        suite.key_lengths(),
    );

    Ok(CompletedSaInit {
        role: Role::Initiator,
        spi_i,
        spi_r,
        suite,
        keys,
        ni: local.nonce.clone(),
        nr: payloads.nonce.data.clone(),
        init_message: request.to_vec(),
        resp_message: response.to_vec(),
        peer_signature_hashes: payloads.signature_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_secret() -> LocalSecret {
        LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xAAAA_AAAA_1111_2222 }
    }
    fn resp_secret() -> LocalSecret {
        LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xBBBB_BBBB_3333_4444 }
    }

    #[test]
    fn sa_init_agrees_over_modp_groups() {
        // Offer a MODP group instead of X25519; the responder must select it and
        // both sides must derive the identical SK_* set (proves the DhGroup wiring).
        for gid in [transform_id::MODP_2048, transform_id::MODP_1024] {
            let offer = SecurityAssociation {
                proposals: vec![Proposal {
                    num: 1,
                    protocol_id: protocol_id::IKE,
                    spi: Vec::new(),
                    transforms: vec![
                        Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_GCM_16, key_length: Some(256) },
                        Transform { transform_type: transform_type::PRF, transform_id: transform_id::PRF_HMAC_SHA2_256, key_length: None },
                        Transform { transform_type: transform_type::DH, transform_id: gid, key_length: None },
                    ],
                }],
            };
            let request = initiator_request(&init_secret(), &offer);
            let (response, resp_done) = responder_respond(&request, &resp_secret()).unwrap();
            let init_done = initiator_complete(&init_secret(), &request, &response).unwrap();
            assert_eq!(resp_done.suite.dh_id, gid);
            assert_eq!(init_done.keys, resp_done.keys, "group {gid}: both sides derive the same keys");
        }
    }

    #[test]
    fn sa_init_advertises_and_captures_signature_hashes() {
        // Each IKE_SA_INIT carries N(SIGNATURE_HASH_ALGORITHMS) (RFC 7427 §4), and
        // each side records what the other advertised.
        let request = initiator_request(&init_secret(), &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp_secret()).unwrap();
        let init_done = initiator_complete(&init_secret(), &request, &response).unwrap();
        assert!(resp_done.peer_signature_hashes.contains(&sighash::SHA2_256));
        assert!(init_done.peer_signature_hashes.contains(&sighash::SHA2_256));
    }

    #[test]
    fn responder_natt_emits_nat_detection_and_still_completes() {
        let request = initiator_request(&init_secret(), &default_offer());
        let our: std::net::SocketAddr = "203.0.113.9:500".parse().unwrap();
        let peer: std::net::SocketAddr = "198.51.100.7:41234".parse().unwrap();
        let response = match responder_respond_natt(&request, &resp_secret(), our, peer, None).unwrap() {
            SaInitResult::Established { response, .. } => response,
            SaInitResult::InvalidKe { .. } => panic!("matching DH group must establish, not renegotiate"),
            SaInitResult::CookieRequired { .. } => panic!("no cookie policy was passed"),
        };

        // An initiator still parses the response — the extra notifies are tolerated.
        let init_done = initiator_complete(&init_secret(), &request, &response).unwrap();
        assert_eq!(init_done.role, Role::Initiator);

        // Both NAT_DETECTION notifies are present so a NAT'd client floats to 4500.
        let hdr = crate::ikev2::message::IkeHeader::parse(&response).unwrap();
        let mut kinds = Vec::new();
        for p in crate::ikev2::message::payloads(hdr.next_payload, &response[crate::ikev2::message::IkeHeader::LEN..]) {
            let p = p.unwrap();
            if p.payload_type == crate::ikev2::message::PayloadType::Notify {
                kinds.push(Notify::parse(p.data).unwrap().notify_type);
            }
        }
        assert!(kinds.contains(&notify_type::NAT_DETECTION_SOURCE_IP));
        assert!(kinds.contains(&notify_type::NAT_DETECTION_DESTINATION_IP));

        // The plain (non-NAT-T) responder emits neither.
        let (plain, _) = responder_respond(&request, &resp_secret()).unwrap();
        let phdr = crate::ikev2::message::IkeHeader::parse(&plain).unwrap();
        for p in crate::ikev2::message::payloads(phdr.next_payload, &plain[crate::ikev2::message::IkeHeader::LEN..]) {
            let p = p.unwrap();
            if p.payload_type == crate::ikev2::message::PayloadType::Notify {
                let nt = Notify::parse(p.data).unwrap().notify_type;
                assert_ne!(nt, notify_type::NAT_DETECTION_SOURCE_IP);
                assert_ne!(nt, notify_type::NAT_DETECTION_DESTINATION_IP);
            }
        }
    }

    #[test]
    fn cookie_gate_challenges_when_required_and_passes_when_not() {
        let request = initiator_request(&init_secret(), &default_offer());
        let our: std::net::SocketAddr = "203.0.113.9:500".parse().unwrap();
        let peer: std::net::SocketAddr = "198.51.100.7:1234".parse().unwrap();
        let peer_ip = match peer.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            _ => unreachable!(),
        };

        // Required + no cookie echoed → a COOKIE challenge (no DH, no state).
        let pol = CookiePolicy { secret: b"s3cret", peer: &peer_ip, required: true };
        assert!(matches!(
            responder_respond_natt(&request, &resp_secret(), our, peer, Some(pol)).unwrap(),
            SaInitResult::CookieRequired { .. }
        ));
        // A cookie from a different secret/peer must NOT be accepted as valid —
        // still challenged (the check is against ike_cookie of THIS secret+peer).
        let other = ike_cookie(b"other", 1, b"ni", b"1.2.3.4");
        assert_ne!(other, ike_cookie(b"s3cret", 1, b"ni", &peer_ip));

        // Not required → normal establishment (gate is off under low load).
        let pol2 = CookiePolicy { secret: b"s3cret", peer: &peer_ip, required: false };
        assert!(matches!(
            responder_respond_natt(&request, &resp_secret(), our, peer, Some(pol2)).unwrap(),
            SaInitResult::Established { .. }
        ));
    }

    /// The core M1 property: run initiator ↔ responder in-process and confirm
    /// both sides independently derive the *same* SK_* set.
    #[test]
    fn initiator_and_responder_agree_on_keys() {
        let init = init_secret();
        let resp = resp_secret();

        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();

        assert_eq!(init_done.keys, resp_done.keys, "both sides must derive identical keys");
        assert!(!init_done.keys.sk_d.is_empty());
        assert_eq!(init_done.keys.sk_ei.len(), 36); // AES-256 key (32) + GCM salt (4)
        assert!(init_done.keys.sk_ai.is_empty()); // AEAD: no separate integ key

        // SPI bookkeeping is consistent from both perspectives.
        assert_eq!(init_done.spi_i, init.spi);
        assert_eq!(init_done.spi_r, resp.spi);
        assert_eq!(resp_done.spi_i, init.spi);
        assert_eq!(resp_done.spi_r, resp.spi);

        assert_eq!(init_done.suite.encr_id, transform_id::AES_GCM_16);
        assert_eq!(init_done.suite, resp_done.suite);
    }

    #[test]
    fn different_nonces_produce_different_keys() {
        let init = init_secret();
        let resp = resp_secret();
        let request = initiator_request(&init, &default_offer());
        let (_, first) = responder_respond(&request, &resp).unwrap();

        let mut resp2 = resp_secret();
        resp2.nonce = vec![0x77; 32];
        let (_, second) = responder_respond(&request, &resp2).unwrap();
        assert_ne!(first.keys, second.keys);
    }

    #[test]
    fn responder_rejects_unsupported_offer() {
        // Offer only MODP-1536 (group 5) for DH, which ryke does not implement.
        let mut offer = default_offer();
        offer.proposals[0].transforms[2] =
            Transform { transform_type: transform_type::DH, transform_id: 5, key_length: None };
        let request = initiator_request(&init_secret(), &offer);
        let err = responder_respond(&request, &resp_secret()).unwrap_err();
        assert_eq!(err, IkeError::NoProposalChosen);
    }

    #[test]
    fn responder_rejects_wrong_ke_group() {
        // SA offers X25519 (accepted) but the KE payload claims MODP-2048.
        let init = init_secret();
        // Build a request whose SA offers X25519 but whose KE claims MODP-2048.
        let public = crypto::dh::x25519_public(&init.dh_private);
        let header = base_header(init.spi, 0, Flags { initiator: true, version: false, response: false });
        let bad_ke = KeyExchange { dh_group: transform_id::MODP_2048, data: public.to_vec() };
        let request = MessageBuilder::new(header)
            .push(PayloadType::SecurityAssociation, default_offer().to_bytes())
            .push(PayloadType::KeyExchange, bad_ke.to_bytes())
            .push(PayloadType::Nonce, init.nonce.clone())
            .build();
        let err = responder_respond(&request, &resp_secret()).unwrap_err();
        assert_eq!(err, IkeError::DhGroupMismatch { expected: transform_id::X25519, got: transform_id::MODP_2048 });
    }
}
