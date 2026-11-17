//! The EAP-MSCHAPv2 authentication exchange inside `IKE_AUTH` (RFC 7296 §2.16),
//! both roles. This is the flow stock iOS/Android use.
//!
//! ```text
//! I → SK{ IDi, SAi2, TSi, TSr }                     (no AUTH: "I'll use EAP")
//! R → SK{ IDr, AUTH(psk), EAP-Req/Identity }
//! I → SK{ EAP-Resp/Identity }
//! R → SK{ EAP-Req/MSCHAPv2-Challenge }
//! I → SK{ EAP-Resp/MSCHAPv2-Response }
//! R → SK{ EAP-Req/MSCHAPv2-Success }
//! I → SK{ EAP-Resp/MSCHAPv2-Success }
//! R → SK{ EAP-Success }
//! I → SK{ AUTH(MSK) }
//! R → SK{ AUTH(MSK), SAr2, TSi, TSr }               (CHILD SA established)
//! ```
//!
//! The responder authenticates with a PSK; both final AUTH payloads key off the
//! EAP-derived MSK. This whole sequence is interop-validated against an
//! independent IKEv2 responder.

use std::collections::HashMap;

use crate::ikev2::auth::{initiator_signed_octets, psk_auth, responder_signed_octets};
use crate::ikev2::eap;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::ike_auth::{
    esp_offer, esp_spi_from_sa, initiator_eap_request, initiator_eap_request_with_certreq,
    AssignedConfig,
};
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::mschapv2;
use crate::ikev2::payload::{
    auth_method, Authentication, Certificate, Configuration, Identification,
    TrafficSelector, TrafficSelectors,
};
use crate::role::Role;
use crate::ikev2::sign::SigningKey;
use crate::ikev2::sk::{build_encrypted_gcm, open_encrypted_gcm};

/// How the server (responder) authenticates *itself* in the EAP exchange
/// (RFC 7296 §2.16 — its own AUTH, separate from the EAP/MSK exchange).
pub enum ServerAuth {
    /// Pre-shared key (RFC 7296 §2.15). Simple, but native phones want a cert.
    Psk(Vec<u8>),
    /// RFC 7427 Digital Signature with an X.509 chain (`chain[0]` = leaf, whose
    /// key signs the AUTH; the rest are intermediates, any order, no root).
    Cert { key: SigningKey, chain: Vec<Vec<u8>> },
}

/// How the client (initiator) authenticates the *server*.
pub enum ServerVerify {
    /// Do not authenticate the server. Only tolerable with a PSK server in an
    /// already-trusted setting; a real phone-style client must not use this.
    Insecure,
    /// Require the server's leaf certificate to (a) build a valid X.509 path to
    /// one of these trusted CA certificates (DER) — checking each hop's
    /// signature, validity window, and CA status — (b) carry `expected_dns` in
    /// its SubjectAltName, and (c) produce a valid RFC 7427 signature. Revocation
    /// (CRL/OCSP) and EKU are still the consumer's to add.
    TrustedCas {
        cas: Vec<Vec<u8>>,
        /// The dNSName the client intends to reach (its "remote identifier").
        expected_dns: String,
        /// Current time (Unix seconds) for certificate validity checks.
        now_unix: u64,
    },
}

/// Outcome of feeding one peer message to a state machine.
#[derive(Debug)]
pub enum EapEvent {
    /// Send this message and await the next reply.
    Reply(Vec<u8>),
    /// Handshake complete. If `Some`, send this final message first.
    Established(Option<Vec<u8>>),
    /// The peer failed authentication.
    Failed,
}

/// A decrypted message's payloads, each as `(type, raw body)`.
type Payloads = Vec<(PayloadType, Vec<u8>)>;

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

fn build_sk(sa: &CompletedSaInit, msg_id: u32, is_response: bool, inner: &[(PayloadType, Vec<u8>)], iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    // (`inner` stays a slice so callers can pass array literals.)
    let header = IkeHeader {
        initiator_spi: sa.spi_i,
        responder_spi: sa.spi_r,
        next_payload: PayloadType::NoNext,
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::IkeAuth,
        flags: Flags { initiator: sa.role == Role::Initiator, version: false, response: is_response },
        message_id: msg_id,
        length: 0,
    };
    let first = first_payload_type(inner);
    let bytes = encode_payload_chain(inner);
    build_encrypted_gcm(header, first, &bytes, our_sk_e(sa), iv)
}

/// Collect a decrypted message's payloads plus its Message ID.
fn decrypt(sa: &CompletedSaInit, message: &[u8]) -> Result<(u32, Payloads), IkeError> {
    let msg_id = IkeHeader::parse(message)?.message_id;
    let (first, inner) = open_encrypted_gcm(message, peer_sk_e(sa))?;
    let mut out = Vec::new();
    for p in payloads(first, &inner) {
        let p = p?;
        out.push((p.payload_type, p.data.to_vec()));
    }
    Ok((msg_id, out))
}

fn find(payloads: &[(PayloadType, Vec<u8>)], want: PayloadType) -> Option<&[u8]> {
    payloads.iter().find(|(t, _)| *t == want).map(|(_, d)| d.as_slice())
}

fn iv(entropy: &mut impl Entropy) -> [u8; 8] {
    let mut iv = [0u8; 8];
    entropy.fill(&mut iv);
    iv
}

/// EAP-MSCHAPv2 **initiator** (client) — the phone's role.
pub struct EapInitiator {
    sa: CompletedSaInit,
    id: Identification,
    user: Vec<u8>,
    password: String,
    child_spi: u32,
    nt_response: [u8; 24],
    verify: ServerVerify,
    server_verified: bool,
    send_certreq: bool,
}

impl EapInitiator {
    pub fn new(
        sa: CompletedSaInit,
        id: Identification,
        user: Vec<u8>,
        password: String,
        child_spi: u32,
        verify: ServerVerify,
    ) -> Self {
        EapInitiator {
            sa,
            id,
            user,
            password,
            child_spi,
            nt_response: [0u8; 24],
            verify,
            server_verified: false,
            send_certreq: false,
        }
    }

    /// Include a `CERTREQ` in the first message (mirrors a strongSwan client) —
    /// used to exercise a responder's CERTREQ-based cert selection.
    pub fn set_send_certreq(&mut self, on: bool) {
        self.send_certreq = on;
    }

    /// Authenticate the server from its first response (`SK{ IDr, [CERT,] AUTH,
    /// EAP }`): the leaf must chain to a trusted CA, vouch for the expected
    /// dNSName, and produce a valid RFC 7427 signature over the responder's
    /// signed octets. Returns `false` on any failure so the caller can abort.
    fn verify_server(&self, ps: &Payloads) -> bool {
        let (cas, expected_dns, now) = match &self.verify {
            ServerVerify::Insecure => return true,
            ServerVerify::TrustedCas { cas, expected_dns, now_unix } => (cas, expected_dns, *now_unix),
        };
        let (Some(idr), Some(auth_bytes)) =
            (find(ps, PayloadType::IdResponder), find(ps, PayloadType::Authentication))
        else {
            return false;
        };
        // Every CERT payload, in order: [0] is the leaf, the rest intermediates.
        let certs: Vec<Vec<u8>> = ps
            .iter()
            .filter(|(t, _)| *t == PayloadType::Certificate)
            .filter_map(|(_, d)| Certificate::parse(d).ok().map(|c| c.data))
            .collect();
        let Some(leaf) = certs.first() else { return false };
        let auth = match Authentication::parse(auth_bytes) {
            Ok(a) => a,
            Err(_) => return false,
        };
        if auth.method != auth_method::DIGITAL_SIGNATURE {
            return false;
        }
        let octets = responder_signed_octets(&self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, idr);
        // Path validation (chain + dates + CA) + SAN binding + signature.
        crate::ikev2::sign::verify_cert_auth(leaf, &certs[1..], cas, Some(expected_dns), now, &auth.data, &octets).is_ok()
    }

    /// First message: `SK{ IDi, SAi2, TSi, TSr }` (no AUTH — request EAP).
    pub fn start(&self, entropy: &mut impl Entropy) -> Result<Vec<u8>, IkeError> {
        if self.send_certreq {
            initiator_eap_request_with_certreq(
                &self.sa,
                &self.id,
                self.child_spi,
                vec![[0u8; 20]],
                &iv(entropy),
            )
        } else {
            initiator_eap_request(&self.sa, &self.id, self.child_spi, &iv(entropy))
        }
    }

    /// Process a responder message and produce the next step.
    pub fn handle(&mut self, message: &[u8], entropy: &mut impl Entropy) -> Result<EapEvent, IkeError> {
        let (msg_id, ps) = decrypt(&self.sa, message)?;
        let next_id = msg_id + 1;

        // The server authenticates itself in its first response (the one that
        // also carries IDr). Verify it once, before answering any EAP request —
        // so we never send our EAP credentials to an unauthenticated server.
        if !self.server_verified
            && find(&ps, PayloadType::IdResponder).is_some()
            && find(&ps, PayloadType::Authentication).is_some()
        {
            if !self.verify_server(&ps) {
                return Ok(EapEvent::Failed);
            }
            self.server_verified = true;
        }

        // Credential firewall: when we require server authentication, refuse to
        // do *anything* else until the server is verified. Otherwise a rogue peer
        // could send a first message with no IDr/AUTH (skipping verify_server) and
        // walk us through EAP, harvesting the username + a crackable MSCHAPv2
        // response. `Insecure` opts out (only for a PSK server in a trusted path).
        if matches!(self.verify, ServerVerify::TrustedCas { .. }) && !self.server_verified {
            return Ok(EapEvent::Failed);
        }

        let Some(eap_bytes) = find(&ps, PayloadType::Eap) else {
            // No EAP → the responder's final message. Key-confirm its MSK-keyed
            // AUTH (mirroring what the responder does to us); presence alone is
            // not enough — it must prove it derived the same EAP MSK.
            let (Some(auth_bytes), Some(_sa)) =
                (find(&ps, PayloadType::Authentication), find(&ps, PayloadType::SecurityAssociation))
            else {
                return Ok(EapEvent::Failed);
            };
            let idr = find(&ps, PayloadType::IdResponder).unwrap_or(&[]);
            let msk = mschapv2::derive_msk(&self.password, &self.nt_response);
            let expect = psk_auth(
                &msk,
                &responder_signed_octets(&self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, idr),
            );
            let got = Authentication::parse(auth_bytes)?;
            return Ok(if got.method == auth_method::SHARED_KEY && got.data == expect {
                EapEvent::Established(None)
            } else {
                EapEvent::Failed
            });
        };

        let eap = eap::EapPacket::parse(eap_bytes)?;
        if eap.code == eap::code::FAILURE {
            return Ok(EapEvent::Failed);
        }
        if eap.code == eap::code::SUCCESS {
            // EAP done: send AUTH keyed by the MSK.
            let msk = mschapv2::derive_msk(&self.password, &self.nt_response);
            let idi = self.id.to_bytes();
            let octets = initiator_signed_octets(&self.sa.init_message, &self.sa.nr, &self.sa.keys.sk_pi, &idi);
            let auth = Authentication { method: auth_method::SHARED_KEY, data: psk_auth(&msk, &octets) };
            let msg = build_sk(&self.sa, next_id, false, &[(PayloadType::Authentication, auth.to_bytes())], &iv(entropy))?;
            return Ok(EapEvent::Reply(msg));
        }

        // EAP Request → respond by method.
        let resp = match eap.eap_type() {
            Some(t) if t == eap::eap_type::IDENTITY => {
                let mut d = vec![eap::eap_type::IDENTITY];
                d.extend_from_slice(&self.user);
                eap::EapPacket { code: eap::code::RESPONSE, identifier: eap.identifier, data: d }
            }
            Some(t) if t == eap::eap_type::MSCHAPV2 && eap.data.get(1) == Some(&eap::op::CHALLENGE) => {
                let (mschap_id, auth_challenge, _name) = eap::parse_challenge(&eap.data)?;
                let mut peer_challenge = [0u8; 16];
                entropy.fill(&mut peer_challenge);
                self.nt_response = mschapv2::generate_nt_response(&auth_challenge, &peer_challenge, &self.user, &self.password);
                let data = eap::build_response(mschap_id, &auth_challenge, &peer_challenge, &self.user, &self.password);
                eap::EapPacket { code: eap::code::RESPONSE, identifier: eap.identifier, data }
            }
            Some(t) if t == eap::eap_type::MSCHAPV2 && eap.data.get(1) == Some(&eap::op::SUCCESS) => {
                eap::EapPacket { code: eap::code::RESPONSE, identifier: eap.identifier, data: vec![eap::eap_type::MSCHAPV2, eap::op::SUCCESS] }
            }
            _ => return Ok(EapEvent::Failed),
        };
        let msg = build_sk(&self.sa, next_id, false, &[(PayloadType::Eap, resp.to_bytes())], &iv(entropy))?;
        Ok(EapEvent::Reply(msg))
    }
}

/// EAP-MSCHAPv2 **responder** (server): authenticates itself ([`ServerAuth`]),
/// verifies the client's EAP password, then exchanges the MSK-keyed AUTHs.
pub struct EapResponder {
    sa: CompletedSaInit,
    id: Identification,
    auth: ServerAuth,
    user: Vec<u8>,
    password: String,
    /// All accepted credentials (username → password). The client's claimed EAP
    /// identity selects one at the Identity step; an unknown identity is rejected.
    users: HashMap<Vec<u8>, String>,
    child_spi: u32,
    eap_id: u8,
    auth_challenge: [u8; 16],
    nt_response: [u8; 24],
    peer_idi: Vec<u8>,
    /// The initiator's ESP SPI (from SAi2 in msg-1), needed to derive the CHILD SA.
    peer_child_spi: Option<u32>,
    /// Inner-network assignment for this client's Configuration Payload (CFG_REPLY)
    /// in the final message — so the cascade's per-client inner IP is handed out
    /// over EAP just like the PSK path.
    assigned: Option<AssignedConfig>,
}

impl EapResponder {
    pub fn new(
        sa: CompletedSaInit,
        id: Identification,
        auth: ServerAuth,
        user: Vec<u8>,
        password: String,
        child_spi: u32,
    ) -> Self {
        let users = HashMap::from([(user, password)]);
        Self::new_multi(sa, id, auth, users, child_spi)
    }

    /// Like [`new`](Self::new) but accepts multiple credentials; the client's EAP
    /// identity picks which password to verify against (an unknown one fails).
    pub fn new_multi(
        sa: CompletedSaInit,
        id: Identification,
        auth: ServerAuth,
        users: HashMap<Vec<u8>, String>,
        child_spi: u32,
    ) -> Self {
        EapResponder {
            sa,
            id,
            auth,
            user: Vec::new(),
            password: String::new(),
            users,
            child_spi,
            eap_id: 1,
            auth_challenge: [0u8; 16],
            nt_response: [0u8; 24],
            peer_idi: Vec::new(),
            peer_child_spi: None,
            assigned: None,
        }
    }

    /// Set the inner-network assignment sent in the final message's Configuration
    /// Payload (a native client needs it to configure its tunnel interface).
    pub fn set_assigned(&mut self, assigned: Option<AssignedConfig>) {
        self.assigned = assigned;
    }

    /// The initiator's ESP SPI (captured from SAi2), for deriving the CHILD SA
    /// after [`EapEvent::Established`].
    pub fn peer_child_spi(&self) -> Option<u32> {
        self.peer_child_spi
    }

    /// The credential (username) selected by the client's EAP identity. Empty
    /// until the Identity step has run; meaningful once authentication succeeds.
    pub fn user(&self) -> &[u8] {
        &self.user
    }

    pub fn handle(&mut self, message: &[u8], entropy: &mut impl Entropy) -> Result<EapEvent, IkeError> {
        let (msg_id, ps) = decrypt(&self.sa, message)?;

        // msg-1: IDi + SA + TS, no AUTH, no EAP → authenticate ourselves and
        // start EAP with an Identity request: SK{ IDr, [CERT,] AUTH, EAP }.
        if find(&ps, PayloadType::Eap).is_none() && find(&ps, PayloadType::Authentication).is_none() {
            let Some(sai2) = find(&ps, PayloadType::SecurityAssociation) else {
                return Ok(EapEvent::Failed);
            };
            // Capture the initiator's ESP SPI (for the CHILD SA) and its IDi
            // verbatim (its final AUTH signs over it).
            self.peer_child_spi = esp_spi_from_sa(sai2);
            self.peer_idi = find(&ps, PayloadType::IdInitiator).unwrap_or(&[]).to_vec();
            let idr = self.id.to_bytes();
            let octets = responder_signed_octets(&self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, &idr);

            let mut inner: Vec<(PayloadType, Vec<u8>)> = vec![(PayloadType::IdResponder, idr)];
            match &self.auth {
                ServerAuth::Psk(psk) => {
                    let auth = Authentication { method: auth_method::SHARED_KEY, data: psk_auth(psk, &octets) };
                    inner.push((PayloadType::Authentication, auth.to_bytes()));
                }
                ServerAuth::Cert { key, chain } => {
                    // Send the chain (leaf first) unconditionally — iOS often
                    // sends no CERTREQ, so gating on one would break the default.
                    for cert in chain {
                        inner.push((PayloadType::Certificate, Certificate::x509(cert.clone()).to_bytes()));
                    }
                    // Method 14 (RFC 7427) if the peer advertised SHA-256, else
                    // the classic ECDSA method 9 — a native iOS EAP client sends
                    // no SIGNATURE_HASH_ALGORITHMS, so it needs the classic form.
                    let auth = crate::ikev2::ike_auth::cert_auth_payload(
                        key,
                        &self.sa.peer_signature_hashes,
                        &octets,
                    )?;
                    inner.push((PayloadType::Authentication, auth.to_bytes()));
                }
            }
            let eap = eap::EapPacket { code: eap::code::REQUEST, identifier: self.eap_id, data: vec![eap::eap_type::IDENTITY] };
            inner.push((PayloadType::Eap, eap.to_bytes()));
            let msg = build_sk(&self.sa, msg_id, true, &inner, &iv(entropy))?;
            return Ok(EapEvent::Reply(msg));
        }

        // Final: the initiator's MSK-keyed AUTH (no EAP, has AUTH).
        if let Some(auth_bytes) = find(&ps, PayloadType::Authentication) {
            if find(&ps, PayloadType::Eap).is_none() {
                let msk = mschapv2::derive_msk(&self.password, &self.nt_response);
                let expect = psk_auth(&msk, &initiator_signed_octets(&self.sa.init_message, &self.sa.nr, &self.sa.keys.sk_pi, &self.peer_idi));
                let got = crate::ikev2::payload::Authentication::parse(auth_bytes)?;
                if got.data != expect {
                    return Ok(EapEvent::Failed);
                }
                // Send our final AUTH(MSK) + SAr2 + TSi + TSr.
                let idr = self.id.to_bytes();
                let our_auth = Authentication {
                    method: auth_method::SHARED_KEY,
                    data: psk_auth(&msk, &responder_signed_octets(&self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, &idr)),
                };
                // Assign the client its inner IP via a Configuration Payload
                // (CFG_REPLY) and narrow TSi to that /32, mirroring the PSK path,
                // so the cascade's per-client IP works over EAP too.
                let mut inner: Vec<(PayloadType, Vec<u8>)> = vec![
                    (PayloadType::IdResponder, idr),
                    (PayloadType::Authentication, our_auth.to_bytes()),
                ];
                let tsi = match &self.assigned {
                    Some(a) => {
                        let dns = a.dns.first().copied();
                        inner.push((
                            PayloadType::Configuration,
                            Configuration::reply_ipv4(a.ip, None, dns).to_bytes(),
                        ));
                        TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(a.ip)] }
                            .to_bytes()
                    }
                    None => full_tunnel_ts(),
                };
                inner.push((PayloadType::SecurityAssociation, esp_offer(self.child_spi).to_bytes()));
                inner.push((PayloadType::TrafficSelectorInitiator, tsi));
                inner.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
                // Advertise MOBIKE so the client migrates the SA across network
                // changes (Wi-Fi↔cellular / NAT rebind) via UPDATE_SA_ADDRESSES
                // instead of tearing the tunnel down and reconnecting.
                inner.push((
                    PayloadType::Notify,
                    crate::ikev2::mobike::mobike_supported().to_bytes(),
                ));
                let msg = build_sk(&self.sa, msg_id, true, &inner, &iv(entropy))?;
                return Ok(EapEvent::Established(Some(msg)));
            }
        }

        // Otherwise an EAP response drives the next step.
        let eap_bytes = find(&ps, PayloadType::Eap).ok_or(IkeError::MissingPayload("EAP"))?;
        let eap = eap::EapPacket::parse(eap_bytes)?;
        self.eap_id = self.eap_id.wrapping_add(1);

        let out = match eap.eap_type() {
            Some(t) if t == eap::eap_type::IDENTITY => {
                // The claimed identity selects this client's credentials; an
                // unknown username is rejected here, before any challenge.
                let claimed = eap.data.get(1..).unwrap_or(&[]).to_vec();
                match self.users.get(&claimed) {
                    Some(pw) => {
                        self.user = claimed;
                        self.password = pw.clone();
                    }
                    None => return Ok(EapEvent::Failed),
                }
                // Got the identity → send an MSCHAPv2 Challenge.
                entropy.fill(&mut self.auth_challenge);
                eap::build_challenge(1, &self.auth_challenge, b"ryke")
            }
            Some(t) if t == eap::eap_type::MSCHAPV2 && eap.data.get(1) == Some(&eap::op::RESPONSE) => {
                let resp = eap::parse_response(&eap.data)?;
                self.nt_response = mschapv2::generate_nt_response(&self.auth_challenge, &resp.peer_challenge, &self.user, &self.password);
                if self.nt_response != resp.nt_response {
                    return Ok(EapEvent::Failed);
                }
                let auth_resp = mschapv2::generate_authenticator_response(&self.password, &self.nt_response, &resp.peer_challenge, &self.auth_challenge, &self.user);
                eap::build_success(1, &auth_resp)
            }
            Some(t) if t == eap::eap_type::MSCHAPV2 && eap.data.get(1) == Some(&eap::op::SUCCESS) => {
                // Client acked → send EAP-Success.
                return Ok(EapEvent::Reply(build_sk(&self.sa, msg_id, true, &[(
                    PayloadType::Eap,
                    eap::EapPacket { code: eap::code::SUCCESS, identifier: eap.identifier, data: vec![] }.to_bytes(),
                )], &iv(entropy))?));
            }
            _ => return Ok(EapEvent::Failed),
        };
        let req = eap::EapPacket { code: eap::code::REQUEST, identifier: self.eap_id, data: out };
        Ok(EapEvent::Reply(build_sk(&self.sa, msg_id, true, &[(PayloadType::Eap, req.to_bytes())], &iv(entropy))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SeedEntropy;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};
    use crate::test_certs::{CA_CERT_DER, LEAF_CERT_DER, LEAF_SCALAR, RSA_KEY_PK8};

    #[derive(PartialEq, Eq, Debug)]
    enum Outcome {
        Established,
        Failed,
    }

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    /// Run the whole exchange to a terminal state, asserting the initiator and
    /// responder agree on success/failure.
    fn drive(mut initiator: EapInitiator, mut responder: EapResponder) -> Outcome {
        let mut ie = SeedEntropy::new(1);
        let mut re = SeedEntropy::new(2);
        let mut in_flight = initiator.start(&mut ie).unwrap(); // msg-1 (init → resp)
        for _round in 0..12 {
            match responder.handle(&in_flight, &mut re).unwrap() {
                EapEvent::Reply(m) => match initiator.handle(&m, &mut ie).unwrap() {
                    EapEvent::Reply(m2) => in_flight = m2,
                    EapEvent::Established(_) => return Outcome::Established,
                    EapEvent::Failed => return Outcome::Failed,
                },
                EapEvent::Established(Some(final_msg)) => {
                    // The responder is up; the initiator must accept the final message.
                    return match initiator.handle(&final_msg, &mut ie).unwrap() {
                        EapEvent::Established(None) => Outcome::Established,
                        _ => Outcome::Failed,
                    };
                }
                EapEvent::Established(None) => return Outcome::Established,
                EapEvent::Failed => return Outcome::Failed,
            }
        }
        Outcome::Failed
    }

    fn ecdsa_leaf_key() -> SigningKey {
        SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(LEAF_SCALAR).unwrap())
    }

    /// A Unix time within the leaf fixture's validity window.
    fn valid_now() -> u64 {
        crate::ikev2::sign::cert_validity(LEAF_CERT_DER).unwrap().0 + 1
    }

    /// Trust the given CAs and expect the leaf-fixture's dNSName, at a valid time.
    fn trust(cas: Vec<Vec<u8>>) -> ServerVerify {
        ServerVerify::TrustedCas { cas, expected_dns: "vpn.example.com".into(), now_unix: valid_now() }
    }

    fn cert_server() -> ServerAuth {
        ServerAuth::Cert { key: ecdsa_leaf_key(), chain: vec![LEAF_CERT_DER.to_vec()] }
    }

    #[test]
    fn full_eap_mschapv2_handshake_in_process() {
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "wrong".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), b"alice".to_vec(), "right".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed, "a wrong password must fail");
    }

    #[test]
    fn eap_with_certificate_server_auth_succeeds() {
        // The phone path: EAP-MSCHAPv2 client + an RFC 7427 cert-authenticated
        // server whose leaf chains to the CA the client trusts and matches name.
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn multi_user_selects_password_by_identity() {
        // Two provisioned users; a client authenticating as the *second* must
        // succeed — proving credentials are keyed by the client's EAP identity.
        let (init_sa, resp_sa) = sa_pair();
        let users = HashMap::from([
            (b"alice".to_vec(), "alice-pw".to_string()),
            (b"bob".to_vec(), "bob-pw".to_string()),
        ]);
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("bob"), b"bob".to_vec(), "bob-pw".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new_multi(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), users, 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn multi_user_rejects_unknown_identity() {
        let (init_sa, resp_sa) = sa_pair();
        let users = HashMap::from([(b"alice".to_vec(), "alice-pw".to_string())]);
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("mallory"), b"mallory".to_vec(), "whatever".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new_multi(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), users, 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed, "an unprovisioned identity must fail");
    }

    #[test]
    fn eap_rejects_server_cert_without_a_trust_anchor() {
        // Same valid server, but the client has no trusted CA → must not proceed
        // (and must not have sent EAP credentials to it).
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![]));
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn eap_rejects_signature_not_matching_the_presented_cert() {
        // The server presents the (CA-signed) ECDSA leaf but signs the AUTH with
        // an unrelated RSA key — the signature must not verify under the leaf's
        // public key, even though the chain checks out.
        use rsa::pkcs8::DecodePrivateKey;
        let wrong_key = SigningKey::RsaSha256(Box::new(rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap()));
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let responder = EapResponder::new(
            resp_sa, Identification::fqdn("vpn.example.com"),
            ServerAuth::Cert { key: wrong_key, chain: vec![LEAF_CERT_DER.to_vec()] },
            b"alice".to_vec(), "s3cret".into(), 0x2222,
        );
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn eap_rejects_valid_cert_for_the_wrong_name() {
        // The leaf chains to the trusted CA and its signature verifies, but its
        // SAN (vpn.example.com) is not the host the client meant to reach — a
        // valid cert for host A must not authenticate host B.
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(
            init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111,
            ServerVerify::TrustedCas { cas: vec![CA_CERT_DER.to_vec()], expected_dns: "other.example.com".into(), now_unix: valid_now() },
        );
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn eap_with_intermediate_cert_chain_succeeds() {
        // The server presents leaf + intermediate; the client trusts only the
        // root and must build the path leaf → intermediate → root.
        use crate::test_certs::{CHAIN_INT_DER, CHAIN_LEAF_DER, CHAIN_LEAF_SCALAR, CHAIN_ROOT_DER};
        let (init_sa, resp_sa) = sa_pair();
        let now = crate::ikev2::sign::cert_validity(CHAIN_LEAF_DER).unwrap().0 + 1;
        let initiator = EapInitiator::new(
            init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111,
            ServerVerify::TrustedCas { cas: vec![CHAIN_ROOT_DER.to_vec()], expected_dns: "vpn.example.com".into(), now_unix: now },
        );
        let responder = EapResponder::new(
            resp_sa, Identification::fqdn("vpn.example.com"),
            ServerAuth::Cert {
                key: SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(CHAIN_LEAF_SCALAR).unwrap()),
                chain: vec![CHAIN_LEAF_DER.to_vec(), CHAIN_INT_DER.to_vec()],
            },
            b"alice".to_vec(), "s3cret".into(), 0x2222,
        );
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn eap_rejects_expired_server_cert() {
        // A valid, correctly-named, correctly-signed cert — but the client's
        // clock is past its notAfter.
        let (init_sa, resp_sa) = sa_pair();
        let expired = crate::ikev2::sign::cert_validity(LEAF_CERT_DER).unwrap().1 + 1;
        let initiator = EapInitiator::new(
            init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111,
            ServerVerify::TrustedCas { cas: vec![CA_CERT_DER.to_vec()], expected_dns: "vpn.example.com".into(), now_unix: expired },
        );
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn cert_server_falls_back_to_classic_ecdsa_without_a_hash_offer() {
        // A native EAP client (iOS) sends no SIGNATURE_HASH_ALGORITHMS. Rather
        // than fail, the ECDSA cert server emits the classic method-9 AUTH
        // (RFC 4754), so it still interoperates.
        let (init_sa, mut resp_sa) = sa_pair();
        resp_sa.peer_signature_hashes.clear(); // client offered none
        let mut responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        // The responder now produces a reply (its cert + a method-9 AUTH), not an error.
        assert!(matches!(
            responder.handle(&msg1, &mut SeedEntropy::new(2)),
            Ok(EapEvent::Reply(_))
        ));
    }

    #[test]
    fn client_refuses_eap_before_the_server_is_authenticated() {
        // A rogue peer that completed the unauthenticated IKE_SA_INIT sends a
        // first message with ONLY an EAP-Identity request — no IDr, no AUTH —
        // trying to skip server auth. The client must abort, never disclosing
        // its username or any MSCHAPv2 response.
        let (init_sa, resp_sa) = sa_pair();
        let mut initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        // Craft the rogue SK{ EAP-Req/Identity } with the responder-side keys.
        let eap = eap::EapPacket { code: eap::code::REQUEST, identifier: 1, data: vec![eap::eap_type::IDENTITY] };
        let rogue = build_sk(&resp_sa, 1, true, &[(PayloadType::Eap, eap.to_bytes())], &[0u8; 8]).unwrap();
        let mut ie = SeedEntropy::new(1);
        assert!(matches!(initiator.handle(&rogue, &mut ie).unwrap(), EapEvent::Failed));
    }
}
