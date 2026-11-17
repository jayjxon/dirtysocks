//! RFC 7427 "Signature Authentication in IKEv2" (Auth Method 14) plus the X.509
//! plumbing native iOS/Android clients use to authenticate the ryke **server**
//! by certificate. (The client still authenticates via EAP-MSCHAPv2.)
//!
//! The method-14 AUTH payload *Data* (the bytes after the 4-byte method+RESERVED
//! header handled by [`crate::ikev2::payload::Authentication`]) is:
//!
//! ```text
//! [1 octet ASN.1 length L] [ L octets: DER AlgorithmIdentifier ] [ signature value ]
//! ```
//!
//! The signature is computed over the exact RFC 7296 §2.15 octets
//! ([`crate::ikev2::auth::responder_signed_octets`] etc.) — method 14 only swaps the
//! final PSK `prf` for a real public-key signature over those same octets.
//!
//! Supported schemes: `sha256WithRSAEncryption` (RSA PKCS#1 v1.5, sign+verify),
//! `ecdsa-with-SHA256` on P-256 (sign+verify, DER `SEQUENCE{r,s}` on the wire),
//! and RSASSA-PSS/SHA-256 (verify only — we accept it from a peer but emit the
//! two widely-interoperable schemes).

use crate::error::IkeError;
use sha2::{Digest, Sha256};

/// DER-encoded `AlgorithmIdentifier`s (RFC 7427 §3 / RFC 5758 / RFC 4055).
pub mod sig_alg {
    /// `sha256WithRSAEncryption`, OID 1.2.840.113549.1.1.11 (SEQUENCE{OID, NULL}).
    pub const RSA_SHA256: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];
    /// `ecdsa-with-SHA256`, OID 1.2.840.10045.4.3.2 (no parameters, per RFC 5758).
    pub const ECDSA_P256_SHA256: &[u8] =
        &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// RSASSA-PSS / SHA-256 / MGF1-SHA256 / salt 32, OID 1.2.840.113549.1.1.10.
    /// Always the explicit 65-byte form — the short "default parameters" form
    /// means SHA-1 and would fail SHA-256 verification.
    pub const RSA_PSS_SHA256: &[u8] = &[
        0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, // rsassaPss
        0x30, 0x34, // parameters SEQUENCE
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, // [0] hashAlgorithm sha256 + NULL
        0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x08, // [1] maskGenAlgorithm mgf1
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, //     with sha256 + NULL
        0xa2, 0x03, 0x02, 0x01, 0x20, // [2] saltLength 32
    ];
}

// X.509 / PKIX algorithm OIDs (dotted form), matched against certificate fields.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    RsaPkcs1Sha256,
    RsaPssSha256,
    EcdsaP256Sha256,
}

fn scheme_of(alg: &[u8]) -> Option<Scheme> {
    if alg == sig_alg::RSA_SHA256 {
        Some(Scheme::RsaPkcs1Sha256)
    } else if alg == sig_alg::RSA_PSS_SHA256 {
        Some(Scheme::RsaPssSha256)
    } else if alg == sig_alg::ECDSA_P256_SHA256 {
        Some(Scheme::EcdsaP256Sha256)
    } else {
        None
    }
}

/// Wrap a DER AlgorithmIdentifier + raw signature into method-14 AUTH Data.
fn wrap_auth_data(alg: &[u8], sig: &[u8]) -> Vec<u8> {
    debug_assert!(alg.len() < 256, "AlgorithmIdentifier must fit a 1-octet length");
    let mut data = Vec::with_capacity(1 + alg.len() + sig.len());
    data.push(alg.len() as u8);
    data.extend_from_slice(alg);
    data.extend_from_slice(sig);
    data
}

/// Split method-14 AUTH Data into its `(DER AlgorithmIdentifier, signature)`.
pub fn parse_auth_data(data: &[u8]) -> Result<(&[u8], &[u8]), IkeError> {
    let l = *data.first().ok_or(IkeError::Truncated { need: 1, have: 0 })? as usize;
    let end = 1 + l;
    if data.len() < end {
        return Err(IkeError::Truncated { need: end, have: data.len() });
    }
    Ok((&data[1..end], &data[end..]))
}

/// A server private key that produces RFC 7427 Digital Signatures over the
/// `IKE_AUTH` signed octets.
pub enum SigningKey {
    /// RSA, PKCS#1 v1.5 padding, SHA-256 (`sha256WithRSAEncryption`). Boxed
    /// because an `RsaPrivateKey` dwarfs the other variant.
    RsaSha256(Box<rsa::RsaPrivateKey>),
    /// ECDSA on P-256 with SHA-256 (deterministic, RFC 6979).
    EcdsaP256(p256::ecdsa::SigningKey),
}

impl SigningKey {
    /// Load an ECDSA P-256 signing key from a PKCS#8 DER document — the form a
    /// server certificate's private key is generated in (`openssl pkcs8 …`).
    pub fn ecdsa_p256_from_pkcs8_der(der: &[u8]) -> Result<Self, IkeError> {
        use p256::pkcs8::DecodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(der)
            .map_err(|_| IkeError::Crypto("bad EC PKCS#8 DER private key"))?;
        Ok(SigningKey::EcdsaP256(key))
    }

    /// The DER `AlgorithmIdentifier` this key advertises in the AUTH payload.
    pub fn algorithm_id(&self) -> &'static [u8] {
        match self {
            SigningKey::RsaSha256(_) => sig_alg::RSA_SHA256,
            SigningKey::EcdsaP256(_) => sig_alg::ECDSA_P256_SHA256,
        }
    }

    /// Sign the §2.15 `signed_octets`, returning the full method-14 AUTH Data
    /// (`[len][DER alg][signature]`).
    pub fn sign_auth_data(&self, signed_octets: &[u8]) -> Result<Vec<u8>, IkeError> {
        let digest = Sha256::digest(signed_octets);
        let sig = match self {
            SigningKey::RsaSha256(key) => key
                .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
                .map_err(|_| IkeError::Crypto("RSA signing failed"))?,
            SigningKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| IkeError::Crypto("ECDSA signing failed"))?;
                // RFC 7427 puts the ASN.1 DER SEQUENCE{r,s} on the wire, not r||s.
                sig.to_der().as_bytes().to_vec()
            }
        };
        Ok(wrap_auth_data(self.algorithm_id(), &sig))
    }

    /// Sign as the classic IKEv2 method-9 AUTH (ECDSA-256, RFC 4754): the raw
    /// `r || s` (64 bytes for P-256) over `SHA-256(octets)`, with no RFC 7427
    /// algorithm wrapper. Used when the peer does not negotiate Digital
    /// Signature (a native EAP client that sends no SIGNATURE_HASH_ALGORITHMS).
    pub fn sign_ecdsa_p256_raw(&self, signed_octets: &[u8]) -> Result<Vec<u8>, IkeError> {
        match self {
            SigningKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let digest = Sha256::digest(signed_octets);
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| IkeError::Crypto("ECDSA signing failed"))?;
                Ok(sig.to_bytes().to_vec())
            }
            SigningKey::RsaSha256(_) => Err(IkeError::Crypto("method 9 needs an ECDSA P-256 key")),
        }
    }
}

/// A public key that verifies RFC 7427 Digital Signatures.
pub enum VerifyingKey {
    Rsa(rsa::RsaPublicKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    /// Extract the public key from a DER-encoded X.509 leaf certificate.
    pub fn from_cert_der(cert_der: &[u8]) -> Result<VerifyingKey, IkeError> {
        use der::{Decode, Encode};
        let cert = x509_cert::Certificate::from_der(cert_der)
            .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let spki_der = spki.to_der().map_err(|_| IkeError::Crypto("malformed SPKI"))?;
        Self::from_spki_der(&spki_der, &spki.algorithm.oid.to_string())
    }

    fn from_spki_der(spki_der: &[u8], alg_oid: &str) -> Result<VerifyingKey, IkeError> {
        match alg_oid {
            OID_RSA_ENCRYPTION => {
                use rsa::pkcs8::DecodePublicKey;
                Ok(VerifyingKey::Rsa(
                    rsa::RsaPublicKey::from_public_key_der(spki_der)
                        .map_err(|_| IkeError::Crypto("malformed RSA public key"))?,
                ))
            }
            OID_EC_PUBLIC_KEY => {
                use p256::pkcs8::DecodePublicKey;
                // from_public_key_der rejects any curve other than P-256.
                Ok(VerifyingKey::EcdsaP256(
                    p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                        .map_err(|_| IkeError::Crypto("unsupported EC curve (need P-256)"))?,
                ))
            }
            _ => Err(IkeError::Crypto("unsupported certificate key algorithm")),
        }
    }

    /// Verify method-14 AUTH Data against the §2.15 `signed_octets`.
    pub fn verify_auth_data(&self, auth_data: &[u8], signed_octets: &[u8]) -> Result<(), IkeError> {
        let (alg, sig) = parse_auth_data(auth_data)?;
        let scheme = scheme_of(alg).ok_or(IkeError::Crypto("unsupported signature algorithm"))?;
        let digest = Sha256::digest(signed_octets);
        match (self, scheme) {
            (VerifyingKey::Rsa(pk), Scheme::RsaPkcs1Sha256) => pk
                .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
                .map_err(|_| IkeError::AuthFailed),
            (VerifyingKey::Rsa(pk), Scheme::RsaPssSha256) => pk
                .verify(rsa::Pss::new::<Sha256>(), &digest, sig)
                .map_err(|_| IkeError::AuthFailed),
            (VerifyingKey::EcdsaP256(vk), Scheme::EcdsaP256Sha256) => {
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                let sig =
                    p256::ecdsa::Signature::from_der(sig).map_err(|_| IkeError::AuthFailed)?;
                vk.verify_prehash(&digest, &sig).map_err(|_| IkeError::AuthFailed)
            }
            _ => Err(IkeError::Crypto("signature algorithm does not match certificate key")),
        }
    }
}

/// Verify that `leaf_der`'s `TBSCertificate` was signed by the key in
/// `issuer_der` — one hop of an X.509 chain.
///
/// This checks only the cryptographic signature. It deliberately does **not**
/// validate notBefore/notAfter, subject/issuer name chaining, BasicConstraints,
/// key usage, or revocation; a consumer needing full RFC 5280 path validation
/// must layer that on top (see the crate docs).
pub fn verify_cert_signed_by(leaf_der: &[u8], issuer_der: &[u8]) -> Result<(), IkeError> {
    use der::{Decode, Encode};
    let leaf = x509_cert::Certificate::from_der(leaf_der)
        .map_err(|_| IkeError::Crypto("malformed leaf certificate"))?;
    let issuer_key = VerifyingKey::from_cert_der(issuer_der)?;
    let tbs = leaf.tbs_certificate.to_der().map_err(|_| IkeError::Crypto("malformed TBS"))?;
    let sig = leaf.signature.as_bytes().ok_or(IkeError::Crypto("unaligned cert signature"))?;
    let alg_oid = leaf.signature_algorithm.oid.to_string();
    let digest = Sha256::digest(&tbs);
    match (&issuer_key, alg_oid.as_str()) {
        (VerifyingKey::Rsa(pk), OID_SHA256_WITH_RSA) => pk
            .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
            .map_err(|_| IkeError::AuthFailed),
        (VerifyingKey::EcdsaP256(vk), OID_ECDSA_WITH_SHA256) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| IkeError::AuthFailed)?;
            vk.verify_prehash(&digest, &s).map_err(|_| IkeError::AuthFailed)
        }
        _ => Err(IkeError::Crypto("unsupported certificate signature algorithm")),
    }
}

/// Whether the certificate's `SubjectAltName` contains `name` as a dNSName
/// (exact, ASCII-case-insensitive; wildcards are not expanded). Modern
/// iOS/Android bind the server identity this way — a valid cert for one host
/// must not authenticate another, so callers doing cert auth must check this.
pub fn cert_has_dns_name(cert_der: &[u8], name: &str) -> Result<bool, IkeError> {
    use der::Decode;
    use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let Some(exts) = &cert.tbs_certificate.extensions else { return Ok(false) };
    for ext in exts.iter() {
        // id-ce-subjectAltName (2.5.29.17).
        if ext.extn_id.to_string() != "2.5.29.17" {
            continue;
        }
        let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
            .map_err(|_| IkeError::Crypto("malformed SubjectAltName"))?;
        for gn in san.0.iter() {
            if let GeneralName::DnsName(dns) = gn {
                if dns.as_str().eq_ignore_ascii_case(name) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// A certificate's `(notBefore, notAfter)` as Unix seconds.
pub fn cert_validity(cert_der: &[u8]) -> Result<(u64, u64), IkeError> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let v = &cert.tbs_certificate.validity;
    Ok((v.not_before.to_unix_duration().as_secs(), v.not_after.to_unix_duration().as_secs()))
}

/// Whether a certificate asserts `BasicConstraints` with `CA:TRUE`.
pub fn cert_is_ca(cert_der: &[u8]) -> Result<bool, IkeError> {
    use der::Decode;
    use x509_cert::ext::pkix::BasicConstraints;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let Some(exts) = &cert.tbs_certificate.extensions else { return Ok(false) };
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                .map_err(|_| IkeError::Crypto("malformed BasicConstraints"))?;
            return Ok(bc.ca);
        }
    }
    Ok(false)
}

/// DER of a certificate's subject / issuer distinguished name (for chaining).
fn subject_dn(cert_der: &[u8]) -> Result<Vec<u8>, IkeError> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    cert.tbs_certificate.subject.to_der().map_err(|_| IkeError::Crypto("bad subject DN"))
}
fn issuer_dn(cert_der: &[u8]) -> Result<Vec<u8>, IkeError> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    cert.tbs_certificate.issuer.to_der().map_err(|_| IkeError::Crypto("bad issuer DN"))
}

fn within_validity(cert_der: &[u8], now_unix: u64) -> Result<(), IkeError> {
    let (not_before, not_after) = cert_validity(cert_der)?;
    if now_unix < not_before || now_unix > not_after {
        return Err(IkeError::AuthFailed);
    }
    Ok(())
}

/// Build and validate an X.509 path from `leaf_der` up to one of `anchors`,
/// using `intermediates` (leaf and each intermediate must be within their
/// validity window at `now_unix`; each non-anchor issuer must be a CA). This is
/// signature + validity + BasicConstraints(CA) validation. It does **not** check
/// `pathLenConstraint`, name constraints, key usage / EKU, or revocation
/// (CRL/OCSP) — the last needs network access a library cannot assume. (Every
/// cert on the path is still a real CA whose signature chains to the anchor, so
/// an unenforced path length introduces no untrusted key.)
pub fn validate_chain(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    now_unix: u64,
) -> Result<(), IkeError> {
    let mut current = leaf_der.to_vec();
    // At most one hop per intermediate, plus the final hop to an anchor.
    for _ in 0..=intermediates.len() {
        within_validity(&current, now_unix)?;
        let want_issuer = issuer_dn(&current)?;

        // Reaching a trust anchor that issued `current` terminates the path.
        for anchor in anchors {
            if subject_dn(anchor)? == want_issuer && verify_cert_signed_by(&current, anchor).is_ok() {
                return Ok(());
            }
        }
        // Otherwise step up through an intermediate CA that issued `current`.
        let next = intermediates.iter().find(|inter| {
            subject_dn(inter).ok().as_deref() == Some(&want_issuer)
                && matches!(cert_is_ca(inter), Ok(true))
                && verify_cert_signed_by(&current, inter).is_ok()
        });
        match next {
            Some(inter) => current = inter.clone(),
            None => return Err(IkeError::AuthFailed),
        }
    }
    Err(IkeError::AuthFailed)
}

/// The full peer-certificate check for RFC 7427 auth: the leaf must be trusted
/// (pinned exactly in `trusted`, or chain to one of the trusted anchors through
/// `intermediates`), be within validity, vouch for `expected_dns` if given, and
/// carry a signature over `signed_octets` that verifies under its key.
#[allow(clippy::too_many_arguments)]
pub fn verify_cert_auth(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    trusted: &[Vec<u8>],
    expected_dns: Option<&str>,
    now_unix: u64,
    auth_data: &[u8],
    signed_octets: &[u8],
) -> Result<(), IkeError> {
    // Trust: exact pin, or a validated path to an anchor.
    if trusted.iter().any(|t| t.as_slice() == leaf_der) {
        within_validity(leaf_der, now_unix)?;
    } else {
        validate_chain(leaf_der, intermediates, trusted, now_unix)?;
    }
    // Identity binding.
    if let Some(name) = expected_dns {
        if !matches!(cert_has_dns_name(leaf_der, name), Ok(true)) {
            return Err(IkeError::AuthFailed);
        }
    }
    // The AUTH signature must verify under the leaf's key.
    VerifyingKey::from_cert_der(leaf_der)?.verify_auth_data(auth_data, signed_octets)
}

/// The SHA-1 of a certificate's DER `SubjectPublicKeyInfo` — the trust-anchor
/// identifier concatenated in a CERTREQ payload (RFC 7296 §3.7). Note this
/// hashes the whole SPKI SEQUENCE, not just the key bits.
pub fn ca_key_hash(cert_der: &[u8]) -> Result<[u8; 20], IkeError> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| IkeError::Crypto("malformed SPKI"))?;
    Ok(sha1::Sha1::digest(&spki_der).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_certs::{CA_CERT_DER, LEAF_CERT_DER, LEAF_SCALAR, RSA_KEY_PK8};

    fn ecdsa_leaf_signer() -> SigningKey {
        SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(LEAF_SCALAR).unwrap())
    }

    fn rsa_signer() -> (SigningKey, VerifyingKey) {
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap();
        let pubk = key.to_public_key();
        (SigningKey::RsaSha256(Box::new(key)), VerifyingKey::Rsa(pubk))
    }

    #[test]
    fn algorithm_identifier_lengths_match_the_der() {
        assert_eq!(sig_alg::RSA_SHA256.len(), 15);
        assert_eq!(sig_alg::ECDSA_P256_SHA256.len(), 12);
        // Full DER SEQUENCE: 0x30 0x41 (2) + 65 content octets = 67.
        assert_eq!(sig_alg::RSA_PSS_SHA256.len(), 67);
        assert_eq!(sig_alg::RSA_PSS_SHA256[1], 0x41); // inner content length
    }

    #[test]
    fn ecdsa_sign_verify_roundtrip_via_certificate_key() {
        let signer = ecdsa_leaf_signer();
        let octets = b"ResponderSignedOctets: msgR | Ni | prf(SK_pr, IDr)";
        let auth = signer.sign_auth_data(octets).unwrap();
        // The AUTH data carries the ecdsa-with-SHA256 AlgorithmIdentifier.
        let (alg, _sig) = parse_auth_data(&auth).unwrap();
        assert_eq!(alg, sig_alg::ECDSA_P256_SHA256);
        // The public key recovered from the leaf CERT verifies it.
        let vk = VerifyingKey::from_cert_der(LEAF_CERT_DER).unwrap();
        vk.verify_auth_data(&auth, octets).unwrap();
        // Tampered octets fail.
        assert!(vk.verify_auth_data(&auth, b"different octets").is_err());
        // A single flipped signature byte fails.
        let mut bad = auth.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(vk.verify_auth_data(&bad, octets).is_err());
    }

    #[test]
    fn rsa_pkcs1v15_sign_verify_roundtrip() {
        let (signer, verifier) = rsa_signer();
        assert_eq!(signer.algorithm_id(), sig_alg::RSA_SHA256);
        let octets = b"InitiatorSignedOctets under RSA";
        let auth = signer.sign_auth_data(octets).unwrap();
        verifier.verify_auth_data(&auth, octets).unwrap();
        assert!(verifier.verify_auth_data(&auth, b"tampered").is_err());
    }

    #[test]
    fn key_and_scheme_must_agree() {
        // An RSA signature presented for verification by an ECDSA cert key fails
        // cleanly rather than misverifying.
        let (rsa_signer, _rsa_vk) = rsa_signer();
        let octets = b"octets";
        let rsa_auth = rsa_signer.sign_auth_data(octets).unwrap();
        let ec_vk = VerifyingKey::from_cert_der(LEAF_CERT_DER).unwrap();
        assert!(ec_vk.verify_auth_data(&rsa_auth, octets).is_err());
    }

    #[test]
    fn chain_verification_accepts_real_issuer_and_rejects_others() {
        // The leaf really was signed by the CA.
        verify_cert_signed_by(LEAF_CERT_DER, CA_CERT_DER).unwrap();
        // The leaf was not signed by itself.
        assert!(verify_cert_signed_by(LEAF_CERT_DER, LEAF_CERT_DER).is_err());
        // The CA is self-signed (sanity: it verifies under its own key).
        verify_cert_signed_by(CA_CERT_DER, CA_CERT_DER).unwrap();
    }

    #[test]
    fn ca_key_hash_is_20_bytes_and_stable() {
        let h1 = ca_key_hash(CA_CERT_DER).unwrap();
        let h2 = ca_key_hash(CA_CERT_DER).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 20);
        // Leaf and CA have different keys → different hashes.
        assert_ne!(ca_key_hash(LEAF_CERT_DER).unwrap(), h1);
    }

    #[test]
    fn parse_auth_data_rejects_truncation() {
        assert!(parse_auth_data(&[]).is_err());
        assert!(parse_auth_data(&[0x0c, 0x30, 0x0a]).is_err()); // claims 12, has 2
    }

    #[test]
    fn chain_building_dates_and_basic_constraints() {
        use crate::test_certs::{CHAIN_INT_DER, CHAIN_LEAF_DER, CHAIN_ROOT_DER};
        let (nb, na) = cert_validity(CHAIN_LEAF_DER).unwrap();
        let now = nb + 1;

        // Full path leaf -> intermediate -> root validates.
        validate_chain(CHAIN_LEAF_DER, &[CHAIN_INT_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], now).unwrap();
        // Missing the intermediate → no path to the anchor.
        assert!(validate_chain(CHAIN_LEAF_DER, &[], &[CHAIN_ROOT_DER.to_vec()], now).is_err());
        // Trusting the intermediate directly (as an anchor) also validates.
        validate_chain(CHAIN_LEAF_DER, &[], &[CHAIN_INT_DER.to_vec()], now).unwrap();
        // Expired / not-yet-valid are rejected.
        assert!(validate_chain(CHAIN_LEAF_DER, &[CHAIN_INT_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], na + 1).is_err());
        assert!(validate_chain(CHAIN_LEAF_DER, &[CHAIN_INT_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], nb - 1).is_err());
        // The intermediate is a CA; the leaf is not.
        assert!(cert_is_ca(CHAIN_INT_DER).unwrap());
        assert!(!cert_is_ca(CHAIN_LEAF_DER).unwrap());
        // A non-CA cannot act as an intermediate issuer.
        assert!(validate_chain(CHAIN_LEAF_DER, &[CHAIN_LEAF_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], now).is_err());
    }

    #[test]
    fn direct_leaf_to_anchor_still_validates() {
        // The simple two-cert fixtures: leaf issued straight off the CA anchor.
        let (nb, _na) = cert_validity(LEAF_CERT_DER).unwrap();
        validate_chain(LEAF_CERT_DER, &[], &[CA_CERT_DER.to_vec()], nb + 1).unwrap();
    }

    #[test]
    fn san_dns_name_matching() {
        // The leaf fixture has SAN dNSName=vpn.example.com.
        assert!(cert_has_dns_name(LEAF_CERT_DER, "vpn.example.com").unwrap());
        assert!(cert_has_dns_name(LEAF_CERT_DER, "VPN.Example.COM").unwrap()); // case-insensitive
        assert!(!cert_has_dns_name(LEAF_CERT_DER, "evil.example.com").unwrap());
        assert!(!cert_has_dns_name(LEAF_CERT_DER, "example.com").unwrap()); // no suffix match
        // The CA fixture has no SAN.
        assert!(!cert_has_dns_name(CA_CERT_DER, "vpn.example.com").unwrap());
    }
}
