//! Encrypted phase-2 ISAKMP messages — Transaction/XAUTH, Mode-Config, Quick
//! Mode, and encrypted Informational. Each carries a leading HASH payload
//! (`HASH = prf(SKEYID_a, M-ID | <payloads after HASH>)`) and is AES-CBC
//! encrypted under SKEYID_e with per-message-id IV chaining (RFC 2409 App. B):
//! the first message of a message-id seeds its IV from `HASH(phase1_iv | M-ID)`,
//! and each subsequent message in that conversation chains from the previous
//! message's last ciphertext block.

use super::crypto1::{self, Prf, AES_BLOCK};
use super::isakmp::{self, flags, payload, IsakmpHeader, Payload};
use crate::error::IkeError;

/// Build an encrypted phase-2 message: prepend the HASH payload, encrypt under
/// `enc_key`/`iv`, and return the wire bytes plus the next IV (last ciphertext
/// block) for chaining the following message of the same message-id.
pub fn build_encrypted(
    header: IsakmpHeader,
    prf: Prf,
    skeyid_a: &[u8],
    enc_key: &[u8],
    iv: &[u8],
    payloads_after_hash: &[(u8, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    build_encrypted_prefixed(header, prf, skeyid_a, enc_key, iv, &[], payloads_after_hash)
}

/// Like [`build_encrypted`] but the HASH also covers `hash_prefix` immediately
/// after the message-id — Quick Mode HASH(2) prefixes the initiator nonce Ni_b:
/// `HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr | …)`.
pub fn build_encrypted_prefixed(
    mut header: IsakmpHeader,
    prf: Prf,
    skeyid_a: &[u8],
    enc_key: &[u8],
    iv: &[u8],
    hash_prefix: &[u8],
    payloads_after_hash: &[(u8, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    // HASH covers M-ID | hash_prefix | (payloads after HASH, canonically encoded).
    let (_first, after_body) = isakmp::encode_payloads(payloads_after_hash);
    let mut hi = header.message_id.to_be_bytes().to_vec();
    hi.extend_from_slice(hash_prefix);
    hi.extend_from_slice(&after_body);
    let hash = prf.mac(skeyid_a, &hi);

    // Full plaintext = HASH || payloads-after-hash.
    let mut all: Vec<(u8, Vec<u8>)> = vec![(payload::HASH, hash)];
    all.extend_from_slice(payloads_after_hash);
    let (first, plaintext) = isakmp::encode_payloads(&all);

    let padded = crypto1::pad_to_block(&plaintext, AES_BLOCK);
    let ct = crypto1::aes256_cbc_encrypt(enc_key, iv, &padded)?;
    let next = crypto1::next_iv(&ct, AES_BLOCK);

    header.next_payload = first;
    header.flags |= flags::ENCRYPTION;
    header.length = (IsakmpHeader::LEN + ct.len()) as u32;
    let mut msg = header.to_bytes();
    msg.extend_from_slice(&ct);
    Ok((msg, next))
}

/// Encrypt an explicit payload list as-is (no HASH is computed or prepended).
/// The caller supplies every payload, including any HASH — used for Quick Mode
/// message 3, whose only payload is `HASH(3) = prf(SKEYID_a, 0 | Ni_b | Nr_b)`.
pub fn encrypt_payloads(
    mut header: IsakmpHeader,
    enc_key: &[u8],
    iv: &[u8],
    payloads: &[(u8, Vec<u8>)],
) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    let (first, plaintext) = isakmp::encode_payloads(payloads);
    let padded = crypto1::pad_to_block(&plaintext, AES_BLOCK);
    let ct = crypto1::aes256_cbc_encrypt(enc_key, iv, &padded)?;
    let next = crypto1::next_iv(&ct, AES_BLOCK);
    header.next_payload = first;
    header.flags |= flags::ENCRYPTION;
    header.length = (IsakmpHeader::LEN + ct.len()) as u32;
    let mut msg = header.to_bytes();
    msg.extend_from_slice(&ct);
    Ok((msg, next))
}

/// Decrypt and parse an encrypted phase-2 message WITHOUT verifying the HASH.
/// The caller verifies (e.g. Quick Mode HASH(3) = `prf(SKEYID_a, 0 | Ni_b | Nr_b)`,
/// which does not fit the generic `M-ID | payloads` form). Returns the header,
/// all payloads, and the next IV for chaining.
pub fn decrypt_payloads(
    data: &[u8],
    enc_key: &[u8],
    iv: &[u8],
) -> Result<(IsakmpHeader, Vec<Payload>, Vec<u8>), IkeError> {
    let header = IsakmpHeader::parse(data)?;
    let ct = &data[IsakmpHeader::LEN..];
    let plaintext = crypto1::aes256_cbc_decrypt(enc_key, iv, ct)?;
    let next = crypto1::next_iv(ct, AES_BLOCK);
    let payloads = isakmp::parse_payloads(header.next_payload, &plaintext)?;
    Ok((header, payloads, next))
}

/// Decrypt and parse an encrypted phase-2 message, verifying its HASH.
/// Returns the header, all payloads (HASH first), and the next IV for chaining.
pub fn parse_encrypted(
    data: &[u8],
    prf: Prf,
    skeyid_a: &[u8],
    enc_key: &[u8],
    iv: &[u8],
) -> Result<(IsakmpHeader, Vec<Payload>, Vec<u8>), IkeError> {
    let header = IsakmpHeader::parse(data)?;
    let ct = &data[IsakmpHeader::LEN..];
    let plaintext = crypto1::aes256_cbc_decrypt(enc_key, iv, ct)?;
    let next = crypto1::next_iv(ct, AES_BLOCK);
    let payloads = isakmp::parse_payloads(header.next_payload, &plaintext)?;

    let hash_p = payloads
        .iter()
        .find(|p| p.payload_type == payload::HASH)
        .ok_or(IkeError::MissingPayload("HASH"))?;
    let after: Vec<(u8, Vec<u8>)> = payloads
        .iter()
        .filter(|p| p.payload_type != payload::HASH)
        .map(|p| (p.payload_type, p.data.clone()))
        .collect();
    let (_f, after_body) = isakmp::encode_payloads(&after);
    let mut hi = header.message_id.to_be_bytes().to_vec();
    hi.extend_from_slice(&after_body);
    if hash_p.data != prf.mac(skeyid_a, &hi) {
        return Err(IkeError::AuthFailed);
    }
    Ok((header, payloads, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::isakmp::exchange;

    #[test]
    fn encrypted_roundtrip_verifies_hash() {
        let prf = Prf::Sha256;
        let skeyid_a = [0x11u8; 32];
        let enc_key = [0x22u8; 32];
        let iv = [0x33u8; AES_BLOCK];
        let hdr = IsakmpHeader {
            init_cookie: [1; 8],
            resp_cookie: [2; 8],
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::TRANSACTION,
            flags: 0,
            message_id: 0xDEADBEEF,
            length: 0,
        };
        let attr = vec![(payload::ATTRIBUTE, vec![1u8, 0, 0, 0, 0x80, 0x11, 0, 1])];
        let (msg, _next) = build_encrypted(hdr, prf, &skeyid_a, &enc_key, &iv, &attr).unwrap();

        let (h2, payloads, _n2) = parse_encrypted(&msg, prf, &skeyid_a, &enc_key, &iv).unwrap();
        assert_eq!(h2.message_id, 0xDEADBEEF);
        assert!(h2.flags & flags::ENCRYPTION != 0);
        assert_eq!(payloads[0].payload_type, payload::HASH);
        assert_eq!(payloads[1].payload_type, payload::ATTRIBUTE);
        assert_eq!(payloads[1].data, attr[0].1);

        // A wrong key must fail the HASH check.
        let bad = [0x99u8; 32];
        assert!(parse_encrypted(&msg, prf, &bad, &enc_key, &iv).is_err());
    }
}
