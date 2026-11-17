//! The Encrypted (`SK{}`) payload for AES-GCM (RFC 7296 §3.14, RFC 5282).
//!
//! From `IKE_AUTH` onward, every payload travels inside an SK payload —
//! encrypted and authenticated under the keys derived in `IKE_SA_INIT`. We
//! implement the AEAD construction for AES-256-GCM-16:
//!
//! - `SK_e{i,r}` is **36 bytes**: a 32-byte AES-256 key ‖ a 4-byte salt.
//! - The GCM nonce (12 bytes) = salt (4) ‖ explicit IV (8, sent in the payload).
//! - Associated Data = the IKE header ‖ the SK generic payload header — i.e.
//!   everything before the IV (RFC 5282 §5.1).
//! - SK body on the wire = IV(8) ‖ ciphertext ‖ ICV/tag(16).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::IkeError;
use crate::ikev2::message::{IkeHeader, PayloadType};

const IV_LEN: usize = 8;
const ICV_LEN: usize = 16;
const SALT_LEN: usize = 4;
const AES256_KEY_LEN: usize = 32;

/// Split a 36-byte `SK_e` into (32-byte AES key, 4-byte salt).
fn split_key(sk_e: &[u8]) -> Result<(&[u8], &[u8]), IkeError> {
    if sk_e.len() != AES256_KEY_LEN + SALT_LEN {
        return Err(IkeError::Crypto(
            "SK_e must be 36 bytes (32-byte AES-256 key + 4-byte GCM salt)",
        ));
    }
    Ok((&sk_e[..AES256_KEY_LEN], &sk_e[AES256_KEY_LEN..]))
}

fn gcm_nonce(salt: &[u8], iv: &[u8; IV_LEN]) -> [u8; SALT_LEN + IV_LEN] {
    let mut nonce = [0u8; SALT_LEN + IV_LEN];
    nonce[..SALT_LEN].copy_from_slice(salt);
    nonce[SALT_LEN..].copy_from_slice(iv);
    nonce
}

/// Low-level AES-256-GCM seal → ciphertext‖tag. Shared by the SK payload and by
/// SKF fragments ([`crate::ikev2::fragment`]).
pub(crate) fn gcm_seal(sk_e: &[u8], iv: &[u8; IV_LEN], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    let (key, salt) = split_key(sk_e)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| IkeError::Crypto("bad AES-256 key length"))?;
    cipher
        .encrypt(Nonce::from_slice(&gcm_nonce(salt, iv)), Payload { msg: plaintext, aad })
        .map_err(|_| IkeError::Crypto("GCM encryption failed"))
}

/// Low-level AES-256-GCM open (verifies the tag) → plaintext.
pub(crate) fn gcm_open(sk_e: &[u8], iv: &[u8; IV_LEN], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>, IkeError> {
    let (key, salt) = split_key(sk_e)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| IkeError::Crypto("bad AES-256 key length"))?;
    cipher
        .decrypt(Nonce::from_slice(&gcm_nonce(salt, iv)), Payload { msg: ct_and_tag, aad })
        .map_err(|_| IkeError::BadIntegrity)
}

/// Build a complete encrypted IKEv2 message: IKE header + an SK payload wrapping
/// `inner` (an already-serialized inner payload chain). `first_inner` is the SK
/// payload's Next Payload (the type of the first inner payload). `sk_e` is the
/// 36-byte AES-GCM key material for our direction; `iv` must be a fresh, unique
/// 8-byte value for this key.
pub fn build_encrypted_gcm(
    mut header: IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    sk_e: &[u8],
    iv: &[u8; IV_LEN],
) -> Result<Vec<u8>, IkeError> {
    let (key, salt) = split_key(sk_e)?;

    // Plaintext = inner ‖ pad_length(0). (GCM needs no block padding; the
    // one-byte Pad Length field of RFC 7296 §3.14 is still required.)
    let mut plaintext = Vec::with_capacity(inner.len() + 1);
    plaintext.extend_from_slice(inner);
    plaintext.push(0);

    let sk_body_len = IV_LEN + plaintext.len() + ICV_LEN;
    let sk_payload_len = 4 + sk_body_len; // + generic payload header
    let total_len = IkeHeader::LEN + sk_payload_len;

    header.next_payload = PayloadType::Encrypted;
    header.length = total_len as u32;
    let header_bytes = header.to_bytes();

    // SK generic payload header.
    let mut sk_gen = [0u8; 4];
    sk_gen[0] = first_inner.to_u8();
    sk_gen[1] = 0; // critical bit clear + RESERVED
    sk_gen[2..4].copy_from_slice(&(sk_payload_len as u16).to_be_bytes());

    // AAD = IKE header ‖ SK generic header (everything before the IV).
    let mut aad = Vec::with_capacity(IkeHeader::LEN + 4);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(&sk_gen);

    let nonce = gcm_nonce(salt, iv);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| IkeError::Crypto("bad AES-256 key length"))?;
    let ct_and_tag = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| IkeError::Crypto("GCM encryption failed"))?;

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&sk_gen);
    out.extend_from_slice(iv);
    out.extend_from_slice(&ct_and_tag);
    Ok(out)
}

/// Decrypt the SK payload of a full message, returning the SK payload's Next
/// Payload (the first inner payload type) and the decrypted inner payload chain
/// (padding stripped). `sk_e` is the 36-byte AES-GCM key for the *sender's*
/// direction.
pub fn open_encrypted_gcm(message: &[u8], sk_e: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    let (key, salt) = split_key(sk_e)?;

    let header = IkeHeader::parse(message)?;
    if header.next_payload != PayloadType::Encrypted {
        return Err(IkeError::MissingPayload("SK"));
    }

    let body = &message[IkeHeader::LEN..];
    if body.len() < 4 {
        return Err(IkeError::Truncated { need: 4, have: body.len() });
    }
    let first_inner = PayloadType::from_u8(body[0]);
    let sk_payload_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if sk_payload_len < 4 + IV_LEN + ICV_LEN || sk_payload_len > body.len() {
        return Err(IkeError::BadLength { declared: sk_payload_len, available: body.len() });
    }

    let sk_body = &body[4..sk_payload_len];
    let iv: [u8; IV_LEN] = sk_body[..IV_LEN].try_into().unwrap();
    let ct_and_tag = &sk_body[IV_LEN..];

    let aad = &message[..IkeHeader::LEN + 4]; // IKE header ‖ SK generic header
    let nonce = gcm_nonce(salt, &iv);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| IkeError::Crypto("bad AES-256 key length"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct_and_tag, aad })
        .map_err(|_| IkeError::BadIntegrity)?;

    // Strip padding: the last byte is the Pad Length; drop it + that many bytes.
    let pad_len = *plaintext.last().ok_or(IkeError::Crypto("empty plaintext"))? as usize;
    if pad_len + 1 > plaintext.len() {
        return Err(IkeError::Crypto("pad length exceeds plaintext"));
    }
    let inner = plaintext[..plaintext.len() - 1 - pad_len].to_vec();
    Ok((first_inner, inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::message::{ExchangeType, Flags};

    fn header() -> IkeHeader {
        IkeHeader {
            initiator_spi: 0x1111_2222_3333_4444,
            responder_spi: 0x5555_6666_7777_8888,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags { initiator: true, version: false, response: false },
            message_id: 1,
            length: 0,
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let sk_e = [0x42u8; 36];
        let iv = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let inner = vec![0xABu8; 40];
        let msg = build_encrypted_gcm(header(), PayloadType::IdInitiator, &inner, &sk_e, &iv).unwrap();

        let h = IkeHeader::parse(&msg).unwrap();
        assert_eq!(h.next_payload, PayloadType::Encrypted);
        assert_eq!(h.length as usize, msg.len());

        let (first, out) = open_encrypted_gcm(&msg, &sk_e).unwrap();
        assert_eq!(first, PayloadType::IdInitiator);
        assert_eq!(out, inner);
    }

    #[test]
    fn empty_inner_roundtrips() {
        let sk_e = [5u8; 36];
        let msg = build_encrypted_gcm(header(), PayloadType::NoNext, &[], &sk_e, &[0u8; 8]).unwrap();
        let (first, out) = open_encrypted_gcm(&msg, &sk_e).unwrap();
        assert_eq!(first, PayloadType::NoNext);
        assert!(out.is_empty());
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let sk_e = [0x42u8; 36];
        let msg = build_encrypted_gcm(header(), PayloadType::Nonce, &[1, 2, 3, 4], &sk_e, &[9u8; 8]).unwrap();
        let mut bad = sk_e;
        bad[0] ^= 0xff;
        assert_eq!(open_encrypted_gcm(&msg, &bad).unwrap_err(), IkeError::BadIntegrity);
    }

    #[test]
    fn tampering_fails_authentication() {
        let sk_e = [7u8; 36];
        let mut msg = build_encrypted_gcm(header(), PayloadType::Nonce, &[9, 9, 9, 9], &sk_e, &[3u8; 8]).unwrap();
        let last = msg.len() - 1;
        msg[last] ^= 0x01; // flip a tag byte
        assert_eq!(open_encrypted_gcm(&msg, &sk_e).unwrap_err(), IkeError::BadIntegrity);
    }

    #[test]
    fn rejects_wrong_key_length() {
        let short = [0u8; 32]; // missing the 4-byte salt
        assert!(matches!(
            build_encrypted_gcm(header(), PayloadType::Nonce, &[], &short, &[0u8; 8]),
            Err(IkeError::Crypto(_))
        ));
    }
}
