//! IKEv1 key schedule and encryption (RFC 2409 §5 + Appendix B).
//!
//! IKEv1 keying is structurally different from IKEv2: a raw-keyed PRF used with
//! explicit `| 0 | 1 | 2` counters (no `prf+`), a `SKEYID → SKEYID_d/a/e` chain,
//! the Phase-1 authentication `HASH_I`/`HASH_R`, a `KEYMAT` for the Quick-Mode
//! ESP SA, and AES-CBC with an IV that is *chained* across messages and reseeded
//! per Message-ID.
//!
//! The PRF is `HMAC-<hash>` for the negotiated Phase-1 hash. We support the two
//! algorithms that matter for the Android interop target (SHA-256 preferred,
//! SHA-1 as a fallback); MD5 / SHA-384 / SHA-512 can slot in behind [`Prf`].

use crate::error::IkeError;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// AES block size — the CBC IV and padding granularity.
pub const AES_BLOCK: usize = 16;

/// The negotiated Phase-1 PRF / hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prf {
    Sha1,
    Sha256,
}

impl Prf {
    /// Output length in bytes.
    pub fn output_len(self) -> usize {
        match self {
            Prf::Sha1 => 20,
            Prf::Sha256 => 32,
        }
    }

    /// `HMAC-<hash>(key, data)` — the IKEv1 PRF.
    pub fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Prf::Sha1 => {
                let mut m = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Prf::Sha256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }

    /// The bare hash (used for the CBC IV derivation, RFC 2409 App. B).
    pub fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Prf::Sha1 => Sha1::digest(data).to_vec(),
            Prf::Sha256 => Sha256::digest(data).to_vec(),
        }
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}

/// `SKEYID = prf(pre-shared-key, Ni_b | Nr_b)` for PSK authentication.
pub fn skeyid_psk(prf: Prf, psk: &[u8], ni: &[u8], nr: &[u8]) -> Vec<u8> {
    prf.mac(psk, &cat(&[ni, nr]))
}

/// `SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)`.
pub fn skeyid_d(prf: Prf, skeyid: &[u8], gxy: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[gxy, cky_i, cky_r, &[0]]))
}

/// `SKEYID_a = prf(SKEYID, SKEYID_d | g^xy | CKY-I | CKY-R | 1)`.
pub fn skeyid_a(prf: Prf, skeyid: &[u8], skeyid_d: &[u8], gxy: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[skeyid_d, gxy, cky_i, cky_r, &[1]]))
}

/// `SKEYID_e = prf(SKEYID, SKEYID_a | g^xy | CKY-I | CKY-R | 2)`.
pub fn skeyid_e(prf: Prf, skeyid: &[u8], skeyid_a: &[u8], gxy: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[skeyid_a, gxy, cky_i, cky_r, &[2]]))
}

/// `HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)`.
#[allow(clippy::too_many_arguments)]
pub fn hash_i(prf: Prf, skeyid: &[u8], gx_i: &[u8], gx_r: &[u8], cky_i: &[u8; 8], cky_r: &[u8; 8], sa_b: &[u8], id_b: &[u8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[gx_i, gx_r, cky_i, cky_r, sa_b, id_b]))
}

/// `HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)`.
#[allow(clippy::too_many_arguments)]
pub fn hash_r(prf: Prf, skeyid: &[u8], gx_r: &[u8], gx_i: &[u8], cky_r: &[u8; 8], cky_i: &[u8; 8], sa_b: &[u8], id_b: &[u8]) -> Vec<u8> {
    prf.mac(skeyid, &cat(&[gx_r, gx_i, cky_r, cky_i, sa_b, id_b]))
}

/// Expand `SKEYID_e` into a cipher key of `key_len` bytes (RFC 2409 App. B): the
/// first `key_len` bytes of `SKEYID_e` if long enough, else
/// `K1 = prf(SKEYID_e, 0) ; Kn = prf(SKEYID_e, K(n-1))`, concatenated.
pub fn derive_cipher_key(prf: Prf, skeyid_e: &[u8], key_len: usize) -> Vec<u8> {
    if skeyid_e.len() >= key_len {
        return skeyid_e[..key_len].to_vec();
    }
    let mut ka = Vec::new();
    let mut prev = prf.mac(skeyid_e, &[0u8]);
    ka.extend_from_slice(&prev);
    while ka.len() < key_len {
        prev = prf.mac(skeyid_e, &prev);
        ka.extend_from_slice(&prev);
    }
    ka.truncate(key_len);
    ka
}

/// Quick-Mode ESP keying material (RFC 2409 §5.5, no PFS):
/// `KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b)`, expanded by feedback
/// to `out_len` bytes.
pub fn keymat(prf: Prf, skeyid_d: &[u8], protocol: u8, spi: &[u8], ni: &[u8], nr: &[u8], out_len: usize) -> Vec<u8> {
    let seed = cat(&[&[protocol], spi, ni, nr]);
    let mut out = Vec::new();
    let mut prev = prf.mac(skeyid_d, &seed);
    out.extend_from_slice(&prev);
    while out.len() < out_len {
        // K(n) = prf(SKEYID_d, K(n-1) | protocol | SPI | Ni_b | Nr_b)
        let mut input = prev.clone();
        input.extend_from_slice(&seed);
        prev = prf.mac(skeyid_d, &input);
        out.extend_from_slice(&prev);
    }
    out.truncate(out_len);
    out
}

/// The Phase-1 CBC IV seed: `HASH(g^xi | g^xr)`, truncated to the block size.
pub fn phase1_iv(prf: Prf, gx_i: &[u8], gx_r: &[u8], block: usize) -> Vec<u8> {
    let mut h = prf.hash(&cat(&[gx_i, gx_r]));
    h.truncate(block);
    h
}

/// The initial IV for a post-Phase-1 exchange with `message_id`:
/// `HASH(last_phase1_iv | message_id)`, truncated to the block size.
pub fn phase2_iv(prf: Prf, phase1_iv: &[u8], message_id: u32, block: usize) -> Vec<u8> {
    let mut h = prf.hash(&cat(&[phase1_iv, &message_id.to_be_bytes()]));
    h.truncate(block);
    h
}

/// Zero-pad `data` up to a multiple of `block` (IKEv1 pads to the cipher block;
/// the real length is delimited by the ISAKMP length fields).
pub fn pad_to_block(data: &[u8], block: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    let rem = out.len() % block;
    if rem != 0 {
        out.resize(out.len() + (block - rem), 0);
    }
    out
}

/// AES-CBC encrypt (raw, no padding). `plaintext` must be block-aligned.
pub fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, IkeError> {
    if plaintext.len() % AES_BLOCK != 0 {
        return Err(IkeError::Crypto("CBC plaintext not block-aligned"));
    }
    let cipher = Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| IkeError::Crypto("bad AES-CBC key/iv"))?;
    Ok(cipher.encrypt_padded_vec_mut::<NoPadding>(plaintext))
}

/// AES-CBC decrypt (raw, no padding). Returns the full padded plaintext; the
/// caller uses ISAKMP length fields to find the real end.
pub fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, IkeError> {
    if ciphertext.is_empty() || ciphertext.len() % AES_BLOCK != 0 {
        return Err(IkeError::Crypto("CBC ciphertext not block-aligned"));
    }
    let cipher = Aes256CbcDec::new_from_slices(key, iv).map_err(|_| IkeError::Crypto("bad AES-CBC key/iv"))?;
    cipher
        .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .map_err(|_| IkeError::Crypto("AES-CBC decrypt failed"))
}

/// The last ciphertext block — becomes the IV for the next message with the same
/// Message-ID (RFC 2409 App. B CBC chaining).
pub fn next_iv(ciphertext: &[u8], block: usize) -> Vec<u8> {
    ciphertext[ciphertext.len().saturating_sub(block)..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CKY_I: [u8; 8] = [0x11; 8];
    const CKY_R: [u8; 8] = [0x22; 8];

    #[test]
    fn skeyid_chain_is_deterministic_and_distinct() {
        for prf in [Prf::Sha1, Prf::Sha256] {
            let gxy = [0xAB; 128];
            let skeyid = skeyid_psk(prf, b"secret", &[1; 16], &[2; 16]);
            assert_eq!(skeyid.len(), prf.output_len());
            let d = skeyid_d(prf, &skeyid, &gxy, &CKY_I, &CKY_R);
            let a = skeyid_a(prf, &skeyid, &d, &gxy, &CKY_I, &CKY_R);
            let e = skeyid_e(prf, &skeyid, &a, &gxy, &CKY_I, &CKY_R);
            // Deterministic.
            assert_eq!(d, skeyid_d(prf, &skeyid, &gxy, &CKY_I, &CKY_R));
            // The three derived keys differ (the 0/1/2 counters).
            assert_ne!(d, a);
            assert_ne!(a, e);
            assert_ne!(d, e);
        }
    }

    #[test]
    fn hash_i_and_hash_r_differ_by_argument_order() {
        let prf = Prf::Sha256;
        let skeyid = skeyid_psk(prf, b"psk", &[1; 16], &[2; 16]);
        let (gxi, gxr, sa, id) = ([0x01; 128], [0x02; 128], vec![0xAA; 16], vec![0xBB; 12]);
        let hi = hash_i(prf, &skeyid, &gxi, &gxr, &CKY_I, &CKY_R, &sa, &id);
        let hr = hash_r(prf, &skeyid, &gxr, &gxi, &CKY_R, &CKY_I, &sa, &id);
        assert_eq!(hi.len(), 32);
        assert_ne!(hi, hr, "HASH_I and HASH_R swap g^x and cookie order");
    }

    #[test]
    fn cipher_key_expansion_lengths() {
        // SHA-1 PRF (20 bytes) expanded to AES-256 (32 bytes) needs feedback.
        let e = vec![0x5A; 20];
        let k = derive_cipher_key(Prf::Sha1, &e, 32);
        assert_eq!(k.len(), 32);
        assert_eq!(derive_cipher_key(Prf::Sha1, &e, 32), k); // deterministic
        // SHA-256 SKEYID_e (32) already covers AES-256 → first 32 bytes.
        let e2 = vec![0x77; 32];
        assert_eq!(derive_cipher_key(Prf::Sha256, &e2, 32), e2);
    }

    #[test]
    fn aes_cbc_roundtrips_and_chains() {
        let key = [0x42; 32];
        let iv = phase1_iv(Prf::Sha256, &[0x01; 128], &[0x02; 128], AES_BLOCK);
        assert_eq!(iv.len(), AES_BLOCK);
        let plain = pad_to_block(b"an encrypted ISAKMP payload chain", AES_BLOCK);
        let ct = aes256_cbc_encrypt(&key, &iv, &plain).unwrap();
        assert_eq!(ct.len(), plain.len());
        let pt = aes256_cbc_decrypt(&key, &iv, &ct).unwrap();
        assert_eq!(pt, plain);
        // The next-message IV is the last ciphertext block.
        assert_eq!(next_iv(&ct, AES_BLOCK), ct[ct.len() - AES_BLOCK..]);
    }

    #[test]
    fn phase2_iv_depends_on_message_id() {
        let p1 = phase1_iv(Prf::Sha256, &[0x01; 128], &[0x02; 128], AES_BLOCK);
        let a = phase2_iv(Prf::Sha256, &p1, 0x1234_5678, AES_BLOCK);
        let b = phase2_iv(Prf::Sha256, &p1, 0x1234_5679, AES_BLOCK);
        assert_eq!(a.len(), AES_BLOCK);
        assert_ne!(a, b);
    }

    #[test]
    fn keymat_fills_requested_length() {
        let km = keymat(Prf::Sha1, &[0x33; 20], 3, &[0xDE, 0xAD, 0xBE, 0xEF], &[1; 16], &[2; 16], 52);
        assert_eq!(km.len(), 52); // e.g. AES-256 (32) + HMAC-SHA1 (20)
        assert_ne!(km[..20], km[20..40]); // feedback blocks differ
    }
}
