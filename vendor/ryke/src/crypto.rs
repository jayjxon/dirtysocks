//! Cryptographic core for `IKE_SA_INIT` (M1): X25519 Diffie-Hellman, the
//! HMAC-SHA256 PRF, `prf+` (RFC 7296 §2.13), and the SKEYSEED / SK_* key
//! schedule (§2.14).
//!
//! Verified against published test vectors where they exist — RFC 7748 for
//! X25519, RFC 4231 for HMAC-SHA256. End-to-end key-schedule correctness is
//! confirmed at the M1 interop checkpoint against an independent IKEv2 responder.
//!
//! At M1 we support exactly one suite's primitives: X25519 (DH group 31) and
//! PRF_HMAC_SHA2_256 (transform 5). More groups/PRFs slot in behind the same
//! functions later.

use crate::error::IkeError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// Diffie-Hellman primitives: X25519 (RFC 7748, group 31) and the finite-field
/// MODP groups 2 (1024-bit) and 14 (2048-bit) from RFC 2409 / RFC 3526.
pub mod dh {
    use super::{PublicKey, StaticSecret};
    use num_bigint_dig::BigUint;

    /// Public key for a 32-byte private scalar.
    pub fn x25519_public(private: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*private)).to_bytes()
    }

    /// Shared secret from our private scalar and the peer's public key.
    pub fn x25519_shared(private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
        StaticSecret::from(*private)
            .diffie_hellman(&PublicKey::from(*peer_public))
            .to_bytes()
    }

    /// RFC 2409 MODP-1024 (Oakley group 2) prime; generator g = 2.
    pub const MODP_1024_PRIME: [u8; 128] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    /// RFC 3526 MODP-2048 (group 14) prime; generator g = 2.
    pub const MODP_2048_PRIME: [u8; 256] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
        0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
        0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
        0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
        0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
        0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
        0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
        0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
        0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ];

    /// `base^exp mod p`, big-endian, left-zero-padded to `prime`'s byte length.
    fn modexp(base: &[u8], exp: &[u8], prime: &[u8]) -> Vec<u8> {
        let v = BigUint::from_bytes_be(base)
            .modpow(&BigUint::from_bytes_be(exp), &BigUint::from_bytes_be(prime))
            .to_bytes_be();
        let mut out = vec![0u8; prime.len()];
        let start = prime.len() - v.len();
        out[start..].copy_from_slice(&v);
        out
    }

    /// MODP public value `g^x mod p` (g = 2).
    pub fn modp_public(exp: &[u8], prime: &[u8]) -> Vec<u8> {
        modexp(&[2], exp, prime)
    }

    /// MODP shared secret `peer^x mod p`.
    pub fn modp_shared(exp: &[u8], peer_public: &[u8], prime: &[u8]) -> Vec<u8> {
        modexp(peer_public, exp, prime)
    }

    /// Reject a peer MODP value outside `[2, p-2]` (identity / small-subgroup).
    pub fn modp_valid(peer: &[u8], prime: &[u8]) -> bool {
        let p = BigUint::from_bytes_be(prime);
        let y = BigUint::from_bytes_be(peer);
        let one = BigUint::from(1u32);
        y > one && y < &p - &one
    }
}

/// A negotiated Diffie-Hellman group. `private` is a byte string of entropy:
/// X25519 uses the first 32 bytes as its scalar; MODP uses it as the exponent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhGroup {
    X25519,
    Modp1024,
    Modp2048,
}

impl DhGroup {
    /// Map an IKE DH transform ID (31 / 2 / 14) to a group.
    pub fn from_transform_id(id: u16) -> Option<DhGroup> {
        match id {
            31 => Some(DhGroup::X25519),
            2 => Some(DhGroup::Modp1024),
            14 => Some(DhGroup::Modp2048),
            _ => None,
        }
    }

    /// The IKE DH transform ID for this group.
    pub fn transform_id(self) -> u16 {
        match self {
            DhGroup::X25519 => 31,
            DhGroup::Modp1024 => 2,
            DhGroup::Modp2048 => 14,
        }
    }

    /// Byte length of the public value carried on the wire.
    pub fn public_len(self) -> usize {
        match self {
            DhGroup::X25519 => 32,
            DhGroup::Modp1024 => 128,
            DhGroup::Modp2048 => 256,
        }
    }

    /// Our public value from `private` (must be ≥ 32 bytes of entropy).
    pub fn public(self, private: &[u8]) -> Vec<u8> {
        match self {
            DhGroup::X25519 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&private[..32]);
                dh::x25519_public(&s).to_vec()
            }
            DhGroup::Modp1024 => dh::modp_public(private, &dh::MODP_1024_PRIME),
            DhGroup::Modp2048 => dh::modp_public(private, &dh::MODP_2048_PRIME),
        }
    }

    /// The shared secret from our `private` and the peer's public value. Rejects
    /// a wrong-length or (for MODP) out-of-range peer value.
    pub fn shared(self, private: &[u8], peer: &[u8]) -> Result<Vec<u8>, IkeError> {
        if peer.len() != self.public_len() {
            return Err(IkeError::BadKeyExchange { group: self.transform_id(), len: peer.len() });
        }
        Ok(match self {
            DhGroup::X25519 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(&private[..32]);
                let mut p = [0u8; 32];
                p.copy_from_slice(peer);
                dh::x25519_shared(&s, &p).to_vec()
            }
            DhGroup::Modp1024 => {
                if !dh::modp_valid(peer, &dh::MODP_1024_PRIME) {
                    return Err(IkeError::BadKeyExchange { group: 2, len: peer.len() });
                }
                dh::modp_shared(private, peer, &dh::MODP_1024_PRIME)
            }
            DhGroup::Modp2048 => {
                if !dh::modp_valid(peer, &dh::MODP_2048_PRIME) {
                    return Err(IkeError::BadKeyExchange { group: 14, len: peer.len() });
                }
                dh::modp_shared(private, peer, &dh::MODP_2048_PRIME)
            }
        })
    }
}

/// PRF_HMAC_SHA2_256 (transform ID 5) — the only PRF supported at M1.
pub fn prf(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// `prf+` (RFC 7296 §2.13): `prf+(K,S) = T1 | T2 | …` where
/// `T1 = prf(K, S | 0x01)` and `Tn = prf(K, T(n-1) | S | n)`. Returns `out_len`
/// bytes. (The RFC caps the counter at 255; real key material never approaches
/// that — 255 blocks is 8160 bytes.)
pub fn prf_plus(key: &[u8], seed: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while out.len() < out_len {
        let mut input = Vec::with_capacity(prev.len() + seed.len() + 1);
        input.extend_from_slice(&prev);
        input.extend_from_slice(seed);
        input.push(counter);
        let block = prf(key, &input);
        out.extend_from_slice(&block);
        prev = block.to_vec();
        counter = counter.saturating_add(1);
    }
    out.truncate(out_len);
    out
}

/// Byte lengths of the keys to derive, set by the negotiated suite.
#[derive(Debug, Clone, Copy)]
pub struct KeyLengths {
    /// SK_d, SK_pi, SK_pr length (the PRF key length; 32 for HMAC-SHA256).
    pub prf: usize,
    /// SK_ai, SK_ar length (integrity key; 0 for an AEAD such as AES-GCM).
    pub integ: usize,
    /// SK_ei, SK_er length (encryption key; e.g. 32 for AES-256).
    pub encr: usize,
}

/// The seven IKE SA keys derived by `IKE_SA_INIT` (RFC 7296 §2.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    /// Seeds CHILD SA keying material.
    pub sk_d: Vec<u8>,
    /// Integrity keys (initiator / responder) for the SK payload.
    pub sk_ai: Vec<u8>,
    pub sk_ar: Vec<u8>,
    /// Encryption keys (initiator / responder) for the SK payload.
    pub sk_ei: Vec<u8>,
    pub sk_er: Vec<u8>,
    /// Keys used inside the AUTH payload computation.
    pub sk_pi: Vec<u8>,
    pub sk_pr: Vec<u8>,
}

/// Derive SKEYSEED and the SK_* set (RFC 7296 §2.14):
///
/// ```text
/// SKEYSEED = prf(Ni | Nr, g^ir)
/// {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
///     = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)
/// ```
pub fn derive_session_keys(
    shared_secret: &[u8],
    ni: &[u8],
    nr: &[u8],
    spi_i: u64,
    spi_r: u64,
    lengths: KeyLengths,
) -> SessionKeys {
    let mut nonces = Vec::with_capacity(ni.len() + nr.len());
    nonces.extend_from_slice(ni);
    nonces.extend_from_slice(nr);
    let skeyseed = prf(&nonces, shared_secret);

    let mut seed = nonces; // Ni | Nr | SPIi | SPIr
    seed.extend_from_slice(&spi_i.to_be_bytes());
    seed.extend_from_slice(&spi_r.to_be_bytes());

    let total = 3 * lengths.prf + 2 * lengths.integ + 2 * lengths.encr;
    let km = prf_plus(&skeyseed, &seed, total);

    let mut off = 0;
    let mut take = |n: usize| {
        let slice = km[off..off + n].to_vec();
        off += n;
        slice
    };
    SessionKeys {
        sk_d: take(lengths.prf),
        sk_ai: take(lengths.integ),
        sk_ar: take(lengths.integ),
        sk_ei: take(lengths.encr),
        sk_er: take(lengths.encr),
        sk_pi: take(lengths.prf),
        sk_pr: take(lengths.prf),
    }
}

/// Derive new IKE keys for an **IKE-SA rekey** (RFC 7296 §2.18). Unlike
/// [`derive_session_keys`], SKEYSEED is keyed by the *old* SK_d and covers the new
/// DH shared secret:
///
/// ```text
/// SKEYSEED = prf(SK_d(old), g^ir | Ni | Nr)
/// {SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr}
///     = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)   (the NEW IKE SPIs)
/// ```
#[allow(clippy::too_many_arguments)]
pub fn derive_rekey_session_keys(
    sk_d_old: &[u8],
    shared_secret: &[u8],
    ni: &[u8],
    nr: &[u8],
    spi_i: u64,
    spi_r: u64,
    lengths: KeyLengths,
) -> SessionKeys {
    let mut data = Vec::with_capacity(shared_secret.len() + ni.len() + nr.len());
    data.extend_from_slice(shared_secret);
    data.extend_from_slice(ni);
    data.extend_from_slice(nr);
    let skeyseed = prf(sk_d_old, &data);

    let mut seed = Vec::with_capacity(ni.len() + nr.len() + 16);
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    seed.extend_from_slice(&spi_i.to_be_bytes());
    seed.extend_from_slice(&spi_r.to_be_bytes());

    let total = 3 * lengths.prf + 2 * lengths.integ + 2 * lengths.encr;
    let km = prf_plus(&skeyseed, &seed, total);
    let mut off = 0;
    let mut take = |n: usize| {
        let slice = km[off..off + n].to_vec();
        off += n;
        slice
    };
    SessionKeys {
        sk_d: take(lengths.prf),
        sk_ai: take(lengths.integ),
        sk_ar: take(lengths.integ),
        sk_ei: take(lengths.encr),
        sk_er: take(lengths.encr),
        sk_pi: take(lengths.prf),
        sk_pr: take(lengths.prf),
    }
}

/// ESP/AH CHILD SA keys, in the order `KEYMAT` provides them (RFC 7296 §2.17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildKeys {
    pub encr_i: Vec<u8>,
    pub integ_i: Vec<u8>,
    pub encr_r: Vec<u8>,
    pub integ_r: Vec<u8>,
}

/// Derive CHILD SA keys for the SA created by `IKE_AUTH` (no PFS):
///
/// ```text
/// KEYMAT = prf+(SK_d, Ni | Nr)
/// ```
///
/// taken in order as `encr_i | integ_i | encr_r | integ_r`. For an AEAD cipher
/// (AES-GCM) `integ_len` is 0 and each `encr` key material includes the salt.
pub fn derive_child_keys(sk_d: &[u8], ni: &[u8], nr: &[u8], encr_len: usize, integ_len: usize) -> ChildKeys {
    let mut seed = Vec::with_capacity(ni.len() + nr.len());
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);
    let km = prf_plus(sk_d, &seed, 2 * (encr_len + integ_len));

    let mut off = 0;
    let mut take = |n: usize| {
        let slice = km[off..off + n].to_vec();
        off += n;
        slice
    };
    ChildKeys {
        encr_i: take(encr_len),
        integ_i: take(integ_len),
        encr_r: take(encr_len),
        integ_r: take(integ_len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn hex32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    // RFC 7748 §6.1 Diffie-Hellman test vector.
    const ALICE_PRIV: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const ALICE_PUB: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const BOB_PRIV: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const BOB_PUB: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    #[test]
    fn x25519_matches_rfc7748() {
        assert_eq!(dh::x25519_public(&hex32(ALICE_PRIV)), hex32(ALICE_PUB));
        assert_eq!(dh::x25519_public(&hex32(BOB_PRIV)), hex32(BOB_PUB));
        assert_eq!(dh::x25519_shared(&hex32(ALICE_PRIV), &hex32(BOB_PUB)), hex32(SHARED));
        assert_eq!(dh::x25519_shared(&hex32(BOB_PRIV), &hex32(ALICE_PUB)), hex32(SHARED));
    }

    #[test]
    fn modp_groups_agree_and_encode_full_width() {
        // Two parties with distinct exponents derive the same shared secret, and
        // the wire values are exactly the prime's byte width.
        for group in [DhGroup::Modp1024, DhGroup::Modp2048] {
            let a_priv = [0x11u8; 32];
            let b_priv = [0x22u8; 32];
            let a_pub = group.public(&a_priv);
            let b_pub = group.public(&b_priv);
            assert_eq!(a_pub.len(), group.public_len());
            assert_eq!(b_pub.len(), group.public_len());
            let a_shared = group.shared(&a_priv, &b_pub).unwrap();
            let b_shared = group.shared(&b_priv, &a_pub).unwrap();
            assert_eq!(a_shared, b_shared, "both sides must derive g^ab");
            assert_eq!(a_shared.len(), group.public_len());
            // A distinct exponent yields a distinct secret.
            let c_shared = group.shared(&[0x33u8; 32], &a_pub).unwrap();
            assert_ne!(c_shared, a_shared);
        }
    }

    #[test]
    fn modp_2_pow_1_is_2_left_padded() {
        // g^1 mod p = 2, which must be left-zero-padded to the full width.
        let mut one = [0u8; 32];
        one[31] = 1;
        let pub14 = DhGroup::Modp2048.public(&one);
        assert_eq!(pub14.len(), 256);
        assert_eq!(pub14[255], 2);
        assert!(pub14[..255].iter().all(|&b| b == 0));
    }

    #[test]
    fn dh_group_rejects_bad_peer_values() {
        let priv_ = [0x44u8; 32];
        // Wrong length.
        assert!(DhGroup::Modp1024.shared(&priv_, &[0u8; 100]).is_err());
        // Out-of-range MODP peers: 0, 1, and p-1 are rejected.
        let mut zero = vec![0u8; 128];
        assert!(DhGroup::Modp1024.shared(&priv_, &zero).is_err());
        zero[127] = 1; // value 1
        assert!(DhGroup::Modp1024.shared(&priv_, &zero).is_err());
        let mut pm1 = dh::MODP_1024_PRIME.to_vec();
        pm1[127] -= 1; // p-1
        assert!(DhGroup::Modp1024.shared(&priv_, &pm1).is_err());
    }

    #[test]
    fn transform_id_roundtrips() {
        for (g, id) in [(DhGroup::X25519, 31), (DhGroup::Modp1024, 2), (DhGroup::Modp2048, 14)] {
            assert_eq!(g.transform_id(), id);
            assert_eq!(DhGroup::from_transform_id(id), Some(g));
        }
        assert_eq!(DhGroup::from_transform_id(99), None);
    }

    #[test]
    fn prf_matches_rfc4231_case1() {
        // RFC 4231 Test Case 1: HMAC-SHA-256.
        let key = [0x0b; 20];
        let data = b"Hi There";
        assert_eq!(
            prf(&key, data).to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn prf_plus_follows_the_recurrence() {
        let key = b"key material";
        let seed = b"Ni|Nr|SPIi|SPIr";
        let out = prf_plus(key, seed, 80); // spans 3 SHA-256 blocks

        // T1 = prf(K, S | 0x01)
        let mut s1 = seed.to_vec();
        s1.push(1);
        let t1 = prf(key, &s1);
        assert_eq!(&out[0..32], &t1[..]);

        // T2 = prf(K, T1 | S | 0x02)
        let mut s2 = t1.to_vec();
        s2.extend_from_slice(seed);
        s2.push(2);
        let t2 = prf(key, &s2);
        assert_eq!(&out[32..64], &t2[..]);

        assert_eq!(out.len(), 80);
    }

    #[test]
    fn session_keys_split_and_are_self_consistent() {
        let shared = hex(SHARED);
        let ni = [0x11u8; 32];
        let nr = [0x22u8; 32];
        let lengths = KeyLengths { prf: 32, integ: 32, encr: 32 };
        let keys = derive_session_keys(&shared, &ni, &nr, 1, 2, lengths);

        // Lengths match the negotiated suite.
        assert_eq!(keys.sk_d.len(), 32);
        assert_eq!(keys.sk_ai.len(), 32);
        assert_eq!(keys.sk_er.len(), 32);
        assert_eq!(keys.sk_pr.len(), 32);

        // SK_d is the leading slice of prf+(SKEYSEED, Ni|Nr|SPIi|SPIr).
        let mut nonces = ni.to_vec();
        nonces.extend_from_slice(&nr);
        let skeyseed = prf(&nonces, &shared);
        let mut seed = nonces;
        seed.extend_from_slice(&1u64.to_be_bytes());
        seed.extend_from_slice(&2u64.to_be_bytes());
        let km = prf_plus(&skeyseed, &seed, 32);
        assert_eq!(keys.sk_d, km);
    }

    #[test]
    fn aead_suite_has_no_integrity_keys() {
        // AES-GCM is an AEAD: SK_ai/SK_ar are empty.
        let keys = derive_session_keys(&[9u8; 32], &[1; 16], &[2; 16], 7, 8, KeyLengths { prf: 32, integ: 0, encr: 32 });
        assert!(keys.sk_ai.is_empty() && keys.sk_ar.is_empty());
        assert_eq!(keys.sk_ei.len(), 32);
    }

    #[test]
    fn child_keys_split_in_keymat_order() {
        let sk_d = [0x33u8; 32];
        let ni = [1u8; 16];
        let nr = [2u8; 16];
        // AES-GCM-256 CHILD SA: 36-byte key material per direction, no integ key.
        let ck = derive_child_keys(&sk_d, &ni, &nr, 36, 0);
        assert_eq!(ck.encr_i.len(), 36);
        assert_eq!(ck.encr_r.len(), 36);
        assert!(ck.integ_i.is_empty() && ck.integ_r.is_empty());
        assert_ne!(ck.encr_i, ck.encr_r);

        // encr_i is the leading slice of prf+(SK_d, Ni|Nr).
        let mut seed = ni.to_vec();
        seed.extend_from_slice(&nr);
        assert_eq!(ck.encr_i, prf_plus(&sk_d, &seed, 36));
    }
}
