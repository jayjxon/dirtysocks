//! MS-CHAP-v2 (RFC 2759) — the challenge/response scheme carried by
//! EAP-MSCHAPv2, which is what stock **iOS and Android** IKEv2 clients use to
//! authenticate. This is legacy crypto (MD4 / DES / SHA-1), pulled in solely for
//! this auth method.
//!
//! Every function is verified against the worked example in RFC 2759 §9.2.

use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use md4::{Digest, Md4};
use sha1::Sha1;

/// `NtPasswordHash = MD4(UTF-16-LE(password))` (RFC 2759 §8.3).
pub fn nt_password_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    Md4::digest(utf16).into()
}

/// `HashNtPasswordHash = MD4(passwordHash)` (RFC 2759 §8.4).
pub fn hash_nt_password_hash(password_hash: &[u8; 16]) -> [u8; 16] {
    Md4::digest(password_hash).into()
}

/// `ChallengeHash` = first 8 bytes of `SHA1(PeerChallenge | AuthenticatorChallenge
/// | UserName)` (RFC 2759 §8.2).
pub fn challenge_hash(
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    user_name: &[u8],
) -> [u8; 8] {
    let mut h = Sha1::new();
    h.update(peer_challenge);
    h.update(authenticator_challenge);
    h.update(user_name);
    let digest = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Expand a 7-byte string into an 8-byte DES key (MS `str_to_key`); the low bit
/// of each output byte is an ignored parity bit.
fn str_to_key(s: &[u8]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = s[0] >> 1;
    k[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2);
    k[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3);
    k[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4);
    k[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5);
    k[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6);
    k[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7);
    k[7] = s[6] & 0x7F;
    for b in &mut k {
        *b <<= 1;
    }
    k
}

fn des_encrypt(challenge: &[u8; 8], key7: &[u8]) -> [u8; 8] {
    let cipher = Des::new_from_slice(&str_to_key(key7)).expect("8-byte DES key");
    let mut block = GenericArray::clone_from_slice(challenge);
    cipher.encrypt_block(&mut block);
    block.into()
}

/// `ChallengeResponse` (RFC 2759 §8.5) → 24 bytes: three DES encryptions of the
/// 8-byte challenge under the password hash (zero-padded to 21 bytes, split 7/7/7).
pub fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut zph = [0u8; 21];
    zph[..16].copy_from_slice(password_hash);
    let mut out = [0u8; 24];
    out[0..8].copy_from_slice(&des_encrypt(challenge, &zph[0..7]));
    out[8..16].copy_from_slice(&des_encrypt(challenge, &zph[7..14]));
    out[16..24].copy_from_slice(&des_encrypt(challenge, &zph[14..21]));
    out
}

/// `GenerateNTResponse` (RFC 2759 §8.1) → the 24-byte NT-Response.
pub fn generate_nt_response(
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    user_name: &[u8],
    password: &str,
) -> [u8; 24] {
    let challenge = challenge_hash(peer_challenge, authenticator_challenge, user_name);
    let password_hash = nt_password_hash(password);
    challenge_response(&challenge, &password_hash)
}

const MAGIC1: &[u8] = b"Magic server to client signing constant";
const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

/// `GenerateAuthenticatorResponse` (RFC 2759 §8.7) → the `"S=<40 hex>"` string
/// the authenticator returns and the peer verifies.
pub fn generate_authenticator_response(
    password: &str,
    nt_response: &[u8; 24],
    peer_challenge: &[u8; 16],
    authenticator_challenge: &[u8; 16],
    user_name: &[u8],
) -> String {
    let password_hash = nt_password_hash(password);
    let password_hash_hash = hash_nt_password_hash(&password_hash);

    let mut h = Sha1::new();
    h.update(password_hash_hash);
    h.update(nt_response);
    h.update(MAGIC1);
    let digest = h.finalize();

    let challenge = challenge_hash(peer_challenge, authenticator_challenge, user_name);
    let mut h2 = Sha1::new();
    h2.update(digest);
    h2.update(challenge);
    h2.update(MAGIC2);
    let digest2 = h2.finalize();

    let mut s = String::with_capacity(2 + 40);
    s.push_str("S=");
    for b in digest2 {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

// --- EAP-MSCHAPv2 key derivation (RFC 3079 + draft-kamath-pppext-eap-mschapv2) ---

const MPPE_MASTER_MAGIC: &[u8] = b"This is the MPPE Master Key";
const MPPE_MAGIC2: &[u8] = b"On the client side, this is the send key; on the server side, it is the receive key.";
const MPPE_MAGIC3: &[u8] = b"On the client side, this is the receive key; on the server side, it is the send key.";
const SHS_PAD1: [u8; 40] = [0x00; 40];
const SHS_PAD2: [u8; 40] = [0xF2; 40];

/// `GetMasterKey` (RFC 3079 §3.2): `SHA1(PasswordHashHash | NTResponse | magic)[0..16]`.
pub fn get_master_key(password_hash_hash: &[u8; 16], nt_response: &[u8; 24]) -> [u8; 16] {
    let mut h = Sha1::new();
    h.update(password_hash_hash);
    h.update(nt_response);
    h.update(MPPE_MASTER_MAGIC);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// `GetAsymmetricStartKey` (RFC 3079 §3.3) for a 128-bit key:
/// `SHA1(MasterKey | SHSpad1 | magic | SHSpad2)[0..16]`.
fn asymmetric_start_key(master_key: &[u8; 16], magic: &[u8]) -> [u8; 16] {
    let mut h = Sha1::new();
    h.update(master_key);
    h.update(SHS_PAD1);
    h.update(magic);
    h.update(SHS_PAD2);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// Derive the 64-byte EAP-MSCHAPv2 **MSK** from the password and NT-Response.
/// Role-independent — both peer and authenticator compute the same value. IKEv2
/// uses this as the shared key for the AUTH payload when EAP produced it
/// (RFC 7296 §2.16).
///
/// Per RFC 3079 / draft-kamath the keys are taken from the *server's*
/// perspective: `MasterReceiveKey = ASK(…, IsSend=false, IsServer=true) = Magic2`
/// and `MasterSendKey = ASK(…, IsSend=true, IsServer=true) = Magic3`, so
/// `MSK = MasterReceiveKey ‖ MasterSendKey ‖ 32 zero bytes = ASK(Magic2) ‖ ASK(Magic3) ‖ 0…`.
pub fn derive_msk(password: &str, nt_response: &[u8; 24]) -> [u8; 64] {
    let phh = hash_nt_password_hash(&nt_password_hash(password));
    let mk = get_master_key(&phh, nt_response);
    let master_receive_key = asymmetric_start_key(&mk, MPPE_MAGIC2);
    let master_send_key = asymmetric_start_key(&mk, MPPE_MAGIC3);
    let mut msk = [0u8; 64];
    msk[0..16].copy_from_slice(&master_receive_key);
    msk[16..32].copy_from_slice(&master_send_key);
    msk
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2759 §9.2 worked example.
    const USER: &[u8] = b"User";
    const PASSWORD: &str = "clientPass";
    const AUTH_CHALLENGE: [u8; 16] =
        [0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28];
    const PEER_CHALLENGE: [u8; 16] =
        [0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E];

    #[test]
    fn rfc2759_challenge_hash() {
        assert_eq!(
            challenge_hash(&PEER_CHALLENGE, &AUTH_CHALLENGE, USER),
            [0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26]
        );
    }

    #[test]
    fn rfc2759_nt_password_hash() {
        assert_eq!(
            nt_password_hash(PASSWORD),
            [0x44, 0xEB, 0xBA, 0x8D, 0x53, 0x12, 0xB8, 0xD6, 0x11, 0x47, 0x44, 0x11, 0xF5, 0x69, 0x89, 0xAE]
        );
    }

    #[test]
    fn rfc2759_password_hash_hash() {
        let ph = nt_password_hash(PASSWORD);
        assert_eq!(
            hash_nt_password_hash(&ph),
            [0x41, 0xC0, 0x0C, 0x58, 0x4B, 0xD2, 0xD9, 0x1C, 0x40, 0x17, 0xA2, 0xA1, 0x2F, 0xA5, 0x9F, 0x3F]
        );
    }

    #[test]
    fn rfc2759_nt_response() {
        assert_eq!(
            generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USER, PASSWORD),
            [
                0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E, 0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
                0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF
            ]
        );
    }

    #[test]
    fn rfc2759_authenticator_response() {
        let nt = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USER, PASSWORD);
        assert_eq!(
            generate_authenticator_response(PASSWORD, &nt, &PEER_CHALLENGE, &AUTH_CHALLENGE, USER),
            "S=407A5589115FD0D6209F510FE9C04566932CDA56"
        );
    }

    #[test]
    fn magic_constants_are_the_right_length() {
        assert_eq!(MPPE_MAGIC2.len(), 84);
        assert_eq!(MPPE_MAGIC3.len(), 84);
        assert_eq!(MPPE_MASTER_MAGIC.len(), 27);
    }

    #[test]
    fn rfc3079_master_key() {
        // PasswordHashHash from RFC 2759 §9.2; MasterKey from RFC 3079 §4.5.3.
        let phh = [0x41, 0xC0, 0x0C, 0x58, 0x4B, 0xD2, 0xD9, 0x1C, 0x40, 0x17, 0xA2, 0xA1, 0x2F, 0xA5, 0x9F, 0x3F];
        let nt = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USER, PASSWORD);
        assert_eq!(
            get_master_key(&phh, &nt),
            [0xFD, 0xEC, 0xE3, 0x71, 0x7A, 0x8C, 0x83, 0x8C, 0xB3, 0x88, 0xE5, 0x27, 0xAE, 0x3C, 0xDD, 0x31]
        );
    }

    #[test]
    fn msk_is_64_bytes_zero_padded_and_deterministic() {
        let nt = generate_nt_response(&AUTH_CHALLENGE, &PEER_CHALLENGE, USER, PASSWORD);
        let msk = derive_msk(PASSWORD, &nt);
        assert!(msk[32..].iter().all(|&b| b == 0)); // trailing 32 bytes are zero
        assert!(msk[..32].iter().any(|&b| b != 0));
        assert_eq!(msk, derive_msk(PASSWORD, &nt)); // deterministic
        let mut nt2 = nt;
        nt2[0] ^= 0xff;
        assert_ne!(derive_msk(PASSWORD, &nt2), msk);
    }
}
