//! Userspace ESP (RFC 4303) in tunnel mode with AES-256-GCM (RFC 4106).
//!
//! `ryke` encrypts and decrypts the tunneled IP packets itself — it does not use
//! the OS kernel's IPsec stack. An ESP packet on the wire:
//!
//! ```text
//! SPI(4) | SeqNum(4) | IV(8) | ciphertext | ICV(16)
//! ```
//!
//! where the ciphertext covers `{ inner IP packet | padding | pad length | next
//! header }` and the AEAD associated data is `SPI | SeqNum`. The GCM nonce is
//! `salt(4) ‖ IV(8)`; the salt comes from the CHILD-SA key material (the last 4
//! bytes of the 36-byte AES-GCM key), and the IV is the packet's sequence number
//! (unique per key, as GCM requires).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::crypto::derive_child_keys;
use crate::error::IkeError;
use crate::role::Role;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 4;
const IV_LEN: usize = 8;
const ICV_LEN: usize = 16;
const ESP_HEADER_LEN: usize = 8; // SPI + SeqNum

/// Next Header values for tunnel-mode inner packets.
pub mod next_header {
    pub const IPV4: u8 = 4;
    pub const IPV6: u8 = 41;
}

/// One direction of an ESP security association: AES-256-GCM, tunnel mode,
/// non-ESN. Holds the SPI to stamp on outbound packets, the key + salt, and the
/// outbound sequence counter.
pub struct EspSa {
    spi: u32,
    key: [u8; KEY_LEN],
    salt: [u8; SALT_LEN],
    seq: u32,
}

impl EspSa {
    /// `key_material` is 36 bytes: a 32-byte AES-256 key + a 4-byte salt, as
    /// produced by [`crate::derive_child_keys`] for AES-GCM.
    pub fn new(spi: u32, key_material: &[u8]) -> Result<Self, IkeError> {
        if key_material.len() != KEY_LEN + SALT_LEN {
            return Err(IkeError::Crypto("ESP key material must be 36 bytes (32-byte key + 4-byte salt)"));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&key_material[..KEY_LEN]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&key_material[KEY_LEN..]);
        Ok(EspSa { spi, key, salt, seq: 0 })
    }

    pub fn spi(&self) -> u32 {
        self.spi
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.key).expect("32-byte AES key")
    }

    fn nonce(&self, iv: &[u8; IV_LEN]) -> [u8; SALT_LEN + IV_LEN] {
        let mut nonce = [0u8; SALT_LEN + IV_LEN];
        nonce[..SALT_LEN].copy_from_slice(&self.salt);
        nonce[SALT_LEN..].copy_from_slice(iv);
        nonce
    }

    /// Encrypt an inner IP packet into an ESP packet (tunnel mode). Advances the
    /// sequence number, which must never repeat under one key.
    pub fn seal(&mut self, inner: &[u8], next_header: u8) -> Result<Vec<u8>, IkeError> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(IkeError::Crypto("ESP sequence number exhausted; rekey required"))?;
        let seq = self.seq;
        let iv = (seq as u64).to_be_bytes();

        // plaintext = inner | padding | pad_len | next_header, padded so that
        // (inner + padding + 2) is a multiple of 4 (RFC 4303 §2.4).
        let unpadded = inner.len() + 2;
        let pad = (4 - (unpadded % 4)) % 4;
        let mut plaintext = Vec::with_capacity(inner.len() + pad + 2);
        plaintext.extend_from_slice(inner);
        for i in 0..pad {
            plaintext.push((i + 1) as u8); // ESP padding is 1, 2, 3, …
        }
        plaintext.push(pad as u8);
        plaintext.push(next_header);

        let mut aad = [0u8; ESP_HEADER_LEN];
        aad[..4].copy_from_slice(&self.spi.to_be_bytes());
        aad[4..].copy_from_slice(&seq.to_be_bytes());

        let ct_and_tag = self
            .cipher()
            .encrypt(Nonce::from_slice(&self.nonce(&iv)), Payload { msg: &plaintext, aad: &aad })
            .map_err(|_| IkeError::Crypto("ESP encryption failed"))?;

        let mut out = Vec::with_capacity(ESP_HEADER_LEN + IV_LEN + ct_and_tag.len());
        out.extend_from_slice(&self.spi.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct_and_tag);
        Ok(out)
    }

    /// Decrypt an ESP packet, returning the inner IP packet and its Next Header.
    /// The packet's SPI must match this SA.
    pub fn open(&self, packet: &[u8]) -> Result<(Vec<u8>, u8), IkeError> {
        let min = ESP_HEADER_LEN + IV_LEN + ICV_LEN;
        if packet.len() < min {
            return Err(IkeError::Truncated { need: min, have: packet.len() });
        }
        let spi = u32::from_be_bytes(packet[0..4].try_into().unwrap());
        if spi != self.spi {
            return Err(IkeError::Crypto("ESP SPI does not match this SA"));
        }
        let iv: [u8; IV_LEN] = packet[8..16].try_into().unwrap();
        let ct_and_tag = &packet[16..];

        let mut aad = [0u8; ESP_HEADER_LEN];
        aad.copy_from_slice(&packet[0..ESP_HEADER_LEN]); // SPI | SeqNum

        let plaintext = self
            .cipher()
            .decrypt(Nonce::from_slice(&self.nonce(&iv)), Payload { msg: ct_and_tag, aad: &aad })
            .map_err(|_| IkeError::BadIntegrity)?;

        // Trailer: [ … | padding(pad_len) | pad_len | next_header ].
        if plaintext.len() < 2 {
            return Err(IkeError::Crypto("ESP plaintext shorter than its trailer"));
        }
        let next_header = plaintext[plaintext.len() - 1];
        let pad_len = plaintext[plaintext.len() - 2] as usize;
        if plaintext.len() < 2 + pad_len {
            return Err(IkeError::Crypto("ESP pad length exceeds plaintext"));
        }
        let inner = plaintext[..plaintext.len() - 2 - pad_len].to_vec();
        Ok((inner, next_header))
    }
}

/// Both ESP directions for one endpoint of a CHILD SA (AES-GCM-256).
pub struct ChildSa {
    /// SA we encrypt outbound traffic on (stamped with the peer's SPI).
    pub outbound: EspSa,
    /// SA we decrypt inbound traffic on (our own SPI).
    pub inbound: EspSa,
}

impl ChildSa {
    /// Derive both ESP SAs from the IKE SA's `SK_d`, the two nonces, our role,
    /// and the two ESP SPIs (`local_spi` is the SPI we chose in our SA payload;
    /// `peer_spi` is the SPI the peer chose). RFC 7296 §2.17: `encr_i` is the
    /// initiator's outbound key, `encr_r` the responder's; a packet carries the
    /// SPI of the SA that *receives* it.
    pub fn derive(sk_d: &[u8], ni: &[u8], nr: &[u8], role: Role, local_spi: u32, peer_spi: u32) -> ChildSa {
        // AES-GCM-256: 36-byte key material per direction, no separate integ key.
        let keys = derive_child_keys(sk_d, ni, nr, KEY_LEN + SALT_LEN, 0);
        let esp = |spi: u32, material: &[u8]| EspSa::new(spi, material).expect("36-byte child key");
        match role {
            Role::Initiator => ChildSa {
                outbound: esp(peer_spi, &keys.encr_i),
                inbound: esp(local_spi, &keys.encr_r),
            },
            Role::Responder => ChildSa {
                outbound: esp(peer_spi, &keys.encr_r),
                inbound: esp(local_spi, &keys.encr_i),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let km = [0x42u8; 36];
        let mut tx = EspSa::new(0xCAFE_BABE, &km).unwrap();
        let rx = EspSa::new(0xCAFE_BABE, &km).unwrap();

        let inner = b"a pretend inner IP packet with some length".to_vec();
        let packet = tx.seal(&inner, next_header::IPV4).unwrap();
        assert_eq!(&packet[0..4], &0xCAFE_BABEu32.to_be_bytes()); // SPI on the wire

        let (out, nh) = rx.open(&packet).unwrap();
        assert_eq!(out, inner);
        assert_eq!(nh, next_header::IPV4);
    }

    #[test]
    fn various_lengths_roundtrip_with_correct_padding() {
        let km = [9u8; 36];
        for len in 0..40 {
            let mut tx = EspSa::new(1, &km).unwrap();
            let rx = EspSa::new(1, &km).unwrap();
            let inner: Vec<u8> = (0..len as u8).collect();
            let packet = tx.seal(&inner, next_header::IPV6).unwrap();
            // ciphertext (after SPI|Seq|IV, before the 16-byte tag) is 4-aligned.
            let ct_len = packet.len() - ESP_HEADER_LEN - IV_LEN - ICV_LEN;
            assert_eq!(ct_len % 4, 0, "len {len}");
            let (out, nh) = rx.open(&packet).unwrap();
            assert_eq!(out, inner);
            assert_eq!(nh, next_header::IPV6);
        }
    }

    #[test]
    fn sequence_increments_and_nonces_differ() {
        let mut tx = EspSa::new(1, &[1u8; 36]).unwrap();
        let p1 = tx.seal(b"x", 4).unwrap();
        let p2 = tx.seal(b"x", 4).unwrap();
        assert_ne!(&p1[4..8], &p2[4..8]); // sequence number advanced
        assert_ne!(p1, p2); // distinct ciphertext (distinct nonce)
    }

    #[test]
    fn wrong_spi_is_rejected() {
        let mut tx = EspSa::new(10, &[2u8; 36]).unwrap();
        let rx = EspSa::new(11, &[2u8; 36]).unwrap();
        let packet = tx.seal(b"hello", 4).unwrap();
        assert!(matches!(rx.open(&packet), Err(IkeError::Crypto(_))));
    }

    #[test]
    fn tampering_and_wrong_key_are_rejected() {
        let mut tx = EspSa::new(5, &[3u8; 36]).unwrap();
        let rx = EspSa::new(5, &[3u8; 36]).unwrap();
        let mut packet = tx.seal(b"hello world", 4).unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert_eq!(rx.open(&packet).unwrap_err(), IkeError::BadIntegrity);

        let mut tx2 = EspSa::new(5, &[7u8; 36]).unwrap();
        let rx2 = EspSa::new(5, &[8u8; 36]).unwrap();
        let good = tx2.seal(b"y", 4).unwrap();
        assert_eq!(rx2.open(&good).unwrap_err(), IkeError::BadIntegrity);
    }
}
