//! Suite negotiation for `IKE_SA_INIT`.
//!
//! From the initiator's Security Association, pick a proposal we support and
//! describe the chosen suite (transforms + key lengths for the schedule). M1
//! supports X25519 (DH group 31) + PRF-HMAC-SHA256, with AES-GCM-16-256 (AEAD)
//! preferred and AES-CBC-256 + HMAC-SHA2-256-128 as a fallback.
//!
//! Note: an **IKE** proposal carries ENCR, PRF, (INTEG for non-AEAD), and D-H —
//! but *not* ESN. ESN is only valid for ESP/AH (CHILD SA) proposals
//! (RFC 7296 §3.3.3), so it is neither required nor emitted here.

use crate::crypto::KeyLengths;
use crate::ikev2::payload::{protocol_id, transform_id, transform_type, Proposal, SecurityAssociation, Transform};

/// The concrete suite chosen from an initiator proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenSuite {
    pub proposal_num: u8,
    pub encr_id: u16,
    pub encr_key_bits: u16,
    pub prf_id: u16,
    /// `None` for an AEAD cipher (AES-GCM), which needs no separate integrity.
    pub integ_id: Option<u16>,
    pub dh_id: u16,
}

impl ChosenSuite {
    /// Key lengths this suite implies, for [`crate::derive_session_keys`].
    ///
    /// AES-GCM is an AEAD: its `SK_e` carries a 4-byte salt appended to the AES
    /// key (RFC 5282 §4), so the encryption key material is `keybits/8 + 4`.
    /// AES-CBC has no salt.
    pub fn key_lengths(&self) -> KeyLengths {
        let salt = if self.encr_id == transform_id::AES_GCM_16 { 4 } else { 0 };
        KeyLengths {
            prf: 32, // HMAC-SHA256 output
            integ: if self.integ_id.is_some() { 32 } else { 0 },
            encr: (self.encr_key_bits / 8) as usize + salt,
        }
    }

    /// Re-express as a single-transform-per-type proposal to echo in the
    /// `IKE_SA_INIT` response (ENCR, PRF, INTEG when non-AEAD, D-H — no ESN).
    pub fn to_proposal(&self) -> Proposal {
        let mut transforms = vec![
            Transform { transform_type: transform_type::ENCR, transform_id: self.encr_id, key_length: Some(self.encr_key_bits) },
            Transform { transform_type: transform_type::PRF, transform_id: self.prf_id, key_length: None },
        ];
        if let Some(integ) = self.integ_id {
            transforms.push(Transform { transform_type: transform_type::INTEG, transform_id: integ, key_length: None });
        }
        transforms.push(Transform { transform_type: transform_type::DH, transform_id: self.dh_id, key_length: None });
        Proposal { num: self.proposal_num, protocol_id: protocol_id::IKE, spi: Vec::new(), transforms }
    }
}

/// Pick the first initiator proposal we fully support, or `None`.
pub fn select(sa: &SecurityAssociation) -> Option<ChosenSuite> {
    sa.proposals.iter().find_map(select_from_proposal)
}

fn select_from_proposal(proposal: &Proposal) -> Option<ChosenSuite> {
    if proposal.protocol_id != protocol_id::IKE {
        return None;
    }
    // Required PRF; then a DH group we support, preferring X25519, then the MODP
    // groups (which native Android IKEv2 and IKEv1 use).
    if !has(proposal, transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None) {
        return None;
    }
    let dh_id = [transform_id::X25519, transform_id::MODP_2048, transform_id::MODP_1024]
        .into_iter()
        .find(|&g| has(proposal, transform_type::DH, g, None))?;

    // Encryption: prefer AEAD (AES-GCM-16-256), else AES-CBC-256 + HMAC-SHA2-256-128.
    if has(proposal, transform_type::ENCR, transform_id::AES_GCM_16, Some(256)) {
        return Some(ChosenSuite {
            proposal_num: proposal.num,
            encr_id: transform_id::AES_GCM_16,
            encr_key_bits: 256,
            prf_id: transform_id::PRF_HMAC_SHA2_256,
            integ_id: None,
            dh_id,
        });
    }
    if has(proposal, transform_type::ENCR, transform_id::AES_CBC, Some(256))
        && has(proposal, transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None)
    {
        return Some(ChosenSuite {
            proposal_num: proposal.num,
            encr_id: transform_id::AES_CBC,
            encr_key_bits: 256,
            prf_id: transform_id::PRF_HMAC_SHA2_256,
            integ_id: Some(transform_id::AUTH_HMAC_SHA2_256_128),
            dh_id,
        });
    }
    None
}

fn has(proposal: &Proposal, ttype: u8, tid: u16, key_bits: Option<u16>) -> bool {
    proposal.transforms.iter().any(|t| {
        t.transform_type == ttype
            && t.transform_id == tid
            && match key_bits {
                Some(bits) => t.key_length == Some(bits),
                None => true,
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tf(ttype: u8, id: u16, key_length: Option<u16>) -> Transform {
        Transform { transform_type: ttype, transform_id: id, key_length }
    }

    fn proposal(num: u8, transforms: Vec<Transform>) -> SecurityAssociation {
        SecurityAssociation {
            proposals: vec![Proposal { num, protocol_id: protocol_id::IKE, spi: Vec::new(), transforms }],
        }
    }

    #[test]
    fn selects_aead_suite() {
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::AES_GCM_16);
        assert_eq!(chosen.integ_id, None);
        assert_eq!(chosen.key_lengths().encr, 36); // AES-256 key (32) + GCM salt (4)
        assert_eq!(chosen.key_lengths().integ, 0);
        // Echoed IKE proposal has neither INTEG (AEAD) nor ESN.
        let echo = chosen.to_proposal();
        assert!(!echo.transforms.iter().any(|t| t.transform_type == transform_type::INTEG));
        assert!(!echo.transforms.iter().any(|t| t.transform_type == transform_type::ESN));
    }

    #[test]
    fn falls_back_to_cbc_hmac() {
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_CBC, Some(256)),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::AES_CBC);
        assert_eq!(chosen.integ_id, Some(transform_id::AUTH_HMAC_SHA2_256_128));
        assert_eq!(chosen.key_lengths().integ, 32);
    }

    #[test]
    fn rejects_unsupported_dh() {
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, 5, None), // MODP-1536 (group 5) — not implemented
        ]);
        assert!(select(&sa).is_none());
    }

    #[test]
    fn ignores_esn_if_present() {
        // Some initiators erroneously add ESN to the IKE proposal; we ignore it.
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        assert!(select(&sa).is_some());
    }

    #[test]
    fn echoed_proposal_reparses() {
        let sa = proposal(2, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&sa).unwrap();
        let echo = SecurityAssociation { proposals: vec![chosen.to_proposal()] };
        assert_eq!(SecurityAssociation::parse(&echo.to_bytes()).unwrap(), echo);
        assert_eq!(echo.proposals[0].num, 2);
    }
}
