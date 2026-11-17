//! IKEv1 payload bodies (RFC 2408 §3): the SA/Proposal/Transform tree with its
//! TLV attributes, and the ID payload. KE / Nonce / HASH / VID payload bodies
//! are raw byte blobs, so they need no typed struct — the generic
//! [`super::isakmp::Payload`] already carries them.

use super::isakmp::{self, payload};
use crate::error::IkeError;

/// IPsec DOI + "identity only" situation (RFC 2407).
pub const IPSEC_DOI: u32 = 1;
pub const SIT_IDENTITY_ONLY: u32 = 1;

/// Phase-1 (IKE SA) transform attribute types (RFC 2409 App. A).
pub mod attr {
    pub const ENCRYPTION: u16 = 1;
    pub const HASH: u16 = 2;
    pub const AUTH_METHOD: u16 = 3;
    pub const GROUP_DESC: u16 = 4;
    pub const LIFE_TYPE: u16 = 11;
    pub const LIFE_DURATION: u16 = 12;
    pub const KEY_LENGTH: u16 = 14;
}

/// Encryption algorithm values (attr `ENCRYPTION`).
pub mod enc {
    pub const DES_CBC: u16 = 1;
    pub const TRIPLE_DES_CBC: u16 = 5;
    pub const AES_CBC: u16 = 7;
}

/// Hash algorithm values (attr `HASH`).
pub mod hash {
    pub const MD5: u16 = 1;
    pub const SHA1: u16 = 2;
    pub const SHA2_256: u16 = 4;
    pub const SHA2_384: u16 = 5;
    pub const SHA2_512: u16 = 6;
}

/// Authentication method values (attr `AUTH_METHOD`).
pub mod auth {
    pub const PSK: u16 = 1;
    pub const RSA_SIG: u16 = 3;
    /// XAUTHInitPreShared — Android's "IPSec Xauth PSK" advertises this, and it
    /// signals that an Xauth exchange follows Phase 1.
    pub const XAUTH_INIT_PSK: u16 = 65001;
}

/// Life-type values (attr `LIFE_TYPE`).
pub mod life {
    pub const SECONDS: u16 = 1;
    pub const KILOBYTES: u16 = 2;
}

/// ISAKMP protocol IDs.
pub mod protocol {
    pub const ISAKMP: u8 = 1;
    pub const ESP: u8 = 3;
}

/// IKEv1 identification types (RFC 2407 §4.6.2.1).
pub mod id_type {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const USER_FQDN: u8 = 3;
    pub const IPV4_ADDR_SUBNET: u8 = 4;
    pub const KEY_ID: u8 = 11;
}

/// A Transform attribute — either a 2-byte short (TV) or a variable long (TLV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrValue {
    Short(u16),
    Long(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// The 15-bit attribute type (the format/AF bit is not stored here).
    pub attr_type: u16,
    pub value: AttrValue,
}

impl Attribute {
    pub fn short(attr_type: u16, v: u16) -> Self {
        Attribute { attr_type, value: AttrValue::Short(v) }
    }

    /// A long (TLV) attribute holding a big-endian integer, e.g. a lifetime.
    pub fn long_u32(attr_type: u16, v: u32) -> Self {
        Attribute { attr_type, value: AttrValue::Long(v.to_be_bytes().to_vec()) }
    }

    /// A long (TLV) attribute holding raw bytes, e.g. an XAUTH username or an IP.
    pub fn long_bytes(attr_type: u16, v: impl Into<Vec<u8>>) -> Self {
        Attribute { attr_type, value: AttrValue::Long(v.into()) }
    }

    /// The value as raw bytes (long form; short form serialised big-endian).
    pub fn bytes(&self) -> Vec<u8> {
        match &self.value {
            AttrValue::Short(v) => v.to_be_bytes().to_vec(),
            AttrValue::Long(d) => d.clone(),
        }
    }

    /// Parse one attribute; returns it and the number of bytes consumed.
    pub fn parse(b: &[u8]) -> Result<(Attribute, usize), IkeError> {
        if b.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: b.len() });
        }
        let type_af = u16::from_be_bytes([b[0], b[1]]);
        let attr_type = type_af & 0x7FFF;
        if type_af & 0x8000 != 0 {
            // Short form (TV): value in the length field.
            Ok((Attribute { attr_type, value: AttrValue::Short(u16::from_be_bytes([b[2], b[3]])) }, 4))
        } else {
            let len = u16::from_be_bytes([b[2], b[3]]) as usize;
            if 4 + len > b.len() {
                return Err(IkeError::BadLength { declared: 4 + len, available: b.len() });
            }
            Ok((Attribute { attr_type, value: AttrValue::Long(b[4..4 + len].to_vec()) }, 4 + len))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match &self.value {
            AttrValue::Short(v) => {
                let mut out = (self.attr_type | 0x8000).to_be_bytes().to_vec();
                out.extend_from_slice(&v.to_be_bytes());
                out
            }
            AttrValue::Long(d) => {
                let mut out = self.attr_type.to_be_bytes().to_vec();
                out.extend_from_slice(&(d.len() as u16).to_be_bytes());
                out.extend_from_slice(d);
                out
            }
        }
    }

    /// The value as a u16 (short form, or a 2-byte long form).
    pub fn as_u16(&self) -> Option<u16> {
        match &self.value {
            AttrValue::Short(v) => Some(*v),
            AttrValue::Long(d) if d.len() == 2 => Some(u16::from_be_bytes([d[0], d[1]])),
            _ => None,
        }
    }
}

pub fn parse_attributes(mut b: &[u8]) -> Result<Vec<Attribute>, IkeError> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let (attr, used) = Attribute::parse(b)?;
        out.push(attr);
        b = &b[used..];
    }
    Ok(out)
}

/// A single Transform inside a Proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub num: u8,
    pub transform_id: u8,
    pub attributes: Vec<Attribute>,
}

impl Transform {
    /// Parse a Transform payload body (after the 4-byte generic header):
    /// `[num][transform-id][RESERVED2][attributes…]`.
    pub fn parse(body: &[u8]) -> Result<Transform, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(Transform {
            num: body[0],
            transform_id: body[1],
            attributes: parse_attributes(&body[4..])?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.num, self.transform_id, 0, 0];
        for a in &self.attributes {
            out.extend_from_slice(&a.to_bytes());
        }
        out
    }

    /// Look up a transform attribute's u16 value.
    pub fn attr(&self, attr_type: u16) -> Option<u16> {
        self.attributes.iter().find(|a| a.attr_type == attr_type).and_then(|a| a.as_u16())
    }
}

/// A Proposal (one protocol) carrying its Transforms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub num: u8,
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    /// Parse a Proposal payload body:
    /// `[num][protocol][spi-size][#transforms][SPI][transform payloads…]`.
    pub fn parse(body: &[u8]) -> Result<Proposal, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let spi_size = body[2] as usize;
        if 4 + spi_size > body.len() {
            return Err(IkeError::BadLength { declared: 4 + spi_size, available: body.len() });
        }
        let spi = body[4..4 + spi_size].to_vec();
        let transforms = isakmp::parse_payloads(payload::TRANSFORM, &body[4 + spi_size..])?
            .into_iter()
            .map(|p| Transform::parse(&p.data))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Proposal { num: body[0], protocol_id: body[1], spi, transforms })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let tf_chain: Vec<(u8, Vec<u8>)> =
            self.transforms.iter().map(|t| (payload::TRANSFORM, t.to_bytes())).collect();
        let (_first, tf_body) = isakmp::encode_payloads(&tf_chain);
        let mut out = vec![self.num, self.protocol_id, self.spi.len() as u8, self.transforms.len() as u8];
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&tf_body);
        out
    }
}

/// The Security Association payload body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaPayload {
    pub doi: u32,
    pub situation: u32,
    pub proposals: Vec<Proposal>,
}

impl SaPayload {
    /// Parse an SA payload body: `[DOI(4)][Situation(4)][proposal payloads…]`.
    pub fn parse(body: &[u8]) -> Result<SaPayload, IkeError> {
        if body.len() < 8 {
            return Err(IkeError::Truncated { need: 8, have: body.len() });
        }
        let doi = u32::from_be_bytes(body[0..4].try_into().unwrap());
        let situation = u32::from_be_bytes(body[4..8].try_into().unwrap());
        let proposals = isakmp::parse_payloads(payload::PROPOSAL, &body[8..])?
            .into_iter()
            .map(|p| Proposal::parse(&p.data))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SaPayload { doi, situation, proposals })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let prop_chain: Vec<(u8, Vec<u8>)> =
            self.proposals.iter().map(|p| (payload::PROPOSAL, p.to_bytes())).collect();
        let (_first, prop_body) = isakmp::encode_payloads(&prop_chain);
        let mut out = Vec::with_capacity(8 + prop_body.len());
        out.extend_from_slice(&self.doi.to_be_bytes());
        out.extend_from_slice(&self.situation.to_be_bytes());
        out.extend_from_slice(&prop_body);
        out
    }
}

/// The Identification payload body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Id {
    pub id_type: u8,
    pub protocol: u8,
    pub port: u16,
    pub data: Vec<u8>,
}

impl Id {
    pub fn ipv4(addr: [u8; 4]) -> Self {
        Id { id_type: id_type::IPV4_ADDR, protocol: 0, port: 0, data: addr.to_vec() }
    }

    /// Parse an ID payload body: `[id-type][protocol][port(2)][data…]`.
    pub fn parse(body: &[u8]) -> Result<Id, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(Id {
            id_type: body[0],
            protocol: body[1],
            port: u16::from_be_bytes([body[2], body[3]]),
            data: body[4..].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.id_type, self.protocol];
        out.extend_from_slice(&self.port.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_short_and_long_roundtrip() {
        let s = Attribute::short(attr::ENCRYPTION, enc::AES_CBC);
        let (p, n) = Attribute::parse(&s.to_bytes()).unwrap();
        assert_eq!((p, n), (s.clone(), 4));
        assert_eq!(s.as_u16(), Some(enc::AES_CBC));

        let l = Attribute::long_u32(attr::LIFE_DURATION, 28800);
        let bytes = l.to_bytes();
        let (p2, n2) = Attribute::parse(&bytes).unwrap();
        assert_eq!(p2, l);
        assert_eq!(n2, 8); // 4 header + 4 value
    }

    /// A transform resembling one of Android's: AES-256 / SHA2-256 / group 2 /
    /// XAUTHInitPreShared, 28800s.
    fn android_transform() -> Transform {
        Transform {
            num: 1,
            transform_id: 1, // KEY_IKE
            attributes: vec![
                Attribute::short(attr::ENCRYPTION, enc::AES_CBC),
                Attribute::short(attr::KEY_LENGTH, 256),
                Attribute::short(attr::HASH, hash::SHA2_256),
                Attribute::short(attr::GROUP_DESC, 2),
                Attribute::short(attr::AUTH_METHOD, auth::XAUTH_INIT_PSK),
                Attribute::short(attr::LIFE_TYPE, life::SECONDS),
                Attribute::long_u32(attr::LIFE_DURATION, 28800),
            ],
        }
    }

    #[test]
    fn transform_roundtrips_and_reads_attrs() {
        let t = android_transform();
        let parsed = Transform::parse(&t.to_bytes()).unwrap();
        assert_eq!(parsed, t);
        assert_eq!(parsed.attr(attr::ENCRYPTION), Some(enc::AES_CBC));
        assert_eq!(parsed.attr(attr::KEY_LENGTH), Some(256));
        assert_eq!(parsed.attr(attr::GROUP_DESC), Some(2));
        assert_eq!(parsed.attr(attr::AUTH_METHOD), Some(auth::XAUTH_INIT_PSK));
    }

    #[test]
    fn sa_with_multiple_transforms_roundtrips() {
        // Two transforms in one proposal (as Android sends 16).
        let mut t2 = android_transform();
        t2.num = 2;
        t2.attributes[2] = Attribute::short(attr::HASH, hash::SHA1);
        let sa = SaPayload {
            doi: IPSEC_DOI,
            situation: SIT_IDENTITY_ONLY,
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol::ISAKMP,
                spi: Vec::new(),
                transforms: vec![android_transform(), t2],
            }],
        };
        let parsed = SaPayload::parse(&sa.to_bytes()).unwrap();
        assert_eq!(parsed, sa);
        assert_eq!(parsed.proposals[0].transforms.len(), 2);
        assert_eq!(parsed.proposals[0].transforms[1].attr(attr::HASH), Some(hash::SHA1));
    }

    #[test]
    fn id_roundtrips() {
        let id = Id { id_type: id_type::KEY_ID, protocol: 0, port: 0, data: b"groupname".to_vec() };
        assert_eq!(Id::parse(&id.to_bytes()).unwrap(), id);
        assert_eq!(Id::ipv4([10, 0, 0, 1]).data, vec![10, 0, 0, 1]);
    }
}
