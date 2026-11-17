//! Typed IKEv2 payload bodies needed for `IKE_SA_INIT` (M1): the Security
//! Association payload with its Proposal/Transform substructures (RFC 7296
//! §3.3), Key Exchange (§3.4), and Nonce (§3.9).
//!
//! Each type parses/serializes its *body* — the bytes after the 4-byte generic
//! payload header. Chaining payloads into a full message (adding those generic
//! headers) is the message-builder's job.

use std::net::Ipv4Addr;

use crate::error::IkeError;

/// Transform types (RFC 7296 §3.3.2).
pub mod transform_type {
    pub const ENCR: u8 = 1;
    pub const PRF: u8 = 2;
    pub const INTEG: u8 = 3;
    pub const DH: u8 = 4;
    pub const ESN: u8 = 5;
}

/// A selection of transform IDs we care about at M1.
pub mod transform_id {
    // ENCR
    pub const AES_CBC: u16 = 12;
    pub const AES_GCM_16: u16 = 20;
    // PRF
    pub const PRF_HMAC_SHA2_256: u16 = 5;
    // INTEG
    pub const AUTH_HMAC_SHA2_256_128: u16 = 12;
    // DH
    pub const MODP_1024: u16 = 2;
    pub const MODP_2048: u16 = 14;
    pub const X25519: u16 = 31;
    // ESN
    pub const ESN_NONE: u16 = 0;
    pub const ESN_ENABLED: u16 = 1;
}

/// IKEv2 protocol IDs (RFC 7296 §3.3.1).
pub mod protocol_id {
    pub const IKE: u8 = 1;
    pub const AH: u8 = 2;
    pub const ESP: u8 = 3;
}

/// The Key Length transform attribute type (RFC 7296 §3.3.5).
const ATTR_KEY_LENGTH: u16 = 14;
/// Attribute Format bit: set = TV (value inline), clear = TLV.
const ATTR_FORMAT_TV: u16 = 0x8000;

fn u16be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// One Transform substructure. We model the single attribute that IKEv2 ever
/// negotiates in practice — Key Length; other attributes are ignored on parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub transform_type: u8,
    pub transform_id: u16,
    /// Key Length attribute (bits), e.g. `Some(256)` for AES-256.
    pub key_length: Option<u16>,
}

impl Transform {
    /// Parse one transform from the front of `buf`; returns it and the number of
    /// bytes consumed (its declared Transform Length).
    fn parse(buf: &[u8]) -> Result<(Transform, usize), IkeError> {
        if buf.len() < 8 {
            return Err(IkeError::Truncated { need: 8, have: buf.len() });
        }
        let length = u16be(buf, 2) as usize;
        if length < 8 {
            return Err(IkeError::ShortPayload(length as u16));
        }
        if length > buf.len() {
            return Err(IkeError::BadLength { declared: length, available: buf.len() });
        }
        let transform_type = buf[4];
        let transform_id = u16be(buf, 6);
        let key_length = Self::find_key_length(&buf[8..length])?;
        Ok((Transform { transform_type, transform_id, key_length }, length))
    }

    fn find_key_length(mut attrs: &[u8]) -> Result<Option<u16>, IkeError> {
        let mut key_length = None;
        while attrs.len() >= 4 {
            let header = u16be(attrs, 0);
            let attr_type = header & 0x7fff;
            if header & ATTR_FORMAT_TV != 0 {
                // TV: 2-byte value inline.
                if attr_type == ATTR_KEY_LENGTH {
                    key_length = Some(u16be(attrs, 2));
                }
                attrs = &attrs[4..];
            } else {
                // TLV: 2-byte length then value.
                let len = u16be(attrs, 2) as usize;
                if 4 + len > attrs.len() {
                    return Err(IkeError::BadLength { declared: 4 + len, available: attrs.len() });
                }
                attrs = &attrs[4 + len..];
            }
        }
        Ok(key_length)
    }

    fn write(&self, out: &mut Vec<u8>, is_last: bool) {
        let mut attrs = Vec::new();
        if let Some(key_length) = self.key_length {
            push_u16(&mut attrs, ATTR_FORMAT_TV | ATTR_KEY_LENGTH);
            push_u16(&mut attrs, key_length);
        }
        let length = 8 + attrs.len();
        out.push(if is_last { 0 } else { 3 }); // Last Substruc
        out.push(0); // RESERVED
        push_u16(out, length as u16);
        out.push(self.transform_type);
        out.push(0); // RESERVED
        push_u16(out, self.transform_id);
        out.extend_from_slice(&attrs);
    }
}

/// One Proposal substructure (RFC 7296 §3.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub num: u8,
    pub protocol_id: u8,
    /// SPI (empty in the initial IKE SA proposal).
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    fn parse(buf: &[u8]) -> Result<(Proposal, usize), IkeError> {
        if buf.len() < 8 {
            return Err(IkeError::Truncated { need: 8, have: buf.len() });
        }
        let length = u16be(buf, 2) as usize;
        if length < 8 {
            return Err(IkeError::ShortPayload(length as u16));
        }
        if length > buf.len() {
            return Err(IkeError::BadLength { declared: length, available: buf.len() });
        }
        let num = buf[4];
        let protocol_id = buf[5];
        let spi_size = buf[6] as usize;
        let transform_count = buf[7] as usize;
        if 8 + spi_size > length {
            return Err(IkeError::BadLength { declared: 8 + spi_size, available: length });
        }
        let spi = buf[8..8 + spi_size].to_vec();

        let mut off = 8 + spi_size;
        let mut transforms = Vec::with_capacity(transform_count);
        for _ in 0..transform_count {
            let (transform, consumed) = Transform::parse(&buf[off..length])?;
            transforms.push(transform);
            off += consumed;
        }
        Ok((Proposal { num, protocol_id, spi, transforms }, length))
    }

    fn write(&self, out: &mut Vec<u8>, is_last: bool) {
        let mut body = Vec::new();
        for (i, transform) in self.transforms.iter().enumerate() {
            transform.write(&mut body, i + 1 == self.transforms.len());
        }
        let length = 8 + self.spi.len() + body.len();
        out.push(if is_last { 0 } else { 2 }); // Last Substruc
        out.push(0); // RESERVED
        push_u16(out, length as u16);
        out.push(self.num);
        out.push(self.protocol_id);
        out.push(self.spi.len() as u8);
        out.push(self.transforms.len() as u8);
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&body);
    }
}

/// The Security Association payload body: a list of proposals (RFC 7296 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAssociation {
    pub proposals: Vec<Proposal>,
}

impl SecurityAssociation {
    pub fn parse(body: &[u8]) -> Result<SecurityAssociation, IkeError> {
        let mut off = 0;
        let mut proposals = Vec::new();
        while off < body.len() {
            let (proposal, consumed) = Proposal::parse(&body[off..])?;
            proposals.push(proposal);
            off += consumed;
        }
        Ok(SecurityAssociation { proposals })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, proposal) in self.proposals.iter().enumerate() {
            proposal.write(&mut out, i + 1 == self.proposals.len());
        }
        out
    }
}

/// Key Exchange payload body (RFC 7296 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchange {
    pub dh_group: u16,
    pub data: Vec<u8>,
}

impl KeyExchange {
    pub fn parse(body: &[u8]) -> Result<KeyExchange, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(KeyExchange { dh_group: u16be(body, 0), data: body[4..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        push_u16(&mut out, self.dh_group);
        push_u16(&mut out, 0); // RESERVED
        out.extend_from_slice(&self.data);
        out
    }
}

/// Nonce payload body (RFC 7296 §3.9) — just the nonce bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    pub data: Vec<u8>,
}

impl Nonce {
    pub fn parse(body: &[u8]) -> Nonce {
        Nonce { data: body.to_vec() }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// Identification types (RFC 7296 §3.5).
pub mod id_type {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const RFC822_ADDR: u8 = 3;
    pub const IPV6_ADDR: u8 = 5;
    pub const KEY_ID: u8 = 11;
}

/// Identification payload body (RFC 7296 §3.5). IDi and IDr share this format.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identification {
    pub id_type: u8,
    pub data: Vec<u8>,
}

impl Identification {
    /// A fully-qualified-domain-name identity (ID_FQDN).
    pub fn fqdn(name: &str) -> Self {
        Identification { id_type: id_type::FQDN, data: name.as_bytes().to_vec() }
    }

    pub fn parse(body: &[u8]) -> Result<Identification, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(Identification { id_type: body[0], data: body[4..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push(self.id_type);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        out.extend_from_slice(&self.data);
        out
    }
}

/// Authentication methods (RFC 7296 §3.8, RFC 7427).
pub mod auth_method {
    pub const RSA_SIG: u8 = 1;
    /// Shared Key Message Integrity Code (PSK).
    pub const SHARED_KEY: u8 = 2;
    pub const DSS_SIG: u8 = 3;
    /// ECDSA-256 with SHA-256 on the P-256 curve (RFC 4754) — the *classic*
    /// ECDSA auth, used when the peer does not negotiate RFC 7427 Digital
    /// Signature (e.g. an iOS EAP client sends no SIGNATURE_HASH_ALGORITHMS).
    /// AUTH Data is the raw `r || s` (64 bytes), no algorithm wrapper.
    pub const ECDSA_SHA256_P256: u8 = 9;
    /// Digital Signature (RFC 7427) — the modern cert-auth method.
    pub const DIGITAL_SIGNATURE: u8 = 14;
}

/// Authentication payload body (RFC 7296 §3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    pub method: u8,
    pub data: Vec<u8>,
}

impl Authentication {
    pub fn parse(body: &[u8]) -> Result<Authentication, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(Authentication { method: body[0], data: body[4..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push(self.method);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        out.extend_from_slice(&self.data);
        out
    }
}

/// Traffic Selector types (RFC 7296 §3.13.1).
pub mod ts_type {
    pub const IPV4_ADDR_RANGE: u8 = 7;
    pub const IPV6_ADDR_RANGE: u8 = 8;
}

/// One Traffic Selector (RFC 7296 §3.13.1): a protocol + port range + address range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelector {
    pub ts_type: u8,
    pub ip_protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: Vec<u8>,
    pub end_addr: Vec<u8>,
}

impl TrafficSelector {
    /// The "everything" IPv4 selector: any protocol, all ports, 0.0.0.0–255.255.255.255.
    pub fn ipv4_any() -> Self {
        TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0, 0, 0, 0],
            end_addr: vec![255, 255, 255, 255],
        }
    }

    /// A single-host IPv4 selector (a /32 range, any protocol/port) — what a
    /// responder narrows TSi to when it assigns the initiator one address.
    pub fn ipv4_host(addr: Ipv4Addr) -> Self {
        TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: addr.octets().to_vec(),
            end_addr: addr.octets().to_vec(),
        }
    }

    fn parse(buf: &[u8]) -> Result<(TrafficSelector, usize), IkeError> {
        if buf.len() < 8 {
            return Err(IkeError::Truncated { need: 8, have: buf.len() });
        }
        let length = u16be(buf, 2) as usize;
        if length < 8 || length > buf.len() || (length - 8) % 2 != 0 {
            return Err(IkeError::BadLength { declared: length, available: buf.len() });
        }
        let addr_len = (length - 8) / 2;
        Ok((
            TrafficSelector {
                ts_type: buf[0],
                ip_protocol: buf[1],
                start_port: u16be(buf, 4),
                end_port: u16be(buf, 6),
                start_addr: buf[8..8 + addr_len].to_vec(),
                end_addr: buf[8 + addr_len..8 + 2 * addr_len].to_vec(),
            },
            length,
        ))
    }

    fn write(&self, out: &mut Vec<u8>) {
        let length = 8 + self.start_addr.len() + self.end_addr.len();
        out.push(self.ts_type);
        out.push(self.ip_protocol);
        push_u16(out, length as u16);
        push_u16(out, self.start_port);
        push_u16(out, self.end_port);
        out.extend_from_slice(&self.start_addr);
        out.extend_from_slice(&self.end_addr);
    }
}

/// A Traffic Selector payload body — TSi or TSr (RFC 7296 §3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelectors {
    pub selectors: Vec<TrafficSelector>,
}

impl TrafficSelectors {
    pub fn parse(body: &[u8]) -> Result<TrafficSelectors, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let count = body[0] as usize;
        let mut off = 4; // skip Number of TSs (1) + RESERVED (3)
        let mut selectors = Vec::with_capacity(count);
        for _ in 0..count {
            let (ts, consumed) = TrafficSelector::parse(&body[off..])?;
            selectors.push(ts);
            off += consumed;
        }
        Ok(TrafficSelectors { selectors })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.selectors.len() as u8);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        for ts in &self.selectors {
            ts.write(&mut out);
        }
        out
    }
}

/// Configuration payload (CP) types (RFC 7296 §3.15.1).
pub mod cfg_type {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    pub const SET: u8 = 3;
    pub const ACK: u8 = 4;
}

/// Configuration Attribute types (RFC 7296 §3.15.1 + IANA registry). Only the
/// IPv4 attributes a client needs to bring up a tunnel interface are named.
pub mod config_attr {
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
}

/// One IKEv2 Configuration Attribute (RFC 7296 §3.15.1): a 15-bit type (the top
/// "reserved" bit is always clear — the TV/AF short form of IKEv1 is not used in
/// IKEv2), a 2-byte length, then the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAttr {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

impl ConfigAttr {
    /// A 4-byte IPv4-valued attribute (address/netmask/DNS).
    pub fn ipv4(attr_type: u16, addr: Ipv4Addr) -> Self {
        ConfigAttr { attr_type, value: addr.octets().to_vec() }
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_u16(out, self.attr_type & 0x7fff); // top bit reserved, MUST be 0
        push_u16(out, self.value.len() as u16);
        out.extend_from_slice(&self.value);
    }

    fn parse(buf: &[u8]) -> Result<(ConfigAttr, usize), IkeError> {
        if buf.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: buf.len() });
        }
        let attr_type = u16be(buf, 0) & 0x7fff;
        let len = u16be(buf, 2) as usize;
        if 4 + len > buf.len() {
            return Err(IkeError::BadLength { declared: 4 + len, available: buf.len() });
        }
        Ok((ConfigAttr { attr_type, value: buf[4..4 + len].to_vec() }, 4 + len))
    }
}

/// A Configuration payload body — CP (payload type 47, RFC 7296 §3.15). Carries
/// the responder's inner-IP assignment (CFG_REPLY) that a native IKEv2 client
/// (iOS/Android/strongSwan) needs to configure its tunnel interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    pub cfg_type: u8,
    pub attrs: Vec<ConfigAttr>,
}

impl Configuration {
    /// A CFG_REPLY assigning the peer an inner IPv4, with optional netmask + DNS.
    pub fn reply_ipv4(addr: Ipv4Addr, netmask: Option<Ipv4Addr>, dns: Option<Ipv4Addr>) -> Self {
        let mut attrs = vec![ConfigAttr::ipv4(config_attr::INTERNAL_IP4_ADDRESS, addr)];
        if let Some(m) = netmask {
            attrs.push(ConfigAttr::ipv4(config_attr::INTERNAL_IP4_NETMASK, m));
        }
        if let Some(d) = dns {
            attrs.push(ConfigAttr::ipv4(config_attr::INTERNAL_IP4_DNS, d));
        }
        Configuration { cfg_type: cfg_type::REPLY, attrs }
    }

    /// A CFG_REQUEST asking the responder to assign an inner IPv4 (an empty
    /// INTERNAL_IP4_ADDRESS attribute), as a native client sends.
    pub fn request_ipv4() -> Self {
        Configuration {
            cfg_type: cfg_type::REQUEST,
            attrs: vec![ConfigAttr { attr_type: config_attr::INTERNAL_IP4_ADDRESS, value: Vec::new() }],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.cfg_type);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        for a in &self.attrs {
            a.write(&mut out);
        }
        out
    }

    pub fn parse(body: &[u8]) -> Result<Configuration, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let cfg_type = body[0];
        let mut off = 4; // skip CFG type (1) + RESERVED (3)
        let mut attrs = Vec::new();
        while off < body.len() {
            let (a, consumed) = ConfigAttr::parse(&body[off..])?;
            attrs.push(a);
            off += consumed;
        }
        Ok(Configuration { cfg_type, attrs })
    }

    /// The first INTERNAL_IP4_ADDRESS attribute value, if present and well-formed.
    pub fn assigned_ipv4(&self) -> Option<Ipv4Addr> {
        self.attrs
            .iter()
            .find(|a| a.attr_type == config_attr::INTERNAL_IP4_ADDRESS && a.value.len() == 4)
            .map(|a| Ipv4Addr::new(a.value[0], a.value[1], a.value[2], a.value[3]))
    }
}

/// Notify Message Types (RFC 7296 §3.10.1 and later). Types < 16384 are errors;
/// ≥ 16384 are status.
pub mod notify_type {
    // Errors
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    pub const TS_UNACCEPTABLE: u16 = 38;
    // Status
    pub const INITIAL_CONTACT: u16 = 16384;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const REKEY_SA: u16 = 16393;
    // MOBIKE (RFC 4555)
    pub const MOBIKE_SUPPORTED: u16 = 16396;
    pub const ADDITIONAL_IP4_ADDRESS: u16 = 16397;
    pub const ADDITIONAL_IP6_ADDRESS: u16 = 16398;
    pub const NO_ADDITIONAL_ADDRESSES: u16 = 16399;
    pub const UPDATE_SA_ADDRESSES: u16 = 16400;
    pub const COOKIE2: u16 = 16401;
    pub const NO_NATS_ALLOWED: u16 = 16402;
    pub const IKEV2_FRAGMENTATION_SUPPORTED: u16 = 16430;
    /// The initiator lists the signature hashes it supports (RFC 7427 §4); a
    /// responder doing Digital Signature auth must answer with a matching one.
    pub const SIGNATURE_HASH_ALGORITHMS: u16 = 16431;
}

/// Hash Algorithm identifiers for `SIGNATURE_HASH_ALGORITHMS` (RFC 7427 §4).
pub mod sighash {
    pub const SHA1: u16 = 1;
    pub const SHA2_256: u16 = 2;
    pub const SHA2_384: u16 = 3;
    pub const SHA2_512: u16 = 4;
}

/// Certificate encodings (RFC 7296 §3.6, IANA registry).
pub mod cert_encoding {
    /// A DER X.509 certificate whose public key validates the AUTH signature.
    pub const X509_SIGNATURE: u8 = 4;
}

/// Notify payload body (RFC 7296 §3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub notify_type: u16,
    pub data: Vec<u8>,
}

impl Notify {
    /// A status/error notify not tied to a CHILD SA (no protocol, no SPI).
    pub fn status(notify_type: u16, data: Vec<u8>) -> Self {
        Notify { protocol_id: 0, spi: Vec::new(), notify_type, data }
    }

    /// Whether this is an error notify (type < 16384).
    pub fn is_error(&self) -> bool {
        self.notify_type < 16384
    }

    pub fn parse(body: &[u8]) -> Result<Notify, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let spi_size = body[1] as usize;
        if 4 + spi_size > body.len() {
            return Err(IkeError::BadLength { declared: 4 + spi_size, available: body.len() });
        }
        Ok(Notify {
            protocol_id: body[0],
            spi: body[4..4 + spi_size].to_vec(),
            notify_type: u16be(body, 2),
            data: body[4 + spi_size..].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.spi.len() + self.data.len());
        out.push(self.protocol_id);
        out.push(self.spi.len() as u8);
        push_u16(&mut out, self.notify_type);
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }
}

/// Delete payload (RFC 7296 §3.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delete {
    pub protocol_id: u8,
    /// ESP/AH SPIs to delete (4 bytes each). Empty with `protocol_id == IKE`
    /// means "delete this IKE SA" (and thereby all its CHILD SAs).
    pub spis: Vec<u32>,
}

impl Delete {
    /// Delete the whole IKE SA.
    pub fn ike_sa() -> Self {
        Delete { protocol_id: protocol_id::IKE, spis: Vec::new() }
    }

    /// Delete the given ESP CHILD SAs by SPI.
    pub fn esp(spis: Vec<u32>) -> Self {
        Delete { protocol_id: protocol_id::ESP, spis }
    }

    pub fn parse(body: &[u8]) -> Result<Delete, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let protocol_id = body[0];
        let spi_size = body[1] as usize;
        let num = u16be(body, 2) as usize;
        let mut spis = Vec::with_capacity(num);
        match spi_size {
            0 => {} // IKE SA delete carries no SPIs
            4 => {
                if 4 + num * 4 > body.len() {
                    return Err(IkeError::BadLength { declared: 4 + num * 4, available: body.len() });
                }
                for i in 0..num {
                    spis.push(u32::from_be_bytes(body[4 + i * 4..8 + i * 4].try_into().unwrap()));
                }
            }
            _ => return Err(IkeError::Crypto("unsupported Delete SPI size")),
        }
        Ok(Delete { protocol_id, spis })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let spi_size: u8 = if self.protocol_id == protocol_id::IKE { 0 } else { 4 };
        let mut out = Vec::with_capacity(4 + self.spis.len() * 4);
        out.push(self.protocol_id);
        out.push(spi_size);
        push_u16(&mut out, self.spis.len() as u16);
        for spi in &self.spis {
            out.extend_from_slice(&spi.to_be_bytes());
        }
        out
    }
}

/// Certificate payload (RFC 7296 §3.6): a 1-octet encoding + certificate data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub encoding: u8,
    pub data: Vec<u8>,
}

impl Certificate {
    /// A DER X.509 certificate (encoding 4).
    pub fn x509(der: Vec<u8>) -> Self {
        Certificate { encoding: cert_encoding::X509_SIGNATURE, data: der }
    }

    pub fn parse(body: &[u8]) -> Result<Certificate, IkeError> {
        let &encoding = body.first().ok_or(IkeError::Truncated { need: 1, have: 0 })?;
        Ok(Certificate { encoding, data: body[1..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.data.len());
        out.push(self.encoding);
        out.extend_from_slice(&self.data);
        out
    }
}

/// Certificate Request payload (RFC 7296 §3.7): a 1-octet encoding + a bare
/// concatenation of 20-byte SHA-1 hashes of trusted CAs' `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRequest {
    pub encoding: u8,
    pub ca_hashes: Vec<[u8; 20]>,
}

impl CertRequest {
    /// Ask for an X.509 certificate. An empty list means "send any/your cert".
    pub fn x509(ca_hashes: Vec<[u8; 20]>) -> Self {
        CertRequest { encoding: cert_encoding::X509_SIGNATURE, ca_hashes }
    }

    pub fn parse(body: &[u8]) -> Result<CertRequest, IkeError> {
        let &encoding = body.first().ok_or(IkeError::Truncated { need: 1, have: 0 })?;
        let rest = &body[1..];
        if rest.len() % 20 != 0 {
            return Err(IkeError::BadLength { declared: rest.len(), available: rest.len() });
        }
        let ca_hashes = rest.chunks_exact(20).map(|c| c.try_into().unwrap()).collect();
        Ok(CertRequest { encoding, ca_hashes })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 20 * self.ca_hashes.len());
        out.push(self.encoding);
        for h in &self.ca_hashes {
            out.extend_from_slice(h);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ike_proposal() -> Proposal {
        Proposal {
            num: 1,
            protocol_id: protocol_id::IKE,
            spi: Vec::new(),
            transforms: vec![
                Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_GCM_16, key_length: Some(256) },
                Transform { transform_type: transform_type::PRF, transform_id: transform_id::PRF_HMAC_SHA2_256, key_length: None },
                Transform { transform_type: transform_type::DH, transform_id: transform_id::X25519, key_length: None },
                Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None },
            ],
        }
    }

    #[test]
    fn sa_roundtrips() {
        let sa = SecurityAssociation { proposals: vec![ike_proposal()] };
        let bytes = sa.to_bytes();
        assert_eq!(SecurityAssociation::parse(&bytes).unwrap(), sa);
    }

    #[test]
    fn certificate_roundtrips() {
        let c = Certificate::x509(vec![0x30, 0x82, 0x01, 0x02, 0xAB, 0xCD]);
        assert_eq!(c.encoding, cert_encoding::X509_SIGNATURE);
        assert_eq!(Certificate::parse(&c.to_bytes()).unwrap(), c);
        // A bare encoding byte with no cert data still parses (empty data).
        assert_eq!(Certificate::parse(&[4]).unwrap(), Certificate { encoding: 4, data: vec![] });
        assert!(Certificate::parse(&[]).is_err());
    }

    #[test]
    fn cert_request_roundtrips_including_empty() {
        let req = CertRequest::x509(vec![[0xAA; 20], [0x11; 20]]);
        assert_eq!(CertRequest::parse(&req.to_bytes()).unwrap(), req);
        // N == 0 is legal: "send any/your cert".
        let empty = CertRequest::x509(vec![]);
        assert_eq!(empty.to_bytes(), vec![cert_encoding::X509_SIGNATURE]);
        assert_eq!(CertRequest::parse(&empty.to_bytes()).unwrap(), empty);
        // A non-multiple-of-20 CA field is rejected, not truncated.
        assert!(CertRequest::parse(&[4, 0, 1, 2]).is_err());
    }

    #[test]
    fn sa_with_multiple_proposals_roundtrips() {
        let mut second = ike_proposal();
        second.num = 2;
        second.transforms[0] = Transform {
            transform_type: transform_type::ENCR,
            transform_id: transform_id::AES_CBC,
            key_length: Some(128),
        };
        second.transforms.insert(
            2,
            Transform { transform_type: transform_type::INTEG, transform_id: transform_id::AUTH_HMAC_SHA2_256_128, key_length: None },
        );
        let sa = SecurityAssociation { proposals: vec![ike_proposal(), second] };
        let bytes = sa.to_bytes();
        let parsed = SecurityAssociation::parse(&bytes).unwrap();
        assert_eq!(parsed, sa);
        assert_eq!(parsed.proposals[1].transforms[0].key_length, Some(128));
    }

    #[test]
    fn key_length_attribute_survives_roundtrip() {
        let sa = SecurityAssociation { proposals: vec![ike_proposal()] };
        let parsed = SecurityAssociation::parse(&sa.to_bytes()).unwrap();
        let encr = &parsed.proposals[0].transforms[0];
        assert_eq!(encr.transform_id, transform_id::AES_GCM_16);
        assert_eq!(encr.key_length, Some(256));
        assert_eq!(parsed.proposals[0].transforms[1].key_length, None);
    }

    #[test]
    fn ke_roundtrips() {
        let ke = KeyExchange { dh_group: transform_id::X25519, data: vec![0xAB; 32] };
        let bytes = ke.to_bytes();
        assert_eq!(bytes.len(), 4 + 32);
        assert_eq!(KeyExchange::parse(&bytes).unwrap(), ke);
    }

    #[test]
    fn nonce_roundtrips() {
        let nonce = Nonce { data: (0..32).collect() };
        assert_eq!(Nonce::parse(&nonce.to_bytes()), nonce);
    }

    #[test]
    fn identification_roundtrips() {
        let id = Identification::fqdn("gateway.example");
        let bytes = id.to_bytes();
        assert_eq!(bytes[0], id_type::FQDN);
        assert_eq!(&bytes[1..4], &[0, 0, 0]); // RESERVED
        assert_eq!(Identification::parse(&bytes).unwrap(), id);
    }

    #[test]
    fn authentication_roundtrips() {
        let auth = Authentication { method: auth_method::SHARED_KEY, data: vec![0xAB; 32] };
        assert_eq!(Authentication::parse(&auth.to_bytes()).unwrap(), auth);
    }

    #[test]
    fn notify_roundtrips_and_classifies() {
        let n = Notify::status(notify_type::NAT_DETECTION_SOURCE_IP, vec![0xEE; 20]);
        assert_eq!(Notify::parse(&n.to_bytes()).unwrap(), n);
        assert!(!n.is_error());
        assert!(Notify::status(notify_type::NO_PROPOSAL_CHOSEN, vec![]).is_error());

        // With a CHILD-SA SPI attached (e.g. a REKEY_SA notify).
        let with_spi = Notify { protocol_id: protocol_id::ESP, spi: vec![1, 2, 3, 4], notify_type: notify_type::REKEY_SA, data: vec![] };
        assert_eq!(Notify::parse(&with_spi.to_bytes()).unwrap(), with_spi);
    }

    #[test]
    fn delete_roundtrips() {
        let ike = Delete::ike_sa();
        assert_eq!(Delete::parse(&ike.to_bytes()).unwrap(), ike);
        assert!(ike.spis.is_empty());

        let esp = Delete::esp(vec![0xDEAD_BEEF, 0x0000_0001]);
        let bytes = esp.to_bytes();
        assert_eq!(bytes[1], 4); // SPI size
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 2); // count
        assert_eq!(Delete::parse(&bytes).unwrap(), esp);
    }

    #[test]
    fn traffic_selectors_roundtrip() {
        let ts = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] };
        let parsed = TrafficSelectors::parse(&ts.to_bytes()).unwrap();
        assert_eq!(parsed, ts);
        assert_eq!(parsed.selectors[0].start_addr, vec![0, 0, 0, 0]);
        assert_eq!(parsed.selectors[0].end_addr, vec![255, 255, 255, 255]);
        assert_eq!(parsed.selectors[0].end_port, 65535);

        // A two-selector set with a specific subnet also roundtrips.
        let ts2 = TrafficSelectors {
            selectors: vec![
                TrafficSelector::ipv4_any(),
                TrafficSelector {
                    ts_type: ts_type::IPV4_ADDR_RANGE,
                    ip_protocol: 6, // TCP
                    start_port: 443,
                    end_port: 443,
                    start_addr: vec![10, 0, 0, 0],
                    end_addr: vec![10, 0, 0, 255],
                },
            ],
        };
        assert_eq!(TrafficSelectors::parse(&ts2.to_bytes()).unwrap(), ts2);
    }

    #[test]
    fn truncated_inputs_are_rejected_not_panicked() {
        assert!(matches!(KeyExchange::parse(&[0, 31, 0]), Err(IkeError::Truncated { .. })));
        assert!(SecurityAssociation::parse(&[0, 0, 0, 4]).is_err());
    }
}
