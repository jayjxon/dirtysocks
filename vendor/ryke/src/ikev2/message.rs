//! IKEv2 message framing: the fixed header (RFC 7296 §3.1) and the generic
//! payload chain (RFC 7296 §3.2).
//!
//! This is the byte-level foundation every exchange builds on. It is
//! deliberately free of crypto and of any interpretation of individual payload
//! bodies — it only frames them. Typed payload bodies land in a later module.

use crate::error::IkeError;

/// The IKEv2 exchange type (RFC 7296 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeType {
    IkeSaInit,
    IkeAuth,
    CreateChildSa,
    Informational,
    /// Any value we don't model yet, preserved as-is.
    Other(u8),
}

impl ExchangeType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            34 => ExchangeType::IkeSaInit,
            35 => ExchangeType::IkeAuth,
            36 => ExchangeType::CreateChildSa,
            37 => ExchangeType::Informational,
            other => ExchangeType::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            ExchangeType::IkeSaInit => 34,
            ExchangeType::IkeAuth => 35,
            ExchangeType::CreateChildSa => 36,
            ExchangeType::Informational => 37,
            ExchangeType::Other(value) => value,
        }
    }
}

/// The IKEv2 payload type, used both as the header's "next payload" and as each
/// generic payload header's "next payload" (RFC 7296 §3.2, table in §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadType {
    NoNext,
    SecurityAssociation,
    KeyExchange,
    IdInitiator,
    IdResponder,
    Certificate,
    CertRequest,
    Authentication,
    Nonce,
    Notify,
    Delete,
    VendorId,
    TrafficSelectorInitiator,
    TrafficSelectorResponder,
    /// SK — Encrypted and Authenticated.
    Encrypted,
    /// CP — Configuration.
    Configuration,
    /// EAP — Extensible Authentication.
    Eap,
    /// SKF — Encrypted and Authenticated Fragment (RFC 7383).
    EncryptedFragment,
    /// Any type we don't model yet, preserved as-is.
    Other(u8),
}

impl PayloadType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => PayloadType::NoNext,
            33 => PayloadType::SecurityAssociation,
            34 => PayloadType::KeyExchange,
            35 => PayloadType::IdInitiator,
            36 => PayloadType::IdResponder,
            37 => PayloadType::Certificate,
            38 => PayloadType::CertRequest,
            39 => PayloadType::Authentication,
            40 => PayloadType::Nonce,
            41 => PayloadType::Notify,
            42 => PayloadType::Delete,
            43 => PayloadType::VendorId,
            44 => PayloadType::TrafficSelectorInitiator,
            45 => PayloadType::TrafficSelectorResponder,
            46 => PayloadType::Encrypted,
            47 => PayloadType::Configuration,
            48 => PayloadType::Eap,
            53 => PayloadType::EncryptedFragment,
            other => PayloadType::Other(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            PayloadType::NoNext => 0,
            PayloadType::SecurityAssociation => 33,
            PayloadType::KeyExchange => 34,
            PayloadType::IdInitiator => 35,
            PayloadType::IdResponder => 36,
            PayloadType::Certificate => 37,
            PayloadType::CertRequest => 38,
            PayloadType::Authentication => 39,
            PayloadType::Nonce => 40,
            PayloadType::Notify => 41,
            PayloadType::Delete => 42,
            PayloadType::VendorId => 43,
            PayloadType::TrafficSelectorInitiator => 44,
            PayloadType::TrafficSelectorResponder => 45,
            PayloadType::Encrypted => 46,
            PayloadType::Configuration => 47,
            PayloadType::Eap => 48,
            PayloadType::EncryptedFragment => 53,
            PayloadType::Other(value) => value,
        }
    }
}

/// The IKEv2 header flags byte (RFC 7296 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flags {
    /// I — set when the message is sent by the original initiator.
    pub initiator: bool,
    /// V — the sender can speak a higher IKE major version.
    pub version: bool,
    /// R — this message is a response to a message with the same Message ID.
    pub response: bool,
}

impl Flags {
    const INITIATOR: u8 = 0x08;
    const VERSION: u8 = 0x10;
    const RESPONSE: u8 = 0x20;

    pub fn from_u8(value: u8) -> Self {
        Flags {
            initiator: value & Self::INITIATOR != 0,
            version: value & Self::VERSION != 0,
            response: value & Self::RESPONSE != 0,
        }
    }

    pub fn to_u8(self) -> u8 {
        let mut value = 0;
        if self.initiator {
            value |= Self::INITIATOR;
        }
        if self.version {
            value |= Self::VERSION;
        }
        if self.response {
            value |= Self::RESPONSE;
        }
        value
    }
}

/// The fixed 28-byte IKEv2 header (RFC 7296 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IkeHeader {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub next_payload: PayloadType,
    pub major_version: u8,
    pub minor_version: u8,
    pub exchange_type: ExchangeType,
    pub flags: Flags,
    pub message_id: u32,
    /// Total message length in bytes, including this header.
    pub length: u32,
}

impl IkeHeader {
    /// The wire size of the header.
    pub const LEN: usize = 28;

    /// Parse the fixed header from the front of `input`.
    pub fn parse(input: &[u8]) -> Result<IkeHeader, IkeError> {
        if input.len() < Self::LEN {
            return Err(IkeError::Truncated {
                need: Self::LEN,
                have: input.len(),
            });
        }
        let version = input[17];
        Ok(IkeHeader {
            initiator_spi: u64::from_be_bytes(input[0..8].try_into().unwrap()),
            responder_spi: u64::from_be_bytes(input[8..16].try_into().unwrap()),
            next_payload: PayloadType::from_u8(input[16]),
            major_version: version >> 4,
            minor_version: version & 0x0f,
            exchange_type: ExchangeType::from_u8(input[18]),
            flags: Flags::from_u8(input[19]),
            message_id: u32::from_be_bytes(input[20..24].try_into().unwrap()),
            length: u32::from_be_bytes(input[24..28].try_into().unwrap()),
        })
    }

    /// Serialize the header to its 28-byte wire form.
    pub fn to_bytes(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..8].copy_from_slice(&self.initiator_spi.to_be_bytes());
        out[8..16].copy_from_slice(&self.responder_spi.to_be_bytes());
        out[16] = self.next_payload.to_u8();
        out[17] = (self.major_version << 4) | (self.minor_version & 0x0f);
        out[18] = self.exchange_type.to_u8();
        out[19] = self.flags.to_u8();
        out[20..24].copy_from_slice(&self.message_id.to_be_bytes());
        out[24..28].copy_from_slice(&self.length.to_be_bytes());
        out
    }
}

/// One framed payload: its type + body, with the 4-byte generic header stripped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawPayload<'a> {
    pub payload_type: PayloadType,
    /// The critical bit (RFC 7296 §2.5): if set and the type is unknown, the
    /// whole message must be rejected. We surface it; enforcement is later.
    pub critical: bool,
    /// Payload body, excluding the 4-byte generic payload header.
    pub data: &'a [u8],
}

/// Walk the generic payload chain of a message body (RFC 7296 §3.2).
///
/// `first` is the header's `next_payload`; `body` is everything after the
/// 28-byte header. Yields each payload in order, or a single error if the chain
/// is malformed (after which iteration stops).
pub fn payloads(first: PayloadType, body: &[u8]) -> PayloadIter<'_> {
    PayloadIter {
        next: first,
        rest: body,
        done: false,
    }
}

/// Iterator returned by [`payloads`].
pub struct PayloadIter<'a> {
    next: PayloadType,
    rest: &'a [u8],
    done: bool,
}

impl<'a> Iterator for PayloadIter<'a> {
    type Item = Result<RawPayload<'a>, IkeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.next == PayloadType::NoNext {
            return None;
        }
        if self.rest.len() < 4 {
            self.done = true;
            return Some(Err(IkeError::Truncated {
                need: 4,
                have: self.rest.len(),
            }));
        }

        let this_type = self.next;
        let next_payload = PayloadType::from_u8(self.rest[0]);
        let critical = self.rest[1] & 0x80 != 0;
        let length = u16::from_be_bytes([self.rest[2], self.rest[3]]);

        if (length as usize) < 4 {
            self.done = true;
            return Some(Err(IkeError::ShortPayload(length)));
        }
        if length as usize > self.rest.len() {
            self.done = true;
            return Some(Err(IkeError::BadLength {
                declared: length as usize,
                available: self.rest.len(),
            }));
        }

        let data = &self.rest[4..length as usize];
        self.rest = &self.rest[length as usize..];
        self.next = next_payload;
        Some(Ok(RawPayload {
            payload_type: this_type,
            critical,
            data,
        }))
    }
}

/// Assembles a full IKEv2 message: the fixed header followed by an ordered
/// payload chain. On [`build`](Self::build) it fills in each generic payload
/// header's Next Payload pointer, the header's first Next Payload, and the total
/// Length — so callers only supply each payload's already-serialized body.
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    header: IkeHeader,
    payloads: Vec<(PayloadType, Vec<u8>)>,
}

impl MessageBuilder {
    /// Start from a header; its `next_payload` and `length` are overwritten by
    /// [`build`](Self::build).
    pub fn new(header: IkeHeader) -> Self {
        Self { header, payloads: Vec::new() }
    }

    /// Append a payload by type and already-serialized body (builder style).
    pub fn push(mut self, payload_type: PayloadType, body: Vec<u8>) -> Self {
        self.payloads.push((payload_type, body));
        self
    }

    /// Serialize to the full wire message.
    pub fn build(&self) -> Vec<u8> {
        let chain = encode_payload_chain(&self.payloads);
        let mut header = self.header;
        header.next_payload = first_payload_type(&self.payloads);
        header.length = (IkeHeader::LEN + chain.len()) as u32;

        let mut out = Vec::with_capacity(header.length as usize);
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&chain);
        out
    }
}

/// Serialize a chain of payloads (each an already-serialized body) with their
/// generic payload headers and Next-Payload pointers. Used for both a message's
/// top-level payloads and the inner payloads inside an SK (encrypted) payload.
pub fn encode_payload_chain(payloads: &[(PayloadType, Vec<u8>)]) -> Vec<u8> {
    let mut chain = Vec::new();
    for (i, (_, body)) in payloads.iter().enumerate() {
        let next = payloads
            .get(i + 1)
            .map(|(t, _)| *t)
            .unwrap_or(PayloadType::NoNext);
        let length = (4 + body.len()) as u16;
        chain.push(next.to_u8());
        chain.push(0); // critical bit clear + RESERVED
        chain.extend_from_slice(&length.to_be_bytes());
        chain.extend_from_slice(body);
    }
    chain
}

/// The type of the first payload in a chain — what the container (IKE header or
/// SK payload) records as its Next Payload.
pub fn first_payload_type(payloads: &[(PayloadType, Vec<u8>)]) -> PayloadType {
    payloads.first().map(|(t, _)| *t).unwrap_or(PayloadType::NoNext)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal IKE_SA_INIT header, initiator flag set, first payload = SA.
    const SA_INIT_HEADER: [u8; 28] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // initiator SPI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // responder SPI (none yet)
        0x21, // next payload = SA (33)
        0x20, // version 2.0
        0x22, // exchange = IKE_SA_INIT (34)
        0x08, // flags = initiator
        0x00, 0x00, 0x00, 0x00, // message id 0
        0x00, 0x00, 0x00, 0x1c, // length = 28
    ];

    #[test]
    fn parses_known_header() {
        let h = IkeHeader::parse(&SA_INIT_HEADER).unwrap();
        assert_eq!(h.initiator_spi, 0x1122334455667788);
        assert_eq!(h.responder_spi, 0);
        assert_eq!(h.next_payload, PayloadType::SecurityAssociation);
        assert_eq!((h.major_version, h.minor_version), (2, 0));
        assert_eq!(h.exchange_type, ExchangeType::IkeSaInit);
        assert!(h.flags.initiator && !h.flags.response);
        assert_eq!(h.message_id, 0);
        assert_eq!(h.length, 28);
    }

    #[test]
    fn header_roundtrips() {
        let h = IkeHeader::parse(&SA_INIT_HEADER).unwrap();
        assert_eq!(h.to_bytes(), SA_INIT_HEADER);

        let rebuilt = IkeHeader {
            responder_spi: 0xaabbccddeeff0011,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags {
                initiator: false,
                version: false,
                response: true,
            },
            message_id: 1,
            length: 80,
            ..h
        };
        assert_eq!(IkeHeader::parse(&rebuilt.to_bytes()).unwrap(), rebuilt);
    }

    #[test]
    fn rejects_short_header() {
        assert_eq!(
            IkeHeader::parse(&SA_INIT_HEADER[..10]).unwrap_err(),
            IkeError::Truncated { need: 28, have: 10 }
        );
    }

    #[test]
    fn walks_payload_chain() {
        // SA payload (next = KE) then KE payload (next = none).
        let body = [
            0x22, 0x00, 0x00, 0x08, 0xAA, 0xAA, 0xAA, 0xAA, // SA -> KE, len 8
            0x00, 0x00, 0x00, 0x08, 0xBB, 0xBB, 0xBB, 0xBB, // KE -> none, len 8
        ];
        let got: Vec<RawPayload> = payloads(PayloadType::SecurityAssociation, &body)
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].payload_type, PayloadType::SecurityAssociation);
        assert_eq!(got[0].data, &[0xAA, 0xAA, 0xAA, 0xAA]);
        assert_eq!(got[1].payload_type, PayloadType::KeyExchange);
        assert_eq!(got[1].data, &[0xBB, 0xBB, 0xBB, 0xBB]);
    }

    #[test]
    fn payload_chain_rejects_bad_length() {
        // Declares length 40 but only 8 bytes present.
        let body = [0x00, 0x00, 0x00, 0x28, 0x01, 0x02, 0x03, 0x04];
        let err = payloads(PayloadType::Nonce, &body)
            .next()
            .unwrap()
            .unwrap_err();
        assert_eq!(err, IkeError::BadLength { declared: 40, available: 8 });
    }

    #[test]
    fn payload_chain_rejects_self_referential_short_length() {
        let body = [0x00, 0x40, 0x00, 0x02]; // length 2 < 4, would loop
        let err = payloads(PayloadType::Notify, &body)
            .next()
            .unwrap()
            .unwrap_err();
        assert_eq!(err, IkeError::ShortPayload(2));
    }

    #[test]
    fn exchange_and_payload_types_roundtrip() {
        for v in 0u8..=255 {
            assert_eq!(ExchangeType::from_u8(v).to_u8(), v);
            assert_eq!(PayloadType::from_u8(v).to_u8(), v);
        }
    }

    #[test]
    fn message_builder_roundtrips_through_parse() {
        let header = IkeHeader {
            initiator_spi: 0x1122334455667788,
            responder_spi: 0x99aabbccddeeff00,
            next_payload: PayloadType::NoNext, // overwritten by build()
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::IkeSaInit,
            flags: Flags { initiator: false, version: false, response: true },
            message_id: 0,
            length: 0, // overwritten by build()
        };
        let msg = MessageBuilder::new(header)
            .push(PayloadType::SecurityAssociation, vec![0xAA; 4])
            .push(PayloadType::KeyExchange, vec![0xBB; 36])
            .push(PayloadType::Nonce, vec![0xCC; 32])
            .build();

        let parsed = IkeHeader::parse(&msg).unwrap();
        assert_eq!(parsed.length as usize, msg.len());
        assert_eq!(parsed.next_payload, PayloadType::SecurityAssociation);

        let bodies: Vec<RawPayload> = payloads(parsed.next_payload, &msg[IkeHeader::LEN..])
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(bodies.len(), 3);
        assert_eq!(bodies[0].payload_type, PayloadType::SecurityAssociation);
        assert_eq!(bodies[0].data, &[0xAA; 4]);
        assert_eq!(bodies[1].payload_type, PayloadType::KeyExchange);
        assert_eq!(bodies[1].data.len(), 36);
        assert_eq!(bodies[2].payload_type, PayloadType::Nonce);
        assert_eq!(bodies[2].data.len(), 32);
    }
}
