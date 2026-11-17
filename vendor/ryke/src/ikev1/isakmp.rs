//! ISAKMP message framing for IKEv1 (RFC 2408): the 28-byte header and the
//! generic-payload chain. This is deliberately separate from the IKEv2
//! [`crate::ikev2::message`] framing — the header layout, the version byte, the
//! exchange types, and the next-payload chaining all differ.

use crate::error::IkeError;

/// IKEv1 exchange types (RFC 2408 §3.1 / the DOI).
pub mod exchange {
    pub const MAIN: u8 = 2;
    pub const AGGRESSIVE: u8 = 4;
    pub const INFORMATIONAL: u8 = 5;
    pub const TRANSACTION: u8 = 6; // Xauth / Mode-Config
    pub const QUICK: u8 = 32;
}

/// ISAKMP header flags (RFC 2408 §3.1).
pub mod flags {
    /// Payloads after the header are encrypted.
    pub const ENCRYPTION: u8 = 0x01;
    pub const COMMIT: u8 = 0x02;
    pub const AUTH_ONLY: u8 = 0x04;
}

/// IKEv1 payload type numbers (RFC 2408 §3.1) — note these differ from IKEv2.
pub mod payload {
    pub const NONE: u8 = 0;
    pub const SA: u8 = 1;
    pub const PROPOSAL: u8 = 2;
    pub const TRANSFORM: u8 = 3;
    pub const KE: u8 = 4;
    pub const ID: u8 = 5;
    pub const CERT: u8 = 6;
    pub const CERTREQ: u8 = 7;
    pub const HASH: u8 = 8;
    pub const SIG: u8 = 9;
    pub const NONCE: u8 = 10;
    pub const NOTIFY: u8 = 11;
    pub const DELETE: u8 = 12;
    pub const VENDOR_ID: u8 = 13;
    /// ISAKMP-CFG / Attribute payload (Xauth + Mode-Config).
    pub const ATTRIBUTE: u8 = 14;
    pub const NAT_D: u8 = 20; // RFC 3947
    pub const NAT_OA: u8 = 21;
}

/// The 28-byte ISAKMP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsakmpHeader {
    pub init_cookie: [u8; 8],
    pub resp_cookie: [u8; 8],
    /// Type of the first payload in the message.
    pub next_payload: u8,
    /// Version: 0x10 = MjVer 1, MnVer 0.
    pub version: u8,
    pub exchange_type: u8,
    pub flags: u8,
    pub message_id: u32,
    pub length: u32,
}

impl IsakmpHeader {
    pub const LEN: usize = 28;
    pub const VERSION_1_0: u8 = 0x10;

    pub fn parse(bytes: &[u8]) -> Result<IsakmpHeader, IkeError> {
        if bytes.len() < Self::LEN {
            return Err(IkeError::Truncated { need: Self::LEN, have: bytes.len() });
        }
        Ok(IsakmpHeader {
            init_cookie: bytes[0..8].try_into().unwrap(),
            resp_cookie: bytes[8..16].try_into().unwrap(),
            next_payload: bytes[16],
            version: bytes[17],
            exchange_type: bytes[18],
            flags: bytes[19],
            message_id: u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
            length: u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.extend_from_slice(&self.init_cookie);
        out.extend_from_slice(&self.resp_cookie);
        out.push(self.next_payload);
        out.push(self.version);
        out.push(self.exchange_type);
        out.push(self.flags);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.length.to_be_bytes());
        out
    }

    pub fn encrypted(&self) -> bool {
        self.flags & flags::ENCRYPTION != 0
    }
}

/// One decoded generic payload: its type and its body (excluding the 4-byte
/// generic header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub payload_type: u8,
    pub data: Vec<u8>,
}

/// Parse the generic-payload chain. `first` is the header's `next_payload`;
/// `body` is everything after the 28-byte header. Each generic payload header is
/// `[Next Payload(1)][RESERVED(1)][Payload Length(2, includes the 4-byte header)]`.
pub fn parse_payloads(first: u8, body: &[u8]) -> Result<Vec<Payload>, IkeError> {
    let mut out = Vec::new();
    let mut next = first;
    let mut off = 0;
    while next != payload::NONE {
        if off + 4 > body.len() {
            return Err(IkeError::Truncated { need: off + 4, have: body.len() });
        }
        let this_next = body[off];
        let len = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        if len < 4 || off + len > body.len() {
            return Err(IkeError::BadLength { declared: len, available: body.len() - off });
        }
        out.push(Payload { payload_type: next, data: body[off + 4..off + len].to_vec() });
        next = this_next;
        off += len;
    }
    Ok(out)
}

/// Encode a payload chain, wiring each generic header's Next-Payload to the
/// following payload's type (and `NONE` after the last). Returns
/// `(first_payload_type, encoded_bytes)`.
pub fn encode_payloads(payloads: &[(u8, Vec<u8>)]) -> (u8, Vec<u8>) {
    if payloads.is_empty() {
        return (payload::NONE, Vec::new());
    }
    let first = payloads[0].0;
    let mut out = Vec::new();
    for (i, (_ptype, data)) in payloads.iter().enumerate() {
        let next = payloads.get(i + 1).map(|p| p.0).unwrap_or(payload::NONE);
        let len = 4 + data.len();
        out.push(next);
        out.push(0); // RESERVED
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    (first, out)
}

/// Assemble a full ISAKMP message from a header template and payload chain,
/// filling in `next_payload` and `length`. `message_id`, cookies, exchange type
/// and flags come from `header`.
pub fn build_message(mut header: IsakmpHeader, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let (first, body) = encode_payloads(payloads);
    header.next_payload = first;
    header.length = (IsakmpHeader::LEN + body.len()) as u32;
    let mut out = header.to_bytes();
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrips() {
        let h = IsakmpHeader {
            init_cookie: [1, 2, 3, 4, 5, 6, 7, 8],
            resp_cookie: [9; 8],
            next_payload: payload::SA,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::AGGRESSIVE,
            flags: 0,
            message_id: 0,
            length: 28,
        };
        assert_eq!(IsakmpHeader::parse(&h.to_bytes()).unwrap(), h);
        assert_eq!(h.to_bytes().len(), IsakmpHeader::LEN);
        assert!(IsakmpHeader::parse(&[0u8; 10]).is_err());
    }

    #[test]
    fn payload_chain_roundtrips() {
        let payloads = vec![
            (payload::SA, vec![0xAA; 12]),
            (payload::KE, vec![0xBB; 128]),
            (payload::NONCE, vec![0xCC; 20]),
            (payload::ID, vec![0xDD; 8]),
        ];
        let (first, body) = encode_payloads(&payloads);
        assert_eq!(first, payload::SA);
        let parsed = parse_payloads(first, &body).unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0], Payload { payload_type: payload::SA, data: vec![0xAA; 12] });
        assert_eq!(parsed[1].payload_type, payload::KE);
        assert_eq!(parsed[1].data.len(), 128);
        assert_eq!(parsed[3], Payload { payload_type: payload::ID, data: vec![0xDD; 8] });
    }

    #[test]
    fn build_message_sets_next_payload_and_length() {
        let header = IsakmpHeader {
            init_cookie: [0x11; 8],
            resp_cookie: [0; 8],
            next_payload: payload::NONE, // overwritten by build_message
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::AGGRESSIVE,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        let msg = build_message(header, &[(payload::HASH, vec![0x01; 20])]);
        let h = IsakmpHeader::parse(&msg).unwrap();
        assert_eq!(h.next_payload, payload::HASH);
        assert_eq!(h.length as usize, msg.len());
        let payloads = parse_payloads(h.next_payload, &msg[IsakmpHeader::LEN..]).unwrap();
        assert_eq!(payloads, vec![Payload { payload_type: payload::HASH, data: vec![0x01; 20] }]);
    }

    #[test]
    fn empty_chain_is_none() {
        let (first, body) = encode_payloads(&[]);
        assert_eq!(first, payload::NONE);
        assert!(body.is_empty());
        assert_eq!(parse_payloads(payload::NONE, &[]).unwrap(), vec![]);
    }

    #[test]
    fn truncated_and_bad_length_rejected() {
        // Claims a KE follows but the body is empty.
        assert!(parse_payloads(payload::KE, &[]).is_err());
        // Payload length < 4.
        assert!(parse_payloads(payload::SA, &[0, 0, 0, 2]).is_err());
        // Payload length runs past the buffer.
        assert!(parse_payloads(payload::SA, &[0, 0, 0xFF, 0xFF, 1, 2]).is_err());
    }
}
