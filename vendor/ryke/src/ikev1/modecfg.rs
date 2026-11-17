//! ISAKMP Configuration Method — the body of an ATTRIBUTE (type 14) payload used
//! by XAUTH (draft-beaulieu-ike-xauth) and Mode-Config (draft-dukes-ike-mode-cfg).
//!
//! Body layout: `[cfg-type(1)][RESERVED(1)][identifier(2)][attributes…]`, where
//! each attribute is a TV/TLV using the same AF-bit encoding as SA attributes.

use super::payloads::{self, Attribute};
use crate::error::IkeError;

/// Configuration exchange types (the `cfg-type` octet).
pub mod cfg {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    pub const SET: u8 = 3;
    pub const ACK: u8 = 4;
}

/// Configuration attribute types (Mode-Config + XAUTH).
pub mod cfg_attr {
    // Mode-Config (draft-dukes-ike-mode-cfg).
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_NBNS: u16 = 4;
    pub const INTERNAL_ADDRESS_EXPIRY: u16 = 5;
    pub const INTERNAL_IP4_DHCP: u16 = 6;
    pub const APPLICATION_VERSION: u16 = 7;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
    // XAUTH (draft-beaulieu-ike-xauth). Type 16520..16529.
    pub const XAUTH_TYPE: u16 = 16520;
    pub const XAUTH_USER_NAME: u16 = 16521;
    pub const XAUTH_USER_PASSWORD: u16 = 16522;
    pub const XAUTH_PASSCODE: u16 = 16523;
    pub const XAUTH_MESSAGE: u16 = 16524;
    pub const XAUTH_CHALLENGE: u16 = 16525;
    pub const XAUTH_DOMAIN: u16 = 16526;
    pub const XAUTH_STATUS: u16 = 16527;
    pub const XAUTH_NEXT_PIN: u16 = 16528;
    pub const XAUTH_ANSWER: u16 = 16529;
}

/// XAUTH authentication types (the value of an `XAUTH_TYPE` attribute).
pub mod xauth_type {
    pub const GENERIC: u16 = 0;
    pub const RADIUS_CHAP: u16 = 1;
    pub const OTP: u16 = 2;
    pub const SKEY: u16 = 3;
}

/// XAUTH_STATUS values.
pub mod xauth_status {
    pub const FAIL: u16 = 0;
    pub const OK: u16 = 1;
}

/// The body of an ISAKMP Configuration (ATTRIBUTE) payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPayload {
    pub cfg_type: u8,
    pub identifier: u16,
    pub attributes: Vec<Attribute>,
}

impl ConfigPayload {
    pub fn new(cfg_type: u8, identifier: u16, attributes: Vec<Attribute>) -> Self {
        ConfigPayload { cfg_type, identifier, attributes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.cfg_type, 0];
        out.extend_from_slice(&self.identifier.to_be_bytes());
        for a in &self.attributes {
            out.extend_from_slice(&a.to_bytes());
        }
        out
    }

    pub fn parse(body: &[u8]) -> Result<ConfigPayload, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(ConfigPayload {
            cfg_type: body[0],
            identifier: u16::from_be_bytes([body[2], body[3]]),
            attributes: payloads::parse_attributes(&body[4..])?,
        })
    }

    /// Find the first attribute of a given type.
    pub fn attr(&self, attr_type: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xauth_request_roundtrips() {
        let p = ConfigPayload::new(
            cfg::REQUEST,
            0x1234,
            vec![
                Attribute::short(cfg_attr::XAUTH_TYPE, xauth_type::GENERIC),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_NAME, Vec::new()),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_PASSWORD, Vec::new()),
            ],
        );
        let bytes = p.to_bytes();
        let back = ConfigPayload::parse(&bytes).unwrap();
        assert_eq!(back.cfg_type, cfg::REQUEST);
        assert_eq!(back.identifier, 0x1234);
        assert_eq!(back.attr(cfg_attr::XAUTH_TYPE).unwrap().as_u16(), Some(xauth_type::GENERIC));
        assert!(back.attr(cfg_attr::XAUTH_USER_NAME).is_some());
    }

    #[test]
    fn reply_carries_credentials() {
        let p = ConfigPayload::new(
            cfg::REPLY,
            0x1234,
            vec![
                Attribute::long_bytes(cfg_attr::XAUTH_USER_NAME, b"alice".to_vec()),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_PASSWORD, b"secret".to_vec()),
            ],
        );
        let back = ConfigPayload::parse(&p.to_bytes()).unwrap();
        assert_eq!(back.attr(cfg_attr::XAUTH_USER_NAME).unwrap().bytes(), b"alice");
        assert_eq!(back.attr(cfg_attr::XAUTH_USER_PASSWORD).unwrap().bytes(), b"secret");
    }
}
