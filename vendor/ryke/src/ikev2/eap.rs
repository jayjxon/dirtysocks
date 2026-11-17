//! EAP (RFC 3748) message framing and the EAP-MSCHAPv2 messages that ride inside
//! an IKEv2 EAP payload. Ties the verified [`crate::ikev2::mschapv2`] crypto into a
//! Challenge → Response → Success round.

use crate::error::IkeError;
use crate::ikev2::mschapv2::{generate_authenticator_response, generate_nt_response};

/// EAP codes (RFC 3748 §4).
pub mod code {
    pub const REQUEST: u8 = 1;
    pub const RESPONSE: u8 = 2;
    pub const SUCCESS: u8 = 3;
    pub const FAILURE: u8 = 4;
}

/// EAP method Types.
pub mod eap_type {
    pub const IDENTITY: u8 = 1;
    pub const NAK: u8 = 3;
    pub const MSCHAPV2: u8 = 26;
}

/// EAP-MSCHAPv2 op-codes (the first byte of the MSCHAPv2 message).
pub mod op {
    pub const CHALLENGE: u8 = 1;
    pub const RESPONSE: u8 = 2;
    pub const SUCCESS: u8 = 3;
    pub const FAILURE: u8 = 4;
}

/// An EAP packet — the body of an IKEv2 EAP payload (RFC 3748 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapPacket {
    pub code: u8,
    pub identifier: u8,
    /// For Request/Response, `[Type, method-data…]`; empty for Success/Failure.
    pub data: Vec<u8>,
}

impl EapPacket {
    pub fn parse(body: &[u8]) -> Result<EapPacket, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let length = u16::from_be_bytes([body[2], body[3]]) as usize;
        if length < 4 || length > body.len() {
            return Err(IkeError::BadLength { declared: length, available: body.len() });
        }
        Ok(EapPacket { code: body[0], identifier: body[1], data: body[4..length].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let length = 4 + self.data.len();
        let mut out = Vec::with_capacity(length);
        out.push(self.code);
        out.push(self.identifier);
        out.extend_from_slice(&(length as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// The EAP method Type (first data byte) for a Request/Response.
    pub fn eap_type(&self) -> Option<u8> {
        self.data.first().copied()
    }
}

/// Build the EAP-MSCHAPv2 **Challenge** method-data (server → peer): the
/// authenticator challenge + a server name.
pub fn build_challenge(mschap_id: u8, challenge: &[u8; 16], name: &[u8]) -> Vec<u8> {
    let ms_len = 4 + 1 + 16 + name.len();
    let mut d = vec![eap_type::MSCHAPV2, op::CHALLENGE, mschap_id];
    d.extend_from_slice(&(ms_len as u16).to_be_bytes());
    d.push(16); // Value-Size
    d.extend_from_slice(challenge);
    d.extend_from_slice(name);
    d
}

/// Parse an EAP-MSCHAPv2 Challenge, returning (mschap_id, challenge, name).
pub fn parse_challenge(data: &[u8]) -> Result<(u8, [u8; 16], Vec<u8>), IkeError> {
    if data.len() < 22 || data[0] != eap_type::MSCHAPV2 || data[1] != op::CHALLENGE {
        return Err(IkeError::Crypto("not an EAP-MSCHAPv2 Challenge"));
    }
    let challenge: [u8; 16] = data[6..22].try_into().unwrap();
    Ok((data[2], challenge, data[22..].to_vec()))
}

/// Build the EAP-MSCHAPv2 **Response** method-data (peer → server): computes the
/// NT-Response from the challenge + credentials.
pub fn build_response(
    mschap_id: u8,
    authenticator_challenge: &[u8; 16],
    peer_challenge: &[u8; 16],
    user: &[u8],
    password: &str,
) -> Vec<u8> {
    let nt = generate_nt_response(authenticator_challenge, peer_challenge, user, password);
    let ms_len = 4 + 1 + 49 + user.len();
    let mut d = vec![eap_type::MSCHAPV2, op::RESPONSE, mschap_id];
    d.extend_from_slice(&(ms_len as u16).to_be_bytes());
    d.push(49); // Value-Size
    d.extend_from_slice(peer_challenge);
    d.extend_from_slice(&[0u8; 8]); // Reserved
    d.extend_from_slice(&nt);
    d.push(0); // Flags
    d.extend_from_slice(user);
    d
}

/// Parsed EAP-MSCHAPv2 Response.
pub struct Response {
    pub mschap_id: u8,
    pub peer_challenge: [u8; 16],
    pub nt_response: [u8; 24],
    pub name: Vec<u8>,
}

pub fn parse_response(data: &[u8]) -> Result<Response, IkeError> {
    if data.len() < 55 || data[0] != eap_type::MSCHAPV2 || data[1] != op::RESPONSE {
        return Err(IkeError::Crypto("not an EAP-MSCHAPv2 Response"));
    }
    Ok(Response {
        mschap_id: data[2],
        peer_challenge: data[6..22].try_into().unwrap(),
        nt_response: data[30..54].try_into().unwrap(),
        name: data[55..].to_vec(),
    })
}

/// Server side: verify a Response against the stored password and the challenge
/// we sent. On success returns the authenticator response string (`"S=<hex>"`)
/// for the MSCHAPv2 Success message; on mismatch returns [`IkeError::AuthFailed`].
pub fn verify_response(authenticator_challenge: &[u8; 16], response_data: &[u8], password: &str) -> Result<String, IkeError> {
    let resp = parse_response(response_data)?;
    let expected = generate_nt_response(authenticator_challenge, &resp.peer_challenge, &resp.name, password);
    if expected != resp.nt_response {
        return Err(IkeError::AuthFailed);
    }
    Ok(generate_authenticator_response(password, &resp.nt_response, &resp.peer_challenge, authenticator_challenge, &resp.name))
}

/// Build the EAP-MSCHAPv2 **Success** method-data (server → peer): `"S=<hex>"`.
pub fn build_success(mschap_id: u8, auth_response: &str) -> Vec<u8> {
    let msg = auth_response.as_bytes();
    let ms_len = 4 + msg.len();
    let mut d = vec![eap_type::MSCHAPV2, op::SUCCESS, mschap_id];
    d.extend_from_slice(&(ms_len as u16).to_be_bytes());
    d.extend_from_slice(msg);
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eap_packet_roundtrips() {
        let p = EapPacket { code: code::REQUEST, identifier: 7, data: vec![eap_type::MSCHAPV2, 1, 2, 3] };
        let bytes = p.to_bytes();
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]) as usize, bytes.len());
        assert_eq!(EapPacket::parse(&bytes).unwrap(), p);
        assert_eq!(p.eap_type(), Some(eap_type::MSCHAPV2));
    }

    // A full MSCHAPv2 auth round, using the RFC 2759 §9.2 challenges so the
    // authenticator response is the known-answer value.
    #[test]
    fn full_mschapv2_auth_round_matches_rfc2759() {
        let auth_challenge = [0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E, 0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28];
        let peer_challenge = [0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E];
        let user = b"User";
        let password = "clientPass";

        // Server → peer: Challenge.
        let chal = build_challenge(1, &auth_challenge, b"server");
        let (id, got_challenge, _name) = parse_challenge(&chal).unwrap();
        assert_eq!(id, 1);
        assert_eq!(got_challenge, auth_challenge);

        // Peer → server: Response.
        let resp = build_response(id, &auth_challenge, &peer_challenge, user, password);
        let parsed = parse_response(&resp).unwrap();
        assert_eq!(parsed.name, user);

        // Server verifies and produces the Success authenticator response.
        let auth_resp = verify_response(&auth_challenge, &resp, password).unwrap();
        assert_eq!(auth_resp, "S=407A5589115FD0D6209F510FE9C04566932CDA56");

        let success = build_success(id, &auth_resp);
        assert_eq!(success[1], op::SUCCESS);

        // Wrong password is rejected.
        assert_eq!(verify_response(&auth_challenge, &resp, "wrong").unwrap_err(), IkeError::AuthFailed);
    }
}
