//! IKE message fragmentation (RFC 7383) for AES-GCM.
//!
//! A too-large encrypted message is sent as several IKE messages, each carrying
//! one **SKF** (Encrypted and Authenticated Fragment) payload instead of `SK`.
//! Each fragment is independently AES-GCM-sealed, with the fragment header
//! (Fragment Number + Total Fragments) folded into the AAD. The first fragment
//! records the Next Payload of the reassembled inner payloads; the rest carry 0.
//!
//! An SKF payload body: `FragNum(2) | Total(2) | IV(8) | ciphertext | ICV(16)`.

use crate::error::IkeError;
use crate::ikev2::message::{IkeHeader, PayloadType};
use crate::ikev2::sk::{gcm_open, gcm_seal};

const IV_LEN: usize = 8;
const ICV_LEN: usize = 16;
const SKF_EXTRA: usize = 4; // Fragment Number (2) + Total Fragments (2)
const SKF_MIN_BODY: usize = SKF_EXTRA + IV_LEN + ICV_LEN;

/// Split a full inner-payload byte string into `total` SKF-payload IKE messages.
///
/// `header` supplies the SPIs / exchange type / message id (its `next_payload`
/// and `length` are set per fragment). `first_inner` is the type of the first
/// inner payload (recorded only in fragment #1). `iv_base` seeds a unique 8-byte
/// IV per fragment (the caller ensures global uniqueness under the key).
/// `content_per_fragment` is the max plaintext bytes per fragment.
pub fn build_fragments(
    header: &IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    sk_e: &[u8],
    iv_base: u64,
    content_per_fragment: usize,
) -> Result<Vec<Vec<u8>>, IkeError> {
    if content_per_fragment == 0 {
        return Err(IkeError::Crypto("fragment content size must be > 0"));
    }
    let chunks: Vec<&[u8]> = if inner.is_empty() {
        vec![&[][..]]
    } else {
        inner.chunks(content_per_fragment).collect()
    };
    let total = chunks.len() as u16;

    let mut out = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let frag_num = (i + 1) as u16;
        let iv = iv_base.wrapping_add(frag_num as u64).to_be_bytes();

        // plaintext = chunk ‖ pad_length(0)
        let mut plaintext = chunk.to_vec();
        plaintext.push(0);

        let skf_payload_len = 4 + SKF_EXTRA + IV_LEN + plaintext.len() + ICV_LEN;
        let total_len = IkeHeader::LEN + skf_payload_len;

        let mut hdr = *header;
        hdr.next_payload = PayloadType::EncryptedFragment;
        hdr.length = total_len as u32;
        let hdr_bytes = hdr.to_bytes();

        let mut skf_gen = [0u8; 4];
        skf_gen[0] = if frag_num == 1 { first_inner.to_u8() } else { 0 };
        skf_gen[1] = 0; // critical + reserved
        skf_gen[2..4].copy_from_slice(&(skf_payload_len as u16).to_be_bytes());

        // AAD = IKE header ‖ SKF generic header ‖ FragNum ‖ Total (before the IV).
        let mut aad = Vec::with_capacity(IkeHeader::LEN + 4 + SKF_EXTRA);
        aad.extend_from_slice(&hdr_bytes);
        aad.extend_from_slice(&skf_gen);
        aad.extend_from_slice(&frag_num.to_be_bytes());
        aad.extend_from_slice(&total.to_be_bytes());

        let ct_and_tag = gcm_seal(sk_e, &iv, &aad, &plaintext)?;

        let mut msg = Vec::with_capacity(total_len);
        msg.extend_from_slice(&hdr_bytes);
        msg.extend_from_slice(&skf_gen);
        msg.extend_from_slice(&frag_num.to_be_bytes());
        msg.extend_from_slice(&total.to_be_bytes());
        msg.extend_from_slice(&iv);
        msg.extend_from_slice(&ct_and_tag);
        out.push(msg);
    }
    Ok(out)
}

struct Fragment {
    frag_num: u16,
    total: u16,
    next_payload: u8,
    content: Vec<u8>,
}

fn open_fragment(message: &[u8], sk_e: &[u8]) -> Result<Fragment, IkeError> {
    let header = IkeHeader::parse(message)?;
    if header.next_payload != PayloadType::EncryptedFragment {
        return Err(IkeError::MissingPayload("SKF"));
    }
    let body = &message[IkeHeader::LEN..];
    if body.len() < 4 + SKF_MIN_BODY {
        return Err(IkeError::Truncated { need: 4 + SKF_MIN_BODY, have: body.len() });
    }
    let next_payload = body[0];
    let skf_payload_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if skf_payload_len < 4 + SKF_MIN_BODY || skf_payload_len > body.len() {
        return Err(IkeError::BadLength { declared: skf_payload_len, available: body.len() });
    }
    let frag_num = u16::from_be_bytes([body[4], body[5]]);
    let total = u16::from_be_bytes([body[6], body[7]]);
    let iv: [u8; IV_LEN] = body[8..16].try_into().unwrap();
    let ct_and_tag = &body[16..skf_payload_len];

    let aad = &message[..IkeHeader::LEN + 4 + SKF_EXTRA];
    let plaintext = gcm_open(sk_e, &iv, aad, ct_and_tag)?;

    let pad_len = *plaintext.last().ok_or(IkeError::Crypto("empty fragment"))? as usize;
    if pad_len + 1 > plaintext.len() {
        return Err(IkeError::Crypto("pad length exceeds fragment"));
    }
    Ok(Fragment {
        frag_num,
        total,
        next_payload,
        content: plaintext[..plaintext.len() - 1 - pad_len].to_vec(),
    })
}

/// Reassemble a set of SKF messages into `(first_inner_type, inner_bytes)`.
/// Fragments may arrive in any order; all of `1..=total` must be present exactly
/// once, and every fragment's AEAD tag must verify.
pub fn reassemble(messages: &[Vec<u8>], sk_e: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    let mut frags: Vec<Fragment> =
        messages.iter().map(|m| open_fragment(m, sk_e)).collect::<Result<_, _>>()?;
    if frags.is_empty() {
        return Err(IkeError::Crypto("no fragments"));
    }
    let total = frags[0].total;
    if total == 0 || frags.iter().any(|f| f.total != total) {
        return Err(IkeError::Crypto("inconsistent Total Fragments"));
    }
    if frags.len() != total as usize {
        return Err(IkeError::Crypto("wrong number of fragments"));
    }
    frags.sort_by_key(|f| f.frag_num);
    for (i, f) in frags.iter().enumerate() {
        if f.frag_num != (i + 1) as u16 {
            return Err(IkeError::Crypto("duplicate or missing fragment number"));
        }
    }
    let first_inner = PayloadType::from_u8(frags[0].next_payload);
    let mut inner = Vec::new();
    for f in &frags {
        inner.extend_from_slice(&f.content);
    }
    Ok((first_inner, inner))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::message::{ExchangeType, Flags};

    fn header() -> IkeHeader {
        IkeHeader {
            initiator_spi: 0x1111_2222_3333_4444,
            responder_spi: 0x5555_6666_7777_8888,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags { initiator: true, version: false, response: false },
            message_id: 1,
            length: 0,
        }
    }

    #[test]
    fn fragment_and_reassemble_roundtrip_any_order() {
        let sk_e = [0x33u8; 36];
        let inner: Vec<u8> = (0..=200u8).collect(); // 201 bytes
        let frags = build_fragments(&header(), PayloadType::IdInitiator, &inner, &sk_e, 1000, 30).unwrap();
        assert_eq!(frags.len(), 7); // ceil(201/30)

        for f in &frags {
            assert_eq!(IkeHeader::parse(f).unwrap().next_payload, PayloadType::EncryptedFragment);
        }

        // Reassemble from a shuffled order.
        let mut shuffled = frags.clone();
        shuffled.reverse();
        let (first, out) = reassemble(&shuffled, &sk_e).unwrap();
        assert_eq!(first, PayloadType::IdInitiator);
        assert_eq!(out, inner);
    }

    #[test]
    fn single_fragment_when_it_fits() {
        let sk_e = [1u8; 36];
        let inner = vec![9u8; 10];
        let frags = build_fragments(&header(), PayloadType::Nonce, &inner, &sk_e, 5, 1000).unwrap();
        assert_eq!(frags.len(), 1);
        let (first, out) = reassemble(&frags, &sk_e).unwrap();
        assert_eq!(first, PayloadType::Nonce);
        assert_eq!(out, inner);
    }

    #[test]
    fn missing_fragment_is_rejected() {
        let sk_e = [2u8; 36];
        let inner = vec![7u8; 100];
        let mut frags = build_fragments(&header(), PayloadType::IdInitiator, &inner, &sk_e, 1, 30).unwrap();
        frags.pop(); // drop the last fragment
        assert!(reassemble(&frags, &sk_e).is_err());
    }

    #[test]
    fn tampered_fragment_fails_authentication() {
        let sk_e = [4u8; 36];
        let inner = vec![3u8; 80];
        let mut frags = build_fragments(&header(), PayloadType::IdInitiator, &inner, &sk_e, 1, 30).unwrap();
        let last = frags[0].len() - 1;
        frags[0][last] ^= 1; // corrupt a tag byte in the first fragment
        assert_eq!(reassemble(&frags, &sk_e).unwrap_err(), IkeError::BadIntegrity);
    }
}
