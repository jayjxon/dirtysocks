//! NAT traversal (RFC 7296 §2.23 + RFC 3948).
//!
//! Two parts:
//! - **NAT detection**: in `IKE_SA_INIT` each peer sends
//!   `NAT_DETECTION_SOURCE_IP` and `NAT_DETECTION_DESTINATION_IP` notifies whose
//!   data is `SHA1(SPIi | SPIr | IP | Port)`. If a received hash doesn't match
//!   what the receiver computes from the *observed* addresses, a NAT sits on
//!   that side, and both peers move IKE (and ESP) to UDP port 4500.
//! - **UDP encapsulation**: on port 4500, IKE messages carry a 4-byte zero
//!   "non-ESP marker" so they can be told apart from ESP packets (whose first 4
//!   bytes are a non-zero SPI).

use std::net::IpAddr;

use sha1::{Digest, Sha1};

use crate::ikev2::payload::{notify_type, Notify};

/// The 4-byte non-ESP marker prefixed to IKE messages on UDP 4500 (RFC 3948 §2.2).
pub const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];

/// `SHA1(SPIi | SPIr | IP | Port)` — the NAT-detection hash (RFC 7296 §2.23).
pub fn nat_detection_hash(spi_i: u64, spi_r: u64, ip: IpAddr, port: u16) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(spi_i.to_be_bytes());
    h.update(spi_r.to_be_bytes());
    match ip {
        IpAddr::V4(a) => h.update(a.octets()),
        IpAddr::V6(a) => h.update(a.octets()),
    }
    h.update(port.to_be_bytes());
    h.finalize().into()
}

/// Build the `NAT_DETECTION_SOURCE_IP` notify for our own address as we see it.
pub fn source_ip_notify(spi_i: u64, spi_r: u64, our_ip: IpAddr, our_port: u16) -> Notify {
    Notify::status(
        notify_type::NAT_DETECTION_SOURCE_IP,
        nat_detection_hash(spi_i, spi_r, our_ip, our_port).to_vec(),
    )
}

/// Build the `NAT_DETECTION_DESTINATION_IP` notify for the peer's address.
pub fn destination_ip_notify(spi_i: u64, spi_r: u64, peer_ip: IpAddr, peer_port: u16) -> Notify {
    Notify::status(
        notify_type::NAT_DETECTION_DESTINATION_IP,
        nat_detection_hash(spi_i, spi_r, peer_ip, peer_port).to_vec(),
    )
}

/// Given the peer's `NAT_DETECTION_SOURCE_IP` notify data and the address we
/// actually observed the packet coming *from*, return whether the **peer** is
/// behind a NAT (its source address was translated → hash mismatch).
pub fn peer_is_behind_nat(source_notify_data: &[u8], spi_i: u64, spi_r: u64, observed_peer_ip: IpAddr, observed_peer_port: u16) -> bool {
    source_notify_data != nat_detection_hash(spi_i, spi_r, observed_peer_ip, observed_peer_port)
}

/// Given the peer's `NAT_DETECTION_DESTINATION_IP` notify data and our own
/// address as the packet arrived *to*, return whether **we** are behind a NAT
/// (our address was translated in transit → hash mismatch).
pub fn we_are_behind_nat(dest_notify_data: &[u8], spi_i: u64, spi_r: u64, our_ip: IpAddr, our_port: u16) -> bool {
    dest_notify_data != nat_detection_hash(spi_i, spi_r, our_ip, our_port)
}

/// Whether a datagram received on UDP 4500 is an IKE message (has the non-ESP
/// marker) rather than an ESP packet.
pub fn is_ike_on_4500(datagram: &[u8]) -> bool {
    datagram.len() >= 4 && datagram[..4] == NON_ESP_MARKER
}

/// Prefix an IKE message with the non-ESP marker for sending on UDP 4500.
pub fn wrap_ike_4500(message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + message.len());
    out.extend_from_slice(&NON_ESP_MARKER);
    out.extend_from_slice(message);
    out
}

/// Strip the non-ESP marker from an IKE datagram received on UDP 4500.
pub fn unwrap_ike_4500(datagram: &[u8]) -> Option<&[u8]> {
    if is_ike_on_4500(datagram) {
        Some(&datagram[4..])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const SPI_I: u64 = 0x1122_3344_5566_7788;
    const SPI_R: u64 = 0x99AA_BBCC_DDEE_FF00;

    #[test]
    fn no_nat_when_addresses_match() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let port = 4500;
        let src = source_ip_notify(SPI_I, SPI_R, ip, port);
        // The peer observes us at exactly the address we hashed → no NAT.
        assert!(!peer_is_behind_nat(&src.data, SPI_I, SPI_R, ip, port));
    }

    #[test]
    fn nat_detected_when_address_translated() {
        let claimed = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)); // private, as the sender sees itself
        let observed = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)); // public, after NAT
        let src = source_ip_notify(SPI_I, SPI_R, claimed, 500);
        assert!(peer_is_behind_nat(&src.data, SPI_I, SPI_R, observed, 500));
    }

    #[test]
    fn non_esp_marker_roundtrips_and_distinguishes_esp() {
        let ike = b"\x11\x22an IKE message";
        let wrapped = wrap_ike_4500(ike);
        assert!(is_ike_on_4500(&wrapped));
        assert_eq!(unwrap_ike_4500(&wrapped).unwrap(), ike);

        // An ESP packet begins with a non-zero SPI, so it's not mistaken for IKE.
        let esp = [0xCA, 0xFE, 0xBA, 0xBE, 0x00];
        assert!(!is_ike_on_4500(&esp));
        assert!(unwrap_ike_4500(&esp).is_none());
    }
}
