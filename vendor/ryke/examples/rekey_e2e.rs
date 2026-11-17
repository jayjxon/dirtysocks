//! Definitive live test of a CHILD-SA rekey INCLUDING the data-plane rollover:
//! establish, ping through the tunnel, rekey the CHILD SA, then ping AGAIN on the
//! new SPI. A reply after the rekey proves the node rolled its data plane (SA,
//! cascade, injector) onto the new SPI — i.e. the tunnel survives the rekey.
//! Usage: rekey_e2e <host> <psk> <client_id> <server_id>

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use ryke::ikev2::rekey::{build_rekey_request, initiator_complete_rekey};
use ryke::{AuthConfig, ChildSa, Client, Identification, OsEntropy};

fn checksum(d: &[u8]) -> u16 {
    let mut s = 0u32;
    let mut i = 0;
    while i + 1 < d.len() {
        s += u16::from_be_bytes([d[i], d[i + 1]]) as u32;
        i += 2;
    }
    if i < d.len() {
        s += (d[i] as u32) << 8;
    }
    while (s >> 16) != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Vec<u8> {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64;
    p[9] = 1;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ck = checksum(&p[..20]);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    p[20] = 8;
    p[24..26].copy_from_slice(&0x1234u16.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    let ick = checksum(&p[20..]);
    p[22..24].copy_from_slice(&ick.to_be_bytes());
    p
}

/// Seal an ICMP echo with `child`, send to the ESP socket, and wait for an echo
/// reply. Returns true on a reply.
fn ping(esp: &UdpSocket, esp_addr: SocketAddr, child: &mut ChildSa, src: Ipv4Addr) -> bool {
    for seq in 1..=5u16 {
        let sealed = child.outbound.seal(&icmp_echo(src, Ipv4Addr::new(1, 1, 1, 1), seq), 4).unwrap();
        esp.send_to(&sealed, esp_addr).unwrap();
        let mut buf = [0u8; 2000];
        if let Ok((n, _)) = esp.recv_from(&mut buf) {
            if let Ok((inner, _)) = child.inbound.open(&buf[..n]) {
                if inner.len() >= 28 && inner[9] == 1 && inner[20] == 0 {
                    return true;
                }
            }
        }
    }
    false
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: rekey_e2e <host> <psk> <client_id> <server_id>");
        std::process::exit(2);
    }
    let (host, psk, client_id) = (&a[1], a[2].clone().into_bytes(), &a[3]);
    let ike_addr: SocketAddr = format!("{host}:500").parse().unwrap();
    let esp_addr: SocketAddr = format!("{host}:4500").parse().unwrap();

    let auth = AuthConfig::psk(Identification::fqdn(client_id), psk);
    let mut client = Client::bind("0.0.0.0:0", OsEntropy::new().unwrap()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let (sa, _id, mut child, assigned) = client.connect(ike_addr, &auth, 0xCAFE_2468).expect("handshake");
    let src = assigned.expect("no inner IP assigned");
    println!("✅ established, inner IP {src}");

    let esp = UdpSocket::bind("0.0.0.0:0").unwrap();
    esp.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    println!("→ pre-rekey ping: {}", if ping(&esp, esp_addr, &mut child, src) { "✅ reply" } else { "❌ no reply" });

    // Rekey the CHILD SA.
    let ike = UdpSocket::bind("0.0.0.0:0").unwrap();
    ike.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let ni = [0x71u8; 32];
    let new_spi = 0x0BAD_F00Du32;
    let req = build_rekey_request(&sa, 2, 0xDEAD_BEEF, new_spi, &ni, &[3u8; 8]).unwrap();
    ike.send_to(&req, ike_addr).unwrap();
    let mut buf = [0u8; 2048];
    let (n, _) = ike.recv_from(&mut buf).expect("no CREATE_CHILD_SA response");
    let mut new_child = initiator_complete_rekey(&sa, &ni, new_spi, &buf[..n]).expect("rekey complete");
    println!("✅ CHILD SA rekeyed");

    // Post-rekey ping on the NEW child SA / new SPI.
    if ping(&esp, esp_addr, &mut new_child, src) {
        println!("✅ POST-REKEY E2E: reply through the tunnel on the new SPI — rollover works 🎉");
    } else {
        println!("❌ POST-REKEY: no reply — data-plane rollover FAILED");
        std::process::exit(1);
    }
}
