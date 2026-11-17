//! Live RFC 7296 §2.1 retransmission check: establish, then send the SAME
//! INFORMATIONAL datagram twice. A compliant responder replays its cached response
//! verbatim, so the two replies must be byte-identical (a re-processed reply would
//! carry a fresh random IV and differ).
//! Usage: retransmit_probe <host> <psk> <client_id> <server_id>

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use ryke::{dpd_request, AuthConfig, Client, Identification, OsEntropy};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: retransmit_probe <host> <psk> <client_id> <server_id>");
        std::process::exit(2);
    }
    let (host, psk, client_id) = (&a[1], a[2].clone().into_bytes(), &a[3]);
    let ike_addr: SocketAddr = format!("{host}:500").parse().unwrap();

    let auth = AuthConfig::psk(Identification::fqdn(client_id), psk);
    let mut client = Client::bind("0.0.0.0:0", OsEntropy::new().unwrap()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let (sa, _id, _child, _assigned) = client.connect(ike_addr, &auth, 0xCAFE_F00D).expect("handshake");
    println!("✅ established — sending an INFORMATIONAL, then retransmitting it");

    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let req = dpd_request(&sa, 2, &[0x5a; 8]).unwrap(); // fixed IV → an identical datagram twice

    let recv = |label: &str| -> Vec<u8> {
        sock.send_to(&req, ike_addr).unwrap();
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => buf[..n].to_vec(),
            Err(e) => {
                println!("❌ {label}: no response ({e})");
                std::process::exit(1);
            }
        }
    };
    let first = recv("first");
    let second = recv("retransmit");

    if first == second {
        println!("✅ RETRANSMIT REPLAYED — identical {} bytes, response cached (RFC 7296 §2.1) 🎉", first.len());
    } else {
        println!("❌ responses DIFFER ({}‖{} bytes) — request was re-processed, not replayed", first.len(), second.len());
        std::process::exit(1);
    }
}
