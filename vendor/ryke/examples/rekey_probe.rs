//! Live CHILD-SA rekey check: establish, then send a CREATE_CHILD_SA and require
//! the node to answer with a rekey the initiator can complete. Proves the node
//! won't drop a native client when it rekeys its CHILD SA (~20-40 min in).
//! Usage: rekey_probe <host> <psk> <client_id> <server_id>

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use ryke::ikev2::rekey::{build_rekey_request, initiator_complete_rekey};
use ryke::{AuthConfig, Client, Identification, OsEntropy};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: rekey_probe <host> <psk> <client_id> <server_id>");
        std::process::exit(2);
    }
    let (host, psk, client_id) = (&a[1], a[2].clone().into_bytes(), &a[3]);
    let ike_addr: SocketAddr = format!("{host}:500").parse().unwrap();

    let auth = AuthConfig::psk(Identification::fqdn(client_id), psk);
    let mut client = Client::bind("0.0.0.0:0", OsEntropy::new().unwrap()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let (sa, _id, _child, _assigned) = client.connect(ike_addr, &auth, 0xCAFE_1234).expect("handshake");
    println!("✅ established — sending CREATE_CHILD_SA (CHILD SA rekey)");

    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let ni = [0x37u8; 32];
    let new_spi = 0x1234_5678u32;
    let req = build_rekey_request(&sa, 2, 0xDEAD_BEEF, new_spi, &ni, &[5u8; 8]).unwrap();
    sock.send_to(&req, ike_addr).unwrap();

    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => {
            if initiator_complete_rekey(&sa, &ni, new_spi, &buf[..n]).is_ok() {
                println!("✅ CHILD SA REKEY ANSWERED — new CHILD SA derived from the node's reply 🎉");
            } else {
                println!("⚠️  got a response but could not complete the rekey");
                std::process::exit(1);
            }
        }
        Err(e) => {
            println!("❌ NO REKEY RESPONSE ({e}) — node would drop the client at CHILD SA lifetime");
            std::process::exit(1);
        }
    }
}
