//! Live Dead-Peer-Detection check: PSK handshake, then send an empty INFORMATIONAL
//! liveness probe and require the responder to answer with an (empty) INFORMATIONAL
//! ack. Proves the node won't silently drop the tunnel the way iOS's DPD does.
//! Usage: dpd_probe <host> <psk> <client_id> <server_id>

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use ryke::{dpd_request, open_informational, AuthConfig, Client, Identification, OsEntropy};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: dpd_probe <host> <psk> <client_id> <server_id>");
        std::process::exit(2);
    }
    let host = &a[1];
    let psk = a[2].clone().into_bytes();
    let client_id = &a[3];
    let server_id = &a[4];
    let ike_addr: SocketAddr = format!("{host}:500").parse().unwrap();

    let auth = AuthConfig::psk(Identification::fqdn(client_id), psk);
    let mut client = Client::bind("0.0.0.0:0", OsEntropy::new().unwrap()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let (sa, got_server_id, _child, _assigned) =
        client.connect(ike_addr, &auth, 0xCAFE_D00D).expect("IKE handshake");
    if got_server_id != Identification::fqdn(server_id) {
        eprintln!("⚠️  server identity {got_server_id:?} != fqdn({server_id})");
    }
    println!("✅ IKEv2 established — now probing DPD liveness…");

    // Empty INFORMATIONAL request (msg-id 2, after SA_INIT=0 / IKE_AUTH=1).
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let req = dpd_request(&sa, 2, &[0x11; 8]).unwrap();
    sock.send_to(&req, ike_addr).unwrap();

    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => match open_informational(&sa, &buf[..n]) {
            Ok(p) if p.is_empty() => {
                println!("✅ DPD LIVENESS ANSWERED — empty INFORMATIONAL ack received 🎉")
            }
            Ok(p) => println!("⚠️  INFORMATIONAL ack had {} payloads (expected empty)", p.len()),
            Err(e) => {
                println!("❌ could not open the response ({e:?})");
                std::process::exit(1);
            }
        },
        Err(e) => {
            println!("❌ NO DPD RESPONSE ({e}) — the node would be declared dead by iOS");
            std::process::exit(1);
        }
    }
}
