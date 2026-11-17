//! EAP-MSCHAPv2 client harness: SA_INIT, then drive the multi-message EAP
//! exchange (verifying the server's certificate against a CA) to completion.
//! Proves the node's EAP responder: server-cert auth + username/password.
//! Usage: ike_client_eap <host> <user> <password> <server_id> <ca.der>

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ryke::{
    default_offer, initiator_complete, initiator_request, EapEvent, EapInitiator, Identification,
    LocalSecret, OsEntropy, ServerVerify,
};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 6 {
        eprintln!("usage: ike_client_eap <host> <user> <password> <server_id> <ca.der>");
        std::process::exit(2);
    }
    let host = &a[1];
    let user = a[2].clone().into_bytes();
    let password = a[3].clone();
    let server_id = &a[4];
    let ca = std::fs::read(&a[5]).expect("read CA der");

    let ike: SocketAddr = format!("{host}:500").parse().unwrap();
    let mut entropy = OsEntropy::new().unwrap();
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();

    // 1. IKE_SA_INIT.
    let local = LocalSecret::generate(&mut entropy, 32);
    let req = initiator_request(&local, &default_offer());
    sock.send_to(&req, ike).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).expect("no SA_INIT response");
    let sa = initiator_complete(&local, &req, &buf[..n]).expect("SA_INIT complete");
    println!("✅ IKE_SA_INIT done");

    // 2. EAP: authenticate the server against the CA, then username/password.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let verify = ServerVerify::TrustedCas {
        cas: vec![ca],
        expected_dns: server_id.clone(),
        now_unix: now,
    };
    let mut init = EapInitiator::new(
        sa,
        Identification::fqdn(&a[2]),
        user,
        password,
        0xEA9_0001,
        verify,
    );
    if a.iter().any(|x| x == "--certreq") {
        init.set_send_certreq(true);
        println!("→ sending a CERTREQ in the first message (mimicking strongSwan)");
    }
    let mut msg = init.start(&mut entropy).expect("build EAP start");
    for step in 0..12 {
        sock.send_to(&msg, ike).unwrap();
        let (n, _) = sock.recv_from(&mut buf).expect("no EAP response");
        match init.handle(&buf[..n], &mut entropy).expect("EAP handle") {
            EapEvent::Reply(next) => {
                if step == 0 {
                    println!("✅ server cert verified against CA + server AUTH ok (EAP proceeding)");
                }
                msg = next;
            }
            EapEvent::Established(_) => {
                println!("✅ EAP-MSCHAPv2 established — username/password accepted 🎉");
                return;
            }
            EapEvent::Failed => {
                eprintln!("❌ EAP failed at step {step}");
                std::process::exit(1);
            }
        }
    }
    eprintln!("❌ EAP did not complete in 12 steps");
    std::process::exit(1);
}
