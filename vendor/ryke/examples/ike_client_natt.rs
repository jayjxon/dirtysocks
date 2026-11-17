//! NAT-T end-to-end harness — emulates a **native phone behind NAT**.
//!
//! Unlike `ike_client` (which keeps IKE on :500), this drives the exact flow a
//! NAT'd iOS/Android client uses: SA_INIT on :500, then — having "detected NAT"
//! from the responder's NAT_DETECTION notifies — it FLOATS IKE_AUTH to UDP :4500
//! wrapped in the non-ESP marker, and runs ESP on :4500 too. Proves the
//! terminator answers IKE on :4500 and hands back a Config-Payload address.
//!
//! Usage: ike_client_natt <host> <psk> <client_id> <server_id> [dst=1.1.1.1]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use ryke::{
    default_offer, initiator_auth_request, initiator_complete, initiator_request,
    initiator_verify_auth, is_ike_on_4500, notify_type, payloads, unwrap_ike_4500, wrap_ike_4500,
    AuthConfig, ChildSa, Entropy, Identification, IkeHeader, LocalSecret, Notify, OsEntropy,
    PayloadType, Role,
};

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    let ick = checksum(&p[20..]);
    p[22..24].copy_from_slice(&ick.to_be_bytes());
    p
}

/// Does the SA_INIT response carry both NAT_DETECTION notifies?
fn has_nat_detection(response: &[u8]) -> bool {
    let Ok(hdr) = IkeHeader::parse(response) else { return false };
    let (mut src, mut dst) = (false, false);
    for p in payloads(hdr.next_payload, &response[IkeHeader::LEN..]) {
        let Ok(p) = p else { break };
        if p.payload_type == PayloadType::Notify {
            if let Ok(n) = Notify::parse(p.data) {
                src |= n.notify_type == notify_type::NAT_DETECTION_SOURCE_IP;
                dst |= n.notify_type == notify_type::NAT_DETECTION_DESTINATION_IP;
            }
        }
    }
    src && dst
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: ike_client_natt <host> <psk> <client_id> <server_id> [dst]");
        std::process::exit(2);
    }
    let host = &a[1];
    let psk = a[2].clone().into_bytes();
    let client_id = &a[3];
    let server_id = &a[4];
    let dst: Ipv4Addr = a.get(5).map(|s| s.as_str()).unwrap_or("1.1.1.1").parse().unwrap();

    let ike500: SocketAddr = format!("{host}:500").parse().unwrap();
    let esp4500: SocketAddr = format!("{host}:4500").parse().unwrap();

    let mut entropy = OsEntropy::new().expect("entropy");
    let sock = UdpSocket::bind("0.0.0.0:0").expect("bind");
    sock.set_read_timeout(Some(Duration::from_secs(8))).unwrap();

    // 1. IKE_SA_INIT on :500.
    let local = LocalSecret::generate(&mut entropy, 32);
    let req = initiator_request(&local, &default_offer());
    sock.send_to(&req, ike500).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).expect("no SA_INIT response");
    let sa_resp = buf[..n].to_vec();
    if has_nat_detection(&sa_resp) {
        println!("✅ SA_INIT response carries NAT_DETECTION notifies → a NAT'd client floats to :4500");
    } else {
        eprintln!("⚠️  SA_INIT response has no NAT_DETECTION — a real phone would not float");
    }
    let sa = initiator_complete(&local, &req, &sa_resp).expect("SA_INIT complete");
    println!("✅ IKE_SA_INIT done (spi_i={:#x}, spi_r={:#x})", sa.spi_i, sa.spi_r);

    // 2. IKE_AUTH FLOATED to :4500 (wrapped in the non-ESP marker), as a NAT'd
    //    client does once it has detected the NAT.
    let auth = AuthConfig::psk(Identification::fqdn(client_id), psk);
    let child_spi = 0xBEEF_0042u32;
    let mut iv = [0u8; 8];
    entropy.fill(&mut iv);
    let auth_req = initiator_auth_request(&sa, &auth, child_spi, &iv).expect("build IKE_AUTH");
    sock.send_to(&wrap_ike_4500(&auth_req), esp4500).unwrap();

    let (n, _) = sock.recv_from(&mut buf).expect("no IKE_AUTH response on :4500");
    let auth_resp = unwrap_ike_4500(&buf[..n]).expect("IKE_AUTH reply lacked non-ESP marker");
    let (got_server_id, peer_child_spi, assigned) =
        initiator_verify_auth(&sa, auth_resp, &auth).expect("IKE_AUTH verify");
    println!("✅ IKE_AUTH answered on :4500 (NAT-T float works) — server_id={got_server_id:?}");
    if got_server_id != Identification::fqdn(server_id) {
        eprintln!("⚠️  server identity mismatch (expected fqdn({server_id}))");
    }
    let inner_src = assigned.expect("responder assigned no inner IP via Config Payload");
    println!("✅ Config-Payload inner IP: {inner_src}");

    // 3. ESP on :4500 (UDP-encapsulated, SPI-first, no marker).
    let mut child = ChildSa::derive(&sa.keys.sk_d, &sa.ni, &sa.nr, Role::Initiator, child_spi, peer_child_spi);
    for seq in 1..=5u16 {
        let sealed = child.outbound.seal(&icmp_echo(inner_src, dst, seq), 4).unwrap();
        sock.send_to(&sealed, esp4500).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            let Ok((n, _)) = sock.recv_from(&mut buf) else { break };
            // Ignore any stray IKE on :4500; only ESP replies matter here.
            if is_ike_on_4500(&buf[..n]) {
                continue;
            }
            if let Ok((inner, _)) = child.inbound.open(&buf[..n]) {
                if inner.len() >= 28 && inner[9] == 1 && inner[20] == 0 {
                    let from = Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]);
                    println!("✅ NAT-T E2E: ICMP echo REPLY from {from} — a NAT'd phone's full path works 🎉");
                    return;
                }
            }
        }
    }
    eprintln!("❌ no ICMP reply over the NAT-T (:4500) path");
    std::process::exit(1);
}
