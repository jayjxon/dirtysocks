//! End-to-end IKEv2 client example: a PSK handshake, then a tunneled ICMP echo.
//!
//! Runs a real IKEv2 (PSK) handshake against an IKEv2 responder on :500, then
//! sends an inner ICMP echo request as ESP to :4500 and waits for the echo
//! reply. The responder is expected to assign the client an inner IP via a
//! Configuration Payload and to forward the decrypted inner packet on toward the
//! internet, so a returning reply exercises the whole control- and data-plane
//! round trip.
//!
//! Usage: ike_client <server_host> <psk> <client_id> <server_id> [inner_src] [dst]
//!   inner_src defaults to the address the responder assigns via its
//!   Configuration Payload; the optional CLI arg is only a fallback if none is
//!   pushed. dst defaults to 1.1.1.1.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use ryke::{AuthConfig, Client, Identification, OsEntropy};

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

fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut p = vec![0u8; 28]; // IPv4(20) + ICMP echo(8)
    p[0] = 0x45;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[8] = 64;
    p[9] = 1; // ICMP
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ck = checksum(&p[..20]);
    p[10..12].copy_from_slice(&ck.to_be_bytes());
    p[20] = 8; // echo request
    p[24..26].copy_from_slice(&id.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    let ick = checksum(&p[20..]);
    p[22..24].copy_from_slice(&ick.to_be_bytes());
    p
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!("usage: ike_client <server_host> <psk> <client_id> <server_id> [inner_src] [dst]");
        std::process::exit(2);
    }
    let host = &a[1];
    let psk = a[2].clone().into_bytes();
    let client_id = &a[3];
    let server_id = &a[4];
    // The inner source is now assigned by the responder's Configuration Payload
    // (like a real phone); the optional arg is only a fallback if none is pushed.
    let inner_src_override: Option<Ipv4Addr> = a.get(5).and_then(|s| s.parse().ok());
    let dst: Ipv4Addr = a.get(6).map(|s| s.as_str()).unwrap_or("1.1.1.1").parse().expect("dst");

    let ike_addr: SocketAddr = format!("{host}:500").parse().expect("ike addr");
    let esp_addr: SocketAddr = format!("{host}:4500").parse().expect("esp addr");

    // 1. IKEv2 SA_INIT + IKE_AUTH (PSK) against the node's ryke terminator.
    let auth = AuthConfig::psk(Identification::fqdn(client_id), psk);
    let mut client = Client::bind("0.0.0.0:0", OsEntropy::new().expect("entropy")).expect("bind");
    client.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let (sa, got_server_id, mut child, assigned_ip) =
        client.connect(ike_addr, &auth, 0xCAFE_BABE).expect("IKE handshake");
    println!("✅ IKEv2 established with {host} — server_id={got_server_id:?}, spi_i={:#x}, spi_r={:#x}",
        sa.spi_i, sa.spi_r);
    if got_server_id != Identification::fqdn(server_id) {
        eprintln!("⚠️  server identity {got_server_id:?} != expected fqdn({server_id})");
    }
    let inner_src: Ipv4Addr = assigned_ip
        .or(inner_src_override)
        .expect("no inner IP assigned via Config Payload and none given on the CLI");
    match assigned_ip {
        Some(ip) => println!("✅ responder assigned inner IP via Config Payload: {ip} (like a real phone)"),
        None => println!("⚠️  no Config Payload from responder — using fallback inner IP {inner_src}"),
    }

    // 2. ESP data plane: seal an inner ICMP echo and send it to the ESP socket.
    let esp = UdpSocket::bind("0.0.0.0:0").expect("esp socket");
    esp.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    println!("→ routing ICMP echo {inner_src} -> {dst} through the tunnel (ESP to {esp_addr})");

    for seq in 1..=5u16 {
        let pkt = icmp_echo(inner_src, dst, 0x1234, seq);
        let sealed = child.outbound.seal(&pkt, 4).expect("seal esp");
        esp.send_to(&sealed, esp_addr).expect("send esp");

        let mut buf = [0u8; 2000];
        match esp.recv_from(&mut buf) {
            Ok((n, _)) => match child.inbound.open(&buf[..n]) {
                Ok((inner, _nh)) if inner.len() >= 28 && inner[9] == 1 && inner[20] == 0 => {
                    // ICMP type 0 == echo reply
                    let from = Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]);
                    println!("✅ E2E: ICMP echo REPLY from {from} (seq {seq}) — full tunnel round trip 🎉");
                    return;
                }
                Ok((inner, _)) => println!("  seq {seq}: got inner proto={} (not an echo reply), retrying", inner.get(9).copied().unwrap_or(0)),
                Err(e) => println!("  seq {seq}: ESP open failed ({e:?}), retrying"),
            },
            Err(e) => println!("  seq {seq}: no reply ({e}), retrying"),
        }
    }
    eprintln!("❌ no ICMP echo reply after 5 attempts");
    std::process::exit(1);
}
