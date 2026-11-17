//! IKEv2 spike: prove a full username/password (EAP-MSCHAPv2) handshake against
//! a Whisker IKEv2 endpoint, then report what the server actually hands back.
//!
//! Flow: IKE_SA_INIT on :500, then — because our source port is never 500, so
//! the responder always sees "NAT" — float IKE_AUTH/EAP to :4500 with the
//! non-ESP marker, exactly like a native phone.
//!
//! Credentials come from the environment so they never land in a file:
//!   IKE_USER, IKE_PASS, [IKE_HOST], [IKE_REMOTE_ID], [IKE_CA], [IKE_ESP=1]

use std::env;
use std::error::Error;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ryke::ikev2::message::{encode_payload_chain, first_payload_type};
use ryke::{
    build_encrypted_gcm, default_offer, initiator_complete, initiator_request, is_ike_on_4500,
    open_encrypted_gcm, payloads, prf, unwrap_ike_4500, wrap_ike_4500, Certificate, ChildSa,
    Configuration, Delete, EapEvent, EapInitiator, Entropy, EspSa, ExchangeType, Flags,
    Identification, IkeHeader, LocalSecret, Notify, OsEntropy, PayloadType, Role,
    SecurityAssociation, ServerVerify, TrafficSelectors,
};

const RECV_TIMEOUT: Duration = Duration::from_secs(10);

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, Box<dyn Error>> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    // Prefer IPv4: the inner tunnel only carries IPv4 traffic here.
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .or_else(|| addrs.first().copied())
        .ok_or_else(|| format!("no address for {host}").into())
}

/// Print the payload chain of a plain (unencrypted) IKE message.
fn dump_payload_types(msg: &[u8]) -> String {
    let Ok(hdr) = IkeHeader::parse(msg) else {
        return "<unparseable>".to_string();
    };
    let mut out = Vec::new();
    for p in payloads(hdr.next_payload, &msg[IkeHeader::LEN..]) {
        match p {
            Ok(p) => {
                let mut s = format!("{:?}", p.payload_type);
                if p.payload_type == PayloadType::Notify {
                    if let Ok(nfy) = Notify::parse(p.data) {
                        s.push_str(&format!("(type={})", nfy.notify_type));
                    }
                }
                out.push(s);
            }
            Err(e) => {
                out.push(format!("<parse error: {e}>"));
                break;
            }
        }
    }
    out.join(", ")
}

/// Describe an encrypted IKE message: payload chain, plus EAP/Notify details.
fn describe(msg: &[u8], sk_er: &[u8]) -> String {
    let Ok((first, inner)) = open_encrypted_gcm(msg, sk_er) else {
        return "<undecryptable>".to_string();
    };
    let mut parts = Vec::new();
    for p in payloads(first, &inner) {
        let Ok(p) = p else { break };
        let mut s = format!("{:?}", p.payload_type);
        if p.payload_type == PayloadType::Eap && p.data.len() >= 5 {
            s.push_str(&format!(
                "(code={} id={} type={} op={:?} len={})",
                p.data[0],
                p.data[1],
                p.data[4],
                p.data.get(5).copied(),
                p.data.len()
            ));
        }
        if p.payload_type == PayloadType::Notify {
            if let Ok(nfy) = Notify::parse(p.data) {
                s.push_str(&format!("(type={})", nfy.notify_type));
            }
        }
        parts.push(s);
    }
    parts.join(", ")
}

/// Dump the responder's certificate chain from an encrypted IKE_AUTH message.
fn dump_certs(msg: &[u8], sk_er: &[u8]) {
    let Ok((first, inner)) = open_encrypted_gcm(msg, sk_er) else {
        println!("⚠️  could not decrypt the first IKE_AUTH response for cert dump");
        return;
    };
    let dir = std::path::Path::new("out");
    let _ = fs::create_dir_all(dir);
    let mut n = 0;
    for p in payloads(first, &inner) {
        let Ok(p) = p else { break };
        if p.payload_type != PayloadType::Certificate {
            continue;
        }
        let Ok(cert) = Certificate::parse(p.data) else {
            continue;
        };
        let path = dir.join(format!("cert-{n}.der"));
        if fs::write(&path, &cert.data).is_ok() {
            println!("→ wrote {} ({} bytes)", path.display(), cert.data.len());
        }
        n += 1;
    }
    if n == 0 {
        println!("⚠️  the responder sent no CERT payload");
    }
}

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

/// A DNS A query for example.com, wrapped in IPv4 + UDP (no UDP checksum).
fn dns_query(src: Ipv4Addr, dst: Ipv4Addr, sport: u16) -> Vec<u8> {
    let mut dns = vec![
        0x12, 0x34, // transaction id
        0x01, 0x00, // flags: recursion desired
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR
    ];
    for label in ["example", "com"] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    dns.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

    let total = 20 + 8 + dns.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    let ck = checksum(&p[..20]);
    p[10..12].copy_from_slice(&ck.to_be_bytes());

    // A real UDP checksum: a zero checksum is legal for IPv4 but some
    // middleboxes drop datagrams that carry it.
    let mut udp = Vec::new();
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&53u16.to_be_bytes());
    udp.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(&dns);

    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&udp);

    let mut udp_ck = checksum(&pseudo);
    if udp_ck == 0 {
        udp_ck = 0xffff;
    }
    udp[6..8].copy_from_slice(&udp_ck.to_be_bytes());

    p.extend_from_slice(&udp);
    p
}

/// Tear the IKE SA down so the responder doesn't keep a session (and a virtual
/// IP) allocated for this account, which makes the next run fail.
fn send_delete(
    sock: &UdpSocket,
    peer: SocketAddr,
    spi_i: u64,
    spi_r: u64,
    sk_ei: &[u8],
    msg_id: u32,
    entropy: &mut OsEntropy,
) -> Result<(), Box<dyn Error>> {
    let inner = vec![(PayloadType::Delete, Delete::ike_sa().to_bytes())];
    let mut iv = [0u8; 8];
    entropy.fill(&mut iv);

    let msg = build_encrypted_gcm(
        IkeHeader {
            initiator_spi: spi_i,
            responder_spi: spi_r,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::Informational,
            flags: Flags {
                initiator: true,
                version: false,
                response: false,
            },
            message_id: msg_id,
            length: 0,
        },
        first_payload_type(&inner),
        &encode_payload_chain(&inner),
        sk_ei,
        &iv,
    )?;

    sock.send_to(&wrap_ike_4500(&msg), peer)?;
    println!("→ sent INFORMATIONAL DELETE (IKE SA released)");
    Ok(())
}

/// RFC 7296 §2.13 `prf+`, implemented here independently of the crate so the
/// ESP key schedule can be cross-checked.
fn prf_plus_local(prf_key: &[u8], seed: &[u8], out: &mut [u8]) {
    let mut prev: Vec<u8> = Vec::new();
    let mut filled = 0;
    let mut counter: u8 = 1;

    while filled < out.len() {
        let mut input = prev.clone();
        input.extend_from_slice(seed);
        input.push(counter);

        let block = prf(prf_key, &input);
        let take = (out.len() - filled).min(block.len());
        out[filled..filled + take].copy_from_slice(&block[..take]);

        filled += take;
        prev = block.to_vec();
        counter = counter.wrapping_add(1);
    }
}

/// Send a DNS query through an ESP SA and report whether a reply comes back.
fn run_probe(
    label: &str,
    sock: &UdpSocket,
    peer: SocketAddr,
    outbound: &mut EspSa,
    inbound: &EspSa,
    query: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    buf: &mut [u8],
    attempts: u32,
) -> bool {
    for attempt in 1..=attempts {
        // RFC 3948 §2.3 NAT keepalive, as a real NAT'd client sends.
        let _ = sock.send_to(&[0xFFu8], peer);
        println!("→ [{label}] ESP DNS query {src} → {dst}:53 (attempt {attempt})");
        match outbound.seal(query, 4) {
            Ok(pkt) => {
                if let Err(e) = sock.send_to(&pkt, peer) {
                    println!("⚠️  [{label}] send failed: {e}");
                    return false;
                }
            }
            Err(e) => {
                println!("⚠️  [{label}] seal failed: {e}");
                return false;
            }
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let Ok((n, _)) = sock.recv_from(buf) else {
                break;
            };
            if n == 1 {
                println!("← [{label}] NAT keepalive ({:#04x})", buf[0]);
                continue;
            }
            if is_ike_on_4500(&buf[..n]) {
                println!("← [{label}] IKE ({n} bytes) while waiting for ESP");
                continue;
            }
            match inbound.open(&buf[..n]) {
                Ok((inner, nh)) if inner.len() >= 28 && nh == 4 && inner[9] == 17 => {
                    let from = Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]);
                    let sport = u16::from_be_bytes([inner[20], inner[21]]);
                    println!(
                        "🎉 [{label}] ESP works: UDP reply from {from}:{sport} ({} bytes)",
                        inner.len()
                    );
                    return true;
                }
                Ok((inner, nh)) => {
                    println!("← [{label}] decrypted {} bytes, next_header={nh}", inner.len());
                }
                Err(e) => println!("← [{label}] {n} bytes failed to decrypt: {e}"),
            }
        }
    }
    false
}

/// Try every plausible SPI / key-direction / nonce-order combination against the
/// live responder, to find out empirically which convention it expects.
fn run_variants(
    sock: &UdpSocket,
    peer: SocketAddr,
    sk_d: &[u8],
    ni: &[u8],
    nr: &[u8],
    local_spi: u32,
    peer_spi: u32,
    query: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    buf: &mut [u8],
) {
    let mut seed = ni.to_vec();
    seed.extend_from_slice(nr);
    let mut km = vec![0u8; 72];
    prf_plus_local(sk_d, &seed, &mut km);

    let mut seed2 = nr.to_vec();
    seed2.extend_from_slice(ni);
    let mut km2 = vec![0u8; 72];
    prf_plus_local(sk_d, &seed2, &mut km2);

    let sets: [(&str, &[u8], &[u8]); 2] = [
        ("Ni|Nr", &km[..36], &km[36..]),
        ("Nr|Ni", &km2[..36], &km2[36..]),
    ];

    println!("=== trying every SPI/key/nonce combination ===");
    for (kname, k_first, k_second) in sets {
        for (sname, out_spi, in_spi) in [
            ("ours->out", local_spi, peer_spi),
            ("peers->out", peer_spi, local_spi),
        ] {
            for (dname, out_key, in_key) in [("encr_i", k_first, k_second), ("encr_r", k_second, k_first)] {
                let label = format!("{kname} {sname} {dname}");
                let (Ok(mut out), Ok(inb)) = (EspSa::new(out_spi, out_key), EspSa::new(in_spi, in_key)) else {
                    continue;
                };
                if run_probe(&label, sock, peer, &mut out, &inb, query, src, dst, buf, 1) {
                    println!("🎯 WORKING COMBINATION: {label}");
                    return;
                }
            }
        }
    }
    println!("=== no combination produced a reply ===");
}

fn main() -> Result<(), Box<dyn Error>> {
    let host = env_or("IKE_HOST", "mia-140-ike.whiskergalaxy.com");
    let remote_id = env_or("IKE_REMOTE_ID", &host);
    let user = env::var("IKE_USER").map_err(|_| "IKE_USER is not set")?;
    let pass = env::var("IKE_PASS").map_err(|_| "IKE_PASS is not set")?;
    let ca = env::var("IKE_CA").ok().map(fs::read).transpose()?;
    let probe_esp = env::var("IKE_ESP").is_ok();

    let server500 = resolve(&host, 500)?;
    let server4500 = SocketAddr::new(server500.ip(), 4500);
    println!("→ {host} ({remote_id}) = {server500}");

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(RECV_TIMEOUT))?;
    println!("→ local {}", sock.local_addr()?);

    let mut entropy = OsEntropy::new()?;
    let mut buf = vec![0u8; 16 * 1024];

    // ---- IKE_SA_INIT ----------------------------------------------------
    let local = LocalSecret::generate(&mut entropy, 32);
    let req = initiator_request(&local, &default_offer());
    println!("→ IKE_SA_INIT ({} bytes) → {server500}", req.len());
    sock.send_to(&req, server500)?;

    let (n, from) = sock
        .recv_from(&mut buf)
        .map_err(|e| format!("no IKE_SA_INIT response from {server500}: {e}"))?;
    println!("← {n} bytes from {from}: [{}]", dump_payload_types(&buf[..n]));

    let sa = initiator_complete(&local, &req, &buf[..n])?;
    println!(
        "✅ IKE_SA_INIT: spi_i={:#018x} spi_r={:#018x}",
        sa.spi_i, sa.spi_r
    );

    // Everything below needs these after `sa` is moved into the EAP state machine.
    let sk_d = sa.keys.sk_d.clone();
    let sk_ei = sa.keys.sk_ei.clone();
    let sk_er = sa.keys.sk_er.clone();
    let (ni, nr) = (sa.ni.clone(), sa.nr.clone());
    let (spi_i, spi_r) = (sa.spi_i, sa.spi_r);

    // ---- IKE_AUTH + EAP-MSCHAPv2, floated to :4500 ----------------------
    let verify = match &ca {
        Some(der) => {
            let now_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            println!("→ verifying the server cert against a {}-byte CA", der.len());
            ServerVerify::TrustedCas {
                cas: vec![der.clone()],
                expected_dns: remote_id.clone(),
                now_unix,
            }
        }
        None => {
            println!("⚠️  IKE_CA not set: the server certificate is NOT verified (spike only)");
            ServerVerify::Insecure
        }
    };

    // A fresh CHILD-SA SPI per run: reusing one collides with a SA the responder
    // may still have installed for a previous session.
    let child_spi = (entropy.next_u64() as u32) | 1;
    println!("→ child SPI {child_spi:#010x}");

    let mut init = EapInitiator::new(
        sa,
        Identification::fqdn(&user),
        user.as_bytes().to_vec(),
        pass,
        child_spi,
        verify,
    );

    let mut msg = init.start(&mut entropy)?;
    let mut last = Vec::new();
    let mut established = false;

    for step in 0..14 {
        println!("→ IKE_AUTH #{} → {server4500}", step + 1);
        sock.send_to(&wrap_ike_4500(&msg), server4500)?;

        let (n, from) = sock.recv_from(&mut buf)?;
        last = if is_ike_on_4500(&buf[..n]) {
            unwrap_ike_4500(&buf[..n])
                .ok_or("responder used the non-ESP marker but the payload was short")?
                .to_vec()
        } else {
            buf[..n].to_vec()
        };
        println!("← {n} bytes from {from}: [{}]", describe(&last, &sk_er));

        if step == 0 {
            dump_certs(&last, &sk_er);
        }

        match init.handle(&last, &mut entropy)? {
            EapEvent::Reply(next) => {
                if step == 0 {
                    println!("✅ server cert + AUTH accepted (EAP proceeding)");
                }
                msg = next;
            }
            EapEvent::Established(Some(final_msg)) => {
                sock.send_to(&wrap_ike_4500(&final_msg), server4500)?;
                println!("✅ EAP-MSCHAPv2 established — username/password accepted");
                established = true;
                // The responder's final CHILD-SA message is the next datagram.
                let (n, _) = sock.recv_from(&mut buf)?;
                last = if is_ike_on_4500(&buf[..n]) {
                    unwrap_ike_4500(&buf[..n])
                        .ok_or("responder used the non-ESP marker but the payload was short")?
                        .to_vec()
                } else {
                    buf[..n].to_vec()
                };
                break;
            }
            EapEvent::Established(None) => {
                println!("✅ EAP-MSCHAPv2 established — username/password accepted");
                established = true;
                break;
            }
            EapEvent::Failed => {
                let next_msg_id = IkeHeader::parse(&last).map(|h| h.message_id + 1).unwrap_or(6);
                let _ = send_delete(
                    &sock,
                    server4500,
                    spi_i,
                    spi_r,
                    &sk_ei,
                    next_msg_id,
                    &mut entropy,
                );
                return Err(format!(
                    "❌ EAP failed at step {step} — wrong credentials, or the server cert was rejected"
                )
                .into());
            }
        }
    }

    if !established {
        return Err("❌ EAP did not complete in 14 steps".into());
    }

    // ---- What did the responder actually give us? -----------------------
    let (first, inner) = open_encrypted_gcm(&last, &sk_er)?;
    let mut peer_child_spi = None;
    let mut assigned = None;

    for p in payloads(first, &inner) {
        let p = p?;
        match p.payload_type {
            PayloadType::SecurityAssociation => {
                for prop in SecurityAssociation::parse(p.data)?.proposals {
                    if prop.protocol_id == 3 && prop.spi.len() == 4 {
                        let spi = u32::from_be_bytes([
                            prop.spi[0],
                            prop.spi[1],
                            prop.spi[2],
                            prop.spi[3],
                        ]);
                        println!(
                            "→ CHILD SA proposal: spi={spi:#010x} transforms={:?}",
                            prop.transforms
                        );
                        peer_child_spi = Some(spi);
                    }
                }
            }
            PayloadType::Configuration => {
                let cfg = Configuration::parse(p.data)?;
                println!("→ CFG payload: type={} attrs={:?}", cfg.cfg_type, cfg.attrs);
                assigned = cfg.assigned_ipv4();
            }
            PayloadType::TrafficSelectorInitiator | PayloadType::TrafficSelectorResponder => {
                if let Ok(ts) = TrafficSelectors::parse(p.data) {
                    println!("→ {:?}: {:?}", p.payload_type, ts.selectors);
                }
            }
            PayloadType::Notify => {
                if let Ok(nfy) = Notify::parse(p.data) {
                    println!("→ NOTIFY type={} ({} bytes)", nfy.notify_type, nfy.data.len());
                }
            }
            _ => {}
        }
    }

    let Some(peer_spi) = peer_child_spi else {
        return Err("❌ the final IKE_AUTH carried no CHILD SA SPI".into());
    };
    match assigned {
        Some(ip) => println!("✅ assigned inner IPv4: {ip}"),
        None => println!("⚠️  no Configuration Payload — the server assigned no inner address"),
    }

    // ---- ESP data plane on :4500 ----------------------------------------
    let mut child = ChildSa::derive(&sk_d, &ni, &nr, Role::Initiator, child_spi, peer_spi);
    println!("✅ CHILD SA derived (ESP over UDP :4500)");

    if !probe_esp && env::var("IKE_VARIANTS").is_err() {
        println!("(set IKE_ESP=1 to probe the data plane, or IKE_VARIANTS=1 to sweep variants)");
        return Ok(());
    }

    let src = assigned.ok_or("cannot probe ESP without an assigned inner IPv4")?;
    let dst = Ipv4Addr::new(1, 1, 1, 1);
    let query = dns_query(src, dst, 44321);

    // The responder needs a moment to install its inbound SA; probing instantly
    // makes the first packets vanish.
    std::thread::sleep(Duration::from_millis(500));

    if env::var("IKE_VARIANTS").is_ok() {
        run_variants(
            &sock,
            server4500,
            &sk_d,
            &ni,
            &nr,
            child_spi,
            peer_spi,
            &query,
            src,
            dst,
            &mut buf,
        );
    }

    let mut worked = run_probe(
        "ryke ChildSa",
        &sock,
        server4500,
        &mut child.outbound,
        &child.inbound,
        &query,
        src,
        dst,
        &mut buf,
        5,
    );

    if !worked {
        // Cross-check: derive KEYMAT ourselves, straight from RFC 7296 §2.17
        // (initial CHILD SA: KEYMAT = prf+(SK_d, Ni | Nr), initiator→responder
        // first, 36 bytes per direction for AES-GCM-256).
        let mut seed = ni.clone();
        seed.extend_from_slice(&nr);
        let mut keymat = vec![0u8; 72];
        prf_plus_local(&sk_d, &seed, &mut keymat);
        println!(
            "→ independent KEYMAT: out[..4]={:02x?} in[..4]={:02x?}",
            &keymat[..4],
            &keymat[36..40]
        );

        let mut outbound = EspSa::new(peer_spi, &keymat[..36])?;
        let inbound = EspSa::new(child_spi, &keymat[36..])?;
        worked = run_probe(
            "independent prf+",
            &sock,
            server4500,
            &mut outbound,
            &inbound,
            &query,
            src,
            dst,
            &mut buf,
            2,
        );
    }

    // Always release the SA, whether or not the data plane worked.
    let next_msg_id = IkeHeader::parse(&last).map(|h| h.message_id + 1).unwrap_or(6);
    if let Err(e) = send_delete(
        &sock,
        server4500,
        spi_i,
        spi_r,
        &sk_ei,
        next_msg_id,
        &mut entropy,
    ) {
        println!("⚠️  could not send DELETE: {e}");
    }

    if worked {
        Ok(())
    } else {
        Err("❌ no reply over ESP — keys or traffic selectors may not match".into())
    }
}
