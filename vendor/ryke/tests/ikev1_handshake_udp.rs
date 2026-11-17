//! Integration test: a full IKEv1 handshake — Aggressive Mode + Quick Mode with
//! pre-shared-key auth — between ryke's own `ikev1::Client` and `ikev1::Server`
//! over real UDP sockets on loopback. Confirms both roles interoperate and that
//! the resulting ESP CHILD SAs share keys (what one seals, the other opens).

use std::time::Duration;

use ryke::crypto::DhGroup;
use ryke::ikev1::payloads::Id;
use ryke::ikev1::phase1::{InitiatorConfig, Phase1Config};
use ryke::ikev1::{Client, Server, ServerEvent};
use ryke::SeedEntropy;

#[test]
fn ikev1_full_handshake_over_udp_loopback() {
    let psk = b"correct horse battery staple".to_vec();

    let rcfg = Phase1Config { psk: psk.clone(), our_id: Id::ipv4([192, 168, 0, 1]) };
    let mut server = Server::bind("127.0.0.1:0", SeedEntropy::new(0x2222), rcfg).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Responder handles the four messages (Aggressive 1/3, Quick 1/3), then hands
    // the server back so we can pull out the CHILD SA.
    let handle = std::thread::spawn(move || {
        let e1 = server.handle_one().unwrap();
        let e2 = server.handle_one().unwrap();
        let e3 = server.handle_one().unwrap();
        let e4 = server.handle_one().unwrap();
        (e1, e2, e3, e4, server)
    });

    let icfg = InitiatorConfig {
        psk,
        our_id: Id::ipv4([10, 1, 1, 1]),
        group: DhGroup::Modp1024,
        xauth: false,
        ts_local: ([10, 0, 99, 0], [255, 255, 255, 0]),
        ts_remote: ([10, 0, 99, 0], [255, 255, 255, 0]),
    };
    let mut client = Client::bind("127.0.0.1:0", SeedEntropy::new(0x1111)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut est = client.connect(server_addr, &icfg).unwrap();

    let (e1, e2, e3, e4, mut server) = handle.join().unwrap();
    assert_eq!(e1, ServerEvent::Phase1SaInit);
    assert_eq!(e2, ServerEvent::Phase1Established);
    assert_eq!(e3, ServerEvent::QuickSaInit);
    assert!(matches!(e4, ServerEvent::ChildSaEstablished { .. }));

    // The two CHILD SAs must interoperate over the wire format.
    let mut rchild = server.take_child(est.phase1.cky_i).expect("server CHILD SA");
    let pkt: Vec<u8> = (0..40u8).collect();
    let sealed = est.child.outbound.seal(&pkt, 4).unwrap();
    let (got, nh) = rchild.inbound.open(&sealed).unwrap();
    assert_eq!(got, pkt);
    assert_eq!(nh, 4);

    let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
    let (got_r, _) = est.child.inbound.open(&sealed_r).unwrap();
    assert_eq!(got_r, pkt);
}
