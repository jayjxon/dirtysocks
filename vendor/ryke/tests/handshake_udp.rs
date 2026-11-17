//! Integration test: a full IKEv2 handshake — `IKE_SA_INIT` + `IKE_AUTH` with
//! mutual pre-shared-key auth — between ryke's own `Client` and `Server` over
//! real UDP sockets on loopback. Exercises both roles end to end and confirms
//! each side verifies the other's identity.

use std::time::Duration;

use ryke::{AuthConfig, Client, Identification, Role, SeedEntropy, Server, ServerEvent};

#[test]
fn full_handshake_over_udp_loopback() {
    let psk = b"correct horse battery staple".to_vec();

    let server_auth = AuthConfig::psk(Identification::fqdn("gw.example"), psk.clone());
    let mut server = Server::bind("127.0.0.1:0", SeedEntropy::new(0x1234), server_auth).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Responder handles SA_INIT then IKE_AUTH on its own thread, then hands the
    // server back so we can pull out the established CHILD SA.
    let handle = std::thread::spawn(move || {
        let e1 = server.handle_one().unwrap();
        let e2 = server.handle_one().unwrap();
        (e1, e2, server)
    });

    let client_auth = AuthConfig::psk(Identification::fqdn("client.example"), psk);
    let mut client = Client::bind("127.0.0.1:0", SeedEntropy::new(0x5678)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let (sa, server_id, mut client_child, _assigned) = client.connect(server_addr, &client_auth, 0x1234_5678).unwrap();

    let (e1, e2, mut server) = handle.join().unwrap();
    assert!(matches!(e1, ServerEvent::SaInit { .. }));
    match e2 {
        ServerEvent::Established { peer_id, spi_i, spi_r } => {
            assert_eq!(peer_id, Identification::fqdn("client.example")); // server verified client
            assert_eq!(spi_i, sa.spi_i);
            assert_eq!(spi_r, sa.spi_r);
        }
        other => panic!("expected Established, got {other:?}"),
    }

    // The client verified the server's identity too.
    assert_eq!(server_id, Identification::fqdn("gw.example"));
    assert_eq!(sa.role, Role::Initiator);

    // Both sides derived an ESP CHILD SA whose keys interoperate: what the client
    // seals, the server opens, and vice versa.
    let mut server_child = server.take_child(sa.spi_i, sa.spi_r).expect("server CHILD SA");
    let pkt: Vec<u8> = (0..40u8).collect();
    let sealed = client_child.outbound.seal(&pkt, 4).unwrap();
    let (got, nh) = server_child.inbound.open(&sealed).unwrap();
    assert_eq!(got, pkt);
    assert_eq!(nh, 4);
    let sealed_r = server_child.outbound.seal(&pkt, 4).unwrap();
    let (got_r, _) = client_child.inbound.open(&sealed_r).unwrap();
    assert_eq!(got_r, pkt);
}
