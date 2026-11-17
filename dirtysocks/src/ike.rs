//! An IKEv2/IPsec transport, for networks that block `WireGuard`.
//!
//! The peer is authenticated with EAP-MSCHAPv2 (username/password) against a
//! server certificate that is verified against a trusted CA, and the tunnel's
//! ESP packets are carried inside UDP (:4500), so no privileges are needed.
//!
//! Two details of a real-world responder are easy to get wrong and are handled
//! here rather than in the IKE library:
//!
//! - NAT detection notifies are sent with values that cannot match, which forces
//!   both ends into UDP-encapsulated ESP. Without them the responder assumes
//!   there is no NAT and answers on raw IP protocol 50, which a usermode socket
//!   can never receive;
//! - the responder assigns the inner address through a Configuration Payload, so
//!   the first `IKE_AUTH` must request one or the CHILD SA is refused outright.

use std::{
    collections::VecDeque,
    io,
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket as StdUdpSocket},
    pin::Pin,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ryke::{
    default_offer, initiator_complete, initiator_request, is_ike_on_4500, open_encrypted_gcm,
    payloads, unwrap_ike_4500, wrap_ike_4500, ChildSa, Configuration, EapEvent, EapInitiator,
    Entropy, EspSa, Identification, LocalSecret, OsEntropy, PayloadType, Role, SecurityAssociation,
    ServerVerify,
};
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium},
    time::Instant as SmolInstant,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, Sleep},
};

use crate::{
    wg::{WgRxToken, WgTxToken},
    MAX_PACKET_SIZE,
};

/// How long to wait for a single handshake message.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound on the EAP message count (identity, challenge, success, AUTH).
const MAX_EAP_STEPS: usize = 14;
/// How often a NAT-T keepalive is sent so the UDP mapping stays open.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
/// The inner MTU: a conservative value that survives ESP overhead anywhere.
pub const DEFAULT_MTU: usize = 1280;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("ike error: {0}")]
    Ike(#[from] ryke::IkeError),
    #[error("no address found for {0}")]
    NoAddress(String),
    #[error("timed out during the IKE exchange")]
    Timeout,
    #[error("malformed IKE message from the server")]
    Malformed,
    #[error("authentication failed: wrong credentials, or the server certificate was rejected")]
    AuthFailed,
    #[error("the server did not complete the CHILD SA: {0}")]
    ChildSa(String),
    #[error("the server assigned no inner address")]
    NoAssignedAddress,
}

/// What the peer needs in order to authenticate and establish the tunnel.
#[derive(Clone, Debug)]
pub struct Credentials {
    /// Server hostname (or address).
    pub host: String,
    /// Username, which is also the local identity.
    pub user: String,
    pub password: String,
    /// The identity the server certificate must vouch for; usually `host`.
    pub remote_id: String,
    /// DER-encoded CA certificate used as the trust anchor.
    pub ca_der: Vec<u8>,
}

/// Runs the whole IKEv2 exchange. Blocking: call it from a blocking context.
///
/// Returns the ESP device and the inner address the server assigned.
pub fn connect(creds: &Credentials) -> Result<(Peer, Ipv4Addr), Error> {
    let server = resolve(&creds.host, 500)?;
    let server_esp = SocketAddr::new(server.ip(), 4500);

    let sock = StdUdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let mut entropy = OsEntropy::new()?;
    let mut buf = vec![0u8; MAX_PACKET_SIZE];

    // ---- IKE_SA_INIT ----
    let local = LocalSecret::generate(&mut entropy, 32);
    let request = initiator_request(&local, &default_offer());
    sock.send_to(&request, server)?;

    let (len, _) = sock.recv_from(&mut buf).map_err(|_| Error::Timeout)?;
    let sa = initiator_complete(&local, &request, &buf[..len])?;

    // Kept across the EAP state machine, which takes ownership of `sa`.
    let sk_d = sa.keys.sk_d.clone();
    let sk_er = sa.keys.sk_er.clone();
    let (ni, nr) = (sa.ni.clone(), sa.nr.clone());

    // A fresh CHILD-SA SPI per session; reusing one collides with a security
    // association the responder may still hold for an earlier session.
    let child_spi = (entropy.next_u64() as u32) | 1;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Timeout)?
        .as_secs();

    let mut initiator = EapInitiator::new(
        sa,
        Identification::fqdn(&creds.user),
        creds.user.as_bytes().to_vec(),
        creds.password.clone(),
        child_spi,
        ServerVerify::TrustedCas {
            cas: vec![creds.ca_der.clone()],
            expected_dns: creds.remote_id.clone(),
            now_unix,
        },
    );

    // ---- IKE_AUTH + EAP-MSCHAPv2, floated to :4500 like a NAT'd client ----
    let mut msg = initiator.start(&mut entropy)?;
    let mut last = Vec::new();
    let mut established = false;

    for _ in 0..MAX_EAP_STEPS {
        sock.send_to(&wrap_ike_4500(&msg), server_esp)?;
        last = receive_ike(&sock, &mut buf)?;

        match initiator.handle(&last, &mut entropy)? {
            EapEvent::Reply(next) => msg = next,
            EapEvent::Established(Some(final_msg)) => {
                sock.send_to(&wrap_ike_4500(&final_msg), server_esp)?;
                last = receive_ike(&sock, &mut buf)?;
                established = true;
                break;
            }
            EapEvent::Established(None) => {
                established = true;
                break;
            }
            EapEvent::Failed => return Err(Error::AuthFailed),
        }
    }

    if !established {
        return Err(Error::AuthFailed);
    }

    // ---- The responder's CHILD SA and the address it assigned ----
    let (first, inner) = open_encrypted_gcm(&last, &sk_er)?;
    let mut peer_spi = None;
    let mut assigned = None;

    for payload in payloads(first, &inner) {
        let payload = payload?;
        match payload.payload_type {
            PayloadType::SecurityAssociation => {
                for proposal in SecurityAssociation::parse(payload.data)?.proposals {
                    if proposal.protocol_id == 3 && proposal.spi.len() == 4 {
                        peer_spi = Some(u32::from_be_bytes([
                            proposal.spi[0],
                            proposal.spi[1],
                            proposal.spi[2],
                            proposal.spi[3],
                        ]));
                    }
                }
            }
            PayloadType::Configuration => {
                assigned = Configuration::parse(payload.data)?.assigned_ipv4();
            }
            _ => {}
        }
    }

    let peer_spi = peer_spi.ok_or_else(|| Error::ChildSa("no CHILD SA SPI".to_owned()))?;
    let assigned = assigned.ok_or(Error::NoAssignedAddress)?;

    let child = ChildSa::derive(&sk_d, &ni, &nr, Role::Initiator, child_spi, peer_spi);

    // The IKE SA stays alive (no DELETE): ESP and its liveness depend on it.
    // The socket has to be connected, both so `send` addresses the peer and so
    // `recv` only ever returns its packets.
    sock.connect(server_esp)?;
    sock.set_nonblocking(true)?;
    let conn = UdpSocket::from_std(sock)?;

    Ok((Peer::new(conn, child, server_esp, DEFAULT_MTU), assigned))
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, Error> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| Error::NoAddress(host.to_owned()))?
        .collect();

    // The tunnel carries IPv4, so prefer it when the name has both families.
    addrs
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| addrs.first())
        .copied()
        .ok_or_else(|| Error::NoAddress(host.to_owned()))
}

/// Reads one IKE datagram and strips the non-ESP marker if it is present.
fn receive_ike(sock: &StdUdpSocket, buf: &mut [u8]) -> Result<Vec<u8>, Error> {
    let (len, _) = sock.recv_from(buf).map_err(|_| Error::Timeout)?;
    let datagram = &buf[..len];

    if is_ike_on_4500(datagram) {
        return Ok(unwrap_ike_4500(datagram).ok_or(Error::Malformed)?.to_vec());
    }

    Ok(datagram.to_vec())
}

/// The ESP device: carries inner IP packets to the responder inside UDP.
pub struct Peer {
    conn: UdpSocket,
    addr: SocketAddr,
    outbound: EspSa,
    inbound: EspSa,
    mtu: usize,

    pub tx_queue: VecDeque<Vec<u8>>,
    pub rx_queue: VecDeque<Vec<u8>>,
    pub should_poll: bool,

    last_keepalive: Instant,
}

impl Peer {
    #[must_use]
    pub fn new(conn: UdpSocket, child: ChildSa, addr: SocketAddr, mtu: usize) -> Self {
        Self {
            conn,
            addr,
            outbound: child.outbound,
            inbound: child.inbound,
            mtu,
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            should_poll: false,
            last_keepalive: Instant::now(),
        }
    }

    pub async fn poll_device(
        &mut self,
        mut sleep: Pin<&mut Sleep>,
        recv_buf: &mut [u8],
    ) -> Result<(), Error> {
        while let Some(packet) = self.tx_queue.pop_back() {
            self.send_packet(&packet).await?;
            self.should_poll = true;
        }

        tokio::select! {
            ready = self.conn.readable() => {
                ready?;

                loop {
                    match self.conn.try_recv(recv_buf) {
                        Ok(0) => break,
                        Ok(len) => self.handle_datagram(&recv_buf[..len]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            // Don't spin on a permanent error.
                            tracing::warn!(?e, "failed to read from the IKE socket");
                            break;
                        }
                    }
                }
            }

            () = sleep.as_mut() => {
                sleep.reset(Instant::now() + KEEPALIVE_INTERVAL);
                self.send_keepalive().await;
            }
        }

        Ok(())
    }

    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let esp = self.outbound.seal(packet, next_header_ipv4())?;

        let sent = self.conn.send(&esp).await?;
        if sent < esp.len() {
            tracing::warn!(sent, total = esp.len(), "failed to send the whole ESP packet");
            self.tx_queue.push_front(packet[sent..].to_vec());
        }

        Ok(())
    }

    /// A single `0xFF` byte is the RFC 3948 NAT keepalive.
    async fn send_keepalive(&mut self) {
        if self.last_keepalive.elapsed() < KEEPALIVE_INTERVAL {
            return;
        }

        self.last_keepalive = Instant::now();

        if let Err(e) = self.conn.send(&[0xFF]).await {
            tracing::debug!(?e, "failed to send an IKE keepalive");
        }
    }

    fn handle_datagram(&mut self, datagram: &[u8]) {
        // Keepalives are a single byte; a non-ESP-marker datagram is IKE.
        if datagram.len() <= 1 || is_ike_on_4500(datagram) {
            return;
        }

        match self.inbound.open(datagram) {
            Ok((inner, _next_header)) => {
                tracing::trace!(len = inner.len(), ?self.addr, "decrypted ESP packet");
                self.rx_queue.push_front(inner);
                self.should_poll = true;
            }
            Err(e) => tracing::trace!(?e, "failed to decrypt an ESP datagram"),
        }
    }
}

/// Next Header value for a tunnelled IPv4 packet (RFC 1700).
const fn next_header_ipv4() -> u8 {
    4
}

impl Device for Peer {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx_queue.pop_back()?;

        Some((
            WgRxToken::new(packet),
            WgTxToken::new(&mut self.tx_queue),
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken::new(&mut self.tx_queue))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}
