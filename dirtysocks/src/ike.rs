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
    build_informational, default_offer, dpd_request, initiator_complete, initiator_request,
    is_ike_on_4500, open_encrypted_gcm, open_informational, payloads, unwrap_ike_4500,
    wrap_ike_4500, ChildSa, CompletedSaInit, Configuration, EapEvent, EapInitiator, Entropy, EspSa,
    ExchangeType, Identification, IkeHeader, LocalSecret, OsEntropy, PayloadType, Role,
    SecurityAssociation, ServerVerify,
};
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium},
    time::Instant as SmolInstant,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc::{error::TryRecvError, unbounded_channel, UnboundedReceiver},
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
/// A DPD probe is sent once nothing has been received for this long.
const DPD_INTERVAL: Duration = Duration::from_secs(30);
/// An unanswered probe for this long means the peer is gone.
const DPD_TIMEOUT: Duration = Duration::from_secs(8);
/// Outbound traffic with no reply for this long means the data path is dead,
/// even when the control plane still answers.
const ESP_STALL_TIMEOUT: Duration = Duration::from_secs(5);
/// Re-handshake before the SA expires, well ahead of the server's lifetime.
const REKEY_INTERVAL: Duration = Duration::from_secs(45 * 60);
/// How long to wait before retrying a failed handshake.
const REHANDSHAKE_RETRY: Duration = Duration::from_secs(5);
/// How often the peer's timers are checked.
const TICK: Duration = Duration::from_secs(1);
/// How often to look for a re-handshake result while one is in flight. The new
/// inner address has to reach the interface promptly, or new connections are
/// opened with the stale one and the peer silently drops them.
const REHANDSHAKE_POLL: Duration = Duration::from_millis(100);
/// Outbound packets buffered while the tunnel is down; smoltcp retransmits.
const MAX_QUEUED_TX: usize = 256;
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
    #[error("handshake task failed: {0}")]
    Join(#[from] tokio::task::JoinError),
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

    // The IKE SA has to stay alive (no DELETE): ESP and its liveness depend on
    // it. Its state is kept so the tunnel can be probed, answered and
    // re-handshaked later without restarting the proxy.
    let liveness = initiator.into_sa();
    let next_msg_id = IkeHeader::parse(&last)?.message_id.saturating_add(1);

    // The socket has to be connected, both so `send` addresses the peer and so
    // `recv` only ever returns its packets.
    sock.connect(server_esp)?;
    sock.set_nonblocking(true)?;
    let conn = UdpSocket::from_std(sock)?;

    let peer = Peer::new(conn, child, server_esp, DEFAULT_MTU, assigned).with_control(
        creds.clone(),
        liveness,
        next_msg_id,
    );

    Ok((peer, assigned))
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
    /// The inner address the server assigned; a re-handshake can change it.
    assigned: Ipv4Addr,

    pub tx_queue: VecDeque<Vec<u8>>,
    pub rx_queue: VecDeque<Vec<u8>>,
    pub should_poll: bool,

    last_keepalive: Instant,
    /// The last time the data path proved itself alive (ESP or a NAT keepalive).
    last_esp: Instant,
    /// The last time anything at all was received.
    last_rx: Instant,

    /// The IKE SA, needed to probe and answer the peer after the handshake.
    liveness: Option<Liveness>,
    /// What to re-handshake with; `None` disables recovery.
    creds: Option<Credentials>,
    /// Encrypted IKE messages waiting to be sent.
    ike_tx: VecDeque<Vec<u8>>,
    rehandshake: Option<UnboundedReceiver<Result<(Self, Ipv4Addr), Error>>>,
    retry_at: Option<Instant>,
    /// Set when the server moved us to a different inner address.
    new_address: Option<Ipv4Addr>,
}

/// The control-plane state of an established IKE SA, kept so the peer can be
/// probed and answered (RFC 7296 §2.4) instead of silently going stale.
struct Liveness {
    sa: CompletedSaInit,
    /// The next IKE Message ID we may use (RFC 7296 §2.2).
    next_msg_id: u32,
    established_at: Instant,
    /// When the outstanding DPD probe was sent.
    probe_sent: Option<Instant>,
}

impl Peer {
    fn new(
        conn: UdpSocket,
        child: ChildSa,
        addr: SocketAddr,
        mtu: usize,
        assigned: Ipv4Addr,
    ) -> Self {
        let now = Instant::now();

        Self {
            conn,
            addr,
            outbound: child.outbound,
            inbound: child.inbound,
            mtu,
            assigned,
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            should_poll: false,
            last_keepalive: now,
            last_esp: now,
            last_rx: now,
            liveness: None,
            creds: None,
            ike_tx: VecDeque::new(),
            rehandshake: None,
            retry_at: None,
            new_address: None,
        }
    }

    /// Keeps the IKE SA and the credentials, which is what enables liveness
    /// probing and re-handshaking.
    fn with_control(mut self, creds: Credentials, sa: CompletedSaInit, next_msg_id: u32) -> Self {
        self.creds = Some(creds);
        self.liveness = Some(Liveness {
            sa,
            next_msg_id,
            established_at: Instant::now(),
            probe_sent: None,
        });
        self
    }

    /// The inner address changed on a re-handshake; the caller has to reconfigure
    /// the interface, or every packet from the new SA carries a stale source.
    pub fn take_new_address(&mut self) -> Option<Ipv4Addr> {
        self.new_address.take()
    }

    pub async fn poll_device(
        &mut self,
        mut sleep: Pin<&mut Sleep>,
        recv_buf: &mut [u8],
    ) -> Result<(), Error> {
        self.collect_rehandshake();

        while let Some(packet) = self.tx_queue.pop_back() {
            self.send_packet(&packet).await?;
            self.should_poll = true;
        }

        // Nothing can be delivered while the tunnel is down, so bound the queue;
        // smoltcp retransmits whatever is dropped here.
        while self.tx_queue.len() > MAX_QUEUED_TX {
            self.tx_queue.pop_front();
        }

        self.flush_ike().await;

        let wake = if self.rehandshake.is_some() {
            REHANDSHAKE_POLL
        } else {
            TICK
        };

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

                self.flush_ike().await;
            }

            () = sleep.as_mut() => {
                sleep.reset(Instant::now() + wake);
                self.tick().await;
                self.flush_ike().await;
            }
        }

        Ok(())
    }

    /// Adopts the tunnel of a finished re-handshake, if there is one.
    ///
    /// Checked with `try_recv` rather than awaited inside `select!`: this future
    /// is cancelled whenever another interface event wins, and a receiver moved
    /// into a branch would take the result down with it.
    fn collect_rehandshake(&mut self) {
        let Some(receiver) = self.rehandshake.as_mut() else {
            return;
        };

        match receiver.try_recv() {
            Ok(result) => {
                self.rehandshake = None;
                self.apply_rehandshake(result);
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.rehandshake = None;
                self.retry_at = Some(Instant::now() + REHANDSHAKE_RETRY);
            }
        }
    }

    fn apply_rehandshake(&mut self, result: Result<(Self, Ipv4Addr), Error>) {
        match result {
            Ok((fresh, assigned)) => {
                self.retry_at = None;
                self.adopt(fresh, assigned);
                self.should_poll = true;
            }
            Err(e) => {
                self.retry_at = Some(Instant::now() + REHANDSHAKE_RETRY);
                tracing::warn!(?e, "IKEv2 re-handshake failed; retrying");
            }
        }
    }

    fn adopt(&mut self, fresh: Self, assigned: Ipv4Addr) {
        self.conn = fresh.conn;
        self.addr = fresh.addr;
        self.outbound = fresh.outbound;
        self.inbound = fresh.inbound;
        self.liveness = fresh.liveness;

        let now = Instant::now();
        self.last_keepalive = now;
        self.last_esp = now;
        self.last_rx = now;

        tracing::info!(%assigned, "IKEv2 tunnel re-established");

        if assigned != self.assigned {
            tracing::info!(
                old = %self.assigned,
                new = %assigned,
                "the server assigned a new inner address"
            );
            self.assigned = assigned;
            self.new_address = Some(assigned);
        }
    }

    /// Starts a fresh full handshake, unless one is already running or the last
    /// attempt failed too recently.
    fn start_rehandshake(&mut self) {
        if self.rehandshake.is_some() {
            return;
        }

        let Some(creds) = self.creds.clone() else {
            return;
        };

        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }

        let (sender, receiver) = unbounded_channel();

        tokio::spawn(async move {
            let result = match tokio::task::spawn_blocking(move || connect(&creds)).await {
                Ok(result) => result,
                Err(e) => Err(Error::Join(e)),
            };

            let _ = sender.send(result);
        });

        self.rehandshake = Some(receiver);
    }

    /// Periodic work: keepalive, dead-peer detection and proactive rekeying.
    async fn tick(&mut self) {
        if self.last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            self.last_keepalive = Instant::now();

            if let Err(e) = self.conn.send(&[0xFF]).await {
                tracing::debug!(?e, "failed to send an IKE keepalive");
            }
        }

        if self.rehandshake.is_some() || self.creds.is_none() {
            return;
        }

        // Traffic that gets no reply is the strongest signal that the SA is dead,
        // even when the control plane still answers.
        if !self.tx_queue.is_empty() && self.last_esp.elapsed() >= ESP_STALL_TIMEOUT {
            tracing::warn!("no replies while sending; re-handshaking");
            self.start_rehandshake();
            return;
        }

        let rekey = self
            .liveness
            .as_ref()
            .is_some_and(|liveness| liveness.established_at.elapsed() >= REKEY_INTERVAL);

        if rekey {
            tracing::info!("rekeying the IKE SA before it expires");
            self.start_rehandshake();
            return;
        }

        let unanswered = self
            .liveness
            .as_ref()
            .and_then(|liveness| liveness.probe_sent)
            .is_some_and(|sent| self.last_rx < sent && sent.elapsed() >= DPD_TIMEOUT);

        if unanswered {
            if let Some(liveness) = self.liveness.as_mut() {
                liveness.probe_sent = None;
            }

            tracing::warn!("the IKE peer stopped answering; re-handshaking");
            self.start_rehandshake();
            return;
        }

        let due = self
            .liveness
            .as_ref()
            .is_some_and(|liveness| liveness.probe_sent.is_none())
            && self.last_rx.elapsed() >= DPD_INTERVAL;

        if !due {
            return;
        }

        // An empty INFORMATIONAL request: a live peer has to answer it.
        let probe = self.liveness.as_ref().and_then(|liveness| {
            let id = liveness.next_msg_id;
            let iv = rand::random::<[u8; 8]>();

            dpd_request(&liveness.sa, id, &iv).ok().map(|msg| (msg, id))
        });

        if let Some((msg, id)) = probe {
            if let Some(liveness) = self.liveness.as_mut() {
                liveness.next_msg_id = id.wrapping_add(1);
                liveness.probe_sent = Some(Instant::now());
            }

            self.ike_tx.push_back(wrap_ike_4500(&msg));
            tracing::debug!(id, "sent a DPD liveness probe");
        }
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

    async fn flush_ike(&mut self) {
        while let Some(msg) = self.ike_tx.pop_front() {
            if let Err(e) = self.conn.send(&msg).await {
                tracing::debug!(?e, "failed to send an IKE message");
                break;
            }
        }
    }

    fn handle_datagram(&mut self, datagram: &[u8]) {
        // A single byte is the RFC 3948 NAT keepalive.
        if datagram.len() <= 1 {
            self.last_rx = Instant::now();
            self.last_esp = Instant::now();
            return;
        }

        if is_ike_on_4500(datagram) {
            self.handle_ike(datagram);
            return;
        }

        self.last_rx = Instant::now();

        match self.inbound.open(datagram) {
            Ok((inner, _next_header)) => {
                self.last_esp = Instant::now();
                tracing::trace!(len = inner.len(), ?self.addr, "decrypted ESP packet");
                self.rx_queue.push_front(inner);
                self.should_poll = true;
            }
            Err(e) => tracing::trace!(?e, "failed to decrypt an ESP datagram"),
        }
    }

    /// Keeps the IKE SA alive: answers the peer's probes, notices a DELETE, and
    /// treats a decrypted INFORMATIONAL as proof the peer is reachable.
    fn handle_ike(&mut self, datagram: &[u8]) {
        self.last_rx = Instant::now();

        let Some(body) = unwrap_ike_4500(datagram) else {
            return;
        };

        let Ok(header) = IkeHeader::parse(body) else {
            return;
        };

        if header.exchange_type != ExchangeType::Informational {
            return;
        }

        let decrypted = self
            .liveness
            .as_ref()
            .and_then(|liveness| open_informational(&liveness.sa, body).ok());

        let Some(inner) = decrypted else {
            tracing::trace!("failed to decrypt an IKE INFORMATIONAL");
            return;
        };

        if inner
            .iter()
            .any(|(payload_type, _)| *payload_type == PayloadType::Delete)
        {
            tracing::info!("the peer deleted the security association; re-handshaking");
            self.start_rehandshake();
            return;
        }

        if header.flags.response {
            if let Some(liveness) = self.liveness.as_mut() {
                liveness.probe_sent = None;
            }

            tracing::debug!("the peer answered a DPD probe");
            return;
        }

        // A live peer expects an answer, carrying the same Message ID.
        let iv = rand::random::<[u8; 8]>();
        let reply = self
            .liveness
            .as_ref()
            .and_then(|liveness| {
                build_informational(&liveness.sa, header.message_id, true, &[], &iv).ok()
            });

        if let Some(msg) = reply {
            self.ike_tx.push_back(wrap_ike_4500(&msg));
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
