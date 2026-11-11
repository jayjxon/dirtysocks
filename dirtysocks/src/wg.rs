use boringtun::noise::{errors::WireGuardError, Tunn, TunnResult};
use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    wire::{Ipv4Packet, PrettyPrinter},
};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    pin::Pin,
    sync::{MutexGuard, PoisonError},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{Instant, Sleep},
};

use crate::MAX_PACKET_SIZE;

/// How often the `WireGuard` timers are updated.
const TIMER_INTERVAL: Duration = Duration::from_millis(250);

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("packet parse error: {0}")]
    ParsePacket(#[from] smoltcp::wire::Error),
    #[error("wireguard error: {0:#?}")]
    WireGuard(WireGuardError),
    #[error("mutex poisoned")]
    MutexPoisoned,
}
// thiserror doesn't like WireGuardError for some reason
// so I have to implement From myself
impl From<WireGuardError> for Error {
    fn from(e: WireGuardError) -> Self {
        Self::WireGuard(e)
    }
}
impl<'a, T> From<PoisonError<MutexGuard<'a, T>>> for Error {
    fn from(_: PoisonError<MutexGuard<'a, T>>) -> Self {
        Self::MutexPoisoned
    }
}

pub struct Peer {
    pub tunn: Tunn,
    pub addr: SocketAddr,
    pub conn: UdpSocket,

    pub mtu: usize,

    pub tx_queue: VecDeque<Vec<u8>>,
    pub rx_queue: VecDeque<Vec<u8>>,

    pub should_poll: bool,

    pub buf: Box<[u8]>,
}

impl Peer {
    pub fn new(tunn: Tunn, addr: SocketAddr, conn: UdpSocket, mtu: usize) -> Self {
        Self {
            tunn,
            addr,
            conn,
            mtu,

            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),

            should_poll: false,

            buf: vec![0; MAX_PACKET_SIZE].into_boxed_slice(),
        }
    }

    pub async fn poll_device(
        &mut self,
        mut sleep: Pin<&mut Sleep>,
        recv_buf: &mut [u8],
    ) -> Result<(), Error> {
        while let Some(packet) = self.tx_queue.pop_back() {
            self.handle_peer_tx_packet(&packet).await?;
            self.should_poll = true;
        }

        tokio::select! {
            ready = self.conn.readable() => {
                ready?;

                loop {
                    match self.conn.try_recv(recv_buf) {
                        Ok(0) => break,
                        Ok(len) => {
                            self.handle_peer_rx_packet(&recv_buf[..len]).await?;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => {
                            // Bail out instead of spinning on a permanent error.
                            tracing::warn!(?e, "failed to read from socket");
                            break;
                        }
                    }
                }
            }
            () = sleep.as_mut() => {
                sleep.reset(Instant::now() + TIMER_INTERVAL);

                self.update_timers(recv_buf).await?;
            }
        }

        Ok(())
    }

    pub async fn handle_peer_tx_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        let res = self.tunn.encapsulate(packet, &mut self.buf);

        match res {
            // send to the peer
            TunnResult::WriteToNetwork(packet) => {
                tracing::trace!(num_bytes = packet.len(), "writing to peer network");

                let sent = self.conn.send(packet).await?;
                if sent < packet.len() {
                    tracing::warn!(
                        sent = sent,
                        total = packet.len(),
                        "failed to send entire packet"
                    );
                    self.tx_queue.push_front(packet[sent..].to_vec());
                }

                Ok(())
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                tracing::debug!("connection expired; re-handshaking");

                // There is no live session, so this packet can't be sent. Start
                // a handshake; the upper layer retransmits the data.
                let mut res = self.tunn.format_handshake_initiation(&mut self.buf, true);

                loop {
                    match res {
                        TunnResult::WriteToNetwork(packet) => {
                            self.conn.send(packet).await?;
                            res = self.tunn.decapsulate(None, &[], &mut self.buf);
                        }
                        TunnResult::Err(e) => break Err(e.into()),
                        _ => break Ok(()),
                    }
                }
            }
            TunnResult::Err(e) => Err(e.into()),
            res => {
                tracing::warn!(?res, "unexpected result from encapsulation");
                Ok(())
            }
        }
    }

    pub async fn handle_peer_rx_packet(&mut self, packet: &[u8]) -> Result<(), Error> {
        tracing::trace!(len = packet.len(), "recieved packet peer");

        let mut res = self.tunn.decapsulate(None, packet, &mut self.buf);

        loop {
            match res {
                TunnResult::WriteToNetwork(packet) => {
                    tracing::trace!(num_bytes = packet.len(), "writing to peer network");

                    let sent = self.conn.send(packet).await?;
                    if sent < packet.len() {
                        tracing::warn!(
                            sent = sent,
                            total = packet.len(),
                            "failed to send entire packet"
                        );
                    }

                    // Keep draining; a single datagram can queue several packets
                    // (`boringtun` wants `decapsulate` called until `Done`).
                    res = self.tunn.decapsulate(None, &[], &mut self.buf);
                }

                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tracing::trace!("WRITE TO SMOL DEVICE");

                    self.rx_queue.push_front(packet.to_vec());
                    self.should_poll = true;

                    break Ok(());
                }

                TunnResult::Done => break Ok(()),

                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    tracing::debug!("connection expired; re-handshaking");
                    res = self.tunn.format_handshake_initiation(&mut self.buf, true);
                }

                TunnResult::Err(e) => break Err(e.into()),
            }
        }
    }

    /// Must be called often.
    pub async fn update_timers(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let mut res = self.tunn.update_timers(buf);

        loop {
            match res {
                TunnResult::WriteToNetwork(packet) => {
                    tracing::trace!(num_bytes = packet.len(), "writing to peer network");

                    let sent = self.conn.send(packet).await?;
                    if sent < packet.len() {
                        tracing::warn!(
                            sent = sent,
                            total = packet.len(),
                            "failed to send entire packet"
                        );
                    }

                    res = self.tunn.decapsulate(None, &[], buf);
                }

                TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                    tracing::trace!("WRITE TO SMOL DEVICE");

                    self.rx_queue.push_front(packet.to_vec());
                    self.should_poll = true;

                    break Ok(());
                }

                TunnResult::Done => break Ok(()),

                TunnResult::Err(WireGuardError::ConnectionExpired) => {
                    tracing::debug!("connection expired; re-handshaking");
                    res = self.tunn.format_handshake_initiation(buf, true);
                }

                TunnResult::Err(e) => break Err(e.into()),
            }
        }
    }
}

pub struct WgRxToken {
    packet: Vec<u8>,
}
impl RxToken for WgRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // Parsing every packet just to log it is wasted work on the hot path.
        if tracing::enabled!(tracing::Level::TRACE) {
            if let Ok(parsed) = Ipv4Packet::new_checked(&*self.packet) {
                tracing::trace!(
                    info = %PrettyPrinter::<Ipv4Packet<&[u8]>>::print(&parsed),
                    "PACKET FROM PEER"
                );
            }
        }

        f(&mut self.packet)
    }
}

pub struct WgTxToken<'a> {
    tx: &'a mut VecDeque<Vec<u8>>,
}
impl<'a> TxToken for WgTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        tracing::trace!(?len, "transfer token consumed");
        let mut packet = vec![0; len];

        let ret = f(&mut packet);

        self.tx.push_front(packet);

        ret
    }
}

impl Device for Peer {
    type RxToken<'a> = WgRxToken;
    type TxToken<'a> = WgTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_queue.pop_back() {
            tracing::trace!(
                len = packet.len(),
                "recieved packet from peer; recv token retrieved"
            );
            Some((
                WgRxToken { packet },
                WgTxToken {
                    tx: &mut self.tx_queue,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        tracing::trace!("trans TOKEN");
        Some(WgTxToken {
            tx: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::{PublicKey, StaticSecret};
    use std::net::Ipv4Addr;
    use tokio::time::timeout;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    fn tunnels() -> (Tunn, Tunn) {
        let client_secret = StaticSecret::from([7u8; 32]);
        let server_secret = StaticSecret::from([9u8; 32]);

        let client = Tunn::new(
            client_secret.clone(),
            PublicKey::from(&server_secret),
            None,
            None,
            0,
            None,
        )
        .unwrap();
        let server = Tunn::new(
            server_secret,
            PublicKey::from(&client_secret),
            None,
            None,
            1,
            None,
        )
        .unwrap();

        (client, server)
    }

    fn ipv4_packet(marker: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, marker]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);

        packet
    }

    fn tunnel_packet(tunn: &mut Tunn, datagram: &[u8], buf: &mut [u8]) -> Option<Vec<u8>> {
        match tunn.decapsulate(None, datagram, buf) {
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                Some(packet.to_vec())
            }
            _ => None,
        }
    }

    #[tokio::test]
    async fn handshakes_then_carries_packets_both_ways() {
        let (client_tunn, mut server_tunn) = tunnels();

        let client_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        client_sock.connect(server_addr).await.unwrap();

        let mut peer = Peer::new(client_tunn, server_addr, client_sock, 1280);

        let mut wire = vec![0u8; MAX_PACKET_SIZE];
        let mut scratch = vec![0u8; MAX_PACKET_SIZE];

        // No session exists yet: this has to start a handshake, not fail.
        let outgoing = ipv4_packet(1);
        peer.handle_peer_tx_packet(&outgoing).await.unwrap();

        let len = timeout(TEST_TIMEOUT, server_sock.recv(&mut wire))
            .await
            .unwrap()
            .unwrap();

        let response = match server_tunn.decapsulate(None, &wire[..len], &mut scratch) {
            TunnResult::WriteToNetwork(response) => response.to_vec(),
            other => panic!("expected a handshake response, got {other:?}"),
        };

        server_sock.send_to(&response, client_addr).await.unwrap();

        // The response completes the handshake on the client side.
        let len = timeout(TEST_TIMEOUT, peer.conn.recv(&mut wire))
            .await
            .unwrap()
            .unwrap();
        peer.handle_peer_rx_packet(&wire[..len]).await.unwrap();

        // With the session up, the packet must survive the round trip intact.
        peer.handle_peer_tx_packet(&outgoing).await.unwrap();

        let mut decrypted = None;
        for _ in 0..4 {
            let len = timeout(TEST_TIMEOUT, server_sock.recv(&mut wire))
                .await
                .unwrap()
                .unwrap();

            if let Some(packet) = tunnel_packet(&mut server_tunn, &wire[..len], &mut scratch) {
                decrypted = Some(packet);
                break;
            }
        }

        assert_eq!(decrypted.as_deref(), Some(outgoing.as_slice()));

        // And back: peer -> device -> smoltcp.
        let incoming = ipv4_packet(3);
        let encrypted = match server_tunn.encapsulate(&incoming, &mut scratch) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected an encrypted packet, got {other:?}"),
        };

        server_sock.send_to(&encrypted, client_addr).await.unwrap();

        let len = timeout(TEST_TIMEOUT, peer.conn.recv(&mut wire))
            .await
            .unwrap()
            .unwrap();
        peer.handle_peer_rx_packet(&wire[..len]).await.unwrap();

        assert!(peer.should_poll);
        assert_eq!(peer.rx_queue.len(), 1);

        let (rx, _tx) = peer.receive(smoltcp::time::Instant::now()).unwrap();
        rx.consume(|buf| assert_eq!(buf, incoming.as_slice()));
    }

    #[tokio::test]
    async fn poll_device_sends_queued_packets() {
        let (client_tunn, _server_tunn) = tunnels();

        let client_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        client_sock.connect(server_addr).await.unwrap();

        let mut peer = Peer::new(client_tunn, server_addr, client_sock, 1280);

        let packet = ipv4_packet(5);
        {
            let token = peer.transmit(smoltcp::time::Instant::now()).unwrap();
            token.consume(packet.len(), |buf| buf.copy_from_slice(&packet));
        }
        assert_eq!(peer.tx_queue.len(), 1);

        let mut sleep = std::pin::pin!(tokio::time::sleep(Duration::from_millis(50)));
        let mut recv_buf = vec![0u8; MAX_PACKET_SIZE];

        // Returning proves the device poll doesn't block on a readable socket.
        timeout(
            TEST_TIMEOUT,
            peer.poll_device(sleep.as_mut(), &mut recv_buf),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(peer.tx_queue.is_empty());
        assert!(peer.should_poll);

        let mut wire = vec![0u8; MAX_PACKET_SIZE];
        let len = timeout(TEST_TIMEOUT, server_sock.recv(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(len, 0);
    }
}
