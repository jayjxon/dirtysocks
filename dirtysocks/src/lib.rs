#![warn(clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_pub_crate,
    clippy::module_name_repetitions
)]

use boringtun::noise::Tunn;
use futures_util::{future::Either, stream::FuturesUnordered, StreamExt};
use handler::{Connection, Initial};
use hickory_resolver::{
    config::{ResolverConfig, CLOUDFLARE},
    net::runtime::TokioRuntimeProvider,
    TokioResolver,
};
use smoltcp::{
    config::IFACE_MAX_ADDR_COUNT,
    iface::{self, Config, SocketHandle, SocketSet},
    socket::{
        tcp::{self, SocketBuffer},
        AnySocket,
    },
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{
    collections::{HashMap, VecDeque},
    convert::Infallible,
    future::Future,
    net::SocketAddr,
    num::NonZeroU16,
    pin::pin,
    time::{Duration as StdDuration, Instant as StdInstant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::mpsc::{Receiver, Sender},
    time::Instant as TokioInstant,
};
use tracing::instrument;

pub mod wg;
use wg::Peer;

pub mod handler;

pub const MAX_PACKET_SIZE: usize = 65535;

/// Maximum amount of data pulled out of a `smoltcp` socket in one go.
const MAX_SOCKET_CHUNK: usize = 16 * 1024;
/// Maximum amount of data coalesced into a single write to a client.
const MAX_WRITE_CHUNK: usize = 64 * 1024;
/// Number of messages handled from the interface channel at once.
const MSG_BATCH: usize = 128;
/// Number of messages forwarded from the interface to a client at once.
const CLIENT_BATCH: usize = 32;
/// Upper bound on data buffered inside the interface for one connection.
/// Beyond this the connection is aborted instead of growing without bound.
const MAX_QUEUED_WRITES: usize = 64;
/// Smallest delay between interface polls, to avoid burning CPU on a busy loop.
const MIN_POLL_WAIT: StdDuration = StdDuration::from_millis(1);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("authentication method not found")]
    AuthMethodNotFound,
    #[error("invalid username or password")]
    InvalidCredentials,
    #[error("invalid version")]
    InvalidVersion,
    #[error("incomplete request parsing")]
    IncompleteRead,
    #[error("unexpected end of input")]
    UnexpectedEOI,
    #[error("invalid address type")]
    InvalidAddressType,
    #[error("invalid command type")]
    InvalidCommandType,
    #[error("failed to message worker thread")]
    SendError,
    #[error("invalid string")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("dns lookup error: {0}")]
    DnsLookup(#[from] hickory_resolver::net::NetError),
    #[error("no such host")]
    NoSuchHost,
    #[error("timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("error waiting for future: {0}")]
    JoinError(#[from] tokio::task::JoinError),
}
impl From<untrusted::EndOfInput> for Error {
    fn from(_: untrusted::EndOfInput) -> Self {
        Self::UnexpectedEOI
    }
}

#[derive(Clone, Debug)]
pub struct UserPass {
    pub username: String,
    pub password: String,
}

#[derive(Debug)]
enum ToWgMsg {
    Connect(SocketAddr, Sender<FromWgMsg>),
    Data(SocketHandle, Box<[u8]>),
    Close(SocketHandle),
}

#[derive(Debug)]
enum FromWgMsg {
    Connect(SocketHandle),
    Data(Box<[u8]>),
    Close,
}

pub struct ServerOptions {
    pub listener: TcpListener,
    pub tunn: Tunn,
    /// The address of the wireguard server.
    pub endpoint_addr: SocketAddr,
    pub max_transmission_unit: usize,
    pub resolver: TokioResolver,
    pub timeout: StdDuration,
    pub user_pass: Option<UserPass>,
    pub iface_addrs: heapless::Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
}
impl ServerOptions {
    pub fn new(
        listener: TcpListener,
        endpoint_addr: SocketAddr,
        tunn: Tunn,
        iface_addrs: heapless::Vec<IpCidr, IFACE_MAX_ADDR_COUNT>,
    ) -> Self {
        Self {
            listener,
            endpoint_addr,
            tunn,
            iface_addrs,
            resolver: cloudflare_resolver(),
            timeout: StdDuration::from_secs(30),
            user_pass: None,
            max_transmission_unit: 1280,
        }
    }
}

/// Builds a resolver backed by Cloudflare's public DNS.
///
/// # Panics
/// Panics if the resolver cannot be built.
#[must_use]
pub fn cloudflare_resolver() -> TokioResolver {
    TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .build()
    .expect("failed to build the Cloudflare DNS resolver")
}

/// A socks5 server implementation, sending data to a single `WireGuard` peer.
pub struct Server {
    pub listener: TcpListener,
    pub iface: Option<IfaceHandler>,
    pub resolver: TokioResolver,
    pub timeout: StdDuration,
    pub user_pass: Option<UserPass>,
    pub next_ephemeral_port: u16,

    socket_tx: Sender<ToWgMsg>,
}

// TODO: reuse sockets
impl Server {
    pub async fn listen(opts: ServerOptions) -> Result<Infallible, Error> {
        let peer_conn = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
        peer_conn.connect(opts.endpoint_addr).await?;

        let mut peer = Peer::new(
            opts.tunn,
            opts.endpoint_addr,
            peer_conn,
            opts.max_transmission_unit,
        );

        let mut iface_conf = Config::new(HardwareAddress::Ip);
        iface_conf.random_seed = rand::random();

        let mut iface = iface::Interface::new(iface_conf, &mut peer, SmolInstant::now());

        iface.update_ip_addrs(|ip_addrs| *ip_addrs = opts.iface_addrs);

        let (socket_tx, socket_rx) = tokio::sync::mpsc::channel(MSG_BATCH);

        let this = Self {
            listener: opts.listener,
            iface: Some(IfaceHandler {
                socket_rx,
                iface,
                socket_set: SocketSet::new(Vec::new()),
                peer,
                next_ephemeral_port: NonZeroU16::new(1024).unwrap(),
                sockets_ctx: HashMap::new(),
                closed_sockets: Vec::new(),
                last_iface_poll: StdInstant::now(),
                iface_poll_delay: None,
            }),
            socket_tx,
            resolver: opts.resolver,
            timeout: opts.timeout,
            user_pass: opts.user_pass,
            next_ephemeral_port: 1024,
        };

        this.listen_().await
    }

    async fn listen_(mut self) -> Result<Infallible, Error> {
        tracing::info!("SOCKS5 server started");
        if self.user_pass.is_some() {
            tracing::info!("using username/password authentication");
        } else {
            tracing::info!("no authentication required");
        }

        let mut piping = FuturesUnordered::new();

        let iface = self.iface.take().unwrap();
        tokio::spawn(iface.handle_iface());

        loop {
            tokio::select! {
                biased;

                res = self.listener.accept() => {
                    let (stream, client_addr) = res?;

                    // Forwarding is latency sensitive; don't let Nagle delay small writes.
                    if let Err(e) = stream.set_nodelay(true) {
                        tracing::debug!(?e, "failed to set TCP_NODELAY on client socket");
                    }

                    piping.push(Self::handle_conn(
                        self.socket_tx.clone(),
                        Connection::new(
                            stream,
                            client_addr,
                            self.resolver.clone(),
                            self.timeout,
                            self.user_pass.clone()
                        ),
                        self.timeout,
                    ));
                }

                Some(conn) = piping.next() => {
                    if let Err(e) = conn {
                        tracing::debug!(?e, "error in piping connection");
                    }
                }
            }
        }
    }

    #[instrument(skip(sender, conn))]
    async fn handle_conn(
        sender: Sender<ToWgMsg>,
        conn: Connection<Initial>,
        timeout: StdDuration,
    ) -> Result<(), Error> {
        // The handshake is client controlled, so it must not be allowed to hang
        // around forever holding resources.
        let handshake = async {
            let (addr, pipe) = conn.init_conn().await?.handle_request().await?;
            Ok::<_, Error>((addr, pipe))
        };
        let (socket_addr, mut pipe) = tokio::time::timeout(timeout, handshake).await??;

        tracing::trace!(?socket_addr, "connected to remote");

        let (socket_tx, mut socket_rx) = tokio::sync::mpsc::channel(CLIENT_BATCH);

        sender
            .send(ToWgMsg::Connect(socket_addr, socket_tx))
            .await
            .map_err(|_| Error::SendError)?;

        let handle = match socket_rx.recv().await {
            Some(FromWgMsg::Connect(handle)) => handle,
            Some(FromWgMsg::Close) | None => {
                tracing::trace!(?socket_addr, "iface could not open connection");
                pipe.stream.shutdown().await?;
                return Ok(());
            }
            Some(FromWgMsg::Data(_)) => return Err(Error::SendError),
        };

        tracing::trace!(?handle, "allocated handle");

        let mut chunks: Vec<FromWgMsg> = Vec::with_capacity(CLIENT_BATCH);
        let mut io_buf: Vec<u8> = Vec::with_capacity(MAX_WRITE_CHUNK);

        loop {
            tokio::select! {
                n = socket_rx.recv_many(&mut chunks, CLIENT_BATCH) => {
                    // The iface drops the sender once the remote end is gone.
                    if n == 0 {
                        tracing::trace!(?handle, "iface closed the connection");
                        break;
                    }

                    io_buf.clear();
                    let mut closed = false;

                    #[allow(clippy::iter_with_drain)] // keep the allocation around
                    for msg in chunks.drain(..) {
                        match msg {
                            FromWgMsg::Data(data) => {
                                io_buf.extend_from_slice(&data);

                                if io_buf.len() >= MAX_WRITE_CHUNK {
                                    pipe.stream.write_all(&io_buf).await?;
                                    io_buf.clear();
                                }
                            }
                            FromWgMsg::Close => {
                                closed = true;
                                break;
                            }
                            FromWgMsg::Connect(_) => {
                                tracing::warn!("spurious connect message");
                            }
                        }
                    }

                    if !io_buf.is_empty() {
                        pipe.stream.write_all(&io_buf).await?;
                    }

                    if closed {
                        break;
                    }
                }
                read = pipe.stream.read(&mut pipe.buf) => {
                    let read = read?;

                    tracing::trace!(read, "read data from stream");

                    if read == 0 {
                        break;
                    }

                    if sender.send(
                        ToWgMsg::Data(
                            handle,
                            pipe.buf[..read].to_vec().into_boxed_slice()
                        )
                    )
                    .await
                    .is_err() {
                        tracing::debug!("error sending data to iface");
                        break;
                    };
                }
            }
        }

        let _ = sender.send(ToWgMsg::Close(handle)).await;
        pipe.stream.shutdown().await?;

        Ok(())
    }
}

struct SocketCtx {
    sender: Sender<FromWgMsg>,
    send_queue: VecDeque<Box<[u8]>>,
}

pub struct IfaceHandler {
    socket_rx: Receiver<ToWgMsg>,
    sockets_ctx: HashMap<SocketHandle, SocketCtx>,
    iface: iface::Interface,
    peer: wg::Peer,
    socket_set: SocketSet<'static>,
    closed_sockets: Vec<SocketHandle>,
    last_iface_poll: StdInstant,
    iface_poll_delay: Option<SmolDuration>,
    next_ephemeral_port: NonZeroU16,
}

impl IfaceHandler {
    pub async fn handle_iface(mut self) {
        let mut needs_poll = true;

        let mut last_device_poll = pin!(tokio::time::sleep(StdDuration::ZERO));
        let mut device_buf = vec![0; MAX_PACKET_SIZE].into_boxed_slice();

        let mut msg_queue = Vec::with_capacity(MSG_BATCH);

        loop {
            while needs_poll || !self.peer.rx_queue.is_empty() {
                self.poll_iface();
                needs_poll = false;
                self.peer.should_poll = false;
            }

            tokio::select! {
                n = self.socket_rx.recv_many(&mut msg_queue, MSG_BATCH) => {
                    if n == 0 {
                        tracing::debug!("iface channel closed");
                        return;
                    }

                    #[allow(clippy::iter_with_drain)] // keep the allocation around
                    for msg in msg_queue.drain(..) {
                        self.handle_msg(msg);
                    }
                    needs_poll = true;
                },

                e = self.peer.poll_device(last_device_poll.as_mut(), &mut device_buf) => {
                    if let Err(e) = e {
                        tracing::warn!(?e, "error polling device");
                    }
                    needs_poll |= self.peer.should_poll;
                },

                () = Self::wait_for_poll_iface(self.last_iface_poll, self.iface_poll_delay) => {
                    needs_poll = true;
                },
            }
        }
    }

    fn poll_iface(&mut self) {
        self.last_iface_poll = StdInstant::now();
        let smoltcp_now = SmolInstant::from(self.last_iface_poll);

        let delay = {
            self.iface
                .poll(smoltcp_now, &mut self.peer, &mut self.socket_set);

            self.iface.poll_delay(smoltcp_now, &self.socket_set)
        };

        self.iface_poll_delay = delay;
        self.poll_sockets();
    }

    /// Moves data between the sockets and their clients.
    ///
    /// This never waits on a client: a client that can't keep up must not stall
    /// the interface, which is shared by every connection.
    fn poll_sockets(&mut self) {
        let Self {
            socket_set,
            sockets_ctx,
            closed_sockets,
            ..
        } = self;

        closed_sockets.clear();

        for (handle, socket) in socket_set.iter_mut() {
            let Some(ctx) = sockets_ctx.get_mut(&handle) else {
                continue;
            };

            let socket = tcp::Socket::downcast_mut(socket).expect("all sockets are tcp");

            // Only pull data out of the tunnel when the client has room for it.
            if socket.can_recv() && ctx.sender.capacity() > 0 {
                let mut receiver_gone = false;

                let res = socket.recv(|buf| {
                    let len = buf.len().min(MAX_SOCKET_CHUNK);
                    let data = buf[..len].to_vec().into_boxed_slice();

                    if ctx.sender.try_send(FromWgMsg::Data(data)).is_ok() {
                        (len, ())
                    } else {
                        // Don't consume data we can't hand off.
                        receiver_gone = true;
                        (0, ())
                    }
                });

                if let Err(e) = res {
                    tracing::warn!(?e, "error reading from socket");
                }

                if receiver_gone {
                    closed_sockets.push(handle);
                    continue;
                }
            }

            while socket.can_send() {
                let Some(data) = ctx.send_queue.pop_front() else {
                    break;
                };

                match socket.send_slice(&data) {
                    Ok(sent) if sent == data.len() => {}
                    Ok(sent) => {
                        // Push the unsent remainder back to the front so the
                        // stream order is preserved.
                        ctx.send_queue
                            .push_front(data[sent..].to_vec().into_boxed_slice());
                        break;
                    }
                    Err(e) => {
                        tracing::trace!(?e, "error writing to socket");
                        ctx.send_queue.push_front(data);
                        break;
                    }
                }
            }

            match socket.state() {
                tcp::State::Closed => closed_sockets.push(handle),
                tcp::State::CloseWait if !socket.can_recv() => closed_sockets.push(handle),
                _ => {}
            }
        }

        for handle in closed_sockets.drain(..) {
            if let Some(ctx) = sockets_ctx.remove(&handle) {
                // Dropping the sender wakes up the connection task as well.
                let _ = ctx.sender.try_send(FromWgMsg::Close);
            }
            socket_set.remove(handle);
        }
    }

    fn handle_msg(&mut self, msg: ToWgMsg) {
        match msg {
            ToWgMsg::Connect(addr, sender) => {
                tracing::trace!(?addr, "connecting to address");

                let mut socket = tcp::Socket::new(
                    SocketBuffer::new(vec![0; MAX_PACKET_SIZE]),
                    SocketBuffer::new(vec![0; MAX_PACKET_SIZE]),
                );

                socket.set_nagle_enabled(false);
                socket.set_keep_alive(Some(SmolDuration::from_secs(30)));

                if let Err(e) = socket.connect(
                    self.iface.context(),
                    (IpAddress::from(addr.ip()), addr.port()),
                    self.next_ephemeral_port.get(),
                ) {
                    tracing::warn!(?e, "error connecting to address");
                    // Tell the client we gave up instead of leaving it hanging.
                    let _ = sender.try_send(FromWgMsg::Close);
                    return;
                }

                self.next_ephemeral_port = next_ephemeral_port(self.next_ephemeral_port);

                let handle = self.socket_set.add(socket);

                if sender.try_send(FromWgMsg::Connect(handle)).is_err() {
                    tracing::debug!("error sending connect message to socket");
                    self.socket_set.remove(handle);
                    return;
                }

                self.sockets_ctx.insert(
                    handle,
                    SocketCtx {
                        sender,
                        send_queue: VecDeque::new(),
                    },
                );
            }
            ToWgMsg::Data(handle, data) => {
                let over_limit = self
                    .sockets_ctx
                    .get(&handle)
                    .is_some_and(|ctx| ctx.send_queue.len() >= MAX_QUEUED_WRITES);

                if over_limit {
                    tracing::debug!(?handle, "send queue full, aborting connection");

                    if let Some(ctx) = self.sockets_ctx.remove(&handle) {
                        let _ = ctx.sender.try_send(FromWgMsg::Close);
                    }
                    self.socket_set.remove(handle);
                    return;
                }

                let Some(ctx) = self.sockets_ctx.get_mut(&handle) else {
                    tracing::trace!(?handle, "socket not found");
                    return;
                };

                let socket = self.socket_set.get_mut::<tcp::Socket>(handle);

                if socket.can_send() {
                    match socket.send_slice(&data) {
                        Ok(sent) if sent == data.len() => {}
                        Ok(sent) => {
                            tracing::trace!(?handle, sent, "socket can't send all data, queueing");
                            ctx.send_queue
                                .push_back(data[sent..].to_vec().into_boxed_slice());
                        }
                        Err(e) => {
                            tracing::trace!(?e, ?handle, "error writing to socket, queueing");
                            ctx.send_queue.push_back(data);
                        }
                    }
                } else {
                    tracing::trace!(?handle, "socket can't send, queueing data");
                    ctx.send_queue.push_back(data);
                }
            }
            ToWgMsg::Close(handle) => {
                tracing::trace!(?handle, "closing socket");

                if self.sockets_ctx.remove(&handle).is_some() {
                    self.socket_set.remove(handle);
                }
            }
        }
    }

    fn wait_for_poll_iface(
        now: StdInstant,
        delay: Option<SmolDuration>,
    ) -> impl Future<Output = ()> {
        let Some(delay) = delay else {
            return Either::Left(std::future::pending());
        };

        // A zero delay means "poll again immediately"; still wait a little so
        // an idle interface doesn't spin at 100% CPU.
        let wait = StdDuration::from_micros(delay.total_micros()).max(MIN_POLL_WAIT);
        let next_wake = now + wait;

        Either::Right(tokio::time::sleep_until(TokioInstant::from_std(next_wake)))
    }
}

/// Returns the next ephemeral source port, wrapping back into the ephemeral range.
const fn next_ephemeral_port(port: NonZeroU16) -> NonZeroU16 {
    let next = port.get().wrapping_add(1);

    if next >= 1024 {
        NonZeroU16::new(next).unwrap()
    } else {
        NonZeroU16::new(1024).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ephemeral_ports_stay_in_range_and_wrap() {
        let mut port = NonZeroU16::new(1024).unwrap();

        for expected in 1025..=1100 {
            port = next_ephemeral_port(port);
            assert_eq!(port.get(), expected);
        }

        // The counter has to wrap instead of sticking at the top of the range.
        assert_eq!(
            next_ephemeral_port(NonZeroU16::new(u16::MAX).unwrap()).get(),
            1024
        );
        assert_eq!(
            next_ephemeral_port(NonZeroU16::new(1023).unwrap()).get(),
            1024
        );
    }
}
