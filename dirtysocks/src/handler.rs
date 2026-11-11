#![allow(clippy::missing_errors_doc)]
use hickory_resolver::TokioResolver;
use seq_macro::seq;
use std::{
    marker::PhantomData,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};
use strum::FromRepr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use untrusted::Input;

use crate::Error;

pub const SOCKS_VERSION: u8 = 0x05;
pub const USERNAME_PASSWORD_VERSION: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
#[repr(u8)]
enum AuthMethod {
    NoAuthRequired = 0x00,
    GssApi = 0x01,
    UsernamePassword = 0x02,
    NoneAcceptable = 0xFF,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
#[repr(u8)]
enum AddressType {
    Ipv4 = 0x01,
    DomainName = 0x03,
    Ipv6 = 0x04,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Address<'input> {
    Ipv4(SocketAddrV4),
    Ipv6(SocketAddrV6),
    DomainName(&'input str, u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, FromRepr)]
#[repr(u8)]
enum CommandType {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Command<'input> {
    addr: Address<'input>,
    ty: CommandType,
    version: u8,
}

/// RFC 1928:
/// ```text
/// The SOCKS request information is sent by the client as soon as it has
/// established a connection to the SOCKS server, and completed the
/// authentication negotiations.  The server evaluates the request, and
/// returns a reply formed as follows:
///
///      +----+-----+-------+------+----------+----------+
///      |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
///      +----+-----+-------+------+----------+----------+
///      | 1  |  1  | X'00' |  1   | Variable |    2     |
///      +----+-----+-------+------+----------+----------+
///
///   Where:
///
///        o  VER    protocol version: X'05'
///        o  REP    Reply field:
///           o  X'00' succeeded
///           o  X'01' general SOCKS server failure
///           o  X'02' connection not allowed by ruleset
///           o  X'03' Network unreachable
///           o  X'04' Host unreachable
///           o  X'05' Connection refused
///           o  X'06' TTL expired
///           o  X'07' Command not supported
///           o  X'08' Address type not supported
///           o  X'09' to X'FF' unassigned
///        o  RSV    RESERVED
///        o  ATYP   address type of following address
///           o  IP V4 address: X'01'
///           o  DOMAINNAME: X'03'
///           o  IP V6 address: X'04'
///        o  BND.ADDR       server bound address
///        o  BND.PORT       server bound port in network octet order
/// ```
pub struct Reply {
    pub version: u8,
    pub reply: u8,
    pub reserved: u8,
    pub address: SocketAddr,
}

impl Reply {
    #[must_use]
    pub const fn new(reply: u8, address: SocketAddr) -> Self {
        Self {
            version: SOCKS_VERSION,
            reply,
            reserved: 0,
            address,
        }
    }

    #[must_use]
    pub fn to_bytes(&self) -> ([u8; 6 + 16], usize) {
        let mut buf = [0; 6 + 16]; // 6 bytes for fixed fields, 16 for a possible ipv6 address
        let addr_len = if self.address.is_ipv4() { 4 } else { 16 };
        buf[0] = self.version;
        buf[1] = self.reply;
        buf[2] = self.reserved;
        buf[3] = if self.address.is_ipv4() {
            AddressType::Ipv4 as u8
        } else {
            AddressType::Ipv6 as u8
        };
        match self.address {
            SocketAddr::V4(addr) => buf[4..4 + 4].copy_from_slice(&addr.ip().octets()),
            SocketAddr::V6(addr) => buf[4..4 + 16].copy_from_slice(&addr.ip().octets()),
        }
        buf[4 + addr_len..6 + addr_len].copy_from_slice(&self.address.port().to_be_bytes());
        (buf, 6 + addr_len)
    }
}

pub struct Initial;
pub struct Authorized;
pub struct Piping;

pub struct Connection<State> {
    pub stream: TcpStream,
    client_addr: SocketAddr,
    resolver: TokioResolver,
    timeout: Duration,
    pub buf: Box<[u8]>,
    user_pass: Option<crate::UserPass>,

    _state: PhantomData<State>,
}
impl<State> Connection<State> {
    /// Reads exactly `len` bytes into `offset` of the connection buffer.
    async fn read_exact_at(&mut self, offset: usize, len: usize) -> Result<(), Error> {
        self.stream
            .read_exact(&mut self.buf[offset..offset + len])
            .await?;

        Ok(())
    }
}

impl Connection<Initial> {
    pub fn new(
        stream: TcpStream,
        client_addr: SocketAddr,
        resolver: TokioResolver,
        timeout: Duration,
        user_pass: Option<crate::UserPass>,
    ) -> Self {
        Self {
            stream,
            client_addr,
            resolver,
            timeout,
            buf: vec![0; crate::MAX_PACKET_SIZE].into_boxed_slice(),
            user_pass,
            _state: PhantomData,
        }
    }

    /// Authorizes with the client and checks version.
    pub async fn init_conn(mut self) -> Result<Connection<Authorized>, Error> {
        // A single `read` is not guaranteed to return a whole packet, so read
        // exactly as many bytes as the packet header announces.
        self.read_exact_at(0, 2).await?;
        let num_methods = self.buf[1] as usize;
        self.read_exact_at(2, num_methods).await?;

        let input = Input::from(&self.buf[..2 + num_methods]);
        let method = Self::parse_initial_packet(input, self.user_pass.is_some())?;

        self.stream
            .write_all(&[SOCKS_VERSION, method as u8])
            .await?;

        if method == AuthMethod::NoneAcceptable {
            tracing::warn!("no acceptable auth method found");
            return Err(Error::AuthMethodNotFound);
        }

        if let Some(user_pass) = self.user_pass.clone() {
            // VER, ULEN, UNAME
            self.read_exact_at(0, 2).await?;
            let uname_len = self.buf[1] as usize;
            self.read_exact_at(2, uname_len).await?;

            // PLEN, PASSWD
            self.read_exact_at(2 + uname_len, 1).await?;
            let pass_len = self.buf[2 + uname_len] as usize;
            self.read_exact_at(3 + uname_len, pass_len).await?;

            let len = 3 + uname_len + pass_len;
            let input = Input::from(&self.buf[..len]);
            let (username, password) = Self::parse_username_password_request(input)?;

            let status = u8::from(!credentials_valid(username, password, &user_pass));

            self.stream
                .write_all(&[USERNAME_PASSWORD_VERSION, status])
                .await?;

            if status != 0x00 {
                tracing::warn!("invalid credentials");
                return Err(Error::InvalidCredentials);
            }
        }

        Ok(change_state::<_, Authorized>(self))
    }

    fn parse_username_password_request(input: Input<'_>) -> Result<(&[u8], &[u8]), Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version = reader.read_byte()?;
            let uname_len = reader.read_byte()?;
            let username = reader.read_bytes(uname_len as usize)?;
            let pass_len = reader.read_byte()?;
            let password = reader.read_bytes(pass_len as usize)?;

            if version != USERNAME_PASSWORD_VERSION {
                return Err(Error::InvalidVersion);
            }

            Ok((username.as_slice_less_safe(), password.as_slice_less_safe()))
        })
    }

    fn parse_initial_packet(input: Input<'_>, use_auth: bool) -> Result<AuthMethod, Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version = reader.read_byte()?;
            let num_methods = reader.read_byte()?;
            let methods = reader.read_bytes(num_methods as usize)?;

            if version != SOCKS_VERSION {
                return Err(Error::InvalidVersion);
            }

            if use_auth && Self::contains_method(methods, AuthMethod::UsernamePassword) {
                Ok(AuthMethod::UsernamePassword)
            } else if !use_auth && Self::contains_method(methods, AuthMethod::NoAuthRequired) {
                Ok(AuthMethod::NoAuthRequired)
            } else {
                Ok(AuthMethod::NoneAcceptable)
            }
        })
    }

    fn contains_method(input: Input<'_>, method: AuthMethod) -> bool {
        input
            .read_all((), |reader| {
                while let Ok(allowed_method) = reader.read_byte() {
                    if allowed_method == method as u8 {
                        reader.skip_to_end();
                        return Ok(true);
                    }
                }
                Ok(false)
            })
            .unwrap_or(false)
    }
}

impl Connection<Authorized> {
    pub async fn handle_request(mut self) -> Result<(SocketAddr, Connection<Piping>), Error> {
        // VER, CMD, RSV, ATYP
        self.read_exact_at(0, 4).await?;

        let total = match AddressType::from_repr(self.buf[3]).ok_or(Error::InvalidAddressType)? {
            AddressType::Ipv4 => {
                self.read_exact_at(4, 4 + 2).await?;
                4 + 4 + 2
            }
            AddressType::Ipv6 => {
                self.read_exact_at(4, 16 + 2).await?;
                4 + 16 + 2
            }
            AddressType::DomainName => {
                self.read_exact_at(4, 1).await?;
                let domain_len = self.buf[4] as usize;
                self.read_exact_at(5, domain_len + 2).await?;

                5 + domain_len + 2
            }
        };

        let input = Input::from(&self.buf[..total]);

        let mut domain_buf = [0; u8::MAX as usize]; // max domain length for socks5 is the size of a byte
        let command = Self::parse_request(&mut domain_buf, input)?;

        tracing::debug!(?command);

        let dest_sock_addr = match command.addr {
            Address::Ipv4(addr) => SocketAddr::from(addr),
            Address::Ipv6(addr) => SocketAddr::from(addr),
            Address::DomainName(domain, port) => {
                tracing::debug!(?domain, ?port, "resolving domain");
                let ips = self.resolver.lookup_ip(domain).await?;

                let Some(ip) = ips.iter().next() else {
                    let (reply_buf, reply_buf_len) =
                        Reply::new(0x04, SocketAddr::from(([0, 0, 0, 0], 0))).to_bytes();
                    self.stream.write_all(&reply_buf[..reply_buf_len]).await?;
                    return Err(Error::NoSuchHost);
                };

                SocketAddr::from((ip, port))
            }
        };

        let piping = match command.ty {
            CommandType::Connect => self.handle_connect(dest_sock_addr).await?,
            // Unsupported commands must be answered, not panic the server.
            CommandType::Bind | CommandType::UdpAssociate => {
                let (reply_buf, reply_buf_len) =
                    Reply::new(0x07, SocketAddr::from(([0, 0, 0, 0], 0))).to_bytes();
                self.stream.write_all(&reply_buf[..reply_buf_len]).await?;

                return Err(Error::InvalidCommandType);
            }
        };

        Ok((dest_sock_addr, piping))
    }

    /// ```text
    /// CONNECT
    /// In the reply to a CONNECT, BND.PORT contains the port number that the
    /// server assigned to connect to the target host, while BND.ADDR
    /// contains the associated IP address.  The supplied BND.ADDR is often
    /// different from the IP address that the client uses to reach the SOCKS
    /// server, since such servers are often multi-homed.  It is expected
    /// that the SOCKS server will use DST.ADDR and DST.PORT, and the
    /// client-side source address and port in evaluating the CONNECT
    /// request.
    /// ```
    async fn handle_connect(
        mut self,
        _dest_sock_addr: SocketAddr,
    ) -> Result<Connection<Piping>, Error> {
        tracing::info!("handling connect");

        // 0x00 reply means success
        // 0.0.0.0:0 means the same address and port
        let (reply_buf, reply_buf_len) =
            Reply::new(0x00, SocketAddr::from(([0, 0, 0, 0], 0))).to_bytes();

        self.stream.write_all(&reply_buf[..reply_buf_len]).await?;
        self.stream.flush().await?;

        Ok(change_state::<_, Piping>(self))
    }

    fn parse_request<'domain>(
        domain_buf: &'domain mut [u8],
        input: Input<'_>,
    ) -> Result<Command<'domain>, Error> {
        input.read_all(Error::IncompleteRead, |reader| {
            let version = reader.read_byte()?;
            let ty =
                CommandType::from_repr(reader.read_byte()?).ok_or(Error::InvalidCommandType)?;
            let _reserved = reader.read_byte()?;
            let address_type =
                AddressType::from_repr(reader.read_byte()?).ok_or(Error::InvalidAddressType)?;

            let addr = match address_type {
                AddressType::Ipv4 => Address::Ipv4(SocketAddrV4::new(
                    seq!(_ in 0..4 {
                        [
                            #(
                                reader.read_byte()?,
                            )*
                        ]
                    })
                    .into(),
                    u16::from_be_bytes([reader.read_byte()?, reader.read_byte()?]),
                )),
                AddressType::Ipv6 => Address::Ipv6(SocketAddrV6::new(
                    seq!(_ in 0..16 {
                        [
                            #(
                                reader.read_byte()?,
                            )*
                        ]
                    })
                    .into(),
                    u16::from_be_bytes([reader.read_byte()?, reader.read_byte()?]),
                    0,
                    0,
                )),
                AddressType::DomainName => {
                    let len = reader.read_byte()?;
                    let domain = reader.read_bytes(len as usize)?;
                    let port = u16::from_be_bytes([reader.read_byte()?, reader.read_byte()?]);

                    let domain_slice = &mut domain_buf[..len as usize];

                    domain_slice.copy_from_slice(domain.as_slice_less_safe());

                    Address::DomainName(std::str::from_utf8(domain_slice)?, port)
                }
            };

            Ok(Command { addr, ty, version })
        })
    }
}

/// Both parts of the credentials have to match; accepting either one would
/// let anyone in with half of the pair.
fn credentials_valid(username: &[u8], password: &[u8], expected: &crate::UserPass) -> bool {
    username == expected.username.as_bytes() && password == expected.password.as_bytes()
}

fn change_state<O, N>(old: Connection<O>) -> Connection<N> {
    Connection {
        stream: old.stream,
        client_addr: old.client_addr,
        resolver: old.resolver,
        timeout: old.timeout,
        buf: old.buf,
        user_pass: old.user_pass,
        _state: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn resolver() -> TokioResolver {
        crate::cloudflare_resolver()
    }

    fn user_pass(username: &str, password: &str) -> crate::UserPass {
        crate::UserPass {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }

    async fn accept_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (server, client) = tokio::join!(listener.accept(), TcpStream::connect(addr));

        (server.unwrap().0, client.unwrap())
    }

    fn connection(server: TcpStream, user_pass: Option<crate::UserPass>) -> Connection<Initial> {
        Connection::new(
            server,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            resolver(),
            Duration::from_secs(5),
            user_pass,
        )
    }

    #[test]
    fn credentials_require_both_username_and_password() {
        let expected = user_pass("user", "pass");

        assert!(credentials_valid(b"user", b"pass", &expected));
        assert!(!credentials_valid(b"user", b"wrong", &expected));
        assert!(!credentials_valid(b"wrong", b"pass", &expected));
        assert!(!credentials_valid(b"", b"", &expected));
    }

    #[test]
    fn auth_method_is_negotiated_against_the_server_config() {
        // Offers no-auth and username/password.
        let greeting = [SOCKS_VERSION, 0x02, 0x00, 0x02];
        assert_eq!(
            Connection::<Initial>::parse_initial_packet(Input::from(&greeting), false).unwrap(),
            AuthMethod::NoAuthRequired
        );
        assert_eq!(
            Connection::<Initial>::parse_initial_packet(Input::from(&greeting), true).unwrap(),
            AuthMethod::UsernamePassword
        );

        // A client that only offers GSSAPI must not be let in.
        let gssapi_only = [SOCKS_VERSION, 0x01, 0x01];
        assert_eq!(
            Connection::<Initial>::parse_initial_packet(Input::from(&gssapi_only), true).unwrap(),
            AuthMethod::NoneAcceptable
        );

        let wrong_version = [0x04, 0x01, 0x00];
        assert!(matches!(
            Connection::<Initial>::parse_initial_packet(Input::from(&wrong_version), false),
            Err(Error::InvalidVersion)
        ));
    }

    #[tokio::test]
    async fn authenticates_with_fragmented_username_password() {
        let (server, mut client) = accept_pair().await;

        let task = tokio::spawn(connection(server, Some(user_pass("user", "pass"))).init_conn());

        // Greeting arrives one byte at a time; a single `read` would parse garbage.
        client.write_all(&[SOCKS_VERSION]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        client
            .write_all(&[0x01, AuthMethod::UsernamePassword as u8])
            .await
            .unwrap();

        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS_VERSION, AuthMethod::UsernamePassword as u8]);

        // Authentication request arrives in two pieces as well.
        client
            .write_all(&[USERNAME_PASSWORD_VERSION, 4, b'u', b's', b'e', b'r'])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        client
            .write_all(&[4, b'p', b'a', b's', b's'])
            .await
            .unwrap();

        let mut status = [0; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [USERNAME_PASSWORD_VERSION, 0x00]);

        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn rejects_correct_username_with_wrong_password() {
        let (server, mut client) = accept_pair().await;

        let task = tokio::spawn(connection(server, Some(user_pass("user", "pass"))).init_conn());

        client
            .write_all(&[SOCKS_VERSION, 0x01, AuthMethod::UsernamePassword as u8])
            .await
            .unwrap();

        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [SOCKS_VERSION, AuthMethod::UsernamePassword as u8]);

        client
            .write_all(&[
                USERNAME_PASSWORD_VERSION,
                4,
                b'u',
                b's',
                b'e',
                b'r',
                3,
                b'b',
                b'a',
                b'd',
            ])
            .await
            .unwrap();

        let mut status = [0; 2];
        client.read_exact(&mut status).await.unwrap();
        assert_eq!(status, [USERNAME_PASSWORD_VERSION, 0x01]);

        assert!(matches!(
            task.await.unwrap(),
            Err(Error::InvalidCredentials)
        ));
    }

    #[test]
    fn parses_connect_requests() {
        let mut domain_buf = [0; u8::MAX as usize];

        let ipv4 = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90];
        let command =
            Connection::<Authorized>::parse_request(&mut domain_buf, Input::from(&ipv4)).unwrap();
        assert_eq!(command.version, SOCKS_VERSION);
        assert_eq!(command.ty, CommandType::Connect);
        assert_eq!(
            command.addr,
            Address::Ipv4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080))
        );

        let ipv6 = [
            0x05, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00, 0x50,
        ];
        let command =
            Connection::<Authorized>::parse_request(&mut domain_buf, Input::from(&ipv6)).unwrap();
        assert_eq!(
            command.addr,
            Address::Ipv6(SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 80, 0, 0))
        );

        let mut domain = vec![0x05, 0x01, 0x00, 0x03, 11];
        domain.extend_from_slice(b"example.com");
        domain.extend_from_slice(&80u16.to_be_bytes());
        let command =
            Connection::<Authorized>::parse_request(&mut domain_buf, Input::from(&domain)).unwrap();
        assert_eq!(command.addr, Address::DomainName("example.com", 80));

        let unknown_address = [0x05, 0x01, 0x00, 0x09];
        assert!(matches!(
            Connection::<Authorized>::parse_request(&mut domain_buf, Input::from(&unknown_address)),
            Err(Error::InvalidAddressType)
        ));
    }

    #[tokio::test]
    async fn replies_to_connect_and_rejects_bind() {
        let (server, mut client) = accept_pair().await;
        let task =
            tokio::spawn(change_state::<_, Authorized>(connection(server, None)).handle_request());

        client
            .write_all(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x1F, 0x90])
            .await
            .unwrap();

        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply[..4], &[SOCKS_VERSION, 0x00, 0x00, 0x01]);

        let (addr, _pipe) = task.await.unwrap().unwrap();
        assert_eq!(addr, SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)));

        let (server, mut client) = accept_pair().await;
        let task =
            tokio::spawn(change_state::<_, Authorized>(connection(server, None)).handle_request());

        // BIND used to `todo!()`, which killed the whole server.
        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x00])
            .await
            .unwrap();

        let mut reply = [0; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x07);

        assert!(matches!(
            task.await.unwrap(),
            Err(Error::InvalidCommandType)
        ));
    }

    #[test]
    fn reply_round_trips_both_address_families() {
        let (buf, len) = Reply::new(0x00, SocketAddr::from((Ipv4Addr::LOCALHOST, 1080))).to_bytes();
        assert_eq!(len, 10);
        assert_eq!(&buf[..4], &[0x05, 0x00, 0x00, 0x01]);
        assert_eq!(&buf[4..8], &Ipv4Addr::LOCALHOST.octets());
        assert_eq!(&buf[8..10], &1080u16.to_be_bytes());

        let (buf, len) =
            Reply::new(0x05, SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 80))).to_bytes();
        assert_eq!(len, 22);
        assert_eq!(buf[3], 0x04);
        assert_eq!(&buf[len - 2..len], &[0x00, 0x50]);
    }
}
