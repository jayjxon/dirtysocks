use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use clap::Parser;

/// A usermode WireGuard or IKEv2 client with a SOCKS5 proxy.
#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Args {
    /// The `wg-quick` config file to read
    #[arg(short, long, required_unless_present = "ike")]
    pub config: Option<PathBuf>,

    /// The socket address the SOCKS5 proxy should listen on
    #[arg(long, default_value_t = SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 3000)))]
    pub host: SocketAddr,

    /// Use IKEv2 (username/EAP-MSCHAPv2) instead of WireGuard
    #[arg(long)]
    pub ike: bool,

    /// The IKEv2 server hostname
    #[arg(long, required_if_eq("ike", "true"))]
    pub ike_host: Option<String>,

    /// The IKEv2 username, which is also the local identity
    #[arg(long, env = "DIRTYSOCKS_IKE_USER", required_if_eq("ike", "true"))]
    pub ike_user: Option<String>,

    /// The IKEv2 password
    #[arg(long, env = "DIRTYSOCKS_IKE_PASS", required_if_eq("ike", "true"))]
    pub ike_pass: Option<String>,

    /// The identity the IKEv2 server certificate must vouch for [default: --ike-host]
    #[arg(long)]
    pub ike_remote_id: Option<String>,

    /// The CA certificate (PEM or DER) used to verify the IKEv2 server
    #[arg(long, default_value = "/etc/ssl/certs/ISRG_Root_X1.pem")]
    pub ike_ca: PathBuf,

    /// Resolve the endpoint to this address instead of using DNS
    #[arg(long)]
    pub endpoint_ip: Option<IpAddr>,

    /// Connect to this endpoint port instead of the one in the config
    #[arg(long)]
    pub endpoint_port: Option<u16>,

    /// Disable transport obfuscation (junk packets and source port rotation)
    #[arg(long)]
    pub no_obfs: bool,

    /// Number of junk datagrams sent before each handshake
    #[arg(long, default_value_t = 4)]
    pub junk_packets: u32,
}
