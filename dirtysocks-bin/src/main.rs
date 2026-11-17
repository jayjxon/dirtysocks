use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    str::FromStr,
    time::Duration,
};

use base64::Engine;
use boringtun::{
    noise::Tunn,
    x25519::{PublicKey, StaticSecret},
};
use dirtysocks::{ike, wg::Obfuscation, ServerOptions, Transport};
use smoltcp::{
    config::IFACE_MAX_ADDR_COUNT,
    wire::{IpAddress, IpCidr},
};
use tokio::net::TcpListener;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

use clap::Parser;
use color_eyre::eyre::{eyre, ContextCompat, Result, WrapErr};

mod cli;
mod conf;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let args = cli::Args::parse();

    let mut iface_addrs: heapless::Vec<IpCidr, IFACE_MAX_ADDR_COUNT> = heapless::Vec::new();
    let mut max_transmission_unit = ike::DEFAULT_MTU;
    let mut endpoint_addr = SocketAddr::from(([0, 0, 0, 0], 0));

    let transport = if args.ike {
        let creds = ike_credentials(&args)?;
        let host = creds.host.clone();

        // The handshake is blocking; keep it off the async runtime threads.
        let (peer, assigned) = tokio::task::spawn_blocking(move || ike::connect(&creds)).await??;

        tracing::info!(%host, %assigned, "IKEv2 tunnel established");

        iface_addrs
            .push(IpCidr::new(IpAddress::from(assigned), 32))
            .ok()
            .context("too many interface addresses")?;

        Transport::Ike(peer)
    } else {
        let config = args
            .config
            .clone()
            .context("--config is required without --ike")?;
        let conf = tokio::fs::read_to_string(config).await?;
        let conf = conf::Conf::from_str(&conf)?;

        let [peer] = &conf.peers[..] else {
            panic!("only one peer is allowed")
        };

        let resolver = dirtysocks::cloudflare_resolver();

        // An explicit address avoids DNS-based blocking entirely.
        let endpoint_ip = match args.endpoint_ip {
            Some(ip) => ip,
            None => match IpAddr::from_str(&peer.endpoint.0) {
                Ok(ip) => ip,
                Err(_) => {
                    let addrs = resolver.lookup_ip(&peer.endpoint.0).await?;

                    addrs
                        .iter()
                        .find(|ip| ip.is_ipv4())
                        .or_else(|| addrs.iter().next())
                        .context("no IPs found for endpoint address")?
                }
            },
        };

        let endpoint_port = args.endpoint_port.unwrap_or(peer.endpoint.1);
        endpoint_addr = SocketAddr::from((endpoint_ip, endpoint_port));
        max_transmission_unit = conf.interface.mtu;

        let obfuscation = if args.no_obfs {
            Obfuscation::OFF
        } else {
            Obfuscation {
                junk_packets: args.junk_packets,
                ..Obfuscation::default()
            }
        };

        tracing::info!(
            ?endpoint_ip,
            endpoint_port,
            junk_packets = obfuscation.junk_packets,
            rotate_source_port = obfuscation.rotate_source_port,
            "starting tunnel"
        );

        iface_addrs = heapless::Vec::from_slice(&conf.interface.addresses)
            .ok()
            .context("too many interface addresses")?;

        Transport::WireGuard {
            tunn: Tunn::new(
                StaticSecret::from(conf.interface.private_key),
                PublicKey::from(peer.public_key),
                peer.preshared_key,
                peer.persistent_keepalive,
                0,
                None,
            ),
            obfuscation,
        }
    };

    dirtysocks::Server::listen(ServerOptions {
        listener: TcpListener::bind(args.host).await?,
        transport,
        endpoint_addr,
        iface_addrs,
        timeout: Duration::from_secs(30),
        max_transmission_unit,
        resolver: dirtysocks::cloudflare_resolver(),
        user_pass: None,
        udp_listener: None,
    })
    .await?;

    Ok(())
}

fn ike_credentials(args: &cli::Args) -> Result<ike::Credentials> {
    let host = args
        .ike_host
        .clone()
        .context("--ike-host is required with --ike")?;
    let user = args
        .ike_user
        .clone()
        .context("--ike-user is required with --ike")?;
    let password = args
        .ike_pass
        .clone()
        .context("--ike-pass is required with --ike")?;

    Ok(ike::Credentials {
        remote_id: args.ike_remote_id.clone().unwrap_or_else(|| host.clone()),
        ca_der: load_ca(&args.ike_ca)?,
        host,
        user,
        password,
    })
}

/// Reads a trust anchor, accepting either PEM or DER.
fn load_ca(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;

    if !raw.starts_with(b"-----BEGIN") {
        return Ok(raw);
    }

    let text = std::str::from_utf8(&raw).context("the CA file is not UTF-8")?;
    let encoded: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| eyre!("failed to decode the PEM certificate: {e}"))
}
