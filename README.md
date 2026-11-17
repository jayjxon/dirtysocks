# dirtysocks

A SOCKS5 proxy with usermode WireGuard capabilities.

Meant to be a replacement/comparable to [`wireproxy`](https://github.com/pufferffish/wireproxy)

## Usage

```
A usermode WireGuard or IKEv2 client with a SOCKS5 proxy

Usage: dirtysocks-bin [OPTIONS]

Options:
  -c, --config <CONFIG>      The `wg-quick` config file to read
      --host <HOST>          The socket address the SOCKS5 proxy should listen on [default: 127.0.0.1:3000]
      --ike                  Use IKEv2 (username/EAP-MSCHAPv2) instead of WireGuard
      --ike-host <HOST>      The IKEv2 server hostname
      --ike-user <USER>      The IKEv2 username, which is also the local identity [env: DIRTYSOCKS_IKE_USER=]
      --ike-pass <PASS>      The IKEv2 password [env: DIRTYSOCKS_IKE_PASS=]
      --ike-remote-id <ID>   The identity the IKEv2 server certificate must vouch for [default: --ike-host]
      --ike-ca <CA>          The CA certificate (PEM or DER) used to verify the IKEv2 server [default: /etc/ssl/certs/ISRG_Root_X1.pem]
      --endpoint-ip <IP>     Resolve the endpoint to this address instead of using DNS
      --endpoint-port <PORT> Connect to this endpoint port instead of the one in the config
      --no-obfs              Disable transport obfuscation (junk packets and source port rotation)
      --junk-packets <N>     Number of junk datagrams sent before each handshake [default: 4]
  -h, --help                 Print help
  -V, --version              Print version
```

## Examples

```
dirtysocks-bin --config <wg-quick config file> --host 127.0.0.1:1234
```

## Evading blocks

Networks commonly block `WireGuard` endpoints, either by fingerprinting the
cleartext handshake or by blacklisting the UDP flow once it is recognised.
The client obfuscates the transport by default, without any server-side
changes:

- random junk datagrams are sent before each handshake initiation, so the first
  packet of the flow is not a recognisable `WireGuard` handshake. A standard
  `WireGuard` peer drops them;
- the UDP socket moves to a fresh source port whenever a handshake is retried,
  so a block tied to the old 5-tuple stops applying. `WireGuard` peers follow
  roaming clients, so the session survives;
- `--endpoint-ip` and `--endpoint-port` override the endpoint in the config, for
  when DNS or the configured address/port is what is blocked;
- the endpoint is resolved to IPv4 when possible, and host interface addresses
  are treated as routes to the peer, so `/32` and `/128` configs work.

Use `--no-obfs` to send exactly the packets a stock `WireGuard` client would.

## IKEv2 fallback

Some networks block `WireGuard` outright while leaving IPsec alone. The proxy
can carry its traffic over IKEv2 instead, authenticating with a
username/password (EAP-MSCHAPv2) and reading the inner address the server
assigns:

```
DIRTYSOCKS_IKE_USER=<username> DIRTYSOCKS_IKE_PASS=<password> \
  dirtysocks-bin --ike --ike-host <server> --host 127.0.0.1:3000
```

The server certificate is verified against `--ike-ca`; most provider chains root
at `ISRG Root X1`, which is the default. The password is taken from the
environment so it never appears in the process list or in a config file.

## Implementation

Follows a very similar implementation to [`onetun`](https://github.com/aramperes/onetun), plus UDP support for SOCKS5 clients that tunnel it.

However, there are bandwidth issues, which were previously seen in [onetun#29](https://github.com/aramperes/onetun/issues/29). I am currently looking into the causes of said bandwidth issues.
