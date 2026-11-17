# ryke

A **clean-room IKEv2 / IKE implementation in Rust** — independent **client
(initiator)** and **server (responder)**.

`ryke` = **R**ust + **IKE**. Built from the RFCs; it does not wrap OpenSSL or any
existing IKE/IPsec daemon, and copies no third-party code.

## Status

Early and moving. The message framing and the `IKE_SA_INIT` cryptographic core
are in place and verified against published test vectors.

## What works today

- **Message framing** — IKE header + generic payload chain (RFC 7296 §3.1–3.2).
- **Payloads** — Security Association (proposals/transforms), Key Exchange, Nonce.
- **Crypto core** for `IKE_SA_INIT`:
  - X25519 Diffie-Hellman — verified against **RFC 7748**.
  - HMAC-SHA256 PRF — verified against **RFC 4231**.
  - `prf+` and the SKEYSEED / SK_* key schedule — RFC 7296 §2.13–2.14.

See [`docs/implementation-plan.md`](docs/implementation-plan.md) for the roadmap.

## Design

- **Control plane in Rust** (framing, exchanges, crypto, auth); the **ESP data
  plane is a userspace ESP implementation in Rust** (AES-GCM) — `ryke`
  encrypts/decrypts tunneled packets itself and uses **no external software**
  (not the OS kernel's IPsec stack, not any external VPN daemon). It moves packets you
  hand it (`Tunnel` / `EspSa` / `ChildSa`); capturing real OS traffic (a TUN
  device, a SOCKS proxy, …) is the consumer's job and out of scope.
- Both roles are first-class ([`Role::Initiator`] / [`Role::Responder`]). The
  server role targets native iOS/Android IKEv2 clients (no app on the phone).

## Build

```bash
cargo build
cargo test        # includes the RFC 7748 / RFC 4231 known-answer tests
```

## License

MIT — see [LICENSE.md](LICENSE.md). © Vladimir Chebotarev
