# Changelog

All notable changes to **ryke** are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-15

Keeping native-client tunnels alive across their whole lifetime: liveness (DPD),
CHILD-SA **and** IKE-SA rekey, MOBIKE roaming, and multi-tenant EAP — the pieces a
responder needs so iOS/Android hold the tunnel from the first minutes through the
hourly rekeys and network changes, not just the opening handshake.

### Added
- **Liveness / Dead-Peer-Detection** as public API: `dpd_request`,
  `build_informational`, and `open_informational` for the INFORMATIONAL exchange
  (RFC 7296 §1.4 / §2.4). A responder can now answer a native client's periodic
  liveness probes — unanswered, iOS declares the peer dead and tears the tunnel
  down within a few minutes — and read `Delete` payloads.
- **CHILD-SA rekey**: `responder_process_rekey` processes a peer's
  `CREATE_CHILD_SA` (RFC 7296 §2.8), derives the new CHILD SA from
  `prf+(SK_d, Ni | Nr)`, and builds the response — **echoing the initiator's
  traffic selectors** (a native client narrows TSi to its assigned `/32` and
  rejects a response with wider selectors).
- **IKE-SA rekey** (RFC 7296 §2.18): `responder_process_ike_rekey` handles a
  `CREATE_CHILD_SA` that rekeys the IKE SA itself — a fresh Diffie-Hellman, new
  IKE SPIs, and the new key schedule `SKEYSEED = prf(SK_d_old, g^ir | Ni | Nr)`
  (exposed as `derive_rekey_session_keys`), with the CHILD SAs inherited by the
  new IKE SA. `is_ike_sa_rekey` routes a `KeyExchange`-carrying, TS-less
  `CREATE_CHILD_SA` here. Without it a native client — iOS refreshes its IKE SA
  on its ~1 h lifetime — fails the rekey and tears the whole tunnel down. (PFS on
  a *CHILD*-SA rekey, i.e. a `KeyExchange` alongside traffic selectors, is still
  not handled.)
- **MOBIKE** (RFC 4555): the responder advertises `MOBIKE_SUPPORTED` in its
  IKE_AUTH response (both the EAP and certificate paths) so a native client
  migrates its SA across network changes (Wi-Fi↔cellular / NAT rebind) via
  `UPDATE_SA_ADDRESSES` instead of tearing down and reconnecting.
- **Multi-tenant EAP-MSCHAPv2**: `EapResponder::new_multi` takes a
  username→password map and selects the credential by the client's EAP identity
  (an unknown identity is rejected); `EapResponder::user()` exposes the
  authenticated username.
- Examples: `dpd_probe`, `retransmit_probe`, `rekey_probe`, `rekey_e2e`.

## [0.2.0] - 2026-07-11

Server-side termination of native OS VPN clients (iOS / Android): the responder
can now authenticate, address, and NAT-traverse a stock device with no custom
client software.

### Added
- **EAP-MSCHAPv2 authentication** (RFC 3748 / RFC 2759), both sides. `EapResponder`
  terminates native clients with a server certificate plus username/password;
  `EapInitiator` drives the exchange for testing. Server certificate auth uses
  RFC 7427 Digital Signature (method 14) and falls back to classic ECDSA
  (method 9) for peers that advertise no `SIGNATURE_HASH_ALGORITHMS` (e.g. iOS).
- **Configuration Payload** (`CFG_REPLY`): the responder assigns the client its
  inner IP (and DNS) and narrows the traffic selector to that host `/32`.
- **NAT traversal (NAT-T)**: `NAT_DETECTION_SOURCE/DESTINATION_IP` notifies, float
  to UDP 4500 behind the non-ESP marker, UDP-encapsulated ESP, and `INVALID_KE`
  Diffie–Hellman group renegotiation.
- **IKE_SA_INIT cookies** (RFC 7296 §2.6): stateless return-routability cookie
  (`ike_cookie`, `CookiePolicy`, `SaInitResult::CookieRequired`) to shed spoofed
  SA_INIT floods before performing Diffie–Hellman.
- Per-user identity extraction (`peer_id_from_auth`) for per-identity PSK lookup.
- Examples: `ike_client` (PSK + Configuration Payload), `ike_client_eap`
  (EAP-MSCHAPv2 with CA verification), `ike_client_natt` (NAT-T float).

### Changed
- PSK `AUTH` verification now uses a constant-time MAC comparison.

## [0.1.0]

- Initial release: IKEv2 / IKEv1 message framing, crypto core (X25519, HMAC-SHA256
  PRF, `prf+`), the `IKE_SA_INIT` key schedule, PSK `IKE_AUTH`, userspace ESP
  (AES-GCM), and the `Tunnel` data-plane helper.
