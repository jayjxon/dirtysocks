# ryke — implementation plan

`ryke` is a clean-room IKEv2 / IKE implementation in Rust, with **independent
client (initiator) and server (responder)** roles.

## Ground rules

- **Clean-room.** The RFCs are the normative source; existing implementations may
  be consulted for *understanding only* — **no third-party code is copied**, so
  `ryke` carries no external license.
- **Both roles are first-class.** The client starts exchanges; the server
  answers. The server role targets native **iOS + Android** IKEv2 clients (no app
  on the phone), which pins the feature set: certificate auth, EAP-MSCHAPv2, IKE
  fragmentation, MOBIKE, NAT-T.

## Architecture — split control/data plane

- **Control plane (this crate, Rust userspace):** UDP 500/4500, message
  framing, exchange state machines, crypto + key schedule, authentication.
- **Data plane → userspace ESP in Rust** (a library API, not a device). The
  application feeds packets to a [`Tunnel`] (`send`/`recv`), or uses the
  lower-level `EspSa`/`ChildSa` directly — pure userspace, no device, no root,
  cross-platform, unit-testable. `ryke` encrypts/decrypts packets itself under
  the CHILD-SA keys and uses **no external software** (not the OS kernel's
  IPsec/XFRM stack, not any external VPN daemon).
- **Out of scope:** capturing a machine's real traffic (TUN device, SOCKS, etc.).
  `ryke` is a library; a consumer wires whatever packet source they want to
  `Tunnel::send`/`recv`.
- **Consumers** (e.g. a node/gateway service) embed `ryke` as a library and drive
  the initiator or responder role.

## Module layout (`src/`)

| Module     | Responsibility                                                       | Status |
| ---------- | ------------------------------------------------------------------- | ------ |
| `message`  | IKE header + generic payload chain framing (§3.1–3.2)                | ✅     |
| `payload`  | SA/Proposal/Transform, KE, Nonce done; IDi/IDr, CERT, AUTH, TS, CP later | 🟡 |
| `crypto`   | X25519, HMAC-SHA256 PRF, `prf+`, SK_* schedule done; more groups later  | 🟡 |
| `role`     | Initiator / Responder duality                                       | ✅     |
| `sa`       | IKE SA + CHILD SA state, SPIs, sequence/window                       | ⬜     |
| `negotiate` | Suite selection from an offered SA (X25519 + HMAC-SHA256, AES-GCM/CBC) | 🟡 |
| `exchange` | `sa_init` done (both roles); `auth`, `create_child_sa`, `informational` later | 🟡 |
| `sk`       | Encrypted `SK{}` payload — AES-256-GCM seal/open (RFC 5282) done     | 🟡     |
| `auth`     | PSK AUTH (RFC 7296 §2.15) done; cert (RFC 7427) + EAP-MSCHAPv2 later | 🟡     |
| `config`   | CP (assign IP/DNS) + traffic-selector negotiation                   | ⬜     |
| `transport`| UDP done (blocking `UdpSocket`); NAT-T 4500 + fragmentation later    | 🟡     |
| `entropy`  | `Entropy` trait; `OsEntropy` (/dev/urandom) + `SeedEntropy` (tests)  | ✅     |
| `esp`      | ESP codec (AES-256-GCM tunnel mode) + `ChildSa` key derivation         | ✅     |
| `tunnel`   | **Internal-mode** data plane (`Tunnel` send/recv over UDP, no device)  | ✅     |
| `client` / `server` | Full handshake (SA_INIT + IKE_AUTH, PSK) for both roles, loopback-tested | ✅ |

## Milestones (each ends at an interop checkpoint)

- **M0 — message framing.** ✅
- **M1 — `IKE_SA_INIT`.** ✅ **Complete + interop-validated.** X25519
  (RFC 7748-tested), HMAC-SHA256 PRF + `prf+` (RFC 4231-tested), SKEYSEED/SK_*
  schedule, framing, message builder, suite negotiation, and the `sa_init`
  exchange for **both roles**. In-process: initiator ↔ responder derive identical
  keys. **Live interop:** the `ryke` initiator completes `IKE_SA_INIT` over UDP
  against an independent IKEv2 responder — the responder accepts ryke's request
  (AES-GCM-256 / HMAC-SHA256 / X25519) and ryke parses its real response and
  derives keys. (Mutual key *agreement* is proven at M2, when ryke can decrypt
  the peer's `IKE_AUTH`.) Fixed along the way: ESN must not appear in an IKE
  proposal (§3.3.3) — caught precisely because interop forces correctness.
- **M2 — `IKE_AUTH`.** *In progress — exchange assembled (in-process).* The full
  `IKE_AUTH` runs for **both roles**: the initiator builds
  `SK{ IDi, AUTH, SAi2, TSi, TSr }`, the responder decrypts + verifies + answers,
  and the initiator verifies the response — mutual PSK auth + identity exchange,
  with wrong-PSK and tampering rejected. `Client::connect()` performs the whole
  SA_INIT + IKE_AUTH handshake. Building blocks (SK crypto, IDi/IDr, AUTH, TSi/TSr,
  CHILD-SA keying) all done. **Remaining:** give the `Server` session state for
  the two-message flow; prove key agreement against an independent IKEv2 peer
  (`Client::connect()` — decrypting its `SK{}` is the proof); then auto-wire the
  handshake to a `Tunnel` (extract the negotiated ESP SPIs) → packets flow.
- **M3 — NAT-T + IKE fragmentation.** ✅ Done. NAT detection
  (`SHA1(SPIi|SPIr|IP|Port)` + source/dest notifies + detection logic) and the
  UDP-4500 non-ESP marker (RFC 7296 §2.23, RFC 3948); plus the Notify payload.
  IKE message fragmentation — `SKF` payload with per-fragment AES-GCM and
  order-independent reassembly (RFC 7383), so large cert/EAP messages survive UDP
  through NAT. All unit-tested (roundtrip, missing/tampered fragments rejected).
- **M4 — EAP-MSCHAPv2** (the iOS/Android auth path). ✅ Done + interop-validated.
  MSCHAPv2 (RFC 2759 §9.2), EAP framing (RFC 3748), and the MSK (RFC 3079). The
  multi-message state machine lives in the library — `eap_auth::EapInitiator`
  (the phone's role) and `eap_auth::EapResponder` (server: PSK self-auth + EAP
  password check + the two MSK-keyed AUTHs) — with an **in-process full-handshake
  test** and a wrong-password rejection test. The **initiator is validated
  end-to-end against an independent IKEv2 responder** over UDP: SA_INIT → NAT-T
  (4500 + non-ESP marker) → EAP Identity → MSCHAPv2 Challenge/Response (password
  verified by the peer) → Success → MSK-keyed AUTH → CHILD SA established. Interop
  caught + fixed a real bug: the MSK's two halves were swapped (it is
  `ASK(Magic2) ‖ ASK(Magic3)`, server perspective).
- **M4b — certificate / Digital-Signature auth (RFC 7427).** ✅ Done + tested.
  The server-auth path phones require. `sign.rs` implements Auth Method 14 — the
  AUTH Data `[len][DER AlgorithmIdentifier][signature]` over the §2.15 octets —
  with `sha256WithRSAEncryption` (RSA PKCS#1 v1.5) and `ecdsa-with-SHA256` on
  P-256 for **sign + verify**, plus RSASSA-PSS/SHA-256 verify; X.509 leaf parsing
  (`VerifyingKey::from_cert_der`), single-hop chain signature checking
  (`verify_cert_signed_by`), and the CERTREQ trust-anchor `ca_key_hash`. `payload.rs`
  carries the `Certificate`/`CertRequest` bodies and the `SIGNATURE_HASH_ALGORITHMS`
  notify. In the EAP flow, `ServerAuth::Cert` makes the responder present its chain
  + a method-14 AUTH in its first response, and `ServerVerify::TrustedCas { cas,
  expected_dns }` makes the client verify chain-to-anchor **+ SAN↔name binding +
  signature** before sending EAP credentials — with a credential firewall that
  refuses the whole EAP exchange until the server is authenticated (so a rogue peer
  can't skip server auth and harvest the username/MSCHAPv2 response). The client
  also key-confirms the responder's final MSK-keyed AUTH, and `IKE_SA_INIT` now
  emits + parses `SIGNATURE_HASH_ALGORITHMS` (RFC 7427 §4), gating the method-14
  AUTH on a mutually-supported hash. All of these were found by an adversarial
  review pass and fixed with regression tests. Crypto is all RustCrypto (pure Rust,
  no OpenSSL): rsa 0.9, p256 0.13, x509-cert 0.2. Cert auth also works on the **plain
  (non-EAP) `IKE_AUTH`** path (`LocalAuth::{Psk,Cert}` × `PeerAuth::{Psk,Cert}` —
  e.g. mutual certificate auth for a node↔node link), and the verifier does real
  **X.509 path building** (`validate_chain`): per-hop signature, validity window,
  and `BasicConstraints` CA checks up to a trusted anchor. A second adversarial pass
  (27 attack vectors: chain cycles, DN spoofing, non-CA intermediates, expired/pin
  edge cases, method confusion) found nothing. **Still deferred:** `pathLenConstraint`,
  name constraints, key-usage/EKU, and revocation (CRL/OCSP needs network); plus
  SHA-384/512 signing (only SHA-256 is emitted; every phone advertises it).
- **M5 — lifecycle.** ✅ Done + tested. The DELETE payload + INFORMATIONAL
  exchange (**DPD** liveness + encrypted **DELETE**, tamper-rejecting);
  **CHILD-SA rekey** via `CREATE_CHILD_SA` (both sides derive matching ESP SAs on
  fresh SPIs; the rekeyed tunnel passes packets both ways); and **MOBIKE**
  (RFC 4555 — MOBIKE_SUPPORTED negotiation + UPDATE_SA_ADDRESSES signalling and
  detection). Socket rebinding on a move is left to the consumer.
- **M6 — device interop:** iPhone, then Android (the long tail).

## Experimental — IKEv3 draft

Separate from the IKEv2 roadmap above: an experimental implementation of
`draft-harkins-ikev3` (the unratified "IKEv3") is planned in an `ikev3draft`
module — signature auth first, Dragonfly PSK deferred/experimental. It has **no
deployed peers to interop against** and is a completeness/research exercise, not
a shipping feature. Full design + decision record:
[`docs/ikev3draft.md`](ikev3draft.md).

## Testing

- Offline unit tests with byte vectors and RFC known-answer tests (in place).
- Integration against an independent IKEv2 implementation as the peer, both directions.
- Real-device interop last, and continuously (OS updates break it).
- Fuzz the parsers (`cargo-fuzz`) — untrusted network input.

## References (read, not copied)

RFC 7296 (IKEv2), 7383 (fragmentation), 4555 (MOBIKE), 7427 (signature auth),
3947/3948 (NAT-T), 8247 (algorithm recommendations), 2759 (MS-CHAP-v2), 3079
(MPPE/MSK keys), 3748 (EAP); RFC 4303 (ESP) + RFC 5282
(AES-GCM in ESP) for the userspace data path.
