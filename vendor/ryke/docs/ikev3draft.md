# ryke — IKEv3 (`draft-harkins-ikev3`) notes

Design + decision record for an **experimental** IKEv3 implementation in ryke.
Everything here is from the public draft and published analysis — read, not
copied (same clean-room rule as the rest of ryke).

## TL;DR

- **IKEv3** is [`draft-harkins-ikev3-01`](https://datatracker.ietf.org/doc/html/draft-harkins-ikev3-01),
  *"The (Real) Internet Key Exchange"* (Dan Harkins, 2013). It is an **expired,
  individual Internet-Draft** — never adopted by a working group, never an RFC.
  It is **not** a superset of IKEv2; it is a simpler clean-slate redesign.
- **Decision:** implement it in a module honestly named **`ikev3draft`** so no
  one mistakes it for a ratified standard. **Signature auth first.** The PSK
  method (Dragonfly) is **deferred and, if built, gated behind an explicit
  `experimental` flag** — see [Dragonfly](#dragonfly-is-the-risky-part).
- **Hard caveat:** there is **no other IKEv3 implementation to interop against**
  (unlike ryke's IKEv1/IKEv2, which we validated against strongSwan). So this can
  only be **faithful-to-draft + self-consistent** (ryke ↔ ryke loopback), never
  interop-proven. The draft is also unfinished (see [gaps](#open-draft-gaps)).
- **Why bother:** intellectual completeness — ryke would be the first *serious*
  (tested, Rust, published) implementation of the road IKE didn't take. It has
  **no practical connectivity value**: nothing else on Earth speaks IKEv3.

## The protocol (what the draft actually specifies)

A deliberately *smaller* protocol than IKEv2.

**Exchange — 2 round trips, fully peer-to-peer (no initiator/responder):**

```
Alice                                      Bob
Init: hdr, IAa, IDa, NOa, KEa [, CRa]  ⇄  Init: hdr, IAb, IDb, NOb, KEb [, CRb]   (cleartext)
Auth: hdr, {[CEa,] AUa, AIs, AId,      ⇄  Auth: hdr, {[CEb,] AUb, AIs, AId,        ({} = AEAD)
       SAa, TSs, TSd}                             SAb, TSs, TSd}
```

Either side may send `Init` first, or both simultaneously — so there are **no
exchange-collision rules** to implement.

**Header:** Transmitter SPI (8) · Receiver SPI (8) · First Payload (1) ·
Major/Minor version (4b/4b) · Message Type (`Init=1`, `Auth=2`) · Flags
(`V` version-capable, `S` secured) · Length (4) · ICV/SIV (conditional).

**Payloads:** `IA`(1) IKE Attributes · `ID`(2) Identity · `NO`(3) Nonce ·
`KE`(4) Key Exchange · `CR`(5) Cert Request · `CE`(6) Certificate ·
`AU`(7) Authentication · `AI`(8) Address Indication (NAT detection) ·
`TS`(9) Traffic Selector · `SA`(10) Security Association · `VE`(11) Vendor.

**Crypto:**
- KDF = `prf+` (RFC 5996) over HMAC-Hash; Hash ∈ {SHA-256, SHA-512}.
- Random function `H(x) = HMAC-Hash(0ⁿ, x)` (all-zeros key).
- AEAD = **AES-SIV (RFC 5297)**, 256- or 512-bit — nonce-misuse resistant, the
  *only* cipher (no GCM/CBC menu).
- DH over MODP **and** ECP groups; abstract `scalar-op` / `element-op` /
  `inverse` / mapping `F()` (x-coordinate for ECP, identity for MODP).

**Authentication:**
- **Public key (signature):** `sig = Sign(cKEY | InitLocal | InitPeer)` over the
  confirmation key and both Init messages, hashed with the negotiated hash.
- **PSK: Dragonfly** (SAE) — hunting-and-pecking to a secret element `SKE`, then a
  commit/confirm exchange; `AU = HMAC-Hash(cKEY, InitLocal | InitPeer)`.

**Key schedule:**
```
aeKEY | cKEY | dKEY = KDF( max(Na,Nb) | min(Na,Nb),  secret | "IKEv3 Key Derivation" )
IPsec key            = KDF( dKEY,                      "IPsec Key Derivation" )
```
`aeKEY` protects the Auth messages, `cKEY` is confirmation, `dKEY` seeds the ESP
SA. Nonces ordered lexicographically; ESP enc/integrity keys taken from the
KDF output in order.

**Deliberately removed vs IKEv2:** identity confidentiality (optional ID-blob
obfuscation only), SA lifetimes, Delete payloads, rekeying, and the whole
initiator/responder role split.

## Why it never shipped

Grounded in the record, not a guess:

- **Never adopted.** It was an *individual* draft, presented once at
  [IETF 85 (2012)](https://www.ietf.org/proceedings/85/slides/slides-85-ipsecme-7.pdf),
  and expired without working-group adoption. IPSECME chose to keep **extending
  IKEv2** (fragmentation, MOBIKE, post-quantum) rather than replace it. IKEv2 was
  deployed, interoperable, and entrenched; IKEv3 offered *simplification*, not new
  capability, so the cost/benefit never favored a rip-and-replace. → **Not
  rejected as broken; there was just no reason to switch.**
- **Contentious bets.** Its PSK method, **Dragonfly**, drew CFRG criticism
  (side-channel-prone password-to-point mapping, no security proofs;
  [cryptanalysis, 2013](https://eprint.iacr.org/2013/058.pdf)) and was later broken
  in practice as WPA3's SAE by
  [Dragonblood (2019)](https://i.blackhat.com/USA-19/Wednesday/us-19-Vanhoef-Dragonblood-Attacking-The-Dragonfly-Handshake-Of-WPA3-wp.pdf).
  Betting a new protocol on a distrusted primitive did not help.
- **Prior art:** one obscure partial implementation exists
  ([`manjurajv/ikev3`](https://github.com/manjurajv/ikev3)). No well-known IKE
  stack (strongSwan, Libreswan, …) ever implemented it.

## Decision for ryke

- **Module `ikev3draft`** (matches the `ikev1`/`ikev2` no-underscore style; the
  `draft` suffix is the honesty label).
- **Reuse** what ryke already has: `crypto` (`prf+`, X25519, P-256, MODP groups),
  `sign` (ECDSA/RSA). **New dependency:** `aes-siv` (RustCrypto) for the AEAD.
- **Signature auth first.** Standard DH + ECDSA + AES-SIV + `prf+` — all safe,
  well-trodden primitives. A ryke ↔ ryke IKEv3 handshake yielding a shared ESP
  `ChildSa` is the milestone.

### Dragonfly is the risky part

Dragonfly is exactly the class of PAKE that keeps getting broken by timing side
channels, and here we would have **no reference peer to validate constant-time
behavior against**. So:

- Dragonfly PSK is **deferred**. If it is ever built, it ships behind an explicit
  `experimental` / "not for production" gate, with the hunting-and-pecking loop
  written constant-time and clearly marked unvalidated.
- The signature-auth path stands alone and is the recommended/only default.

## Plan (milestones)

- **A — handshake skeleton (signature auth).**
  `ikev3draft/message.rs` (header + the 11 payloads), `ikev3draft/crypto.rs`
  (`H()`, the `aeKEY|cKEY|dKEY` schedule, AES-SIV wrap, IPsec key derivation),
  `ikev3draft/exchange.rs` (symmetric peer: Init → Auth-with-signature → derive
  ESP `ChildSa`). **Test:** two peers over loopback derive matching ESP keys
  (seal/open both ways), mirroring the `ikev1`/`ikev2` loopback tests.
- **B — Dragonfly PSK (experimental-gated).** Hunting-and-pecking for ECP + MODP,
  commit/confirm, the HMAC `AU`. Constant-time; behind the experimental flag.
- **C — NAT detection (`AI`), traffic selectors, and an `ikev3draft::Peer` UDP
  driver.**

## Open draft gaps

The draft is unfinished; where it is silent, ryke makes a documented choice:

- **Retransmission timer** period — unspecified (§6.3.2).
- **Stale-instance cleanup** — "sufficient time" undefined (§6.3.4).
- **Traffic-selector encoding** — the section truncates mid-definition (§6.4.11).
- **IANA values** — payload/type numbers point to an external `[IKEV3IANA]`
  registry that was never assigned; ryke will pick private values and document
  them.

## References (read, not copied)

- [`draft-harkins-ikev3-01`](https://datatracker.ietf.org/doc/html/draft-harkins-ikev3-01)
  and [`-00`](https://datatracker.ietf.org/doc/html/draft-harkins-ikev3-00);
  [IETF 85 slides](https://www.ietf.org/proceedings/85/slides/slides-85-ipsecme-7.pdf).
- Cheng et al., *Analysis and improvement of the Internet-Draft IKEv3 protocol*
  ([Wiley, 2017](https://onlinelibrary.wiley.com/doi/10.1002/dac.3194)).
- AES-SIV: [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297).
- Dragonfly: [RFC 7664](https://datatracker.ietf.org/doc/html/rfc7664),
  [cryptanalysis (2013)](https://eprint.iacr.org/2013/058.pdf),
  [Dragonblood (2019)](https://i.blackhat.com/USA-19/Wednesday/us-19-Vanhoef-Dragonblood-Attacking-The-Dragonfly-Handshake-Of-WPA3-wp.pdf).
- Prior art: [`manjurajv/ikev3`](https://github.com/manjurajv/ikev3).
