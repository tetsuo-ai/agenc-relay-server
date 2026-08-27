# Protocol source and decision ledger

Status: research and review evidence for the version-1 specifications. This
file is not a third normative protocol document. The precedence rules in
`ircd-architecture-and-implementation-spec.md` remain authoritative.

Last source-status check: 2026-08-24.

## 1. Purpose

This ledger records why a source is used, superseded, narrowed, or excluded.
It prevents a current crate default, mutable web page, expired draft, or old
base-protocol rule from silently becoming protocol authority. A source check
is evidence of provenance and status, not a security audit of this design.
The frozen specifications, supporting documents, validator, and derived
negotiation hashes are bound by `specification-manifest.txt`. The manifest is
evidence rather than protocol authority and deliberately does not hash itself.

The implementation conformance ledger must bind each applicable decision
below to requirements, vectors, and release evidence. A source revision alone
never changes version-1 wire bytes, persistent bytes, cryptographic domains,
or security claims.

## 2. Published standards

| Source | Publication status at check | Version-1 decision |
| --- | --- | --- |
| RFC 2119 and RFC 8174 | BCP 14 | Adopted for requirement words. |
| RFC 1459 and RFCs 2810-2813 | historical/legacy base documents | Adopt familiar client behavior only where the architecture specification does not narrow or replace it. Legacy server links, address disclosure, collision handling, and insecure authentication are not adopted. |
| RFC 7194 | Informational | Historical client TLS port guidance only; the version-1 TLS profile is stricter. |
| RFC 6455 | Proposed Standard | Adopted for the optional WebSocket transport, with compression and plaintext upgrades forbidden by the architecture profile. |
| RFC 6973 | Informational IAB guidance | Adopted as threat-analysis and data-minimization guidance, not as a cryptographic protocol. |
| RFC 8265 and RFC 8266 | Proposed Standards | Adopted for the exact username/nickname preparation profiles named by the architecture specification. |
| RFC 8439 | Informational | Adopted for ChaCha20-Poly1305 primitives and vectors where named. It does not define XChaCha. |
| RFC 9106 | Informational IRTF/CFRG | Adopted for Argon2id, narrowed to the fixed OPAQUE KSF parameters. |
| RFC 9180 | Proposed Standard | Adopted for the fixed Base-mode HPKE account-service suite and contexts. |
| RFC 9325, updated by RFC 9852 | BCP 195 | Adopted for TLS deployment. Because this is a new TLS-based protocol, every endpoint requires TLS 1.3 and disables TLS 1.2 rather than using RFC 9852's optional compatibility allowance. |
| RFC 9420 | Proposed Standard | Normative MLS protocol. The companion specification deliberately narrows suites, extensions, message forms, proposal handling, and delivery-service behavior. |
| RFC 9525 | Proposed Standard | Adopted for DNS service-identity verification. Onion endpoints use the separately pinned SPKI rule. |
| RFC 9750 | Informational | Adopted as MLS architecture and threat-model guidance. It does not replace the exact RFC 9420 or companion wire requirements. |
| RFC 9807 | Informational IRTF/CFRG | Deliberately adopted as the OPAQUE protocol despite not being an IETF Standards Track RFC; the exact suite, identities, context, fake-record behavior, and KSF are fixed locally. |
| RFC 9846 | Proposed Standard | Normative TLS 1.3 authority. It obsoletes RFC 8446; the local RFC 8446 file is historical input only. |
| RFC 9954 | Informational IETF | Adopted only as the hybrid TLS key-exchange construction referenced by RFC 10024. It does not assign the selected group. |
| RFC 10024 | Proposed Standard | Normative definition and assignment for `X25519MLKEM768`; strict native clients require it and compatibility clients may use only X25519 fallback. |
| RFC 10015 | Proposed Standard | Reviewed and not applicable to the negotiated profile because it only deprecates TLS/DTLS 1.2 key exchanges and version 1 forbids TLS 1.2 entirely. |

Authoritative publication pages:

- <https://www.rfc-editor.org/info/rfc9846/>
- <https://www.rfc-editor.org/info/rfc9852/>
- <https://www.rfc-editor.org/info/rfc9954/>
- <https://www.rfc-editor.org/info/rfc10024/>
- <https://www.rfc-editor.org/info/rfc9807/>
- <https://www.rfc-editor.org/info/rfc9420/>
- <https://www.rfc-editor.org/info/rfc9750/>

RFC 9807 ends the online exchange with client `KE3`; it does not define an
application-state commit acknowledgement to the client. Because an edge in
this design terminates client TLS and is not trusted to assert account state,
the local profile adds one fixed-size RFC-9180-exporter-authenticated completion
receipt after every account-service finish. That receipt does not alter OPAQUE
or feed back into its transcript. The profile also fixes the RFC-9807
ristretto255 serialization lengths and rejects the dependency's generic or
Serde-shaped alternatives. With `Noe=32`, `Nn=32`, `Npk=32`, and `Nm=64`, the
RFC structure makes `CredentialResponse` 192 bytes and `AuthResponse` 128
bytes, so the complete `KE2` is 320 bytes. Each response header carries a fresh authenticated
32-byte salt used in both HPKE exporter contexts. The client's pinned recovery
epoch domain-separates both request opening and response exports, while an
authenticated coordinator StateMeta counter limits newly committed responses
to fewer than `2^64` per epoch. This prevents a request replayed after result
retention
from reusing an AEAD key/nonce when its later semantic outcome differs and
gives the random-salt collision claim an explicit bound.

The fixed response registry has no separate START-rejection arm. A fully
opened and parsed START that fails a semantic admission predicate therefore
uses the ordinary challenge and retains a non-authorizing transaction whose
only terminal result is an encrypted rejected completion. It creates no
reservation or mutation authority. Pre-Open, parse, entropy, allocation,
counter, deadline, and internal-corruption failures remain operational failures
without a response.

## 3. Work in progress and deliberately excluded algorithms

`draft-ietf-mls-pq-ciphersuites-06` was an active Internet-Draft last updated
2026-07-21, with intended Proposed Standard status and working-group state
"Waiting for WG Chair Go-Ahead Revised I-D Needed - Issue raised by WG" at the
check. It still contained unassigned placeholder cipher-suite values. Version 1
therefore advertises no post-quantum MLS suite and makes no post-quantum E2EE
claim. A later final RFC requires a new negotiated profile, vectors,
interoperability evidence, migration rules, and integration validation.

Status source:
<https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/>

At-rest XChaCha20-Poly1305 remains pinned to
`draft-irtf-cfrg-xchacha-03`, an expired IRTF draft, plus independently checked
library vectors. It is not described as an RFC or an IETF standard. The
project-specific nonce reservation, authenticated manifest, rollback guard,
and crash-recovery composition is covered by fixed vectors and the crash/fault
matrix; a successful primitive vector alone does not validate that behavior.

## 4. Living protocol sources

The following commits were both the named pins and the remote default-branch
heads when checked with `git ls-remote` on 2026-08-24:

| Source | Immutable commit | Use |
| --- | --- | --- |
| IRCv3 specifications | `9ff58d1342af67aff88753388f568542820c4bfe` | CAP, tags, SASL, labeled response, batch, account/presence capabilities, message IDs, server time, MONITOR, SETNAME, standard replies, UTF8ONLY, STS, WebSocket, and the pinned optional history draft. |
| Modern IRC | `8f4c3cc51f0036597f5c95e595fb6ec3177ba4c9` | Base behavior where the architecture profile does not narrow it. |
| Tor specifications | `bc5ebcad4d5545efc9a527ee33ec039c66d7cdf3` | Version-3 onion service and SOCKS extension behavior. |

Remote repositories:

- <https://github.com/ircv3/ircv3-specifications>
- <https://github.com/ircdocs/modern-irc>
- <https://gitlab.torproject.org/tpo/core/torspec>

The Tor community setup guide is operational guidance only. The pinned Tor
specification commit and the architecture's exact listener/isolation/DNS rules
control conformance.

The local version-1 client profile deliberately extends the complete IRC
message envelope to 8,703 stream bytes so its fixed 1,024-byte topics and
512-byte message bodies remain representable with required prefixes and
targets. Ratified message-tag side and combined-section limits remain intact,
CAP replies retain a 512-byte compatibility budget, and all bytes share the
one physical ceiling. This is a locally versioned narrowing/extension decision,
not a claim that legacy IRC clients accept every maximum-sized message.

## 5. Initial Rust dependency evidence

These checksums came from the crates.io version API on 2026-08-24. They pin
the initial direct versions reviewed by the specification; the release
`Cargo.lock`, source policy, SBOM, advisory review, and canonical vectors pin
the complete graph actually shipped.

| Package | Version | crates.io SHA-256 | Production feature decision |
| --- | ---: | --- | --- |
| `tokio` | 1.53.1 | `202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed` | no defaults; `rt-multi-thread,net,io-util,time,signal,sync,macros` |
| `rustls` | 0.23.43 | `0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06` | no defaults; `std,aws_lc_rs,prefer-post-quantum`; TLS 1.3 list only |
| `getrandom` | 0.4.3 | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | no defaults; `std` |
| `redb` | 4.2.0 | `de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36` | no defaults; `std`; no production compaction call |
| `opaque-ke` | 4.0.1 | `ded22991b43cd15561b62b2e1cf9ace1344a8534eebec96202d5c96a77a6616a` | no defaults; `ristretto255,argon2,std`; no Serde |
| `opaque-sha2` | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | Cargo alias for package `sha2`; no defaults; scoped to the OPAQUE ciphersuite required by `opaque-ke` 4.0.1 |
| `precis-profiles` | 0.1.13 | `31e2768890a47af73a032af9f0cedbddce3c9d06cf8de201d5b8f2436ded7674` | no defaults; private bounded adapter; networking feature disabled |
| `hpke` | 0.14.0 | `dd5130e119706b4d8c2180da6126f7e60b6c38c2d340d539219f57051f0a7af7` | no defaults; `alloc,chacha,x25519,hkdfsha2` |
| `tls_codec` | 0.5.0 | `18cc98286004cea38f717e2b03d990fc774fbfd38a82720de40e5c94365067c8` | no defaults; `std,mls`; no production derive/Serde |
| `base64` | 0.23.1 | `ac07cdecf99051d9a5238b80f35af32cdeba5b336e55d957b318b50137e18da5` | no defaults; `alloc`; canonical unpadded URL-safe adapter only |
| `chacha20poly1305` | 0.11.0 | `9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb` | no defaults; `alloc,zeroize`; XChaCha type only |
| `ed25519-dalek` | 3.0.0 | `6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de` | no defaults; `fast,zeroize`; strict verification only |
| `sha2` | 0.11.0 | `446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4` | no defaults; `zeroize` |
| `hmac` | 0.13.0 | `6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f` | no defaults; `zeroize` |
| `hkdf` | 0.13.0 | `4aaa26c720c68b866f2c96ef5c1264b3e6f473fe5d4ce61cd44bbe913e553018` | no defaults |
| `argon2` | 0.5.3 | `3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072` | no defaults; `alloc`; fixed Argon2id adapter only |
| `zeroize` | 1.9.0 | `e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e` | no defaults; `alloc` |
| `subtle` | 2.6.1 | `13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292` | no defaults |

The observed rustls default feature set included `tls12`; disabling defaults
and constructing a TLS-1.3-only version list are both required. The observed
hpke defaults included algorithms outside the fixed account-service profile.
The observed opaque-ke defaults included Serde. None of those defaults are
protocol authority.

The workspace uses a reviewed local source patch for `opaque-ke` 4.0.1. The
patch does not change its protocol bytes, suite, features, or version. It keeps
password-derived OPRF and KSF outputs in zeroizing storage while constructing
the HKDF state, and returns the server-finish session key in a move-only,
non-formatting zeroizing field. The published crates.io checksum above remains
the upstream provenance value. `conformance/vendored-dependencies.toml` records
the complete patched-tree digest, and the workspace checker rejects any other
source override or tree content.

redb 4.2.0 documents commit outcomes that can be indeterminate and exposes an
in-place compaction operation implemented through its own write transactions.
The architecture therefore defines explicit reconciliation for indeterminate
commit and forbids in-place compaction outside the authenticated StateCore
mutation/manifest/guard contract. Space reclamation occurs only while building
a fresh verified database through the specified offline construction ledger.

## 6. Update and review procedure

For every source or dependency update:

1. verify publication status, obsoletes/updates relationships, errata, tag or
   commit identity, crate checksum, MSRV, feature graph, and yanked/advisory
   status from a primary source;
2. diff the exact normative behavior used by both specifications;
3. record an explicit adopt, narrow, supersede, or reject decision;
4. update affected wire/state registries, domain strings, bounds, vectors,
   requirements, threat analysis, raw source hashes, and the companion's
   domain-separated CAP/ECAP profile hash together;
5. rerun the complete conformance and downgrade suites; and
6. analyze any affected cryptographic integration, identity, authorization,
   persistence, privacy, or cross-profile atomicity behavior and record the
   decision and evidence.

No entry in this ledger replaces implementation tests or the release evidence
required by the architecture specification.
