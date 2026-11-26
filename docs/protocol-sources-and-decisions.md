# Protocol source and decision ledger

Status: research and review evidence for the version-1 specifications. This
file is not a third normative protocol document. The precedence rules in
`arc-architecture-and-implementation-spec.md` remain authoritative.

Last source-status check: 2026-09-05.

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
| RFC 9420 | Proposed Standard | Normative MLS protocol. The companion specification deliberately narrows suites, extensions, message forms, proposal handling, and delivery-service behavior. Its length padding is applied to the application content rather than to the MLS padding field, and its policy publication, sequencer quorum check, and edge record-chain witness are application-layer decisions over an unmodified MLS. |
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
| `rustls` | 0.23.45 | `0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634` | no defaults; `std,aws_lc_rs,prefer-post-quantum`; TLS 1.3 list only |
| `getrandom` | 0.4.3 | `300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099` | no defaults; `std` |
| `redb` | 4.2.0 | `de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36` | no defaults; `std`; no production compaction call |
| `opaque-ke` | 4.0.1 | `ded22991b43cd15561b62b2e1cf9ace1344a8534eebec96202d5c96a77a6616a` | no defaults; `ristretto255,argon2,std`; no Serde |
| `opaque-sha2` | 0.10.9 | `a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283` | Cargo alias for package `sha2`; no defaults; scoped to the OPAQUE ciphersuite required by `opaque-ke` 4.0.1 |
| `precis-profiles` | 0.1.13 | `31e2768890a47af73a032af9f0cedbddce3c9d06cf8de201d5b8f2436ded7674` | no defaults; private bounded adapter; networking feature disabled |
| `hpke` | 0.14.0 | `dd5130e119706b4d8c2180da6126f7e60b6c38c2d340d539219f57051f0a7af7` | no defaults; `alloc,chacha,x25519,hkdfsha2` |
| `tls_codec` | 0.5.0 | `18cc98286004cea38f717e2b03d990fc774fbfd38a82720de40e5c94365067c8` | no defaults; `std,mls`; no production derive/Serde |
| `base64` | 0.23.1 | `ac07cdecf99051d9a5238b80f35af32cdeba5b336e55d957b318b50137e18da5` | no defaults; `alloc`; canonical unpadded URL-safe protocol adapter and the explicitly specified padded SASL/WebSocket encodings |
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

The workspace also uses a reviewed local source patch for redb 4.2.0: the
STO-1 bounded write transaction, applied from
`docs/upstream/redb-bounded-transaction/bounded-transaction.patch`, whose
digest and per-file before-and-after digests `source.json` records. It adds
`begin_write_bounded` and the typed allocation allowance that charges every
page extent and file extension before the allocation happens, the frozen
prepared transaction whose publication cannot allocate, resumable bounded
reclamation, and a bounded close. Ordinary transactions, their commit path,
the on-disk format and the crate version are unchanged. The fork is owned by
the project: it is not submitted upstream and no upstream acceptance is
assumed or awaited. The published crates.io checksum above remains the
upstream provenance value, `conformance/vendored-dependencies.toml` records
the complete patched-tree digest, and the workspace checker rejects any other
source override or tree content, exactly as for `opaque-ke`.

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

Since Stage 10 the status part of step 1 is automated for every source this
ledger names. `scripts/check-release-sources.py` reads the RFC Editor status
record of each RFC in Section 2, the Datatracker document and state records
of the draft in Section 3, and the default-branch head of each repository in
Section 4, then fetches each pinned commit to prove the remote still serves
it. `conformance/release-source-decisions.toml` holds one entry per source
with the observed status fields, the pin, the decision word, a note, and the
SHA-256 of this ledger at the time of the decision. Any change in those
fields, or an edit to this ledger, fails the release sources job until the
change is reviewed and a new decision is recorded there.

The 2026-09-05 check found two changes since 2026-08-24. RFC 9325 is now also
updated by RFC 10015, which Section 2 already reviews as not applicable. The
Tor specification default branch moved twelve commits past the pinned commit;
the changes are typo fixes in the rendezvous specification, a shared random
value tie-breaker for directory authorities, ntor handshake wording, and a
pluggable-transport variable, none of which touches the onion-service or
SOCKS behavior the architecture pins, so the pin in Section 4 is retained.

## 7. Stage 09 optional profiles and database upgrade

The 2026-09-04 Stage 09 decision retains the IRCv3 commit pinned in Section 4.
History adopts anchored LATEST and mixed, directed BETWEEN selectors from that
snapshot. It remains an explicitly enabled, current-member-only plaintext
channel service. The architecture defines bounded retention, deletion,
selection, authorization, and expiry rather than delegating those decisions
to an upstream draft.

WSS accepts either pinned subprotocol in client preference order. It ignores
extension offers while negotiating none, so browser compression offers do not
force compression or prevent connection. The private WebSocket accept adapter
uses already-locked `aws-lc-rs` 1.18.0, crates.io checksum
`ce2b2dcc879c3bae0d371e77c99f2238400ef24ec001394befa67b6e543add9e`,
with defaults disabled and exactly `non-fips`. Only this optional public
handshake adapter may use `SHA1_FOR_LEGACY_USE_ONLY`; it exposes no general
SHA-1 API and does not change account, storage, federation, or E2EE hashing.
The handshake's standard padded base64 is another narrow encoding exception.
The existing TLS provider remains unchanged.

Typed history pages preserve original sender and message metadata. Durable
result records retain replay identities and immutable row references without
additional message-body copies. A lost authorization or expired/purged row
causes the specified terminal history-expired result, never a rerun of LATEST
under the same request identity. These canonical changes require a new base
federation profile hash and coordinated peer upgrades. The E2EE companion
bytes and profile remain unchanged.

All optional-feature builds use the current database format. Turning history
off never bypasses authentication, deletion, or encrypted-binding exclusion.

Build-time exclusion removes optional service dependency edges. Runtime
disablement suppresses the service, listeners, capabilities, and new service
writes; it cannot remove dependencies already compiled into the binary.
Disabled-mode equivalence compares the same corrected source/profile and
logical storage effects rather than nonce-dependent ciphertext bytes. Existing
history databases retain their documented validation and cleanup behavior.
Historical conformance manifests continue to describe only their recorded
source commits. Stage 09 completion requires a new exact-source checkpoint.

## 8. Stage 10 client directory reply corrections

Production qualification found that Appendix A.2 omitted numeric 263 for
temporary command refusal, numeric 302 for the required USERHOST command,
and numerics 730 through 734 for the required MONITOR command. The registry
now includes these replies with their pinned
Modern IRC and IRCv3 meanings. USERHOST exposes only the visible session's
ephemeral public cloak. MONITOR status applies the same presence visibility
rules as ISON, while its list contains the requester's own subscriptions.
This corrects the client reply registry. The federation object schema,
federation profile hashes, and persistent record format are unchanged.

WHOWAS also lacked numeric 314 and any retention implementation. Its reply
uses only the fields Section 14.5 permits, with the public account label in
place of a realname. The retained cloak can authorize a historical nickname
only while it identifies a currently visible live session. A record whose
session has disconnected is hidden; the daemon retains no historical audience
or account identifier and grants no authority based on a public label.

## 9. Stage 10 ReInit target and onboarding corrections

The 2026-10-04 revision changes the E2EE companion and the architecture
specification together. No source pin, dependency, or decision of Sections 2
to 8 changes.

In the companion, Section 13.8 removes the old-group state ID from
`ArcReInitTargetTBS`. The field named the finalization ID of the very Commit
whose authorization commits the target digest, so no target could be built
and no conforming ReInit could complete. Every `ArcReInitAttempt` now carries
the exact target. The sequencer refuses an attempt with
`E2EE_FINALITY_REQUIRED` while the old conversation's accepted state is not
the finalization of a ReInit Commit; otherwise, before it signs an attempt
receipt, it checks the attempt and its target against the digest that
finalization authorized and refuses a mismatch with
`E2EE_BINDING_AUTH_INVALID`. At
activation the coordinator installs the successor from the carried target in
the transaction that stores the activation certificate, so a ReInit successor
needs no `EGROUP RESERVE` or `EGROUP BIND`. The revision also states how an
endpoint reconstructs the target, how a member that joins after activation
checks its ReInit entries against the carried target, the successor initial
Commit's authenticated data, the rosters that verify a successor policy, that
a ReInit never carries a root discontinuity, and that `CLAIM STATUS` names the
stored claim's target device. Profile version 1 keeps its number and the profile
hash moves from `c1b5313f8a7f196cda30eea797fb1ab65b004a55d71cf9a81071927046e5d395`
(token `wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U`) to the value that
`specification-manifest.txt` and architecture Section 30.3 record. Companion
Sections 2.3 and 22 record why the revision keeps the version although it
changes two object layouts: under the previous hash no target could be
constructed, so no conforming ReInit exists to keep interoperable, and
exact-match negotiation refuses every peer that presents that hash.

In the architecture, Section 9.3 and Appendix C.8 state that an edge
advertises, and its onboarding descriptor pins, its coordinator's recovery
epoch. Section 9.5 states that the welcome recovery-epoch `NOTE` does not
depend on `standard-replies`, and Appendix E.2 shows the account-state `900`
after that `NOTE`, in the order Section 10.2 already fixed. Section 19.1 and
Appendix C.6 raise the `preauth_command` default burst from 10 to 24, inside
the unchanged hard maximum of 50, so that an account client's creation
followed by registration, or its pre-registration login, completes within the
30-second registration limit at round trips of up to 3 seconds, as `tor-exit`
and `onion` connections can have. Section 24.1 adds the
`agenc-relay-client-support` and `agenc-relay-transport` crates, and
Section 28.8 runs `cargo fmt --check`.

Every node that has the encrypted profile enabled moves to this revision in
one coordinated upgrade. CAP and ECAP accept only an exact
`(version, profile-hash)` pair, so a client of the previous revision is not
offered the encrypted profile, and a federation link whose ends present
different profile hashes fails ECAP and closes (companion Section 12.5). An
edge whose coordinator link is closed behaves as architecture Section 20.10
states until both ends run this revision.

The `print-onboarding` descriptor of every node with the encrypted profile
enabled carries `e2ee-profile-sha256`, which an importer requires to equal its
own build constant, so after the upgrade the operator issues each such
descriptor again, and every account invitation that embeds one; a descriptor
without the four E2EE lines is unaffected. A client imports the new
descriptor through the explicit confirmation that architecture Sections 6.3
and 9.3 require for a changed pin. The recovery epochs, keys, and other pins
are unchanged.

The persistent format is unchanged: the database stays at storage generation
5 with the same records, keys, and tables. Stored objects keep their exact
wire bytes under their content IDs, so a ReInit attempt stored before this
revision, and a ReInit activation or abort record that embeds one, remains an
object of the previous hash, which companion Section 2.3 forbids
reinterpreting under this one; the implementation that adopts the new attempt
layout states how a node that holds one restores.

Against the four version axes of architecture Section 26.2, only the
encrypted client and federation axis moves, to the new profile hash at
version 1. The base federation profile and its registry are unchanged, and so
is the database format. The client base profile stays `agenc.ag/privacy=v1`:
the edge epoch rule names which node's epoch an edge advertises, which a
client only compares with its pin; the `NOTE` and `900` text clarifies the
Section 10.2 order and corrects an example of it; and a default inside an
unchanged hard maximum is not a mandatory limit. The crate graph and the
formatting command change no wire byte, persistent byte, or negotiated value.
