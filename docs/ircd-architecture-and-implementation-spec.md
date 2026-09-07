# Secure IRC Daemon Architecture and Implementation Specification

Version 1.0-draft.1, 2026-08-24

## 1. Status and purpose

This document is the implementation specification for the version-1 daemon.
It defines the client protocol profile, federation, state model, storage,
concurrency, Rust boundaries, privacy behavior, security invariants, and
release tests. An implementation is not conforming merely because it accepts
traditional IRC commands; it is conforming only when every requirement and
release gate in this document and the referenced E2EE profile is satisfied.

The companion [IRC-MLS E2EE specification](irc-mls-e2ee-extension.md) is
normative for encrypted conversations. This document owns the surrounding
daemon. The E2EE document owns cryptographic identity, MLS group state,
encrypted object formats, the published conversation policy, the E2EE
sequencer and its finality quorum check, the edge record-chain witness, and
its exact client and federation commands.

This is a design document, not permission to deploy an unaudited
implementation. The words "secure", "private", and "anonymous" in product
material MUST be limited to the properties actually established in Sections 5
and 6.

### 1.1 Conformance targets

Version 1 has three additive conformance targets:

1. **Core node**: one standalone server, public and secret channels, accounts,
   moderation, persistence, and the complete client profile.
2. **Federated node**: a core node plus the version-1 coordinator/edge
   federation protocol.
3. **Encrypted node**: a federated node plus the complete IRC-MLS profile.

A release advertised as the full daemon MUST satisfy all three. An optional
WebSocket listener does not define a fourth target; when enabled, it MUST have
the same protocol and security behavior as the TCP listener.

### 1.2 Requirements language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**,
**SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and
**OPTIONAL** are interpreted as described by BCP 14 when they appear in bold
or in uppercase.

`Reject` means no state change, no fanout, and an error response unless the
command is `NOTICE`. `Close` means send one bounded `ERROR` when safe, stop
accepting input, flush already-queued control output for at most one second,
and close the transport. A malformed message never causes a panic.

## 2. Normative document order

Conflicts are resolved in this order, highest first:

1. this document;
2. `docs/irc-mls-e2ee-extension.md` for an encrypted operation;
3. ratified IRCv3 specifications explicitly named here;
4. the Modern IRC Client Protocol snapshot fetched for the implementation;
5. RFC 2812 for client behavior not resolved above;
6. RFCs 1459, 2810, 2811, and 2813 as historical background only.

The implementation MUST vendor an immutable copy or content hash of every
living specification used to derive tests. A later website edit cannot change
released behavior silently. Internet-Drafts are not normative unless this
document identifies an exact revision and capability name.

The historical RFCs are not a federation design. Their plaintext passwords,
host disclosure, ambiguous character encodings, collision merge rules, and
spanning-tree server protocol are explicitly superseded.

### 2.1 Adopted client specifications

The daemon implements these ratified IRCv3 facilities:

- Capability Negotiation, including `CAP LS 302` and `cap-notify`;
- Message Tags and `TAGMSG`;
- `account-notify`, `account-tag`, and `extended-join`;
- `away-notify`, `batch`, `echo-message`, `invite-notify`,
  `labeled-response`, `message-ids`, `monitor`, `multi-prefix`, `server-time`,
  `setname`, `standard-replies`, `userhost-in-names`, and `utf8only`;
- SASL 3.2 transport, with the mechanisms narrowed by Section 11; and
- the IRCv3 WebSocket transport when that listener is enabled.

`STARTTLS` is not implemented. No plaintext listener exists, so STS is
advertised only as `sts=duration=31536000` on DNS-name TLS connections and is
informational defense for clients that already understand it. Onion-only
connection profiles use a pinned onion address and MUST NOT use STS as their
trust anchor.

The work-in-progress `draft/multiline`, `draft/chathistory`, metadata, account
registration, channel rename, read marker, typing, reaction, and redaction
specifications are not core version-1 behavior. Section 17 defines the one
optional history compatibility profile. Unsupported drafts are neither
advertised nor partially implemented.

## 3. Goals and non-goals

### 3.1 Required goals

The daemon MUST:

- preserve the familiar nickname, direct-message, `/join #channel`, topic,
  channel-mode, invite, ban, kick, presence, and query model;
- support discoverable public channels, unlisted channels, and secret
  channels without conflating discovery with encryption;
- provide pseudonymous accounts whose security identity is never a nickname,
  user mask, IP address, or mutable account label;
- offer direct TLS, Tor SOCKS client guidance, and a version-3 onion-service
  listener without silent fallback between them;
- minimize collection, exposure, retention, and correlation of metadata;
- provide MLS E2EE without allowing plaintext downgrade on a bound route;
- remain total and resource-bounded for every untrusted input;
- persist acknowledged security state before making it externally visible;
- behave deterministically across federation reconnects, retries, crashes,
  and partitions; and
- be implementable in safe, legible Rust with explicit ownership and bounded
  concurrency.

### 3.2 Non-goals and honest limits

Version 1 does not claim:

- anonymity against a global passive adversary performing end-to-end timing
  or volume correlation;
- content confidentiality for plaintext channels or direct messages;
- end-to-end integrity of ordinary base commands or replies after client TLS
  terminates at a federated edge;
- concealment of channel membership from the logical delivery coordinator;
- protection after an endpoint is compromised while plaintext or keys are
  available there;
- availability against an operator, coordinator, or Tor adversary able to
  deny service;
- deniability for MLS messages;
- post-quantum protection for MLS content; or
- detection of a coordinated rollback of both the live database and its
  separately stored rollback-guard file when no non-rolled-back peer, client,
  hardware counter, or external witness remains; or
- interoperability with RFC 2813, TS6, P10, or any existing server-link
  protocol.

Tor improves network-location privacy; it does not make application
identifiers, message timing, group membership, or voluntarily disclosed text
anonymous. MLS protects content and membership integrity; it does not hide all
delivery metadata. Clients and documentation MUST state both limitations.

## 4. Fixed version-1 decisions

The following are protocol decisions, not configuration suggestions:

| Concern | Version-1 decision |
| --- | --- |
| Client transports | TLS 1.3 over TCP; optional WSS; TLS 1.3 inside Tor onion streams |
| Plaintext/STARTTLS | Forbidden |
| Text encoding | Well-formed UTF-8 only |
| Global channel prefix | `#` |
| Local channel prefix | `&` |
| Unsupported prefixes | `+` and `!` |
| Global state authority | One logical network coordinator |
| Edge topology | Every edge has one authenticated coordinator link; no edge-to-edge transit |
| Storage engine | `redb` 4.2.0, one dedicated storage owner, immediate two-phase commits |
| Runtime | Tokio 1.x multi-thread runtime |
| Rust language | Rust 2024 edition, compiler 1.98.0 for the first implementation |
| Initial server targets | `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` |
| Unsafe Rust | Forbidden in workspace source |
| TLS library | rustls 0.23.x with the `aws-lc-rs` provider |
| TLS key exchange | Prefer RFC 10024 `X25519MLKEM768`; allow X25519 compatibility fallback |
| Account password protocol | RFC 9807 OPAQUE profile in Section 11; never SASL PLAIN |
| E2EE | RFC 9420 MLS through the companion profile |
| Server-side E2EE content | Opaque; never decrypted |
| At-rest protection | AEAD, an authenticated mutation ledger, and a separately keyed rollback guard outside the database |
| Reverse DNS and ident | Forbidden |
| Raw IP logging/storage | Forbidden |
| Remote network administration | Separate mTLS admin listener or local Unix socket only |

The compiler pin is recorded in `rust-toolchain.toml` and every package sets
`edition = "2024"` and `rust-version = "1.98"`. Updating it is a reviewed
maintenance change with a full verification run, not an automatic build-time
download. Dependency minor versions are pinned in `Cargo.lock`; protocol
semantics MUST NOT depend on an unpinned crate default.

Another operating system or target is nonconforming until it supplies and
passes equivalent peer-credential, no-follow file-open, advisory-lock, atomic-
rename, file/directory-`fsync`, locked-secret, and crash-fault evidence. A
successful cross-compile alone is not that evidence.

`aws-lc-rs` includes a vetted native cryptographic backend. "Written in Rust"
describes the daemon and workspace source, not a false claim that every
transitive cryptographic instruction is Rust. Replacing mature cryptography
to satisfy language purity is forbidden without a separate security review.

## 5. Threat and trust model

### 5.1 Adversaries

The design assumes any combination of:

- arbitrary Internet clients sending malformed, adversarial, replayed, or
  high-volume bytes;
- a network attacker who can observe, delay, reorder, duplicate, inject, or
  drop traffic but cannot break the negotiated cryptography;
- malicious users, guests, bots, channel operators, and federated edge
  operators;
- compromise, record substitution, or rollback of the persistent database
  without simultaneous access to the at-rest master or rollback-guard keys;
- a compromised delivery coordinator attempting equivocation, censorship,
  rollback, stale key delivery, or metadata analysis;
- a compromised E2EE Authentication Service or directory; and
- process crashes, power loss, disk-full conditions, clock changes, netsplits,
  replay after reconnect, and slow consumers.

Every public listener and every federation frame is untrusted. Configuration,
database contents, DNS, certificates, and peer snapshots can also be corrupt
or stale and are validated before use.

### 5.2 Trust boundaries

| Component | Trusted for | Not trusted for |
| --- | --- | --- |
| Client TLS endpoint | Link confidentiality and server authentication | E2EE identity or peer honesty |
| Edge server | Admission, parsed routing, local rate limits, and attribution/rendering of ordinary base-session commands | Private account-service login/invitation/credential-change plaintext, account success assertions, password recovery, E2EE plaintext, or valid client/root signatures |
| Network coordinator | Ordered base state and delivery | E2EE plaintext, honest availability, or undetectable MLS forks |
| E2EE sequencer | Companion-profile receipts and terminal certificates issued only at the published policy's finality quorum | Conversation content, unilateral membership, or finality that endpoints have not verified themselves |
| E2EE edge witness | Refusal and audit evidence for a sequencer record chain that forks or skips a position | Detection of a record the coordinator never delivers |
| Account service | Session authentication | Root identity ownership or silent E2EE device creation |
| Tor | Network-path separation under Tor's threat model | Application-layer unlinkability or global traffic-analysis resistance |
| Storage AEAD | Record confidentiality and authenticity under its exact table/key binding | Freshness, availability, access-pattern hiding, or a live-process compromise |
| Storage integrity ledger and rollback guard | Record-set integrity and database-only rollback detection while the guard/key remain current | A coordinated rollback of both database and guard, dishonest storage hardware, or a live-process compromise |
| Channel moderators | Channel policy and membership enforcement | Decrypting E2EE content they did not receive |

Authorization is always based on immutable typed IDs and current generations.
Display names, nicknames, cloaks, timestamps, server prefixes, and account tags
are never authorization inputs.

### 5.3 Compromise behavior

- A leaked TLS private key requires certificate replacement and client pin or
  WebPKI recovery. It does not reveal earlier TLS 1.3 sessions.
- A leaked federation key removes that server from the signed peer registry,
  increments its incarnation, and requires a full snapshot before readmission.
- A leaked storage key requires offline re-encryption from a trusted backup;
  the old database is treated as disclosed. If the independent rollback-guard
  key remains secret, forged state still cannot be activated as a current
  database. Compromise of either storage key does not justify reusing the
  other; both are rotated into a freshly bound database.
- A leaked rollback-guard key removes the local freshness boundary. The daemon
  is quiesced, peers and native clients compare their last observed recovery
  epoch and revisions, and recovery proceeds into a new database instance and
  recovery epoch with a new guard key. An old valid database/guard pair is not
  treated as evidence of freshness.
- A leaked login-index key lets an attacker who also obtains index keys from
  the database test guessed login identifiers offline; it does not expose an
  OPAQUE password verifier by itself. Section 23.9 begins a new generation,
  migrates entries only after successful OPAQUE proof, and never invents a
  reversible login escrow to make rotation look instantaneous. If dormant
  entries prevent safe completion, availability remains quiesced until an
  explicit account-recovery decision rather than silently orphaning users.
- A leaked account-service OPRF seed and credential database does not reveal
  plaintext passwords directly, but weak passwords remain at risk. Users are
  warned, affected authentication is disabled if active exploitation is
  possible, and any recovery uses a new named setup/mechanism with explicit
  client re-registration rather than silent key rotation.
- A leaked account-service HPKE recipient key can expose recorded request
  envelopes made to that key, including login identifiers and invitations. It
  requires immediate key replacement, explicit onboarding-pin confirmation,
  transaction/session reset, and disclosure of this retrospective metadata
  risk; HPKE is not claimed to erase recorded ciphertext.
- A disaster restore performed without the surviving current database/guard
  witness can reactivate an OPAQUE record that was current at the backup cut
  but later replaced. Prior native-client generation pins detect the rollback
  under Sections 11.4 and 23.7; a client with no prior pin cannot. Restored
  account access still cannot forge the separate E2EE root/device authority.
- A malicious terminating edge can drop, alter, or originate ordinary base
  operations for a session after authentication. It can cause account-service
  denial but cannot forge an exporter-authenticated creation, login, or
  credential-change completion. It still cannot learn the OPAQUE password or
  forge companion-required device/root signatures, MLS ciphertext, or
  verification state. The strongest profile connects through
  Tor directly to a coordinator-operated onion endpoint rather than a
  separately operated edge.
- An E2EE device or root compromise follows the revocation, roster, ReInit,
  and recovery rules in the companion specification.

## 6. Privacy and anonymity profiles

Privacy is a property of the path, identifiers, server policy, other group
members, and user behavior together. The server exposes three named profiles
so clients do not guess.

### 6.1 `direct`

The client connects to a DNS name over TLS. The accepting process necessarily
observes the source address while the socket exists. It MUST use that address
only for admission and abuse buckets, MUST NOT perform reverse DNS, MUST NOT
send it to peers or users, MUST NOT write it to disk or logs, and MUST erase
the in-memory bucket no later than ten minutes after the last connection using
it closes.

### 6.2 `tor-exit`

The client reaches the normal TLS listener through Tor SOCKS5. The server sees
a Tor exit address, not the client address, but cannot reliably distinguish
this profile from other direct connections. Native clients MUST send the DNS
hostname through SOCKS5 rather than resolving locally and MUST use a unique
Tor stream-isolation value per configured network/account context; different
accounts never share it. They MUST NOT fall back to direct DNS or TCP after a
Tor failure.

### 6.3 `onion`

The client connects to the configured 56-character version-3 onion address.
Tor forwards the virtual port to a Unix-domain socket owned by the daemon.
TLS 1.3 still runs inside the onion stream. The daemon MUST reject TCP on the
onion-only listener path and MUST NOT enable HAProxy PROXY headers there.

The canonical onboarding descriptor in Appendix C pins at least:

```text
network_id = base64url(32 bytes)
onion_address = 56 lowercase base32 characters + ".onion"
onion_virtual_port = 6697
tls_spki_sha256 = base64url(32 bytes)
recovery_epoch = base64url(16 random bytes)
base_federation_profile_hash = base64url(32 bytes)
e2ee_profile_hash = base64url(32 bytes)
account_service_hpke_key_id = base64url(32 bytes)
account_service_hpke_public_key = base64url(32 bytes)
sequencer_key_set_generation = uint64
sequencer_key_set_hash = base64url(32 bytes)
```

Changing any pin is an explicit network-identity transition. A native client
configured for `onion` MUST NOT try a clearnet endpoint automatically. A
browser WSS client requires a certificate it can validate for the onion name;
pin bypass UI is forbidden.

### 6.4 Metadata-minimized session policy

The `agenc.ag/privacy=v1` capability advertises these mandatory server-wide
behaviors and lets a native client pin or demand the profile; failure to
negotiate never authorizes the server to weaken them:

- WHO, WHOIS, NAMES, LIST, MONITOR, account notifications, and away
  notifications reveal only data permitted by Sections 14 and 16;
- user masks contain only session-derived pseudonyms;
- client IP, port, TLS fingerprint, user agent, WebSocket headers, and Tor
  path are absent from protocol-visible state;
- read markers, typing notifications, link previews, automatic unfurls,
  presence polling, and client-version probes are not implemented by the
  server;
- plaintext history is off unless a public channel explicitly enables it;
- E2EE history contains ciphertext only as allowed by the companion profile;
- logs use per-process correlation IDs and contain no message text, nick,
  channel name, login identifier, Account ID, Device ID, or source address;
- aggregate metrics have no labels derived from a user, account, channel,
  message, address, onion name, or federation request ID.

The capability does not hide membership from the delivery coordinator and
does not add cover traffic. A future mixnet or cover-traffic profile requires
a separate, analyzed protocol; fake padding with no stated traffic model is
not presented as anonymity.

## 7. Typed identifiers and canonical names

All random identifiers use the operating system CSPRNG and are generated only
after successful entropy initialization. Fixed byte strings use unpadded
base64url on text wires and retain their full byte length in storage. Parsers
decode and re-encode them and reject alternate encodings.

| Type | Bytes | Text form | Lifetime |
| --- | ---: | --- | --- |
| `NetworkId` | 32 | 43 base64url chars | permanent network identity |
| `ServerId` | 16 | 22 base64url chars | permanent server identity |
| `ServerIncarnation` | 16 | 22 base64url chars | until durable request state is lost |
| `RecoveryEpoch` | 16 | 22 base64url chars | one explicitly continuous server-state lineage |
| `SessionId` | 16 | 22 base64url chars | one accepted client connection |
| `UserId` | 16 | 22 base64url chars | one registered client connection |
| `AccountRandomId` | 16 | `a_` plus 22 base64url chars | permanent, never reused |
| `OpaqueCredentialId` | 32 | no public text form | one account; private account-service state |
| `ChannelInstanceId` | 16 | 22 base64url chars | one creation of a channel |
| `MessageId` | 16 | 22 base64url chars | permanent within the network |
| `RequestId` | 16 | 22 base64url chars | one logical idempotent request |
| `EventSequence` | 8 | canonical unsigned decimal | one coordinator incarnation |

No identifier contains a timestamp, MAC address, host ID, process ID, shard
number, account name, or IP-derived bits. Random identifiers are not sorted as
time values.

### 7.1 Account identity

The E2EE `Account ID` is exactly the UTF-8 bytes of the textual
`AccountRandomId`. It is immutable and never reassigned. The chosen login
identifier and mutable public account label are separate fields. The
`account-tag` capability carries the public label or `*`; it never carries
authority by itself.

Account deletion follows the explicit two-step control in Section 14.6. It
creates a permanent tombstone for the random ID and a 30-day keyed-hash
reservation for the login identifier. The same login string may be registered
after that interval, but receives a different Account ID. The server never
publicly links the successor to the tombstone; clients warn whenever a locally
named or pinned contact presents a different Account ID or E2EE root identity.

### 7.2 Nicknames

A nickname is a mutable routing name, not an identity. Version 1 deliberately
uses the portable ASCII grammar below so existing clients agree on comparison
and targeting behavior:

```text
nickname = (ALPHA / "_") 0*31(ALPHA / DIGIT / "_" / "-")
```

Uniqueness maps `A` through `Z` to lowercase and otherwise compares exact
bytes. The server advertises `CASEMAPPING=ascii` and `NICKLEN=32`. A Unicode
display name belongs in `SETNAME`; it is prepared with the RFC 8266 Nickname
profile, limited to 64 UTF-8 bytes, and never used for routing or
authorization. Changing either field does not change `UserId` or
`AccountRandomId`.

### 7.3 Channel names

Version 1 intentionally uses a small portable profile:

```text
global-channel = "#" channel-body
local-channel  = "&" channel-body
channel-body   = 1*63(ALPHA / DIGIT / "." / "_" / "-" / "+")
```

`A` through `Z` are mapped to lowercase for canonical comparison; all other
bytes are preserved. The wire display form is the first successfully created
spelling. `#` channels are coordinator-owned and federated. `&` channels are
owned by one edge, never federated, and cannot be E2EE-bound in version 1.
Names beginning with `+` or `!`, invalid UTF-8, or characters outside this
grammar receive `ERR_BADCHANMASK`.

Destroying an ephemeral channel and recreating the same name allocates a new
`ChannelInstanceId`. A registered channel preserves its instance ID through
zero-member periods. Names and instance IDs are never treated as equivalent.

### 7.4 User masks and server names

The visible source form is:

```text
<nickname>!u-<10 base32 chars>@h-<16 base32 chars>.invalid
```

The coordinator generates the user and host components independently from the
operating-system CSPRNG when it accepts `session_open`, using 50 and 80 random
bits respectively, and rejects a collision with any live cloak before
commit. The resulting `PublicCloak` is stored only in live session state,
changes on every connection, and has no derivation from a source address,
account, device, or stable secret. Federation projects the authenticated
`UserId` and this public cloak; it never transmits a source address. A cloak
is therefore consistently renderable at every edge but is neither reversible
nor stable across reconnects.

Server names are configured lowercase ASCII DNS names with at least one dot,
maximum 253 bytes, and exact-match comparison. An onion address is an endpoint,
not a server name. Protocol authorization uses `ServerId`, not the name.

## 8. Transport security

### 8.1 TLS configuration

All client, WebSocket, federation, and remote-admin connections use TLS 1.3
as specified by RFC 9846 only. RFC 8446 is an obsolete research input, not the
version-1 TLS authority. This also satisfies RFC 9852's BCP-195 requirement
that a new TLS-based protocol require TLS 1.3. The server MUST disable TLS 1.2
and earlier, renegotiation, 0-RTT,
application compression, TLS-level application protocol fallback, and
post-handshake client authentication.

Allowed TLS 1.3 cipher suites are:

1. `TLS_CHACHA20_POLY1305_SHA256`;
2. `TLS_AES_256_GCM_SHA384`; and
3. `TLS_AES_128_GCM_SHA256`.

The provider **MAY** reorder AES and ChaCha20 based on hardware capability, but
MUST NOT add a CBC, CCM-8, static RSA, or non-forward-secret suite. The first
key-exchange group offered is RFC 10024 `X25519MLKEM768`; `X25519` is the only
compatibility fallback in the default profile. Native clients in strict mode
require `X25519MLKEM768` and fail closed if it is not negotiated. This is a
transport post-quantum hedge only; it does not change the companion document's
no-post-quantum-MLS claim.

Client endpoints use ALPN `agenc-chat/1`. Federation uses
`agenc-chat-fed/1`. The admin listener uses `agenc-chat-admin/1`. A connection
with a missing or incorrect ALPN is closed before application bytes are read,
except WSS, which negotiates HTTP/1.1 and then the required WebSocket
subprotocol.

### 8.2 Certificate validation

DNS-name clients construct their reference identifier from configuration,
not from certificate fields or redirects. They verify `subjectAltName` as
specified by RFC 9525; Common Name fallback is forbidden. Name mismatch,
expiry, unknown issuer, revoked pin, weak signature, or incomplete chain is a
hard failure with no click-through path.

Onion-native clients validate the exact onboarding SPKI pin and onion address.
Federation and remote-admin listeners require mutual TLS against separate
private trust stores. Federation additionally validates Section-20 peer
identity; remote administration validates the Section-22.4 session challenge.
Public WebPKI roots are never federation or admin trust anchors.

Certificate and federation signing keys are distinct. TLS ticket-encryption
keys rotate every 6 hours, tickets expire after 24 hours, and ticket keys are
not persisted across process restart. Session resumption never bypasses
application authentication.

### 8.3 Time and resource bounds

| Phase | Hard limit |
| --- | ---: |
| TCP accepted to TLS complete | 10 seconds |
| TLS complete to registration complete | 30 seconds |
| Idle before server `PING` | 120 seconds |
| `PING` to matching `PONG` | 30 seconds |
| Graceful write stall | 30 seconds |
| TLS close-notify grace | 1 second |
| TLS handshakes in progress | configurable, default 1,024, hard max 16,384 |

Handshake concurrency uses a global semaphore before expensive cryptography.
Exhaustion pauses accepts; it does not create unbounded tasks or queues.

### 8.4 WebSocket listener

When enabled, the endpoint is exactly `/irc`, requires WSS, HTTP method `GET`,
WebSocket version 13, and a configured exact Origin allowlist. Missing Origin
is accepted only from a separately configured non-browser listener. Cookies,
HTTP authentication, redirects, per-message compression, and unnegotiated
extensions are forbidden.

The request is exactly HTTP/1.1 and carries one valid `Host`, version 13,
and a canonical standard-base64 WebSocket key decoding to 16 bytes. The
server selects the first supported subprotocol in the client's offered order.
Extension offers are parsed but none are negotiated: the response omits
`Sec-WebSocket-Extensions`, and subsequent nonzero RSV bits are rejected.
This permits ordinary browser extension offers without enabling compression.
Present Origin values match the validated allowlist byte-for-byte, without
normalization. Missing Origin requires `allow_missing_origin=true` on an
explicitly configured non-browser listener.

The server supports `text.ircv3.net` and `binary.ircv3.net`, requires one of
them, and follows the IRCv3 WebSocket specification: one WebSocket message is
one protocol line without CR or LF. Because the network is UTF-8-only, binary
messages are still validated as UTF-8. Fragment reassembly is bounded by the
8,701-byte WebSocket-message ceiling in Section 9.1. The HTTP request line is
at most 2,048 bytes, there are at most 64 header fields, each field line is at
most 4,096 bytes, all headers together are at most 16,384 bytes, and the
upgrade must complete within five seconds. A body, second request, obsolete
folded header, duplicate singleton header, or transfer coding is rejected.
Client masking, control frames, and close behavior follow RFC 6455; invalid
masking or framing closes with WebSocket code 1002.

The request-line and field-line limits exclude their terminating CRLF. The
aggregate header limit includes each field's CRLF but excludes the final
empty line. A fixed 18,436-byte upgrade buffer therefore covers all permitted
request bytes and delimiters. `Content-Length: 0` declares no body; any
nonzero content length, buffered trailing bytes, or transfer coding is refused.
HTTP failures have fixed bodyless responses and close the connection: 400 for
malformed or forbidden requests, 403 for Origin refusal, 404 for the wrong
endpoint, 405 for the wrong method, 426 for the wrong version, 431 for header
limits, 414 for the request-line limit, and 408 for the upgrade deadline.
Rejected values are never reflected.

The upgrade deadline begins at TLS completion. Registration still expires
30 seconds after that same instant, including upgrade and queue admission.
The active Origin policy is checked immediately before deciding to send 101;
a reload completed before that decision applies to the pending upgrade.
Established WebSocket connections retain their admission decision.
WebSocket Ping/Pong does not satisfy the IRC keepalive exchange. The existing
bounded writer and shutdown protocol applies to both transports. Every
additional reassembly, output, and control allocation is charged to the global
budget, including temporary overlapping message buffers.

### 8.5 Tor deployment

The daemon does not embed or reimplement Tor. The operator configures a
version-3 onion service and maps virtual port 6697 to the daemon's Unix socket:

```text
HiddenServiceDir /var/lib/tor/agenc-chat/
HiddenServicePort 6697 unix:/run/agenc-ircd/onion.sock
```

The key directory MUST be owned by the Tor service account and inaccessible
to the daemon. The socket directory is shared through a dedicated group with
mode 0750; the socket is mode 0660. The public TLS listener and onion Unix
listener are separate configuration objects, making accidental clearnet bind
impossible for an onion-only deployment.

Native clients use SOCKS5 hostname requests, not locally resolved IP
addresses. They use a fresh random Tor isolation string for each configured
network/account context and retain it for reconnects within that context;
different accounts never share it. Operators and test clients use Tor's
`SafeSocks 1`/`TestSocks 1` checks in the integration suite.

## 9. Client wire format

### 9.1 Stream framing

TCP and onion transports are streams of CRLF-terminated messages. A bare LF,
bare CR, embedded NUL, or invalid UTF-8 is a protocol error. The parser scans
for CRLF without growing past the active limit and does not allocate from a
declared length.

The traditional IRC interoperability envelope is 512 bytes including CRLF,
but version 1 uses one bounded extended envelope so the fixed 1,024-byte topic
and 512-byte message limits remain representable with their required prefixes
and targets. Every complete stream message, tagged or untagged, is at most
8,703 bytes including CRLF. Implementations should keep ordinary messages
within 512 bytes when their complete semantic value fits; they never truncate
or split a value merely to meet that compatibility target.

For message tags, the limits from the ratified IRCv3 Message Tags
specification still apply independently:

- client-provided tag data: at most 4,094 bytes;
- server-added tag data: at most 4,094 bytes;
- combined tag section including `@` and its trailing SPACE: at most 8,191
  bytes; and
- complete physical message including CRLF: at most 8,703 bytes.

The command portion is at most 8,701 bytes without CRLF. The tag section and
command portion share the 8,701-byte stream-content budget, so a maximum tag
section leaves only 510 command bytes. A client line above its tag-side,
combined-tag, command, or physical budget is rejected and the connection is
closed; the server never truncates it. WebSocket messages omit CRLF and have
the same 8,701-byte complete-message and command ceilings.

The parser accepts at most 15 parameters. Prefixes from clients are forbidden.
Commands are non-empty ASCII letters, compared case-insensitively, and
canonicalized to uppercase before dispatch. A middle parameter is non-empty,
contains no SPACE or colon as its first byte, and contains no NUL/CR/LF. A
trailing parameter begins after `:` and may be empty. Empty lines are ignored
but consume flood budget.

### 9.2 Tag handling

Tag keys, escaping, client-only `+` tags, and `TAGMSG` follow the ratified
Message Tags specification. The parser preserves raw tag bytes until syntax
validation, unescapes once into a separate bounded buffer, and rejects a
duplicate key. The generic IRCv3 last-value behavior is intentionally narrowed
to reject duplicates because security-sensitive extension tags must not have
ambiguous provenance.

Before relaying a client message, the server removes every unprefixed
client-supplied tag unless a named negotiated extension explicitly defines and
validates it. Client-only tags are untrusted and are relayed only on
`PRIVMSG`, `NOTICE`, and `TAGMSG`, subject to these limits:

- at most 16 client-only tags;
- at most 256 decoded bytes per value except the companion E2EE tag;
- at most 1,024 decoded client-only bytes in total except E2EE framing; and
- no tag may influence authorization, moderation identity, ordering, or
  persistence unless a normative extension says so.

`label` is at most 64 bytes. `batch` references are at most 64 bytes and must
name one live batch on the same connection. `msgid`, `time`, `account`, and
all other server-originated trust-bearing tags are generated after the
authoritative operation commits.

### 9.3 Advertised capabilities

Every full node implements and advertises:

```text
account-notify account-tag away-notify batch cap-notify echo-message
extended-join invite-notify labeled-response message-ids message-tags
monitor multi-prefix sasl=AGENC-OPAQUE server-time setname standard-replies
userhost-in-names utf8only agenc.ag/privacy=v1 agenc.ag/account-controls=v1
agenc.ag/account-credentials=v1 agenc.ag/channel-controls=v1
agenc.ag/recovery=v1.<22-char-recovery-epoch>
```

The value of `agenc.ag/recovery` is literal `v1.`, followed by canonical
unpadded base64url for the live header's 16-byte recovery epoch. A native
client compares it with its onboarding pin during `CAP LS`, before sending
`PASS`, `ACCTCREATE`, `ACCTCRED`, or `AUTHENTICATE`. A mismatch blocks account/E2EE use and
requires explicit descriptor confirmation; it is never accepted as an
ordinary capability-value update. Conventional clients may ignore this vendor
capability and retain the base chat profile.

It advertises `agenc.ag/e2ee-mls` only under the dependency and profile rules
of the companion document. It advertises `sts=duration=31536000` only under
Section 8. It advertises `draft/chathistory` only when the optional history
profile in Section 17 is enabled. It advertises
`agenc.ag/account-create=v1` only when account creation is enabled for that
listener; an invite requirement does not suppress the capability.

Capability names are opaque and requests are atomic: every entry in one
`CAP REQ` succeeds or the whole request receives `NAK`. `CAP LS 302` may span
messages using the continuation marker. CAP negotiation suspends registration
until `CAP END`. A capability that becomes unavailable is announced with
`CAP DEL`; E2EE downgrade handling remains fail-closed.

### 9.4 `RPL_ISUPPORT`

After registration, numeric 005 advertises at least:

```text
AWAYLEN=256 CASEMAPPING=ascii CHANNELLEN=64 CHANTYPES=#&
CHANMODES=beI,,kl,imnpst EXCEPTS=e INVEX=I KICKLEN=256 MAXLIST=b:100,e:100,I:100
MODES=6 MONITOR=100 NETWORK=<display-name> NICKLEN=32
PREFIX=(qaohv)~&@%+ SAFELIST STATUSMSG=@+ TARGMAX=PRIVMSG:4,NOTICE:4,TAGMSG:1,JOIN:20,PART:20
TOPICLEN=1024 UTF8ONLY EXTBAN=$,auncq LISTBUCKETS=1,2,5,10,25,50,100
```

`<display-name>` is configured ASCII without spaces. The vendor token
`AGENCNET=<43-character-NetworkId>` is also mandatory. No token may advertise
a limit larger than the parser, state owner, persistence schema, or federation
link actually enforces.
The empty second `CHANMODES` group is intentional: both `k` and `l` take a
parameter only when set, so `-k` and `-l` have no argument and never require a
client to repeat a secret.

### 9.5 Errors

If `standard-replies` is negotiated, new behavior uses:

```text
FAIL <command> <code> [context ...] :<description>
WARN <command> <code> [context ...] :<description>
NOTE <command> <code> [context ...] :<description>
```

Codes are uppercase ASCII `[A-Z0-9_]{1,64}`. Descriptions are bounded human
text, never parsed by clients, and never reflect a password, channel key,
unescaped input, certificate, source address, or database error. Traditional
commands still emit the expected numerics for legacy clients. A request with
a negotiated `label` receives that label on exactly one logical response,
using a batch when the response has multiple messages.

The public renderer recognizes only the following standard-reply shapes. A
bracketed context is optional; every other listed context is required:

| Kind and operation | Code | Public context |
| --- | --- | --- |
| `FAIL *` | `REGISTRATION_REQUIRED` | none |
| `FAIL ACCTCREATE`, `FAIL ACCTCRED` | `UNAVAILABLE` | none |
| `FAIL ACCT`, `FAIL ACCTCREATE`, `FAIL ACCTCRED`, `FAIL AUTHENTICATE` | `BAD_STATE` | none |
| `FAIL JOIN` | `E2EE_REQUIRED`, `NETWORK_UNAVAILABLE` | optional channel |
| `FAIL PRIVMSG` | `E2EE_REQUIRED` | channel |
| `FAIL JOIN`, `FAIL MODE`, `FAIL NAMES`, `FAIL TOPIC` | `SECRET_UNAVAILABLE` | supplied channel |
| `FAIL CHATHISTORY`, `FAIL JOIN`, `FAIL LIST`, `FAIL MONITOR`, `FAIL NAMES`, `FAIL WHO`, `FAIL WHOIS`, `FAIL WHOWAS` | `QUERY_EXPIRED` | none |
| `FAIL PRIVMSG` | `UNSAFE_CTCP` | none |
| `FAIL <public-client-command>` | `INVALID_ARGUMENT`, `NETWORK_UNAVAILABLE`, `SERVER_BUSY` | none |
| `NOTE ACCTCREATE` | `CREATED` | Account ID |
| `NOTE ACCTCRED` | `CHANGED` | none |
| `NOTE ACCT` | `DELETE_CHALLENGE` | 22-character token |
| `NOTE ACCT` | `UPDATED` | none |
| `NOTE CHANCTL` | `UPDATED` | channel |
| `NOTE *` | `RECOVERY_EPOCH` | 22-character epoch |

`CHALLENGE`, `CHECKPOINT`, `CONFIRM`, `EVENT`, and `VALUE` remain admin-only;
`SLOW_CONSUMER` remains queue-owner-only. The remaining registered codes are
typed base-federation result values or future-stage internal mappings and have
no direct public-renderer shape in version 1. Registry membership never
authorizes a renderer to guess a command or context.

## 10. Connection and registration state machine

Each client connection occupies exactly one state:

```text
ACCEPTED -> TLS_HANDSHAKE -> NEGOTIATING -> REGISTERED -> CLOSING -> CLOSED
                               |              |
                               +-> AUTHENTICATING
```

Transitions are monotonic. Authentication is a substate of `NEGOTIATING` or
`REGISTERED`; a failed reauthentication does not silently replace the current
account.

### 10.1 Pre-registration behavior

In `NEGOTIATING`, the accepted commands are `CAP`, `AUTHENTICATE`, `PASS`,
`NICK`, `USER`, `PING`, `PONG`, `QUIT`, and `ACCTCREATE`. Every other command
receives `ERR_NOTREGISTERED`. At most 16 parsed messages or 32 KiB, whichever
comes first, may be waiting for the state owner. Exceeding the limit closes the
connection.

`PASS` is only a deployment connection-admission token. It is accepted once
before `USER`. When configured, its parameter is canonical unpadded base64url
for exactly 32 random bytes and is compared in constant time with the 32-byte
configured token. It is cleared from memory immediately, never logged, never
used as an account password or account-creation invite, and never sent across
federation. If no access token is configured, a 1..256-byte `PASS` is accepted
and ignored for compatibility. A second `PASS` receives
`ERR_ALREADYREGISTRED`.

`USER <user> <mode> <unused> :<realname>` records no host-supplied username.
The first parameter is syntax-checked and then discarded; the server-generated
cloak from Section 7 is used. `<mode>` and `<unused>` are ignored. `realname`
is validated UTF-8, stripped of control characters, and limited to 64 bytes;
an empty value is valid.

Registration completes when a valid, globally reserved `NICK`, one valid
`USER`, and `CAP END` have been received. If the client never starts CAP,
CAP is considered ended. The coordinator atomically allocates `UserId`,
nickname, account binding if present, and initial session revision before the
welcome burst is sent.

### 10.2 Welcome burst

The successful burst is ordered:

1. `RPL_WELCOME` (001), `RPL_YOURHOST` (002), `RPL_CREATED` (003), and
   `RPL_MYINFO` (004);
2. one or more `RPL_ISUPPORT` (005);
3. `RPL_LUSER*` counters with privacy-safe aggregate values;
4. MOTD numerics or `ERR_NOMOTD`;
5. when `agenc.ag/recovery` is negotiated,
   `NOTE * RECOVERY_EPOCH <22-char-epoch> :Current server recovery identity`;
6. the authenticated account numeric/tag state, when present; and
7. any negotiated registration-time batches.

No raw host, address, client certificate subject, federation edge, or login
identifier appears. `RPL_CREATED` is the software build timestamp, not process
start time, avoiding an unnecessary uptime signal. `TIME` remains available
as coarse seconds.

### 10.3 Keepalive and closure

The server sends `PING :<22-character-random-token>` after 120 seconds with no
complete incoming message. Only an exact `PONG` token satisfies it. Client
`PING` receives `PONG` without touching protocol state. Payload reflection is
limited to 64 bytes.

`QUIT` is idempotent. The optional reason is limited to 256 bytes; on an E2EE
route it is replaced as required by the companion document. Transport loss
uses the fixed public reason `connection closed`. A session is removed from
all channels in one authoritative transition; fanout occurs only after that
transition is committed where persistence is required.

## 11. Accounts, authentication, and onboarding

### 11.1 Separation of identities

Four values are deliberately distinct:

- login identifier: private input used to find an OPAQUE record;
- `AccountRandomId`: immutable security identity;
- account label: mutable, optional public label exposed through IRCv3 account
  tracking; and
- nickname: mutable per-session routing name.

The normalized login identifier and account label MUST NOT be equal by
default, and the server never exposes the login identifier. For login-index
key generation `g`, database lookups use the exact 36-byte stored key:

```text
uint32(g) || HMAC-SHA-256(
    key = login_index_key[g],
    data = "agenc-chat login index v1" || network_id || normalized_login)
```

The generation is unsigned network order. Login-index keys live outside the
database, are unique to one Network ID, and are never derived from a storage,
OPAQUE, HPKE, federation, or rollback-guard key. The database stores no
reversible encryption of the normalized login. Section 23.9 therefore rotates
this key through an explicit current/previous generation and migrates an
index entry only after a successful OPAQUE login supplies the identifier
again; it does not pretend that a one-shot offline rebuild is possible.

Login identifiers are 3 through 64 UTF-8 bytes after the RFC 8265
UsernameCaseMapped profile. An account label is absent or 1 through 32 ASCII
bytes matching `[A-Za-z0-9][A-Za-z0-9._-]{0,31}`; it is compared and exposed
with exact case, need not be unique, and carries no authority. Unicode human
names use `SETNAME`, not the account tag. Passwords are opaque client bytes:
native clients require valid UTF-8, 12 through 1,024 bytes, preserve exact
bytes, and never trim, case-map, or normalize them silently.

### 11.2 OPAQUE profile

The mechanism name is `AGENC-OPAQUE`; it is an application profile of RFC
9807 intended for registration with IANA before public standardization. The
fixed suite is:

```text
OPRF: ristretto255-SHA512
KDF: HKDF-SHA-512
MAC: HMAC-SHA-512
Hash: SHA-512
KSF: Argon2id v=0x13, m=65536 KiB, t=3, p=4, output=64 bytes, salt=16 zero bytes
AKE group: ristretto255
Context: "agenc-chat account authentication v1" || network_id
credential_identifier: opaque_credential_id[32]
client_identity: opaque_credential_id[32]
server_identity: network_id
```

The KSF parameters are RFC 9106's second recommended, memory-constrained
Argon2id option with a 64-byte tag as required by this SHA-512 suite. They are
protocol parameters and cannot be tuned per account. A future change requires
a new named mechanism and re-registration, never silent parameter drift.
For this suite `Noe=32`, `Nn=32`, `Npk=32`, `Nh=64`, and `Nm=64`. The only
accepted RFC-9807 serializations and their exact byte lengths are:

| Value carried by this profile | RFC 9807 value | Bytes |
| --- | --- | ---: |
| account-create start message | `RegistrationRequest` | 32 |
| account-create challenge message | `RegistrationResponse` | 64 |
| account-create finish message and stored password file | `RegistrationRecord` | 192 |
| authentication start message | `KE1` | 96 |
| authentication challenge message | `KE2` | 320 |
| authentication finish message | `KE3` | 64 |
| credential-change start message | `RegistrationRequest` | 32 |
| credential-change challenge message | `RegistrationResponse` | 64 |
| credential-change finish message and replacement password file | `RegistrationRecord` | 192 |

The implementation uses the library's canonical `serialize`/`deserialize`
methods and requires those methods to consume exactly the stated length. The
library name `RegistrationUpload` denotes the 192-byte RFC
`RegistrationRecord`; it is not a different wire object. A variable-size,
Serde-derived, platform-layout, or trailing-byte representation is invalid.
The context is the exact ASCII bytes shown above immediately followed by the
32 Network-ID bytes, with no NUL or length prefix. Both identities and the
credential identifier are the exact 32-byte values shown above.
`opaque_credential_id` is sampled uniformly at account-creation start, is
stored only inside encrypted coordinator records that require it (the
creation/authentication/credential-change transaction, account/OPAQUE records, and login-index
value), and is returned only inside the HPKE-exporter-encrypted account-service
challenge. It is neither an Account ID nor a login-derived public value, never
reaches an edge in plaintext, and does not change when the login-index key
rotates. The client uses the challenge value for that OPAQUE run and need not
persist it.

For an unknown login, the coordinator supplies an indistinguishable stable
fake credential ID:

```text
fake_opaque_credential_id = HMAC-SHA-256(
    key = opaque_fake_credential_key,
    data = "agenc-chat fake opaque credential id v1" || network_id ||
           normalized_login)
```

The fake key is an independent 32-byte coordinator secret generated with the
OPAQUE setup and never held by an edge. Stability prevents repeated encrypted
challenges from becoming a real-versus-fake oracle; domain/key separation
prevents it from serving as the login-index digest. Real and fake identifiers
are processed at the same exact length and are never logged or projected.

The first implementation uses
`opaque-ke` 4.0.1 with its RFC-9807-compatible
`TripleDh<Ristretto255, SHA-512>` path and a project-owned `Ksf` adapter that
fixes the Argon2id parameters above; the crate's example identity KSF and
unspecified default Argon2 parameters are forbidden. Implementations validate
every group element and exact length, erase intermediate secrets, compare
authenticators in constant time, and pass all RFC 9807 vectors for the selected
primitives plus project vectors for this profile. A library substitution
requires wire-vector equality and focused cryptographic review.

The logical account service resides at the coordinator. Edges proxy bounded
HPKE-sealed OPAQUE messages but never receive the OPRF seed, account-service or
OPAQUE server private key, login plaintext, invitation plaintext, password,
export key, or recovered client private key.

One connection owns at most one account-service transfer and one live
account-service transaction total across `ACCTCREATE`, `AUTHENTICATE`, and
`ACCTCRED`. Starting or interleaving another class returns `BAD_STATE` and does
not disturb the first; transport close terminally consumes or expires its
transaction under that class's rule. This single owner also holds the one HPKE
context, padded buffer, OPAQUE client/server state handle, and response permit,
so two parsers can never race one secret state machine.

#### 11.2.1 End-to-end account-service envelope

An edge also MUST NOT learn the private login identifier, an account-creation
invitation, or a credential-change record merely because it terminates client
TLS. Every account-creation, OPAQUE-authentication, and credential-change
application message is therefore sealed by the client to the pinned
account-service HPKE public key before IRC/SASL framing. An edge validates only
the outer canonical envelope and size, forwards the exact bytes, and cannot
decrypt or rewrite the inner request.

Version 1 uses RFC 9180 Base mode with this fixed suite:

```text
KEM:  DHKEM(X25519, HKDF-SHA256)    // 0x0020
KDF:  HKDF-SHA256                   // 0x0001
AEAD: ChaCha20Poly1305              // 0x0003
```

The independently generated X25519 recipient key is not a TLS, federation,
OPAQUE, E2EE, storage, backup, audit, invitation, or admin key. Its public-key
ID is:

```text
account_service_key_id = SHA256(
    "agenc-chat account service hpke key v1" || hpke_public_key)
```

The exact public key and ID are pins in the Appendix-C onboarding descriptor.
Native clients retain both with the Network ID and require an explicit
network-identity update before accepting a different pair. A key supplied only
over the current edge connection is not trusted. The coordinator holds the
private key; edges hold only the pinned public value needed for configuration
agreement and onboarding output.

The canonical request envelope is:

```text
enum {
    account_create_start(1), account_create_finish(2),
    opaque_auth_start(3), opaque_auth_finish(4),
    credential_change_start(5), credential_change_finish(6)
} AccountServiceMessageKind;

struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque recipient_key_id[32];
    opaque client_request_id[16];           // fresh random bytes
    AccountServiceMessageKind message_kind;
} AccountServiceRequestHeader;

struct {
    AccountServiceRequestHeader header;
    opaque enc[32];                         // serialized X25519 KEM output
    opaque ciphertext<4608..4608>;          // one HPKE sequence-zero seal
} AccountServiceEnvelope;
```

Every envelope is exactly 4,726 encoded bytes and 6,302 unpadded-base64url
characters. Every response below is exactly 4,342 encoded bytes and 5,790
unpadded-base64url characters. `ACCTCREATE` and `ACCTCRED` use exactly those
unpadded-base64url forms. SASL instead uses canonical padded RFC-4648 Base64,
producing the exact 6,304- and 5,792-character forms in Section 11.4. All three
transports use at most 400 characters per chunk so every command portion
remains within the traditional 512-byte limit; no implementation may place a
complete object in one oversized parameter. No layer may raise an inner bound
or chunk count beyond this proof without a new profile.

For each logical request the client creates a fresh HPKE sender context and
fresh Client Request ID. It calls `SetupBaseS` with the pinned recipient key
and:

```text
info = "agenc-chat account service hpke request v1" ||
       TLS-encode(recovery_epoch, profile_version, network_id, recipient_key_id,
                  client_request_id, message_kind)
aad  = "agenc-chat account service request aad v1" ||
       TLS-encode(AccountServiceRequestHeader, enc)
```

It calls `Seal(aad, plaintext)` exactly once at HPKE sequence zero. Every
successfully opened request that reaches a protocol outcome has exactly one
fixed-size
`AccountServiceResponse`: a start request receives a challenge and a finish
request receives a completion receipt. Both endpoints retain the HPKE context
only long enough to export the one response key/nonce below and erase it after
that response is processed. A request rejected before successful `Open`
cannot have an exporter-authenticated response and receives only the bounded
outer `UNAVAILABLE` failure. The coordinator checks
profile, Network ID, current recipient key ID, exact 32-byte `enc`, envelope
bounds, and outer command/message-kind agreement before `SetupBaseR` and
`Open`. Any failure returns the same bounded `UNAVAILABLE` class and performs
no semantic lookup. A decrypted plaintext is parsed only after HPKE
authentication; it must consume the fixed padded wrapper and then its exact
selected arm with no trailing bytes:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque normalized_login<3..64>;
    opaque registration_request<32..32>;
    opaque creation_invite<0..132>;
} AccountCreateStart;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque transaction_id[16];
    opaque registration_record<192..192>;
} AccountCreateFinish;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque normalized_login<3..64>;
    opaque ke1<96..96>;
} AuthStart;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque transaction_id[16];
    opaque ke3<64..64>;
} AuthFinish;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id[24];
    opaque registration_request<32..32>;
} CredentialChangeStart;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque transaction_id[16];
    opaque registration_record<192..192>;
} CredentialChangeFinish;

struct {
    uint16 padding_version;                 // 1
    opaque inner_payload<72..265>;
    opaque zero_padding<4321..4514>;
} AccountServiceRequestPlaintext;
```

The profile and Network ID in an inner arm must equal the envelope header.
Creation-invitation presence follows Section 11.3. Start and finish messages
use independent HPKE contexts and request IDs; the transaction ID securely
links their inner plaintexts. Retrying one accepted request on the same origin
reuses the byte-identical envelope through the base idempotency path rather
than generating a second encapsulation.

`inner_payload` is the complete exact encoding of the arm selected by the
outer message kind. `AccountCreateStart` is 72 through 133 bytes with no
invitation and 204 through 265 bytes with the exact 132-byte invitation; its
only other variable is login length. The other arm lengths are 243 bytes for
`AccountCreateFinish`, 135 through 196 bytes for `AuthStart`, and 115 bytes
for `AuthFinish`, 91 bytes for `CredentialChangeStart`, and 243 bytes for
`CredentialChangeFinish`. The global bounds remain 72 and 265 bytes. The wrapper
plaintext is exactly 4,592 bytes:
`2 + 2 + inner_payload.length + 2 + zero_padding.length = 4592`.
Consequently `zero_padding.length = 4586 - inner_payload.length`, is within
the written bounds, and every byte is zero. The authenticated HPKE ciphertext
is exactly 4,608 bytes including its 16-byte tag. A wrong relationship,
nonzero padding, wrong selected arm, or trailing byte is the same bounded
`UNAVAILABLE` failure. Fixed sizing prevents an edge from learning login,
OPAQUE-message, or invitation length; the outer operation kind remains visible
for routing.

Every response uses its request's HPKE exporter so no second public key or
unauthenticated response channel is needed:

```text
enum {
    account_create_challenge(1), opaque_auth_challenge(2),
    account_create_complete(3), opaque_auth_complete(4),
    credential_change_challenge(5), credential_change_complete(6)
} AccountServiceResponseKind;

struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque recipient_key_id[32];
    opaque client_request_id[16];
    AccountServiceResponseKind response_kind;
    opaque response_salt[32];               // fresh for this response
} AccountServiceResponseHeader;

struct {
    AccountServiceResponseHeader header;
    opaque ciphertext<4224..4224>;
} AccountServiceResponse;

struct {
    uint16 profile_version;
    opaque transaction_id[16];
    opaque opaque_credential_id[32];
    opaque opaque_message<64..320>;         // exactly 64 or 320 bytes
} AccountServiceChallenge;

enum { rejected(1), committed(2) } AccountServiceCompletionStatus;

struct {
    uint16 profile_version;
    opaque transaction_id[16];
    AccountServiceCompletionStatus status;
    opaque account_id[24];                  // zero-filled on rejection
    uint64 account_session_generation;      // auth success only
} AccountServiceCompletion;

struct {
    uint16 padding_version;                 // 1
    opaque payload<52..372>;
    opaque zero_padding<3830..4150>;
} AccountServiceResponsePlaintext;
```

The closed request/response mapping is:

| Request kind | Response kind | Exact payload |
| --- | --- | --- |
| `account_create_start` | `account_create_challenge` | `AccountServiceChallenge` with 64-byte `RegistrationResponse` |
| `account_create_finish` | `account_create_complete` | `AccountServiceCompletion` |
| `opaque_auth_start` | `opaque_auth_challenge` | `AccountServiceChallenge` with 320-byte `KE2` |
| `opaque_auth_finish` | `opaque_auth_complete` | `AccountServiceCompletion` |
| `credential_change_start` | `credential_change_challenge` | `AccountServiceChallenge` with 64-byte `RegistrationResponse` |
| `credential_change_finish` | `credential_change_complete` | `AccountServiceCompletion` |

Version 1 has no separate START-rejection response arm. After a START has
successfully opened and parsed, a failed policy or state-admission predicate
therefore produces the ordinary fixed-size challenge and a one-use transaction
marked for rejection. That transaction carries no reservation, mutation, or
commit authority. A matching FINISH consumes it and produces the corresponding
encrypted `rejected` completion. This protocol-shaped exchange is not semantic
acceptance of the requested account operation. A failure before complete
authenticated parsing, an entropy or bounded-allocation failure, counter or
deadline overflow, or internal crypto/state corruption creates no such
transaction and emits no response.

`payload` is the complete exact object selected by the response kind. A
challenge is 116 bytes with a 64-byte `RegistrationResponse` or 372 bytes with
a 320-byte `KE2`; no other length is valid. A completion is exactly 52 bytes.
For `account_create_complete`, `committed` requires a canonical Account ID and
generation zero. For `opaque_auth_complete`, `committed` requires the exact
authenticated Account ID and a nonzero account-session generation. For
`credential_change_complete`, `committed` requires the exact Account ID and
new nonzero account-session generation. For any `rejected` arm, the Account ID
is 24 zero bytes and the generation is zero.
The profile and transaction ID repeat the authenticated request. `committed`
also requires an exact live transaction match; `rejected` may repeat an
unknown, expired, or already consumed claimed ID. A mismatch at the client is
fatal.

The response plaintext is exactly 4,208 bytes:
`2 + 2 + payload.length + 2 + zero_padding.length = 4208`; therefore its
padding length is `4202 - payload.length` and every padding byte is zero.
ChaCha20-Poly1305 adds its 16-byte tag, producing the exact 4,224-byte response
ciphertext. The client validates padding and complete payload consumption
before using any field.

The current 16-byte `recovery_epoch` is an external input to both the request
HPKE `info` above and the response exports below. It is the exact value pinned
by the client's accepted Appendix-C onboarding descriptor and held by the
coordinator; it is not transmitted inside either envelope. Consequently a
recorded request from an earlier recovery epoch fails HPKE authentication,
and a client using an earlier epoch cannot authenticate a current response.

The crypto worker samples `response_salt` uniformly from 32 fresh OS-CSPRNG
bytes for each newly created response. An exact idempotent replay returns the
stored header/ciphertext and does not sample or seal again. Both sides derive
exactly one 32-byte response key and 12-byte response nonce:

```text
response_key = Export(
    "agenc-chat account service response key v1" ||
    recovery_epoch || response_salt, 32)
response_nonce = Export(
    "agenc-chat account service response nonce v1" ||
    recovery_epoch || response_salt, 12)
response_aad = "agenc-chat account service response aad v1" ||
               TLS-encode(AccountServiceResponseHeader)
```

The 32-byte salt is not a secret. It is authenticated by AAD and makes the
derived key/nonce pair independent even if an old request envelope is replayed
after its idempotency tombstone expires and the semantic outcome has changed.
Without this salt, encrypting committed and later rejected completions under
one replayed exporter key/nonce would be catastrophic AEAD nonce reuse. A salt
generation failure fails before response construction; there is no clock or
deterministic fallback.

On the coordinator, `StateMeta.account_service_response_count` starts at zero
in each recovery epoch and increments exactly once, with checked arithmetic,
in the same transaction that first commits each distinct response and its
idempotency result. An edge's corresponding field is always zero because an
edge forwards stored ciphertext but never seals an account-service response.
A stored idempotent replay does not increment the coordinator counter. No new
response is constructed once the counter is `uint64::MAX`; account-service
readiness then fails closed until an explicitly reviewed recovery transition
creates a fresh epoch. Thus at most `2^64 - 1` independently salted responses
exist in one epoch and the probability of any 256-bit salt collision in that
epoch is less than `2^-129`. The fresh recovery epoch domain-separates resets
of this count.

For every successfully opened request that reaches a protocol outcome, the
coordinator encrypts the exact padded
`AccountServiceResponsePlaintext` with ChaCha20-Poly1305 under that key, nonce,
and AAD, stores the resulting response bytes in the idempotency result, and
erases the exporter material. A semantic finish rejection, including an
invalid OPAQUE `KE3`, still produces the fixed encrypted `rejected` completion;
a failure before HPKE authentication cannot. Entropy failure, counter
exhaustion, or an indeterminate storage outcome emits no response and
fail-closes account-service processing; it is an operational failure, not a
forgeable protocol rejection. A committed completion and the
durable state/result it describes are created in one atomic transaction, so a
success receipt can never describe an uncommitted account or login. The client
decrypts once and verifies every repeated field and expected response arm.
AEAD failure, a mismatched request ID/kind/network/key, reuse of a response
key/nonce, or an unsolicited response aborts the exchange. HPKE Base mode does
not authenticate the unauthenticated client; OPAQUE and invitation policy do
that. It does authenticate the response as coming from the holder of the
pinned recipient private key. Recipient-key compromise can decrypt recorded
request envelopes, so the document makes no forward-secrecy claim for login
metadata and requires an explicit pin transition after compromise.

An IRC numeric, standard reply, or edge assertion is never sufficient account
confirmation. A conforming native client accepts account creation or login
success only after decrypting the matching `committed` completion and checking
that its Account ID and generation equal the terminal reply and subsequent
session state. A malicious edge can suppress that receipt and cause denial of
service, but cannot forge a committed completion or transplant one between
requests, transactions, connections, networks, or response kinds.

### 11.3 Account creation

Clients negotiate `agenc.ag/account-create=v1` and perform:

```text
C: ACCTCREATE START <decoded-envelope-length>
S: ACCTCREATE READY START <decoded-envelope-length>
C: ACCTCREATE DATA <base64url-chunk>        (exactly 16 lines)
C: ACCTCREATE END
S: ACCTCREATE CHALLENGE <decoded-response-length>
S: ACCTCREATE DATA <base64url-chunk>        (exactly 15 lines)
S: ACCTCREATE END
C: ACCTCREATE FINISH <decoded-envelope-length>
S: ACCTCREATE READY FINISH <decoded-envelope-length>
C: ACCTCREATE DATA <base64url-chunk>        (exactly 16 lines)
C: ACCTCREATE END
S: ACCTCREATE COMPLETE <decoded-response-length>
S: ACCTCREATE DATA <base64url-chunk>        (exactly 15 lines)
S: ACCTCREATE END
S: NOTE ACCTCREATE CREATED <account-id> :Account created
```

The canonical unsigned-decimal declared length is exactly 4,726 for every
request envelope and exactly 4,342 for every response. `START`/`FINISH`
reserve that fixed bounded buffer before READY. `CHALLENGE` is legal only after
the coordinator successfully HPKE-opens and parses START and creates either an
admissible reservation-backed transaction or the closed latent-rejection
transaction in Section 11.2.1. `COMPLETE` is legal only after a finish request
that the coordinator successfully HPKE-opened and parsed. DATA is legal only in
the immediately preceding transfer state. A request has fifteen 400-character
chunks and one final 302-character chunk; either response has fourteen
400-character chunks and one final 190-character chunk. Every chunk is
canonical unpadded base64url and END marks the preceding chunk final.
Concatenation must decode canonically to the declared fixed length and one
exact Section-11.2.1 object. Empty, short, long, early, extra, interleaved,
duplicate, or post-END chunks fail and erase the transfer. The transfer has a 15-second idle
and 60-second total monotonic deadline and consumes the pre-auth byte/command
budgets on every line. No client tag is legal on an `ACCTCREATE` line; one
connection can have only one such transfer, so correlation is implicit in its
state machine.

The decrypted login is 3 through 64 bytes. The registration request, response,
and record are exactly 32, 64, and 192 bytes. A transaction ID is 16 random
bytes, expires after 60 seconds,
is bound to one TLS connection, origin, login hash, one freshly sampled
32-byte opaque credential ID, network ID, HPKE start request ID, and exact
request/response, and is consumed once whether finishing succeeds or fails.
The credential ID is included in the encrypted challenge and becomes part of
the OPAQUE/account record only on success; a failed candidate is never reused.
A connection holds at most one creation transaction and one active transfer
buffer. The invitation field inside `AccountCreateStart` is empty only when
absent; no outer `*` token exists.

Account-creation invitations are a distinct, automatically handled onboarding
credential, not `PASS`. Their decoded canonical form is:

```text
struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque invite_id[16];                   // random and never reused
    uint64 not_before;                      // Unix seconds
    uint64 expires_at;                      // exclusive Unix seconds
    uint16 use_limit;                       // exactly 1 in version 1
} AccountCreationInviteTBS;

struct {
    AccountCreationInviteTBS tbs;
    opaque signature[64];                   // Ed25519
} AccountCreationInvite;
```

The signature input is
`"agenc-chat account creation invite v1" || TLS-encode(tbs)`. The verification
key is the exact configured offline invitation authority; it is distinct from
TLS, federation, account-service HPKE, admin, and E2EE keys. The object is
exactly 132 bytes inside the encrypted `AccountCreateStart`; only the offline QR
envelope in Appendix C base64url-encodes it separately. It is valid only when
the profile and Network ID match, `not_before <= now < expires_at`, its lifetime
is 1 through 2,592,000 seconds, `use_limit=1`, the signature verifies, and its
Invite ID has never been reserved, redeemed, or tombstoned. No clock skew is
silently added to those comparisons.

Under `open` policy the inner invitation field must be empty; under `invite` it
must contain one valid invitation; under `closed`, creation always fails. Only
the coordinator can decrypt and verify it. An edge sees only the bounded HPKE
envelope and the mutually authenticated federation carrier. The token is never
copied into an account, event, audit log, application log, metric, or reply.

`START` computes the current-generation keyed login digest and checks both the
current and any previous-generation index for a conflict. For a semantically
admissible request, it durably reserves the current stored key with the exact
Section-23.9 creation-reservation value and, when present, reserves the Invite
ID for the transaction. A policy, invitation, or login-conflict rejection
instead creates only the latent-rejection transaction from Section 11.2.1; it
reserves neither identifier and can produce only a rejected completion. START
then erases the normalized login; neither the identifier nor a reversible
encoding of it enters durable state. A second transaction cannot reserve any
matching active-generation value. `FINISH` validates the exact RFC 9807
record, allocates a random Account ID, and atomically stores the current-
generation live index value with its opaque credential ID, record,
reservation consumption, invitation redemption tombstone, default policy,
and account-creation event.
The tombstone remains until seven days after invitation expiry. Success is sent
only after an immediate durable commit. The same atomic transaction stores the
exact encrypted `account_create_complete` receipt in the idempotent result; its
Account ID and the terminal NOTE value are identical. A semantically rejected,
successfully opened finish sends the same fixed-size response with `rejected`,
then `FAIL ACCTCREATE UNAVAILABLE :Account creation unavailable`. A failure
before HPKE authentication has no completion response and sends the same FAIL.
No failure distinguishes conflict, rate limit, token, policy, malformed record,
expired transaction, or storage outcome. A failed or expired transaction
releases its login and invitation reservations but never removes an already
redeemed tombstone. The client accepts creation only after authenticating the
committed completion; a missing receipt, receipt/NOTE mismatch, bare NOTE, or
rejected receipt followed by NOTE is a fatal exchange failure.

The default is closed registration for onion-only deployments and invite
registration for public networks unless the operator explicitly selects open
registration. Invitation material is not embedded in the OPAQUE transcript.

After creation, the native client generates the account root and first device
locally and publishes the root, enrollment, roster, capabilities, and
KeyPackages through the companion E2EE flow. The server cannot generate or
recover the root private key.

### 11.4 OPAQUE login over SASL

`AUTHENTICATE` framing follows IRCv3 SASL: payload chunks are base64, each line
contains at most 400 characters, a final `+` represents an empty or exactly
multiple-of-400 terminator, and decoding is canonical RFC-4648 Base64 with
required `=` padding. Each request envelope is exactly 4,726 bytes and encodes
to 6,304 characters (fifteen 400-character chunks plus 304); each response is
exactly 4,342 bytes and encodes to 5,792 characters (fourteen 400-character
chunks plus 192). Neither length needs a `+` terminator. Any other decoded
length, chunk shape, alphabet, or padding aborts SASL. The exchange is:

```text
C: AUTHENTICATE AGENC-OPAQUE
S: AUTHENTICATE +
C: AUTHENTICATE <base64(AccountServiceEnvelope[opaque_auth_start]), chunked>
S: AUTHENTICATE <base64(AccountServiceResponse[opaque_auth_challenge]), chunked>
C: AUTHENTICATE <base64(AccountServiceEnvelope[opaque_auth_finish]), chunked>
S: AUTHENTICATE <base64(AccountServiceResponse[opaque_auth_complete]), chunked>
S: 903 <nick-or-*> :SASL authentication successful
```

The envelope and inner application wrappers use the unsigned network-order
integers and TLS-style vectors in Section 11.2.1. `AuthStart` and `AuthFinish`
are the request plaintexts: `ke1` is exactly the 96-byte OPAQUE KE1 and `ke3`
is exactly the 64-byte KE3. For response kind `opaque_auth_challenge`, the
`AccountServiceChallenge.opaque_message` is exactly the 320-byte OPAQUE KE2;
for `account_create_challenge` it is exactly the 64-byte
RegistrationResponse. The other arm is invalid in either exchange.

There are no optional or trailing fields. If processing an authenticated,
well-formed KE2 returns the OPAQUE invalid-login error, the native client
generates 64 fresh uniform bytes with the OS CSPRNG and sends them as the
syntactically valid dummy `AuthFinish.ke3`; it does not abort SASL early. A
real KE3 and dummy KE3 have the same envelope, framing, and timing class. The
client never treats the dummy as an OPAQUE value or retains it. Unknown-account
and wrong-password paths generate an RFC 9807 fake credential response,
perform equivalent validation and timing work through server finish, return
the fixed encrypted `opaque_auth_complete` receipt with `rejected`, and end
with numeric 904. One fake registration
record is created once for each OPAQUE server setup and stored in the encrypted
OPAQUE-record table. It contains an independently random valid client public
key, an independently random 64-byte masking key, and a zero envelope of the
suite-prescribed nonce-plus-MAC length; it is never an actual client record.
For every start, `StorageOwner` computes the current-generation digest and,
during a Section-23.9 transition, the previous-generation digest. It performs
both fixed-key lookups in current-then-previous order (a dummy second lookup
when no transition exists), rejects duplicate cross-generation ownership as
corruption, and then performs one OPAQUE-record lookup. Exactly one live arm
selects its real record; absence, a creation reservation, or a deletion
tombstone selects the fixed fake record without an early response. The real path
uses the private OpaqueCredentialId from the index; the fake path derives the
stable Section-11.2 fake ID from the supplied normalized login. Both use that
32-byte value as `credential_identifier` and `client_identity`, the same
global OPRF seed, and the same exact OPAQUE work. The encrypted challenge
returns the selected ID so the client supplies the identical OPAQUE
identifiers at finish; it does not reveal whether the ID was real or fake.
Before returning the sealed `AccountServiceResponse`, the coordinator durably
stores the encrypted library-versioned server-login state, exact HPKE and
OPAQUE request/response binding, current keyed login digest, selected opaque
credential ID, matched index generation/account when present,
origin/connection binding, expiry, and exact idempotent result. The normalized
login is erased before the transaction is serialized. The selected credential
ID is private pseudorandom state, not human metadata, and is supplied again in
the exact `ServerLoginParameters` at finish. A serialized library state is
accepted only after byte-length/version vectors and secret-erasure behavior
are reviewed; arbitrary Serde state remains forbidden.
An unknown library-state version fails closed; it is never interpreted through
Serde or Rust memory layout. The transaction is consumed once in the same
commit that produces success or terminal failure. The server counts an attempt
as failed unless a valid `AuthFinish` arrives within 30 seconds. Errors do not
reveal account existence.

A successful finish atomically binds the account, creates the one-use
authentication grant, and stores a `committed` completion containing the exact
Account ID and account-session generation. The server sends that fixed
response before numeric 903. A semantic rejection sends `rejected` before
904. A conforming client accepts 903 only after decrypting and validating the
committed completion and accepts neither a bare 903 nor values that disagree
with the later 900/session state. Receipt suppression or any mismatch is a
fatal authentication failure, never a reason to fall back to another SASL
mechanism.

The grant also carries the coordinator's current monotonic authentication
instant inside private memory. Consuming it in `session_open` initializes that
session's `fresh_auth_at` proof; same-account reauthentication replaces it with
the newer instant. The proof is valid while `now - fresh_auth_at <= 300`
seconds, cannot survive coordinator restart, is never projected or persisted,
and can be checked or consumed only by the destructive controls that explicitly
require it. A still-valid durably replayed grant consumed after restart can
bind the account but initializes no fresh-auth proof; the client reauthenticates
before a destructive control.

After any committed login or credential change, a native client stores the
authenticated `(Network ID, Account ID, recovery epoch,
account_session_generation)` in protected local state. Within one recovery
epoch, a generation below the stored value is rollback and equality is valid
only for an ordinary login to the same unchanged account. A credential-change
completion must be strictly greater. After the user explicitly accepts a new
recovery epoch, the first committed login for a previously pinned Account ID
must also have a generation strictly greater than the old-epoch pin. Section
23.7 increments every restored live account exactly once, so equality catches
one lost generation and a lower value catches a longer rollback. A violation
aborts account use and warns that restored credentials may be stale; it is
never overridden by the edge's 900/903 text. A client with no prior pin cannot
make this comparison.

At most two attempts are allowed per connection and five per keyed login hash
per 15 minutes. OPRF operations have a global bounded worker semaphore.
Successful login from a previous-generation entry atomically creates the
current-generation entry, deletes the previous entry, decrements the exact
previous-entry count, and binds the Account ID and session generation. A
current-generation login only performs the binding. In both cases,
reauthentication to the same account refreshes only the monotonic
`fresh_auth_at` proof used by destructive controls. Reauthentication to a
different account first requires `AUTHENTICATE *` logout and is rejected while
the session occupies an E2EE-bound channel.

### 11.5 Credential change and non-recovery

Version 1 supports password change without exposing either password or the
replacement OPAQUE record to an edge. A client negotiates
`agenc.ag/account-credentials=v1`, is already registered to the target account,
and performs this fixed `ACCTCRED` exchange using the same base64url transfer
rules, 4,726-byte requests, 4,342-byte responses, chunk counts, idle deadline,
total deadline, tag prohibition, and one-transfer-per-connection rule as
`ACCTCREATE`:

```text
C: ACCTCRED START 4726
S: ACCTCRED READY START 4726
C: ACCTCRED DATA <base64url-chunk>          (exactly 16 lines)
C: ACCTCRED END
S: ACCTCRED CHALLENGE 4342
S: ACCTCRED DATA <base64url-chunk>          (exactly 15 lines)
S: ACCTCRED END
C: ACCTCRED FINISH 4726
S: ACCTCRED READY FINISH 4726
C: ACCTCRED DATA <base64url-chunk>          (exactly 16 lines)
C: ACCTCRED END
S: ACCTCRED COMPLETE 4342
S: ACCTCRED DATA <base64url-chunk>          (exactly 15 lines)
S: ACCTCRED END
S: NOTE ACCTCRED CHANGED :Account credential changed; reconnect required
```

The start and finish envelopes select `credential_change_start` and
`credential_change_finish`. `CredentialChangeStart` carries the exact logged-in
Account ID and a fresh 32-byte `RegistrationRequest`; `CredentialChangeFinish`
carries the returned transaction ID and exact 192-byte replacement
`RegistrationRecord`. The encrypted challenge repeats the account's existing
private OpaqueCredentialId and a 64-byte `RegistrationResponse`; both OPAQUE
identities, the credential identifier, server identity, KSF, context, and
server setup remain exactly Section 11.2. The client supplies the new password
only to its local RFC-9807 registration computation, applies the exact
Section-11.1 password byte rules, and erases its registration state after
finish.

START is semantically admissible only when all of these are true:

- the origin is registered and its Account ID equals the encrypted request;
- a successful same-account OPAQUE authentication on this connection set
  `fresh_auth_at` within the previous five monotonic minutes;
- no account deletion, credential change, login-index migration for that
  account, or storage/recovery operation conflicts with it; and
- the account, OPAQUE record, session generation, account revision, and
  private credential ID are internally consistent.

A successfully opened and parsed START that fails one of those predicates
still performs the fixed registration-challenge shape and creates the
non-authorizing latent-rejection transaction from Section 11.2.1. It consumes
the supplied fresh-auth proof, acquires no account-operation reservation, and
can produce only an encrypted rejected completion after FINISH.

The coordinator creates one 60-second transaction bound to Network ID,
Account ID, account revision, account-session generation, session, edge,
incarnation, origin/generation, connection nonce, credential ID, start request
ID, and exact request/response. Each account and connection has at most one
such transaction. It is consumed on every finish outcome. A duplicate logical
request replays exact stored bytes; a second encapsulation is a different
request and cannot join the transaction.

The first accepted START atomically clears the session's `fresh_auth_at`; an
exact idempotent retry uses the stored transaction and does not need a second
proof. Any new START after failure, expiry, or completion requires a new
same-account OPAQUE authentication. This prevents one recent password proof
from authorizing several independent destructive flows.

FINISH validates the complete replacement record and, on success, atomically
replaces only that account's OPAQUE record, increments its account revision and
account-session generation, invalidates every authentication grant/login
transaction/fresh-auth proof for the account, fences all of its sessions, and
stores the exact `credential_change_complete` committed receipt and resulting
events. Each removed session uses `FederationSessionHideKind.security_fenced`
and the public reason `connection closed`; the wire never labels the event as a
password change. Channel departures, projections, origin fences, and outboxes
are the ordinary bounded session-removal plan. The login identifier,
login-index entries, Account ID, E2EE root/device authority, contacts, nickname
reservations, channel ownership, and message state do not change. The
committed receipt contains the Account ID and new session generation. Its NOTE
is rendered before the initiating socket closes; the new generation is
authoritative immediately, so neither that socket nor another old session can
execute a later account command while closure is pending. When the initiating
edge applies its own `session_hidden`, it retains only the physical socket and
reserved control-output permit in `CLOSING`, accepts no further input, waits
for matching request-completion coverage, renders the already stored
completion/NOTE, and closes. Other affected sockets close as soon as their
ordered hide event is applied. The client then reconnects and proves the new
password.

A semantic rejection sends the fixed encrypted `rejected` completion followed
by `FAIL ACCTCRED UNAVAILABLE :Credential change unavailable`; a pre-HPKE
failure sends the same FAIL without a completion. No reply distinguishes stale
state, malformed record, authorization, transaction expiry, or storage error.
The existing record remains byte-for-byte unchanged on every failure. A client
accepts the change only after validating the committed completion, exact NOTE,
and connection closure; a bare NOTE or mismatched receipt is failure.

There is deliberately no password reset, recovery question, email/SMS reset,
operator password replacement, reusable recovery token, or login-identifier
rename in version 1. Losing the password loses account access unless another
already authenticated session can first complete the fresh-OPAQUE requirement;
E2EE recovery material never substitutes for account authentication. The
OPAQUE `export_key` is not used by the daemon or stored server-side, so changing
the password cannot silently rewrap or destroy an E2EE secret. A future reset
or identifier-change design requires a new reviewed protocol profile.

### 11.6 Forbidden mechanisms

`AGENC-OPAQUE` is the only version-1 SASL mechanism. `EXTERNAL` is deliberately
not advertised: a client certificate authenticated only to a terminating edge
does not give the coordinator an end-to-end proof of private-key possession,
so a malicious edge could otherwise impersonate an account. A future
certificate mechanism must carry a coordinator-originated, connection-bound
proof under a new named mechanism.

`EXTERNAL`, `PLAIN`, `LOGIN`, `SCRAM-SHA-1`, `SCRAM-SHA-256`, bearer
passwords, NickServ password messages, and server-generated reusable tokens
are forbidden in the full conformance profile. A compatibility fork enabling
them cannot call itself version-1 conforming. This avoids sending reusable
passwords to the server and avoids retaining a second password verifier that
weakens the OPAQUE compromise model.

### 11.7 Device onboarding and recovery

Account login and E2EE device authority are separate. Logging in does not let
the server mint an MLS credential. A new native device:

1. authenticates the account with OPAQUE;
2. generates its Device ID and authorization key locally;
3. displays a QR/pairing code containing the network, Account ID, Device ID,
   device-key fingerprint, and one-time enrollment challenge;
4. obtains the root and new-device signatures defined by the companion
   profile from an already authorized root holder; and
5. publishes the successor roster and fresh one-use KeyPackages.

The client automates these steps; users confirm the account and device
fingerprints, not protocol objects. If no root holder or encrypted recovery
backup exists, the server cannot restore the old E2EE identity. Recovery
creates a visibly new root identity or a new account and forces verification;
it never silently resets pins.

### 11.8 Guests and nickname reservations

Guests have no Account ID, use a random session identity, and may join listed
public plaintext channels. They cannot create registered or secret channels,
bind E2EE, use offline history, reserve nicknames, send direct messages to
users who disallow guests, or exceed the stricter guest quotas in Section 19.
An invite, key, or `+I` match does not let a guest join an unlisted, secret, or
E2EE-bound channel; authentication is required before its existence is
revealed.

An account may reserve at most five nicknames. Reservations use the ASCII
comparison form, are visible in account settings, and are enforced globally.
On disconnect, a reservation remains; an unreserved nickname becomes
available after the authoritative quit. Collision never kills both users or
merges identities.

## 12. Session and presence model

One network connection is one `SessionId` and one `UserId`. Multiple sessions
authenticated to one account remain distinct IRC users and may use different
nicknames. Account-wide policies and E2EE device rosters are shared; channel
membership, away state, nickname, capabilities, rate state, and send queue are
per session.

The coordinator-owned logical session contains only:

```text
GlobalSession {
  session_id, user_id, home_server_id, connection_nonce,
  optional account_id, account_session_generation,
  nickname, display_name, public_cloak, away_state,
  negotiated_capability_hash, joined_channel_ids,
  created_at_utc, optional coordinator_local_fresh_auth_deadline,
  state_revision
}
```

The home edge separately owns `LocalConnectionContext`, containing the socket,
TLS state, the exact negotiated capability set, privacy profile, admission
class, local rate state, monotonic creation time, and output queue. No exact
capability set is represented in `GlobalSession`; transport type and Tor use
are never federated. Socket addresses and TLS
details are not members of protocol state. `connection_nonce` is 32 random
bytes used only by the companion E2EE origin binding and is never displayed.
The coordinator retains only the hash of the bytewise-sorted capability-name
vector sent in `session_open`; it binds registration/idempotency but never
authorizes a command. The edge validates capability-dependent input before
federation and renders semantic results from its exact local set. The
fresh-auth deadline is coordinator-memory-only, is omitted from
projections/snapshots/storage, and therefore expires on coordinator restart.

An edge separately owns the Appendix-B home-only account projection keyed by
Account ID while it hosts an authenticated session for that account. That
projection supplies the current account/session generations needed for account
commands without copying contacts, login material, or private policy to the
edge. It is reference-counted by local projected sessions and erased with the
last ordered session removal.

User mode `+i` is enabled by default and cannot be disabled in the full
profile. It hides the user from broad WHO/WHOIS queries while preserving
visibility to users sharing a channel. User mode `+w` subscribes to bounded,
non-sensitive operator notices. Mode `+o` is server-set only on the dedicated
admin listener. Unknown user modes receive `ERR_UMODEUNKNOWNFLAG`.

Away text is optional, at most 256 bytes, and visible only to direct-message
senders and shared-channel peers. The server does not expose idle time or last
activity. `MONITOR` is limited to 100 nicknames and reports presence only when
the requester shares a current channel, the target explicitly allows public
presence, or both sessions have mutually permitted account contact.

## 13. Channel model

### 13.1 Channel record

The authoritative record is:

```text
Channel {
  channel_instance_id, canonical_name, display_name, scope,
  visibility, content_policy, persistence_policy,
  creator_principal, created_at, state_revision,
  simple_modes, optional key_verifier, optional member_limit,
  optional plaintext_topic, topic_setter, topic_set_at,
  live_memberships, account_role_grants,
  bans, exceptions, invite_exceptions, pending_invites,
  history_policy, optional e2ee_route_binding
}
```

`scope` is `global` for `#` and `local` for `&`. `visibility` is one of
`listed`, `unlisted`, or `secret`. `content_policy` is `plaintext` or
`e2ee_bound`. `persistence_policy` is `ephemeral` or `registered`. These axes
are independent: an E2EE channel may be listed, and a secret channel may be
plaintext.

The first successful JOIN creates an `ephemeral`, `listed`, `plaintext`
channel with modes `+nt`, no key/limit/topic/list entries/invites/history, and
grants the creator owner role. An authenticated owner can register it through
`CHANCTL REGISTER`, making its instance and policy survive zero members. A
registered local channel persists only on its owning edge and is never
federated. An ephemeral channel is destroyed atomically when the last member
leaves after all E2EE tombstone requirements are met.

A guest-created channel remains ephemeral and cannot become secret, enable
history, or bind E2EE. Setting `+s`, registering, or initiating E2EE binding
requires an authenticated account owner even when the current guest holds the
owner role.

### 13.2 Roles and prefix modes

Roles form this strict order:

```text
owner (+q, ~) > admin (+a, &) > operator (+o, @) > halfop (+h, %) > voice (+v, +) > member
```

Each membership has exactly one highest role; lower privileges are implied.
`multi-prefix` renders every implied prefix, otherwise only the highest.
Permission checks use typed roles, not prefix characters.

An ephemeral channel stores roles only on live User-ID memberships. A
registered channel additionally stores a durable map from authenticated
Account ID to highest granted role; at least one grant is owner. Every live
session of a granted account in that channel has the higher of its live role
and account grant for authorization and prefix rendering. Guest roles remain
session-only and a guest can never be a durable owner.

Changing a prefix mode for an authenticated target in a registered channel
changes its account grant and recomputes every live membership of that account
in the same transaction; changing a guest target changes only that User ID.
For an account target, the coordinator emits exactly one
`channel_memberships_recomputed` state event at the one resulting channel
revision. It contains all 1..32 affected live memberships in User-ID order;
each recipient edge gets only its visible event subset and persists only
memberships homed there. A guest target uses the ordinary single-membership
mode event. The server renders one MODE change for each affected nickname.
Thus revocation is immediate and does not leave another session with stale
authority. Registering a channel converts
each authenticated member's current highest role into one account grant,
taking the maximum where several sessions share an account; unregistering
materializes each grant into current live roles before deleting the grant map.

Applying `+q/+a/+o/+h/+v` raises the target to the higher of its current and
named role. Applying the corresponding removal is valid only when the named
role is the target's current highest role and lowers it exactly one level
(`q` to `a`, `a` to `o`, `o` to `h`, `h` to `v`, `v` to member). Removing an
implied lower role is rejected as `INVALID_ARGUMENT`; it never unexpectedly
demotes a higher role. Authorization and the nonzero-owner rule are evaluated
against the final state of the complete mode vector, permitting an atomic
owner transfer.

- owner: change ownership, registration, all policy, and every lower role;
- admin: change policy except ownership/registration and grant through admin;
- operator: modes, topic, invites, bans, kicks, and grant through operator;
- halfop: topic, voice, routine kick, and non-owner ban management;
- voice: speak in moderated channels; and
- member: read and speak when modes permit.

The last owner grant of a registered channel cannot be removed or demoted
without atomically granting another account ownership or unregistering the
channel. Its sessions may part because the grant persists through dormancy.
E2EE role and membership changes additionally require the companion policy
transition; the server-side mode is not cryptographic authorization by itself.

### 13.3 Modes

The advertised `CHANMODES` classes have these exact meanings:

| Mode | Type | Meaning |
| --- | --- | --- |
| `b` | list | ban matching a typed mask |
| `e` | list | ban exception |
| `I` | list | invite-only exception |
| `k` | set/unset parameter | channel join secret |
| `l` | set parameter | maximum simultaneous memberships |
| `i` | simple | invite-only |
| `m` | simple | moderated |
| `n` | simple | reject messages from nonmembers; enabled and locked on all channels |
| `p` | simple | unlisted but existence may be confirmed by exact authorized query |
| `s` | simple | secret and existence-hiding to nonmembers |
| `t` | simple | only halfop or higher may set plaintext topic |

`p` and `s` are mutually exclusive; setting one clears the other in the same
mode transaction. `n` cannot be cleared. Prefix modes consume a nickname
parameter. At most six changes are accepted in one MODE command, matching
`MODES=6`; extras reject the whole command.

Channel secrets are 8 through 256 UTF-8 bytes. The server stores only an
Argon2id verifier with a random 16-byte salt (`m=65536 KiB`, `t=3`, `p=4`) and
uses a bounded verification pool. The raw secret is cleared immediately and
never appears in MODE replies, federation events, logs, or history. `MODE #c`
shows `+k` without its value to all users, including operators. A global
channel-mode or `b/e/I` list query is a bounded Appendix-B coordinator query;
an edge does not retain those list rows or infer a reply from stale projected
state.

Startup also creates one in-memory dummy verifier from an independent random
16-byte salt and random valid secret using the identical Argon2id parameters.
For any syntactically valid JOIN carrying a nonempty key, the coordinator runs
exactly one admitted Argon2 verification: against the real verifier only when
the route exists and has `+k`, otherwise against the dummy. A wrong key,
nonexistent channel, unavailable secret channel, or real channel without `+k`
therefore has the same expensive-work class. The dummy material is never
persisted or used as a valid channel key and is regenerated on restart.

### 13.4 Typed masks

List modes accept only:

```text
$a:<AccountRandomId>       authenticated account
$u:<22-char-UserId>        one live session
$n:<ASCII-nickname-glob>   nickname display/routing match
$c:<cloak-glob>            visible ephemeral cloak match
$q:<one-complete-mask>      quiet wrapper, legal only in channel +b
```

Globs are 1..96 bytes and contain only `[A-Za-z0-9._-]`, `*`, and `?`; they
are compiled into a bounded linear-time matcher, never a regular expression.
The quiet wrapper is not recursive and its complete text remains within the
fixed 128-byte typed-mask text limit. `$a` is preferred. IP, CIDR, DNS, real host,
TLS fingerprint, login name, and arbitrary extban scripts are forbidden. Each
list has at most 100 entries. Match strength is account 4, session 3, nickname
2, and cloak 1. The strongest matching `b` and `e` entry are selected; a ban is
effective exactly when there is a matching ban and no exception of equal or
greater strength. A non-quiet effective ban blocks JOIN but does not newly mute
an existing member; a quiet effective ban blocks the Section-16.2 actions but
not JOIN. A matching `I` entry bypasses only `+i`, independently of `b/e`.

Adding a list entry canonicalizes the mask, rejects an identical
`(mode, kind, quiet, value)` already present, and assigns a random 16-byte
Entry ID. Removing names the exact canonical mask and removes its one matching
entry; an absent mask changes nothing and returns
`FAIL MODE INVALID_ARGUMENT :Invalid mode mask`.
Version-1 client list entries do not carry expiry, so their federated
`expires_at` is zero. Queries order entries by creation time then Entry ID.

### 13.5 Public, unlisted, and secret discovery

`LIST` returns only `listed` channels, the lower bound of their member-count
privacy bucket (`1`, `2`, `5`, `10`, `25`, `50`, or `100`), and a plaintext
topic or the fixed E2EE placeholder. The buckets mean 1, 2--4, 5--9, 10--24,
25--49, 50--99, and 100 or more. `p` channels are omitted but
may be named by a member. `s` channels are omitted from LIST, NAMES, WHO,
WHOIS channel lists, MONITOR context, errors, and timing-distinct lookups for
nonmembers.

For an unauthenticated or unauthorized user, nonexistent and secret channel
JOIN/NAMES/TOPIC/MODE requests take the same logical path and return:

```text
FAIL <command> SECRET_UNAVAILABLE <supplied-name> :Channel is unavailable
```

After any required real-or-dummy key job and all bounded authorization
lookups, the server pads failed unavailable processing to the same configured
5 ms minimum after syntax validation. Current members need no existence-hiding
path because membership already reveals the channel. This is a best-effort
enumeration defense, not protection against traffic analysis or membership
disclosure by users.

Users still join a known secret channel normally with `/join #name` when they
hold an invite, match `+I`, or supply its key. A listed E2EE channel remains
discoverable and joinable through the familiar name, while its content and
private topic remain encrypted.

## 14. Base command behavior

Unless overridden below, parameter syntax, reply ordering, and traditional
numerics follow the Modern IRC snapshot selected under Section 2. Every row is
mandatory for a full node; `restricted` means implemented on the admin
transport but unavailable on public client listeners.

| Command | Status | Version-1 behavior |
| --- | --- | --- |
| `CAP` | supported | IRCv3 capability negotiation |
| `AUTHENTICATE` | supported | Section 11 mechanisms only |
| `PASS` | supported | pre-registration access token only |
| `NICK` | supported | global atomic reservation; no collision kills |
| `USER` | supported | ignores claimed username/host fields |
| `PING`, `PONG` | supported | bounded keepalive semantics |
| `QUIT` | supported | atomic session removal |
| `JOIN`, `PART` | supported | at most 20 comma-separated channels |
| `MODE` | supported | user/channel modes defined here |
| `TOPIC` | supported | plaintext only; E2EE rules in companion spec |
| `NAMES`, `LIST` | supported | visibility-filtered and paged |
| `INVITE`, `KICK` | supported | typed authorization and privacy rules |
| `PRIVMSG`, `NOTICE`, `TAGMSG` | supported | Section 15 routing |
| `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN`, `INFO` | supported | privacy-safe static or aggregate output |
| `WHO`, `WHOIS`, `WHOWAS` | supported | shared-context visibility only |
| `AWAY`, `ISON`, `USERHOST`, `MONITOR`, `SETNAME` | supported | privacy-filtered presence |
| `BATCH` | server output | client-sent BATCH is not authorized by any v1 extension |
| `ACCT`, `CHANCTL` | supported | authenticated account/channel controls in Section 14.6 |
| `CHATHISTORY` | optional | only under the pinned Section 17 profile |
| `STATS` | restricted | unavailable on public listeners; bounded aggregates via admin |
| `LINKS` | supported | server names and status only, never addresses/topology metrics |
| `OPER`, `CONNECT`, `KILL`, `REHASH`, `RESTART`, `SQUIT`, `DIE` | restricted | Section 22 admin transport |
| `TRACE` | disabled | returns `ERR_NOPRIVILEGES`; topology leak |
| `SERVLIST`, `SQUERY` | disabled | returns `ERR_UNKNOWNCOMMAND` |
| `SUMMON`, `USERS` | disabled | obsolete; returns `ERR_UNKNOWNCOMMAND` |

### 14.1 Atomic multi-target rules

Syntax validation for an entire command completes before any target is
processed. `JOIN` and `PART` accept at most 20 targets; `PRIVMSG` and `NOTICE`
at most 4; `TAGMSG` exactly 1. Duplicate canonical targets are rejected.

A multi-target `JOIN`, `PART`, `PRIVMSG`, or `NOTICE` cannot mix local `&`
channels with global channels or users. Direct-user targets are global. A
mixed-authority command is rejected as `INVALID_ARGUMENT` before lookup or
state change; clients issue separate commands when they intentionally cross
scopes. This keeps each accepted multi-target operation under one state and
durability authority rather than pretending an undefined distributed
transaction exists.

For state mutations, authorization is evaluated per target and successful
targets commit and are reported in canonical target order as one transaction.
If a storage or federation failure occurs, none commit. Policy failures are
reported per target after the transaction for the successful subset; this
preserves common IRC behavior without partial persistence accidents. One
global multi-target command is one Section-20.5 vector request, never several
independently committed federation requests. E2EE commands retain the stricter
single-target rules from the companion specification.

### 14.2 `JOIN` and `PART`

`JOIN 0` parts all current channels in canonical channel-ID order only when
they are all local or all global; if both scopes are occupied it returns
`INVALID_ARGUMENT` and changes nothing. Otherwise, keys align positionally
with the channel list; a missing key is empty, and extra keys are invalid. JOIN
checks, in order: syntax, visibility-safe lookup/create eligibility, account
requirement, ban/exception, invite, channel key, limit, then E2EE eligibility.
An invite is consumed only in the successful commit.

Successful JOIN sends the JOIN event, then topic numerics, then one NAMES
burst. With `extended-join`, the JOIN includes the public account label and
display name. Secret-channel membership is sent only to current members.

For a global JOIN, that ordering is implemented without copying the channel's
remote membership into the edge projection. The covered `committed` result
contains the bounded topic numerics and per-target failures; after rendering
them, the edge opens one connection-owned `JoinNamesContinuation` for the
accepted channel names and issues an internal Appendix-B `directory_query`
`names` request at the origin's next operation sequence. It advances the same
immutable query snapshot cursor page by page and fetches the next page only
when the client queue is below 50 percent. Every page retains the original
client label/batch context locally, and the final page contains the one 366 for
each accepted channel. The edge admits no later global request from that origin
until this continuation ends, although at most the ordinary bounded number of
parsed commands may wait behind it.

The continuation owns at most 20 channel names, one 32-byte cursor, one query
snapshot slot, and one open response batch; it is not a federation or
persistence field and never copies a client label to the coordinator. Exact
federation retries replay the stored page. Coordinator/link failure, query
expiry, client cancellation, or output-queue closure aborts the continuation
and closes that client connection with the reserved control path rather than
claiming a complete JOIN burst. The already committed membership remains an
ordinary uncertain-on-disconnect network effect and is removed when the old
origin closes/expires. A coordinator-local client uses the same logical query
snapshot and output state machine without serializing the internal request.

PART requires membership. Reasons are at most 256 bytes. Leaving the final
membership triggers destruction or registered-channel dormancy in the same
authoritative transition.

### 14.3 `TOPIC`, `NAMES`, and `LIST`

`TOPIC #c` returns the current topic and setter/time when visible. On an edge,
that read is the `channel_topic` coordinator query rather than an inference
from a directory cache. Setting a plaintext topic requires membership and the
role required by `+t`, validates at most 1,024 UTF-8 bytes, and assigns a new
Message ID. An E2EE-bound route uses only the fixed public placeholder and
companion-protected private topic.

Global NAMES is evaluated at the coordinator because an edge retains only
local memberships. It returns at most 512 users per page and checks visibility
before lookup. Large results use `batch`; legacy clients receive multiple 353
lines followed by one 366. LIST likewise uses an immutable coordinator
snapshot cursor, returns at most 200 channels per request, and charges one
query token per 20 scanned records.
`LIST >min`, `<max`, masks, and nonstandard filters are not implemented.

### 14.4 `INVITE` and `KICK`

An invite is a random 128-bit single-use record bound to channel instance,
target Account ID or User ID, inviter User ID, creation revision, and a
10-minute expiry. The wire `INVITE <nick> <channel>` creates it; no bearer
token is exposed. An invite never bypasses a matching `+b`; only the ordinary
matching `+e` rule does. `+I` is solely an exception to invite-only `+i` and
does not alter ban evaluation.

KICK requires halfop or higher and may not target an equal or higher role.
At most four users may be kicked in one command. The reason is at most 256
bytes. For E2EE channels the server-side kick and cryptographic Remove follow
the companion ordering; delivery pauses while removal is pending.

### 14.5 Queries

WHO with no exact shared channel returns only the requester. WHOIS returns the
target only when the requester shares a channel, has mutual account contact,
or the target opted into public presence. It never returns source address,
idle duration, login identifier, client certificate, Tor status, or exact
server route. Channel lists omit secret/unshared channels.

WHOWAS retains only nickname, ephemeral user/host mask, public account label,
and disconnect second for 15 minutes, with 10,000 records network-wide. It
contains no IP or realname. ISON and USERHOST use the same visibility rule;
an invisible target is indistinguishable from offline.

`VERSION` returns the daemon protocol version and Rust target family, not
dependency versions, compiler patch metadata, operating-system release, CPU,
or configuration flags. `TIME` is UTC rounded to the nearest second. `LINKS`
returns only configured public server names and whether each is available.

### 14.6 Account and channel controls

The vendor capabilities in Section 9 enable this closed command surface:

```text
ACCT LABEL <label-or-*>
ACCT PRESENCE PUBLIC|PRIVATE
ACCT GUEST-DM ALLOW|DENY
ACCT DIRECT-MESSAGES ALLOW|CONTACTS|DENY
ACCT CONTACT ADD|REMOVE <AccountRandomId>
ACCT NICK RESERVE|RELEASE <nickname>
ACCT DELETE START
ACCT DELETE CONFIRM <22-character-confirmation-token>
CHANCTL REGISTER <channel>
CHANCTL UNREGISTER <channel>
CHANCTL HISTORY <channel> OFF|ON|1H|24H|7D
```

Every command requires a registered, authenticated session. `*` clears the
public account label. Contact relationships are unilateral allowlist entries;
the "mutual contact" condition elsewhere in this document means both accounts
have independently added the other. An account has at most 1,000 contacts and
five reserved nicknames. `ACCT CONTACT` accepts only an immutable Account ID
and never performs a name search.

`DIRECT-MESSAGES ALLOW` accepts authenticated senders, `CONTACTS` accepts only
an authenticated sender whose Account ID the recipient has added, and `DENY`
rejects all other-account direct messages. Another session of the same account
is always permitted. Guest senders are evaluated only by `GUEST-DM` and never
inherit contact permission. The default is `ALLOW` for familiar behavior;
clients expose the stricter policies as one clear privacy control.

Account deletion requires a successful OPAQUE authentication to the same
account on this connection within the previous five monotonic minutes.
`DELETE START` creates one random 16-byte confirmation token, bound to the
Account ID, session/origin generation, current account revision, and a
60-second monotonic expiry, and returns it only as
`NOTE ACCT DELETE_CHALLENGE <token> :Confirm account deletion`. Starting again
with a new logical request consumes the old challenge. An exact idempotent
retry in the same process returns the same token and original deadline; it
never extends validity.

The first accepted `DELETE START` atomically clears `fresh_auth_at`. Its exact
idempotent retry uses the stored challenge; any new deletion or credential-
change start after that challenge is consumed or expires requires another
same-account OPAQUE authentication.

`StateCore` owns at most one deletion challenge per authenticated session in a
bounded secret map and its indexed timer heap. The raw token exists only in
that secret value and the encrypted exact request result; the map key is the
typed Session ID, and neither token nor digest enters logs, metrics, audit, a
projection, or a federation event. This challenge is deliberately not
restored: process startup has a new challenge epoch and accepts no value from
an earlier epoch. If an exact `DELETE START` result is replayed after restart,
the required exact reply may repeat its now-invalid token; `DELETE CONFIRM`
fails `BAD_STATE`, and a client obtains a usable token by issuing a new
`DELETE START` operation sequence. Native clients perform that retry
automatically without reusing the stale token.

`DELETE CONFIRM` compares the canonical token in
constant time and consumes it on every outcome. It fails unless the account
has no other live session, the confirming session occupies no channel, the
account has transferred or unregistered every registered channel it would
leave ownerless, has left every E2EE route, and has no pending companion
security transition.

Success atomically tombstones the Account ID, deletes the login index and
OPAQUE record, installs the 30-day login-hash reservation, releases nickname
reservations and outgoing contacts, invalidates authentication grants and the
confirming session, and emits its session-hidden event. Public E2EE objects,
other users' local contact entries, moderation evidence, backups, and
cryptographic tombstones follow their existing retention rules and are not
falsely claimed erased. The final NOTE is queued from the committed result and
the connection closes; another session cannot race the deletion.

`CHANCTL` requires current channel membership and owner role. `REGISTER`
requires an authenticated creator and changes an ephemeral channel to
registered. `UNREGISTER` changes it to ephemeral and destroys it immediately
if it has no members; the last owner rule and E2EE tombstone rules still
apply. `HISTORY` is accepted only for a listed, registered, plaintext global
channel and has the semantics in Section 17. Every accepted change increments
the account or channel revision and commits durably before returning
`NOTE ACCT UPDATED :Account setting updated` or
`NOTE CHANCTL UPDATED <channel> :Channel setting updated`. Syntax, stale revision,
authorization, and policy failures change nothing.

## 15. Message routing

### 15.1 Plaintext messages

`PRIVMSG` requires non-empty text; `NOTICE` permits empty text and never
causes an automatic error reply. Both validate target visibility, sender
membership/ban/mute state, channel `+m`, the recipient's guest and
authenticated-direct-message policies, and rate budget before allocating a
`MessageId`.

For channels, the authoritative channel owner creates one event and fans it
out to current memberships in `UserId` order. For direct messages, the
coordinator resolves the nickname to a `UserId` at the request revision and
routes one event. A later nick reuse never receives an earlier message.

Every accepted message receives:

```text
@msgid=<22-char-MessageId>;time=<RFC3339-milliseconds>[;account=<label>]
```

The timestamp is coordinator receive time in UTC with millisecond syntax; it
is not trusted for authorization or total ordering. The per-channel event
sequence and Message ID break equal-time ties. `echo-message` returns the
authoritative rendered message only after acceptance.

The server treats CTCP payloads as ordinary text and never executes them.
Clients in the privacy profile **SHOULD** disable automatic `VERSION`, `TIME`,
`PING`, and DCC replies. The server rejects plaintext CTCP DCC messages by
default with `FAIL PRIVMSG UNSAFE_CTCP :Unsafe CTCP command refused` because
they commonly disclose direct
network coordinates; `/me` ACTION remains ordinary text.

### 15.2 E2EE messages

On an E2EE-bound channel or direct route, plaintext `PRIVMSG` and `NOTICE` are
rejected and exact encrypted `TAGMSG` objects are routed under the companion
specification. The base message pipeline may enforce membership, size, rate,
mute, ban, and target rules but MUST NOT decrypt, rewrite, normalize,
compress, inspect, index, or moderate ciphertext content.

The base `MessageId` is not substituted for an E2EE application ID. Any outer
delivery ID is metadata and is not rendered as cryptographically authenticated
content. The companion replay and ordering rules take precedence.

### 15.3 Backpressure and fanout

Fanout never awaits a socket. Before allocating a Message ID, creating an
event, or beginning a durable commit, `StateCore` derives the complete
protocol recipient set and asks the renderer for every exact encoded frame
length without allocating a frame buffer. All frames for the same sink are
grouped in final output order into one bounded `ClientQueueDemand`; a sink is
never reserved one target at a time. It then builds one tentative
`FanoutReservation` in canonical recipient order. For each local sink,
`try_reserve` atomically reserves that whole demand or reports that the sink is
already closed or that its logical byte/item ceiling is full. A closed sink is
no longer a transport recipient. A full sink is put
on the tentative slow-consumer close list and is likewise excluded; the close
does not become visible yet.

After the queue pass, `StateCore` acquires one checked batch of global memory
permits for every distinct encoded frame buffer and every new queue-backing
allocation needed by the remaining reservations. It encodes only into those
already permitted capacities. Failure at any point drops all tentative queue
and memory reservations and changes no protocol or connection state; the
command receives `SERVER_BUSY`, except that NOTICE remains silent. Only after
the complete remaining fanout is representable does `StateCore` commit the
slow-consumer closes and transfer each sink's complete ordered frame group and
permits into its reserved queue slots. This enqueue step performs no
allocation and cannot be partially committed within or across sinks.

For a durable operation, the `MutationPlan` owns the complete
`FanoutReservation` while storage is in flight. `Rejected` or cancellation
before irreversible commit drops it. `Committed` transfers every reservation
to its sink before any success is rendered. A sink that disconnects after
reservation is a transport failure: its generation-bound reservation and
frame are discarded together, while the already accepted object and other
sinks are unchanged. Federation delivery is represented by the durable
outbox, so a full federation writer queue marks the link unhealthy and later
re-drives the same stored object; it never substitutes an untracked in-memory
copy.

Identical renderings may share one immutable accounted byte buffer. Each sink
still owns a separate queue-item reservation and its charged backing storage.
No path truncates a frame, evicts an older frame, allocates before its global
permit, or treats successful delivery to one sink as permission to skip a
failed reservation for another remaining sink.

The sender is charged before fanout using the encoded bytes and recipient
bucket. A single channel message costs:

```text
1 command token + ceil(application_bytes / 512) byte tokens
```

Fanout count does not multiply the sender's byte tokens, but the channel has a
separate aggregate fanout bucket to prevent one sender from exhausting all
recipient queues.

## 16. Moderation and user safety

### 16.1 Enforcement layers

Moderation has four independent layers:

1. a client may locally block an Account ID, Device ID, User ID, or current
   nickname without informing the server;
2. a user may reject guest or unsolicited direct messages at the server;
3. channel roles, modes, bans, mutes, invites, and kicks govern one channel;
4. network operators may suspend accounts, revoke sessions, quarantine an
   edge, or deny federation through the separate admin plane.

A local block is strongest for user autonomy and leaks least. Server and
channel blocks are needed to stop delivery and resource use. Every UI and API
must distinguish them rather than presenting one ambiguous "block" switch.

### 16.2 Mutes, bans, and sanctions

A channel mute uses the Section-13.4 `$q:<mask>` wrapper in `+b`; it prevents
`PRIVMSG`, `NOTICE`, `TAGMSG`, topic changes, and invites without removing the
membership. The canonical stored form is a typed enum, not reparsed text.
Only operator or higher may set it. Ordinary bans prevent a new join and may
be paired with a KICK to remove a current member.

Sanctions target immutable Account IDs when available. A session-only sanction
expires at disconnect. Nickname and cloak masks are convenience filters and
MUST be shown as weak, reconnectable rules. No moderator can request or reveal
a source IP through protocol commands.

Every privileged action records actor principal, target typed ID, scope,
reason code, creation time, expiry, and authoritative revision. Free-form
reasons are optional, encrypted at rest, never included in aggregate metrics,
and limited to 512 bytes. Default expiry is 24 hours for a session/nickname
rule and 30 days for an account rule; `permanent` requires owner or network
operator authority.

### 16.3 E2EE moderation

The server cannot inspect E2EE content. It may enforce outer-object validity,
membership, role, rate, size, replay, and route policy. It MUST NOT claim to
scan encrypted messages, add a hidden moderation recipient, escrow group keys,
or weaken MLS for abuse handling.

A client may locally export content it decrypted for a user-chosen external
reporting channel. `agenc.ag/report=v1` is a possible future extension and is
not advertised, parsed, or stored in version 1; the daemon has no hidden or
underspecified public report-upload path. Clients clearly state that exporting
plaintext makes that selected content visible to its recipient and never
grants access to other messages.

Removing a member from an E2EE channel is incomplete until the companion
profile finalizes the MLS Remove. While it is pending, application sending
pauses under that profile. A server-side KICK alone is never displayed as
cryptographic eviction.

### 16.4 Operator accountability

Authenticated operator actions are append-only audit events, except bounded
PING/PONG liveness traffic and QUIT. `AdminAuditPhase` is
`committed_mutation(1)`, `intent(2)`, `outcome_success(3)`,
`outcome_failure(4)`, or `observed(5)`. The canonical event is:

```text
struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque server_id[16];
    opaque audit_signing_key_id[32];
    uint64 audit_sequence;
    uint64 created_at;                      // Unix seconds
    opaque operator_id[16];
    AdminCommandTBS command_tbs;
    opaque operator_signature[64];
    AdminAuditPhase phase;
    opaque safe_outcome_code<1..64>;
    opaque previous_event_hash[32];
} AdminAuditEventTBS;

struct {
    AdminAuditEventTBS tbs;
    opaque event_hash[32];
    opaque server_signature[64];
} AdminAuditEvent;

struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque server_id[16];
    opaque audit_signing_key_id[32];
    uint64 checkpoint_sequence;
    uint64 created_at;                      // Unix seconds
    uint64 deleted_first_sequence;
    uint64 deleted_last_sequence;
    uint64 deleted_count;
    opaque deleted_last_event_hash[32];
    uint64 next_retained_sequence;
    opaque previous_checkpoint_hash[32];
} AdminAuditCheckpointTBS;

struct {
    AdminAuditCheckpointTBS tbs;
    opaque checkpoint_hash[32];
    opaque checkpoint_signature[64];
} AdminAuditCheckpoint;

event_hash = SHA256("agenc-chat admin audit event v1" ||
                    TLS-encode(AdminAuditEventTBS))
server_signature = Ed25519(
    "agenc-chat admin audit signature v1" || event_hash)
checkpoint_hash = SHA256("agenc-chat admin audit checkpoint v1" ||
                         TLS-encode(AdminAuditCheckpointTBS))
checkpoint_signature = Ed25519(
    "agenc-chat admin audit checkpoint signature v1" || checkpoint_hash)
```

The audit-signing key ID is
`SHA256("agenc-chat audit signing key v1" || ed25519_public_key)`. The embedded
operator signature must verify the embedded command TBS under the operator's
enrolled key; the accepting server signs the complete event hash with its
dedicated Ed25519 audit-signing key under the domain above. Its key ID and
event creation time must resolve in the configured historical audit trust
manifest. `safe_outcome_code` is exactly `COMMITTED` for
`committed_mutation`, `PENDING` for `intent`, `SUCCEEDED` for
`outcome_success`, `FAILED` for `outcome_failure`, or `OBSERVED` for
`observed`.
Sequence starts at zero, increments without gaps, and the first previous hash
is 32 zero bytes. Outcome codes are closed safe ASCII identifiers, not error
text. An intent and its outcome carry the same command-TBS hash. The encrypted
audit log retains 30 days by default and can be exported for independent
verification.

Retention deletes only one nonempty prefix of currently retained events per
transaction. The first checkpoint has sequence zero, deleted-first zero, and a
zero previous-checkpoint hash. Every later checkpoint increments its sequence,
starts at the previous deleted-last plus one, and names the previous complete
checkpoint hash. `deleted_count` equals `deleted_last_sequence -
deleted_first_sequence + 1` under checked arithmetic;
`next_retained_sequence` equals deleted-last plus one; and
`deleted_last_event_hash` is the already verified hash of that last event. The
first retained or subsequently appended event at `next_retained_sequence`
must name this event hash as its previous hash. The same dedicated audit key
signs the checkpoint under the separate checkpoint domain, and its key ID/time
must resolve through the audit trust manifest. Creating the checkpoint and
deleting the covered events is one immediate transaction. A gap, overlap,
fork, bad signature, or counter overflow fails closed; no further retention
deletion occurs.

Audit events contain canonical typed commands and operator reasons, but never
source addresses, client message bodies, secret keys, passwords, join keys,
invitation tokens, raw confirmation tokens, or internal errors. The signed
command TBS contains only the confirmation-token hash, so its operator
signature remains independently verifiable without retaining the bearer
token.

## 17. Persistence and history visible to users

### 17.1 Default behavior

Protocol state persistence does not imply chat-history retention. By default:

- plaintext channel and direct-message bodies are fanned out and discarded;
- E2EE application ciphertext is retained only for the bounded mailbox and
  retry periods required by the companion profile;
- registered channel policy, account records, bans, and security state are
  durable; and
- server logs never contain message bodies.

Clients that need durable personal history store it locally, encrypt it at
rest, and make that fact visible to their users. The server never tells a
client another participant did not save a message.

### 17.2 Optional plaintext channel history

An operator may enable the pinned IRCv3 `draft/chathistory` compatibility
profile for listed, registered, plaintext `#` channels. It is disabled for
secret channels, local `&` channels, direct messages, and E2EE-bound routes.
Enabling it sets channel policy `history=plaintext:<duration>`; it is not a
letter mode and requires owner confirmation.

The implementation pins the 2026-08-24 IRCv3 draft snapshot, advertises
`draft/chathistory`, `CHATHISTORY=100`, and
`MSGREFTYPES=msgid,timestamp`, and implements `LATEST`, `BEFORE`, `AFTER`,
`AROUND`, and `BETWEEN`. `TARGETS` is disabled because it creates an account
conversation index. Results require current channel membership, use the
`chathistory` batch type, preserve original `msgid` and `server-time`, and are
ordered by `(channel_event_sequence, MessageId)`.

Retention choices are exactly 1 hour, 24 hours, or 7 days; the default when
enabled is 24 hours. The coordinator encrypts records at rest, expires them by
authoritative receive time, and runs deletion in bounded batches of 1,000.
Redaction is not promised: an owner may stop future server retrieval, but
clients and recipients may retain copies. Changing retention affects only new
messages unless an explicit purge is confirmed through the admin plane.

### 17.2.1 History admission and selection

The `history` build feature and `privacy.history_enabled` are independently
required to advertise or serve history. The capability also requires `batch`,
`server-time`, and `message-ids`. Runtime history settings remain restart-only.
An authenticated owner issuing `CHANCTL HISTORY <channel> ON|1H|24H|7D`
explicitly confirms retention. `ON` selects the coordinator's configured
`privacy.history_default`; an edge never resolves this default locally.

Only ordinary channel-wide `PRIVMSG` and `NOTICE` messages are retained.
`TAGMSG`, status-restricted delivery, events, direct messages, local channels,
unregistered or unlisted channels, and encrypted routes are excluded. The
stored sender view, Message ID, authoritative receive timestamp, message kind,
body, and permitted client tags are immutable. Connection labels, batch IDs,
and authentication or connection-private tags are not retained. Rendering
filters the permitted tags through the requesting client's capabilities.

Retention admission and the corresponding message operation commit in one
durable transaction before fanout. Capacity refusal, storage failure, or an
untrusted clock refuses the history-requiring message before acceptance; the
server never silently omits required retention or evicts unexpired messages.
History writes and delivery pause while the authoritative clock is untrusted.
Destructive expiry also pauses until the Section-21.6 clock recovery condition.

Selectors preserve the pinned draft's exclusive reference boundaries.
`LATEST` accepts either `*` or one exclusive reference. `BEFORE` and `AFTER`
require one reference. `BETWEEN` permits message-ID and timestamp references
in either combination and selects in the direction from the first reference
toward the second, excluding both boundaries. Returned rows always sort by
`(channel_event_sequence, MessageId)`. A Message ID resolves to an event
position, never to the lexical order of its bytes. Limits are 1..100.
`AROUND` includes its resolved pivot, allocates floor((limit - 1) / 2) rows
before it and the remaining rows after it, then backfills an unavailable side
from the other side. A timestamp pivot is the first row at or after that time,
or the latest row if none follows. Unknown message references return an empty
batch. Empty successful selections still produce one `chathistory` batch.

Authorization is checked at request admission, after asynchronous storage
reads, and before delivery or replay. It requires the original live session,
current membership, exact channel instance, registered/listed plaintext policy,
global and channel enablement, and absence of quarantine or a hiding purge.
Membership and policy transitions invalidate pending authorization without
ordinary new messages changing an already frozen selection. The history
authorization generation advances on history-policy, visibility, quarantine,
purge, and binding transitions and never on ordinary message retention. Each query freezes
at most 100 immutable message identities. One query per origin and at most 256
queries network-wide are admitted. Each query retains at most one encoded and
rendered page of 65,536 bytes each, charged to the existing protocol pool.

### 17.2.2 Durable history and deletion

Database format 1, schema generation 2 defines History table 19 with the
existing 24-byte key `ChannelInstanceId || uint64(sequence)`. Kind 1 is a
version-1 typed HistoryMessage at a positive accepting state generation.
Kind 2 is a version-1 HistoryControl at sequence zero. The sealed-record schema
and domain envelope remain 1. Decoders validate the key, kind, body version,
channel binding, sequence, expiry, and envelope together.

HistoryControl records retain the channel identity, a nonzero history
authorization generation, sequence high-water mark,
message count, logical message bytes, monotonic purged-through watermark,
idle/active purge state, frozen cutoff, scan cursor, and durable audit-operation
identity. Counters include physically retained rows hidden by an active purge.
Message writes, control counters, deletion progress, and audit progress change
atomically. Startup authenticates all rows, recomputes the counters, and
reconstructs only bounded metadata indexes. Message bodies are loaded through
bounded exact reads when a query needs them. Missing controls, conflicting
keys, unknown versions, impossible counters, or insufficient reconstruction
memory fail closed; startup does not discard history to fit a smaller budget.

Hard admission limits are 4,096 history channels including retained controls,
262,144 messages network-wide, 65,536 messages and 67,108,864 logical message
bytes per channel. Total logical history bytes are at most
`min(1073741824, storage.database_max_bytes / 4)`. The history index is charged
from the existing protocol pool P and capped at `min(268435456, P / 8)`;
this is a ceiling within P, not another allowance. Every backing allocation,
including durable-index and control entries, is charged. Empty controls can
be reclaimed only after history is off, no purge or snapshot depends on them,
and affected replay entries are terminal. Limits are admission ceilings, not
preallocations or guarantees of message capacity under a smaller memory budget.

Each message's receive time, chosen retention, and expiry are immutable.
`OFF` stops writes and retrieval immediately; old rows remain subject to their
original expiry. History-disabled builds and configurations still authenticate
retained rows, enforce encrypted-binding exclusion, and support expiry/purge.
They advertise no history capability and admit no history service requests.

The coordinator admin command
`CHANNEL HISTORY PURGE <ChannelInstanceId> :reason` requires the existing
channel permission and a Section-22.5 signed confirmation bound to the exact
command and channel revision. Its durable cutoff hides all rows at or below
that sequence before deletion begins. Deletion uses at most 1,000 rows per
transaction and resumes from authenticated progress after interruption. New
messages above the cutoff may be retained while policy remains on. Successful
completion is reported only after physical deletion commits. Binding E2EE
requires history off, no remaining message rows, and no pending purge, checked
against the exact channel instance and revision in the binding transaction;
an empty control row is not a retained plaintext message.

### 17.3 Offline account state

Away status, channel membership, transient invites, nickname, and read state
are not restored after a disconnected session. Registered channel roles and
account sanctions persist. E2EE device mailboxes and Welcome delivery follow
their own exact retention and acknowledgment rules.

## 18. E2EE integration contract

The companion document plugs into the daemon at five typed interfaces:

```text
AccountView       -> immutable Account ID, current session/device binding
ChannelView       -> channel instance, canonical name, membership and roles
E2eeIngress       -> validated complete opaque wire object + authenticated origin
E2eeDurableStore  -> atomic object, receipt, route, replay, and mailbox transaction
E2eeFanout        -> exact immutable fragments to an authorized recipient set
```

The base daemon MUST NOT expose an API returning MLS plaintext or MLS secret
state. The E2EE relay crate validates public framing, sizes, hashes, types,
route bindings, origin state, and server authorization only. The coordinator
additionally retains each conversation's published policy chain and verifies
finality votes against it before signing a terminal certificate, and every
edge witnesses the sequencer record chain it projects; both use public objects
only. Client crypto is not linked into the daemon.

The companion `IrcFederationOrigin` is a subordinate mirror of the exact base
Server Incarnation, Origin ID/generation, Connection/Session/User IDs, Account
ID/session generation, and connection nonce; only its device attachment is
additional. The two profiles cannot advance those shared fields independently.
They do maintain separate, explicitly domain-separated contiguous operation
sequence counters inside one shared origin generation; neither profile can
fill the other's gap, and origin deletion commits both declared next values.
For recipient rendering, the coordinator derives the companion's bounded
`IrcFederationSourceView` from that same base session revision; its complete
encoding is byte-for-byte identical to Appendix-B `FederationSourceView`.
This avoids
projecting an unrelated session directory merely to render one encrypted
event and never grants authority to the copied nickname, cloak, or label.

### 18.1 Channel binding

Binding is a durable transition from `content_policy=plaintext` to
`content_policy=e2ee_bound`. It requires:

- a registered global `#` channel;
- no retained plaintext history and completed deletion of any old history;
- all current principals authenticated and represented by the approved E2EE
  binding roster;
- the exact channel instance and canonical name in the companion binding;
- owner authorization in base policy and the companion approval threshold;
- successful coordinator persistence of both base and E2EE route state in one
  transaction; and
- successful edge acknowledgment before any encrypted application send.

Binding is one-way for an existing `ChannelInstanceId`. Closing the E2EE group
does not restore plaintext. A new plaintext channel requires destruction and a
new instance; an encrypted tombstone prevents name-race downgrade as specified
by the companion document.

### 18.2 Cross-document precedence

For an E2EE route, companion rules override base behavior for:

- allowed targets and commands;
- topic and reason text;
- fragment and object limits;
- account/device requirements;
- membership-change ordering;
- policy publication, finality-vote verification, and record-chain witnessing;
- replay, receipt, finality, abort, ReInit, and recovery;
- history and offline delivery; and
- federation synchronization and collision handling.

The base daemon remains authoritative for socket admission, UTF-8 IRC framing,
CAP negotiation, session authentication, current channel routing, outer rate
limits, and output backpressure. If the two layers cannot jointly authorize an
operation, it fails closed. Section 18.4 is an additive server-state rollback
gate: it narrows what a restored daemon may emit and never relaxes a companion
validation or recovery requirement.

### 18.3 Direct conversations

Plaintext direct messages resolve a current nickname and are ephemeral.
Encrypted direct conversations resolve immutable Account IDs through the
companion reservation and semantic-route lock. A nickname change, disconnect,
or account-label change does not create a new encrypted peer. A client with a
pinned encrypted direct route MUST NOT fall back to a plaintext nickname
message after any capability, account, federation, or state failure.

### 18.4 Server recovery gate for encrypted routes

The companion governs ordinary E2EE recovery; this additional daemon gate
handles restoration of server-side state from a backup whose freshness cannot
be proven against every client. Its storage record is:

```text
enum {
    e2ee_recovery_normal(1), e2ee_recovery_pending(2),
    e2ee_recovery_conflict(3), e2ee_recovery_closed(4)
} E2eeServerRecoveryKind;

struct {
    uint16 recovery_gate_version;           // 1
    opaque conversation_id[32];
    E2eeServerRecoveryKind state;
    opaque recovery_epoch[16];
    opaque restored_binding_id[32];
    opaque restored_accepted_state_id[32];
    opaque restored_sequencer_head_id[32];
    opaque source_rollback_guard_hash[32];
} E2eeServerRecoveryGate;
```

Ordinary live routes use `normal` and the current epoch; backup restore writes
`pending` for every nonterminal route with the exact restored heads and signed
source-guard hash. While pending, the daemon rejects application ciphertext,
membership/policy/route mutation, new sequencer records, receipts, and any
operation that could reuse a generation or sequence. It permits only fetching
already-known public objects and idempotent re-upload of byte-identical,
previously signed objects whose complete predecessor chain extends the stored
heads. It never signs a missing link after restore.

If re-upload proves one continuous companion-valid chain ending in an already
finalized terminal close, one joint transaction installs that evidence, sets
`closed`, and retains the encrypted tombstone. The old route never returns to
`normal`. Two valid conflicting successors at one chain position atomically set
`conflict`, preserve both proof objects, and permanently block that lineage.
If no complete terminal evidence survives, users create a fresh semantic
lineage under a newly confirmed sequencer key set and renewed out-of-band
verification; the old pending/conflict tombstone remains. No administrator
flag clears or rewrites the gate.

## 19. Abuse resistance and resource limits

### 19.1 Hierarchical admission

Work is admitted through hierarchical token buckets. All required buckets
must have capacity before work begins; tokens are charged even when later
semantic validation fails, preventing error-oracle floods.

| Bucket | Refill | Burst | Key |
| --- | ---: | ---: | --- |
| new direct TCP | 1/second | 8 | IPv4 /24 or IPv6 /56 |
| new onion connection | 8/second | 32 | onion listener globally |
| TLS handshake | 4/second | 16 | direct prefix or onion listener |
| pre-auth command | 1/second | 10 | connection |
| registered command | 4/second | 20 | session |
| guest message | 0.5/second | 4 | session |
| account message | 2/second | 10 | Account ID |
| channel message | 10/second | 40 | channel instance |
| expensive query | 0.2/second | 2 | session |
| channel-key attempt | 1/30 seconds | 4 | Account ID; guest session plus direct prefix/onion listener |
| account creation | 1/hour | 2 | open: direct prefix/onion listener; invite: verified Invite ID |
| OPAQUE attempt | 1/3 minutes | 5 | keyed login hash |
| credential change | 1/10 minutes | 2 | Account ID |

One command consumes one command token plus byte tokens defined in Section
15. Limits are monotonic-clock based. Clock rollback cannot refill a bucket.
Operators may lower defaults or raise them up to the hard maxima below; a
configuration outside the range fails startup.

Every nonempty key in one JOIN target vector consumes one channel-key token,
and all required tokens are acquired atomically before channel lookup or a
real/dummy Argon2 job. Insufficient credit returns the same bounded
`SERVER_BUSY` class independent of channel existence and performs no lookup.
Jobs from different requests execute in bounded parallelism; one request
submits its canonically ordered key jobs sequentially and therefore owns at
most one queued-or-running slot. An ordinary complete client command has a fixed 30-second
monotonic pre-commit deadline, which includes every job. Expiry before durable
commit begins has no side effect and returns `SERVER_BUSY`; after commit begins,
Section 21.5's indeterminate/cancellation rules take precedence. Account,
fragment, batch, and E2EE exchanges with a stricter named deadline keep that
deadline.

Tor intentionally removes a stable source address, weakening per-origin abuse
controls. The onion listener therefore prioritizes authenticated accounts,
uses global pre-auth limits, and may temporarily reject new guests with
`FAIL * REGISTRATION_REQUIRED :Registration required`. It MUST NOT silently
demand deanonymization,
route Tor users to clearnet, or invent a CAPTCHA/proof-of-work protocol.

### 19.2 Hard resource maxima

| Resource | Default | Hard maximum |
| --- | ---: | ---: |
| simultaneous client connections | 50,000 | 250,000 |
| TLS handshakes in progress | 1,024 | 16,384 |
| direct connections per IPv4 /32 or IPv6 /64 | 16 | 256 |
| sessions per account | 8 | 32 |
| channels joined per session | 64 | 256 |
| members per channel | 4,096 | 65,535 |
| live global channels | 100,000 | 1,000,000 |
| live local channels per edge | 10,000 | 100,000 |
| list-mode entries per channel | 300 | 300 (100 each for `b/e/I`) |
| outstanding invites per channel | 256 | 4,096 |
| outstanding invites per target principal | 32 | 256 |
| outstanding invites network-wide | 100,000 | 1,000,000 |
| standing base-projection entries per edge | 1,000,000 | 1,000,000 |
| encoded standing base-projection bytes per edge | 512 MiB | 512 MiB |
| outstanding requests per connection | 32 | 128 |
| open response batches per connection | 4 | 16 |
| immutable query snapshots per session | 4 | 16 |
| rows across live query snapshots | 100,000 | 1,000,000 |
| bytes across live query-snapshot backing | 64 MiB | 512 MiB |
| bytes across response batch state | 64 KiB | 256 KiB |
| normal outbound queue per client | 1 MiB | 4 MiB |
| reserved control output within queue | 64 KiB | 256 KiB |
| federation outbound queue per link | 16 MiB | 64 MiB |
| durable base outbox bytes per edge | 256 MiB | 1 GiB |
| durable base outbox objects per edge | 65,536 | 262,144 |
| cross-profile event parts per edge mutation | 2,048 | 2,048 |
| encoded cross-profile event/payload bytes per edge mutation | 16 MiB | 16 MiB |
| logical live-database bytes | 80 GiB | 1 TiB |
| exact encoded backup-stream bytes | 100 GiB | 1 TiB |
| encoded tracked-record writes/deletes per durable transaction | 16 MiB | 16 MiB |
| integrity-manifest plaintext per transaction | 16,777,200 B | 16,777,200 B |
| physical-growth admission allowance per storage transaction | 256 MiB | 256 MiB |
| parsed command arena per connection | 32 KiB | 128 KiB |
| concurrent channel-key Argon2 jobs | 4 | 64 |
| concurrent account-service/OPAQUE server jobs | 8 | 128 |
| LIST/WHO snapshot rows | 10,000 | 100,000 |

Limits are checked with overflow-safe arithmetic before allocation. A zero
configuration never means unlimited. Counts use integer types capable of the
hard maximum and conversions are checked.

The two standing-projection ceilings are fixed federation-profile limits. The
byte total is the checked sum of the complete canonical encodings of all
`FederationProjectionEntry` objects for one edge, not database page size or
the sum of inner values. A replace operation subtracts the prior complete
encoding and adds the candidate complete encoding in one checked calculation;
a delete is always admissible. The coordinator maintains count and byte totals
transactionally with every edge projection, and an edge independently
recomputes them during event apply, startup, and snapshot validation. A
mismatch or over-limit snapshot is fatal. These fixed limits are exactly the
Section-20.9 snapshot limits, so every legally installed projection always has
a representable recovery artifact.

Invite admission acquires the channel, target-principal, and network counters
atomically before creating an ID; expiry, consumption, channel destruction,
or target/session deletion decrements all matching counters in the same
transaction. Account-target copies on several edges are projection entries,
not additional authoritative invites. Each live query snapshot consumes one
per-session slot plus its exact row count and charged backing capacity from
the process-wide query totals and `MemoryBudget`; admission is all-or-none.
Expiry or connection close releases all four. No cursor can allocate a second
copy of the same snapshot.

The connection, queue, snapshot, and job values above are logical admission
ceilings, not eagerly allocated capacities. In particular,
`client_output_bytes`, `federation_output_bytes`, `response_batch_bytes`, and
`parsed_arena_bytes` are per-owner ceilings. Backing storage is acquired only
as needed and only after the global memory permit described below has been
obtained. Reaching the memory budget before a logical ceiling is not permission
to overcommit: the new connection, command, fanout, or job is rejected at its
last side-effect-free admission point.

All count-scaled or peer-influenced heap storage is allocated through one
process-wide `MemoryBudget` authority owned by the root supervisor. Other
components hold non-cloneable RAII permits but cannot inspect or modify its
counter. A checked batch acquisition sums all charges first and changes the
available total once; it either returns the complete splittable permit batch
or no permit. For a requested backing allocation capacity `n`, its permit
charge is:

```text
allocation_charge(0) = 0
allocation_charge(n) = 4096 * ceil((n + 256) / 4096), for n > 0
```

The addition, ceiling division, and multiplication use checked `u64`
arithmetic. The 256 bytes cover the allocation/container bookkeeping for one
logical backing allocation; the 4 KiB rounding covers allocator size classes
and fragmentation. An object with multiple backing allocations is charged
once for each. Capacity, not current length, is charged. A shared immutable
buffer is charged exactly once, and ownership of its permit moves with the
buffer. Shrinking does not release a partial charge unless the backing
allocation is actually replaced. Implementation allocation tests MUST prove
that these charges plus the fixed charges below dominate all selected
dependency and allocator allocations; a build that does not satisfy that
proof is nonconforming.

The following fixed charges are acquired atomically before the named work is
admitted and held until the corresponding allocations and tasks are gone:

| Charge | Bytes | Lifetime and contents |
| --- | ---: | --- |
| client connection base | 65,536 | entire admitted client connection; transport tasks/state, steady-state TLS buffers, one 8,703-byte input frame, and one fatal/control output frame |
| federation connection base | 262,144 | entire live link connection; transport tasks/state and fixed framing/sequence state |
| admin connection base | 65,536 | entire admitted admin connection |
| TLS setup increment | 262,144 | from TLS-handshake admission through destruction of handshake-only allocations |
| WebSocket setup increment | 65,536 | from HTTP-upgrade admission through destruction of upgrade-only allocations |

The client base charge's control-frame allowance is not a general queue. It
guarantees that one fatal or overload response can be rendered without another
global permit, after which the writer closes the connection. All queued
application frames and any additional control frames are charged by their
actual backing capacities. Within a client queue, normal output may occupy at
most `client_output_bytes - client_control_output_bytes`; control output may
use the reserved subrange up to the total ceiling. Thus the configured control
subrange is an admission partition, not 64 KiB eagerly allocated for every
client.

Let `B = server.memory_budget_bytes`. Startup computes these exact checked
values:

```text
H = max(268_435_456, ceil(B / 8))
D = 2 * 58_720_240
C = server.crypto_worker_threads * 75_497_472
P = B - H - D - C
```

`H` is unavailable runtime/allocator headroom, `D` permanently backs both
storage handoff slots, `C` is the crypto-worker reservation pool, and `P` is
the live protocol permit pool. Underflow fails startup. `P` must also cover
one complete minimum working set for every enabled listener purpose, computed
as the maximum of the applicable rows below; disabled purposes contribute
nothing:

| Enabled purpose | Minimum working set |
| --- | ---: |
| `client_tls` or `client_onion` | `65_536 + max(262_144, allocation_charge(parsed_arena_bytes) + allocation_charge(8_703))` |
| `client_wss` | `65_536 + max(327_680, allocation_charge(parsed_arena_bytes) + allocation_charge(8_701))` |
| `federation` | `262_144 + max(262_144, allocation_charge(16_777_216))` |
| `admin_local` | `65_536 + allocation_charge(8_703)` |
| `admin_tls` | `65_536 + max(262_144, allocation_charge(8_703))` |

The maximum is a viability floor, not a permanent additional reservation.
Before accepting a socket, the listener must be below its own count ceiling,
below the applicable global count ceiling, and able to atomically acquire the
base and setup charges. A failed acquisition closes the just-accepted socket
without spawning connection tasks or beginning TLS. Setup increments are
released only after their backing allocations are destroyed. A configured
connection count is therefore a strict upper bound, not a promise that every
connection can simultaneously consume every other configured maximum.
Capacity claims are valid only for a named workload that passes Section 28.7.

Each admitted durable batch reserves 58,720,240 bytes: two copies of the
16,777,216-byte encoded-write ceiling, one 16,777,200-byte manifest plaintext,
and 8,388,608 bytes of codec/index overhead. The two-slot storage handoff is
backed by `D` in startup memory arithmetic even though
StateCore permits only one logical batch in flight. Implementations may use
less memory but cannot advertise the remainder until the reservation is
released.

`channel_key_jobs` and `opaque_jobs` bound admitted queued-plus-running jobs of
each class; `opaque_jobs` covers HPKE open/response plus the associated OPAQUE,
credential-change, or invitation work so envelope floods cannot bypass it. At most
`server.crypto_worker_threads` jobs execute concurrently.
At startup, each crypto worker contributes 75,497,472 bytes to `C` (64 MiB KSF
memory, 8 MiB conservative implementation allowance, and accounting
rounding). A worker leases its reserved slot before an Argon2 job and returns
it only after all secret buffers are zeroized and destroyed. HPKE, OPAQUE,
signature, and hashing allocations that exceed the worker's fixed allowance
also require ordinary allocation charges from `P`. `channel_key_jobs` and
`opaque_jobs` can therefore limit queues independently without multiplying
Argon2 memory beyond the fixed worker count.

### 19.3 Slow clients and overload

Outbound order is preserved in one bounded queue with reserved capacity for
the next control message. Crossing 75% sends one
`WARN * SLOW_CONSUMER :Output queue nearing capacity` when
negotiated; crossing the hard limit closes immediately. No message is evicted
to make room for a newer one.

At 80% global memory budget, the server stops accepting guests and expensive
queries. At 90%, it stops all new connections and channel creation. At 95%, it
selects whole client connections in descending charged-queue-byte order,
marks each one closing, and destroys its entire queue with the connection
until usage is below 85%. It never evicts an individual frame or reuses its
permit while the frame remains reachable. Existing authenticated messages
continue only if their complete Section-15.3 fanout reservation fits. The
process never relies on allocator failure as flow control.

Disk free space is checked before each durable batch. For the filesystem `F`
that contains the affected file, let `R(F)` be the greater of
`storage.disk_reserve_bytes` and the checked ceiling of total filesystem bytes
times `storage.disk_reserve_percent / 100`. Available bytes are the checked
product of the filesystem's blocks available to the daemon UID and fundamental
block size, not blocks reserved for root. Let
`MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH = G = 268,435,456` bytes be the fixed
version-1 maximum combined physical growth allowance for one legal redb
transaction, its guard temporary/replacement file, and required directory
metadata. A live write starts only when `database.redb`, `rollback.guard`, and
their temporary replacements resolve to the same filesystem and current
available bytes are at least `R(F) + G`.

The release artifact contains a signed storage-characterization report for
each supported `(target triple, redb version, filesystem type, filesystem block
size, mount-option class)` tuple. Using the maximum Section-23.4 transaction
shape and every replacement/deletion/insertion boundary, that report must show
that the greatest observed combined allocation is no more than 134,217,728
bytes, leaving a required twofold margin inside `G`. The
test is repeated after any storage engine, feature, allocator, filesystem, or
release-profile change. Startup identifies the actual tuple and refuses writes
when no exact passing tuple is embedded; an unrecognized platform is not
silently assigned the nearest result. This empirical gate supports the
operational reserve claim but does not turn a filesystem into a transactional
security boundary: concurrent external disk consumption or a later I/O/commit
error still enters Section 21.5's `Indeterminate` reconciliation path.

`BACKUP CREATE` is different because its complete final stream length is
already authenticated as `StateMeta.backup_stream_bytes`. Before creating the
temporary file on the backup filesystem it requires available bytes of at
least `R(F) + backup_stream_bytes`; the temporary is renamed in place and does
not coexist with a second final copy. Restore, rekey, migration, scratch-plan,
and target-construction databases cannot reserve an assumed redb file length.
They instead prove their exact logical and backup-stream ceilings in preflight
and apply this same `R(F) + G` gate independently before every scratch or
target redb transaction. They may stop safely for later `--resume` if future
space is unavailable; they never weaken `R(F)` or claim that logical bytes are
physical allocated bytes.

If an external writer consumes space after admission or a write returns a
space/commit error, the result is indeterminate under Section 21.5: no success
or ACK is emitted, the storage owner closes, and restart reconciles the
database/guard pair. New durable mutations and history remain disabled until
both reserve and logical database/backup counters are within bounds. E2EE
security transitions fail closed; they are never acknowledged from memory
only. Ephemeral plaintext delivery may continue while operators are alerted.

### 19.4 Parser and algorithmic defenses

- No untrusted regular expression is compiled or executed.
- Wildcards use a linear-time, allocation-bounded matcher.
- Maps keyed by attacker-chosen strings use a keyed collision-resistant hash
  or ordered map; protocol hashes remain SHA-256 where specified.
- Sorting is bounded by an admitted collection limit.
- Unicode preparation occurs only on fields that allow Unicode and has a
  byte/scalar bound before and after normalization.
- Decompression is absent from the application protocol and E2EE path.
- Recursive parsers are forbidden; nesting depth is explicit and capped.
- An invalid item in a batch invalidates the whole logical batch without
  partial state change.

## 20. Federation architecture and wire protocol

### 20.1 Logical topology

Version 1 uses one logical coordinator and zero or more edges. The coordinator
may also accept clients. Every edge has one direct mutually authenticated link
to the coordinator. Edges never transit traffic for other edges, form loops,
or establish an alternate coordinator based on reachability. This eliminates
server-tree ambiguity and makes the authority for every global mutation
explicit.

The coordinator owns:

- global nickname and User ID allocation;
- `#` channel creation, membership, roles, modes, invites, and destruction;
- direct-message target resolution;
- base message/event IDs and per-channel ordering;
- account/OPAQUE records and account-session generations;
- the durable idempotency, projection, outbox, and snapshot-cut state; and
- the logical E2EE coordinator/sequencer surface required by the companion
  profile.

An edge owns its sockets, local admission state, `&` channels, output queues,
and a read-only committed replica of global state. It parses and validates
locally visible outer syntax; HPKE account-service and E2EE bodies remain
opaque. A global mutation succeeds only after the coordinator returns or
broadcasts its durable result.

The initial implementation is a single durable coordinator process. Automatic
leader election is not part of version 1. A deployment may put the logical
coordinator behind a replicated state machine only if that system preserves
the exact materialized state, integrity ledger/guard, request table, E2EE
sequencer keys, mailboxes, commit atomicity, and fencing semantics. DNS
failover, shared storage without consensus, or operator promotion of a stale
backup is forbidden.

### 20.2 Link transport and trust

Federation uses a dedicated TLS listener, TLS 1.3, ALPN
`agenc-chat-fed/1`, mutual certificate validation against the network's
private CA, and static peer entries keyed by `ServerId`. The certificate SAN
contains exactly one URI:

```text
urn:agenc-chat:server:<22-character-ServerId>
```

The peer configuration additionally pins the certificate SPKI hash and an
independent Ed25519 federation public key. A certificate or key valid for the
client or admin listener is invalid here. The TLS endpoint address is
configuration-only and never propagated to clients.

An edge endpoint is exactly `tcp:<literal-ip>:<port>` (IPv6 in brackets) or
`onion:<56-character-v3-name>.onion:<port>`. An onion endpoint is sent as a
SOCKS5 hostname request to the configured local Tor proxy with SafeSocks and a
fresh isolation credential for `(Network ID, peer Server ID, incarnation)`;
the daemon performs no DNS lookup and never falls back to TCP. A coordinator
does not need or learn an edge dial address.

The configured server name is at most 127 bytes on every federation-enabled
node. Its complete serialized prefix, including leading colon and following
space, is therefore at most 129 bytes. This narrower limit makes the 260-byte
`FederationHello` encode to 347 unpadded base64url characters; the complete
untagged line including CRLF is at most 508 bytes. A longer Section-7.4 name is
legal only on a core-only node and prevents federation from being enabled.

Application frames use the IRC line envelope and the 8,703-byte ceiling from
Section 9 so the companion E2EE server commands pass unchanged. Only server
prefixes are legal. Client-only `+` tags, client labels/batch IDs, any tag not
required by the exact base or companion carrier, and arbitrary unknown
commands are fatal after registration.

### 20.3 Authenticated hello

Both peers send one `FHELLO` before any other application frame:

```text
:<server-name> FHELLO <peer-server-id> <base64url-FederationHello>
```

The binary object uses network byte order and TLS-style vectors:

```text
enum { coordinator(1), edge(2) } FederationRole;

struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque sender_server_id[16];
    opaque expected_peer_server_id[16];
    opaque server_incarnation[16];
    opaque recovery_epoch[16];
    FederationRole role;
    opaque hello_nonce[32];
    opaque profile_hash[32];
    opaque tls_exporter[32];
} FederationHelloTBS;

struct {
    FederationHelloTBS tbs;
    opaque signature[64];
} FederationHello;
```

`tls_exporter` is the RFC 9846 exporter output with label
`EXPORTER-agenc-chat-federation-v1`, length 32, and context
`network_id || min(ServerId) || max(ServerId)`. The signature is Ed25519 over:

```text
"agenc-chat federation hello v1" || TLS-encode(FederationHelloTBS)
```

`profile_hash` is SHA-256 of the exact canonical federation constants and
schema registry in Appendix B. Each side verifies the TLS identity, configured
role, network, both IDs, configured peer recovery-epoch pin, fresh nonce,
exporter equality, profile hash, and signature before replying:

```text
:<server-name> FREADY <peer-server-id> <hello-nonce>
```

The echoed nonce is the receiver's peer nonce. Hello or READY timeout is five
seconds. Duplicate, missing, mismatched, or pre-hello frames close the link.
Only an edge initiates a version-1 federation connection, and its link
supervisor has at most one live attempt. The coordinator accepts the first
complete valid FHELLO for a peer/incarnation with no live link and closes any
later duplicate; the edge cancels any superseded socket as soon as one FREADY
succeeds. A coordinator never dials an edge, so no symmetric connection tie
break is implied.

After FREADY, the companion `ECAP IRCMLS` negotiation runs. Its OFFER and ACK
bind the exact domain-separated companion-document hash as well as the
network, coordinator, limits, and sequencer key set. Base state synchronization
follows Section 20.8. The link becomes `ACTIVE` only after both base and, for
an encrypted node, E2EE profile and state are active. A companion-profile
mismatch or credential-set change follows the companion's fail-closed
reconnect transition; the base link never ignores or rewrites that failure.

A recovery epoch differing from the last accepted value is legal only after
the static peer pin was explicitly updated and the sender also uses a fresh
server incarnation. The receiver fences every old origin/cursor, does not send
`FRESUME` for the old projection, and requires a complete base snapshot plus
companion state synchronization. Cached global state from the prior epoch is
not rendered as current during this transition. A same-incarnation epoch
change, a changed epoch without a pin update, or reuse of an earlier pinned
epoch is a fatal recovery/rollback error.

After FREADY, either peer sends
`:<server-name> FPING <peer-server-id> <43-character-random-nonce>` after 15
seconds without a complete inbound frame. The peer replies
`:<server-name> FPONG <peer-server-id> <same-nonce>` immediately. The nonce is
32 random bytes in canonical unpadded base64url; only one ping may be
outstanding. Any complete valid frame resets the idle timer, but only the exact
FPONG clears an outstanding ping. Missing, unsolicited, duplicate, or
mismatched PONG closes the link; no response within ten seconds does likewise.
PING/PONG frames have no tags and do not affect request, delivery, or origin
sequences.

### 20.4 Canonical federation objects

Federation objects use the same deterministic TLS presentation encoding,
unpadded base64url rules, and SHA-256 object identity discipline as the
companion profile. There are no maps, floats, optional trailing fields,
platform-sized integers, or serde-derived wire layouts. Enum discriminants and
vector bounds are fixed below. A decoder rejects unknown discriminants,
non-minimal or out-of-range lengths, trailing bytes, and an object whose
recomputed ID differs from its carrier.

```text
object_id = SHA256("agenc-chat federation object v1" || encoded_object)
```

Large objects use the unprefixed server tag:

```text
@agenc.ag/fed=v1.<object-id>.<part>.<count>.<total>.<segment>
```

Its grammar, canonical decimal/base64url encoding, fragment size 2,940 bytes,
contiguous fragment ordering, preallocation checks, timeout, and no-truncation
rules are identical to Section 11.2 of the companion specification, with tag
name `agenc.ag/fed`. Every complete encoded `FederationRequest`,
`FederationResult`, `FederationEvent`, `FederationOrigin`, and
`FederationProjectionEntry` is 1..262,144 bytes; a component vector's written
maximum never overrides this aggregate cap. Fragment count is exactly
`ceil(total / 2,940)`, is 1..90, every nonfinal decoded segment is exactly
2,940 bytes, and the final segment is 1..2,940 bytes. A link permits at most 32
incomplete base objects and 8 MiB of base reassembly memory, exactly enough for
32 maximum objects and no more. Base and E2EE quotas are separate so one
cannot starve the other. Base reassembly, companion live reassembly, and
completed objects awaiting `StateCore` share one 16-MiB in-memory ingress
budget per link. Companion live reassembly may occupy at most its fixed 2-MiB
per-connection sublimit. Larger authenticated companion control/mailbox
objects follow its disk-spool rules; its 64-MiB per-federation-peer decoded
reassembly quota is an aggregate memory-plus-spool admission ceiling, not an
additional 64-MiB heap allowance. A completed buffer transfers its existing
permit into the reader queue instead of holding a second encoded copy.

Every descriptor line repeats the object ID as a normal parameter. The tag
object ID, descriptor ID, recomputed hash, declared total, fragment count, and
decoded size MUST all agree before dispatch. Fragments are never processed as
partial commands.

### 20.5 Requests and idempotency

An edge sends a parsed, typed request rather than forwarding a client line:

```text
@agenc.ag/fed=<fragment> :<edge-name> FREQUEST <coordinator-server-id>
  <server-incarnation> <origin-id> <origin-generation>
  <operation-sequence> <request-id>
  <request-object-id>
```

Line wrapping above is explanatory; every wire command is one IRC line. The
complete object is:

```text
enum {
    session_open(1), session_close(2), nick_change(3), join(4), part(5),
    channel_mode(6), user_mode(7), topic(8), invite(9), kick(10),
    message(11), away(12), setname(13), channel_register(14),
    channel_unregister(15), account_settings(16), history_query(17),
    directory_query(18), account_create_start(19),
    account_create_finish(20), opaque_auth_start(21),
    opaque_auth_finish(22), channel_settings(24),
    credential_change_start(25), credential_change_finish(26)
} FederationOpcode;

struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque home_server_id[16];
    opaque server_incarnation[16];
    opaque origin_id[16];
    uint64 origin_generation;
    uint64 operation_sequence;
    opaque request_id[16];
    FederationOpcode opcode;
    opaque operation<1..262144>;
} FederationRequest;
```

The descriptor parameters repeat the corresponding object fields. An
`origin_id` is a random 16-byte value allocated by the edge at accept and
remains unchanged for that transport connection; it is deliberately distinct
from Connection ID, Session ID, and User ID. Generation zero is the
pre-registration principal. Successful session registration, account switch,
logout, companion device attach/detach, or any other replacement of the
connection's security principal
increments the origin generation and resets its operation sequence to zero
only after an acknowledged `FORIGIN UPDATE` in Section 20.7.

Within one `(home_server_id, server_incarnation, origin_id,
origin_generation)`, the first operation sequence is zero and every later
logical request increments by one. The replay key is that tuple plus sequence.
The coordinator durably maps it to the exact request ID, object ID, and result:

- an exact duplicate returns the stored result without re-execution;
- a different request or object at the same key is a fatal peer violation;
- a reused request ID at another key is a fatal peer violation;
- a sequence gap returns `ORIGIN_GAP`, blocks that origin, and requires origin
  resynchronization; and
- a lower sequence without a retained exact result returns `ORIGIN_EXPIRED`
  and fences the origin.

Results and tombstones remain until 24 hours after origin deletion and at
least seven days for an account, channel-policy, or E2EE security mutation.
The companion's longer idempotency requirement wins for its operations. A new
server incarnation permanently fences all earlier incarnations for that
Server ID.

#### 20.5.1 Common operation types

```text
enum { absent(0), present(1) } Presence;
enum { account_principal(1), guest_principal(2) } PrincipalKind;
enum { channel_target(1), user_target(2) } TargetKind;
enum { privmsg(1), notice(2), tagmsg(3) } FederationMessageKind;
enum { add_mode(1), remove_mode(2) } ModeDirection;
enum { listed(1), unlisted(2), secret(3) } FederationVisibility;
enum { ephemeral(1), registered(2) } FederationPersistence;

struct {
    PrincipalKind kind;
    opaque identifier<16..24>;              // Account ID text or User ID bytes
} PrincipalRef;

struct {
    opaque key<1..255>;
    opaque value<0..256>;
} FederationClientTag;

struct {
    ModeDirection direction;
    uint16 mode_code;                       // Appendix B registry
    opaque argument<0..512>;                // exact arm encoding
} FederationModeChange;

struct { opaque value[16]; } FederationChannelId;

struct {
    FederationChannelName channel_name;
    opaque join_key<0..256>;
} FederationJoinTarget;

struct {
    TargetKind target_kind;
    opaque value<1..32>;                    // Channel ID or canonical nickname
    uint64 expected_target_revision;        // user target: zero
} FederationMessageTarget;
```

Join targets sort by canonical channel-name bytes, channel-ID vectors sort by
ID bytes, and message targets sort by `(uint16 target_kind, value)`; each is
unique. Other vectors are canonical in client-specified order unless a row
says otherwise.
`identifier` length and syntax must match its discriminant. Client tags are
sorted bytewise by key, unique, and contain only validated client-only tags.
A mode argument is empty exactly when its registered arm has no argument.

#### 20.5.2 Closed operation table

`operation` is exactly the TLS encoding of the fields in this table. An
unlisted, missing, extra, or trailing field is invalid.

| Opcode | Exact fields in order |
| --- | --- |
| `session_open` | connection ID `[16]`, optional auth-grant ID `<0..32>`, nickname `<1..32>`, realname `<0..64>`, negotiated-capability hash `[32]`, connection nonce `[32]` |
| `session_close` | session ID `[16]`, reason code `uint16` |
| `nick_change` | session ID `[16]`, expected session revision `uint64`, nickname `<1..32>` |
| `join` | session ID `[16]`, expected session revision `uint64`, `FederationJoinTarget targets<1..20>` |
| `part` | session ID `[16]`, expected session revision `uint64`, `Presence all_channels`, `FederationChannelId channels<0..256>`, reason `<0..256>` |
| `channel_mode` | session ID `[16]`, channel-instance ID `[16]`, expected channel revision `uint64`, `FederationModeChange changes<1..6>` |
| `user_mode` | session ID `[16]`, expected session revision `uint64`, `FederationModeChange changes<1..6>` |
| `topic` | session ID `[16]`, channel-instance ID `[16]`, expected channel revision `uint64`, topic `<0..1024>` |
| `invite` | session ID `[16]`, channel-instance ID `[16]`, target canonical `FederationNickname`, expected channel revision `uint64` |
| `kick` | session ID `[16]`, channel-instance ID `[16]`, target User IDs `<16..64>` as 1..4 fixed IDs, expected channel revision `uint64`, reason `<0..256>` |
| `message` | session ID `[16]`, `FederationMessageKind`, `FederationMessageTarget targets<1..4>`, `FederationClientTag tags<0..16>`, body `<0..512>` |
| `away` | session ID `[16]`, expected session revision `uint64`, away text `<0..256>` |
| `setname` | session ID `[16]`, expected session revision `uint64`, display name `<0..64>` |
| `channel_register` | session ID `[16]`, channel-instance ID `[16]`, expected channel revision `uint64` |
| `channel_unregister` | session ID `[16]`, channel-instance ID `[16]`, expected channel revision `uint64` |
| `account_settings` | session ID `[16]`, expected account revision `uint64`, canonical `AccountSettingsChange` from Appendix B |
| `history_query` | session ID `[16]`, channel-instance ID `[16]`, canonical `HistorySelector`, limit `uint16`, continuation cursor `<0..32>` |
| `directory_query` | session ID `[16]`, canonical `DirectoryQuery` |
| `account_create_start` | canonical `AccountServiceEnvelope` whose header kind is `account_create_start` |
| `account_create_finish` | canonical `AccountServiceEnvelope` whose header kind is `account_create_finish` |
| `opaque_auth_start` | canonical `AccountServiceEnvelope` whose header kind is `opaque_auth_start` |
| `opaque_auth_finish` | canonical `AccountServiceEnvelope` whose header kind is `opaque_auth_finish` |
| `channel_settings` | session ID `[16]`, channel-instance ID `[16]`, expected channel revision `uint64`, canonical `ChannelSettingsChange` from Appendix B |
| `credential_change_start` | session ID `[16]`, canonical `AccountServiceEnvelope` whose header kind is `credential_change_start` |
| `credential_change_finish` | session ID `[16]`, canonical `AccountServiceEnvelope` whose header kind is `credential_change_finish` |

For `part`, `all_channels=absent` is ordinary PART, requires 1..20 channels,
and permits the shared reason; `all_channels=present` is JOIN 0, requires the
0..256-element vector to equal every current global membership at the expected
session revision, including the empty set, and requires an empty reason. A connection with both local and global
memberships was rejected before this request under Section 14.1. For a message
target, `channel_target` has exactly 16 raw ChannelInstanceId bytes and a
nonzero exact channel revision; `user_target` has one canonical nickname and
revision zero, which the coordinator resolves to the current User ID in the
same authorization decision. This prevents an edge from needing unauthorized
directory state and prevents later nickname reuse through the durable request
result. `TAGMSG` requires exactly one target; `PRIVMSG` and `NOTICE` permit
1..4.

Join keys are present only in the request object and constant-time verifier
jobs; they are zeroized before the result is constructed. Account-service
envelopes remain byte-for-byte opaque to the edge and are opened only by the
coordinator under Section 11.2.1; the decrypted invitation is empty only for
open registration and otherwise is the exact Section-11.3 object. Auth
operations may be sent only from an unregistered origin. All other operations
except `session_open` require
that the authenticated session ID, edge, incarnation, origin, and generation
exactly match coordinator state.

### 20.6 Results and semantic replies

The coordinator answers every request exactly once logically:

```text
@agenc.ag/fed=<fragment> :<coordinator-name> FRESULT <home-server-id>
  <server-incarnation> <origin-id> <origin-generation>
  <operation-sequence> <request-id>
  <result-object-id>
```

```text
enum {
    failed(1), committed(2), session_registered(3), auth_challenge(4),
    authenticated(5), account_created(6), reply_page(7), no_content(8),
    history_page(9), history_expired(10)
} FederationResultKind;

struct {
    opaque command<1..32>;
    FederationParameter parameters<0..15>;
    Presence trailing_presence;
    opaque trailing<0..4096>;
} FederationReply;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque home_server_id[16];
    opaque server_incarnation[16];
    opaque origin_id[16];
    uint64 origin_generation;
    uint64 operation_sequence;
    opaque request_id[16];
    opaque request_object_id[32];
    opaque completion_event_id<0..16>;
    FederationResultKind result_kind;
    opaque result<0..262144>;
    FederationReply replies<0..512>;
} FederationResult;
```

`command` is either uppercase ASCII `A` through `Z` or exactly three ASCII
decimal digits and must be in the client reply registry. Middle parameters
contain no SPACE, NUL, CR, LF, or leading colon. The edge adds its
configured server prefix, negotiated tags, label/batch correlation, and CRLF;
it rejects any reply that cannot be rendered within the client limits. Results
never contain a raw client label or connection-local batch ID.

`FederationParameter` is one `opaque value<1..2048>`. `trailing_presence` is
`absent` exactly when `trailing` is empty and no trailing parameter is to be
rendered; when it is `present`, the trailing parameter may itself be empty.

The closed `result` arms are:

| Kind | Exact result fields |
| --- | --- |
| `failed` | reply code `<1..64>`, safe context `<0..255>` |
| `committed` | resulting global state generation `uint64` |
| `session_registered` | Session ID `[16]`, User ID `[16]`, session revision `uint64`, optional Account ID `<0..24>`, account-session generation `uint64`, account revision `uint64`, resulting global state generation `uint64` |
| `auth_challenge` | canonical `AccountServiceResponse` for the exact ingress request |
| `authenticated` | Account ID `<24..24>`, account-session generation `uint64`, auth-grant ID `[32]` |
| `account_created` | Account ID `<24..24>`, account revision `uint64` |
| `reply_page` | snapshot token `[32]`, page sequence `uint32`, next cursor `<0..32>` |
| `no_content` | empty tuple |
| `history_page` | Session ID `[16]`, ChannelInstanceId `[16]`, FederationChannelName, FederationHistoryAuthorization, snapshot token `[32]`, snapshot state generation `uint64`, page sequence `uint32`, next cursor `<0..32>`, FederationHistoryMessage vector `<0..100>` |
| `history_expired` | original result object ID `[32]` |

Only `reply_page` may contain more than the ordinary command's bounded reply
set; it has 1 through 512 replies and a non-empty snapshot token. Other kinds
contain only the numerics/standard replies required for that operation. A
failed result has no state event. The coordinator stores and replays the exact
result object, not a reconstructed approximation. History pages use the
exact reconstruction and terminal-expiry exception in Section 20.6.1.

For a finish request that was successfully HPKE-opened and parsed, the reply
vector also carries the exact exporter-authenticated completion before its
terminal status. Account creation uses, in order, `ACCTCREATE COMPLETE 4342`,
fourteen `ACCTCREATE DATA` lines with 400 canonical unpadded-base64url
characters, one DATA line with 190 characters, `ACCTCREATE END`, and exactly
one matching NOTE or FAIL. Credential change uses the identical sequence with
`ACCTCRED COMPLETE`, `ACCTCRED DATA`, and `ACCTCRED END`. Authentication uses fourteen `AUTHENTICATE` lines
with 400 canonical padded-Base64 characters, one with 192 characters, and
exactly one matching 903 or 904. A committed account/credential result requires
NOTE/903; a rejected completion is carried by a `failed` result and requires
FAIL/904.
A failure before successful HPKE open has no completion lines. The coordinator
constructs and stores these reply strings; the edge only renders them and may
not independently choose the completion status, Account ID, generation,
alphabet, chunk boundaries, or terminal reply.

One accepted mutation advances global `state_generation` once and may create
several logical events, as with a multi-target JOIN, PART, message, or KICK.
Every target-edge copy receives a distinct random Event ID. The mutation plan
orders copies by request-target index, then the following semantic phase, then
target Server ID, then the Appendix-B event subject key: prerequisite
`session_visible`/`channel_visible` (phase 1), the named mutation event
(phase 2), dependent membership/invite removals and `session_hidden` (phase
3), and `channel_hidden` (phase 4). Within a phase, subject keys are
Channel ID then User ID then Invite/Entry ID as applicable; absent components
are empty and therefore sort first. A phase with no applicable event is simply
absent, and a vector event such as membership recomputation occupies one
subject key rather than one event per element.
Timer, expiry, recovery-cleanup, and server-originated plans have target index
zero and sort their independent subjects by the same bytewise subject key.
After all semantic copies, the coordinator appends exactly one home-only
`request_completed` event for a `committed` or `session_registered` result.
The completion event's ID is the result's exact 16-byte
`completion_event_id`, its arm repeats
that result's resulting state generation, and it alone carries the
request-correlation tuple. Those two result kinds require the field; every
other result kind requires it empty. The edge may receive FRESULT first but
durably stores it as pending and holds its semantic replies until either (a)
that completion event and every preceding delivery sequence have committed
locally or (b) a Section-20.9 successor snapshot becomes ACTIVE with a state
generation at least the result's generation. The latter is an explicit
snapshot-coverage proof for state already represented by the installed cut;
it never applies to a result whose arm has no resulting generation. The edge
records event/snapshot coverage in its local exact request-result record before
rendering. The request result, semantic events, completion event, and all
outbox entries commit atomically at the coordinator. An exact retry
replays that same boundary; it never allocates new event IDs or renders a
partial target subset.

#### 20.6.1 History results and replay expiry

`history_query` returns `failed`, `history_page`, or `history_expired`.
A history page carries the original session and channel instance, display
channel name, frozen authorization tuple, snapshot token and state generation,
page sequence, next cursor,
and at most 100 `FederationHistoryMessage` rows. The exact fields are in the
canonical registry. The authorization tuple contains Session ID, User ID,
session generation, optional 24-byte Account ID, account-session generation,
membership revision, and history authorization generation. Its Session ID must
equal the page Session ID; account absence requires generation zero, and all
other generations/revisions are positive. The edge compares current local
session/account/membership facts and retains the coordinator token unchanged;
only the coordinator authorizes that token. Rows contain the original Message ID, positive event
sequence, receive and expiry milliseconds, PRIVMSG/NOTICE kind, public sender
view, permitted client tags, and message body. The entire encoded result and
its rendered IRC page are each at most 65,536 bytes. History results have no
completion event and no outer semantic replies; ordinary `FederationReply`
objects cannot substitute for original message prefixes and tags.

The first request has an empty cursor. Continuations use a new operation
sequence and one single-use cursor bound to the original origin, session,
channel instance, selector, limit, snapshot, and authorization generation.
They use the existing 60-second idle and ten-minute absolute snapshot limits.
A client command selects at most 100 rows across all pages. The edge starts
one connection-local `chathistory` batch, carries its original label, and
fetches each continuation only after bounded queue admission. Empty selections
still open and close a batch. Cancellation or expiry closes that batch and
returns the command's explicit failure without disconnecting unrelated clients.

RequestResult kind 5 stores coordinator history replay metadata; kind 6 stores
edge history request metadata. Both use closed version-1 bodies in database
schema generation 2. They contain the exact request/replay binding, immutable
selection and page metadata where applicable, original result digest,
expiry/authorization binding, and terminal state. They never contain retained
history message bodies. Row references in replay metadata are not storage
retention roots. They cannot carry mutation-completion or snapshot-coverage
states because history queries have no RequestCompleted event.

A successful duplicate reconstructs only the original selected rows, checks
current authorization and expiry, and verifies the original result digest.
It never reruns LATEST or substitutes another selection. If the original
selection can no longer be served, the coordinator first durably records a
terminal `history_expired` result whose body contains exactly the original
result object ID. Later retries return that same terminal result, including
after rejoin or re-enablement. This is the sole history-specific exception to
the ordinary byte-identical successful-result replay requirement. The edge
accepts only an authenticated transition bound to the exact original request
and result digest; unrelated or conflicting results remain fatal.

Edges keep page bodies only in bounded transient memory and publish them
only after durable metadata admission, current authorization checks, and
writer queue reservation. An unresolved request may be resent after link
reconnect for the same surviving client sink. A daemon restart has no surviving
client sockets, so reconstructed entries are sink-gone and never render to a
new connection. Rendered entries are terminal. A lost authority or partition
fence prevents serving queued history pages from a local cache.

### 20.7 Origin lifecycle

The edge declares origins only after the link is base-synchronized:

```text
:<edge> FORIGIN RESET <coordinator-id> <server-incarnation>
@agenc.ag/fed=<fragment> :<edge> FORIGIN ADD <coordinator-id>
  <server-incarnation> <origin-id> <generation> <object-id>
@agenc.ag/fed=<fragment> :<edge> FORIGIN UPDATE <coordinator-id>
  <server-incarnation> <origin-id> <generation> <object-id>
:<edge> FORIGIN DEL <coordinator-id> <server-incarnation>
  <origin-id> <generation> <next-operation-sequence>
:<coordinator> FORIGIN ACK <edge-id> <server-incarnation>
  <origin-id> <generation> <object-id-or-star>
:<coordinator> FORIGIN READY <edge-id> <server-incarnation>
```

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque home_server_id[16];
    opaque server_incarnation[16];
    opaque origin_id[16];
    uint64 generation;
    opaque previous_origin_object_id[32];
    opaque connection_id[16];
    opaque session_id<0..16>;
    opaque user_id<0..16>;
    opaque account_id<0..24>;
    uint64 account_session_generation;
    opaque connection_nonce[32];
} FederationOrigin;
```

Generation zero uses an all-zero predecessor. `UPDATE` increments by one and
names the exact previous object. Session and User IDs are either both empty or
both 16 bytes. Account ID is empty exactly for a guest or unauthenticated
origin, in which case account-session generation is zero. Connection ID and
nonce never change. A session registration, login, logout, account switch, or
companion device attach/detach
is represented by the next generation before requests under it are accepted;
the origin ID itself never changes during the connection.

RESET fences all live execution from that edge until it has replayed each
origin and receives READY. DEL is durable, permanently rejects later requests,
and retains the stated next sequence for replay checking. Link loss fences new
execution immediately, marks every origin on that edge suspended, and starts
one fixed 120-second monotonic grace interval. Suspended sessions cannot be a
new direct-message target or execute a mutation; their existing channel
memberships remain during the grace interval so a prompt RESET/replay can
resume without identity churn. Base events produced during that interval enter
the bounded per-edge outbox and replay after synchronization.

If READY does not complete before the grace interval, the coordinator first
commits one constant-size edge-expiry fence in `federation_peer`: the old
incarnation can no longer authorize, receive, or become a target; its
projection generation advances; and a durable cleanup cursor starts before
the fence is acknowledged. Session visibility/membership queries immediately
treat every session behind that fence as absent.

Cleanup then walks old Session IDs in byte order in transactions of at most 256
sessions and within the Section-23.4 manifest byte/record bounds. Each batch
contains one canonical `MutationPlan` and one successive state generation per
session, although several plans may share the database transaction. A plan
removes memberships/invite projections, emits exact `session_hidden`,
`invite_removed(projection_hidden)`, and channel-hidden events plus target
outbox entries, and writes the session/origin DEL tombstone with the recorded
next operation sequence. The transaction stops before adding a plan that would
cross either manifest bound. The durable cursor resumes after crash; completing it
marks the peer record clean. A later connection must use a new server
incarnation and its clients must register new sessions. TCP connects, failed
handshakes, partial RESETs, or wall-clock changes extend neither grace nor
cleanup, and cleanup latency cannot revive fenced authority.

### 20.8 Events, projection, and acknowledgments

The coordinator sends a contiguous, per-edge delivery stream:

```text
@agenc.ag/fed=<fragment> :<coordinator> FEVENT <target-server-id>
  <delivery-sequence> <event-id> <event-object-id>
:<edge> FACK <coordinator-id> <delivery-sequence> <event-id>
```

```text
enum {
    session_visible(1), session_hidden(2), nickname_changed(3),
    channel_visible(4), channel_hidden(5), member_joined(6), member_parted(7),
    channel_modes_changed(8), topic_changed(9), invited(10), kicked(11),
    away_changed(12), display_name_changed(13), message_delivered(14),
    channel_destroyed(15), account_label_changed(16), network_notice(17),
    user_modes_changed(18), channel_policy_changed(19),
    channel_memberships_recomputed(20), account_state_changed(21),
    request_completed(22), invite_removed(23)
} FederationEventKind;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque target_server_id[16];
    uint64 projection_generation;
    uint64 coordinator_state_generation;
    uint64 delivery_sequence;
    opaque event_id[16];
    FederationEventKind event_kind;
    opaque event<1..262144>;
    opaque cross_profile_mutation_id<0..16>;
    uint16 cross_profile_part_index;
    uint16 cross_profile_part_count;
    opaque request_home_server_id<0..16>;
    opaque request_server_incarnation<0..16>;
    opaque request_origin_id<0..16>;
    uint64 request_origin_generation;
    uint64 request_operation_sequence;
    opaque request_id<0..16>;
} FederationEvent;
```

`coordinator_state_generation` is the one resulting global state generation that produced
the event. All semantic copies and the completion event for one accepted
mutation carry the same value. Values in one projection-generation stream are
nondecreasing; duplicate generations are expected, and a decrease is fatal.

The three cross-profile fields form one closed optional tuple. An absent tuple
has an empty mutation ID and zero index/count. A present tuple has an exact
16-byte mutation ID, `cross_profile_part_count` in `2..2048`, and a zero-based
index strictly less than that count. Any other combination is invalid.

When one coordinator `MutationPlan` creates at least one base event and at
least one companion event for the same target edge, every event for that target
from that plan participates in one cross-profile barrier. The coordinator
samples a fresh uniformly random mutation ID separately for each target edge,
rejects a collision with any retained ID, and stores it with the plan; retries
reuse it byte-for-byte. IDs are never shared between target edges. If `B` base
events and `E` companion events target the edge, the `B + E` count is present
on every part, base events receive indices `0..B-1` in their ordinary delivery
order, and companion events receive indices `B..B+E-1` in their ordinary
delivery order. Both counts are nonzero. A plan targeting only one profile at
that edge uses the absent tuple. No implementation or operator may choose a
barrier based on whether a particular event is expected to render output.

The participating events are contiguous in each contributing delivery stream,
carry the same target Server ID and nonzero coordinator state generation, and
have a checked aggregate of at most 16,777,216 bytes. That aggregate is the sum
of every complete event-object encoding plus the complete required payload/data
object for each part that has one; a referenced object is charged again for
each part that references it. More than 2,048 parts or a larger aggregate rejects
the initiating operation before any state, sequence, ID, package, or mailbox
consumption: a base request receives `SERVER_BUSY` and a companion request
receives `E2EE_SYNCING`.

The 2,048-part ceiling is above the largest version-1 target-specific plan
under the other fixed maxima. A last local session can own at most 256
memberships and 256 target-principal invites, hence at most 512 distinct local
channel entitlements. Its maximal teardown uses one `session_hidden`, at most
256 invite removals, at most 512 channel hidden/destroyed copies, at most 512
companion route-hidden copies, and one home completion: 1,282 parts. Opening a
session with every invite needs no more than one session event, one account
projection event, 256 invite events, 256 channel-visible events, 256 companion
route projections, and one completion: 771 parts. Other version-1 operations
have smaller request-vector maxima. Raising any contributing maximum without
reproving this inequality requires a new federation profile; unused headroom is
not permission to invent another event vector.

The four variable correlation IDs are either all present at their fixed
lengths or all empty; the two numeric correlation values are zero when empty.
They are present exactly on `request_completed`, which is sent only to the
request's home edge, and empty on every other event kind. Event arms are the
exact canonical state/event records in Appendix B, not raw IRC lines. Unknown
kinds or trailing bytes are fatal.

Projection is least-information delivery:

- there is no replicated global channel directory: `LIST`, nonlocal `NAMES`,
  `WHO`, `WHOIS`, `TOPIC`, and channel-mode/list queries use the bounded
  coordinator query path in Appendix B;
- an edge receives one channel-detail record only while it hosts a current
  member of that channel or an unconsumed, unexpired invite whose target is a
  local User ID or Account ID;
- an edge retains membership records only for sessions whose home is that
  edge, and invite records only for targets hosted by that edge; it never
  retains a remote channel's complete membership, invite, account-grant, or
  mode-list set;
- a complete session record is projected only to that session's home edge;
  other entitled edges receive the bounded event-scoped pseudonymous source
  view in Appendix B and discard it after rendering and replay validation;
- a home edge receives one account projection while it hosts at least one
  session for that account, and no other edge receives that projection merely
  because it sees a remote source view;
- direct messages go only to sender and recipient home edges;
- channel messages and semantic events go only to edges with current local
  recipients; and
- login identifiers, Account IDs of remote users, home-server routes, OPAQUE
  material, source addresses, join keys, admin evidence, and unrelated account
  state never enter a projection or source view.

The first local entitlement to an existing channel therefore adds at most one
channel detail plus the joining local membership or targeted invite; it never
copies pre-existing remote members or mode-list entries. `channel_visible`
precedes that membership/invite event in the same coordinator mutation. When
the last local entitlement disappears, all local child entries have already
been removed in delivery order and `channel_hidden` removes the one remaining
detail. Each mutation computes the exact encoded standing-projection entry and
byte deltas before commit and rejects with `SERVER_BUSY` if either fixed
Section-19 projection ceiling would be crossed. It does not fall back to a
partial projection, a bulk event, or an implicit snapshot.

When an edge loses its last reason to see an object, it receives a hidden event
and must erase the projected state before ACK. Delivery sequence starts at
zero for each projection generation. The edge persists event application and
its new sequence atomically, then ACKs. `FACK` is cumulative through its named
sequence and is accepted only when the Event ID matches that exact delivered
row; outside the cross-profile rule below it may advance by exactly one.
Duplicate exact events at the installed cursor re-ACK; a gap, conflict, or
event under another generation blocks global processing and starts snapshot
recovery.

For a cross-profile barrier, the coordinator first commits every base and
companion outbox part in the originating state transaction. It sends the
complete contiguous slices on both active profiles without waiting for an
intermediate ACK and sends no later event on either stream to that edge until
the barrier is acknowledged. Cross-profile rows are admitted against both
profiles' unacknowledged row/byte ceilings and are never evicted, converted to
a base snapshot, or partially committed. Insufficient capacity rejects the
whole mutation with the initiating profile's overload result.

The edge persists a barrier with the deterministic Appendix-B.1 encoding and
these closed storage types; these are database types, not new federation wire
objects:

```text
enum { cross_profile_base(1), cross_profile_companion(2) }
    CrossProfileStream;

struct {
    uint16 barrier_storage_version;         // 1
    opaque network_id[32];
    opaque coordinator_server_id[16];
    opaque coordinator_server_incarnation[16];
    opaque coordinator_recovery_epoch[16];
    opaque target_server_id[16];
    opaque target_server_incarnation[16];
    opaque mutation_id[16];
    uint64 coordinator_state_generation;
    uint16 part_count;
} CrossProfileBarrierIdentity;

struct {
    CrossProfileBarrierIdentity identity;
    uint16 received_count;
    opaque received_bitmap<1..256>;
    uint64 aggregate_event_payload_bytes;
} CrossProfileBarrierStage;

struct {
    CrossProfileBarrierIdentity identity;
    CrossProfileStream stream;
    uint16 part_index;
    uint64 delivery_generation;
    uint64 delivery_sequence;
    opaque event_id[16];
    opaque event_object_id[32];
    opaque encoded_event_object<1..262344>;
    opaque payload_object_id<0..32>;
    uint32 payload_object_bytes;
} CrossProfileBarrierPart;

struct {
    CrossProfileStream stream;
    uint16 part_index;
    uint64 delivery_generation;
    uint64 delivery_sequence;
    opaque event_id[16];
    opaque event_object_id[32];
    opaque payload_object_id<0..32>;
} CrossProfileBarrierReceiptEntry;

struct {
    CrossProfileBarrierIdentity identity;
    uint64 applied_storage_commit_sequence;
    uint64 applied_local_state_generation;
    uint64 applied_at;
    uint64 retain_until;
    uint64 aggregate_event_payload_bytes;
    CrossProfileBarrierReceiptEntry entries<2..2048>;
} CrossProfileBarrierReceipt;
```

`delivery_generation` is the base projection generation for a base part and
the E2EE delivery generation for a companion part. A base part's encoded event
is the complete canonical `FederationEvent`, and its Event Object ID is the
Section-20.4 hash; it has an empty payload ID and zero payload bytes. A
companion part's encoded event is the complete canonical `IrcWireObject` of
kind `federation_event`, and its ID is the companion object hash. Its payload
fields are empty/zero exactly for an event whose selector has no data object;
otherwise the ID is 32 bytes, the length is `1..4,194,304`, and table 22
contains the byte-identical validated `IrcWireObject` under that ID before the
part is marked received. An otherwise-unused staged payload is inert: no
route, mailbox, result, fetch, or client output may reference it until apply.
The payload row is inserted only if absent; an existing row must match kind,
length, ID, and bytes exactly. Stage parts and applied receipts are retention
roots for that object, in addition to its ordinary companion retention roots.

The 262,344-byte event bound is the exact maximum encoding of the base
`FederationEvent`; the smaller companion control-object bound still applies to
a companion part. The stage aggregate is the checked sum, over every received
part, of `len(encoded_event_object) + payload_object_bytes`. It equals the
complete barrier aggregate at apply. The bitmap length is exactly
`ceil(part_count / 8)`, bit `i` records complete part `i`, unused high bits in
the final byte are zero, `received_count` is its population count, and the
part rows present under the identity are exactly those set bits.

All barrier rows are schema-one sealed values in table 23. Their stored keys
are exact byte concatenations:

```text
head_key = ASCII("cross-profile/head/v1/") ||
           coordinator_server_id || coordinator_server_incarnation ||
           mutation_id
part_key = ASCII("cross-profile/part/v1/") ||
           coordinator_server_id || coordinator_server_incarnation ||
           mutation_id || uint16(part_index)
```

The head key is 70 bytes, the part key is 72 bytes, and the index is network
byte order. No other table-23 key starts with either prefix. A collecting head
contains exactly one `CrossProfileBarrierStage`; an applied head at the same
key contains exactly one `CrossProfileBarrierReceipt`. The coordinator's
table-11 peer row contains either an empty open-barrier key or that exact
70-byte head key. A stage insert/replace and peer pointer, and later a receipt
replacement and pointer clear, are integrity-tracked in their respective
transactions. The identity's target fields equal the current database header
and authenticated link; its coordinator fields equal the accepted peer
incarnation/recovery epoch. Any mismatch is corruption rather than a cleanup
hint.

`StateCore` owns at most one `CrossProfileBarrierStage` per coordinator link.
It accepts only the exact next contiguous event on either contributing stream,
durably stages each complete event as one immutable part record, installs any
required companion payload object, and replaces the small bitmap/header in the
same transaction without
advancing either applied/ACK cursor. A staging transaction is integrity-
tracked but does not advance the edge's externally meaningful protocol state
generation. Staging produces no client output and does not cover a request
result. An exact duplicate complete part performs no write; a duplicate index
with any different carrier, event, or payload field is fatal. Once all indices
`0..count-1` are
present, it verifies the common ID, target, generation, count, index partition,
stream contiguity, aggregate byte count, and all base/companion cross-
references. It then acquires one combined `MemoryBudget` and
`FanoutReservation` for every resulting local frame before opening the apply
transaction.

One immediate edge database transaction applies all base projection and
companion route changes, records all completion-coverage/result markers and
pending fanout, advances both applied cursors through their participating
slices, and changes the header to an applied receipt indexing every
`(profile, delivery generation, delivery sequence, Event ID, object ID)` tuple.
The immutable part/payload records are not rewritten or deleted in this
transaction; the receipt references them through the replay window, after
which ordinary bounded retention transactions remove them.
Only after commit are frames made visible; the edge then sends one cumulative
FACK for the final base part and one cumulative EACK for the final companion
part. Neither ACK may be sent alone. A result whose completion is a barrier
part cannot render until this transaction commits.

Receipt entries are in strictly increasing part-index order and cover exactly
`0..part_count-1`. Their fields equal the immutable part rows. The two applied
counters equal the successor StateMeta written by the apply transaction.
`applied_at` is the authoritative edge receive time for that commit and
`retain_until` is its checked addition of 604,800 seconds. The receipt, every
part, and their payload retention roots remain until that time, both final ACKs
have been durably covered by the peer state, and every correlated request
result has reached its independently required retention boundary. Cleanup is
one bounded ordinary transaction series and never changes applied cursors.
An open stage has no time-based expiry while its peer incarnation remains
accepted. Once a different authenticated coordinator incarnation/recovery
epoch is permanently accepted, the old stage cannot apply; the same peer-fence
cleanup that invalidates old cursors deletes its head/parts and releases only
payload roots not retained elsewhere.

Allocation, reservation, storage, cancellation, or link failure leaves all
received parts staged and both applied cursors unchanged. Reconnect resumes
from the durable applied cursors and retransmits the same barrier. A complete
matching replay of an already applied barrier is answered with the two final
cumulative ACKs without reapplication or rerendering; the compact receipt is
retained for the longer of the base and companion idempotency windows. A
conflicting part, repeated index with different bytes, second open barrier,
cross-profile generation mismatch, or later-stream event before the barrier
finishes is fatal. A same-incarnation FSNAPSHOT/ESTATE reset cannot supersede
an open or unacknowledged barrier; it must finish first.

A base `request_completed` event may arrive before its FRESULT after link
reconnect. The edge resolves the event's complete correlation tuple to the
exact retained outbound request before applying it. If the result is already
present, the event transaction marks that exact result event-covered. If the
result is absent, the same transaction writes a `completion-coverage` arm in
`request_result`, keyed by the complete replay key and containing the retained
request-object ID, completion Event ID and object ID, projection generation,
delivery sequence, and coordinator state generation. This arm is evidence of
delivery only: it is not a result, renders nothing, and cannot advance the
origin operation sequence.

Later FRESULT arrival must match every replay field, the retained request-
object ID, completion Event ID, and generation. Its storage transaction links
the exact result to the coverage arm and changes the rendering state to event-
covered; only post-commit rendering to the still-live matching sink is then
allowed. A result-first arrival remains pending until the event or the explicit
Section-20.9 snapshot proof. A mismatch, a completion for an absent retained
request, or conflicting second result is fatal rather than guessed. A
`sink_gone` marker suppresses rendering in either arrival order. Coverage
records use the request/result retention in Section 20.5: at least 24 hours
after origin deletion and at least seven days for account, channel-policy, or
E2EE-security mutations. A cross-profile completion writes or consumes this
arm only in the combined barrier transaction above.

For cursor replay, the coordinator targets 24 hours of ACKed events while
retaining at most 1,000,000 events and 1 GiB of event/object bytes per edge.
Reaching either cap first marks the old generation snapshot-required and
permits deletion only after the successor snapshot cut durably covers every
retained state mutation. Message bodies may be discarded after all target
edges ACK unless history/mailbox policy requires longer retention.
Security-state evidence follows its longer table retention even when its
delivery object is replaced by snapshot state.

The unacknowledged base outbox is independently bounded by the configured
per-edge object and byte limits in Section 19.2. Before an append would exceed
either limit, the coordinator atomically fences that projection generation,
marks the edge snapshot-required, and stops targeting new ephemeral base
messages to it. State mutations continue because their successor state will be
in the snapshot; exact request results and security/audit evidence remain in
their own retention tables. If the link was active, it is closed and its
origins enter the Section-20.7 grace interval. No base outbox eviction can
delete a companion mailbox/object or weaken companion retention.

### 20.9 Snapshot and resume protocol

After FREADY, an edge attempts:

```text
:<edge> FRESUME <coordinator-id> <projection-generation>
  <last-delivery-sequence-or-star> <last-event-id-or-star>
```

If the exact cursor is retained, the coordinator replies `FRESUME OK` and
replays the next event. Otherwise it replies `FRESUME SNAPSHOT` and sends:

```text
:<coordinator> FRESUME OK <edge-id> <projection-generation>
  <next-delivery-sequence>
:<coordinator> FRESUME SNAPSHOT <edge-id>
```

Exactly one reply is sent. `next-delivery-sequence` is zero for an empty
projection or one greater than the accepted cursor; overflow forces SNAPSHOT.
The reply parameters must match the authenticated edge and requested
generation. A SNAPSHOT reply is immediately followed by:

```text
:<coordinator> FSNAPSHOT BEGIN <edge-id> <snapshot-token>
  <recovery-epoch> <projection-generation> <state-generation>
  <entry-count> <snapshot-digest>
@agenc.ag/fed=<fragment> :<coordinator> FSNAPSHOT ENTRY <edge-id>
  <snapshot-token> <entry-index> <entry-object-id>
:<coordinator> FSNAPSHOT END <edge-id> <snapshot-token>
  <last-delivery-sequence-or-star> <last-event-id-or-star>
:<edge> FSNAPSHOT READY <coordinator-id> <snapshot-token>
  <recovery-epoch> <projection-generation> <state-generation> <snapshot-digest>
:<coordinator> FSNAPSHOT ACTIVE <edge-id> <snapshot-token>
  <recovery-epoch> <projection-generation> <state-generation> <snapshot-digest>
```

Snapshot entries are canonical `FederationProjectionEntry` objects from
Appendix B, strictly sorted by `(entry-kind, primary-ID bytes)`, indexed from
zero without gaps, and limited to 1,000,000 entries and a checked sum of
536,870,912 complete encoded entry-object bytes. BEGIN values exceeding either
fixed standing-projection ceiling are rejected before allocating or opening a
pending generation. The digest is:

```text
SHA256("agenc-chat federation snapshot v1" ||
       TLS-encode(recovery_epoch, projection_generation, state_generation,
                  ordered_entry_object_ids))
```

`recovery-epoch` is the 22-character encoding of the coordinator FHELLO field
on this exact link. A mismatch is fatal. An edge persists that epoch with the
installed generation and may attempt `FRESUME` only when it equals the current
authenticated coordinator epoch; otherwise it requests a full snapshot.

The edge writes entries into a new storage generation, verifies count, order,
IDs, cross-references, digest, and E2EE/base route consistency, and atomically
installs the verified generation as pending before READY. A snapshot is a
state-recovery mechanism, not an event-replay substitute visible as seamless
continuity. Before sending READY, the edge durably advances its local
`client_resync_epoch`, marks every registered global-client origin
`sink_gone`, emits at most one reserved-control `ERROR :Network state
resynchronization required; reconnect` per such connection, and closes those
connections. It retains the corresponding origin DEL work until the base
projection is active. Local-only `&`-channel connections cannot coexist with
global memberships under Section 14.1 and are unaffected.

The old projection may answer only internal validation needed to finish the
download; no client reads it and it accepts no global mutations or messages.
After READY the edge uses neither generation until matching ACTIVE. Receipt of
ACTIVE atomically swaps the pending generation into active state, applies the
coverage rule below, and then permits replay of events after the snapshot
cursor. It next completes `FORIGIN RESET`, replaying DEL for every closed
origin before accepting a new global registration. A pending result for a
`sink_gone` origin may become event- or snapshot-covered for cleanup but is
never rendered to a different connection or origin. Consequently a missed
JOIN, PART, KICK, MODE, TOPIC, or message is never silently replaced by a
state image while an ordinary client believes its session remained
continuous; the native client reconnects automatically and obtains a normal
fresh registration/join burst.

The ACTIVE transaction also examines the edge's durable pending
`FederationResult` records in replay-key order. A pending `committed` or
`session_registered` result is snapshot-covered exactly when its resulting
state generation is no greater than the installed cut and its home Server ID,
incarnation, origin, generation, operation sequence, request ID, request-object
ID, and completion-event ID still match the exact stored request. The same
transaction marks every such record covered; rendering occurs afterward in
origin/operation order only for a still-live matching sink. A `sink_gone`
record becomes cleanup-eligible but is never rendered. This rule lets a
snapshot replace an unacknowledged
completion event without stranding a committed client request. It does not
invent a result, cover a failed/auth/query result, cross an origin fence, or
claim that a remote edge ACKed delivery.

Snapshot coverage never substitutes for any part of a cross-profile barrier.
A result whose completion Event ID belongs to such a barrier is ineligible for
the rule above unless the compact applied receipt already proves the complete
combined transaction, in which case it is event-covered rather than newly
snapshot-covered. The coordinator likewise cannot delete or reclassify either
profile's barrier rows at READY. A same-incarnation recovery must replay and
finish the barrier before constructing the paired FSNAPSHOT/ESTATE cut.

The coordinator may delete an old-generation completion-event outbox copy only
after either its ACK is durable or it has durably recorded a matching READY for
a successor snapshot whose cut covers the result generation. READY proves the
edge already persisted the verified pending generation; ACTIVE is the
coordinator's replayable authorization to use it. If the link fails after
READY, the edge re-sends the exact READY after the next authenticated FREADY,
and the coordinator returns the byte-identical ACTIVE without rebuilding or
advancing the snapshot. A conflicting READY/token is fatal. The exact
coordinator request result and completion Event ID retain their ordinary
replay lifetime; an exact retry after snapshot returns the same result, which
the edge can match to its durable coverage marker.

Snapshot token is 32 random bytes, expires after 15 minutes, and has one live
instance per edge. An error discards the incomplete generation. Base ACTIVE
does not override the companion `STATE_ACTIVE` gate; both are required on an
encrypted node.

### 20.10 Partitions and coordinator recovery

When the coordinator link is unavailable, an edge:

- keeps TLS sessions alive and serves PING, local `&` channels, cached MOTD,
  and strictly local account-independent queries;
- rejects new registration, authentication, global nickname changes, `#`
  JOIN/PART/MODE/TOPIC, global messages, and account mutations with
  `FAIL <command> NETWORK_UNAVAILABLE`;
- never guesses success, assigns global IDs, buffers unbounded mutations,
  elects itself, or converts E2EE to plaintext; and
- may queue at most one reconnect attempt per configured backoff interval,
  using full jitter between 1 and 60 seconds.

After coordinator restart, it opens and verifies durable state before
listening, retains its `ServerId`, and retains its incarnation only if the
request-result table, authenticated integrity chain/guard, and projection
cursors are intact. Losing any of them requires a new incarnation and forces
all edges through full origin and snapshot synchronization. Every backup
restore, whether lower or not, requires an operator-declared network recovery
epoch and client-visible security warning; it cannot masquerade as normal
continuation.

## 21. State ownership and concurrency

### 21.1 Ownership rule

Each mutable datum has exactly one runtime owner. Sharing read-only immutable
snapshots is permitted; sharing mutable protocol maps behind `Arc<Mutex<_>>`
is not. The version-1 implementation uses one `StateCore` actor per process as
the sole owner of:

- sessions and nickname indexes visible to that process;
- local-channel state;
- the coordinator's complete global state, when in coordinator role;
- an edge's installed federation projection, when in edge role;
- timers that mutate protocol state;
- rate-bucket state after transport admission;
- current-process account-deletion challenges and challenge epoch;
- immutable coordinator query snapshots and their count/row/byte permits;
- the edge's durable client-resync epoch and pending closed-origin DEL work; and
- staged mutation plans and their revisions;
- the one optional cross-profile barrier head and its combined apply
  reservation per coordinator link; and
- every in-flight durable batch's domain plans, client/federation fanout
  reservations, sink generations, and sole completion receiver.

The root supervisor owns the process-wide `MemoryBudget` authority and
listener admission semaphores. Handles may acquire and transfer opaque
permits, but only that authority changes the global available-byte ledger.
Each connection supervisor owns its queue storage and socket generation;
for at most one global JOIN barrier it also owns the bounded
`JoinNamesContinuation`, its local label/batch context, and its query-cursor
handle. `StateCore` may hold only the rollback-capable queue reservations
described in Section 15.3. Connection tasks own sockets and transport-only metadata. The
storage thread owns the database handle and every write transaction. Crypto
workers own temporary HPKE, OPAQUE, Argon2, signature-verification, and hash
buffers until they return a value. No other component mutates these resources.

Account-service completion uses an explicit two-continuation type state so
StateCore never performs cryptography and a crypto worker never commits domain
state. After HPKE `Open`, the worker returns one parsed, bounded
`OpenedAccountRequest` plus a move-only, non-`Clone`, zeroizing
`AccountResponseSealToken` containing only the unexpanded HPKE exporter
material and authenticated request binding. StateCore verifies the
request/transaction, acquires one move-only `AccountResponseCountPermit` only
after checked addition proves that the committed count plus all pending
permits is at most `uint64::MAX`, and creates one
`PendingAccountCompletion` that freezes the affected account/session
revisions, chooses the exact rejected or committed completion plaintext and
terminal reply, and owns both tokens. It rejects only conflicting operations
with `BAD_STATE`; unrelated state may continue.

StateCore moves the token and plaintext into exactly one
`SealAccountCompletion` crypto job together with the current recovery epoch,
expected response kind, and authenticated request binding. The worker samples
the salt, derives the one-use key/nonce, seals once, and erases the exporter.
The result repeats a fresh internal job ID, the account-service transaction ID,
response header, and exact 4,342-byte response; StateCore accepts it only for
the matching pending plan. The seal token is consumed and cannot return from
the job. StateCore then
constructs the single Section-23.4 storage batch containing the still-current
precondition revisions, semantic mutation or terminal rejection, response
reply strings, request result, events, completion record, and exact successor
`account_service_response_count`. No response byte or success status is
visible before `Committed`. A semantic `rejected` completion is a normal
durable batch. A `StoragePort::Rejected` outcome instead discards the plan and
sealed response, releases the count permit, and makes no state change or
protocol response. A compatible batch may contain several such plans; its
successor count is the prior committed count plus exactly its number of count
permits in canonical plan order.
`Indeterminate` emits
nothing, closes the state owner, and relies on restart reconciliation. A lost completion sender,
job-ID mismatch, duplicate crypto result, token reuse, or impossible AEAD
failure is internal corruption and fail-closes the account service rather than
emitting an unauthenticated fallback. Every pre-seal drop path zeroizes the
exporter token; every later failure drops the completion plaintext and sealed
response and releases the count permit exactly once.

### 21.2 Task tree

The root supervisor owns and joins this bounded tree:

```text
Supervisor
├── SignalTask
├── StateCoreTask
├── StorageThread
├── CryptoPool (fixed workers)
├── ListenerSet
│   └── ConnectionSupervisor (one per admitted connection)
│       ├── ReaderTask
│       └── WriterTask
├── FederationLinkSupervisor (one per configured peer, maximum 64)
│   ├── FederationReaderTask
│   └── FederationWriterTask
└── MaintenanceTask
```

No task is detached. Every spawn requires an owned cancellation token, a
supervisor registration, and a bounded completion path. A failed critical
task cancels the tree; a failed client connection cancels only that connection;
a failed federation link enters its reconnect state. Panics are bugs, not
recoverable protocol outcomes, and cause controlled process termination after
the panic hook emits a body-free crash identifier.

Connection supervisors are created only after acquiring both global and
listener admission permits. A permit lives until both reader and writer have
joined. Rejected accepts never spawn a task.

### 21.3 Bounded channels

| Channel | Capacity | Full behavior |
| --- | ---: | --- |
| connection reader -> StateCore | configured `requests_per_connection` / `parsed_arena_bytes` | pause socket reads, then close after 30 s |
| StateCore -> connection writer | Section 19 byte budget | close slow consumer |
| federation reader -> StateCore | 256 objects / 16 MiB | stop link reads; reconnect after 30 s stall |
| StateCore -> federation writer | 1,024 objects / configured `federation_output_bytes` | mark link unhealthy; no state loss |
| StateCore -> storage | 2 mutation batches | stop admitting new mutations |
| storage -> StateCore | 2 completions | storage thread blocks on completion handoff |
| StateCore -> crypto pool | 2 x worker count | return `SERVER_BUSY` before enqueue |
| signal/maintenance -> StateCore | 64 events | coalesce identical maintenance events |

Byte capacity is tracked separately from item capacity and reserved before an
item is cloned or encoded. Queue ownership transfers the reservation; drop or
dequeue releases it exactly once. No Tokio unbounded channel is present in the
dependency graph.

A tentative client queue reservation names the connection generation, bounded
ordered vector of exact encoded byte counts, corresponding item slots, and
exact additional backing-allocation charge, which may be zero when existing
backing suffices. The whole demand succeeds or fails; no prefix reservation is
observable. Dropping it rolls back every logical count. After the global batch acquisition, `prepare` consumes the
matching optional `MemoryPermit`, creates only that backing allocation, and
returns a prepared reservation; allocation failure rolls back the complete
fanout before any visible effect. Committing a prepared reservation transfers
its counts and backing permit into the writer queue without allocation. The
connection supervisor keeps the queue generation alive until every
outstanding reservation is committed or dropped; if transport cancellation
has already begun, commit discards the frame and releases its permits as one
operation. Thus queue close cannot turn a reservation into a write to a later
connection or leak capacity.

The federation reader's 16-MiB byte capacity is the same per-link ingress
budget used by Section 20.4, not an additional reservation. Incomplete base
and live E2EE objects, completed in-memory objects, decoder scratch, and queued
reader items draw from that one budget. Spool-backed companion objects enqueue
only a bounded authenticated descriptor; their bytes remain charged to the
companion disk/account/route/peer quotas until consumed or expired.

### 21.4 Input pipeline

Each incoming client message moves through explicit, testable phases:

```text
bounded framing
  -> syntax parse
  -> canonical typed command
  -> connection-state validation
  -> semantic lookup
  -> authorization
  -> rate/resource admission
  -> MutationPlan or QueryPlan
  -> durable commit when required
  -> in-memory apply
  -> semantic result/event
  -> capability-aware rendering
  -> bounded output enqueue
```

Each phase consumes a type that proves the previous phase succeeded. A raw
`String`, unchecked integer, or user-provided name cannot cross directly into
authorization or storage. Rejection before commit has no state effect. After
commit, application of the already-validated plan is infallible by type; an
unexpected failure terminates the process and startup reconstructs the
authoritative materialized state before accepting traffic.

Command handlers use guard clauses and small named decisions. A handler that
mixes parsing, policy, database I/O, and rendering is rejected in review.
Functions over roughly 60 logical lines, nesting deeper than three control
levels, or cyclomatic complexity above 10 require an explicit decomposition
review; these are review triggers, not excuses for mechanical code splitting.
Numeric limits and protocol literals live in typed registries, never inline as
unexplained magic values.

### 21.5 Durable mutation batches

`StateCore` maintains at most one durable batch in flight. It gathers up to
256 compatible plans or one millisecond of work, whichever comes first. Each
pure domain `MutationPlan` records all expected revisions, logical storage
writes/deletes, resulting revisions, emitted events, idempotency result, and
logical output recipients. `StateCore` wraps those plans with their complete
Section-15.3 local `FanoutReservation`s, sink generations, and request
cancellation state in one private `PendingMutationBatch` that never leaves the
state owner. It derives a separate `StorageMutationBatch` containing only the
transaction ID, expected storage/StateMeta revision, canonical persistent
deltas, exact seal count, and accounting totals and transfers that owned value
to `StorageOwner`. Neither socket/sink handle, frame, fanout permit, label, nor
runtime callback crosses the storage boundary.

While a batch is in flight:

- its touched entity IDs are reserved at their expected revisions;
- later mutations touching those IDs wait in the bounded state inbox;
- read-only queries observe the last committed state, never the staged state;
- unrelated ephemeral local delivery may proceed; and
- no success, fanout, or federation ACK for the batch is emitted.

The storage owner first computes the exact seal count, durably installs the
Section-23.5.1 one-use nonce-reservation guard, draws/seals only within that
block, performs one immediate two-phase database transaction, and installs the
matching committed guard. It returns exactly one of:

```text
Committed { transaction_id, storage_commit_sequence, state_generation,
            rollback_guard_hash }
Rejected { error_code }
Indeterminate
```

`Committed` is returned only after the reservation guard, database commit, and
committed-guard replacement are durable. `Rejected` is returned only when the
write transaction was proven not to have begun its irreversible commit and
abort succeeded; its already reserved block remains burned and the next write
starts after it. Any database commit error, guard write/sync/rename error,
entropy failure after reservation, worker panic after commit begins, or uncertainty about persistence yields
`Indeterminate`; the storage owner rejects further work and the supervisor
restarts into offline recovery. This follows redb's documented rule that a
commit error may nevertheless have made the transaction durable. StateCore
never guesses which outcome occurred.

On `Committed`, `StateCore` applies plans in canonical order, advances
revisions, then emits results/events. On `Rejected`, it discards the staged
plans, releases reservations, and emits bounded failures. On `Indeterminate`,
it emits no semantic result, enters shutdown, and leaves retry resolution to
the durable idempotency table after recovery. A partially visible batch is
impossible.

Once `StorageMutationBatch` is submitted, its one completion receiver belongs
to `StateCore`, not to any initiating connection or request future. Client
disconnect, request timeout, label cancellation, or sink closure marks the
matching output `sink_gone` but cannot drop that receiver or cancel the storage
transaction. Cancellation may discard a plan only before submission. The
supervisor treats a lost sender, receiver, mismatched transaction ID, or
completion-channel panic as `Indeterminate` and shuts down for durable
reconciliation.

Federated message delivery is durable even when user history is disabled: the
transaction stores the request result and target-edge outbox object. After all
required edge ACKs, the body may be deleted while its replay/result tombstone
remains.

### 21.6 Timers and clocks

One indexed min-heap owned by `StateCore` handles registration deadlines,
PING/PONG, invites, reservations, sanctions, account-deletion challenges,
fragment assembly, batch expiry, history expiry, idempotency expiry, and
reconnect triggers. There is no task per timer. Each entry contains
`(monotonic_deadline, timer_kind, typed_id, generation)`; stale generations
are ignored.

Durations and rate limits use a monotonic clock. Wall-clock UTC is read only
for displayed timestamps, credential validity, certificate checks, and durable
retention boundaries. A backward wall-clock jump never revives an expiry or
decrements a generation. While running, StateCore compares wall elapsed time
with monotonic elapsed time at least once per minute. A forward or backward
disagreement over five minutes marks wall time untrusted, raises an operator
alert, and pauses every time-based destructive retention/expiry transaction,
credential issuance, and new time-bound credential acceptance; already-valid
TLS sessions and monotonic liveness timers continue. Correction requires ten
continuous minutes with disagreement no greater than one second and a wall
value no lower than the last accepted value. The daemon never uses a clock
jump to delete an idempotency row, barrier receipt, tombstone, security proof,
mailbox object, history row, or audit record early.

### 21.7 CPU and blocking work

redb calls, file synchronization, certificate loading, HPKE, Argon2, OPAQUE server
operations, large SHA-256 validation, and snapshot integrity checks never run
on a Tokio executor worker. Storage uses its dedicated OS thread. Crypto and
integrity work uses a fixed worker pool with explicit queues and per-job
cancellation.

Jobs copy only the bounded inputs they need. Secret jobs return secret-wrapper
types that do not implement `Debug`, and cancellation zeroizes intermediate
buffers. Timing-sensitive comparisons use library constant-time primitives.

### 21.8 Cancellation and shutdown

Shutdown has four bounded phases:

1. **quiesce** (5 s): close listeners, reject new mutations, notify links;
2. **drain** (20 s): finish accepted durable batches and enqueue final QUIT or
   server-shutdown events;
3. **flush** (10 s): persist cursors/audit checkpoint and flush writer queues;
4. **stop** (5 s): cancel remaining tasks, join threads, close databases and
   TLS transports.

The total default is 40 seconds and hard maximum 120 seconds. A second
termination signal skips to stop. Security mutations already acknowledged are
never rolled back; uncommitted staged plans fail on reconnect and are retried
under their idempotency keys. Shutdown does not serialize raw session
addresses or message queues for restart.

## 22. Configuration and administration

### 22.1 Configuration document

The daemon reads one UTF-8 TOML document with `config_version = 1`.
Deserialization denies unknown fields, duplicate keys, implicit type
conversion, environment interpolation, includes, and executable hooks.
Relative paths resolve against the configuration file's canonical parent, not
the current directory.

The required top-level tables are:

```text
[network]      NetworkId, display name, role, coordinator ServerId
[server]       ServerId, server name, data/runtime paths, resource budget
[listeners]    explicit TLS, WSS, onion, federation, and admin entries
[tls]          certificate/key refs, trust stores, ticket policy
[federation]   static peer records and signing-key refs
[storage]      state-directory, storage/guard-key refs, backup policy, disk reserve
[accounts]     registration, account-service/OPAQUE keys, and guest policy
[limits]       values within Section 19 ranges
[privacy]      retention, history, logs, public-presence defaults
[moderation]   role/account policy and audit retention
[e2ee]         companion coordinator, keys, and fixed profile limits
```

Every listener requires an explicit transport, address or Unix path, purpose,
and enabled boolean. Empty addresses, wildcard public binds, symlinked secret
paths, duplicate endpoints, reused TLS/federation/admin keys, unknown peer
IDs, or inconsistent coordinator roles fail startup.

TLS, federation, backup, audit, invitation-authority, admin-operator, OPAQUE,
account-service HPKE, storage, login-index, onion, and E2EE key material is
purpose-separated. Where public-key comparison is meaningful, active public keys are pairwise distinct;
where it is not, secret files and byte strings are pairwise distinct. A
historical trust manifest may of course retain a retired key for its one
original purpose.

### 22.2 Secret material

TOML contains only paths or operating-system key references, never secret
bytes. Required secret and trust material includes:

- storage master key, rollback-guard root key, current login-index key, and
  the previous login-index key only during a Section-23.9 transition;
- OPAQUE OPRF seed, logical-server AKE private key, and independent fake-
  credential-ID key on the coordinator;
- account-service HPKE recipient private key on the coordinator and its pinned
  public key on every node;
- TLS private keys;
- federation Ed25519 private key;
- backup Ed25519 private key and historical trust manifest;
- audit Ed25519 private key and historical trust manifest;
- network sequencer private key where applicable;
- admin trust roots and operator public verification keys;
- optional deployment access-token verification key; and
- the account-invitation verification public key when invite registration is
  enabled.

Secret files are regular, non-symlink files, owned by the daemon UID or root,
mode 0600, and located outside the web root, database, backup staging area, and
source tree. Directory components cannot be group/world writable. The daemon
opens with `O_NOFOLLOW` where available, checks metadata before and after open,
reads once into locked/zeroizing memory when supported, and never prints a
secret path's contents.

### 22.3 First-run initialization

The operator workflow is one explicit command:

```text
agenc-ircd init --config /etc/agenc-ircd/config.toml
```

It refuses to overwrite any existing file. It creates a Network ID for a new
network or requires one for an edge, creates Server ID/incarnation and separate
keys (including the rollback-guard root, generation-one login-index key,
coordinator-only fake-credential-ID key, and account-service HPKE recipient
key), writes the initial
authenticated database/guard pair with a stable Section-23.9 key-state record
and restrictive directories, emits a complete commented
configuration, emits but does not install a Tor `HiddenServicePort` snippet,
and prints certificate enrollment instructions. It does not start the daemon,
contact a CA, enable a public bind, register a peer, or transmit keys.
Edge initialization imports the trusted onboarding descriptor and public HPKE
pin but never creates or requests the recipient private key.

`agenc-ircd check-config` performs every startup validation without opening
listeners or mutating storage. `agenc-ircd print-onboarding` emits the public
DNS/onion/pin descriptor and contains no private material.

### 22.4 Administrative transports

Public client connections cannot obtain network-operator authority. `OPER`
there returns `ERR_NOPRIVILEGES`. Administration is available through:

- a Unix socket admitted by OS peer credentials and an allowlisted UID/GID;
  or
- an optional remote TLS listener with the admin ALPN, a separate private CA,
  and an exact certificate-SPKI allowlist.

Both transports additionally require the configured operator Ed25519 key; OS
credentials or a certificate alone never authenticate an operator. Before
authentication the server permits only bounded PING/PONG, QUIT, and one OPER.
It sends:

```text
NOTE OPER CHALLENGE <admin-session-id> <challenge> <local-or-tls> <transport-binding> :Authenticate this administrative session
```

All three binary tokens are canonical unpadded base64url for 16, 32, and 32
bytes respectively. For remote TLS, `transport-binding` is the 32-byte RFC
9846 exporter with label `EXPORTER-agenc-chat-admin-v1` and context
`network_id || server_id || admin_session_id`; the client recomputes it. For a
local Unix socket it is a fresh random 32-byte connection binding. The client
answers `OPER <operator-id> <86-character-signature>`, where the signature is
Ed25519 over:

```text
"agenc-chat admin session v1" || uint16(1) || network_id || server_id ||
admin_session_id || challenge || uint16(transport_kind) || transport_binding
```

Transport kind is `local(1)` or `tls(2)`. The operator ID, signing key, and
local UID/GID or remote certificate pin must all select the same enabled
operator record. Verification is strict. Any malformed, mismatched, replayed,
or failed proof closes the connection and emits a safe local alert; it is not
retryable on that connection.

After authentication, every client command, including read-only commands and
QUIT, has exactly one client-only tag:

```text
@+agenc.ag/admin=v1.<counter>.<86-character-signature>
```

The unsigned decimal counter is canonical with no leading zero, starts at zero,
fits `uint64`, and increments contiguously without wrap. The
command line after the tag must already be canonical: uppercase command,
exactly one SPACE between parameters, no unnecessary trailing-parameter form,
and the Section-9 UTF-8/control rules. The signature covers:

```text
struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque server_id[16];
    opaque admin_session_id[16];
    uint64 command_counter;
    opaque confirmation_token_hash<0..32>;
    opaque canonical_command<1..4096>;      // bytes after tags, without CRLF
} AdminCommandTBS;

"agenc-chat admin command v1" || TLS-encode(AdminCommandTBS)
```

`confirmation_token_hash` is empty unless the separately validated
`+agenc.ag/confirm=<22-character-token>` tag is present; when present it is
`SHA256("agenc-chat admin confirmation token v1" || token_bytes)`. The two
allowed tag keys are bytewise ordered and unique. Admin input is CRLF-framed
UTF-8 with at most 512 bytes from `@` through the tag-separating SPACE, 4,096
command bytes after it, and 4,610 bytes including CRLF. Server output retains
the Section-9 8,703-byte ceiling so an audit-event line fits. A bad counter,
signature, canonical form, bound, or confirmation binding closes the admin
session before dispatch.

### 22.5 Admin command surface

The admin ALPN fixes UTF-8, message-tag, batch, and standard-reply support; it
does not run CAP, NICK, USER, account login, channel join, or client
registration. In addition to signed `PING`, `PONG`, `QUIT`, `MOTD`, `VERSION`,
`TIME`, `INFO`, and `LINKS`, its parser accepts only this closed set:

| Command | Required permission | Effect |
| --- | --- | --- |
| `OPER <operator-id> <signature>` | pre-authentication | prove the Section-22.4 operator identity |
| `STATS <selector>` | observe | selector is exactly `RUNTIME`, `STORAGE`, `FEDERATION`, `QUEUES`, `RATES`, or `E2EE` |
| `REHASH :reason` | configure | validate and apply reloadable configuration atomically |
| `KILL <UserId> :reason` | sessions | terminate one exact live session |
| `ACCOUNT SUSPEND <AccountId> <seconds> :reason` | accounts | durable bounded suspension |
| `ACCOUNT RESTORE <AccountId> :reason` | accounts | remove suspension, not cryptographic revocation |
| `CHANNEL QUARANTINE <ChannelInstanceId> :reason` | channels | block new delivery, preserve evidence/state |
| `CHANNEL HISTORY PURGE <ChannelInstanceId> :reason` | channels | coordinator-only confirmed bounded plaintext history deletion |
| `CONNECT <ServerId> :reason` | federation | on an edge, start its configured coordinator link; invalid on a coordinator |
| `SQUIT <ServerId> :reason` | federation | quiesce one link without deleting peer identity |
| `PEER QUARANTINE <ServerId> :reason` | federation | durable deny and incarnation fence |
| `BACKUP CREATE :reason` | backup | create verified encrypted snapshot |
| `AUDIT EXPORT <from> <to>` | audit | stream canonical signed audit events over the authenticated transport |
| `RESTART :reason` | process | graceful exec/restart only when service manager supports it |
| `DIE :reason` | process | graceful shutdown |

Targets are typed IDs, not nicknames or channel names, except read-only
lookups. Suspension seconds are canonical decimal 1..31,536,000. Audit export
sequences are canonical uint64 values with `from <= to` and return at most
10,000 combined event/checkpoint records or 64 MiB per request. A reason is
1..512 prepared UTF-8 bytes.

`STATS` first collects one fixed-size snapshot from each owner needed by its
selector. Collection has a one-second monotonic deadline, does not hold a
StateCore/database guard across an await, and completes before the first reply
is rendered. The values are individually coherent owner snapshots but are not
claimed to be one transactional database cut. Collection failure returns
exactly `FAIL STATS UNAVAILABLE <selector> :Statistics unavailable` and emits
no batch or values. Success uses a fresh random 16-byte batch ID encoded as 22
characters of canonical unpadded base64url and this exact framing:

```text
BATCH +<batch-id> agenc.ag/stats <selector> <field-count> <sample-unix-seconds>
@batch=<batch-id> NOTE STATS VALUE <selector> <field-name> <uint64> :Statistic value
BATCH -<batch-id>
```

`sample-unix-seconds` and every value are canonical unsigned decimal `uint64`.
There is exactly one VALUE line for every field below, in the listed order;
`field-count` equals that selector's listed count. Unknown, duplicate, missing,
reordered, noncanonical, overflowing, or extra fields are invalid. All counts
refer to this process and its locally materialized authoritative or projected
state, never an inferred network-wide total unless the field says otherwise:

- `RUNTIME` (9): `uptime_seconds`, `live_client_connections`,
  `tls_handshakes_in_progress`, `registered_sessions`,
  `authenticated_sessions`, `local_channels`, `global_channels`,
  `memory_charged_bytes`, `memory_budget_bytes`.
- `STORAGE` (13): `logical_database_bytes`, `database_file_bytes`,
  `database_max_bytes`, `backup_stream_bytes`, `backup_max_bytes`,
  `state_generation`, `manifest_sequence`, `storage_commit_sequence`,
  `account_service_response_count`, `nonce_draw_high_water`,
  `checkpoint_manifest_sequence`,
  `filesystem_available_bytes`, `filesystem_reserve_bytes`,
  `pending_storage_constructions`.
- `FEDERATION` (7): `configured_peers`, `active_peers`, `quarantined_peers`,
  `base_outbox_objects`, `base_outbox_bytes`, `base_replay_events`,
  `open_cross_profile_barriers`.
- `QUEUES` (10): `client_queued_bytes`, `client_queue_capacity_bytes`,
  `federation_queued_bytes`, `federation_queue_capacity_bytes`,
  `crypto_jobs_in_flight`, `crypto_job_capacity`, `storage_jobs_in_flight`,
  `storage_job_capacity`, `query_snapshots`, `query_snapshot_rows`.
- `RATES` (8): `client_commands_accepted_60s`,
  `client_commands_rate_limited_60s`, `connections_admitted_60s`,
  `connections_rejected_60s`, `authentication_started_60s`,
  `authentication_rejected_60s`, `federation_ingress_bytes_60s`,
  `federation_rejected_bytes_60s`.
- `E2EE` (9): `enabled`, `active_conversations`,
  `recovery_pending_routes`, `directory_objects`, `mailbox_objects`,
  `stored_objects`, `stored_bytes`, `global_disk_bytes_limit`,
  `pending_candidates`.

`database_file_bytes` is the sampled regular-file length and is not logical
usage or evidence of secure erasure. `filesystem_reserve_bytes` is the exact
effective byte reserve computed from the configured fixed and percentage
floors at the sample. `pending_storage_constructions` is zero or one for the
fixed staging sibling known to this stopped/live state directory; arbitrary
directory entries are not scanned. Each `*_60s` field is the checked sum of
the current monotonic one-second bucket and the preceding 59 buckets; buckets
before process start contribute zero and a bucket is cleared before reuse.
`enabled` is exactly zero or one. When the companion profile is disabled, its
other eight E2EE values are zero. No STATS field, label, description, or
metric backend may contain a user, account, address, channel, conversation,
peer, operator, reason, message, object ID, or other attacker-chosen string.

Audit export uses one server-generated batch ID and this exact framing:

```text
BATCH +<batch-id> agenc.ag/audit <from> <to> <event-count> <checkpoint-count>
@batch=<batch-id> NOTE AUDIT CHECKPOINT <base64url-AdminAuditCheckpoint> :Audit checkpoint
@batch=<batch-id> NOTE AUDIT EVENT <base64url-AdminAuditEvent> :Audit event
BATCH -<batch-id>
```

The two counts are exact. Export includes every signed checkpoint whose deleted
range intersects the requested inclusive range and every retained event in the
range, checkpoints first in checkpoint-sequence order and events second in
audit-sequence order. Each base64url token is canonical and decodes to the
named Section-16.4 object with no trailing bytes. Every requested sequence that
ever existed must be covered exactly once by a returned checkpoint range or
event; a gap/overlap or unavailable trust key fails the request rather than
emitting a partial batch. The terminator is emitted only after all hashes,
signatures, ranges, and the retained event chain have been reverified. A range
above the highest allocated sequence has both counts zero. The export does not
decrypt or expose unrelated database records.

A durable protocol or moderation mutation includes its audit event in the same
database transaction and returns success only after commit. A filesystem,
configuration, connection-management, or process action instead commits a
signed intent before acting and a signed outcome afterward; it returns success
only after the outcome, except DIE/RESTART necessarily terminate after their
durable intent. Startup reconciles an intent without an outcome using the
specific action's idempotent status check and never invents success.

A successful authenticated read-only command commits one `observed` audit
event before its first response. `AUDIT EXPORT` freezes its requested view
after that event commits, so the event is included when its new sequence lies
inside the requested range. A failure before a read-only result is available
emits a bounded structured local alert but no falsely successful audit event.
If the observed-event commit itself fails, the server discards the prepared
output and sends
`FAIL <command> STORAGE_UNAVAILABLE :Administrative audit unavailable` when
the transport remains safe. STATS instead sends exactly
`FAIL STATS STORAGE_UNAVAILABLE <selector> :Administrative audit unavailable`.
It emits no partial batch and performs no requested external action.
Responses on one admin session are rendered completely in command-counter
order and batches never interleave.

`DIE`, `RESTART`, peer quarantine, and account suspension longer than
30 days use the following exact two-step rule: the first correctly signed
command has no confirmation tag, changes no state, and returns
`NOTE <command> CONFIRM <token> :Repeat this exact command to confirm`. The
token is 16 random bytes, expires after 60 monotonic seconds, and is bound to
the admin session, operator, permission set, SHA-256 of the exact canonical
command bytes, and current target revision. The client repeats the same command
with the next command counter and `+agenc.ag/confirm=<token>`. Any attempt,
success, disconnect, reload affecting authority, or expiry consumes it. At
most one token exists per admin session.

### 22.6 Reload behavior

Reloadable fields are MOTD, lower resource/rate limits, Origin allowlist,
guest/registration policy, public-presence default, certificate chains with
the same key identity, peer endpoint addresses, and moderation grants.

Network ID, Server ID, role, coordinator identity, state-directory path,
storage/rollback-guard keys, listener purpose, federation signing key, OPAQUE
profile, wire limits, E2EE
profile, account-service HPKE pin/key, and existing onion identity are
restart-only. A REHASH parses and
validates a complete candidate, computes a typed diff, rejects any restart-only
change, applies all reloadable changes at one state revision, and retains the
old configuration on any error.

## 23. Persistence

### 23.1 Engine and durability

The first implementation uses `redb` 4.2.0 as an embedded ACID key-value
store. Exactly one `StorageOwner` OS thread opens `database.redb` and performs
writes; the async runtime never calls a potentially blocking database API. The
process holds the fixed `writer.lock` exclusively for the database lifetime and
refuses a second writer.

Every write transaction uses `Durability::Immediate` with redb two-phase
commit explicitly enabled. A success visible to a client or peer follows both
the engine's successful durable commit and durable installation of the exact
rollback guard in Section 23.5. `Durability::None`, the default one-phase
checksum commit, persistent savepoint restore, and an implementation-selected
durability mode are forbidden outside a disposable benchmark database.

redb documents that a commit error can be indeterminate: the transaction may
already be durable and the database then refuses further writes until reopen.
Consequently, no post-commit error is translated into a normal rejection.
Section 21.5's `Indeterminate` path closes the writer, emits no semantic
result, and lets startup reconcile the database/guard pair.

redb's structural checksum is not treated as cryptographic integrity. Every
logical value except the `DatabaseHeader` and purpose-key-MACed
`NonceReservationState` is application-AEAD sealed. An
authenticated mutation ledger detects deletion, insertion, or substitution of
an older valid sealed record, while a separately keyed external guard detects
rollback of the database alone. Public objects that need stable content
identity additionally carry their prescribed SHA-256 digest inside the sealed
plaintext. Corruption or failed authentication is fatal to startup or to the
affected online transaction; the daemon never substitutes a default record.

### 23.2 Database identity and schema

The logical `meta` table contains exactly two unencrypted, canonical fixed
metadata records: the header below and the independently MACed nonce-
reservation control record in Section 23.5.1. Neither is a byte prefix
prepended to redb's own file format:

```text
struct {
    opaque magic[16];                       // "AGENC-IRCD-DB\0\0\0"
    uint16 database_format;                 // 1
    opaque network_id[32];
    opaque server_id[16];
    opaque server_incarnation[16];
    opaque database_instance_id[16];
    uint32 storage_key_generation;          // starts at 1
    uint64 schema_generation;
    opaque recovery_epoch[16];              // random recovery identity
} DatabaseHeaderTBS;

struct {
    DatabaseHeaderTBS tbs;
    opaque key_check_object_id[32];
} DatabaseHeader;
```

Its immutable record-encryption binding is:

```text
struct {
    opaque magic[16];
    uint16 database_format;
    opaque network_id[32];
    opaque server_id[16];
    opaque server_incarnation[16];
    opaque database_instance_id[16];
} DatabaseBinding;
```

The header leaks only database type and deployment identity. Configuration
must match its Network and Server IDs. `server_incarnation`,
`database_instance_id`, and `recovery_epoch` are independently random at
initialization. Server incarnation remains fixed while the durable request and
projection continuity of that database is intact. Restore changes the server
incarnation, instance ID, and recovery epoch; rekey changes only the instance
ID, and copy-on-write schema migration likewise changes only the instance ID
among those three identity fields. A construction retaining the same master
advances `storage_key_generation` by exactly one without wrap because the
fresh DatabaseBinding creates a new record-key generation; a construction
with bytewise new master material starts that master's generation at one. A recovery epoch MUST be different from the source and any readable
currently configured database. `schema_generation` changes only through
Section-23.6 migration. The
key-check object in Section 23.3
authenticates every header field, including the mutable generations, without
making those mutable fields associated data for every record.

Version 1 has these fixed redb tables. The “Encrypted value” column has two
intentional exceptions: the fixed `meta` records described above.

| Table | Key | Encrypted value | Owner/retention |
| --- | --- | --- | --- |
| `meta` | fixed `header/v1` and `nonce-reservation/v1` bytes | unencrypted `DatabaseHeader` and guard-key-MACed `NonceReservationState` | permanent |
| `key_check` | fixed `agenc-chat/key-check/v1` bytes | sealed header digest | permanent/current generation |
| `account` | Account ID bytes | account policy, label, revisions, tombstone | permanent tombstone |
| `login_index` | generation + keyed login digest | closed live/reservation/deletion-tombstone value repeating digest/generation; live arm carries Account ID, OPAQUE reference, and private OpaqueCredentialId | account lifetime + 30 d |
| `opaque_record` | Account ID bytes or reserved fake-record key | RFC 9807 record and generations | account/setup lifetime |
| `auth_transaction` | random transaction ID | encrypted creation/login/credential-change state, binding, and expiry | consumed or expiry + 24 h tombstone |
| `nickname_reservation` | keyed nickname digest | Account ID, exact nickname, and revision | until released/deleted |
| `registration_invite` | random Invite ID bytes | active reservation or redemption tombstone and expiry | invitation expiry + 7 d |
| `session` | Session ID bytes | authoritative live/suspended session, origin binding, revision | close tombstone + origin replay window |
| `channel` | ChannelInstanceId | registered/global channel state | channel/tombstone lifetime |
| `channel_name` | keyed canonical-name digest | exact name, instance ID, and state | channel/tombstone lifetime |
| `sanction` | scope + random sanction ID | typed sanction and expiry | expiry + 30 d audit link |
| `federation_peer` | peer Server ID | current incarnation/epoch/projection fence, active/pending projection count and encoded-byte totals, optional exact 70-byte open cross-profile head key, local client-resync epoch, and all accepted recovery-epoch hashes | current state + permanent epoch tombstones |
| `federation_origin` | peer/incarnation/origin/generation | origin, next sequence, and edge pending-DEL/`sink_gone` state | DEL + 24 h minimum |
| `request_result` | complete replay key | coordinator request hash/exact result or edge exact result plus pending/completion-coverage/event-covered/snapshot-covered/`sink_gone` rendering state | Section 20.5/20.9 |
| `state_meta` | fixed `agenc-chat/state-meta/v1` bytes | current storage/state counters and integrity anchors | exactly one |
| `integrity_manifest` | manifest sequence | canonical before/after record commitments and hash link | after latest installed integrity checkpoint |
| `integrity_checkpoint` | cut manifest sequence | canonical record-set digest and chain anchor | latest two verified checkpoints |
| `edge_outbox` | target edge + delivery sequence | exact event/object and ACK state | ACK + replay window |
| `edge_projection` | projection generation + entry key | projected entry | active/pending/previous generation |
| `history` | channel ID + channel sequence | plaintext-history record | channel retention |
| `audit` | audit sequence | signed audit event and chain hash | 30 d default |
| `audit_checkpoint` | checkpoint sequence | signed deletion checkpoint and chain hash | permanent |
| `e2ee_object` | companion object ID | exact opaque object | companion retention |
| `e2ee_state` | companion typed key | exact route/replay/sequencer/mailbox state and Section-20.8 cross-profile stage, immutable part, and applied-receipt records | companion retention; barrier rows use their exact profile window |
| `login_index_key_state` | fixed `agenc-chat/login-index-key-state/v1` bytes | current/previous generation, key IDs, and exact previous-entry count | exactly one |
| `storage_construction` | fixed `agenc-chat/storage-construction/v1` bytes | restore/rekey/schema-migration staging identity, phase, and source cursor | staging only; absent from a live database |
| `storage_operation` | storage-operation ID | authenticated completed restore/rekey/schema-migration provenance and finalization counters | permanent |

The record-encryption and backup `table_id` registry is fixed as follows:

```text
0  key_check
1  account
2  login_index
3  opaque_record
4  auth_transaction
5  nickname_reservation
6  registration_invite
7  session
8  channel
9  channel_name
10 sanction
11 federation_peer
12 federation_origin
13 request_result
14 state_meta
15 integrity_manifest
16 integrity_checkpoint
17 edge_outbox
18 edge_projection
19 history
20 audit
21 audit_checkpoint
22 e2ee_object
23 e2ee_state
24 login_index_key_state
25 storage_construction
26 storage_operation
```

IDs 27 through 65,535 are invalid in database format 1. `meta` is deliberately
outside this registry because neither fixed value is a `SealedRecord`; both
are carried explicitly by `BackupHeader`, never as a `BackupRecord`. The
fixed key-check record is included in a backup so the source header/key can be
verified, but restore replaces it rather than copying it into the destination.

Tables 1..13 and 17..26 are **integrity-tracked tables**. Tables 0 and 14..16
are integrity-control tables: the header/key check, MACed nonce-reservation
state, external guard, and mutually anchored control records authenticate them without creating a
self-referential manifest. Every value in every numbered table is nevertheless
a `SealedRecord`; exclusion from the record-set digest never means plaintext
or unauthenticated storage.

No active socket address, TLS fingerprint, login plaintext or reversible
login encoding, channel join key,
message plaintext outside enabled history, MLS secret, client root private key,
or transient rate bucket is a database field. Values use hand-written versioned
codecs; Rust memory layout and Serde defaults are not storage formats.

### 23.3 Record encryption

The storage master key is 32 random bytes outside the database. HKDF is
HKDF-SHA-256. For the canonical `DatabaseBinding`, derive:

```text
storage_salt = SHA256("agenc-chat storage salt v1" ||
                      TLS-encode(DatabaseBinding))
storage_prk = HKDF-Extract(salt = storage_salt, IKM = master_key)
record_key = HKDF-Expand(storage_prk,
    info = "agenc-chat storage record key v1" ||
           uint16(table_id) || uint32(key_generation), L = 32)
table_index_key = HKDF-Expand(storage_prk,
    info = "agenc-chat storage table index key v1" ||
           uint16(table_id) || uint32(key_generation), L = 32)
```

The integer encodings above are unsigned network order. Table ID zero is
reserved for the key-check object. A record key and index key are never
interchanged. The separately provisioned login-index key remains independent
of these derivations so rotating it does not change OPAQUE inputs or records.
Every numbered envelope, including controls, has `key_generation` exactly
equal to `DatabaseHeader.storage_key_generation`; mixed generations inside one
database instance are invalid.

Sensitive values are encoded as:

```text
struct {
    uint16 envelope_version;                // 1
    uint16 table_id;
    uint32 record_schema;
    uint32 key_generation;
    opaque nonce[24];
    opaque ciphertext<16..16777216>;
} SealedRecord;
```

The stable identifier of one complete envelope is:

```text
sealed_record_id = SHA256("agenc-chat sealed record id v1" ||
                          TLS-encode(SealedRecord))
```

The encoding passed to this formula includes the vector prefix on
`ciphertext`. This identifier is a commitment, not a decryption or
confidentiality mechanism.

Encryption is XChaCha20-Poly1305 with an independently sampled, uniformly
random 24-byte nonce for every sealing operation. Associated data is:

```text
"agenc-chat sealed record v1" || TLS-encode(DatabaseBinding) ||
uint16(table_id) || uint32(record_schema) || uint32(key_generation) ||
SHA256(stored_database_key_bytes)
```

The ciphertext includes the 16-byte tag. A nonce-source failure is fatal;
there is no fallback PRNG or unverifiable claim that all prior random nonces
can be retained in memory. `StateMeta.nonce_draw_high_water` is the last
committed high-water mark; a Section-23.5.1 reserved-phase guard may
authenticatedly advance the effective mark while the database remains at that
StateMeta. The current guard's value is authoritative in that phase. Together
they account for every nonce-draw slot durably reserved under the current
storage-key generation, including slots burned by an aborted or crashed
transaction. Except for sequence-zero initialization, no nonce is
drawn until Section 23.5.1 has durably installed the exact one-use reservation
guard; a used or uncertain reservation is never reused. Admission stops before
the high-water mark would exceed the fixed `2^40` limit
(1,099,511,627,776), and offline rekey is required. Since total actual draws
cannot exceed this conservative high-water mark, the birthday-collision
probability for uniformly sampled 192-bit nonces remains below `2^-113` per
storage-key generation even across failed commits and crashes. Nonces are not
counters reconstructed after crash. Decryption validates
envelope, immutable database
binding, table, schema, key generation, stored key, and AEAD before parsing
plaintext. Errors are indistinguishable in online responses and include no
key/value in logs.

`stored_database_key_bytes` is the exact canonical, versioned byte sequence
used as redb's key. A database key that would expose a login, nickname,
channel name, or other human identifier is
`HMAC-SHA-256(table_index_key, canonical_semantic_key)`; its encrypted value
contains the semantic key and verifies it after lookup. The fixed-size
channel/event ordering prefixes required for scans remain visible; their
associated names and bodies are encrypted. This does not hide record count,
table, value size, ordering prefixes, or access pattern from a filesystem
observer.

The key-check plaintext is
`SHA256("agenc-chat database header v1" || TLS-encode(DatabaseHeaderTBS))`.
It is sealed under table ID zero, record schema one,
the active key generation, and the fixed stored key
`"agenc-chat/key-check/v1"`; `key_check_object_id` is the
`sealed_record_id` of that complete `SealedRecord`. Startup first verifies that
object ID, then decrypts and constant-time compares the header digest.
Sequence-zero initialization for a first run, restore, rekey, or schema
migration writes the header and matching key-check object in one immediate
transaction. This authenticates mutable header
generations and detects a wrong master key without attempting arbitrary record
decryption.

### 23.4 Atomicity rules

Every transaction that changes an integrity-tracked table also writes exactly
one Section-23.5 `IntegrityManifest` and the successor `StateMeta` in that
same redb transaction. The matching external guard is installed before the
transaction is reported committed. Those control records are implicit in each
set below and are not repeated in every row.

`state_generation` is scoped by `(network_id, recovery_epoch,
server_incarnation)`, starts at zero for initialization or restore, and is
preserved by rekey. Each externally meaningful `MutationPlan` advances it
exactly once in canonical plan order. One database transaction may batch
1..256 plans,
so its manifest records the exact previous and resulting generation and their
difference equals its state-advancing plan count. Retention, integrity-
checkpoint installation, backup bookkeeping, and representation-only
migration work do not advance `state_generation`. Counters use checked
arithmetic and never wrap.

One manifest has at most 65,535 distinct tracked-record mutations and at most
16,777,200 encoded plaintext bytes, leaving the 16-byte AEAD tag inside the
`SealedRecord` ciphertext maximum. For integrity-tracked records, the sum of
canonical stored keys, replaced or deleted old-envelope lengths, and new
sealed-envelope lengths is at most 16,777,216 bytes per transaction. The
manifest and small fixed integrity-control envelopes are excluded from that
sum and independently bounded above. Admission computes all three bounds with
checked arithmetic before opening a write transaction. Independent plans may
be split between batches;
one atomic set below is never split. The fixed protocol/configuration maxima
must make every single legal command fit, or startup rejects that
configuration. These sets MUST be one database transaction:

- account-creation start: login reservation, optional invitation reservation,
  transaction state, request result, and expiration cursor;
- account-creation finish: login index, OPAQUE record, Account ID and initial
  account revision, reservation consumption, optional invitation tombstone,
  encrypted completion/reply result, and audit event where required;
- authentication start: encrypted OPAQUE server-login state, connection/origin
  binding, expiry, failed-attempt accounting, and exact challenge result;
- authentication finish: consumed transaction, session grant, failed-attempt
  counters, optional previous-to-current login-index migration and count,
  and exact encrypted completion/reply result;
- credential-change start: current account/session/revision/credential binding,
  encrypted transaction state, expiry cursor, and exact challenge result;
- credential-change finish: replacement OPAQUE record, incremented account and
  session generations, consumed transaction, invalidated grants/transactions,
  every affected session fence/event/outbox, encrypted completion/reply result,
  request completion, and audit record;
- account deletion: account/login/OPAQUE/index changes, permanent Account-ID
  tombstone, 30-day login reservation, contact/nickname cleanup, confirming
  session removal, events/outboxes, request result, and audit record;
- channel mutation: channel record/name index, invite counters where changed,
  each target projection entry/count/byte delta and outbox, request result, and
  audit event;
- nickname/session mutation: indexes, local-only session/account projection
  changes, transient-view events/outboxes, projection counters, and request
  result;
- E2EE mutation: every base channel change plus all companion objects,
  receipts, replay keys, route state, mailboxes/outboxes, cross-profile barrier
  IDs/indices, and exact result;
- projection apply: projection record/count/byte changes, matching
  completion-coverage or event-covered request-result markers, and new ACK
  cursor; a cross-profile apply additionally includes every companion route
  change, both applied cursors, the compact barrier receipt, and all combined
  pending fanout in one transaction;
- snapshot READY preparation: incremented client-resync epoch, every affected
  origin's `sink_gone`/pending-DEL state, matching request-result sink markers,
  and the verified pending projection identity;
- snapshot ACTIVE apply: pending-to-active projection-generation swap and
  exact count/byte totals, every exact snapshot-covered request-result marker,
  and installed snapshot cursor;
- login-index transition start/finalize: key-state record and signed audit
  event, advancing `state_generation` exactly once;
- edge-expiry fence: peer incarnation fence, successor projection generation,
  and cleanup cursor; each later cleanup batch atomically carries its cursor,
  session/origin tombstones, membership/invite removals, events, and outboxes;
- retention deletion: deleted records, new deletion cursor, and audit
  checkpoint when applicable; and
- offline restore/rekey/schema-migration construction batch: inserted/replaced target records,
  exact construction cursor, manifest, StateMeta, and successor guard; the
  dedicated finalization transaction atomically deletes the construction
  record, inserts its completed storage-operation record, and writes its
  manifest/StateMeta/guard before the final checkpoint is installed.

An event cannot exist without the state it describes, a result cannot say
committed without its event, an ACK cursor cannot advance without applied
objects, and a visible E2EE binding cannot exist in only one of the base/E2EE
tables.

On the coordinator, each of the six account-service start/finish sets above
also advances
`StateMeta.account_service_response_count` by exactly the number of newly
stored challenge/completion responses in that set. A semantic rejection that
has an encrypted response follows the same rule; an exact durable replay does
not enter a new set and does not advance the counter.

Replica projection-event apply, snapshot download batches, and snapshot ACTIVE
swap are edge-local durable plans and advance that edge database's own
`StateMeta.state_generation` under the ordinary rules above. They never derive
or modify `FederationEvent.coordinator_state_generation` from that local
counter; the exact event or snapshot-cut generation is stored separately in
the federation peer/projection metadata. A coordinator mutation is the sole
source of a new coordinator global generation.

### 23.5 Authenticated integrity, rollback guard, and recovery

The materialized tables are authoritative; startup does not depend on an
unspecified replay function or a monolithic serialized snapshot. AEAD alone is
insufficient because an attacker could substitute an older ciphertext that is
still valid under the same table/key binding. Version 1 therefore combines a
hash-linked mutation manifest, compact record-set checkpoints, and a guard
file authenticated by an independent key.

All structures in this section use the deterministic encoding rules in
Appendix B.1 and are consumed completely. The storage-specific presence enum
is a `uint16` and is not the federation `Presence` type:

```text
enum { storage_absent(0), storage_present(1) } StoragePresence;

struct {
    StoragePresence presence;
    uint32 record_schema;
    opaque sealed_record_id<0..32>;
} IntegrityRecordVersion;

struct {
    uint16 table_id;
    opaque stored_database_key<1..4096>;
    IntegrityRecordVersion before;
    IntegrityRecordVersion after;
} IntegrityRecordMutation;

struct {
    uint16 manifest_version;                // 1
    opaque database_instance_id[16];
    uint64 manifest_sequence;
    uint64 storage_commit_sequence;
    uint64 previous_state_generation;
    uint64 resulting_state_generation;
    uint64 previous_account_service_response_count;
    uint64 resulting_account_service_response_count;
    uint64 previous_nonce_draw_high_water;
    uint64 transaction_nonce_reservation_start;
    uint64 resulting_nonce_draw_high_water;
    uint32 transaction_seal_count;
    opaque previous_manifest_hash[32];
    IntegrityRecordMutation mutations<1..65535>;
} IntegrityManifestTBS;

struct {
    IntegrityManifestTBS tbs;
    opaque manifest_hash[32];
} IntegrityManifest;
```

For `storage_absent`, schema is zero and the ID vector is empty. For
`storage_present`, schema is nonzero and the ID is exactly 32 bytes. Before and
after must differ. A mutation names only an integrity-tracked table, and its
table ID/key pair is unique within the manifest. Mutations sort by the
unsigned network-order `table_id` bytes and then stored-key bytes. The before
version must equal the current record or absence; the after version must equal
the record written by the same transaction or its deletion. The complete
`IntegrityManifest` plaintext is at most 16,777,200 bytes.

The first retained manifest after a checkpoint names its exact
`cut_manifest_hash`; each later manifest names its immediate predecessor.
Manifest sequence starts at one, increments by exactly one for every
transaction that changes an integrity-tracked record, and never wraps. Storage
commit sequence starts at zero with database initialization and increments for
every later immediate transaction that writes a successor StateMeta, including
an integrity-checkpoint installation; it likewise never wraps. The
nonce-reservation-only meta transaction uses its separate reservation sequence
and is the sole immediate database write excluded from storage commit. Manifest commit sequences therefore
increase strictly but may have the one active-checkpoint installation gap
defined below.

The manifest's previous account-service response count equals the prior
StateMeta. In a coordinator database, its resulting count equals the successor
StateMeta and is the checked sum of the previous value plus the exact number
of first-committed request-result records that contain one newly
coordinator-sealed `AccountServiceResponse`, either in `auth_challenge` or in
the canonical finish-completion reply block. Edge receipt/forwarding and
every other transition, including result retention deletion and copy-on-write
construction, repeat the previous value; that value is always zero on an
edge. Decoder and reconstruction logic derives the role-aware delta from the
typed before/after records; it never trusts a plan-supplied aggregate alone.

For an ordinary tracked transaction,
`transaction_seal_count` is exactly two (the manifest and StateMeta) plus one
for each mutation whose `after` is present. No other value is valid. The count
is nonzero and at most 65,537 under the fixed manifest limits; a key check and
header are created only in a sequence-zero database construction, never in a
later application transaction.

`previous_nonce_draw_high_water` equals the prior StateMeta value.
`transaction_nonce_reservation_start` is at least that value; a strict gap is
the exact set of one-use reservation slots burned by earlier aborted or
uncertain transactions. `resulting_nonce_draw_high_water` is the checked sum
of the reservation start and `transaction_seal_count`, is at most `2^40`, and
equals the successor StateMeta and the reservation guard's end. Each of the
transaction's sealing calls consumes one slot in written mutation order,
followed by the manifest and StateMeta; it makes exactly the declared number of calls.
Thus a retry cannot silently reuse an uncertain block, while a normal
failure-free transaction has reservation start equal to the previous high
water. The manifest hash is:

```text
manifest_hash = SHA256("agenc-chat integrity manifest v1" ||
                       TLS-encode(IntegrityManifestTBS))
```

The following compact checkpoint commits to a consistent materialized record
set without copying that state into one giant value:

```text
struct {
    uint16 checkpoint_version;              // 1
    opaque database_instance_id[16];
    uint64 cut_storage_commit_sequence;
    uint64 cut_manifest_sequence;
    uint64 cut_state_generation;
    uint64 cut_account_service_response_count;
    uint64 cut_nonce_draw_high_water;
    opaque cut_manifest_hash[32];
    uint64 tracked_record_count;
    opaque tracked_state_digest[32];
    opaque previous_checkpoint_hash[32];
    uint64 installation_storage_commit_sequence;
    uint64 installation_manifest_sequence;
    uint64 installation_nonce_reservation_start;
    uint64 installation_nonce_draw_high_water;
} IntegrityCheckpointTBS;

struct {
    IntegrityCheckpointTBS tbs;
    opaque checkpoint_hash[32];
} IntegrityCheckpoint;

checkpoint_hash = SHA256("agenc-chat integrity checkpoint v1" ||
                         TLS-encode(IntegrityCheckpointTBS))
```

For each present record in an integrity-tracked table, compute:

```text
record_commitment = SHA256(
    "agenc-chat tracked record commitment v1" ||
    TLS-encode(uint16(table_id),
               opaque stored_database_key<1..4096>,
               uint32(record_schema),
               opaque sealed_record_id[32]))
```

Records are ordered by table ID and then stored-key bytes. With `N` equal to
the exact number of records at the cut:

```text
tracked_state_digest = SHA256(
    "agenc-chat tracked state digest v1" || uint64(N) ||
    record_commitment[0] || ... || record_commitment[N-1])
```

The empty record set has `N = 0` and no commitment bytes. The first checkpoint
has cut/installation manifest sequence zero, cut/installation storage commit
sequence zero, an all-zero cut-manifest and previous-checkpoint hash, covers
every integrity-tracked record created during initialization, and has
`cut_account_service_response_count` equal to the initial StateMeta value and
`cut_nonce_draw_high_water = installation_nonce_draw_high_water` equal to the
initial StateMeta high-water mark; its installation reservation start is that
same value. If initialization creates `I` integrity-tracked
envelopes, that count is exactly `I + 3`: one key-check envelope, the `I`
tracked envelopes, one genesis-checkpoint envelope, and one StateMeta
envelope. No manifest exists at sequence zero. The ordinary first-run set has
at least the login-index key-state record; a restore/rekey/migration staging
set has exactly one tracked construction record at sequence zero, with the
login-index key state supplied later by its required plan entry.
Implementations compute `I` from the actual initial mutation set rather than
using either example as a constant. Later
checkpoints have a strictly greater cut manifest sequence and name the
previous retained checkpoint hash.

A later checkpoint records the StateMeta nonce-draw high-water mark at its immutable read cut.
At installation, `installation_manifest_sequence` is the exact current
manifest head, `installation_storage_commit_sequence` is the prior StateMeta
commit plus one, `installation_nonce_reservation_start` is at least the prior
StateMeta high-water mark, and `installation_nonce_draw_high_water` is that
start plus exactly two for the newly sealed checkpoint and StateMeta. A strict
pre-reservation gap burns older uncertain blocks. Startup replays manifest
high-water transitions from the cut through the installation manifest
sequence, applies exactly this authenticated two-draw installation block, and
then continues through later manifests. The manifest storage commit sequences and
installation commit sequence are contiguous in that order: starting at the
cut, each manifest through `installation_manifest_sequence` advances the
commit by one; the installation then advances it by one and the high-water
mark to its declared reservation end; each later manifest again advances the commit by one. When the cut and
installation manifest sequences are equal, the installation commit is
exactly `cut_storage_commit_sequence + 1`. Any second gap, reordered position,
storage-commit discontinuity, invalid reservation interval, mismatch with
either checkpoint counter, or value above
`2^40` is corruption.

The single `state_meta` plaintext is:

```text
struct {
    uint16 state_meta_version;              // 1
    uint64 storage_commit_sequence;
    uint64 manifest_sequence;
    uint64 state_generation;
    uint64 account_service_response_count;
    uint64 nonce_draw_high_water;
    uint64 logical_database_bytes;
    uint64 backup_stream_bytes;
    uint64 checkpoint_manifest_sequence;
    opaque latest_manifest_hash[32];
    opaque checkpoint_hash[32];
    opaque previous_rollback_guard_hash[32];
} StateMetaTBS;

struct {
    StateMetaTBS tbs;
    opaque commit_authorization_mac[32];
} StateMeta;
```

The two byte counters make persistent admission reproducible and continuously
backupable. For every row in numbered table `0..26`, define:

```text
logical_record_charge =
    2 + 4 + len(stored_database_key) + 4 + len(complete_SealedRecord)
logical_database_bytes =
    sum(logical_record_charge for every numbered-table row) +
    sum(4 + len(meta_key) + 4 + len(meta_value) for the two meta rows)
```

The fixed-width additions represent table ID, key length, and value length;
they are part of this accounting formula even if redb uses a different page
layout. `complete_SealedRecord` includes its ciphertext vector prefix and tag.
The StateMeta row itself participates, but this is not recursive because the
encoded StateMeta length is fixed independently of its counter values.

`account_service_response_count` is the epoch-scoped response-admission
counter defined in Section 11.2. It is zero at first-run initialization and
after the one recovery transform that creates a fresh recovery epoch. In a
coordinator database, every transaction that first stores one or more
coordinator-sealed account-service responses advances it by exactly that
number in canonical plan order; exact replay of a stored result, edge receipt
or forwarding of that ciphertext, retention deletion, checkpointing, and
backup bookkeeping do not advance it. An edge database requires zero at every
cut. Rekey and schema migration preserve the role-appropriate value exactly.
Startup and construction validation reject a decrease or an unexplained
advance within one recovery epoch, and checked overflow rejects before salt
generation or any semantic side effect.

`backup_stream_bytes` is the exact byte length a Section-23.7 backup of this
cut will have:

```text
len("AGENC-IRCD-BACKUP-V1\0") + 4 + len(BackupHeader) +
sum(4 + len(BackupRecord) for every numbered-table row) +
4 + len(BackupTrailer)
```

The future creation time, random Backup ID, signing-key ID, digest, and
signature are fixed-width fields, so their values do not change this length.
Every mutation computes replacement/deletion/insertion deltas with checked
arithmetic before reserving nonces. Its resulting logical charge must be no
greater than `storage.database_max_bytes`, and its resulting backup length no
greater than `storage.backup_max_bytes`; otherwise it rejects at the last
side-effect-free point. Retention deletions remain admissible. Startup,
checkpoint scans, backup verification, restore, rekey, and migration recompute
both sums independently and require exact StateMeta equality. These are abuse
and recoverability ceilings, not claims about redb page overhead or filesystem
allocation; the physical safety boundary is the reserve rule below.

It is sealed under table ID 14, schema one, and stored key
`"agenc-chat/state-meta/v1"`. Its checkpoint fields identify exactly one
retained checkpoint. Its latest manifest hash equals that checkpoint's cut
hash when no later manifest exists, otherwise it equals the final contiguous
manifest. `previous_rollback_guard_hash` is the hash of the guard preceding
the transaction that wrote this StateMeta; for a newly created database it is
the declared predecessor hash or all zero. Before the database transaction
begins, the independent guard key authorizes the exact successor:

```text
commit_authorization_mac = HMAC-SHA-256(
    key = state_meta_authorization_key,
    data = "agenc-chat state meta commit authorization v1" ||
           database_header_hash || TLS-encode(StateMetaTBS))
```

`database_header_hash` is the exact Section-23.5.1 value.

The MAC is computed only after all counters, manifest/checkpoint hashes, prior
guard hash, and resulting header are fixed. Startup verifies it in constant
time before accepting an exact state or blessing a crash successor. Thus an
attacker needs both the storage master key and the independent guard key to
construct a different admissible logical-state successor. The guard root alone
can authenticate burned nonce reservations and therefore cause availability
loss, but cannot create a valid sealed application transition; the master key
alone cannot authorize either. `nonce_draw_high_water` starts with the exact number of envelopes
sealed by the sequence-zero initialization transaction. A successful
transaction advances StateMeta to its reservation end; after an unsuccessful
transaction the reserved-phase guard may remain ahead until a later successful
transaction carries the burned prefix into StateMeta. The effective guard/DB
mark counts committed sealing calls and conservatively burns every uncertain
slot, including values later replaced or deleted. It never decreases within one database instance/storage-key
generation and never exceeds `2^40`. Restore, rekey, and schema migration reset
it only by creating a new database instance and storage-key generation; their
bounded construction transactions then reserve and advance it normally rather
than pretending the final mark is zero or merely the number of currently
present records.

#### 23.5.1 External rollback guard

`storage.rollback_guard_key_file` contains exactly 32 independent random
bytes as a root key. It is never derived from or stored with the master key.
For the configured Network ID and Server ID plus the candidate database
instance, derive purpose-separated subkeys exactly as follows:

```text
rollback_guard_salt = SHA256(
    "agenc-chat rollback guard salt v1" || network_id || server_id ||
    database_instance_id)
rollback_guard_prk = HKDF-Extract(
    salt = rollback_guard_salt, IKM = rollback_guard_root_key)
state_meta_authorization_key = HKDF-Expand(
    rollback_guard_prk,
    info = "agenc-chat state meta authorization key v1", L = 32)
nonce_reservation_mac_key = HKDF-Expand(
    rollback_guard_prk,
    info = "agenc-chat nonce reservation mac key v1", L = 32)
guard_file_mac_key = HKDF-Expand(
    rollback_guard_prk,
    info = "agenc-chat rollback guard file mac key v1", L = 32)
```

The candidate instance is untrusted until the MAC and all database bindings
verify; using it as HKDF context grants no authority. The three derived keys are
never used interchangeably or persisted. The guard file contains exactly one
324-byte canonical object. The database's fixed nonce-reservation record is
the 196-byte canonical object preceding it:

```text
enum { guard_state_committed(1), guard_nonce_reserved(2) }
    RollbackGuardPhase;

struct {
    uint16 nonce_reservation_version;       // 1
    opaque database_instance_id[16];
    uint64 reservation_sequence;
    RollbackGuardPhase phase;
    uint64 nonce_reservation_start;
    uint64 nonce_draw_high_water;
    uint64 storage_commit_sequence;
    uint64 manifest_sequence;
    uint64 state_generation;
    opaque database_header_hash[32];
    opaque state_meta_record_id[32];
    opaque previous_guard_hash[32];
} NonceReservationStateTBS;

struct {
    NonceReservationStateTBS tbs;
    opaque reservation_mac[32];
} NonceReservationState;

struct {
    opaque magic[20];                       // "AGENC-IRCD-GUARD-V1\0"
    uint16 guard_format;                    // 1
    opaque network_id[32];
    opaque server_id[16];
    opaque database_instance_id[16];
    uint32 storage_key_generation;
    uint64 schema_generation;
    opaque recovery_epoch[16];
    uint64 storage_commit_sequence;
    uint64 manifest_sequence;
    uint64 state_generation;
    RollbackGuardPhase phase;
    uint64 reservation_sequence;
    uint64 nonce_reservation_start;
    uint64 nonce_draw_high_water;
    opaque database_header_hash[32];
    opaque state_meta_record_id[32];
    opaque nonce_reservation_state_hash[32];
    opaque previous_guard_hash[32];
} RollbackGuardTBS;

struct {
    RollbackGuardTBS tbs;
    opaque guard_mac[32];
} RollbackGuard;
```

The hashes and MAC are:

```text
database_header_hash = SHA256(
    "agenc-chat complete database header v1" || TLS-encode(DatabaseHeader))

reservation_mac = HMAC-SHA-256(
    key = nonce_reservation_mac_key,
    data = "agenc-chat nonce reservation state mac v1" ||
           TLS-encode(NonceReservationStateTBS))

nonce_reservation_state_hash = SHA256(
    "agenc-chat nonce reservation state hash v1" ||
    TLS-encode(NonceReservationState))

guard_mac = HMAC-SHA-256(
    key = guard_file_mac_key,
    data = "agenc-chat rollback guard mac v1" ||
           TLS-encode(RollbackGuardTBS))

rollback_guard_hash = SHA256(
    "agenc-chat rollback guard hash v1" || TLS-encode(RollbackGuard))
```

`NonceReservationState` is the sole value at exact meta key
`"agenc-chat/nonce-reservation/v1"`; it is never a numbered backup record or
AEAD envelope. Its HMAC and the guard's state hash provide its authentication.
Its sequence starts at zero, increments exactly once when a new block is
reserved, stays unchanged when that block is committed, and never wraps.

The nonce-reservation MAC, StateMeta MAC, and guard MAC are compared in
constant time. In an exact pair, the fixed reservation record and guard repeat
the same phase, reservation sequence/start/end, database/header/StateMeta
identity, counters, state hash, and predecessor. A committed pair requires
`start = high_water = StateMeta.nonce_draw_high_water` and both predecessor
fields equal StateMeta's. A reserved pair still names the unchanged
StateMeta, requires `start >= StateMeta.nonce_draw_high_water`, a strictly
greater end no more than `2^40`, a length in 1..65,537, and equal reservation/
guard predecessors. A missing fixed reservation record or guard, short/long
object, unknown version/phase, bad MAC/hash, wrong identity, or symlinked guard
fails closed; neither object is regenerated from unauthenticated data.

At most one redb write transaction is in flight, whether reservation-control
or application. Let `G` and `N` be the verified current guard and fixed
reservation record, and let `S` be the exact number of envelopes the candidate
application transaction will seal. Before drawing any nonce, StorageOwner
constructs reserved record `N_R` with reservation sequence `N.sequence + 1`,
start `N.nonce_draw_high_water`, end `start + S`, unchanged logical database
counters/StateMeta ID, and predecessor `rollback_guard_hash(G)`. It checks all
arithmetic and the cap, computes the reservation MAC, and replaces only the
fixed meta record in an immediate two-phase redb control transaction. This
control transaction advances reservation sequence but not storage commit,
manifest, state generation, or any logical revision and needs no AEAD nonce.

After that commit, StorageOwner constructs reserved guard `R` matching `N_R`
and naming its exact state hash and predecessor. It writes `R` completely to a
random mode-0600 `O_EXCL` sibling temporary file, calls `fsync` on that file,
atomically replaces the guard path, calls `fsync` on the parent directory, and
reopens/verifies the pair. Only then may it draw exactly `S` independent
nonces and begin the application transaction. If `N` was already reserved
because a prior transaction aborted or was uncertain, `N_R.start = N.end`, so
the prior block is permanently burned. Rolling only `R` back cannot recover
that block because the newer authenticated `N_R` remains in the database.

The application transaction writes its records, optional manifest, successor
StateMeta, and committed form `N_C` of the fixed reservation record in one
immediate two-phase commit. `N_C` keeps `N_R.reservation_sequence`, sets start
and end both to `N_R.nonce_draw_high_water`, names the successor counters,
header hash, and StateMeta record ID, and uses
`previous_guard_hash = rollback_guard_hash(R)`. The successor StateMeta commit
sequence is `R.storage_commit_sequence + 1`, its previous-guard hash is also
`rollback_guard_hash(R)`, and its nonce high-water mark is `R`'s reservation
end; both MACs are computed before the transaction begins. After database
commit success, StorageOwner constructs a committed guard `C` matching `N_C`
and installs it through the same temporary-file/sync/rename/sync sequence.
Only then may it return `Committed` or reserve another transaction.

A crash can therefore leave only four admissible states:

1. reservation record, database, and committed guard describe the same state;
2. reservation record, unchanged database, and reserved guard describe one
   burned or not-yet-used nonce block;
3. the database reservation record is the one MAC-authorized direct successor
   of the guard-bound record (sequence +1, start at the old end, unchanged
   StateMeta/counters, predecessor equal to the old guard hash), but its
   matching reserved guard was not durably installed; or
4. the application database/committed reservation record is the one direct
   successor of its reserved guard, with storage commit +1 and StateMeta naming
   that exact guard hash and reservation end.

Case 4 has exactly one of two application forms. A tracked successor has one
new manifest whose sequence and storage commit are respectively
`R.manifest_sequence + 1` and `R.storage_commit_sequence + 1`; its previous
high-water mark equals the old StateMeta, its reservation start/end and seal
count equal `R`, and its resulting generation, manifest hash, and record
transitions equal the successor StateMeta and materialized records; its
previous/resulting account-service response counts satisfy the exact typed
request-result delta rule above. A
checkpoint-installation successor keeps manifest and state generation
and account-service response count unchanged, advances storage commit by one,
and contains the one new checkpoint
whose installation reservation is exactly `R` and has seal count two. Header
hash and schema are immutable within one database instance; Section 23.6
changes them only by constructing a new instance. No unmanifested or counter-
only application successor is valid.

In case 2, startup accepts the database but never consumes or reuses the
reserved block; the next write creates a later reservation record. In case 3,
startup fully validates the control-record successor, installs its matching
reserved guard, and treats the entire block as uncertain/burned. In case 4,
startup fully validates the exact application form, complete database, and
integrity ledger, then installs the byte-for-byte derived committed guard.
No listener opens before reconciliation. A guard/reservation record otherwise
ahead of the database, a sequence or database gap larger than one, a block or
predecessor mismatch, a second possible successor, or any other disagreement
is not repaired automatically. If either redb commit returns an error, the
process assumes neither outcome: it closes and reopens through this comparison.

Initialization writes the header, key check, initial tracked records, genesis
checkpoint, StateMeta, and a committed `NonceReservationState` at
commit/manifest/reservation sequence zero inside a
mode-0700 sibling staging directory, with the exact `I + 3` initial seal count
defined above. The sequence-zero high-water mark is that exact count because
no prior reservation can exist for a new instance/key generation. It durably
commits the database and only then creates and syncs the first committed guard,
whose reservation start/end equal that mark and whose reservation-state hash
binds the fixed database record. It installs the pair by the same atomic state-directory rename
used by restore; a final directory can never contain only one member of the
initial pair. Restore, rekey, and schema migration create a new database
instance and guard chain as Sections 23.6 through 23.8 specify.
`uint64::MAX` is never wrapped; exhaustion requires an explicit new recovery
epoch and fresh database instance before another affected logical counter can
advance. Reaching the smaller `2^40` nonce-draw cap requires Section-23.8
rekey into a fresh database instance/storage-key generation; rekey alone does
not change the recovery epoch. Reservation-sequence exhaustion likewise
requires rekey and is never wrapped.

The guard detects database rollback while the guard file remains current; the
MACed database reservation record also makes rollback of only a guard-side
nonce reservation fail instead of reopening a burned block. The keyed hashes
detect record-level splicing. The pair cannot distinguish
a coordinated replacement of the database and guard with a mutually matching
historical pair. Non-rolled-back federation peers and native clients must
retain and compare recovery epoch/revisions. Operational snapshot restores
must replace `database.redb` only and exclude the live `rollback.guard`; rolling
back the whole state directory is the explicitly unsupported coordinated case.
No version-1 claim assumes that a disk which lies about `fsync` provides
durable ordering.

#### 23.5.2 Checkpoint production and bounded ledger

At `storage.integrity_checkpoint_manifests` manifests after the active
checkpoint (default 100,000), or at clean shutdown when the cut would advance,
StorageOwner opens one immutable redb read transaction
at a verified guard boundary. It records the cut counters/hashes, scans table
IDs and keys in canonical order, authenticates each tracked record, and
computes the count/digest above. redb read transactions may coexist with the
single writer; the checkpoint scan is owned by StorageOwner, processes at most
4,096 records or 16 MiB per service slice, and yields between slices. Exactly
one long-lived storage snapshot job (checkpoint or backup) may exist; a manual
backup has priority before a new checkpoint starts but never cancels an active
scan. Disk-reserve pressure or any read/authentication error
aborts it without changing state.

After the scan, a control transaction verifies that its cut manifest is still
on the current chain. Before opening the transaction it snapshots the current
StateMeta as `P`, installs an exact two-draw reservation guard `R` under
Section 23.5.1, and constructs a checkpoint with the recorded cut fields,
`installation_manifest_sequence = P.manifest_sequence`,
`installation_storage_commit_sequence = P.storage_commit_sequence + 1`, and
`installation_nonce_reservation_start = R.nonce_reservation_start`, and
`installation_nonce_draw_high_water = R.nonce_draw_high_water`, all with
checked arithmetic and the fixed cap; `R` has end = start + 2 and start at
least `P.nonce_draw_high_water`. The same transaction stores that checkpoint,
writes a StateMeta with the installation commit/high-water counters and new
checkpoint hash, and deletes only manifests through the cut plus checkpoints
older than the latest two. Its StateMeta retains `P.state_generation` and
`P.account_service_response_count` and `P.latest_manifest_hash`. Later
manifests remain anchored by the checkpoint's
cut hash. Installation advances storage commit and nonce-draw high water but
neither manifest sequence, state generation, nor account-service response
count, and receives its matching committed guard.

The post-checkpoint ledger is hard-limited to 1,000,000 manifests and
4,294,967,296 encoded bytes. Reaching either cap stops admission of further
tracked mutations until a checkpoint is installed; records and manifests are
never evicted to manufacture space. The configured 100,000 target may be
lowered or raised only within Section C.5's range, but the two hard caps are
fixed. If manifests produced after a long snapshot cut still exceed a cap when
that checkpoint installs, admission remains stopped and the next checkpoint
starts immediately from the newer head.

#### 23.5.3 Startup integrity reconstruction

Before opening listeners, startup performs:

1. configuration, key purpose/separation, path, and permission validation;
2. redb engine recovery, exact two-record meta-table membership, then header,
   nonce-reservation MAC/hash, key-check, and schema validation;
3. guard MAC/identity/phase validation and the exact committed pair,
   same-database reserved phase, or direct-successor decision in Section
   23.5.1;
4. StateMeta commit-authorization MAC and active/predecessor checkpoint
   decode/hash/counter validation, including the sequence-zero `I + 3`
   high-water formula or the active checkpoint's exact cut-to-install
   two-draw reservation;
   `state_meta`/`key_check` each contain exactly their fixed record, and the
   checkpoint table contains exactly the active checkpoint plus its predecessor
   unless the active checkpoint is genesis;
5. exact manifest-table membership for every sequence after the checkpoint
   through StateMeta with no extra record, followed by hash-chain, mutation-
   order, transition, commit/state-generation, account-service response-count,
   and nonce-reservation/high-water validation; this replays the cut-to-install and install-to-head ranges in
   their exact storage-commit order, permits only the active checkpoint's
   declared storage-commit gap, and accepts a high-water jump only as the
   manifest/checkpoint's authenticated burned-reservation prefix plus exact
   transaction block;
6. a canonical scan that AEAD-opens and schema-validates every tracked record;
7. checkpoint record-set reconstruction and digest comparison;
8. full domain cross-reference, revision, tombstone, E2EE, outbox, request,
   origin, projection, login-index-generation/count, and cursor validation,
   including exactly one key-state record, canonical completed
   `storage_operation` provenance records, and no `storage_construction`
   record in a live state directory; and
9. construction of StateCore followed by a complete Section-27 invariant pass.

Step 7 uses a fresh mode-0600 scratch redb file created with `O_EXCL` in the
private runtime directory. The verifier scans manifests forward into a sorted
changed-key table: the first `before` is the checkpoint version, every later
`before` must equal the prior `after`, and the final `after` is the expected
current version. It then merge-scans that table with current tracked records,
checks every current presence/ID, and emits checkpoint commitments in canonical
order using the first versions. This handles records created or deleted since
the cut without loading the entire database into memory. Scratch bytes count
against the memory/disk reservation and contain only the same stored keys and
commitments already exposed by the encrypted database indexes, never decrypted
logical values or secrets. They are never trusted across a restart and are
removed after verification or on the next startup.

Any missing/extra record, bad AEAD, hash mismatch, transition conflict,
revision gap, unknown schema, construction marker in a live directory, impossible E2EE/base
combination, or exhausted verifier resource fails closed into offline repair
mode. Automatic deletion, rollback, guard regeneration, or "best effort"
startup is forbidden.

### 23.6 Migrations

Migrations are forward-only, copy-on-write constructions from one exact schema
generation to its immediate successor. In-place mixed-schema state,
reverse-running migration code, and redb savepoint restoration are forbidden.
Each shipping migration is a reviewed protocol artifact with one source
generation, target = source + 1 under checked arithmetic, command version,
canonical rule registry, normative per-rule transformation pseudocode, and
golden before/after/corruption vectors. Its profile hash is:

```text
storage_migration_profile_hash = SHA256(
    "agenc-chat storage migration profile v1" ||
    uint64(source_schema_generation) ||
    uint64(target_schema_generation) ||
    canonical_migration_registry_bytes)
```

Registry bytes are printable ASCII plus LF, end in exactly one LF, have no
blank line, and sort bytewise. Each line is
`rule|<uint16-decimal-rule-id>|<source-table-id>|<source-record-schema>|`
`<target-table-id-or-absent>|<target-record-schema-or-zero>|<normative-name>`.
Rule IDs are unique 1..65,535; numeric fields are canonical unsigned decimal;
the source/target table-and-schema tuple is unique; `absent` requires target schema zero; a present
target uses an integrity-tracked table and nonzero schema; and the normative
name is 1..64 lowercase ASCII `[a-z0-9-]`. The separately cited normative
rule text defines every field conversion, validation, split/merge, target-key
derivation, and failure condition. A registry line without that text and
vectors is not implementable and blocks release. Database format 1 initially
began at schema generation 1. Stage 09 ships exactly one migration from
generation 1 to 2, defined below. Fresh databases use generation 2, including
builds with both optional service features disabled.

The stopped-daemon command is:

```text
agenc-ircd storage migrate --config <file>
    --target-schema-generation <current-plus-one>
    --output-state-directory <new-directory> [--resume]
```

It holds the source writer lock, requires a current-head integrity checkpoint
and a newly created/verified backup of that exact reservation/guard boundary,
and resolves exactly one compiled migration profile whose source, target, and
checked-in hash match. It then uses the Section-23.7 construction protocol
with kind `construction_migrate`, the same source/target master and guard-root
keys, a fresh database instance/storage-key generation, and one
`construction_migrate_transform` plan entry per emitted target record. The
plan entry's rule ID selects the exact registry rule; zero, an unknown rule,
or a source/action/target tuple not admitted by that rule is fatal. A rule may
emit zero or more entries and an entry may cite zero, one, or two canonically ordered
source records; a migration needing a larger atomic source group requires a
new construction-plan version rather than hidden scratch state.

The target header names the successor schema from sequence zero and its key
check is created there. Every retained logical value is decoded under the
source schema, semantically validated, transformed, target-key-derived, and
freshly sealed even when its logical bytes are unchanged. The migration
preserves server incarnation, recovery epoch, state generation,
account-service response count, domain revisions, request/outbox continuity,
login-index key state, E2EE counters, and prior completed storage-operation
records. Final marker replacement adds
the new migration `StorageOperationCompletion`; full startup reconstruction,
cross-schema vectors, a second read-back, and invariant validation precede
atomic output-directory installation. The source state/configuration is never
modified.

A crash resumes only through the authenticated construction/completion
identity and rebuilt migration-profile/plan hashes. A binary that lacks the
exact source or target codec/profile refuses the command. Before the new
output is ever started, the untouched source can be selected again without a
rollback because no logical mutation occurred. Once the migrated instance has
accepted a mutation, downgrade requires restoring the verified pre-migration
backup into a new recovery epoch under Section 23.7; it never reopens the old
continuity as though later state had not existed.

#### 23.6.1 The generation-1 to generation-2 migration

The canonical rules are pinned in `docs/storage-migration-1-to-2.registry`.
Command version is 1. Source generation is exactly 1 and target generation is
exactly 2. The database format, table IDs, stored-key shapes, sealed-record
schema, and domain envelope remain 1. Ordinary service requires generation 2;
source-generation decoding is available only to authenticated maintenance and
backup readers. A generation-1 service startup reports that offline migration
is required and does not modify the source.

For each source table 1..13, 17, 18, 20..24, and 26 at record schema 1, rule ID
is the table ID and the rule name is `preserve-validated-record`. Decode the
source with its closed generation-1 key/kind/body/reference codecs, validate
its semantic invariants, preserve its logical value, derive the target stored
key through the same binding-aware rules as rekey construction, and emit one
freshly sealed target record under the target binding. In particular, keyed
NicknameReservation and ChannelName keys change with the target binding.
The
source RequestResult kind set remains 1..4. Target kinds 5/6 and typed History
kinds 1/2 are admitted only under generation 2.

Rule 27, `initialize-legacy-history-control`, additionally maps each source
Channel record (table 8, schema 1) whose history policy is non-Off to one empty
History control record (table 19, schema 1). It preserves the channel policy,
uses the source's positive global state generation as both the control record
revision and history authorization generation, and creates no message rows.
Multiple rules with the same source tuple apply only through their explicitly
distinct target tuples; both rules 8 and 27 apply to such a channel.

Rule 19 is `reject-legacy-history`; any source History row aborts migration.
Rule 25 is `reject-live-construction`; any source live construction marker
also aborts migration. Their absent-target registry arms authorize no data
deletion or guessed transformation. Production Stage 08 databases contain no
History rows. Source key-check table 0, StateMeta table 14, and integrity tables
15/16 are verified by source admission and regenerated through the construction
protocol rather than copied as application records. The target key check
binds the generation-2 header. Existing logical state, revisions, counters,
login-index state, E2EE state, and request/outbox continuity are preserved.

The checked-in rule registry, per-rule semantics, migration profile hash, and
before/after/corruption vectors are one protocol artifact. A missing rule,
unknown profile, nonempty source History table, changed rebuilt plan, or
source/target invariant mismatch fails closed. Every publication boundary is
covered by interruption/resume tests. The source configuration and directory
remain untouched; selecting the installed target is an explicit stopped-daemon
operator step under the upgrade and rollback rules above.

### 23.7 Backup format and restore

`BACKUP CREATE` waits for an exact database/guard boundary (a matching
committed guard or the same-database reserved phase), copies the verified
guard, opens a concurrent consistent read transaction at that boundary, and
writes this stream to a new mode-0600 file in the backup directory. If the one
long-lived snapshot permit is occupied, it returns `SERVER_BUSY` without
opening another read transaction:

```text
magic "AGENC-IRCD-BACKUP-V1\0"
uint32 header_length || canonical BackupHeader
repeat: uint32 record_length || canonical BackupRecord
uint32 trailer_length || canonical BackupTrailer
```

The canonical objects are:

```text
struct {
    uint16 backup_format;                   // 1
    DatabaseHeader source_header;
    NonceReservationState source_nonce_reservation;
    RollbackGuard source_rollback_guard;
    uint64 created_at;                      // Unix seconds
    opaque backup_id[16];                   // random and never reused
    opaque signing_key_id[32];
} BackupHeader;

struct {
    uint16 table_id;
    opaque stored_database_key<1..4096>;
    uint32 record_schema;
    opaque sealed_record<56..16777256>;
} BackupRecord;

struct {
    uint64 record_count;
    opaque stream_digest[32];
    opaque signature[64];
} BackupTrailer;
```

The embedded nonce-reservation state and guard must have valid purpose-
separated MACs at creation time and must match each other, the source header,
StateMeta record ID and storage/manifest/state counters and, through that
record ID, the account-service response count at the read-transaction cut. Its
nonce fields
satisfy the exact committed or reserved
phase rules; a reserved block is already burned and is never consumed during
backup or restore. The
backup signature authenticates those exact guard bytes for later restore; the
guard key itself is never embedded. All numbered tables, including integrity-
control tables, are streamed. No writer begins between guard verification and
read-transaction acquisition; after acquisition, MVCC permits normal writes
without changing the cut.

Before the temporary file is created, the backup worker independently scans
the cut, recomputes `logical_database_bytes` and `backup_stream_bytes`, requires
both to equal its decoded StateMeta, requires the latter not to exceed
`storage.backup_max_bytes`, and applies Section 19.3's exact backup-filesystem
space gate. It writes exactly that many bytes. An early EOF, one extra byte,
counter mismatch, short write, changed output-filesystem identity, or final
file length different from `backup_stream_bytes` aborts before rename. This
check is repeated by the mandatory post-write verification pass.

The signing-key ID is
`SHA256("agenc-chat backup signing key v1" || ed25519_public_key)`. The stream
digest is SHA-256 of every byte before `trailer_length`, including the magic,
encoded lengths, header, and records. The signature input is
`"agenc-chat backup signature v1" || stream_digest`. The signing key is the
server's dedicated backup Ed25519 key, and restore trusts it only if its ID
resolves to the active or an explicitly retained historical public key in the
offline backup trust manifest; a key embedded beside an untrusted backup would
not establish trust.

Each record contains the exact redb key bytes and the complete already sealed
record, ordered bytewise by `(uint16(table_id), stored_database_key)`. Its
duplicated table and record-schema values must equal the sealed envelope.
Lengths and integers are unsigned network order. The ciphertext vector's
16,777,216-byte maximum requires a four-byte prefix, making `SealedRecord`
56..16,777,256 bytes; its enclosing vector also uses four bytes. Including the
maximum key and fixed fields, each `BackupRecord` is therefore at most
16,781,364 bytes. The configured total backup maximum defaults to 100 GiB.

The backup preserves storage encryption and the source nonce-reservation/guard
MACs and therefore
requires separately escrowed source master and rollback-guard root keys for a
conforming restore. It never embeds a secret key. The backup signature is an
additional artifact-authenticity boundary, not a substitute for verifying the
source nonce-reservation MAC, guard MAC, or StateMeta authorization MAC.
Completion requires
`fsync(file)`, atomic rename from a random temporary name, and `fsync(parent
directory)`, followed by a full streaming verify pass that reopens every
record, reconstructs the manifest/checkpoint state, checks the embedded guard
binding, and runs cross-reference invariants against the immutable cut. A
failed backup is reported and its incomplete temporary file is removed on next
startup.

Restore, rekey, and schema migration use the same bounded target-construction protocol; they do
not write an arbitrarily large database in one transaction and do not label a
multi-transaction result as commit sequence zero. The target staging database
is initialized by one small sequence-zero transaction containing its header,
key check, this construction record, a genesis
checkpoint over those tracked records, StateMeta, and the matching committed
nonce-reservation state. Its first rollback guard
names the verified source guard hash as predecessor.
The sequence-zero StateMeta and genesis checkpoint use response count zero for
restore because restore creates a fresh recovery epoch. Rekey and migration
instead copy the authenticated source response count exactly because they
preserve that epoch. No construction batch emits an account-service response,
so every later construction manifest repeats that initial target count.

```text
enum {
    construction_restore(1), construction_rekey(2), construction_migrate(3)
}
    StorageConstructionKind;
enum { cursor_before_first(0), cursor_at_target(1), cursor_complete(2) }
    StorageConstructionCursorKind;
enum { source_database_record(1), source_backup_record(2) }
    StorageConstructionSourceKind;
enum {
    construction_rekey_copy(1),
    construction_restore_copy(2),
    construction_restore_account(3),
    construction_restore_channel(4),
    construction_restore_channel_name(5),
    construction_restore_peer_tombstones(6),
    construction_restore_e2ee_state(7),
    construction_migrate_transform(8)
} StorageConstructionAction;

struct {
    StorageConstructionCursorKind kind;
    uint16 target_table_id;
    opaque target_stored_key<0..4096>;
} StorageConstructionCursor;

struct {
    uint16 construction_version;            // 1
    StorageConstructionKind kind;
    uint32 command_version;                 // 1
    opaque source_database_header_hash[32];
    opaque target_database_header_hash[32];
    opaque source_rollback_guard_hash[32];
    opaque source_stream_digest<0..32>;      // restore: 32; others: empty
    uint64 source_schema_generation;
    uint64 target_schema_generation;
    opaque transform_profile_hash[32];
    opaque target_database_instance_id[16];
    opaque output_path_hash[32];
    opaque source_master_key_id[32];
    opaque source_guard_root_key_id[32];
    opaque target_master_key_id[32];
    opaque target_guard_root_key_id[32];
    uint64 planned_entry_count;
    opaque construction_plan_hash[32];
    StorageConstructionCursor next_target;
    uint64 target_records_committed;
} StorageConstruction;

struct {
    StorageConstructionSourceKind kind;
    uint16 source_table_id;
    opaque source_stored_key<1..4096>;
    uint32 source_record_schema;
    opaque source_sealed_record_id[32];
    uint64 source_backup_byte_offset;       // database: 0
} StorageConstructionSource;

struct {
    uint16 plan_entry_version;              // 1
    StorageConstructionSource sources<0..2>;
    uint16 target_table_id;
    opaque target_stored_key<1..4096>;
    uint32 target_record_schema;
    StorageConstructionAction action;
    uint16 transform_rule_id;               // restore/rekey: 0
} StorageConstructionPlanEntry;

struct {
    uint16 identity_version;                // 1
    StorageConstructionKind kind;
    uint32 command_version;                 // 1
    opaque source_database_header_hash[32];
    opaque target_database_header_hash[32];
    opaque source_rollback_guard_hash[32];
    opaque source_stream_digest<0..32>;
    uint64 source_schema_generation;
    uint64 target_schema_generation;
    opaque transform_profile_hash[32];
    opaque target_database_instance_id[16];
    opaque source_master_key_id[32];
    opaque source_guard_root_key_id[32];
    opaque target_master_key_id[32];
    opaque target_guard_root_key_id[32];
    uint64 planned_entry_count;
    opaque construction_plan_hash[32];
} StorageOperationIdentityTBS;

struct {
    uint16 completion_version;              // 1
    StorageOperationIdentityTBS identity;
    opaque storage_operation_id[32];
    uint64 target_records_committed;
    uint64 finalization_storage_commit_sequence;
    uint64 finalization_manifest_sequence;
    uint64 finalization_state_generation;
    uint64 finalization_account_service_response_count;
    uint64 finalization_nonce_draw_high_water;
} StorageOperationCompletion;
```

For absent source stream material in rekey or schema migration,
`source_stream_digest` is empty; it is exactly 32 bytes for restore.
`source_schema_generation` equals the verified source header. Restore/rekey
require an equal target schema generation; migration requires target schema =
source schema + 1. If target master bytes equal the source master, the target
header's storage-key generation is source + 1 without wrap; if the target
master is bytewise new, its generation is exactly one. A source at
`uint32::MAX` therefore requires a new target master. The target header hash
and instance fields must agree with that complete header. Transform profile
hashes are exactly:

```text
restore_transform_profile_hash = SHA256(
    "agenc-chat RecoveryTransformV1 profile v1")
rekey_transform_profile_hash = SHA256(
    "agenc-chat storage rekey transform profile v1")
```

Migration uses the Section-23.6 registry hash. Any other kind/generation/hash
combination is invalid. `cursor_before_first` and
`cursor_complete` have table ID zero and an empty key. `cursor_at_target`
names the next uncommitted plan entry, has a table ID in `1..13`, `17..24`,
or `26`, and a nonempty key.
`target_records_committed` is the number of complete plan entries strictly
before that cursor and equals `planned_entry_count` only for
`cursor_complete`. `cursor_before_first` requires a nonempty plan and committed
count zero; a zero-entry plan is initialized directly as `cursor_complete`.
Counts never wrap. The record is sealed under table ID 25,
schema one, at the fixed key `"agenc-chat/storage-construction/v1"` and is
forbidden in a completed live database.

Every source reference has a nonzero schema and an ID equal to the complete
referenced sealed envelope. A database source has byte offset zero and is
looked up by its exact table/key under the continuously held source writer
lock. A backup source has an offset equal to the first byte of that record's
outer `record_length`; the offset, table, key, schema, envelope ID, and record
bytes must all agree with the already verified signed stream. Source
references within one entry are unique and sort by table ID/key. Plan entries
are unique and sort by target table ID/key. Table IDs 0, 14..16, and 25
are never plan targets: target key check and integrity controls are generated
by the construction ledger, and the construction record is updated by the
ledger itself. The one table-24 login-index key state is an ordinary required
plan target and must exist exactly once at completion. Prior table-26
completion records are ordinary plan targets and
are preserved.

The canonical plan entry is 16..12,403 bytes. It contains no open action
parameter bytes. The closed action defines all transformation behavior, so a
new transform requires a new command/protocol version rather than an
interpretation of an opaque parameter. `construction_rekey_copy` is valid only
for rekey, has rule ID zero and one same-table logical source, and reproduces
the exact decoded
logical value while deriving its target stored key and fresh envelope under
the target binding. Restore uses these exact actions:

- every restore action has rule ID zero; `construction_restore_copy` has one
  source and is valid only for a table-2 live value or deletion tombstone, a
  table-6 redeemed-invitation tombstone, or any validated value in tables 3,
  5, 10, 19..22, 24, and 26; it preserves that exact logical value;
- `construction_restore_account` targets table 1; it copies a deleted account
  tombstone unchanged, or checked-increments both account-session generation
  and account state revision exactly once for a live account;
- `construction_restore_channel` targets table 8, retains only a registered
  channel, removes every live membership and pending channel invite, retains
  account role grants and durable policy, and checked-increments the channel
  revision exactly once;
- `construction_restore_channel_name` targets table 9 and has the matching
  source channel and source name-index records; it regenerates the index from
  the transformed channel, including the incremented revision and exact
  instance/name binding;
- `construction_restore_peer_tombstones` targets table 11, removes the live
  peer/incarnation/projection/cursor portion, retains only the canonical
  permanent accepted-recovery-epoch tombstones, and emits no target entry when
  that retained set is empty; and
- `construction_restore_e2ee_state` targets table 23 and applies exactly
  Section 18.4: terminal/proof/sequencer/mailbox state is preserved, every
  nonterminal live route becomes `e2ee_recovery_pending` under the new target
  recovery epoch with its restored heads, and no old lineage is resumed. It
  omits every cross-profile stage, part, applied receipt, E2EE delivery cursor,
  request replay row, and other record scoped to the discarded federation
  peer/incarnation. A table-22 object retained only by one of those omitted
  records is likewise omitted; an object with an independent proof, mailbox,
  route, or terminal-state root remains exactly once.

`construction_migrate_transform` is valid only for migration, has rule ID
1..65,535, may have zero, one, or two sources as its rule declares, and is accepted only when the exact source set and target
table/schema match that rule in the profile hashed by the construction
identity. Restore/rekey reject a nonzero rule ID; migration rejects every
other action. The normative migration rule determines whether a source is
omitted, copied, split into several independently planned targets, or joined
with one second source. Plan order, not rule execution order, remains target
table/key order.

Restore emits no plan target for a table-2 account-creation reservation, a
table-6 in-flight invitation reservation, tables 4, 7, 12, 13, 17, or 18, an
ephemeral channel, a channel invitation embedded in a retained channel, or a
peer record with no permanent epoch tombstone. Omitting the table-2 and table-6
reservations is the same terminal-abort release applied when their omitted
account-creation transaction expires; a redeemed invitation tombstone is never
released. Because account creation writes only the current login-index
generation and rotation start requires no live creation transaction, omitting
that reservation cannot change `previous_entry_count`; preflight treats a
previous-generation creation reservation as source corruption. Preflight
rejects an unknown record union arm, an action/table/rule or
source-count mismatch, a target-key derivation mismatch, or any source record
selected zero or multiple times contrary to these explicit omission rules.
Cross-record validation proves every retained table-9 entry has exactly one retained
table-8 channel and every retained base/E2EE reference has its required
counterpart.

The permanent operation ID and record are:

```text
storage_operation_id = SHA256(
    "agenc-chat completed storage operation id v1" ||
    TLS-encode(StorageOperationIdentityTBS))
```

`StorageOperationCompletion.storage_operation_id` must equal that value,
`target_records_committed` must equal the planned count, and all five
finalization counters must equal the StateMeta produced by the transaction
that replaces the construction marker with this record. It is sealed under
table ID 26, schema one, at the raw 32-byte operation ID. The finalization
identity fields are copied byte-for-byte from `StorageConstruction` except for
the intentionally path-local `output_path_hash`; restore retains a 32-byte
stream digest and rekey retains an empty one. The
transaction has exactly two tracked mutations (delete table 25, insert table
26), advances neither logical state generation nor any domain revision, and
adds exactly three seals: the completion, manifest, and StateMeta. Existing
completion records form a set keyed by distinct operation IDs; they are not a
chain and do not authorize recovery by themselves.

For any 32-byte high-entropy secret used above:

```text
storage_operation_key_id = SHA256(
    "agenc-chat storage operation key id v1" ||
    opaque purpose_label<1..32> || secret_key_bytes)
```

Purpose labels are exactly `source-master`, `source-guard-root`,
`target-master`, and `target-guard-root`. An ID compares retries only within
the same role; the tool separately compares raw keys in locked memory when a
new key must differ, while IDs from different purposes are deliberately not
comparable. The key IDs are resumability checks, not password verifiers; every
referenced secret is exactly 32 uniformly random bytes. `output_path_hash` is SHA-256 of
`"agenc-chat storage output path v1"` followed by the canonical absolute
UTF-8 CLI path. A non-UTF-8 path or one containing `.` or `..` after lexical
resolution is rejected.

Before creating the target, the tool performs a complete source verification
and deterministic preflight. Preflight writes a fresh mode-0600 scratch redb
plan in the private staging directory. It streams the source and never retains
more than two source records plus one plan entry in memory. Decrypted values,
login identifiers, message bodies, and secret keys never enter the plan. The
canonical entry bytes total at most twice `storage.backup_max_bytes` and at
most the fixed 2-TiB version-1 ceiling; a rekey or migration first computes the
source's exact logical-database and backup-stream charges and rejects either
one above its configured ceiling or the fixed 1-TiB version-1 ceiling. Counts
and byte sums use checked `uint64` arithmetic. Preflight also computes the
exact final target `logical_database_bytes` and `backup_stream_bytes` from
every validated transform, including generated integrity-control and
completion records. It rejects a target above `storage.database_max_bytes`,
`storage.backup_max_bytes`, or the fixed 1-TiB ceiling, so a migration rule
cannot hide unbounded expansion. Scratch insertion and every target batch use
Section 19.3's exact-filesystem `R(F) + G` gate; exhaustion aborts safely for a
later exact `--resume` rather than weakening the bound. The tool hashes the
entry count and the exact TLS encodings in target order as:

```text
construction_plan_hash = SHA256(
    "agenc-chat storage construction plan v1" ||
    uint64(planned_entry_count) ||
    TLS-encode(plan_entry[0]) || ... || TLS-encode(plan_entry[n-1]))
```

The plan is rebuilt and the hash rechecked on every resume; a scratch redb
file is only a resumable index over that rederived authority. Each target
batch starts at `next_target`, reopens and authenticates all referenced source
records, rederives and compares the target key/schema/action, performs the
fixed transform in memory, freshly seals the target values, and advances the
cursor in the same transaction. One batch obeys all Section-23.4
mutation/byte bounds and reserves one mutation for the replaced construction
record. Its `transaction_seal_count` is therefore the number of inserted
target values plus three: the freshly sealed construction record, manifest,
and StateMeta; its reservation interval follows Section 23.5.1 and may include
only an authenticated burned prefix before that exact block. Every batch receives an immediate two-phase commit and
successor rollback guard; commit errors use the normal `Indeterminate`
reconciliation. Thus the target counters honestly include all construction
work.

At `cursor_complete`, the tool verifies the complete target domain while
allowing only its one construction record. It then atomically replaces that
record with the exact table-26 `StorageOperationCompletion`, using the
three-seal finalization transition above, installs a checkpoint at the
resulting manifest head, and performs ordinary startup reconstruction, which
now requires the construction table to be empty. The resulting StateMeta
logical-database and backup-stream counters must equal both a fresh full scan
and the final values predicted by preflight; a difference is corruption, not a
reason to revise the plan after construction. A crash before replacement
resumes from the authenticated construction cursor. A crash after replacement
recognizes only the exact completion ID rebuilt from the supplied source,
keys, target instance, and plan, then repeats checkpoint/readback work
idempotently; an unrelated completed database cannot satisfy that identity.
If the active checkpoint already cuts at the completion's finalization
manifest and validates, checkpoint installation is complete and is not
repeated; if it is earlier, the one normal installation runs; an incompatible
same-cut/different-hash checkpoint is corruption. A requested output that has
validly advanced beyond completion is an already-used live state, so `--resume`
refuses to relabel or mutate it and directs the operator to normal verification.
The tool closes and reopens both files for a second read-back before the
directory rename. Scratch-plan files are synced only for resumability, are
never accepted as authority, and are deleted before the completed directory
is installed.

Restore is
`agenc-ircd storage restore --config <file> --backup <file>
--source-master-key-file <file> --source-rollback-guard-key-file <file>
--output-state-directory <new-directory>
--target-rollback-guard-key-file <file>
[--target-master-key-file <file>] [--resume] --declare-recovery-epoch`; the target master
key defaults to the source key. The recovery declaration is mandatory for
every restore, not only a known rollback. The daemon must be stopped; the
target rollback-guard root must be freshly generated and bytewise distinct
from the source root, while retaining the source master is permitted because
the new DatabaseBinding derives different record keys. The
output directory and its exact sibling
`.<output-basename>.agenc-construction-v1` must not exist for a new operation;
`--resume` requires exactly one of that staging directory or the requested
output directory. A staging directory resumes construction; an output
directory is read-only reverified against the rebuilt completion identity and
returns the already-complete result, covering a crash after rename but before
the original command returned. The staging path is derived only after canonicalizing the absolute
UTF-8 output path, is opened without following symlinks, and is created
mode 0700. The configured backup trust manifest remains authoritative.

The command verifies all length/count/order bounds while computing the stream
digest, resolves the trusted historical signing key, verifies the signature,
source header/key-check, source nonce-reservation MAC/hash, source guard MAC,
StateMeta authorization MAC, embedded guard binding, full integrity
reconstruction, and every
cross-reference after decrypting each record under the source
`DatabaseBinding`. The signed and independently MAC-verified embedded guard
supplies the source counters and lineage hash; the backup never supplies or
replaces either source or target guard key.

Restore applies one fixed `RecoveryTransformV1` rather than pretending live
transport state survived:

- preserve accounts, live login/OPAQUE records, deletion and redemption
  tombstones, nickname reservations, sanctions, registered channels
  and account-role grants, permanent peer recovery-epoch tombstones, permitted
  history, audit chains/checkpoints, E2EE proof/route/sequencer/mailbox records,
  completed storage-operation evidence, and the exact
  login-index key-generation state and retained entries;
- delete every authentication transaction, login creation reservation,
  in-flight invitation reservation, live/suspended session, transient nickname
  ownership, live federation peer cursor/origin/request-result/outbox/
  projection, and channel invitation; destroy each ephemeral channel
  and remove every live membership from a registered channel, advancing every
  retained registered channel's revision exactly once;
- advance every nondeleted account's account-session generation and account
  revision exactly once, invalidating all prior auth grants; overflow aborts
  the restore;
- preserve every companion counter and proof head, but mark each live E2EE
  route `e2ee_recovery_pending`; Section 18.4 permits only byte-identical
  previously signed recovery evidence and never resumes the old lineage;
- discard every open/applied cross-profile barrier, its parts and receipt,
  base/E2EE delivery cursor, and federation-scoped request replay root because
  the target incarnation cannot ACK or resume either old stream; and
- generate a fresh server incarnation, database instance, and 16-byte recovery
  epoch, and reset the new epoch's `state_generation` and
  `account_service_response_count` to zero.

The selection and mutation rules are deterministic over the verified source
state; only the explicitly fresh incarnation/instance/epoch IDs and sealing
nonces use randomness. Expired retained records are removed only by their
ordinary authenticated retention transactions after first startup. The
transform discards the source key check, nonce-reservation state, StateMeta,
manifests, integrity checkpoints, and any impossible source construction
record. Every
preserved/transformed logical record is freshly sealed under the new
`DatabaseBinding` through the bounded construction ledger above. The target's
initial guard chain uses the signed source rollback-guard hash as predecessor,
a new key check authenticates the new header, and the final checkpoint covers
the complete transformed set at the honest final construction counters.

The command builds fixed `database.redb` and `rollback.guard` files in the
mode-0700 staging directory under the authenticated construction cursor,
validates a complete second read-back, syncs both files and the staging
directory, atomically renames that directory to the requested new directory,
and syncs its parent. Configuration is changed only after this command
succeeds. A crash leaves either no final output directory or the complete
pair; the fixed staging directory resumes only when every
`StorageConstruction` field matches, or after marker replacement when the
rebuilt `StorageOperationCompletion` identity, plan, source, target instance,
and supplied key IDs all match exactly. If both staging and output paths exist,
either is a symlink, or the one existing path lacks its expected authenticated phase, the
command fails without deleting either path.

Every restore therefore forces federation peers and native clients to
resynchronize under the new recovery epoch and server incarnation. Before
work begins, the mandatory declaration prints the backup state generation. If
the configured current database/guard pair is readable, restore proceeds only
when its recovery epoch, server incarnation, exact guard hash, and state
generation equal the signed backup boundary; any older, newer, divergent, or
unrelated source is refused rather than normalized by confirmation. When the
current pair is absent or unreadable, the declaration states that comparison
is unknown and requires the explicit disaster-recovery confirmation; this
never suppresses the new epoch or warning. A backup may contain an account
password record superseded after its boundary. The transform cannot infer a
lost change without a surviving current guard, client generation pin, or
external witness, so it makes no stronger credential-rollback claim. The
Section-11.4 strict post-restore generation check protects clients that retain
their pin; a previously unseen client cannot detect that history. Confirmation
and completion output include only Network
ID, old/new recovery-epoch text, old/new server-incarnation text, source and
current state generations when known, and the new zero generation, never
backup paths, key paths, login material, guard MACs, or backup identifiers.
Recovery-epoch and incarnation text are canonical unpadded base64url for
exactly 16 bytes.

### 23.8 Deletion and key rotation

Expiry uses durable cursors and batches of at most 1,000 records or 16 MiB.
Logical deletion removes indexes and values in one transaction. Physical pages
may remain until an offline copy-on-write rekey, restore, or schema migration
writes a fresh database containing only retained logical records. Version 1
has no in-place or standalone compaction operation and MUST NOT invoke redb's
internal compaction path: its independent write transactions cannot bypass the
StateCore mutation batch, authenticated manifest, nonce-reservation, and
rollback-guard transition contract. An operator who needs space reclamation
without a pending restore or migration performs a genuine key rotation with
the rekey command below. Operators are told that logical deletion or later
file rewriting is not secure erasure on snapshots, copy-on-write filesystems,
SSDs, or backups.

Key rotation is the offline, copy-on-write command
`agenc-ircd storage rekey --config <file>
--output-state-directory <new-directory>
[--new-master-key-file <file>]
[--new-rollback-guard-key-file <file>] [--resume]`; at least one new key is
required, every new path must already satisfy secret-file rules, and a new
operation requires both output and the exact Section-23.7 sibling staging
directory to be absent. `--resume` follows Section 23.7's exactly-one-path
rule and requires the identical key arguments. An omitted key retains its configured source value.
The stopped daemon's exclusive lock, exact source database/guard pair, complete
integrity reconstruction, free-space reserve, and purpose separation of every
new key are verified before output creation. The command holds the source
writer lock until output installation succeeds or the command exits.

The command creates a new random database instance and applies the exact
Section-23.7 target storage-key-generation rule, decrypts and validates each source record, rebuilds every master-
derived HMAC index under its new `table_index_key`, preserves the independent
login-index keys, generations, and stored keys byte-for-byte, and freshly
seals every logical value, including prior completed table-26 operation
records. OPAQUE `credential_identifier` values and registration records remain
unchanged. Source integrity-control records are not copied: Section-23.7
construction creates a new guard/manifest chain with the verified current
source guard as predecessor and installs a final checkpoint at its honest
nonzero counters. Server incarnation, recovery epoch, logical state generation,
account-service response count, revisions, request/outbox state, login-index
transition state, and E2EE counters remain unchanged.

Bounded idempotent batches use the exact Section-23.7
construction plan, marker, completion replacement, and counter rules. A
mismatch requires explicit deletion of only that staging directory; no source
or completed output is removed. A construction record is never accepted as a
live database, and a completion record proves provenance but grants no special
startup bypass.

After full reconstruction/invariant verification and a second read-back pass,
the command syncs `database.redb`, `rollback.guard`, and the staging directory,
atomically renames the directory to the requested output, and syncs its parent.
It never modifies the source state directory or configuration. The operator
then changes `storage.state_dir` and applicable key paths together in one
atomically replaced configuration file and starts the daemon. Startup requires
the exact new pair before listeners open. Because server incarnation, logical
state generation, and recovery epoch are unchanged, this re-encryption alone
is not a rollback; peers still verify normal cursors. Old state directories
and keys stay in offline recovery custody until every dependent backup expires
and are never loaded by the new process.

### 23.9 Login-index key transition

The login-index key cannot be transparently rebuilt offline because the
normalized login is deliberately neither stored nor reversibly encrypted.
Version 1 therefore permits at most two consecutive generations and migrates
entries only when their owner successfully supplies the identifier and proves
the OPAQUE password. The fixed key-state plaintext is:

```text
enum {
    login_index_live(1), login_index_creation_reservation(2),
    login_index_deletion_tombstone(3)
} LoginIndexValueKind;

struct {
    opaque account_id[24];
    opaque opaque_credential_id[32];
} LoginIndexLive;

struct {
    opaque transaction_id[16];
    uint64 expires_at;                      // exclusive Unix second
} LoginIndexCreationReservation;

struct {
    opaque deleted_account_id[24];
    uint64 expires_at;                      // exclusive Unix second
} LoginIndexDeletionTombstone;

struct {
    uint16 login_index_value_version;       // 1
    uint32 generation;
    opaque keyed_login_digest[32];
    LoginIndexValueKind kind;
    select (kind) {
        case login_index_live: LoginIndexLive live;
        case login_index_creation_reservation:
            LoginIndexCreationReservation reservation;
        case login_index_deletion_tombstone:
            LoginIndexDeletionTombstone tombstone;
    } value;
} LoginIndexValue;

enum { login_key_stable(1), login_key_transition(2) }
    LoginIndexKeyStateKind;

struct {
    uint16 login_index_state_version;       // 1
    LoginIndexKeyStateKind kind;
    uint32 current_generation;              // starts at 1
    opaque current_key_id[32];
    uint32 previous_generation;             // stable: 0
    opaque previous_key_id<0..32>;           // stable: empty
    uint64 previous_entry_count;            // stable: 0
} LoginIndexKeyState;
```

The redb key is exactly the 36-byte generation/digest construction in Section
11.1, and the decrypted value must repeat both components. A live value's
Account ID also names its table-3 OPAQUE record, whose private credential ID
must equal the index value. A creation reservation exists only with the named
unconsumed account-creation transaction and has the same expiry; finish
atomically replaces it with a live value, while terminal failure/expiry
deletes it. Account deletion atomically replaces a live value with a
30-day deletion tombstone at the same key; deleting that tombstone at expiry
finally releases the identifier. A reservation or tombstone is a conflict for
account creation and selects the indistinguishable fake path for
authentication. Unknown arms, zero generations, mismatched digests/expiry,
or broken transaction/account/OPAQUE references are corruption.

It is sealed under table ID 24, schema one, and the fixed key
`"agenc-chat/login-index-key-state/v1"`. A key ID is:

```text
login_index_key_id = SHA256(
    "agenc-chat login index key id v1" || network_id || key_bytes)
```

Keys are exactly 32 uniformly random bytes. Stable state requires generation
1..`uint32::MAX`, one matching configured current key, and all previous fields
empty/zero. Transition state requires `current_generation =
previous_generation + 1` without wrap, distinct 32-byte IDs, both matching
configured key files, and `previous_entry_count` equal to a complete scan of
all previous-generation `LoginIndexValue` arms. Every index stored key begins
with its generation and digest and every decrypted value repeats both;
mismatch, a same-login live/reservation/tombstone conflict across generations,
an unregistered generation, or an incorrect count is storage corruption.

Rotation start is the stopped-daemon command:

```text
agenc-ircd storage login-index-rotate-start --config <file>
    --new-key-file <file>
```

It requires stable state, a new purpose-separated key, the source exclusive
lock, full startup reconstruction, and no live account-creation or
authentication transaction after their bounded quiesce/expiry cleanup. It
scans the old generation, then atomically changes key state to transition,
using old generation as previous, old entry count as the exact count, and
old+1 as current, appends the signed security audit event, and advances
`state_generation` once. It does not rewrite an index entry. Before starting the
daemon, the operator atomically changes configuration so
`storage.login_index_key_file` names the new key and
`storage.login_index_previous_key_file` names the old key; any other mapping
fails startup.

During transition, account creation checks both digests and writes current
only, first as the exact creation-reservation arm and then as its replacement
live arm. Authentication performs both lookups as Section 11.4 requires.
After a successful previous-generation live authentication, the same durable
transaction inserts the current live value, deletes the previous live value,
and decrements `previous_entry_count` exactly once. A retry observes the
current entry and is idempotent. Converting a previous live value to a
previous deletion tombstone leaves the count unchanged; deleting a
previous-generation reservation after terminal creation failure or deleting
a previous tombstone at expiry decrements it exactly once in that deletion
transaction. Rate limiting always uses the current-generation digest computed
from the presented identifier, so the transition does not create two attempt
buckets.

Finalization is the stopped-daemon command:

```text
agenc-ircd storage login-index-rotate-finish --config <file>
```

It succeeds only when an exact scan and key state both report zero previous
entries and no live auth transaction references the previous generation. One
transaction changes the state to stable without changing current generation,
appends the signed security audit event, and advances `state_generation` once.
The operator then removes `storage.login_index_previous_key_file` atomically
from configuration and retains the old key only in offline recovery custody
until every backup that needs it expires. No conforming command silently
invalidates dormant accounts to force completion. If an old key is
compromised and entries remain, operators keep authentication quiesced or run
a separately reviewed account-recovery campaign; the protocol reports that
availability/security tradeoff instead of claiming impossible transparent
rotation.

## 24. Rust workspace and module boundaries

### 24.1 Crate graph

The first implementation uses the following workspace. A listed dependency is
permission to depend in that direction; every other workspace edge is
forbidden. This graph is checked in CI from `cargo metadata`.

| Crate | Owns | May depend on workspace crates |
| --- | --- | --- |
| `agenc-ircd-types` | typed IDs, bounded text/bytes, enums, constants, public error codes | none |
| `agenc-ircd-client-wire` | incremental client framing, syntax parser, tag codec, capability-aware renderer | `types` |
| `agenc-ircd-federation-wire` | Appendix-B codecs, object IDs, fragment assembly | `types` |
| `agenc-ircd-crypto` | domain-separated hashes/KDFs, AEAD, signature and exporter adapters, secret wrappers | `types` |
| `agenc-ircd-auth` | HPKE account-service envelopes, OPAQUE/SASL, account creation, and credential-change state machines | `types`, `crypto` |
| `agenc-ircd-domain` | validated commands, authorization, state, plans, events, projections, rate policy | `types` |
| `agenc-ircd-e2ee` | companion-profile public-object validation and base/E2EE transaction plans | `types`, `crypto`, `domain`, `federation-wire` |
| `agenc-ircd-storage` | record codecs, redb owner, migrations, backups, recovery validation | `types`, `crypto`, `domain`, `e2ee` |
| `agenc-ircd-config` | strict TOML schema, path/permission validation, typed configuration | `types` |
| `agenc-ircd-admin` | admin command parser, challenge verification, permission mapping | `types`, `crypto`, `domain` |
| `agenc-ircd-runtime` | Tokio supervisors, listeners, `StateCore`, federation/link state, queue plumbing | every production library above |
| `agenc-ircd-testkit` | deterministic clocks/RNGs, reference model, fault stores, transcript drivers | any production crate; dev-only |
| `agenc-ircd` | binary composition and subcommand selection only | `runtime`, `config`, `storage` |

The short name in the dependency column means the same `agenc-ircd-*` prefix.
No library depends on the binary, `testkit` is absent from release dependency
graphs, and no dependency cycle is accepted. Wire crates contain no sockets,
policy, database calls, or Tokio tasks. `domain` contains no concrete clock,
random generator, executor, database, TLS, or filesystem API. `storage` does
not render client lines. `runtime` coordinates components but does not
reimplement codecs, cryptography, or authorization.

The server-side `e2ee` crate does not contain an MLS client engine. It knows
only the public objects and validation surfaces expressly assigned to the
daemon by the companion specification. A dependency on a client MLS state
machine from any production daemon crate is a release-blocking violation.

### 24.2 Core interfaces and ownership

Cross-crate interaction uses these narrow interfaces; concrete types may add
private implementation fields but cannot widen the authority described here:

```text
trait EntropySource { fill_exact(&mut [u8]) -> Result<(), EntropyError> }
trait MonotonicClock { now() -> MonoInstant }
trait WallClock { utc_now() -> Result<UtcSecond, ClockError> }

trait StoragePort {
    submit(StorageMutationBatch) -> BoundedCompletion<CommitReceipt>;
    consistent_read(ReadPlan) -> BoundedCompletion<ReadResult>;
}

trait CryptoPort {
    submit(CryptoJob) -> BoundedCompletion<CryptoResult>;
}

trait MemoryBudgetPort {
    try_acquire_batch(BoundedMemoryCharges)
        -> Result<MemoryPermitBatch, MemoryExhausted>;
}

trait ClientRenderer {
    measure(&RenderPlan) -> Result<EncodedByteCount, RenderError>;
    encode(&RenderPlan, MemoryPermit)
        -> Result<AccountedClientFrame, RenderError>;
}

trait ClientSink {
    generation() -> ConnectionGeneration;
    try_reserve(ClientQueueDemand)
        -> Result<TentativeClientQueueReservation, SinkReserveError>;
    prepare(TentativeClientQueueReservation, Option<MemoryPermit>)
        -> Result<ClientQueueReservation, QueueAllocationError>;
    commit(ClientQueueReservation, BoundedSharedClientFrames);
    begin_slow_consumer_close();
}

trait FederationSink {
    notify_durable(DurableOutboxCursor) -> Result<(), QueueFull>;
    try_send_control(AccountedFederationFrame) -> Result<(), QueueFull>;
}
```

`ClientQueueDemand` and `BoundedSharedClientFrames` contain the same nonempty,
bounded ordered frame count and exact encoded lengths; commit rejects no value
because private constructors make a mismatch unrepresentable.
`BoundedMemoryCharges` is a nonempty, count-bounded vector of already checked
`MemoryCharge` values. `MemoryPermitBatch`, `MemoryPermit`,
`TentativeClientQueueReservation`, and `ClientQueueReservation` are
`#[must_use]`, non-`Clone`, private-field RAII types. Splitting a batch
preserves its exact total; no constructor can mint, inflate, or forget a
charge. A tentative reservation exposes only its exact additional backing
charge. `prepare` requires no permit when that charge is zero and exactly one
matching permit otherwise; it cannot consume a differently sized permit.
`ClientRenderer::measure` performs no heap allocation and `encode` may
allocate only the capacity owned by its argument; an encoded frame owns that
permit. `SharedAccountedClientFrame` shares both immutable bytes and their one
permit, while every prepared queue reservation separately accounts for its
queue node/backing allocation. `ClientSink::commit` is infallible and
allocation-free for a matching prepared reservation; the post-reservation
disconnect behavior is fixed by Section 21.3.

`FederationSink::notify_durable` carries only a cursor into an already
committed outbox and may be dropped/coalesced when full; the maintenance/link
owner scans from its durable ACK cursor, so notification loss cannot lose an
event. Non-durable control frames own ordinary memory permits and queue failure
closes or marks the link unhealthy according to the exact Section-20 command.

`MutationPlan` and `StorageMutationBatch` are distinct private-field types.
The former is a pure domain transition. Only `StateCore` can combine it with
runtime reservations in `PendingMutationBatch` or consume it after the matching
receipt. The latter is an owned storage-only projection with no generic
closure, trait object, connection handle, borrow into StateCore, or output
bytes. Its validating constructor recomputes the Section-23 mutation, byte,
seal, and accounting limits and binds one `TransactionId`;
`CommitReceipt.transaction_id` must equal it before StateCore consumes either
value.

Production entropy is the operating-system CSPRNG and has no fallback.
Deterministic entropy exists only in `testkit` and cannot be enabled by a
release feature. Clocks enter policy explicitly; calling the system clock in
domain logic is forbidden. `StoragePort` accepts complete, prevalidated
`StorageMutationBatch` values, not domain plans, closures, callbacks, or
database handles. A submitted completion has exactly one receiver owned by
`StateCore`; request cancellation cannot cancel it, and a receipt after
connection loss is still consumed for durable reconciliation.

Every inbound pipeline stage uses a distinct type, including `FramedLine`,
`ParsedMessage`, `CanonicalCommand`, `AuthorizedCommand`, and `MutationPlan`.
Constructors for bounded strings, identifiers, prepared Unicode, revisions,
and canonical encodings are fallible and keep fields private. There is no
`From<String>` or unchecked deserialization path for a validated domain type.

### 24.3 Safe-Rust and code-shape policy

Every workspace crate declares `#![forbid(unsafe_code)]`. Build scripts,
procedural macros written in this workspace, examples, benches, and tests are
included. A required native implementation may exist only behind an audited
upstream safe API and the dependency exception process in Section 24.5; no
workspace wrapper contains an unsafe escape hatch.

Production code obeys these rules:

- no `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, unchecked index,
  or assertion can be reached from configuration, network, database, clock,
  entropy, or peer input;
- `assert!` is reserved for tests and compile-time/internal proofs whose
  preconditions are enforced by an unforgeable validated type;
- arithmetic that touches sizes, counts, time, sequence numbers, or quotas is
  checked and returns a typed error on overflow;
- secret-bearing types do not implement `Debug`, `Display`, `Clone`, Serde,
  or implicit string conversion, and zeroize on drop where the library permits;
- protocol errors are closed enums with stable public mappings; internal
  errors retain a causal chain but are never rendered or logged wholesale;
- async functions do not hold a lock, database guard, or secret borrow across
  `.await`; blocking calls are confined to the owners in Section 21; and
- cancellation, queue-full behavior, and timeout behavior appear in the
  function contract of every operation that can wait.

CI denies warnings and enables at least Clippy `correctness`, `suspicious`,
`complexity`, `perf`, and selected `pedantic` lints. Any allow has the lint
name, local scope, reason, owner, and review date. The review triggers in
Section 21.4 apply to all production functions. Large match expressions that
merely enumerate a closed protocol registry are exempt from the line trigger,
but each arm delegates nontrivial behavior to a named function.

### 24.4 Serialization and crypto libraries

The initial dependency choices are fixed below. `Cargo.lock` pins the exact
transitive graph used for a release; patch upgrades are security maintenance,
not protocol revisions, when all canonical vectors remain byte-identical.

| Purpose | Initial package/profile |
| --- | --- |
| async runtime | Tokio 1.53.1 with `default-features = false` and exactly `rt-multi-thread,net,io-util,time,signal,sync,macros`; `test-util` is dev-only |
| TLS | rustls 0.23.43 with `default-features = false` and exactly `std,aws_lc_rs,prefer-post-quantum`; explicit `aws-lc-rs` provider, TLS-1.3-only version list, and `[X25519MLKEM768, X25519]` key-exchange list |
| operating-system CSPRNG | `getrandom` 0.4.3 with `default-features = false` and `std`; no deterministic or userspace fallback in production |
| persistence | redb 4.2.0 with `default-features = false` and exactly `std`; no experimental, logging, cache-metrics, or compaction surface |
| OPAQUE | `opaque-ke` 4.0.1 with `default-features = false` and exactly `ristretto255,argon2,std`; no Serde; plus the fixed custom Argon2id KSF |
| account-service HPKE | `hpke` 0.14.0, no default features; `alloc,chacha,x25519,hkdfsha2` only; Base mode and the fixed project suite only |
| binary/presentation encoding | `tls_codec` 0.5.0 with `default-features = false` and exactly `std,mls`, plus `base64` 0.23.1 with `default-features = false` and exactly `alloc`; production protocol codecs use no derive or Serde |
| at-rest AEAD | RustCrypto `chacha20poly1305` 0.11.0, no defaults, `alloc,zeroize`; `XChaCha20Poly1305` only, no reduced rounds or crate RNG |
| signatures | `ed25519-dalek` 3.0.0 with `default-features = false` and exactly `fast,zeroize`, using `verify_strict`; no batch/hazmat/legacy/Serde |
| hashes/MAC/KDF | RustCrypto `sha2` 0.11.0 with no defaults and `zeroize`, `hmac` 0.13.0 with no defaults and `zeroize`, and `hkdf` 0.13.0 with no defaults; SHA-256/SHA-512 only as registered; optional WSS uses the private RFC-6455 SHA-1 handshake adapter below |
| password hashing | RustCrypto `argon2` 0.5.3 with `default-features = false` and exactly `alloc`; Argon2id v1.3 through the `opaque-ke` adapter |
| secret erasure/comparison | `zeroize` 1.9.0 with `default-features = false` and `alloc`, and `subtle` 2.6.1 with `default-features = false` |

Serde may parse the strict configuration into an untrusted intermediate. It
is forbidden for federation, E2EE, persistent records, signatures, hashes,
or protocol-state IDs. Those formats use hand-reviewed codecs and
`tls_deserialize_exact`-equivalent consumption. Derive macros are permitted
only when golden vectors prove their complete encoding and an enum's explicit
wire discriminants cannot follow Rust declaration order accidentally.

No implementation writes a cipher, curve, PAKE, KDF, MAC, signature scheme,
random generator, or constant-time primitive. A new algorithm or provider
requires a protocol/security decision record, published vectors, differential
tests where two implementations exist, and cryptographic review.

`opaque-ke` 4.0.1 intentionally retains its audited digest/HMAC/curve
dependency generation while the direct HPKE/signature/storage stack uses the
current RustCrypto generation above. Those duplicate cryptographic crates are
a reviewed, reachability-scoped exception: OPAQUE types never cross into the
direct primitive adapters, the lockfile records both graphs, vectors exercise
both, and dependency consolidation requires an `opaque-ke` release with
byte-identical RFC-9807 behavior. No other duplicate cryptographic primitive
crate is accepted without the Section-24.5 exception record.

The optional WSS accept adapter uses `aws-lc-rs` 1.18.0 with defaults
disabled and exactly `non-fips`, matching the existing locked TLS provider.
It exposes only RFC-6455 `Sec-WebSocket-Accept` computation with
`SHA1_FOR_LEGACY_USE_ONLY` and standard padded base64. This exception applies
only to public HTTP handshake bytes; no general SHA-1 API is exposed and all
other registered hashes retain their existing algorithms. Cargo features
`wss` and `history` default off and are independently additive. Durable schema
validation and stopped-daemon maintenance remain available in every build.
Enabling an uncompiled optional service fails configuration validation before
listener admission or storage writes. Runtime disablement does not claim to
remove dependencies already compiled into a feature-enabled binary.

### 24.5 Dependency and build integrity

Release builds use `--locked`, a checked-in lockfile, no Git dependencies, no
wildcard requirements, and crates.io as the only default registry. Cargo
source replacement, patches, and vendoring manifests are reviewed files.
Network access is disabled during the reproducible build after dependencies
are fetched and hash-verified.

`cargo deny check` fails on known advisories, yanked packages, unknown sources,
unapproved licenses, wildcard dependencies, and unreviewed duplicate security
crates. `cargo audit` may run as a second view of RustSec but cannot weaken the
`cargo-deny` result. Each ignored advisory has a tracking issue, reachability
analysis, compensating control, owner, and expiry no longer than 30 days.

Every release emits an SPDX or CycloneDX SBOM, compiler version, target,
enabled Cargo features, lockfile hash, source commit, and reproducible artifact
hash. Build scripts, proc macros, native archives, and dynamically loaded
libraries are part of the threat review. Release artifacts are signed from an
isolated release identity; the daemon never contains that private key.

## 25. Operations, observability, and host security

### 25.1 Process and filesystem isolation

The daemon runs as a dedicated unprivileged account. It never starts as root
to bind a low port, change identity, or read keys; a service manager or socket
activation owns privileged setup. Database, runtime, backup, secret, and log
directories are distinct and have the minimum permissions in Section 22.

On Linux, the shipped service profile sets `NoNewPrivileges`, a read-only
system image, a private temporary directory, a restrictive system-call set,
and write access only to declared state paths. It denies ptrace, device access,
kernel-module access, raw sockets, and address-family use not required by the
configured listeners. Equivalent platform controls are documented elsewhere;
absence of one control is reported by `check-config`, not silently claimed.

Core dumps are disabled. Secret memory is locked where the platform and
quota permit; failure to lock is a startup warning in ordinary mode and fatal
when `require_locked_secrets=true`. Operators encrypt or disable swap and
exclude state, keys, logs, and backups from unreviewed cloud crash collection.

### 25.2 Logging

Structured logs use a closed event registry. Allowed common fields are event
code, severity, coarse UTC second, server ID, software version, listener
purpose, typed public error code, bounded duration bucket, bounded byte/count
bucket, and a fresh process-local correlation number. The correlation number
is random at process start plus a counter and is never a protocol ID.

Logs MUST NOT contain source or destination IPs, ports tied to users, onion
addresses used by clients, login identifiers or their keyed hashes, passwords,
access tokens, channel keys, TLS certificate subjects, account IDs,
OpaqueCredentialIds, User IDs,
nicknames, channel names, message/tag bodies, E2EE object bytes, KeyPackages,
Welcome objects, database keys/values, secrets, free-form moderation reasons,
or raw parser input. Error formatting uses explicit safe fields, never `Debug`
on an input-bearing aggregate.

The default level retains operational logs for 24 hours with a hard supported
maximum of 30 days. Security audit events use their separate encrypted chain.
Log rotation is atomic, compressed only after close, and deletion is bounded.
Debug logging cannot be enabled on a public listener at runtime and no build
feature adds body logging.

### 25.3 Metrics and health

Metrics are process/network aggregates with a fixed label vocabulary. Allowed
labels are role, listener purpose, transport family, command class, bounded
result class, queue name, and peer Server ID on the private operator endpoint.
Nicknames, accounts, channels, messages, IP prefixes, error text, and arbitrary
input are forbidden labels. Histograms use fixed buckets to prevent a
high-cardinality timing transcript.

Readiness is false until configuration, keys, storage recovery, StateCore,
and required federation/E2EE synchronization are ready. Liveness says only
that the supervisor and StateCore loop are progressing; it does not claim the
coordinator is reachable. Health is exposed on the local admin socket or
authenticated admin listener, never an unauthenticated public HTTP port.

### 25.4 Key lifecycle

Each key has one purpose, owner, generation, creation time, activation time,
retirement time, and offline recovery procedure. Rotation never reuses key
bytes or silently changes an identity:

- TLS certificates may rotate in place when the configured identity and pin
  policy are satisfied;
- federation and sequencer signing-key rotation uses signed continuity and a
  bounded overlap from the applicable protocol;
- backup and audit signing keys rotate independently, append their public keys
  to the corresponding offline trust manifest before activation, and retain
  old verification keys through the last signed artifact's retention
  (permanently when an audit checkpoint uses the key);
- OPAQUE OPRF/AKE setup and its independent fake-credential-ID key are never
  regenerated or rotated in place: RFC 9807 defines no transparent setup
  rotation for existing records, and changing the fake key would create an
  account-enumeration distinguisher across attempts. Compromise
  disables affected authentication and requires a separately specified new
  mechanism/setup generation plus explicit client re-registration while a
  reviewed migration path is available;
- the account-service HPKE recipient key changes only through a coordinated
  hard-cut onboarding transition. Version 1 accepts exactly one key: operators
  distribute the pending descriptor out of band, quiesce account operations,
  restart coordinator and edges with the new public/private pair, invalidate
  every old account-service transaction, and erase the old private key after
  verified activation. Compromise skips any rollback retention, warns that
  recorded envelopes may be readable, and requires the same client pin
  confirmation before account operations resume;
- storage-master and rollback-guard rotation follows Section 23.8;
  privacy-preserving login-index transition follows Section 23.9; and
- onion identity rotation creates a new address and an explicit onboarding
  migration; it is never presented as the same endpoint.

Emergency revocation is a durable admin event. Removing a key file without a
protocol transition causes a fail-closed startup or link failure, not silent
regeneration. Backups of keys are separately encrypted, access-audited, and
restored in rehearsals at least every six months.

### 25.5 Upgrade and incident behavior

An upgrade is staged edge by edge only after the coordinator understands both
old and new wire profiles. Because version 1 has an exact profile hash, any
wire/schema change requires a new profile and explicit dual-version bridge;
operators cannot rolling-upgrade incompatible peers by ignoring FHELLO.
Database migrations occur offline or under the bounded migration state in
Section 23.6 before new listeners open.

For suspected key compromise, equivocation, rollback, database corruption,
or secret exposure, the safe default is to quiesce affected listeners,
preserve encrypted audit evidence, fence the affected incarnation/key, and
issue a client-visible security notice after facts are verified. The runbook
never asks operators to disable certificate checks, delete a tombstone, reuse
an incarnation, force an MLS epoch, or accept partial storage.

## 26. Compatibility, extension, and versioning policy

### 26.1 Client compatibility boundary

A conventional UTF-8 client with TLS, CAP, and the supported base commands can
use plaintext public, unlisted, or secret channels and direct messages. It
does not gain account creation, OPAQUE login, credential change, advanced
privacy controls, or E2EE unless it implements the named vendor capabilities. A client that lacks
`agenc.ag/e2ee-mls` cannot join an E2EE-bound channel and receives
`FAIL JOIN E2EE_REQUIRED :End-to-end encryption is required`; it is never
shown a fake plaintext view.

The daemon intentionally does not interoperate with plaintext port 6667,
STARTTLS, legacy server links, non-UTF-8 text, hostname/IP masks, services
password messages, DCC routing, or unknown channel types. A gateway that adds
one of those behaviors is a separate security boundary and cannot advertise
full version-1 conformance.

### 26.2 Protocol versions and registries

There are four independent version axes:

| Axis | Version-1 signal | Changes when |
| --- | --- | --- |
| client base profile | `agenc.ag/privacy=v1` plus ISUPPORT Network ID | client-visible base semantics or mandatory limits change |
| base federation | FHELLO `profile_version=1` and Appendix-B `profile_hash` | any canonical base object, registry, bound, or semantic changes |
| encrypted client/federation | CAP `profile=<profile-hash>` and ECAP `(version=1, profile-hash)` | any companion-document byte, negotiated grammar, or encrypted semantic changes |
| database | `database_format` and `schema_generation` | persistent encoding or migration generation changes |

An unknown major profile is rejected. A new optional client capability may be
added without changing the base major version only when disabling it leaves
all version-1 semantics unchanged. New enum values, optional wire fields,
reply meanings, mode meanings, projection visibility, or relaxed bounds are
not silently tolerated; they require a new negotiated profile.

Appendices A and B are closed registries. Removed numeric values remain
reserved forever. Experimental work uses a separate capability and profile
hash and cannot reuse a production discriminant. String comparison rules,
canonical ordering, domain-separation labels, and error privacy are protocol
surface, not implementation detail.

### 26.3 Upgrade negotiation and downgrade resistance

Peers advertise supported federation profiles before origin or state replay
and select the highest mutually configured profile, never merely the highest
received. Version 1 supports only profile 1, so mismatch closes the link.
Clients explicitly request optional capabilities; a capability disappearing
mid-session triggers `CAP DEL`, and any route pinned to that capability follows
its fail-closed rule.

No recovery, compatibility, or administrator flag may reinterpret a version-1
object under another version, omit a signature, ignore trailing bytes, accept
an unknown enum, reduce an identity to a nickname, or convert an encrypted
route to plaintext. An explicit export/import tool may translate formats
offline only when it verifies the source and emits a new recovery epoch.

### 26.4 Conformance claims

A build reports `core-v1`, `federated-v1`, and `encrypted-v1` separately.
`encrypted-v1` implies the other two and the exact companion version. Optional
history and WSS are reported separately. A conformance statement includes the
source commit, Appendix-B profile hash, raw E2EE document SHA-256, derived
E2EE profile hash, compiler, target, and completed test-manifest hash. Local
patches invalidate the statement until the complete release gates are rerun.

## 27. Security and correctness invariants

These invariants hold after startup validation, before and after every state
transition, at every durable commit boundary, after recovery, and across every
rendered result. The identifiers are stable test and audit references.

### 27.1 Transport and input invariants

| ID | Invariant |
| --- | --- |
| `TRN-01` | No application byte is accepted or emitted on a client, federation, or remote-admin connection before TLS 1.3 and the exact ALPN/subprotocol complete. |
| `TRN-02` | TLS early data, TLS 1.2 or earlier, plaintext listeners, STARTTLS, renegotiation, and post-handshake client authentication are unreachable configurations. |
| `TRN-03` | A federation/admin peer must pass both certificate policy and its independent application signature before gaining its role. |
| `TRN-04` | A physical line, WebSocket message, tag section, fragment, object, or queue reservation never exceeds its admitted byte bound. |
| `TRN-05` | Parsing is total: each finite byte input yields one bounded success/error/need-more result without panic, recursion, unbounded allocation, or superlinear wildcard work. |
| `TRN-06` | Invalid UTF-8, NUL, invalid CRLF, client prefixes, duplicate tags, noncanonical encodings, unknown discriminants, and trailing binary bytes never reach semantic dispatch. |

### 27.2 Identity, authentication, and privacy invariants

| ID | Invariant |
| --- | --- |
| `ID-01` | Authorization keys are immutable typed IDs and current generations; nickname, label, display name, cloak, server name, and source address never grant authority. |
| `ID-02` | An Account ID, User ID, Session ID, ChannelInstanceId, Message ID, request ID, and event ID is never reused for a different logical entity. |
| `ID-03` | A public cloak is fresh per connection and statistically independent of address, account, device, and previous cloaks. |
| `ID-04` | Raw source addresses leave the transport/admission owner only as an in-memory rate-prefix key and never enter protocol state, federation, persistence, logs, metrics, replies, or audit events. |
| `ID-05` | Login plaintext exists only at the client and, after a valid pinned HPKE open, inside the coordinator account-service job; an edge sees only the sealed envelope. Neither it nor its keyed lookup hash enters a result, event, projection, account object, log, metric, audit record, or public reply. |
| `ID-06` | A native client performs no account or E2EE operation when the TLS-authenticated recovery-epoch capability differs from its onboarding pin; a change requires explicit human confirmation. |
| `ID-07` | Persistent state contains neither login plaintext nor a reversible login escrow. At most one current and one previous keyed generation exist, and a previous entry migrates only after successful OPAQUE authentication supplies the identifier again. |
| `AUTH-01` | An OPAQUE unknown-account attempt performs the same protocol-shaped path as a known account and exposes no account-existence distinction in code, timing class, or response. |
| `AUTH-02` | An authentication, account-creation, or credential-change transaction is connection-bound, context-bound, expires, and is consumed exactly once on success or failure. |
| `AUTH-03` | Edges never possess the coordinator's OPRF seed, OPAQUE AKE private key, password, export key, or recovered client private key. |
| `AUTH-04` | Account authentication cannot create, replace, or silently recover an E2EE root/device identity. |
| `AUTH-05` | Logout, account switch, device attach/detach, or principal replacement advances/fences the relevant generation before a request under the new principal executes. |
| `AUTH-06` | No edge assertion alone authenticates an account; version 1 requires a successful coordinator-run OPAQUE exchange bound to the exact origin and connection, and the client accepts success only with the matching HPKE-exporter-authenticated completion receipt. |
| `AUTH-07` | Account deletion requires fresh same-account OPAQUE authentication, a single-use revision-bound confirmation, all bounded preconditions, and one durable tombstone transaction. |
| `AUTH-08` | Every account creation/login/credential-change inner message reaches semantic processing only after HPKE authentication to the client-pinned account-service key and recovery epoch; every opened request that reaches a protocol outcome has one matching encrypted challenge or completion, and request/response contexts, IDs, kinds, independently salted one-use exporter material, and the epoch-scoped response count cannot be substituted, rolled back, or reused within an accepted lineage. |
| `AUTH-09` | Real and unknown-account paths use same-length private OpaqueCredentialIds, identical OPAQUE work, and HPKE-encrypted challenges; a public Account ID, login digest, or real/fake discriminator never occupies that field. |
| `AUTH-10` | Every account-service request and response uses the exact fixed-size authenticated wrapper and all-zero padding; an edge can observe the routed operation kind but not login, invitation, OPAQUE-message, or real/fake response length. |
| `AUTH-11` | Credential replacement requires fresh same-account OPAQUE proof, reuses the exact private credential identity/setup, atomically replaces one record and fences every old session generation, and has no server-assisted reset path. |
| `PRV-01` | Secret-channel nonexistence and unauthorized existence use the same public error and bounded logical path. |
| `PRV-02` | A projection, query, event, log, metric, or health result contains only the least information its authenticated recipient is entitled to at that revision. |
| `PRV-03` | Direct, Tor-exit, and onion profiles never silently fall back to one another; transport profile is not federated. |
| `PRV-04` | No protocol path claims resistance to global timing/volume correlation, server compromise, endpoint compromise, or metadata the design necessarily exposes. |

### 27.3 State, authorization, and delivery invariants

| ID | Invariant |
| --- | --- |
| `STA-01` | At most one live session owns a canonical nickname, and nickname changes are coordinator-serialized without collision kills or merges. |
| `STA-02` | A global channel name maps to at most one active ChannelInstanceId; recreation after destruction never inherits prior membership, policy, history, or E2EE binding. |
| `STA-03` | The fixed role order is enforced, no actor grants above its own role, and a registered channel never has zero owners. |
| `STA-04` | `+n` is always set; `+p` and `+s` are mutually exclusive; mode vectors are validated completely before any mode is applied. |
| `STA-05` | A membership, invite, ban, exception, role, topic, or policy decision uses one authoritative state revision and cannot be applied to a later entity incarnation. |
| `STA-06` | A multi-target command either commits its complete authorized success subset in canonical order or commits none on storage/federation failure. |
| `STA-07` | A sender is authorized and charged before a Message ID/event exists; a recipient set is derived from the same committed target revision. |
| `STA-08` | Before an object is accepted, every remaining local sink has one complete generation-bound queue reservation and every unique frame/backing allocation has its global permit; failure rolls all of them back, while later queue pressure can disconnect only whole affected consumers and cannot reorder, truncate, partially enqueue, or roll back the accepted object. |
| `STA-09` | A plaintext body exists durably only under an explicitly enabled Section-17 channel history policy or an unacknowledged federation outbox transaction. |
| `STA-10` | An invisible/offline user or unavailable secret channel cannot be distinguished through a richer error, route, count, server name, or timing class promised by this profile. |

### 27.4 E2EE and federation invariants

| ID | Invariant |
| --- | --- |
| `E2E-01` | The daemon never obtains or requests MLS epoch secrets, plaintext, client root private keys, or device private keys. |
| `E2E-02` | A route bound or tombstoned as encrypted rejects every plaintext send, history write, private-topic write, and legacy fallback. |
| `E2E-03` | Base membership/policy and companion cryptographic transition commit atomically where the companion requires joint state; neither can become visible alone. |
| `E2E-04` | A KICK/part/revocation is not represented as cryptographic removal until the companion finality rule succeeds; sending pauses when removal uncertainty requires it. |
| `E2E-05` | Every E2EE object, semantic ID, signature, generation, replay key, receipt, finalization, abort, mailbox transition, and restoration follows the companion invariant and test set. |
| `E2E-06` | A restored E2EE route never resumes its old lineage: while pending it accepts only byte-identical previously signed recovery evidence, and a conflict or missing terminal chain remains blocked behind a permanent tombstone. |
| `E2E-07` | A client or federation link enables encrypted behavior only after the exact companion `(version, profile-hash)` matches; an absent, malformed, stale, or unequal hash blocks encryption and cannot select plaintext fallback. |
| `FED-01` | Exactly one logical coordinator decides each global mutation; an edge cannot self-promote, merge state, or acknowledge a guessed outcome during partition. |
| `FED-02` | A base federation link is active only after exact FHELLO/READY identity and profile agreement, base state synchronization, and required E2EE synchronization. |
| `FED-03` | For each live origin, operation sequences are contiguous; exact retries replay the exact durable result and conflicting reuse permanently fences the origin/peer. |
| `FED-04` | A new server incarnation fences all earlier incarnations, and origin deletion permanently fences later operations from the deleted generation. |
| `FED-05` | An event is ACKed only in the same transaction that durably applies it and advances the exact projection cursor; a committed result is rendered only after its completion event is covered by that transaction or by an ACTIVE successor snapshot cut at least as new. |
| `FED-06` | A snapshot becomes pending only after complete count/order/object-ID/digest/cross-reference validation, becomes active only on the exact replayable ACTIVE authorization, and atomically swaps generation plus covered-result markers. |
| `FED-07` | Losing the last authorization to projected state causes durable erasure before ACK; no unrelated secret channel, session, account, auth, address, or admin data enters a projection. |
| `FED-08` | A fragment/object direction, authenticated prefix, descriptor, carrier ID, declared length, recomputed hash, and typed payload must all agree before dispatch. |
| `FED-09` | A silent or lost peer is detected by bounded keepalive; its origins expire after one nonextendable grace interval, and a full base outbox fences the projection into snapshot recovery instead of growing or dropping security state. |
| `FED-10` | FHELLO recovery epoch equals the static peer pin; a changed epoch requires a fresh incarnation, permanent old-epoch tombstone, full snapshot/E2EE synchronization, and no prior-epoch cursor reuse. |
| `FED-11` | Every coordinator plan that targets one edge in both federation profiles uses one target-specific bounded cross-profile barrier with one exact durable stage/part/receipt set; neither cursor, ACK, result coverage, projection/route change, snapshot, nor client frame can cross that barrier separately. |
| `FED-12` | Result-first and completion-first delivery converge on one exact replay record; neither arrival order renders before durable coverage, transfers a sink, invents a result, or strands an accepted request. |
| `FED-13` | A paged directory query retains one bounded immutable snapshot and one process-keyed, session/account/query/page-bound cursor slot; successful continuation atomically replaces that slot, while expiry, restart, wrong binding, or consumption can only fail with `QUERY_EXPIRED` and can never splice a new state cut into the reply stream. |

### 27.5 Persistence, concurrency, and operations invariants

| ID | Invariant |
| --- | --- |
| `DUR-01` | No success, event, federation result, ACK, or E2EE receipt that implies durable mutation is visible before successful immediate two-phase commit and durable installation of its exact rollback guard. |
| `DUR-02` | State, event, outbox, request result, audit record, E2EE companion records, integrity manifest, and StateMeta named as atomic in Section 23.4 either all commit or none commit. |
| `DUR-03` | An encrypted record is parsed only after header/AAD/schema/key generation and AEAD verification; corruption never yields a default or partial value. |
| `DUR-04` | Recovery accepts materialized state only when the guard-bound StateMeta, active checkpoint, complete later manifest chain, reconstructed tracked-record digest, revisions, cursors, origins, projections, and base/E2EE cross-references all agree. |
| `DUR-05` | Every backup restore creates a new server incarnation, database instance, and recovery epoch, resets that epoch's state generation, and produces a visible resynchronization warning; a readable current guard permits only its exact backup boundary, and disaster recovery relies on retained client generation pins rather than presenting stale credentials as continuous. |
| `DUR-06` | Every record seal samples a fresh uniform 192-bit XChaCha20 nonce from the OS CSPRNG only after a durable one-use reservation is anchored by both the MACed database control record and matching guard; aborted/uncertain slots are burned, the authenticated nonce-draw high-water mark never exceeds `2^40` under one storage-key generation, and the resulting collision bound remains below `2^-113`. |
| `DUR-07` | Insertion, deletion, or substitution of any integrity-tracked sealed record changes a manifest transition or checkpoint reconstruction and fails closed before state use. |
| `DUR-08` | Startup accepts only an exact committed reservation-record/database/guard set, a valid same-state reserved set whose block is burned, the reservation record's one MAC-authorized pre-guard successor, or that reserved guard's one fully validated application successor; missing, otherwise ahead, stale, gapped, or mismatched control state is never guessed or regenerated. |
| `DUR-09` | Restore/rekey/schema-migration output is produced only through the authenticated bounded construction ledger; its counters include every committed batch, its marker is atomically replaced by the matching permanent completion record, and an installed live database contains no construction record or scratch plan. |
| `DUR-10` | Login-index key state, configured key IDs, generations, index-key prefixes/value repeats, and exact previous-entry count agree; a missing key, duplicate owner, third generation, or forced dormant-account invalidation fails closed. |
| `DUR-11` | StateMeta's logical-database and exact-backup-stream byte counters equal a full record scan at every accepted cut; no growth crosses either configured ceiling or begins without the fixed release-qualified physical-growth reserve. |
| `DUR-12` | A coordinator StateMeta's account-service response count starts at zero only with a fresh recovery epoch, advances exactly once per newly committed coordinator-sealed response, never advances for exact replay or edge forwarding, is preserved by rekey/migration, and never wraps; the edge value is always zero. |
| `CON-01` | Each mutable protocol datum has exactly one runtime owner; no shared mutable map bypasses `StateCore` or `StorageOwner`. |
| `CON-02` | Every task, worker job, timer, channel, batch, snapshot, reassembly, and output queue has a named owner, finite bound, cancellation path, and joined shutdown path. |
| `CON-03` | A durable plan is constructed from one committed revision, reserved while in flight, and applied infallibly exactly once after its matching receipt. |
| `CON-04` | Blocking storage/crypto/integrity work never executes on an async runtime worker, and an async task never holds a blocking guard across await. |
| `CON-05` | Every count-scaled or peer-influenced allocation acquires its exact global permit before allocation; fixed headroom and worker/storage pools are never lent to protocol work, permit ownership follows buffer ownership, and exhaustion rejects work before side effects rather than overcommitting. |
| `OPS-01` | Public protocol output, logs, metrics, health, crash identifiers, and backups obey their explicit data allowlists; debug formatting cannot override them. |
| `OPS-02` | Configuration unknowns, unsafe permissions, missing keys, role conflicts, unsupported versions, and out-of-range limits fail before listeners open. |
| `OPS-03` | No administrative authority is obtainable through a public client session, public WebPKI certificate alone, or nickname/user mode. |
| `OPS-04` | Shutdown either completes an already accepted durable transition or leaves it unacknowledged for idempotent recovery; it never fabricates success. |
| `OPS-05` | Every post-authentication administrative command is counter-contiguous, strictly signed, permission-checked, and audit-bound before its success becomes visible; read-only batches are complete, ordered, noninterleaved, and contain only their closed aggregate field sets. |

## 28. Verification, conformance, and security testing

### 28.1 Requirement ledger and evidence

The implementation repository maintains `conformance/requirements.toml`.
Every normative requirement in this document and the companion document has a
stable ID, source section/hash, target crate, one or more test/evidence IDs,
and status. Generated checks fail if a requirement is unmapped, a test ID is
missing, a source hash changes, or an applicable requirement is waived.
Waivers cannot apply to a MUST/MUST NOT or security invariant; changing one
requires a protocol revision.

Each release produces a machine-readable evidence manifest containing the
test command, tool/version, source and lock hashes, target, start/end time,
result, and artifact hash for every gate below. Tests use no live user data or
production secret. A release is conforming only if every applicable gate is
present and successful on the release source and lockfile.

### 28.2 Deterministic unit and vector tests

Checked-in canonical vectors cover every:

- identifier/name success and each rejection boundary;
- client line/tag escape, maximum-length line, command grammar, and render
  budget at one byte below, equal to, and one byte above every limit;
- Appendix-B enum arm, structure, empty/present option, vector count, object
  hash, fragment count, profile hash, and malformed canonical alternative;
- companion raw-document/profile-hash derivation, CAP value, ECAP OFFER/ACK
  maximum wire forms, simultaneous negotiation, timeout, every tuple mismatch,
  and reconnect-only sequencer-set transition;
- account-service HPKE request/response/exporter vectors, pin mismatch,
  recovery-epoch mismatch, completion forgery/substitution, bare-success,
  idempotent replay, post-tombstone replay with a changed semantic outcome,
  response-salt collision fixtures, response-count `uint64::MAX` refusal, and
  replay failures; exact
  fixed-wrapper/padding arithmetic and nonzero-padding rejection; plus every
  exact OPAQUE message length, registration/login/fake-record paths, the dummy
  KE3 transcript, credential-change success/rejection/session fencing,
  real/fake OpaqueCredentialId indistinguishability, and the fixed custom KSF
  profile;
- signature, HKDF, HMAC, AEAD/AAD, sealed-record ID, key-check, integrity
  manifest/checkpoint, StateMeta commit authorization, rollback-guard MAC/hash,
  XChaCha draft vectors and `2^40` nonce-reservation boundary, login-index generations,
  construction plan/cursor/completion, audit chain/checkpoint, backup digest, and
  logical-database/backup-stream charge arithmetic, physical-growth reserve,
  and wrong-key/tamper failure;
- base/E2EE joint transaction, cross-profile tuple absence/presence and
  stage/part/receipt encodings, 70/72-byte keys, bitmap/popcount/padding,
  payload-root lifetime, 2,047/2,048/2,049-part plus
  one-byte-under/equal/one-byte-over aggregate boundaries,
  and every companion Section-21 vector; and
- capability-specific rendering and traditional/standard reply ordering.

Golden bytes are generated once by a reviewed vector generator and then
treated as test input. Production codecs do not generate their own expected
values at test time. At least one separate small reference encoder/decoder,
written without production derive code, cross-checks every federation vector.

### 28.3 State-machine and model tests

A deterministic reference model executes the full command and federation
operation registries against an in-memory value state. Property tests generate
valid and invalid sequences including registration, authentication, nickname
reuse, channel recreation, roles, modes, invites, history, partitions, origin
updates, duplicates, gaps, snapshot swaps, account switches, deletion-challenge
replacement/expiry/restart replay, credential-change fresh-proof consumption,
success/rejection/replay, response-count advancement/edge-zero behavior, and
multi-session fencing, E2EE binding,
login-index transition/migration, removal, rollback, restore/rekey/schema-
migration construction, and shutdown. After every step, all Section-27 invariants
and equality between model and implementation snapshots are checked.

Restore sequences cover an exact current-boundary source, a refused older or
divergent source while the current guard is readable, disaster recovery with
no current witness, and zero/one/multiple credential-generation advances after
the backup cut. Native-client model pins must accept only the strict
post-restore generation relation in Section 11.4 and must reject a stale
OPAQUE completion even when the edge supplies matching 900/903 text.

The query model uses deterministic cursor keys and controlled monotonic time.
It covers authorized data sets with zero, one, exactly one-page, one-page-plus-
one, and maximum configured rows; required protocol opener/terminator replies
remain part of the page bounds. It proves byte-identical retry under the same
federation replay key, one-use replacement under the next key, unchanged old-
cursor usability after ordinary commit failure, process closure after an
indeterminate commit, and final-result replay after all snapshot permits are
released. Negative cases include a consumed cursor; altered query arm/kind;
wrong session, user, account, or account generation; session close; idle time
immediately below/at 60 seconds; absolute time immediately below/at 600
seconds despite intervening pages; orderly restart with an unchanged server
incarnation; cursor-counter exhaustion; and an injected live HMAC-output
collision. Every case asserts exact permit counts and `QUERY_EXPIRED` with
empty context and no new snapshot. The NAMES continuation variant additionally
asserts the Section-14.2 connection close without a partial 366 terminator.

A bounded formal model of coordinator/edge durable execution covers two edges,
three clients, two channels, duplicate/reordered/lost messages, one crash at
every nonce-reservation/commit/ACK/guard boundary, origin replacement, snapshot recovery, and one
E2EE-bound route. It orders FRESULT before and after its completion event,
creates one two-stream cross-profile barrier, permutes every permitted part
arrival, loses each cumulative ACK, crashes before and after the combined
apply, replays every exact part, conflicts each part field independently,
reaches receipt cleanup and peer-incarnation cleanup, loses ACTIVE after READY,
and replaces only a non-barrier
unacknowledged completion with an equal/newer snapshot cut. It also delivers a
completion before its result and the result before its completion in both
profiles. No cursor or frame may cross the barrier alone, and no result may
render early or remain permanently stranded. Model checking must exhaust its
configured state space with no violation of
`DUR-01/02/04/07/08/09/10/11/12`, `FED-01/03/04/05/06/11/12`, `STA-01/02`, or
`E2E-02/03`. The model source, exact bounds, tool version, and state-count
report are release evidence; shrinking the bounds requires review.

Loom tests enumerate permitted schedules for queue reservation transfer,
StateCore/storage completion, request cancellation before and after storage
submission, account-response seal-token submission/return/drop, connection
cancellation, response-count-permit acquire/commit/release, crypto or storage
completion-sender loss, job/transaction-ID
mismatch, duplicate completion, link replacement, shutdown, and post-commit
cancellation. No schedule may reuse or fail to zeroize the one seal token,
orphan the sole storage receipt, or move a runtime reservation into
`StorageOwner`. There is no "flaky retry" allowance:
a nondeterministic failure blocks release until its cause is fixed. Every
accepted schedule leaves the committed count plus live
`AccountResponseCountPermit`s equal to the model ledger and never exposes a
sealed response whose permit did not commit.

### 28.4 Parser and fuzz testing

`cargo-fuzz` targets, each with a structured seed corpus, cover:

1. TCP framing and CRLF boundary splitting;
2. WebSocket-to-line adaptation;
3. client message/tag parse and render round trips;
4. every base federation object and descriptor line;
5. base and E2EE fragment reassembly/interleaving/timeouts;
6. every persistent record, backup record, construction plan, and migration-profile decoder;
7. account-service HPKE/OPAQUE application wrappers, certificates, signatures,
   and sealed records;
8. wildcard masks, PRECIS preparation, and base64url canonicalization; and
9. configuration and admin command parsing.

For all inputs, the oracle requires no panic, abort, timeout, excessive
allocation, partial output, trailing-byte acceptance, or decode/re-encode
change after successful canonical parse. Each parser target runs for at least
24 cumulative CPU-hours on every release candidate and continuously on the
main branch. The corpus includes all fixed boundaries and every previously
reported defect. Address/undefined-behavior sanitizers run where supported;
Miri covers pure Rust codec/domain/crypto-wrapper tests.

### 28.5 Crash, storage, and fault injection

A faulting storage backend fails before and after every logical write, redb
transaction phase, database sync, guard temporary write/sync/rename/directory
sync for both reservation and committed phases, every reserved nonce draw,
manifest/checkpoint installation/prune, migration-profile/plan validation, backup record,
construction-plan rebuild/batch/cursor/marker-to-completion replacement, and login-index
transition/migration. The process is killed at each point, restarted, and
required to recover the complete prior state with either a committed or burned
reserved guard, the one direct successor plus a new committed guard, or fail
closed offline. It must never expose an intermediate semantic state.

Tests corrupt each header/NonceReservationState/guard/StateMeta field, length, schema, key generation,
guard phase/reservation/high-water mark, nonce, ciphertext/tag, database key, manifest transition/link, checkpoint cut,
tracked-state digest, cursor, object ID, record order, snapshot digest, audit
checkpoint range/signature, login-key state/count, construction field/plan,
completed storage-operation field/ID/counters, and backup signature independently. They insert,
delete, and substitute an older valid ciphertext in every tracked table; roll
the database back with a current guard; make the guard ahead; and roll both
files back to document the explicit coordinated-rollback limit. Forged direct
application successors made with only the master key or only the guard key
must fail; a guard-key-only fixture can burn a reservation but cannot change
logical state. The two-key fixture succeeds only as an explicit total-key-
compromise case.
Disk-full,
read-only
filesystem, permission change, stale lock, truncated file, wrong master key,
wall-clock jumps, entropy failure, and worker panic are mandatory cases.
Account-service crash schedules cover salt generation, sealing, count
advancement, result insertion, commit, and output; recovery must return the
stored response byte-for-byte or emit nothing, never reseal a committed
request or expose an uncommitted response.
Configuration tests reject `storage.compaction_enabled` and every other
unlisted key. A dependency/source policy check rejects a production call to
redb's in-place compaction API. Deletion tests distinguish logical charge from
database file length, and rekey/restore/migration rehearsals prove that their
fresh output contains no deleted logical record while making no secure-erasure
claim about the source filesystem or backup media.
Restore rehearsals use wrong/correct source guard roots and prove successful
recovery, fixed transport-state cleanup,
new-incarnation/epoch fencing, removal of every collecting/applied
cross-profile barrier and federation-scoped payload root, preservation of an
identical payload that has an independent proof/mailbox root, and E2EE
`recovery_pending` behavior for both
lower and equal/newer source generations. Rehearsals snapshot every
account-creation phase and prove that login and invitation reservations whose
transactions are omitted are also omitted, redeemed/deletion tombstones remain,
the previous-generation login-index count is unchanged, and no dangling
transaction reference survives.

### 28.6 Network, interoperability, and privacy tests

Black-box transcript suites exercise every Appendix-A command in every legal
connection state with capabilities off and on. They compare exact command,
numeric, tag, prefix, parameter, ordering, batch, label, line-length, and
visibility behavior. At least two independently implemented conventional
clients must complete TLS registration and use a plaintext public and secret
channel; a native client must complete the pinned account-service HPKE/OPAQUE
exchange, Tor onion onboarding, account controls, channel controls, federation,
and the entire companion E2EE suite.

TLS tests reject old versions, wrong ALPN, early data, bad names, expired and
untrusted chains, wrong pins, cross-purpose certificates, weak groups, bad
client certificates, exporter mismatch, and session-resumption bypass. They
confirm the strict native hybrid group and compatibility fallback separately.
WebSocket tests cover Origin, masking, fragmentation, compression rejection,
message boundaries, and close codes.

Tor integration runs through an isolated test network and a real v3 onion
service. DNS-leak tests require hostname-form SOCKS requests, `SafeSocks`, and
`TestSocks`; account contexts demonstrate distinct SOCKS isolation credentials.
Packet capture on the client host must show no destination DNS query or direct
destination connection for the onion profile.

Privacy canary values shaped like IPs, logins, OpaqueCredentialIds,
account/channel/user IDs,
passwords, keys, plaintext, ciphertext fragments, and moderation reasons are
injected into every error path. Automated scans assert that forbidden values
do not appear in logs, metrics, health, crash output, federation projections,
backups where forbidden, or unauthorized query results. Secret-channel and
unknown-channel transcript/timing-class tests run in statistically shuffled
batches; results may not expose a protocol-visible distinction.

Administrative transcript tests cover every command, permission, signature
counter, confirmation state, and audit phase. For every STATS selector they
assert the exact batch type, field count/order/names, canonical zero and
`uint64::MAX` rendering, one-second collection deadline, owner failure before
BEGIN, no batch interleaving, 60 one-second rate-bucket rollover, partial
startup window, disabled-E2EE zeros, and absence of every injected privacy
canary. The observed audit event must commit before BEGIN. Separate grammar
tests require a trailing human description on every NOTE/WARN/FAIL and reject
each missing, extra, reordered, or selector-inapplicable field.

### 28.7 Abuse and capacity tests

Adversarial tests hold partial TLS handshakes, partial lines, maximum tags,
fragment slots, auth transactions, query snapshots, output queues, federation
windows, storage batches, and crypto jobs concurrently. Allocation-instrumented
tests verify `allocation_charge` at zero, every 4 KiB boundary, and `u64`
overflow; prove each fixed charge dominates the selected dependencies' live
allocations; and assert that permits are neither leaked nor double-released
across cancellation and panic containment. Measured resident memory must stay
at or below `server.memory_budget_bytes`; admitted allocation charges plus
the reserved `D + C` worker/storage pools must stay at or below `B - H`, leaving the
exact Section-19 headroom untouched. Queue counts and worker counts may not
exceed their hard bounds.

Boundary scenarios exhaust each logical ceiling before memory, memory before
each logical ceiling, and both on the same operation. They require a
side-effect-free `SERVER_BUSY` or specified connection close, never partial
fanout or partial durable admission. The default configuration must admit
50,000 idle client base charges within its four-GiB budget, while attempts to
fill every client's one-MiB queue are rejected without exceeding the budget.
Listener-global/client-global count interactions, setup-charge release, the
one reserved fatal frame, and REHASH increases and decreases are covered by
deterministic model tests.

Fanout fault tests use one through four targets whose recipient sets overlap.
They make the first, middle, and last sink full; exhaust global memory while
reserving each frame buffer and queue backing; fail allocation after a
matching permit; cancel before and after preparation; close a sink between
reservation and commit; and inject `Rejected`, `Committed`, and
`Indeterminate` storage outcomes. Assertions cover all-or-none rollback,
whole-sink exclusion, canonical per-sink frame order, shared-buffer single
charging, connection-generation non-reuse, exact permit return, and durable
federation re-drive without an in-memory-only event.

Storage qualification runs the release binary with redb 4.2.0 separately for
every declared target/filesystem/block-size/mount-option tuple. A generator
constructs the greatest legal Section-23.4 transaction and each mutation
shape at empty/one/maximum record counts, minimum/maximum keys and values,
insert/replace/delete mixtures, B-tree split/merge boundaries, fragmented
free-space layouts, checkpoint installation, and guard replacement. Allocated
filesystem blocks for the database, guard temporary/final files, and directory
metadata are measured immediately before and after every `fsync`/rename phase.
No observed positive delta may exceed 134,217,728 bytes; the embedded report
records the tuple, kernel, redb features, release-profile hash, corpus hash,
per-case deltas, maximum, and raw log hash and is signed by the release key.
Startup must reproduce the tuple lookup. Boundary tests start one byte below
`R(F) + G`, exactly at it, and one byte above it and prove respectively
side-effect-free rejection, admission, and admission; injected external disk
consumption and every write/sync/rename failure prove the exact
`Indeterminate` closure path. Backup tests likewise use `R(F) + O - 1`, equal,
and plus one for authenticated output length `O`, and construction tests prove
that every scratch/target transaction rechecks `R(F) + G` rather than relying
on stale preflight space.

Load qualification demonstrates the advertised connection/member/channel
configuration on named hardware without missed keepalives, sequence gaps,
unbounded latency growth, or memory growth after quiescence. The report gives
p50/p95/p99 admission, message, durable mutation, OPAQUE, fanout, and snapshot
latencies rather than turning one machine's throughput into a protocol promise.
Soak testing runs seven days with reconnects, churn, storage rekey and
login-index transition, snapshots,
backups, disk-pressure transitions, and injected peer loss; state/memory/file
descriptor counts must return to the expected envelope after each cycle.

### 28.8 Mandatory build and analysis gates

The release pipeline runs, with the pinned release toolchain:

```text
cargo fmt --all --check
cargo check --workspace --all-targets --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
cargo test --workspace --doc --all-features --locked
cargo deny check
cargo audit --deny warnings
cargo llvm-cov --workspace --all-features --branch
```

Branch coverage is at least 90% overall and 100% for parser error
discriminants, authorization decisions, protocol enum arms, persistence
recovery branches, and Section-27 invariant checkers. Coverage never replaces
vectors, fuzzing, model checking, review, or negative tests. The workspace
contains no unsafe block by source scan and no unbounded Tokio channel by
dependency/source scan.

### 28.9 Release decision

Implementation may begin once the specification and profile checks pass. It
does not wait for an external document audit.

The project does not implement cryptographic primitives. Implementation and
tests for the pinned TLS, HPKE, OPAQUE, MLS, AEAD, KDF, and signature libraries
check that their standardized interfaces are configured and composed exactly
as specified: suite selection, identities, contexts, domains, nonce/counter
rules, replay handling, downgrade refusal, key lifecycle, persistent state,
and published vectors. No novel security proof is a release requirement.

There is no fixed reviewer count, signed-report format, degree or credential
requirement. Core and base-federation qualification impose no external-review
gate. An encrypted-v1 release also requires the external cryptographic and
protocol review, remediation, and re-review in companion Section 21 gate 13.
That requirement does not prevent implementation or testing of any profile.

No unresolved critical or high finding is permitted. A medium finding needs a
documented threat analysis, compensating control, owner, and expiry approved by
the release owner; authentication, downgrade, authorization, durability,
secret-leak, or memory-exhaustion findings cannot be waived for the initial
production release. Review evidence may be an ordinary issue, pull request, or
report that identifies the reviewed commit, scope, findings, and disposition.

The release owner signs a checklist asserting every conformance target, gate,
finding disposition, build artifact, SBOM, rollback plan, restore rehearsal,
and deployment guide matches the candidate. Marketing security claims are
checked against Sections 3, 5, 6, and the companion claim template.

## 29. Implementation sequence and acceptance gates

Implementation proceeds in this order. A phase does not begin its
security-sensitive successor until its acceptance evidence is complete.

1. **Registries and types:** implement Appendix A/B constants, private-field
   validated types, canonical codecs, golden/reference vectors, and source
   hash checks. Acceptance: all vector/round-trip/negative tests pass.
2. **Client wire:** implement bounded stream/WebSocket framing, parser,
   capability state, renderer, and transcript harness. Acceptance: parser
   fuzzing plus every client-wire boundary and registration transcript.
3. **Pure domain model:** implement accounts/sessions/channels/modes/roles,
   privacy projections, commands, plans, and the deterministic reference
   model without sockets or storage. Acceptance: generated sequence tests and
   all applicable state/privacy invariants.
4. **Crypto and authentication:** integrate CSPRNG, hashes, AEAD, Ed25519,
   account-service HPKE, OPAQUE, SASL, completion receipts, and credential
   change. Acceptance: vectors, fake-record/dummy-KE3 tests, malicious-edge
   confirmation tests, constant-time-path review, secret-canary scans, and
   worker bounds.
5. **Persistence:** implement record codecs, StorageOwner, transactions,
   integrity/guard recovery, migration, backup/restore construction, deletion,
   storage rekey, and login-index transition. Acceptance:
   the complete crash/fault/corruption matrix and `DUR-*` invariants.
6. **Single-node runtime:** connect supervisors, StateCore, queues, timers,
   TLS listeners, admin, local/global channels, and overload behavior.
   Acceptance: core-v1 transcripts, Loom schedules, shutdown, soak, and host
   hardening checks.
7. **Base federation:** implement FHELLO, origins, requests/results, events,
   projections, snapshots, ACKs, partitions, and recovery. Acceptance: bounded
   formal model, multi-edge fault simulation, exact replay, and privacy scans.
8. **E2EE adapter:** integrate the companion public-object validator and joint
   durable transactions without an MLS client engine. Acceptance: every
   companion Section-21 gate, base/E2EE invariant, collision, reset, and
   downgrade test.
9. **Optional transports/history:** add WSS and pinned history independently.
   Acceptance: their complete negative/interop/privacy tests; neither may
   alter behavior when disabled.
10. **Production qualification:** capacity/soak, reproducible build and SBOM,
    restore/key-rotation drills, release checks, documentation/claim review,
    and signed release decision.

No phase introduces a temporary plaintext listener, permissive parser,
in-memory acknowledgment, unbounded channel, placeholder crypto, wildcard
admin permission, or E2EE downgrade. Test doubles are compile-time dev-only
dependencies and cannot be selected from production configuration.

## 30. Sources and pinned research baseline

The companion evidence file
[Protocol source and decision ledger](protocol-sources-and-decisions.md)
records publication status, deliberate exclusions, living-source commits,
crate checksums/features, and the update procedure. It is supporting evidence;
this specification and the E2EE companion remain the normative project texts.
The nonnormative
[specification manifest](specification-manifest.txt) records the exact raw
hashes of the frozen specification artifacts and validator plus both derived
negotiation hashes. It deliberately does not hash itself.

### 30.1 Normative standards

The following authoritative sources were checked on 2026-08-24. RFC links are
the RFC Editor's immutable publications:

- [BCP 14 / RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
  [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html), requirements words;
- [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html), WebSocket;
- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html), HMAC;
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), HKDF;
- [RFC 6973](https://www.rfc-editor.org/rfc/rfc6973.html), privacy data
  minimization and threat analysis;
- [RFC 8265](https://www.rfc-editor.org/rfc/rfc8265.html) and
  [RFC 8266](https://www.rfc-editor.org/rfc/rfc8266.html), PRECIS username and
  nickname profiles;
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html), ChaCha20-Poly1305;
- [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846.html), the current TLS 1.3
  protocol and exporters, which obsoletes RFC 8446;
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html), Argon2;
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html), HPKE;
- [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html), secure TLS use, as
  updated for new protocols by
  [RFC 9852](https://www.rfc-editor.org/rfc/rfc9852.html);
- [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), MLS;
- [RFC 9525](https://www.rfc-editor.org/rfc/rfc9525.html), TLS service
  identity;
- [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html), MLS architecture;
- [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html), OPAQUE;
- [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html), the TLS 1.3 hybrid
  key-exchange construction; and
- [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html), the Standards
  Track hybrid
  `X25519MLKEM768` TLS key agreement.

The historical base references are the local RFC 1459, 2810, 2811, 2812,
2813, and 7194 files listed in Section 30.3. Their legacy security and server
link behavior is superseded as stated in Sections 2 and 4.

### 30.2 Living protocol and implementation sources

The base client profile is pinned to:

- [IRCv3 specifications commit
  `9ff58d1342af67aff88753388f568542820c4bfe`](https://github.com/ircv3/ircv3-specifications/tree/9ff58d1342af67aff88753388f568542820c4bfe),
  including capability negotiation, message tags, SASL 3.2, labeled response,
  batch, account/presence capabilities, message IDs, server time, monitor,
  SETNAME, standard replies, UTF8ONLY, STS, and WebSocket; and
- [Modern IRC commit
  `8f4c3cc51f0036597f5c95e595fb6ec3177ba4c9`](https://github.com/ircdocs/modern-irc/tree/8f4c3cc51f0036597f5c95e595fb6ec3177ba4c9),
  narrowed wherever this document is stricter.

Operational Tor requirements derive from the Tor Project's
[onion-service protocol](https://spec.torproject.org/rend-spec/),
[SOCKS extensions](https://spec.torproject.org/socks-extensions.html), and
[onion-service setup guide](https://community.torproject.org/onion-services/setup/).
The implementation records a fetched content hash for these living pages in
its conformance ledger.

The initial Rust choices were checked against the official
[Rust 1.98.0 announcement](https://blog.rust-lang.org/2026/08/20/Rust-1.98.0/),
[Cargo `rust-version` reference](https://doc.rust-lang.org/cargo/reference/rust-version.html),
[`opaque-ke` v4.0.1 source](https://github.com/facebook/opaque-ke/tree/v4.0.1),
its exact [`ServerLogin` state/finish contract](https://docs.rs/opaque-ke/4.0.1/opaque_ke/struct.ServerLogin.html),
[`tls_codec` documentation](https://docs.rs/tls_codec/0.5.0/tls_codec/),
[`redb` 4.2.0 documentation](https://docs.rs/redb/4.2.0/redb/), its
[`WriteTransaction` durability/error contract](https://docs.rs/redb/4.2.0/redb/struct.WriteTransaction.html),
and its pinned [two-phase/MVCC design](https://github.com/cberner/redb/blob/v4.2.0/docs/design.md),
[`rustls` documentation](https://docs.rs/rustls/0.23.43/rustls/), and
[`hpke` 0.14.0](https://docs.rs/hpke/0.14.0/hpke/),
[`chacha20poly1305` 0.11.0](https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/),
[`ed25519-dalek` 3.0.0](https://docs.rs/ed25519-dalek/3.0.0/ed25519_dalek/),
and [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny). Package
documentation supports implementation selection; the protocol bytes and
project vectors, not crate defaults, remain normative.

At-rest XChaCha20-Poly1305 is pinned to the construction and known-answer
vectors in [`draft-irtf-cfrg-xchacha-03`](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03),
plus RFC 8439 for its ChaCha20-Poly1305 component. That Internet-Draft expired
and the datatracker records it as a dead IRTF document; this specification does
not mislabel XChaCha as an RFC or IETF standard. Its use is local at-rest
format, not a negotiated wire algorithm, and release requires the pinned draft
vectors, independent library vectors, the `2^40` key-generation usage cap, and
specialist cryptographic review. The reservation-record/guard/manifest
composition is likewise a project storage construction rather than a standard
cryptographic protocol; its domain/key separation, crash-state proof,
rollback limits, nonce accounting, and every serialized transition require an
independent cryptographic review before implementation freeze and again before
a conformance release.

### 30.3 Local immutable-source hashes

These SHA-256 values identify the exact files read for this draft:

| Local file | SHA-256 |
| --- | --- |
| `rfcs/rfc1459-irc-protocol.txt` | `d1fdc86169252b234b17c2f501c0ba7f512ba697ddf8a13b3da7ee4491a76799` |
| `rfcs/rfc2810-irc-architecture.txt` | `b00c6ae92ef66b1b2c3a15df86e6e1ab8268bcb40ebbadd388d75531bf6e62f6` |
| `rfcs/rfc2811-irc-channel-management.txt` | `41e2b24141669f0094e78896f5d2c54d26db2cbed8a299cf9b0bb1aca42d3a96` |
| `rfcs/rfc2812-irc-client-protocol.txt` | `9337603057716c2e74809e8c57b557ee0bdbfca60cc5c852e240df0e5ba53479` |
| `rfcs/rfc2813-irc-server-protocol.txt` | `f67d31f2d4a23fda979ace02e3279c9b3d1ab33e279c8a41e1add7ab293991ba` |
| `rfcs/rfc7194-irc-over-tls.txt` | `7848ebe7e8e7efda651a3488b1122a2db91f3de6253e0fcd9c2eb285256da4ec` |
| `rfcs/rfc8446-tls-1.3.txt` | `47871bc8820a2c3b6ea89f061055577058862cf543686b82d10131239702b3bd` (obsolete historical input; RFC 9846 is normative) |
| `rfcs/rfc9180-hpke.txt` | `f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6` |
| `rfcs/rfc9325-secure-tls-recommendations.txt` | `e3475381d056bde1eed65252954cce68250168454387f6799b38660806f215bc` |
| `rfcs/rfc9420-mls-protocol.txt` | `251ab11076c43fd4b8dc080a068a8caaf55e2fc5e6aa61d4274961627f32624b` |
| `rfcs/rfc9525-tls-service-identity.txt` | `ed8116c2435376dffe37ec2ca688c3a8515e36820852b29e0b6cdfbe92abd2c5` |
| `rfcs/rfc9750-mls-architecture.txt` | `6aa156c5592f99802aae9c39510bf347cacee4abdb1c34baab4c933a6cd992dd` |
| `docs/irc-mls-e2ee-extension.md` | `398237eccca60c7056774b7565dbcac19c38417828191729f50d8fb86a33fdb1` |

Changing a file without updating its hash, source decision, and affected
vectors is a conformance-ledger failure.
The companion's domain-separated version-1 profile hash is
`699c74adfe70c8cc336888e5191d1e09166c5de4406b9c7c8e9a58edadc48159`
(unpadded base64url
`aZx0rf5wyMwzaIjlGR0eCRZsXeRAa5x8jppY7a3EgVk`).

## Appendix A. Client wire registries

### A.1 Command grammar

The parser recognizes only the commands below on a public client listener.
Commands are compared case-insensitively and canonicalized to the uppercase
spelling shown. `csv(T,N)` means one through `N` comma-separated non-empty
values of type `T`, with no whitespace or duplicate canonical value. Brackets
mean an optional complete parameter, not optional bytes within a parameter.
The global 15-parameter and line budgets still apply.

| Command | Accepted parameters after the command |
| --- | --- |
| `CAP` | `LS [302]`, `LIST`, `REQ :<capability-list>`, or `END` |
| `AUTHENTICATE` | one mechanism/chunk token or `*`; Section 11 bounds |
| `PASS` | configured: one canonical 43-character token; otherwise one ignored 1..256-byte token; pre-registration only |
| `ACCTCREATE` | `START <decoded-length>`, `FINISH <decoded-length>`, state-exact `DATA <base64url-chunk>`, or `END`; exact Section-11.2.1/11.3 fixed lengths/chunk counts |
| `ACCTCRED` | registered-only `START <decoded-length>`, `FINISH <decoded-length>`, state-exact `DATA <base64url-chunk>`, or `END`; exact Section-11.2.1/11.5 fixed lengths/chunk counts |
| `NICK` | one nickname |
| `USER` | `<discarded-user> <mode> <unused> :<realname>` |
| `PING`, `PONG` | one trailing or middle token, 0..64 bytes after parsing |
| `QUIT` | optional trailing reason, 0..256 bytes |
| `JOIN` | `0`, or `csv(channel,20) [csv(key,20)]` |
| `PART` | `csv(channel,20) [:reason]`, reason 0..256 bytes |
| `MODE` | `<nick-or-channel> [<mode-string> [arguments...]]`; at most six changes |
| `TOPIC` | `<channel> [:topic]`; omitted trailing means query, present empty means clear |
| `NAMES` | optional `csv(channel,20)`; no server parameter |
| `LIST` | optional `csv(channel,20)`; no masks, ranges, options, or server parameter |
| `INVITE` | `<nickname> <channel>` |
| `KICK` | `<channel> <csv(nickname,4)> [:reason]` |
| `PRIVMSG`, `NOTICE` | `<csv(target,4)> :<body>` |
| `TAGMSG` | one target and at least one permitted client-only tag |
| `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN`, `INFO`, `LINKS` | no parameter, or the exact local server name where the traditional grammar permits one |
| `WHO` | no parameter, one exact visible nickname, or one exact channel; optional `%` WHOX fields are not supported |
| `WHOIS` | one nickname; no remote-server form and no nickname list |
| `WHOWAS` | one nickname and optional decimal count 1..10 |
| `AWAY` | optional trailing text, 0..256 bytes; omitted or empty clears |
| `ISON` | 1..20 nickname parameters |
| `USERHOST` | 1..5 nickname parameters |
| `MONITOR` | `+ <csv(nickname,20)>`, `- <csv(nickname,20)>`, `C`, `L`, or `S` |
| `SETNAME` | one trailing display name, 0..64 prepared UTF-8 bytes |
| `ACCT` | one exact production from Section 14.6 |
| `CHANCTL` | one exact production from Section 14.6 |
| `CHATHISTORY` | exact pinned Section-17 draft production when advertised |

`BATCH` is a server-to-client command in version 1. The `batch` capability is
mandatory infrastructure for labeled and history responses, but no adopted
version-1 facility authorizes a client-sent `BATCH`; such a line receives
`ERR_UNKNOWNCOMMAND`. The same is true of server event commands such as
`ACCOUNT` received from a client.

`STATS`, `OPER`, `CONNECT`, `KILL`, `REHASH`, `RESTART`, `SQUIT`, `DIE`, and
the other restricted commands are recognized only by the separate admin
parser. A public use receives `ERR_NOPRIVILEGES` without parsing credentials or
targets. `TRACE`, `SERVLIST`, `SQUERY`, `SUMMON`, and `USERS` have the fixed
disabled behavior in Section 14. Unknown commands receive
`ERR_UNKNOWNCOMMAND`; an unknown command never reaches a plugin or shell.

For a parameter-count, syntax, or bound error, the complete command is rejected
with `ERR_NEEDMOREPARAMS`, `ERR_INPUTTOOLONG`, an applicable traditional
numeric, or `FAIL <command> INVALID_ARGUMENT`. `NOTICE` suppresses only
automatic delivery errors; malformed framing and connection-level abuse still
follow Sections 9 and 19.

### A.2 Server command and numeric registry

The base daemon may render these nonnumeric commands to a client:

```text
ACCOUNT ACCTCREATE ACCTCRED ACK AUTHENTICATE AWAY BATCH CAP ERROR FAIL INVITE JOIN KICK MODE
NICK NOTE NOTICE PART PING PONG PRIVMSG QUIT SETNAME TAGMSG TOPIC WARN
```

It may render only these three-digit base numerics. Their parameter shape and
traditional meaning follow the pinned Modern IRC source unless this document
narrows them:

```text
001 002 003 004 005
221 251 252 253 254 255 263 265 266
301 302 303 305 306 311 312 314 315 318 319
321 322 323 324 329 331 332 333 341
346 347 348 349 352 353 366 367 368 369
371 372 374 375 376 391
401 402 403 404 405 406 407 409 411 412 417
421 422 431 432 433 441 442 443 451 461 462 464 465
471 472 473 474 475 476 477 481 482 483 501 502
730 731 732 733 734
900 901 902 903 904 905 906 907 908
```

Numeric 417 is `ERR_INPUTTOOLONG`. Numerics 900 through 908 have their IRCv3
SASL meanings. Numeric 317 idle time is intentionally absent. Numerics 325,
338, 378, 379, and any numeric traditionally exposing an address, real host,
route, or idle timestamp are forbidden. Admin replies use standard replies and
the same safe subset rather than creating an unrestricted numeric tunnel.

WHOWAS numeric 314 uses the retained nickname, ephemeral public user and host
components, the fixed `*` marker, and the retained public account label or `*`
as its trailing field. That field never contains a realname. Its numeric 312
uses the configured public reply prefix and retained Unix second, without an
exact server route. Current shared-context authorization still governs each
record; neither a public label nor a historical nickname establishes account
identity or permission to disclose a disconnected session.

The closed base standard-reply code registry is:

```text
ALREADY_AUTHENTICATED AUTH_REQUIRED BAD_SEQUENCE BAD_STATE CHALLENGE CHANGED CHANNEL_FULL
CHECKPOINT CONFIRM CREATED DELETE_CHALLENGE E2EE_REQUIRED E2EE_SYNCING EVENT
INVALID_ARGUMENT NETWORK_UNAVAILABLE NOT_ALLOWED ORIGIN_EXPIRED ORIGIN_GAP
QUERY_EXPIRED RATE_LIMITED RECOVERY_EPOCH REGISTRATION_REQUIRED SECRET_UNAVAILABLE
SERVER_BUSY SLOW_CONSUMER STALE_STATE STORAGE_UNAVAILABLE TOO_LARGE UNAVAILABLE
UNSAFE_CTCP UPDATED VALUE
```

`CHALLENGE`, `CHECKPOINT`, `CONFIRM`, `EVENT`, and `VALUE` are legal only on
the authenticated administrative ALPN with the exact Section-22 shapes.
`SLOW_CONSUMER` is legal only as the Section-19.2 queue warning. All other
codes retain the command applicability defined by their normative sections;
presence in this registry does not make a code valid for an unrelated command.

The base `FederationResult.failed` subset is exactly:

```text
ALREADY_AUTHENTICATED AUTH_REQUIRED BAD_SEQUENCE BAD_STATE CHANNEL_FULL
E2EE_REQUIRED E2EE_SYNCING INVALID_ARGUMENT NOT_ALLOWED ORIGIN_EXPIRED ORIGIN_GAP
QUERY_EXPIRED RATE_LIMITED REGISTRATION_REQUIRED SECRET_UNAVAILABLE SERVER_BUSY
STALE_STATE STORAGE_UNAVAILABLE TOO_LARGE UNAVAILABLE
```

This set is present byte-for-byte as
`mapping|federation-failed-reply-codes` in the profile registry. An admin-only,
local-overload, local-connectivity, successful-NOTE, or unlisted code is a
fatal base-federation result violation.

Companion-profile reply codes are additionally legal only for companion
commands and retain their exact companion semantics. A federation reply with
an unregistered command, numeric, standard-reply code, parameter shape, or
unsafe field is a fatal peer violation, not text to relay.

### A.3 Capability dependencies

| Capability | Required companions/conditions |
| --- | --- |
| `account-notify`, `away-notify`, `invite-notify`, `setname` | standalone |
| `account-tag`, `server-time`, `message-ids` | message-tag parsing support; each is separately negotiated |
| `batch` | message-tag parsing support |
| `labeled-response` | `batch`; server treats the request atomically |
| `echo-message` | standalone; tags are added only when their own capability is active |
| `extended-join` | `account-notify`; absence of an account renders `*` |
| `message-tags` | enables client-only tags and `TAGMSG` |
| `monitor`, `multi-prefix`, `userhost-in-names`, `utf8only` | standalone |
| `sasl` | account service available and at least one Section-11 mechanism active |
| `draft/chathistory` | `batch`, `server-time`, `message-ids`, and enabled Section-17 policy |
| `agenc.ag/account-create=v1` | listener permits account creation |
| `agenc.ag/account-controls=v1` | authenticated account control implementation available |
| `agenc.ag/account-credentials=v1` | pinned account service and Section-11.5 credential-change implementation available |
| `agenc.ag/channel-controls=v1` | channel control implementation available |
| `agenc.ag/recovery` | standalone; advertised value is the exact live Section-9.3 epoch token |
| `agenc.ag/e2ee-mls` | every dependency in companion Section 11.1 |

The server rejects one `CAP REQ` atomically if it includes a capability without
its required companions. It never enables a dependency implicitly except
`cap-notify` through CAP version 302 as the ratified specification requires.

### A.4 Mode and LIST presentation

Client mode letters and prefix order are exactly Sections 12 and 13. Mode
queries never expose a join secret; `+k` is rendered with no secret parameter.
List-mode replies render the canonical typed-mask text, never an internal
binary record or address-derived mask.

`RPL_LIST` numeric 322 carries the lower bound of the privacy bucket as its
integer user-count parameter: `1`, `2`, `5`, `10`, `25`, `50`, or `100`.
The server adds `LISTBUCKETS=1,2,5,10,25,50,100` to ISUPPORT. Thus `2` means
2--4 and `100` means 100 or more; an exact count is never exposed by LIST.
NAMES visible to a current member remains exact because those memberships are
already visible in that channel.

## Appendix B. Base federation canonical schema

### B.1 Encoding notation

All Appendix-B objects use deterministic TLS-presentation-style encoding. The
rules below resolve every shorthand used in Section 20 and this appendix:

- `uint8`, `uint16`, `uint24`, `uint32`, and `uint64` are unsigned network-byte
  order integers of exactly the named width;
- every enum in this document is encoded as one `uint16`; only a listed value
  is valid;
- `opaque x[N]` is exactly `N` bytes without a prefix;
- `opaque x<a..b>` is a byte vector prefixed by the smallest of `uint8`,
  `uint16`, `uint24`, or `uint32` capable of representing `b`, followed by
  exactly that many bytes; both bounds are inclusive;
- `T x<a..b>` for non-opaque `T` is an element-count vector. Its count uses
  the smallest fixed-width unsigned integer capable of representing `b`, then
  exactly that many consecutive encodings of `T`;
- a structure is the concatenation of its fields in written order with no
  alignment, padding, terminator, map key, field name, or version added;
- a union is its `uint16` enum discriminant followed by exactly the registered
  arm; and
- an optional fixed-size opaque field is encoded with its written vector
  prefix and must be either empty or exactly the fixed size required by its
  semantic rule.

ASCII/UTF-8 constraints apply to decoded bytes. Strings have no NUL terminator.
One-byte Boolean values are not used; `Presence` is the `uint16` enum below.
Decoders consume the entire containing vector/object and reject a non-minimal
length, an impossible empty/present combination, an unknown value, duplicate
canonical key, wrong ordering, or trailing byte. Encoders produce exactly one
byte representation for every value.

Every top-level base federation object is hashed as specified in Section 20.4.
Substructures are never independently hashed unless a formula says so.
`profile_version` is exactly 1 and `network_id` must match link configuration
before any other semantic processing.

### B.2 Closed enum registry

The enums declared earlier retain these exact discriminants; this table also
defines the types needed by projection and query arms:

```text
FederationRole: coordinator=1, edge=2
Presence: absent=0, present=1
PrincipalKind: account_principal=1, guest_principal=2
TargetKind: channel_target=1, user_target=2
FederationMessageKind: privmsg=1, notice=2, tagmsg=3
ModeDirection: add_mode=1, remove_mode=2
FederationVisibility: listed=1, unlisted=2, secret=3
FederationPersistence: ephemeral=1, registered=2
FederationContentPolicy: plaintext=1, e2ee_bound=2
FederationRoleLevel: member=0, voice=1, halfop=2, operator=3, admin=4, owner=5
FederationAwayKind: not_away=0, away=1
FederationMemberBucket: one=1, two_to_four=2, five_to_nine=3,
  ten_to_twenty_four=4, twenty_five_to_forty_nine=5,
  fifty_to_ninety_nine=6, one_hundred_plus=7
FederationHistoryPolicy: history_off=0, history_one_hour=1,
  history_twenty_four_hours=2, history_seven_days=3
FederationMaskKind: account_mask=1, user_mask=2, nickname_glob=3,
  cloak_glob=4
FederationAccountSettingKind: set_label=1, clear_label=2,
  public_presence=3, private_presence=4, allow_guest_dm=5,
  deny_guest_dm=6, add_contact=7, remove_contact=8,
  reserve_nickname=9, release_nickname=10, delete_start=11,
  delete_confirm=12, direct_messages_allow=13,
  direct_messages_contacts=14, direct_messages_deny=15
FederationChannelSettingKind: history_off=1, history_one_hour=2,
  history_twenty_four_hours=3, history_seven_days=4, history_default=5
FederationHistorySelectorKind: latest=1, before=2, after=3, around=4,
  between=5
FederationHistoryReferenceKind: no_reference=0, message_id_reference=1,
  timestamp_reference=2
FederationInviteRemovalKind: consumed=1, expired=2, target_gone=3,
  projection_hidden=4
FederationSessionHideKind: client_quit=1, transport_lost=2,
  origin_expired=3, account_deleted=4, operator_removed=5,
  security_fenced=6
FederationDirectoryQueryKind: list=1, names=2, who=3, whois=4,
  whowas=5, ison=6, userhost=7, links=8, monitor_add=9,
  monitor_remove=10, monitor_clear=11, monitor_list=12, monitor_status=13,
  channel_topic=14, channel_modes=15, channel_mode_list=16
FederationQueryTargetKind: no_target=0, nickname_target=1, channel_name_target=2
FederationProjectionKind: session=1, channel_detail=3, membership=4,
  invite=6, account=7
AccountServiceMessageKind: account_create_start=1, account_create_finish=2,
  opaque_auth_start=3, opaque_auth_finish=4, credential_change_start=5,
  credential_change_finish=6
AccountServiceResponseKind: account_create_challenge=1,
  opaque_auth_challenge=2, account_create_complete=3,
  opaque_auth_complete=4, credential_change_challenge=5,
  credential_change_complete=6
AccountServiceCompletionStatus: rejected=1, committed=2
```

The already declared opcode registry is exactly `session_open=1` through
`opaque_auth_finish=22`, followed by reserved value 23,
`channel_settings=24`, `credential_change_start=25`, and
`credential_change_finish=26`, in the order in Section 20.5. The result registry is
exactly `failed=1`, `committed=2`,
`session_registered=3`, `auth_challenge=4`, `authenticated=5`,
`account_created=6`, `reply_page=7`, `no_content=8`, `history_page=9`,
and `history_expired=10`.

The event registry is extended and fixed as:

```text
session_visible=1, session_hidden=2, nickname_changed=3,
channel_visible=4, channel_hidden=5, member_joined=6, member_parted=7,
channel_modes_changed=8, topic_changed=9, invited=10, kicked=11,
away_changed=12, display_name_changed=13, message_delivered=14,
channel_destroyed=15, account_label_changed=16, network_notice=17,
user_modes_changed=18, channel_policy_changed=19,
channel_memberships_recomputed=20, account_state_changed=21,
request_completed=22, invite_removed=23
```

Values not listed above are invalid and remain reserved. In particular, zero
is invalid except where explicitly assigned to an absent/none/member/off state.

### B.3 Common validated values and control arms

These helper structures have the following exact encoding:

```text
struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque recipient_key_id[32];
    opaque client_request_id[16];
    AccountServiceMessageKind message_kind;
} AccountServiceRequestHeader;

struct {
    AccountServiceRequestHeader header;
    opaque enc[32];
    opaque ciphertext<4608..4608>;
} AccountServiceEnvelope;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque recipient_key_id[32];
    opaque client_request_id[16];
    AccountServiceResponseKind response_kind;
    opaque response_salt[32];
} AccountServiceResponseHeader;

struct {
    AccountServiceResponseHeader header;
    opaque ciphertext<4224..4224>;
} AccountServiceResponse;

struct {
    uint16 profile_version;
    opaque transaction_id[16];
    opaque opaque_credential_id[32];
    opaque opaque_message<64..320>;
} AccountServiceChallenge;

struct {
    uint16 profile_version;
    opaque transaction_id[16];
    AccountServiceCompletionStatus status;
    opaque account_id[24];
    uint64 account_session_generation;
} AccountServiceCompletion;

struct {
    uint16 padding_version;
    opaque payload<52..372>;
    opaque zero_padding<3830..4150>;
} AccountServiceResponsePlaintext;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque normalized_login<3..64>;
    opaque registration_request<32..32>;
    opaque creation_invite<0..132>;
} AccountCreateStart;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque transaction_id[16];
    opaque registration_record<192..192>;
} AccountCreateFinish;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque normalized_login<3..64>;
    opaque ke1<96..96>;
} AuthStart;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque transaction_id[16];
    opaque ke3<64..64>;
} AuthFinish;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque account_id[24];
    opaque registration_request<32..32>;
} CredentialChangeStart;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque transaction_id[16];
    opaque registration_record<192..192>;
} CredentialChangeFinish;

struct {
    uint16 padding_version;
    opaque inner_payload<72..265>;
    opaque zero_padding<4321..4514>;
} AccountServiceRequestPlaintext;

// Both padding_version values are 1. Request plaintext is exactly 4592 bytes;
// response plaintext is exactly 4208 bytes; padding is all zero; and the
// selected inner object/response payload consumes its vector exactly.

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque invite_id[16];
    uint64 not_before;
    uint64 expires_at;
    uint16 use_limit;
} AccountCreationInviteTBS;

struct {
    AccountCreationInviteTBS tbs;
    opaque signature[64];
} AccountCreationInvite;

struct { opaque value<1..32>; } FederationNickname;
struct { opaque value<2..64>; } FederationChannelName;
struct { opaque value<1..2048>; } FederationParameter;
struct { opaque value[16]; } FederationChannelId;

struct {
    FederationChannelName channel_name;
    opaque join_key<0..256>;
} FederationJoinTarget;

struct {
    TargetKind target_kind;
    opaque value<1..32>;
    uint64 expected_target_revision;
} FederationMessageTarget;

struct {
    opaque user_component[10];              // lowercase base32, no padding
    opaque host_component[16];              // lowercase base32, no padding
} FederationPublicCloak;

struct {
    PrincipalKind kind;
    opaque identifier<16..24>;
} PrincipalRef;

struct {
    opaque key<1..255>;
    opaque value<0..256>;
} FederationClientTag;

struct {
    FederationMaskKind kind;
    Presence quiet;
    opaque value<1..96>;
} FederationTypedMask;
```

The account-service structures, HPKE suite, key ID, `info`, AAD, exporter,
response encryption, inner-arm mapping, and failure rules are exactly Section
11.2.1. A request operation carries one complete `AccountServiceEnvelope`; its
outer kind must equal the operation opcode, and its authenticated plaintext
must be the corresponding exact `AccountCreateStart`, `AccountCreateFinish`,
`AuthStart`, `AuthFinish`, `CredentialChangeStart`, or
`CredentialChangeFinish`. A successful start result carries one exact
`AccountServiceResponse` whose challenge arm matches the request kind. Every
successfully opened and parsed finish carries its exact encrypted completion
through the Section-20.6 semantic reply list before the terminal NOTE, FAIL,
903, or 904; the coordinator stores those bytes in the idempotent result.

The invitation's field constraints and signature input are exactly Section
11.3. The decrypted `AccountCreateStart` carries the complete 132-byte TLS
encoding of `AccountCreationInvite` inside its `creation_invite` vector, or an
empty vector under open registration; a partial object or trailing byte is
invalid.

`PrincipalRef.identifier` is exactly 24 ASCII bytes matching the Account ID
grammar for `account_principal` and exactly 16 raw User-ID bytes for
`guest_principal`. A `FederationTypedMask.value` is 24 Account-ID ASCII bytes,
16 raw User-ID bytes, or 1..96 ASCII glob bytes according to its kind. `quiet`
may be present only for a ban (`b`) entry and is otherwise `absent`. Client tag
keys are unique and bytewise sorted; each begins `+`, is permitted by Section
9.2, and is stored without IRC tag escaping. Values are the once-unescaped
UTF-8 bytes.

The mode-code registry is:

| Code | Client mode | Legal operation | Request argument encoding |
| ---: | --- | --- | --- |
| 1 | channel `b` | add/remove | `FederationTypedMask` |
| 2 | channel `e` | add/remove | `FederationTypedMask`, `quiet=absent` |
| 3 | channel `I` | add/remove | `FederationTypedMask`, `quiet=absent` |
| 4 | channel `k` | add | `opaque key<8..256>` |
| 4 | channel `k` | remove | empty tuple |
| 5 | channel `l` | add | `uint32 limit`, 1..65,535 |
| 5 | channel `l` | remove | empty tuple |
| 6..11 | channel `i,m,n,p,s,t` | add/remove | empty tuple; removing code 8 (`n`) is invalid |
| 12..16 | channel `q,a,o,h,v` | add/remove | target User ID `[16]` |
| 17..18 | user `i,w` | add/remove | empty tuple; removing code 17 (`i`) is invalid |

The enclosing `FederationModeChange.argument` is `opaque<0..512>` so the
258-byte TLS encoding of a maximum-length channel key fits without changing
the inner `opaque key<8..256>` bound. The letter corresponding to codes 6
through 18 is the positional order shown
in the table. `channel_mode` requests may use only codes 1..16 and `user_mode`
only 17..18. The `FederationModeChange.argument` is exactly the encoding in
the selected row inside its existing length prefix. A mode vector is applied
in client order, but authorization and invariants are checked against its
single final state. Repeating the same `(mode_code, target/mask)` direction in
one vector is invalid; `+p/+s` resolves in vector order and the final state may
contain only one.

Account and channel control payloads are:

```text
struct {
    FederationAccountSettingKind setting_kind;
    opaque value<0..64>;
} AccountSettingsChange;

struct {
    FederationChannelSettingKind setting_kind;
} ChannelSettingsChange;
```

`set_label` carries one valid 1..32-byte account label; `clear_label`, the
four presence/guest-policy selectors, the three direct-message-policy
selectors, and `delete_start` carry empty value.
`add_contact`/`remove_contact` carry exactly one 24-byte Account ID.
`reserve_nickname`/`release_nickname` carry one valid nickname.
`delete_confirm` carries exactly the decoded 16-byte Section-14.6 token.
Every channel setting consists only of its discriminant, which selects the
complete history policy; `history_default` resolves the coordinator
configuration before mutation. These operations carry an expected revision in the enclosing
request and cannot contain multiple changes.

History selectors use:

```text
struct {
    FederationHistoryReferenceKind reference_kind;
    opaque message_id<0..16>;
    uint64 unix_milliseconds;
} FederationHistoryReference;

struct {
    FederationHistorySelectorKind selector_kind;
    FederationHistoryReference first;
    FederationHistoryReference second;
} HistorySelector;
```

`no_reference` has an empty message ID and zero time;
`message_id_reference` has exactly 16 message-ID bytes and zero time; and
`timestamp_reference` has an empty message ID and a nonzero UTC Unix
millisecond value. `latest` permits a reference or no-reference `first` and
requires no-reference `second`. `before`, `after`, and `around` require a
nonempty `first` and no-reference `second`. `between` requires two nonempty
references, permits different kinds and either direction, and uses the
exclusive selection rules in Section 17.2.1. Client timestamps with
nonzero precision below one millisecond are rejected rather than rounded.

Join targets are unique and sorted by `channel_name.value`; each join key is
empty when omitted or the exact 1..256-byte value supplied for that channel.
Only an 8..256-byte value can match a valid stored verifier. Channel-ID
vectors are unique and sorted by `value`. A `FederationMessageTarget` with
`channel_target` has a 16-byte ChannelInstanceId and a nonzero exact channel
revision. One with `user_target` has the canonical nickname comparison form in
1..32 bytes and revision zero. Message targets are unique and sorted by
`(uint16 target_kind, value)`.

Directory requests use one discriminated payload:

```text
struct {
    FederationQueryTargetKind target_kind;
    opaque value<0..64>;
} FederationQueryTarget;

struct {
    FederationDirectoryQueryKind query_kind;
    opaque query<0..2048>;
    opaque cursor<0..32>;
} DirectoryQuery;
```

The `query` arm and cursor rule are closed:

| Query kind | Exact `query` arm | Cursor |
| --- | --- | --- |
| `list` | `FederationChannelName channels<0..20>` | empty/32 bytes |
| `names` | `FederationChannelName channels<0..20>` | empty/32 bytes |
| `who` | one `FederationQueryTarget` | empty/32 bytes |
| `whois` | one `FederationNickname` | empty |
| `whowas` | one `FederationNickname`, then `uint16 count` in 1..10 | empty |
| `ison` | `FederationNickname nicknames<1..20>` | empty |
| `userhost` | `FederationNickname nicknames<1..5>` | empty |
| `links` | empty tuple | empty/32 bytes |
| `monitor_add`, `monitor_remove` | `FederationNickname nicknames<1..20>` | empty |
| `monitor_clear`, `monitor_status` | empty tuple | empty |
| `monitor_list` | empty tuple | empty/32 bytes |
| `channel_topic` | one `FederationChannelName` | empty |
| `channel_modes` | one `FederationChannelName` | empty |
| `channel_mode_list` | one `FederationChannelName`, then mode code `uint16` in 1..3 | empty/32 bytes |

An empty LIST channel vector means every listed channel; an empty NAMES vector
means the requester's currently joined visible channels. `who` accepts
`no_target` only for the requester-only form, otherwise one valid nickname or
channel name. A 32-byte cursor names coordinator-held immutable query state.
Its exact capability construction is:

```text
struct {
    uint16 profile_version;                 // 1
    opaque network_id[32];
    opaque coordinator_server_id[16];
    opaque process_nonce[16];
    opaque session_id[16];
    opaque user_id[16];
    opaque account_id<0..24>;               // guest: empty
    uint64 account_session_generation;      // guest: 0
    FederationDirectoryQueryKind query_kind;
    opaque query_arm<0..2048>;              // exact query bytes; no cursor
    uint64 state_generation;
    opaque snapshot_token[32];
    uint32 next_page_sequence;
    uint64 cursor_counter;
} QueryCursorBindingTBS;

cursor = HMAC-SHA256(
    process_cursor_key,
    "agenc-chat query cursor v1" || TLS-encode(QueryCursorBindingTBS))
```

The Account ID is empty with generation zero for a guest; otherwise it is
exactly 24 bytes and the generation is the session's current nonzero account-
session generation. `query_arm` is the canonical selected union-arm encoding,
not the enclosing `DirectoryQuery` and never includes cursor bytes.

Startup draws an independent 32-byte `process_cursor_key` and 16-byte
`process_nonce` from the operating-system CSPRNG and initializes a checked
`uint64` cursor counter to zero before accepting clients. Each nonfinal page
uses and then increments that counter exactly once; counter exhaustion stops
new query admission with `SERVER_BUSY` and requires a controlled process
restart rather than wrapping. The live cursor table stores the complete TBS,
creation/last-use monotonic instants, snapshot backing, and permits under the
cursor. A computed cursor already present in the live table is a fatal
cryptographic-process failure, not a value to retry with a changed binding.
Consumed cursors do not require an ever-growing tombstone set because every
HMAC input in one process has a unique counter and exact federation request
replay is independently durable.

A cursor expires before use when checked monotonic elapsed time from its last
successful page installation is at least 60 seconds or elapsed time from the
initial snapshot creation is at least 600 seconds. A successor retains the
original creation instant and takes its last-use instant from its infallible
receipt installation, so activity can reset only the idle clock. Creating the snapshot first acquires the Section-19
per-session/global snapshot, row, byte, cursor-slot, and `MemoryBudget`
permits; no row scan or backing allocation occurs before all permits are
available. The snapshot owns exactly one replace-in-place cursor slot, so a
continuation never allocates or copies a second row set. A continuation is
accepted only from the bound live origin/session/account generation with the
exact query kind and arm, current cursor, and next federation replay key. A
retry with that same replay key returns the stored byte-identical result.

The cursor is a one-use capability: durably storing an accepted continuation
result consumes it, and a nonfinal page installs its precomputed successor in
the corresponding infallible StateCore receipt apply. An ordinary commit
failure leaves the old cursor usable; an indeterminate commit enters the
ordinary closed/reconciliation path and no query cursor survives the process.
The snapshot token remains identical and the page sequence increments by one
across all pages. A final page has an empty next cursor and releases the
snapshot permits only after its exact result is durable; replay of that result
does not require the snapshot.

Query snapshots, cursor keys, and cursor tables are deliberately process-local
and are not part of the coordinator incarnation or federation projection.
Therefore an orderly restart may retain its server incarnation while
invalidating every query cursor. Idle/absolute expiry, session close, and
process shutdown release the snapshot and its permits. Presenting an unknown,
expired, consumed, wrong-process, wrong-session, or wrong-query cursor returns
`failed(QUERY_EXPIRED)` with empty safe context and does not consume another
binding's live cursor, create a snapshot, or restart a query. The edge renders
one `FAIL <command> QUERY_EXPIRED :Query snapshot expired`; it never silently
splices a new state cut into a partially delivered query. The stricter
connection-close rule in Section 14.2 applies when this occurs inside a JOIN
NAMES continuation.

The three channel-query arms perform visibility and membership authorization
before revealing whether the name exists. `channel_modes` never returns a join
secret, and `channel_mode_list` returns only canonical `b`, `e`, or `I` entries
visible to a current member or channel operator under Section 13.3. Their
textual replies follow Appendix A and the ordinary `reply_page` byte and row
ceilings; the cursor is present only when a list page continues.

### B.4 Projection records

The coordinator discloses state through these exact least-information records:

```text
struct {
    opaque account_id[24];
    uint64 account_session_generation;
    uint64 account_revision;
} FederationAccountProjection;

struct {
    opaque session_id[16];
    opaque user_id[16];
    opaque home_server_id[16];
    uint64 session_revision;
    opaque account_id<0..24>;
    uint64 account_session_generation;
    FederationNickname nickname;
    opaque display_name<0..64>;
    FederationPublicCloak public_cloak;
    opaque account_label<0..32>;
    uint16 user_mode_bits;
    FederationAwayKind away_kind;
    opaque away_text<0..256>;
} FederationSessionProjection;

struct {
    opaque user_id[16];
    FederationNickname nickname;
    FederationPublicCloak public_cloak;
    opaque account_label<0..32>;
} FederationSourceView;

struct {
    FederationSourceView source;
    opaque home_session_projection<0..508>;
} FederationSessionEventView;

struct {
    Presence user_present;
    opaque source<0..108>;
} FederationActorView;

struct {
    opaque channel_instance_id[16];
    FederationChannelName canonical_name;
    FederationChannelName display_name;
    uint64 channel_revision;
    FederationVisibility visibility;
    FederationContentPolicy content_policy;
    FederationPersistence persistence_policy;
    uint16 simple_mode_bits;
    FederationHistoryPolicy history_policy;
    opaque e2ee_route_binding<0..32>;
} FederationChannelDetail;

struct {
    opaque channel_instance_id[16];
    opaque user_id[16];
    FederationRoleLevel role;
    uint64 membership_revision;
    uint64 joined_at;
} FederationMembership;

struct {
    FederationMembership membership;
    FederationSourceView source;
} FederationMembershipView;

struct {
    opaque channel_instance_id[16];
    uint16 mode_code;                       // 1, 2, or 3
    opaque entry_id[16];
    FederationTypedMask mask;
    FederationSourceView setter;
    uint64 created_at;
    uint64 expires_at;                      // zero means no expiry
} FederationModeListEntry;

struct {
    opaque channel_instance_id[16];
    opaque invite_id[16];
    PrincipalRef target_principal;
    opaque inviter_user_id[16];
    uint64 creation_revision;
    uint64 expires_at;
} FederationInviteProjection;

struct {
    opaque channel_instance_id[16];
    opaque invite_id[16];
    uint64 resulting_revision;
    opaque local_invite_projection<0..91>;
    FederationSourceView inviter;
    FederationSourceView named_target;
} FederationInviteEventView;

struct {
    FederationProjectionKind projection_kind;
    opaque value<1..8192>;
} FederationProjectionValue;

struct {
    uint16 profile_version;
    opaque network_id[32];
    opaque target_server_id[16];
    uint64 projection_generation;
    FederationProjectionValue projection;
} FederationProjectionEntry;
```

`account_id` is empty exactly for an unauthenticated/guest session; its
generation is then zero and its account label is empty. Otherwise it is an
exact 24-byte Account ID and generation is nonzero. `user_mode_bits` uses bit
0 for `i`, bit 1 for `w`, and has no other set bit; bit 0 is always set.
`not_away` requires empty text, while `away` requires 1..256 bytes.
Public-cloak components match `[a-z2-7]` at their fixed lengths.

`FederationSourceView` is the complete event-scoped pseudonymous identity and
encodes to exactly 45..108 bytes. Its fields equal one live authoritative
session revision at event acceptance. It deliberately contains no Session ID,
Account ID, home Server ID, address, transport class, device identity,
realname/display name, away text, user mode, or authority. An edge may retain
the bytes only with the unacknowledged/replay event and discards them after
durable apply and client-frame construction; they are never promoted into a
standing session record.

`FederationSessionEventView.home_session_projection` is empty for a remote or
monitor-only recipient and otherwise contains the exact 101..508-byte encoding
of one `FederationSessionProjection` whose home Server ID is the event target
and whose User ID, nickname, cloak, and account label equal `source`. It is
present exactly when the named local session remains live after the event;
`session_visible` on the home edge requires it, while `session_hidden` uses a
source view directly and deletes the prior home projection. A
`FederationActorView` has `user_present=absent` and empty source only for a
server-originated transition; `present` requires an exact 45..108-byte source
view. `FederationMembershipView` requires matching User IDs between its two
members. Applying one persists the membership only if that User ID resolves to
a current local session projection; otherwise it is used for this event's
rendering and discarded.

`simple_mode_bits` uses bits 0..5 for `i,m,n,p,s,t`; bit 2 (`n`) is always set,
bits 3 and 4 cannot both be set, and all higher bits are zero. An E2EE detail
has a 32-byte route binding; a plaintext detail has an empty route binding.
History is `history_off` unless all Section-17 conditions hold. The standing
detail deliberately omits creator/owner Account IDs, creation time, join-key
existence or verifier, member limit, topic/setter history, account grants,
mode-list rows, and remote membership. The coordinator returns authorized
TOPIC/MODE/NAMES data through bounded queries and supplies live changes through
event arms; none is inferred from an omitted field.

Mode-list codes are limited to `b/e/I`. The mask quiet flag is legal only on
`b`. Its setter is the exact pseudonymous source view captured when the entry
was created; a later identity change does not rewrite it. An account mask
necessarily exposes the Account ID explicitly named by that mask to an
authorized list viewer, but the setter field never adds one. Expiry must exceed
creation when nonzero. An invite expires exactly ten
minutes after its authoritative creation time and is projected only to an edge
hosting its target. An account-target invite is copied to each edge currently
hosting a session for that Account ID; a guest-target invite goes only to its
User ID's home edge. `FederationInviteEventView.local_invite_projection` is
the exact 83- or 91-byte invite encoding on those target edges and is empty on
other recipient edges. When present, its channel/invite IDs equal the two
outer fixed IDs and its creation revision equals `resulting_revision`. Its
inviter and named-target source views match the
authoritative sessions at creation. Current channel-member edges may receive
the transient event for `invite-notify`, but never the target principal or a
standing foreign invite. IRC exposes no invite-list query.

The projection union arms are exactly:

| Kind | `value` encoding |
| --- | --- |
| `session` | `FederationSessionProjection` |
| `channel_detail` | `FederationChannelDetail` |
| `membership` | `FederationMembership` |
| `invite` | `FederationInviteProjection` |
| `account` | `FederationAccountProjection` |

Discriminants 2 and 5 are reserved and invalid in version 1; summaries and
mode-list rows are coordinator query state, never standing edge projection.
The primary key for snapshot order is, respectively: User ID; Channel ID;
Channel ID followed by User ID; Channel ID followed by invite ID; or Account
ID. Entries sort by
`uint16 projection_kind` then this primary-key byte string. The key is unique.
Every membership/session and child/channel reference must resolve within the
same installed generation. An edge has exactly one detail entry for each
locally entitled channel. It has no remote membership, mode-list, global
directory-summary, or foreign invite entry.

An account projection has a canonical 24-byte Account ID and nonzero
generation/revision. It exists on an edge exactly while that edge hosts at
least one authenticated session naming the same Account ID and session
generation. It is never projected solely because a remote session is visible.
Every local authenticated session resolves one such entry; guests resolve
none. Account settings use its exact revision and an account-state event
atomically replaces it on every edge currently hosting that account.

### B.5 Event arms and projection deltas

Projected mode changes redact request-only secrets:

```text
struct {
    opaque channel_instance_id[16];
    uint64 resulting_revision;
} FederationDepartedChannel;

struct {
    ModeDirection direction;
    uint16 mode_code;
    opaque argument<0..8192>;
} FederationProjectedModeChange;

struct {
    opaque message_id[16];
    FederationMessageKind message_kind;
    TargetKind target_kind;
    opaque target_id[16];
    FederationSourceView sender;
    uint64 target_revision;
    uint64 channel_event_sequence;
    uint64 received_unix_milliseconds;
    FederationClientTag tags<0..16>;
    opaque body<0..512>;
} FederationDeliveredMessage;
```

For a projected mode change, codes 1..3 carry the complete
`FederationModeListEntry` for both addition and removal (the removal arm is the
exact record captured before deletion); code 4 carries one `Presence`
representing the resulting key state; code 5 carries one `uint32`
resulting limit where zero means absent; codes 6..11 carry an empty tuple; and
codes 12..16 carry the complete resulting `FederationMembershipView`. Raw join
keys never occur in events or projections. User-mode changes use no projected
mode-change object; their complete resulting session projection is sent only
to the home edge.

A registered-channel account-grant change that can affect multiple sessions
uses `channel_memberships_recomputed`: Channel ID `[16]`, one resulting
revision, the actor view, and 1..32 complete `FederationMembershipView` values
in User-ID order. It is one event and one revision; each target edge receives
only membership views visible to one of its local members, persists only those
whose User ID is local, and recomputes prefix rendering for all included
users. This output expansion does not relax the six-change request limit.

For a delivered message, channel target is a ChannelInstanceId and direct
target is a User ID. Channel event sequence is nonzero for a channel and zero
for a direct message. `privmsg` requires nonempty body; `notice` permits empty
body; `tagmsg` requires empty body and at least one tag. Tags are canonical as
in B.3. The captured sender source view is exact at acceptance so a later
nickname, cloak, or label change cannot rewrite history or an echo. Its target
edge uses that view only for this delivery and replay window.

The `event` field of `FederationEvent` has exactly the following arm. Names in
parentheses are structures above; comma-separated items are concatenated in
that order:

| Event kind | Exact `event` arm |
| --- | --- |
| `session_visible` | one `FederationSessionEventView` |
| `session_hidden` | one `FederationSourceView`, last session revision `uint64`, one `FederationSessionHideKind`, `FederationDepartedChannel channels<0..256>`, reason `<0..256>` |
| `nickname_changed` | old `FederationNickname`, then one `FederationSessionEventView` |
| `channel_visible` | one `FederationProjectionValue(channel_detail)` |
| `channel_hidden` | Channel ID `[16]`, last channel revision `uint64` |
| `member_joined` | one `FederationMembershipView`, resulting home-session revision `uint64`, then display name `<0..64>` |
| `member_parted` | Channel ID `[16]`, one `FederationSourceView`, resulting channel revision `uint64`, resulting home-session revision `uint64`, reason `<0..256>` |
| `channel_modes_changed` | Channel ID `[16]`, resulting revision `uint64`, one `FederationActorView`, `FederationProjectedModeChange changes<1..6>` |
| `topic_changed` | Channel ID `[16]`, resulting revision `uint64`, one `FederationActorView`, topic presence, topic `<0..1024>`, set time `uint64`, Message ID `<0..16>` |
| `invited` | one `FederationInviteEventView` |
| `invite_removed` | Channel ID `[16]`, Invite ID `[16]`, resulting channel revision `uint64`, one `FederationInviteRemovalKind` |
| `kicked` | Channel ID `[16]`, one `FederationActorView`, target `FederationSourceView`, resulting channel revision `uint64`, target home-session revision `uint64`, reason `<0..256>` |
| `away_changed` | one `FederationSessionEventView`, resulting `FederationAwayKind`, away text `<0..256>` |
| `display_name_changed` | one `FederationSessionEventView`, display name `<0..64>` |
| `message_delivered` | one `FederationDeliveredMessage` |
| `channel_destroyed` | Channel ID `[16]`, final revision `uint64` |
| `account_label_changed` | one `FederationSessionEventView` |
| `network_notice` | registered code `<1..64>`, safe text `<1..512>` |
| `user_modes_changed` | one `FederationProjectionValue(session)` |
| `channel_policy_changed` | one `FederationProjectionValue(channel_detail)` |
| `channel_memberships_recomputed` | Channel ID `[16]`, resulting revision `uint64`, one `FederationActorView`, `FederationMembershipView memberships<1..32>` in User-ID order |
| `account_state_changed` | one `FederationProjectionValue(account)` |
| `request_completed` | resulting global state generation `uint64` |

`security_fenced` is used only when an account-security generation invalidates
a still-live session, including Section-11.5 credential replacement. Its reason
is exactly the UTF-8 bytes `connection closed`; it carries no password,
credential-change, recovery, or incident discriminator. Other hide kinds may
not be substituted merely to avoid their authorization or retention rules.

The event subject key used by Section 20.6 is exact: session-visible/hidden,
nickname, away, display-name, account-label, and user-mode events use User ID;
channel-visible/hidden/destroyed, channel-mode/topic/policy, and membership-
recompute events use Channel ID; join/part use Channel ID then subject User ID;
invite and invite-removal use Channel ID then Invite ID; kick uses Channel ID then target User
ID; message uses encoded TargetKind then target ID then Message ID; account
state uses Account ID; network notice uses code bytes; and request completion
uses the complete replay key. All concatenated components have fixed width
except the notice code, whose bytes are compared directly. No nickname or
display text participates in durable event ordering.

Every projection value's kind must match its arm, target edge, projection
generation, and current entitlement. `channel_visible` is emitted immediately
before the first local membership/invite that creates entitlement.
`channel_hidden` atomically deletes the detail only after the last local child
record is removed; `channel_destroyed` may delete the detail and all remaining
local children together. There is no summary transition. A transient remote
membership/source view never creates a projection entry.

`session_visible`, `nickname_changed`, `away_changed`,
`display_name_changed`, and `account_label_changed` carry a home session
projection exactly under the B.4 rule and otherwise only transient public
fields. `session_hidden` is one target-specific event for the home edge, every
edge with a local member sharing at least one departed channel, and every
current authorized MONITOR-recipient edge; its source is the final accepted
pseudonym. Its channel vector is bytewise sorted and unique. It contains every
departed channel on the home edge, only channels with an immediately preceding
local recipient on a shared edge, and is empty on a monitor-only edge.

Before deleting anything, the edge unions its local membership indexes for
that vector and its authorized MONITOR subscribers. It renders exactly one
QUIT per eligible local client even when several channels overlap, plus the
normal MONITOR offline notification where negotiated. The home copy then
deletes the local session and all its membership projections; if it was the
last local session for its Account ID/User ID target, the preceding bounded
`projection_hidden` invite events remove those copies and the session-hidden
transaction removes the now-unreferenced account projection. Remote copies
retain no session or membership to delete. `client_quit` preserves the
validated client reason; every other kind uses a registered generic reason
that discloses no address, Tor status, peer route, or sanction evidence.
`channel_hidden` events for newly unentitled channels follow this event.

`user_modes_changed`
is home-only. The extra display name on `member_joined` is solely for
`extended-join`; away/display fields on their named events are solely for the
matching negotiated notification and are discarded after fanout.

The home-session revision in a JOIN, PART, or KICK copy is nonzero exactly
when the affected User ID has a session homed on the target edge; it is zero
on every remote copy. These three event kinds leave the session live. A
nonzero value updates that local
session projection and is exactly its prior revision plus one. All accepted
targets of one multi-target JOIN/PART for the same session repeat the one
resulting revision; only the first applied copy advances it. A mismatch,
revision gap, nonzero value without a matching local session, or zero value for
a continuing local session is fatal.

`member_parted` represents explicit PART/JOIN-0 or another membership removal
that leaves the session live and renders PART. Closing, losing, expiring, or
operator-removing a complete session never synthesizes per-channel PARTs; it
uses the one `session_hidden` event above so conventional clients receive one
QUIT.

A TOPIC event always requires a present actor. `topic_presence=absent`
requires empty topic, zero set time, and empty Message ID; `present` requires
a 1..1,024-byte plaintext topic or the fixed nonempty E2EE placeholder,
nonzero set time, and a 16-byte Message ID. An invited event's inviter view
matches its local projection's inviter User ID when that projection is
present, and its named target is the nickname target resolved by the request.
A target edge persists the local projection before rendering; every other
recipient uses both source views only for `invite-notify`. A KICK actor is
present for a user command and may be absent only for a registered
server/operator enforcement path; its target view names the removed
membership. Mode/recompute actor absence follows the same rule. Added or
updated prefix-mode membership views use their embedded sources for rendering
and retain only local memberships.

For an already visible channel, the first state-changing event for a new
`coordinator_state_generation` advances its channel revision by exactly one;
later phases/copies for that same channel and generation repeat that resulting
revision. A lower revision, a jump, or two revisions for one generation is
fatal. `channel_visible` introduces the complete current nonzero revision
without replaying hidden history, and snapshot installation does likewise.
`message_delivered.target_revision` equals the installed current revision and
does not advance it. `member_joined` uses
`membership.membership_revision` as its resulting channel revision;
`invited` uses its explicit resulting revision. PART, KICK, mode, topic,
recompute, policy,
hidden, and destroyed arms carry the resulting revision explicitly.
Each `session_hidden.channels` element likewise advances that named visible
channel by one for the authoritative membership removal; a following
`channel_hidden` repeats it. The same channel cannot occur twice in the vector
or in two session-hidden copies for the same target edge and mutation.
Mode-delta application changes the detail's simple bits for codes 6..11,
updates only the revision for codes 1..5, and applies codes 12..16 only to
matching local memberships. Topic changes update only the detail revision;
topic content remains event/query state rather than standing projection.
`invite_removed` deletes exactly one local invite projection. `consumed`,
`expired`, and `target_gone` carry the authoritative resulting channel
revision (consumption may repeat the JOIN revision); `projection_hidden`
removes only an edge copy because its last local target session disappeared
and therefore repeats the current channel revision. If that deletion removes
the last local entitlement, its `channel_hidden` follows. Opening the first
new local session for an account reprojects each still-live account invite as
one ordinary target-only `invited` event; it does not resend `invite-notify` to
unrelated member edges. That session-open plan sorts at most
`invites_per_principal` invites by `(Channel ID, Invite ID)`, inserts any
needed channel detail immediately before its first invite, and admits every
entry/event/counter/outbox delta atomically or rejects registration with
`SERVER_BUSY`. Closing the last local target session emits the corresponding
`projection_hidden` removals and channel hides in the same bounded order; it
never leaves a foreign invite projection behind or deletes the authoritative
account invite.

The request-correlation fields in `FederationEvent` are present exactly on
`request_completed` under Section 20.8 and empty on every other arm. A
completion event does not alter user/channel/account projection state. In the
same transaction as its durable delivery cursor, it marks the matching local
exact request-result record event-covered; only that marker authorizes
rendering of the already stored result unless Section-20.9 snapshot coverage
does so first.

`account_state_changed` is sent only to edges currently hosting a session for
that account. All copies from one account mutation contain the identical
account projection. When the last such session leaves an edge, applying its
ordered `session_hidden` event removes the now-unreferenced account projection
in the same edge transaction; a snapshot likewise contains no unreferenced
account projection.

### B.6 Request/result and origin constraints

The Section-20.5 operation table is the exhaustive union registry. In addition
to its field bounds, these arm constraints are normative:

- `session_open` is accepted only under a generation-zero pre-registration
  origin; its Connection ID and nonce match `FederationOrigin`, its capability
  hash is SHA-256 over the bytewise-sorted enabled capability names encoded as
  an element vector, and its auth-grant field is empty or exactly 32 bytes;
- `session_close` is accepted once for a currently registered origin and
  permanently closes that logical session even if the socket disappears first;
- every Session ID in an operation matches the current origin object; every
  Channel ID/target and expected revision is resolved in the coordinator's
  current state before authorization;
- `invite` carries a canonical nickname rather than requiring the edge to
  possess an otherwise-hidden User ID; the coordinator resolves it inside the
  same visibility and authorization decision;
- each `join` target names a channel because lookup itself is
  visibility-sensitive; operations after join use the returned immutable
  ChannelInstanceId;
- ordinary `part` has `all_channels=absent` and 1..20 channel IDs; JOIN 0 has
  `all_channels=present`, an empty reason, and the exact sorted set of 0..256
  current global memberships at the expected session revision;
- mode/list/multi-target encodings have the ordering and uniqueness rules in
  Sections 14 and B.3; KICK's concatenated 1..4 User IDs are sorted bytewise
  and unique, and the raw join key exists only in the request job;
- `message` is base plaintext/client-tag delivery only, uses the exact sorted
  1..4 target union from B.3, and has exactly one target for `tagmsg`; all
  companion objects use the companion request protocol, never this arm;
- account/channel settings encode exactly one Appendix-B selector;
- account creation and OPAQUE auth operations are accepted only under an
  unregistered origin; credential-change operations require the exact current
  registered Session ID and Section-11.5 fresh-auth state; every account-service
  envelope outer kind, opcode, and authenticated
  inner arm agree, only the coordinator decrypts them, and the decrypted
  `account_create_start` has an empty invitation exactly under open policy or a
  canonical Section-11.3 invitation under invite policy; and
- query `limit` is 1..100 for history and is exactly the server's requested
  page size after clamping to the advertised maximum; a caller cannot request
  a larger internal scan through federation.

An authentication grant is 32 random bytes created in the durable successful
authentication transaction and bound to Network ID, edge/incarnation,
origin/generation, connection nonce, Account ID, and account-session
generation. It expires after 30 seconds, is consumed by exactly one matching
`session_open`, and is never stored after consumption except as a keyed digest
inside the exact idempotency result. A duplicate `session_open` replays its
result; another use fails without revealing the account. The same-process
grant owner may also hold the nonpersistent Section-11.4 monotonic
authentication instant; absence after restart affects only fresh-auth status,
not the account binding or grant's one-use rule.

The `result` union in `FederationResult` is exactly:

| Result kind | Exact `result` encoding |
| --- | --- |
| `failed` | reply code `<1..64>`, safe context `<0..255>` |
| `committed` | resulting global state generation `uint64` |
| `session_registered` | Session ID `[16]`, User ID `[16]`, session revision `uint64`, Account ID `<0..24>`, account-session generation `uint64`, account revision `uint64`, resulting global state generation `uint64` |
| `auth_challenge` | canonical `AccountServiceResponse` for the exact ingress request |
| `authenticated` | Account ID `<24..24>`, account-session generation `uint64`, auth-grant ID `[32]` |
| `account_created` | Account ID `<24..24>`, account revision `uint64` |
| `reply_page` | snapshot token `[32]`, page sequence `uint32`, next cursor `<0..32>` |
| `no_content` | empty tuple |
| `history_page` | Session ID `[16]`, ChannelInstanceId `[16]`, FederationChannelName, FederationHistoryAuthorization, snapshot token `[32]`, snapshot state generation `uint64`, page sequence `uint32`, next cursor `<0..32>`, FederationHistoryMessage vector `<0..100>` |
| `history_expired` | original result object ID `[32]` |

Every opcode permits `failed`. Its only successful result kinds are:

| Opcode | Permitted success result kind |
| --- | --- |
| `session_open` | `session_registered` |
| `session_close`, `nick_change`, `join`, `part`, `channel_mode`, `user_mode`, `topic`, `invite`, `kick`, `away`, `setname`, `channel_register`, `channel_unregister`, `channel_settings` | `committed` |
| `message` | `committed`, or `no_content` only for a NOTICE with zero accepted targets |
| `account_settings` | `committed`, or `no_content` only for `delete_start` |
| `history_query` | `history_page`, or terminal `history_expired` under Section 20.6.1 |
| `directory_query` | `reply_page`, or `no_content` only when the selected MONITOR operation has no protocol reply |
| `account_create_start`, `opaque_auth_start` | `auth_challenge` |
| `account_create_finish` | `account_created` |
| `opaque_auth_finish` | `authenticated` |
| `credential_change_start` | `auth_challenge` |
| `credential_change_finish` | `committed` |

For a multi-target operation with at least one accepted target, the result is
`committed` and `replies` also contains every canonical per-target failure.
With no accepted target it is `failed`, using the first canonical failure in
the result arm and the complete bounded failure set in `replies`; NOTICE is
the sole suppression case above. A result kind not listed for its request
opcode is a fatal federation protocol violation even if its bytes otherwise
decode.

For `join`, semantic `member_joined` events supply the JOIN lines. The
`committed` result replies contain, in accepted-target order, exactly the
applicable 331 or 332+333 topic numerics, interleaved with the canonically
ordered failed-target replies, and never contain 353/366 NAMES numerics. With
at most 20 targets this is at most 40 replies. The home edge derives the exact
accepted name set from its request plus this complete failure set and runs the
Section-14.2 `JoinNamesContinuation`; any missing, duplicate, or non-requested
failure context is a fatal result inconsistency. History pages may continue
under the bounded Section-20.6.1 history cursor protocol. No other operation implicitly
starts a follow-up federation request.

`FederationResult.completion_event_id` is exactly 16 bytes for `committed` and
`session_registered` and empty for every other result kind. For the two
present cases it names the matching Section-20.6 `request_completed` event and
that event's `coordinator_state_generation` and arm both equal the result arm.
Rendering requires either the
durably applied event or the exact successor-snapshot coverage proof in
Section 20.9; merely receiving FRESULT is insufficient.

The Account ID/generation consistency rule from B.4 applies to
`session_registered`; its account revision is zero for a guest and is the
nonzero value in the simultaneously projected account entry for an
authenticated session. A base `failed` code is in Appendix A's exact
federation subset; a companion code is in the companion registry as
applicable. Its context is empty or a validated identifier/name already
present in the request; it never contains parser/database/crypto text.
`no_content` is used only by the three
explicit mapping rows above and has exactly the operation's bounded replies.

A non-page result contains 0..64 `FederationReply` values. A `reply_page`
contains 1..512, uses a nonzero random snapshot token, starts at page sequence
zero, and increments contiguously. Its next cursor is empty on the final page
and exactly 32 bytes otherwise. Query snapshot and cursor state has the
60-second idle and nonextendable 10-minute absolute lifetime from B.3 and is
capped by Section 19. Every continuation page retains the initial snapshot
token and uses the one-use current-process cursor transition in B.3; any cursor
failure returns exactly `failed(QUERY_EXPIRED)` rather than silently restarting
a query.

The complete encoded `FederationResult` for a reply page and the sum of its
predicted rendered client frames are each at most 65,536 bytes. Page formation
stops before the first reply that would cross either bound and returns a cursor;
because one legal client frame is at most 8,703 bytes, every individual reply
fits. This fixed floor is why conforming configurations cannot lower
`response_batch_bytes` below 65,536.

Within `FederationReply`, `command` is an Appendix-A server command or numeric
in ASCII. A numeric is exactly three digits. Middle parameters are 1..2048
bytes, contain no NUL/CR/LF/SPACE, and do not begin `:`. With
`trailing_presence=absent`, trailing bytes are empty; with `present`, 0..4096
validated UTF-8 bytes are rendered after `:`. The complete rendered frame must
fit the receiving client's negotiated tag/line budget. Query pages are formed
at IRC message boundaries and never split one reply between results.

For `FederationOrigin`, generation zero has an all-zero predecessor and empty
Session/User/Account fields. Each UPDATE increments generation exactly once,
sets `previous_origin_object_id` to the Section-20.4 object ID of the accepted
predecessor, and carries the complete new state. Session and User ID are both
empty or both present. A registered guest has present Session/User IDs with
empty Account ID and zero account-session generation. An authenticated session
has a 24-byte Account ID and nonzero generation. Connection ID, connection
nonce, home server, incarnation, and origin ID are immutable. No origin object
contains nickname, cloak, transport class, source address, TLS certificate, or
login material.

### B.7 Event, delivery, and snapshot consistency

An event ID is 16 fresh random bytes durably reserved with the event. Delivery
sequence begins at zero for each `(target_server_id, projection_generation)`
and increments by one without wrap; reaching `uint64::MAX` requires a new
snapshot generation before another event. The event's target, generation,
sequence, ID, kind, object ID, and carrier parameters are mutually checked.
Its `coordinator_state_generation` is the exact resulting global generation of the
durable mutation that created it. It is nondecreasing in delivery order, and
every event correlated to one request has the same value as that request's
successful result arm. A value greater than the coordinator's authenticated
current state, a decrease, or a completion-arm mismatch is fatal.

The optional correlation tuple in `FederationEvent` has these exact presence
rules:

```text
request_home_server_id: empty or 16 bytes
request_server_incarnation: empty or 16 bytes
request_origin_id: empty or 16 bytes
request_origin_generation: zero if empty, exact value if present
request_operation_sequence: zero if empty, exact value if present
request_id: empty or 16 bytes
```

The four variable IDs are all empty or all present. Both integers are zero for
an empty tuple. A present tuple carries the exact generation and operation
sequence from the durable request result; either value may be zero under
Section 20.5. The tuple occurs only on that request's home-edge
`request_completed` event, and its event field plus arm generation equal the
committed result.

The cross-profile tuple is independently all absent or all present:

```text
cross_profile_mutation_id: empty or 16 bytes
cross_profile_part_index: zero when empty; 0..count-1 when present
cross_profile_part_count: zero when empty; 2..2048 when present
```

For a present tuple, at least one companion event for the same target, mutation
ID, count, and coordinator generation exists in addition to at least one base
event; every index is occupied exactly once across the two profiles, base
indices are the contiguous prefix, and the complete charged aggregate is at
most 16,777,216 bytes. The target-specific ordering, staging, combined apply,
cumulative ACK, replay receipt, and non-snapshot-replacement rules in Section
20.8 are part of canonical event validation, not optional implementation
behavior.

For a snapshot, every `FSNAPSHOT ENTRY` object is one
`FederationProjectionEntry` with the BEGIN target/generation. Its carrier index
starts at zero and its object ID is the Section-20.4 hash. The declared
`entry-count` is exact and its uint64 value is no greater than 1,000,000.
`state-generation` is the coordinator global state generation at which the immutable
projection was cut. The snapshot digest input encodes the projection and state
generations as `uint64`, preceded by the exact 16-byte coordinator recovery
epoch, then an element-count vector of 32-byte object IDs in entry order.

The END cursor is the delivery sequence/event ID immediately preceding the
first queued post-snapshot event, or `*/*` if the projection has no prior event.
Both are present or both `*`. Events created after the snapshot cut remain in
the outbox and begin replay only after ACTIVE. READY/ACTIVE echo every BEGIN
identity field and digest. A token is bound to one link identity, target,
projection generation, state generation, digest, and expiry and is unusable
after success/failure.

Applying an event or snapshot value revalidates all B.4 semantic constraints;
an object ID alone is never sufficient. A projection generation stores no
orphan session, child channel entry, duplicate summary/detail, mismatched
revision, or E2EE route inconsistent with the simultaneously installed
companion state.

### B.8 Text carrier tokens and command arity

All base federation text tokens use this grammar:

```text
b64char      = ALPHA / DIGIT / "-" / "_"
id16         = 22b64char                  ; exactly 16 decoded bytes
hash32       = 43b64char                  ; exactly 32 decoded bytes
uint64-dec   = "0" / (%x31-39 *19DIGIT)
uint32-dec   = "0" / (%x31-39 *9DIGIT)
index-dec    = uint32-dec
star-cursor  = "*" / uint64-dec
star-id      = "*" / id16
```

Base64url is unpadded with canonical unused bits and must decode/re-encode
identically. Decimal tokens have no leading zero and are range-checked. A
server name is the configured authenticated name, not an arbitrary token.
Every Section-20 federation command has exactly the displayed parameters, no
optional trailing parameter, no client-only tag, and no tag other than its one
required `agenc.ag/fed` fragment tag. `FHELLO`, `FREADY`, `FPING`, `FPONG`,
`FRESUME`, `FACK`, and the non-object snapshot/origin controls have no tag.

The `FHELLO` payload is one unpadded base64url encoding of the exact
`FederationHello` bytes. Its peer Server ID and every textual 16-byte ID use
`id16`; the FREADY hello nonce and every profile/object/snapshot digest use
`hash32`. An object-bearing line's descriptor ID and fragment-tag ID must be
equal before a reassembly reservation is granted. All fragmented lines for one
object repeat byte-identical command and descriptor parameters.

### B.9 Federation profile hash

The normative machine-readable registry is
`docs/federation-v1-profile.registry`. It is UTF-8 restricted to printable
ASCII plus LF, uses LF line endings, ends in exactly one LF, contains no blank
or comment line, and has complete lines sorted in ascending bytewise order.
Each line is one `category|name|canonical-value` triple; `|`, CR, and LF cannot
occur inside a component. Numeric values are canonical decimal. Schema field
values use the exact B.1 type spelling and comma-separated field order. The
closed categories are `constant`, `crypto`, `enum`, `hash`, `mapping`, `mode`,
`order`, `schema`, and `wire`. Mapping lines define closed cross-union
relationships; `mapping|result.<opcode>|...` lists every permitted result kind
for that opcode in discriminant order.

FHELLO computes:

```text
profile_hash = SHA256(
    "agenc-chat base federation profile registry v1\0" ||
    exact_registry_file_bytes
)
```

The exact registry file SHA-256 is
`1b94cb7b43dc458ff683ddcfd86eed1939128a7a6d0229b89342bd6816eb5411`.
The resulting version-1 `profile_hash` is
`7b00e0d0844270626411d398f15f7520224ea906117738e3da9741a611dc67b3`
(unpadded base64url `ewDg0IRCcGJkEdOY8V91ICJOqQYRdzjj2pdBphHcZ7M`). A placeholder
or hash of a locally regenerated alternative is invalid. The registry
enumerates every enum, top-level/arm/helper structure, field, mode code, bound,
carrier command, cryptographic suite/domain label, hash label, and ordering
rule that changes federation interpretation. Prose privacy and authorization
rules remain normative even where they do not alter the hash.

## Appendix C. Complete configuration schema

### C.1 Scalar rules and top-level document

The root contains `config_version = 1` followed by exactly these tables:
`network`, `server`, `listeners`, `tls`, `federation`, `storage`, `accounts`,
`limits`, `privacy`, `moderation`, and `e2ee`. A table cannot be omitted,
although fields with stated defaults may be omitted. Arrays use the singular
element names shown below. No other root value or table is legal, and every
table or array element rejects a key not listed in this appendix. This closed
schema makes misspelled security and limit settings startup errors.

Configuration integers are unsigned TOML integers and are range-checked before
conversion. Byte sizes are bytes; durations state their unit in the key. IDs,
hashes, public keys, DNS names, onion names, nicknames, and channel names use
the canonical grammars in this document. An "optional string" is omitted when
absent; an empty string is invalid. Paths are absolute after resolution and
undergo Section-22 permission/symlink validation. `required` means `init`
emits the value and startup rejects its absence.

### C.2 Network and server

| Key | Type/default | Constraint and reload class |
| --- | --- | --- |
| `network.network_id` | string, required | 43-character Network ID; restart-only |
| `network.display_name` | string, required | 1..32 ASCII `[A-Za-z0-9._-]`; reloadable |
| `network.role` | `coordinator` or `edge`, required | restart-only |
| `network.coordinator_server_id` | Server ID, required | equals local ID for coordinator; restart-only |
| `network.dns_name` | optional string | lowercase RFC-9525 reference DNS name; restart-only |
| `network.dns_port` | integer, 6697 | 1..65,535; restart-only |
| `network.onion_address` | optional string | exact lowercase 56-base32 v3 name plus `.onion`; restart-only |
| `network.onion_port` | integer, 6697 | 1..65,535; restart-only |
| `network.onion_tls_spki_sha256` | optional hash | required exactly when onion address is present; restart-only |
| `server.server_id` | Server ID, required | matches database/certificate identity; restart-only |
| `server.name` | string, required | Section-7.4 name, at most 127 bytes when federation is enabled; restart-only |
| `server.data_dir` | path, required | dedicated existing directory; restart-only |
| `server.runtime_dir` | path, required | dedicated existing directory; restart-only |
| `server.memory_budget_bytes` | integer, 4,294,967,296 | 536,870,912..1,099,511,627,776; restart-only |
| `server.tokio_worker_threads` | integer, 4 | 2..128; restart-only |
| `server.crypto_worker_threads` | integer, 4 | 1..128, no greater than `channel_key_jobs + opaque_jobs`, and passes Section-19 memory arithmetic; restart-only |
| `server.quiesce_seconds` | integer, 5 | 1..30; reloadable downward only |
| `server.drain_seconds` | integer, 20 | 1..60; reloadable downward only |
| `server.flush_seconds` | integer, 10 | 1..30; reloadable downward only |
| `server.stop_seconds` | integer, 5 | 1..30; reloadable downward only |
| `server.require_locked_secrets` | bool, false | host policy; restart-only |

The four shutdown values sum to no more than 120. `display_name` changing does
not change Network ID. A DNS/onion endpoint may be absent, but at least one
enabled client listener must correspond to the onboarding endpoints unless the
node is explicitly an edge with `accounts.accept_clients=false` below.

### C.3 Listener union

`listeners` contains 1..16 `[[listeners.endpoint]]` elements with these common
fields:

| Key | Type/default | Rule |
| --- | --- | --- |
| `name` | string, required | unique 1..32 ASCII identifier |
| `enabled` | bool, required | no implicit enable |
| `purpose` | enum, required | `client_tls`, `client_wss`, `client_onion`, `federation`, `admin_local`, or `admin_tls` |
| `bind` | string, required | exact IP:port in brackets where needed, or absolute Unix path by purpose |
| `max_connections` | integer, required | 1..applicable Section-19 hard maximum |
| `tls_certificate_file` | optional path | required for every purpose except `admin_local` |
| `tls_private_key_file` | optional path | required with certificate; secret-file rules |
| `client_ca_file` | optional path | required only for `federation`/`admin_tls` |
| `allowed_origins` | string array, empty | only `client_wss`; 0..64 exact HTTPS origins |
| `allow_missing_origin` | bool, false | only `client_wss`; requires a non-browser-only listener decision |
| `allowed_uids` | integer array, empty | only `admin_local`; 1..64 unique OS UIDs |
| `allowed_gids` | integer array, empty | only `admin_local`; 0..64 unique OS GIDs |

`max_connections` is purpose-specific: a client-purpose value is
1..`limits.client_connections`, a federation value is 1..64 and no greater
than `federation.max_peers`, and an admin-purpose value is 1..64. The client
limit is global across all enabled client listeners; each listener also has
its own ceiling. Client-listener maxima need not sum to the global value,
because listeners share the global permit, and their sum may exceed it.
Federation and admin connections have independent count permits. Every TLS
purpose, including the onion listener behind Tor, also shares the global
`limits.tls_handshakes` in-progress ceiling.

`client_tls`, `client_wss`, `federation`, and `admin_tls` use a literal unicast
IP and port; hostnames, port zero, multicast, broadcast, and wildcard IPs are
invalid. `client_onion` and `admin_local` use an absolute Unix-socket path and
no TCP fields. An onion socket cannot be shared with another purpose. A key or
certificate path cannot be reused across client, federation, and admin
purposes. `allowed_origins` is required nonempty for browser-facing WSS.

When `federation.enabled=true`, there is exactly one enabled federation
listener on a coordinator and none on an edge; when false, neither role has
one. There is at most one admin-local and one admin-TLS listener. Listener
enable/address/purpose is restart-only; a certificate chain with unchanged key
identity and an Origin allowlist are reloadable after complete validation.

### C.4 TLS and federation

| Key | Type/default | Constraint |
| --- | --- | --- |
| `tls.group_policy` | `hybrid_preferred` | or `hybrid_required`; never X25519-only in a full release |
| `tls.session_tickets` | bool, true | disabling is allowed; enabling uses fixed Section-8 lifecycle |
| `tls.ticket_rotation_seconds` | integer, 21,600 | fixed in v1 |
| `tls.ticket_lifetime_seconds` | integer, 86,400 | fixed in v1 |
| `tls.require_ocsp_staple` | bool, false | applies to configured public DNS certificates |
| `tls.key_log_file` | absent | this key is forbidden; presence is an unknown-field error |
| `federation.enabled` | bool, true | false is core-only and cannot claim federated/encrypted conformance |
| `federation.private_ca_file` | path, required when federation enabled | separate CA bundle |
| `federation.signing_private_key_file` | optional path | required when federation is enabled; Ed25519 key matching local identity |
| `federation.tor_socks_endpoint` | optional string | loopback IP:port or absolute Unix socket; required when any peer endpoint is `onion:` |
| `federation.connect_timeout_seconds` | integer, 10 | 1..30; reloadable downward |
| `federation.reconnect_max_seconds` | integer, 60 | fixed v1 maximum; full jitter from one second |
| `federation.max_peers` | integer, 64 | fixed v1 maximum |

Cipher suites, ALPN, protocol versions, early-data policy, providers, exporter
labels, profile hash, and key-exchange group names are not configurable.

`federation` contains 0..64 `[[federation.peer]]` elements on a coordinator
and exactly one coordinator element on an edge:

| Peer key | Type | Constraint |
| --- | --- | --- |
| `server_id` | Server ID | unique and not local |
| `server_name` | string | exact Section-7.4 name, unique |
| `role` | `coordinator` or `edge` | inverse legal relationship to local role |
| `recovery_epoch` | 22-character base64url | exact 16-byte epoch expected in FHELLO; explicit restart-only recovery pin |
| `endpoints` | 0..8 string array | edge's coordinator record requires 1..8 exact Section-20.2 `tcp:`/`onion:` endpoints; coordinator's edge records require empty |
| `certificate_spki_sha256` | hash | exact independent certificate pin |
| `signing_public_key` | 43-character base64url | exactly 32 Ed25519 public-key bytes |
| `enabled` | bool | explicit; reloadable after quarantine checks |

An edge peer's Server ID equals `network.coordinator_server_id`. A coordinator
lists only edges. Endpoint changes are reloadable, but IDs, roles, recovery
epochs, certificate pins, trust roots, and signing keys require restart plus
the applicable authenticated transition. A recovery-epoch update also requires
a new peer incarnation and is recorded in the permanent peer-state tombstone
set; reusing any previously accepted epoch is invalid. Duplicate endpoint
ownership or a peer certificate key reused for signing is invalid.

### C.5 Storage and accounts

| Key | Type/default | Constraint |
| --- | --- | --- |
| `storage.state_dir` | path, required | dedicated mode-0700 directory under `server.data_dir`, containing fixed `database.redb`, `rollback.guard`, and runtime-created `writer.lock`; restart-only |
| `storage.master_key_file` | path, required | exact 32 secret bytes; restart-only except explicit rotation |
| `storage.rollback_guard_key_file` | path, required | exact 32-byte guard root distinct from master/index keys; restart-only except explicit rotation |
| `storage.login_index_key_file` | path, required | exact 32 distinct secret bytes matching current key-state generation; restart-only |
| `storage.login_index_previous_key_file` | optional path | required exactly during a Section-23.9 transition; distinct 32-byte key matching previous generation; restart-only |
| `storage.backup_dir` | path, required | dedicated directory, not database/source/web path |
| `storage.backup_signing_private_key_file` | path, required | dedicated Ed25519 backup-signing key; distinct from every other key |
| `storage.backup_trust_manifest_file` | path, required | offline-authorized historical backup-signing public keys; restart/restore-only |
| `storage.database_max_bytes` | integer, 85,899,345,920 | exact logical live-state ceiling; 1 GiB..1 TiB, no greater than `backup_max_bytes`; reloadable only downward to no less than current charge |
| `storage.backup_max_bytes` | integer, 107,374,182,400 | 1 GiB..1 TiB |
| `storage.disk_reserve_bytes` | integer, 1,073,741,824 | 64 MiB..1 TiB |
| `storage.disk_reserve_percent` | integer, 5 | 1..25; effective reserve is max(bytes, percent) |
| `storage.integrity_checkpoint_manifests` | integer, 100,000 | 10,000..1,000,000; soft checkpoint target below fixed count/byte hard caps |
| `accounts.accept_clients` | bool, true | false allowed for a dedicated coordinator without client listeners |
| `accounts.registration` | `open`, `invite`, or `closed`; `invite` | onion-only default is `closed` unless explicitly set |
| `accounts.invite_verification_key_file` | optional path | exact Ed25519 public key; required only for `invite` registration, identical on coordinator/edges, restart-only |
| `accounts.access_token_key_file` | optional path | exact 32 random token bytes; enables PASS admission, independent from invites; restart-only |
| `accounts.account_service_hpke_public_key` | base64url, required | exact 32-byte X25519 public key, identical on coordinator/edges; restart-only onboarding pin |
| `accounts.account_service_hpke_private_key_file` | optional path | exact matching RFC-9180 private key; required only on logical coordinator; restart-only secret |
| `accounts.opaque_server_setup_file` | optional path | required only on logical coordinator; RFC-9807 server setup |
| `accounts.opaque_fake_credential_key_file` | optional path | required only on logical coordinator; independent exact 32-byte key for Section-11.2 fake IDs |
| `accounts.allow_guests` | bool, true | reloadable; disabling affects new registrations only |
| `accounts.default_public_presence` | bool, false | copied at account creation |
| `accounts.default_allow_guest_dm` | bool, false | copied at account creation |
| `accounts.default_direct_messages` | `allow`, `contacts`, or `deny`; `allow` | copied at account creation |
| `accounts.max_contacts` | integer, 1,000 | 1..10,000 |
| `accounts.max_reserved_nicknames` | integer, 5 | fixed v1 maximum |
| `accounts.auth_transaction_seconds` | integer, 30 | fixed v1 |
| `accounts.create_transaction_seconds` | integer, 60 | fixed v1 |
| `accounts.credential_change_transaction_seconds` | integer, 60 | fixed v1 |

`storage.state_dir` is owned by the daemon UID or root, is not a symlink, and
is outside the backup, web, source, and runtime directories. `database.redb`
and `rollback.guard` are regular non-symlink mode-0600 files on startup.
`writer.lock` is a fixed mode-0600 regular file opened without following
symlinks and held by a nonblocking exclusive OS file lock for the entire open
database lifetime; a stale unlocked file is harmless and never deleted to
break a live lock. An unexpected entry does not authorize its use, and the
daemon never discovers a database or guard by globbing. The three fixed names
make restore/rekey/schema-migration installation one atomic state-directory
rename.

The configured current/previous login-index key IDs must equal the exact
Section-23.9 database state before account listeners open. A previous key is
forbidden in stable state and required in transition state; an extra key is not
accepted as a recovery fallback. Restore preserves this state and therefore
requires every key it names. Storage rekey never changes it.

`storage.database_max_bytes` is no greater than
`storage.backup_max_bytes`. Both are at least the matching StateMeta counter
before listeners open. REHASH may lower either only to a value no smaller than
the current exact counter and may raise it only within the table range after a
fresh free-space check. A deployment therefore cannot accept permanent
accounts/tombstones until the state is no longer representable by its own
configured backup format.

Edges have neither the OPAQUE setup, fake-credential-ID key, nor account-service HPKE private key and
cannot synthesize any of them. The configured HPKE public key is deserialized and
validated by the selected RFC-9180 implementation, its derived ID must match
the onboarding descriptor, and the coordinator proves its private file matches
before opening listeners. The coordinator's OPAQUE setup contains its OPRF seed
and AKE private key in the library's reviewed versioned encoding in a
Section-22.2 protected file or operating-system secret store. An unknown or
migration-incompatible encoding is fatal; regeneration would break existing
accounts and is forbidden.

The backup trust manifest is a canonical TOML document with
`backup_trust_version = 1` and one or more `[[key]]` tables containing only
`key_id`, `ed25519_public_key`, `not_before`, and `not_after`. IDs and public
keys are canonical unpadded base64url for exactly 32 bytes; times are unsigned
Unix seconds with `not_before < not_after`; IDs must equal the Section-23.7
derivation and be unique. A backup creation time must fall in the matching key
interval. Unknown fields, duplicate keys, an empty manifest, or an unprotected
file fail backup restore. The active backup private key must match exactly one
currently valid manifest entry. Initialization adds its public key;
rotation retains old verification keys until every signed backup expires.

### C.6 Resource and rate limits

Resource keys are all members of `[limits]`. Bounds and defaults are exact:

| Key | Minimum | Default | Maximum |
| --- | ---: | ---: | ---: |
| `client_connections` | 1 | 50,000 | 250,000 |
| `tls_handshakes` | 1 | 1,024 | 16,384 |
| `direct_connections_per_address` | 1 | 16 | 256 |
| `sessions_per_account` | 1 | 8 | 32 |
| `channels_per_session` | 1 | 64 | 256 |
| `members_per_channel` | 1 | 4,096 | 65,535 |
| `global_channels` | 1 | 100,000 | 1,000,000 |
| `local_channels` | 1 | 10,000 | 100,000 |
| `invites_per_channel` | 1 | 256 | 4,096 |
| `invites_per_principal` | 1 | 32 | 256 |
| `invites_global` | 1 | 100,000 | 1,000,000 |
| `requests_per_connection` | 1 | 32 | 128 |
| `response_batches_per_connection` | 1 | 4 | 16 |
| `response_batch_bytes` | 65,536 | 65,536 | 262,144 |
| `client_output_bytes` | 262,144 | 1,048,576 | 4,194,304 |
| `client_control_output_bytes` | 16,384 | 65,536 | 262,144 |
| `federation_output_bytes` | 8,388,608 | 16,777,216 | 67,108,864 |
| `base_outbox_bytes_per_edge` | 16,777,216 | 268,435,456 | 1,073,741,824 |
| `base_outbox_objects_per_edge` | 1,024 | 65,536 | 262,144 |
| `parsed_arena_bytes` | 32,768 | 32,768 | 131,072 |
| `channel_key_jobs` | 1 | 4 | 64 |
| `opaque_jobs` | 1 | 8 | 128 |
| `query_snapshot_rows` | 512 | 10,000 | 100,000 |
| `query_snapshots_per_session` | 1 | 4 | 16 |
| `query_snapshot_rows_global` | 512 | 100,000 | 1,000,000 |
| `query_snapshot_bytes_global` | 1,048,576 | 67,108,864 | 536,870,912 |

Every key is optional with its default, accepts its inclusive table range, and
is reloadable only to an equal or smaller value. A later increase requires a
validated REHASH; it changes a logical ceiling but creates no permit and takes
effect only after the Section-19 budget formula and minimum-working-set check
succeed. `client_output_bytes` is no smaller than both
`client_control_output_bytes` and `response_batch_bytes`. The control value is
strictly smaller than the total output value, leaving at least one byte of
normal-output space. Listener maxima obey Section C.3 rather than being
summed as eager memory reservations. Direct address bucketing uses IPv4 `/32`
and IPv6 `/64` for the per-address connection key and the broader Section-19
prefixes for new connection rates.

`invites_per_channel` and `invites_per_principal` are no greater than
`invites_global`. `query_snapshot_rows` is the row ceiling of one immutable
snapshot and is no greater than `query_snapshot_rows_global`.
`query_snapshot_bytes_global` is a logical capacity ceiling in addition to,
not a reservation outside, the Section-19 `MemoryBudget`; startup requires it
to be no greater than the live protocol permit pool `P`. Query and invite
limits are reloadable only downward to a value not below current use; an
increase requires validated REHASH under the ordinary memory checks.

Rate limits live in the closed tables `[limits.rate.<name>]`. Each has exactly
`refill_tokens`, `refill_seconds`, and `burst`, all positive integers. The
effective rational rate is compared by checked cross multiplication and may
not exceed the hard rate below; burst may not exceed the hard burst.

| Name | Default tokens/seconds, burst | Hard tokens/seconds, burst | Fixed key |
| --- | --- | --- | --- |
| `new_direct` | 1/1, 8 | 16/1, 64 | IPv4 `/24` or IPv6 `/56` |
| `new_onion` | 8/1, 32 | 64/1, 256 | onion listener |
| `tls_handshake` | 4/1, 16 | 32/1, 128 | direct prefix or onion listener |
| `preauth_command` | 1/1, 10 | 10/1, 50 | connection |
| `registered_command` | 4/1, 20 | 40/1, 200 | session |
| `guest_message` | 1/2, 4 | 5/1, 20 | session |
| `account_message` | 2/1, 10 | 20/1, 100 | Account ID |
| `channel_message` | 10/1, 40 | 100/1, 400 | ChannelInstanceId |
| `expensive_query` | 1/5, 2 | 2/1, 10 | session |
| `channel_key_attempt` | 1/30, 4 | 1/1, 20 | Account ID; guest session plus direct prefix/onion listener |
| `account_creation` | 1/3600, 2 | 10/3600, 10 | open: direct prefix/onion listener; invite: verified Invite ID |
| `opaque_attempt` | 1/180, 5 | 1/10, 10 | keyed login hash |

`refill_tokens` is 1..1,000, `refill_seconds` 1..3,600, and burst 1..1,000 in
addition to the row maximum. Rates are reloadable. Lowering a rate clamps
existing bucket credit to the new burst; raising it creates no immediate
credit. No value, zero, negative number, or omitted table means unlimited.

Account-service HPKE opening and invitation signature verification occur only
after the connection's pre-auth bucket admits the command and use the bounded
crypto pool. The edge charges only its connection/address-or-onion admission
keys because it cannot inspect the envelope. At the coordinator, only a
successfully opened, valid invitation selects an Invite-ID account-creation
bucket; malformed envelopes or invalid tokens cannot manufacture independent
buckets and receive the same `UNAVAILABLE` response.

The memory-overload thresholds are fixed at 80/90/95 percent with recovery to
below 85 percent as Section 19.3 states. They are not configurable because
different peers must not assume that a purported full node can disable bounded
admission.

### C.7 Privacy, moderation, and E2EE

| Key | Type/default | Constraint |
| --- | --- | --- |
| `privacy.log_retention_hours` | integer, 24 | 1..720; reloadable downward |
| `privacy.history_enabled` | bool, false | enables capability, not any channel's policy |
| `privacy.history_default` | `24h` | `1h`, `24h`, or `7d`; copied on explicit owner enable |
| `privacy.secret_lookup_floor_milliseconds` | integer, 5 | 1..50 |
| `privacy.whowas_retention_seconds` | integer, 900 | fixed v1 |
| `privacy.whowas_records` | integer, 10,000 | 1..10,000 |
| `privacy.motd_file` | optional path | UTF-8 public text, at most 64 KiB/256 lines |
| `privacy.public_info_file` | optional path | UTF-8 ADMIN/INFO text, at most 64 KiB/256 lines |
| `moderation.audit_signing_private_key_file` | path, required | dedicated Ed25519 audit-signing key; distinct from every other key |
| `moderation.audit_trust_manifest_file` | path, required | authorized current/historical audit-signing public keys |
| `moderation.audit_retention_days` | integer, 30 | 30..365 |
| `moderation.session_sanction_hours` | integer, 24 | 1..720 |
| `moderation.account_sanction_days` | integer, 30 | 1..365 |
| `moderation.free_reason_bytes` | integer, 512 | fixed v1 maximum |
| `e2ee.enabled` | bool, true | false forbidden when any active/tombstoned encrypted route exists |
| `e2ee.profile_version` | integer, 1 | fixed |
| `e2ee.coordinator_server_id` | Server ID, required when enabled | equals network coordinator |
| `e2ee.sequencer_private_key_file` | optional path | required only on logical E2EE coordinator |
| `e2ee.sequencer_credentials_file` | path, required when enabled | canonical public active/overlap credentials |
| `e2ee.max_group_leaves` | integer, 512 | 1..companion `MAX_GROUP_LEAVES` |
| `e2ee.max_devices_per_account` | integer, 64 | 1..companion maximum |
| `e2ee.mailbox_bytes_per_account` | integer, 67,108,864 | 1 MiB..companion maximum |
| `e2ee.directory_bytes_per_account` | integer, 8,388,608 | 1 MiB..companion maximum |
| `e2ee.stored_bytes_per_conversation` | integer, 268,435,456 | 1 MiB..companion maximum |
| `e2ee.global_disk_bytes` | integer, 107,374,182,400 | explicit 1 GiB..16 TiB logical E2EE ceiling; never unlimited |
| `e2ee.federation_peer_bytes_per_second` | integer, 16,777,216 | 65,536..1,073,741,824 decoded bytes per direction |
| `e2ee.federation_peer_burst_bytes` | integer, 33,554,432 | 4 MiB..4 GiB and no more than ten seconds of the configured peer rate |

The companion profile hash is a release build constant, not a configuration
key. Startup hashes the packaged canonical companion document, verifies the
raw source digest and Section-2.3 domain-separated profile digest against the
release manifest and compiled constants, and fails before opening a listener
on any mismatch. `e2ee.profile_version` cannot select a locally modified
revision with the same numeric version.

`e2ee.global_disk_bytes` charges every table-22/table-23 stored key plus sealed
envelope by `4096 * ceil((key_bytes + envelope_bytes + 256) / 4096)` and every
external authenticated spool extent by its allocated length rounded up to 4
KiB. The additions and rounding are checked `u64`; a zero-length extent costs
zero. One persisted counter and per-account/conversation/peer subtotals are
updated in the same transaction as every allocation/release and are verified
against a complete bounded scan before listeners open. redb free pages,
filesystem metadata, and copy-on-write amplification remain protected by the
independent Section-19 disk reserve; the logical ceiling is not a claim about
physical secure erasure or exact filesystem consumption. New storage that
would cross any nested or global ceiling is rejected before state mutation and
never evicts an unexpired object or security proof.

Each federation peer has separate ingress and egress token buckets with the
configured byte rate/burst. Ingress charges canonical decoded fragment bytes
after cheap base64url/length checks but before reassembly reservation, spool
write, hashing, or signature work; rejected authenticated traffic remains
charged. Egress charges each encoded object's decoded length once per
transmission attempt before that attempt's first fragment and schedules fairly
by route. An idempotent operation does not create a second durable fanout, but
link retransmission still consumes peer credit. Insufficient egress credit
delays a durable object within its bounded outbox/mailbox deadline and never
drops or truncates it. The burst must fit every enabled companion object class
that may traverse the link, and checked `burst <= 10 * rate`; otherwise startup
fails.

The audit trust manifest has the same closed `[[key]]` field grammar and time
rules as the backup manifest, but its root is
`audit_trust_version = 1`, its IDs use the Section-16.4 derivation, and an
event's `created_at` must fall in the selected key interval. The active audit
private key must match exactly one currently valid manifest entry. Historical
keys remain until all events signed by them expire and remain permanently once
they sign any permanent checkpoint; retaining a public verification key is not
retaining its private key.

There is no setting for IP logging, reverse DNS, ident, plaintext transport,
TLS key logging, E2EE plaintext inspection, key escrow, hidden recipients,
cover-traffic claims, or plaintext fallback. Such a key is unknown and fails
configuration rather than toggling an invariant.

`moderation` contains 1..64 `[[moderation.operator]]` records:

| Operator key | Type | Constraint |
| --- | --- | --- |
| `operator_id` | ID16 text | immutable, unique |
| `display_label` | string | 1..32 safe ASCII, no authority |
| `signing_public_key` | base64url | exactly 32 Ed25519 public-key bytes, unique |
| `certificate_spki_sha256` | optional hash | required for remote admin, unique |
| `local_uids` | integer array | 0..16 unique mappings for local admin |
| `local_gids` | integer array | 0..16 unique mappings for local admin |
| `permissions` | string array | nonempty subset of registry below |
| `enabled` | bool | disabling is reloadable and terminates its sessions |

The permission registry is exactly `observe`, `configure`, `sessions`,
`accounts`, `channels`, `federation`, `backup`, `audit`, and `process`. There
is no wildcard permission. A UID/GID, certificate pin, or signing key maps to
at most one operator. Remote admin requires both the certificate pin and the
signing key from the same record. The configured grant cannot exceed the
permission implied by the listener's local policy.

### C.8 Cross-field validation and easy setup

Startup validates, in order: root/schema; canonical scalar syntax; paths and
file types; secret/public key parsing; local identity consistency; listener
union constraints; role/peer topology; resource arithmetic; database header;
and E2EE/base state compatibility. It accumulates safe configuration errors up
to 100 and returns them together, but stops before opening a secret value,
database, socket, or network connection when structural parsing fails.

`init` offers three non-protocol convenience profiles: `public`, `onion`, and
`dual`. They populate every table with the defaults above, generate independent
keys and IDs, leave listener addresses disabled until explicitly confirmed,
and print the Tor/system-service snippets without installing them. An operator
needs to choose only role, explicit bind addresses, public DNS/onion name, and
peer enrollment; every security-sensitive default remains present and visible.

`print-onboarding` emits this canonical LF-terminated descriptor, omitting an
unavailable endpoint line rather than using an empty value:

```text
AGENC-CHAT-CONNECT/1
network-id=<43-char-NetworkId>
server-name=<configured DNS-style server name>
dns-endpoint=<lowercase DNS name>:<port>
onion-endpoint=<56-char-v3-name>.onion:<port>
onion-tls-spki-sha256=<43-char-hash>
recovery-epoch=<22-char-random-recovery-epoch>
base-profile-sha256=ewDg0IRCcGJkEdOY8V91ICJOqQYRdzjj2pdBphHcZ7M
account-service-hpke-key-id=<43-char-hash>
account-service-hpke-public-key=<43-char-X25519-public-key>
e2ee-profile=IRC-MLS/1
e2ee-profile-sha256=aZx0rf5wyMwzaIjlGR0eCRZsXeRAa5x8jppY7a3EgVk
sequencer-key-set-generation=<uint64-decimal>
sequencer-key-set-hash=<43-char-hash>
```

Lines occur exactly in that order; optional DNS and the paired onion lines are
omitted as units. At least one endpoint remains. Values contain printable ASCII
and no whitespace. `e2ee-profile-sha256` is the exact companion Section-2.3
profile hash and must equal the importing client's supported build constant;
an absent or unequal value rejects the descriptor. A QR code contains the
exact descriptor bytes. Import verifies the account-service key ID from the
public key, then shows the network, chosen `direct`, `tor-exit`, or `onion`
profile, endpoint, TLS/onion pin when applicable, recovery epoch, base and
E2EE profile fingerprints, account-service key fingerprint, and sequencer
key-set fingerprint for one confirmation; it never auto-selects clearnet after
onion/Tor failure.
The descriptor is an onboarding pin conveyed by the user's trusted invitation
channel, not a substitute for WebPKI or E2EE identity verification.

For invite registration, the offline command
`agenc-ircd account-invite create --descriptor <file> --signing-key-file
<file> --expires-in <seconds>` verifies the descriptor and key, accepts 1
through 2,592,000 seconds, generates a fresh Invite ID, and emits exactly:

```text
AGENC-CHAT-ACCOUNT-INVITE/1
connect-descriptor=<unpadded-base64url-of-exact-descriptor-bytes>
account-invite=<unpadded-base64url-of-AccountCreationInvite>
```

The envelope is LF-terminated with no extra or reordered lines and is encoded
directly into one QR code. The private invitation key is used only by this
offline command, is never a daemon configuration value, and receives the same
file checks as Section 22.2. A native client imports the connection descriptor,
shows one network/transport/pin confirmation, retains the invitation only in
protected local credential storage, and supplies it automatically in the first
`ACCTCREATE START` plaintext before HPKE sealing. It erases the bearer token
after creation succeeds or the token expires; an edge never receives it in the
clear, and the client never sends it as `PASS`.

## Appendix D. Requirement traceability

This matrix is the human-readable completeness index. The implementation's
machine ledger in Section 28 expands each row to individual MUST/MUST NOT
statements and test IDs.

| Required surface | Normative definition | Exact artifact/invariants | Mandatory evidence |
| --- | --- | --- | --- |
| historical/base behavior | Sections 2, 9, 10, 14; Appendix A | pinned RFC/Modern/IRCv3 hashes; `TRN-04..06` | client transcripts, parser vectors/fuzz |
| familiar channels/direct messages | Sections 13--15 | `STA-01..10`; Appendix-A grammar | model sequences, two-client interoperability |
| public/unlisted/secret discovery | Sections 13.5, 14.3 | `PRV-01/02`, projection arms | authorization matrix, privacy/timing-class tests |
| nicknames, display names, cloaks | Sections 7, 12 | `ID-01..03`; B.4 session record | property/collision/wire-render tests |
| pseudonymous accounts | Sections 7.1, 11 | `ID-01/02/05`, `AUTH-*` | account lifecycle and non-enumeration suite |
| private account service and OPAQUE | Sections 11.2--11.5 | pinned HPKE envelope, exact RFC 9807 profile, completion receipts, `AUTH-01/02/06/08/11`, B.6 grant | RFC/project vectors, edge-leak/forgery canaries, fake-record/timing and credential-fence review |
| simple onboarding/recovery | Sections 6, 11.7, 22.3; C.8 | descriptor/profile pins, `AUTH-04`, `PRV-03` | QR import, pin change, lost-root tests |
| TLS and WebSocket | Section 8; C.3/C.4 | `TRN-01..04`, RFC 10024 policy | negative TLS/WSS matrix and scanner report |
| Tor and onion service | Sections 6.2/6.3, 8.5; C.8 | `PRV-03/04` | real onion integration, SafeSocks/TestSocks, packet capture |
| metadata minimization | Sections 5, 6, 12, 14.5, 17, 25 | `ID-04/05`, `PRV-*`, `OPS-01` | canary leak scans and query/projection diff tests |
| MLS E2EE | Section 18 plus companion | `E2E-01..07`, companion registries/profile hash | complete companion Section-21 gates plus restored-route recovery-gate vectors |
| moderation/user safety | Section 16, 22.5; C.7 | `STA-03..05`, `OPS-03` | role/sanction/audit/E2EE-removal tests |
| abuse resistance | Section 19; C.6 | `TRN-04/05`, `CON-02/05`, `OPS-02` | adversarial reservation/capacity/soak tests |
| federation authority | Sections 20.1/20.10 | `FED-01/02/04` | partition/restart/fencing model |
| federation transport/auth | Sections 20.2--20.4; B.8/B.9 | registry/profile hash, `TRN-03`, `FED-08` | hello/exporter/pin/fragment negative vectors |
| requests/idempotency and paged queries | Sections 20.5--20.7; B.3/B.6 | opcode/result/origin/reply-code registry, `FED-03/04/13` | duplicate/conflict/gap/crash/cursor-expiry tests |
| events/projections | Sections 20.8/20.9; B.4/B.5/B.7 | `PRV-02`, `FED-05..07` | multi-edge least-information and snapshot tests |
| state ownership/concurrency | Section 21; Section 24.2 | `CON-01..05` | Loom, cancellation, queue and shutdown tests |
| persistence/recovery | Section 23; C.5 | `DUR-01..12` | fault matrix, corruption, restore/migration/rekey drills |
| Rust module boundaries | Section 24.1 | acyclic cargo-metadata policy | dependency-graph CI |
| safe/legible Rust | Sections 21.4, 24.3 | no unsafe/panic/unbounded channel | lint/source scans and ordinary code review |
| crypto/dependency policy | Sections 24.4/24.5, 30; source-decision ledger | locked versions/features/checksums/SBOM | vectors, deny/audit, reproducible build |
| configuration/admin | Section 22; Appendix C | `OPS-02/03/05`, strict union schema, exact STATS/audit frames | config fuzz, permission/transcript/privacy matrix, REHASH atomicity |
| observability/host hardening | Section 25 | `OPS-01`, closed log/metric fields | canary scans and service-profile tests |
| compatibility/versioning | Section 26; Appendix A/B | profile hash and closed registries | legacy-client and mismatch/downgrade tests |
| exhaustive release testing | Sections 27--29 | requirement ledger/[evidence manifest](specification-manifest.txt) | every applicable implementation/release gate and finding disposition |

No row is satisfied by prose alone. Conversely, an implementation-specific
choice that changes any row's observable behavior must be documented as a
protocol revision rather than hidden in code or configuration.

## Appendix E. Worked protocol flows

These flows fix state/order expectations but use angle-bracket placeholders
for deployment-specific IDs and binary base64url. They are illustrative
transcripts, not substitutes for the byte-exact golden vectors required by
Section 28.

### E.1 TLS registration and public channel

After TLS 1.3 and ALPN `agenc-chat/1`:

```text
C: CAP LS 302
S: CAP * LS * :account-notify account-tag away-notify batch cap-notify echo-message extended-join invite-notify
S: CAP * LS * :labeled-response message-ids message-tags monitor multi-prefix sasl=AGENC-OPAQUE server-time setname
S: CAP * LS :standard-replies userhost-in-names utf8only agenc.ag/privacy=v1 agenc.ag/account-controls=v1 agenc.ag/account-credentials=v1 agenc.ag/channel-controls=v1 agenc.ag/recovery=v1.<recovery-epoch>
C: CAP REQ :message-tags server-time message-ids echo-message standard-replies
S: CAP * ACK :message-tags server-time message-ids echo-message standard-replies
C: NICK kestrel
C: USER ignored 0 * :Kestrel
C: CAP END
S: 001 kestrel :Welcome to <network>
S: 005 kestrel CASEMAPPING=ascii CHANTYPES=#& NICKLEN=32 UTF8ONLY AGENCNET=<network-id> :are supported
...
C: JOIN #garden
S: :kestrel!u-<cloak>@h-<cloak>.invalid JOIN #garden
S: 331 kestrel #garden :No topic is set
S: 353 kestrel = #garden :~kestrel
S: 366 kestrel #garden :End of /NAMES list
C: @label=m1 PRIVMSG #garden :hello
S: @label=m1;msgid=<message-id>;time=<time> :kestrel!u-<cloak>@h-<cloak>.invalid PRIVMSG #garden :hello
```

Registration does not expose the source address, supplied USER name, Tor
status, or login. The echoed message is emitted only after authoritative
acceptance; a federated durable outbox commits first.

### E.2 OPAQUE login then session registration

The client negotiates `sasl`, selects `AGENC-OPAQUE`, and applies IRCv3 400-byte
chunking to the binary wrappers:

```text
C: AUTHENTICATE AGENC-OPAQUE
S: AUTHENTICATE +
C: AUTHENTICATE <base64(AccountServiceEnvelope[opaque_auth_start]), chunked>
S: AUTHENTICATE <base64(AccountServiceResponse[opaque_auth_challenge]), chunked>
C: AUTHENTICATE <base64(AccountServiceEnvelope[opaque_auth_finish]), chunked>
S: AUTHENTICATE <base64(AccountServiceResponse[opaque_auth_complete]), chunked>
S: 903 * :SASL authentication successful
C: NICK kestrel
C: USER ignored 0 * :Kestrel
C: CAP END
S: 001 kestrel :Welcome to <network>
S: 900 kestrel kestrel!u-<cloak>@h-<cloak>.invalid <public-account-label-or-*> :You are now logged in
```

Unknown-account and wrong-password transcripts substitute the client's
uniform dummy KE3, carry the same fixed exporter response with a rejected
completion, have the same number and kinds of messages, and end in 904. The
edge receives only HPKE-sealed account-service objects, fixed response
ciphertexts, the result class, and on success a one-use grant; it learns
neither the login identifier/invitation nor password-derived secrets. The
client does not accept the terminal numeric without the matching authenticated
completion.

### E.3 Secret channel and owner controls

```text
C: @label=s1 JOIN #known-secret
S: @label=s1 FAIL JOIN SECRET_UNAVAILABLE #known-secret :Channel is unavailable
```

The same transcript is returned for a nonexistent channel. After an authorized
member creates an invite for the exact User ID behind nickname `kestrel`:

```text
S: :inviter!u-<cloak>@h-<cloak>.invalid INVITE kestrel #known-secret
C: JOIN #known-secret
S: :kestrel!u-<cloak>@h-<cloak>.invalid JOIN #known-secret
```

An authenticated owner can then use:

```text
C: CHANCTL REGISTER #known-secret
S: NOTE CHANCTL UPDATED #known-secret :Channel setting updated
C: ACCT PRESENCE PRIVATE
S: NOTE ACCT UPDATED :Account setting updated
```

Neither command changes E2EE state by implication.

### E.4 Encrypted-channel downgrade refusal

A client without the companion capability attempts a known listed encrypted
channel:

```text
C: JOIN #secure-room
S: FAIL JOIN E2EE_REQUIRED #secure-room :End-to-end encryption is required
```

A capable client completes the companion binding/join flow. Thereafter:

```text
C: PRIVMSG #secure-room :plaintext attempt
S: FAIL PRIVMSG E2EE_REQUIRED #secure-room :Plaintext is disabled for this route
C: @+agenc.ag/e2ee=<fragment> TAGMSG #secure-room
S: @+agenc.ag/e2ee=<same-accepted-fragment>;... :<source> TAGMSG #secure-room
```

The exact E2EE receipt, candidate, finality, fragment, and label transcripts
are those in the companion document. Base events never translate the object.

### E.5 Base federation mutation and retry

For a registered origin at generation 1 and next operation sequence 7, the
edge constructs one canonical `FederationRequest`, computes its object ID, and
sends all contiguous fragments:

```text
E: @agenc.ag/fed=<fragment> :edge.example FREQUEST <coordinator-id> <incarnation> <origin-id> 1 7 <request-id> <request-object-id>
C: @agenc.ag/fed=<fragment> :core.example FRESULT <edge-id> <incarnation> <origin-id> 1 7 <request-id> <result-object-id>
C: @agenc.ag/fed=<fragment> :core.example FEVENT <edge-id> <delivery-sequence> <event-id> <event-object-id>
E: :edge.example FACK <coordinator-id> <delivery-sequence> <event-id>
```

The result and event exist only after one durable transaction. If the result
is lost, the edge resends byte-identical FREQUEST fragments with the same
tuple and receives the stored byte-identical result without re-execution. A
different object at sequence 7 closes/fences the peer; sequence 8 arriving
before 7 produces `ORIGIN_GAP` and blocks that origin.

### E.6 Partition and resynchronization

While its coordinator link is down, an edge continues PING and local `&`
channels but answers a global mutation:

```text
C: JOIN #global
S: FAIL JOIN NETWORK_UNAVAILABLE #global :The network coordinator is unavailable
```

It does not queue the JOIN or create a local copy. On reconnect it completes
FHELLO/FREADY and the companion ECAP exchange, sends FRESUME, then either
replays exact events or installs/activates a verified snapshot. Only after both
base and companion state are active can the user retry.

### E.7 Onion onboarding

The native client imports the Appendix-C descriptor, displays its Network ID,
onion endpoint, TLS SPKI fingerprint, and `onion` profile, then obtains one
confirmation. It sends the `.onion` hostname through SOCKS5 with a fresh
network/account isolation credential, negotiates TLS 1.3 inside the onion
stream, requires the pinned SPKI and ALPN, and then runs E.1/E.2. Failure at
SOCKS, onion, pin, TLS, or ALPN ends the attempt; no DNS lookup or direct TCP
fallback occurs.
