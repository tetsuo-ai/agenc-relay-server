# Stage 09 optional profiles

The `wss` and `history` Cargo features are independent and disabled by default.
Enabling a profile in configuration requires a binary compiled with that
feature. Unsupported enabled profiles fail configuration validation before
the daemon opens storage for writes.

```sh
cargo build --release --locked
cargo build --release --locked --features wss
cargo build --release --locked --features history
cargo build --release --locked --features wss,history
```

## WebSocket listener

Compile with `wss`, then add a public TLS endpoint with its own listener name
and bind address:

```toml
[[listeners.endpoint]]
name = "browser"
enabled = true
purpose = "client_wss"
bind = "203.0.113.1:443"
max_connections = 1000
tls_certificate_file = "/etc/arcd/tls/client-chain.pem"
tls_private_key_file = "/etc/arcd/tls/client-key.pem"
allowed_origins = ["https://chat.example"]
allow_missing_origin = false
```

Use the deployment's actual address, certificate, and key paths. The listener
uses TLS 1.3 and ALPN `http/1.1`. It applies the configured TLS group policy
and requires the prepared OCSP response when public certificate stapling is
required. WSS clients share direct-client host/prefix admission quotas and
the global client limit.

Browsers connect to `wss://<server>/arc` and offer `text.ircv3.net`,
`binary.ircv3.net`, or both. The first supported offered protocol wins.
Each WebSocket message contains one IRC line without CR or LF. Both
subprotocols require UTF-8. CAP negotiation, OPAQUE authentication, account
carriers, channel commands, and encrypted carriers use the existing IRC
wire rules inside those messages.

A present Origin must match one configured value exactly. Scheme, host,
port, and spelling are not normalized during admission. Missing Origin is
rejected unless a separately configured non-browser endpoint explicitly
sets `allow_missing_origin = true`. Keep browser endpoints on the explicit
allowlist. Origin allowlist reloads take effect when an in-flight upgrade
finishes parsing, immediately before its response is prepared. An accepted
connection keeps its established admission after later reloads.

The endpoint accepts only `GET /arc HTTP/1.1`, WebSocket version 13, one
valid Host, and a canonical padded base64 key encoding 16 bytes. It rejects
cookies, HTTP authentication, bodies, transfer coding, folded fields,
duplicate singleton fields, and a buffered second request. Extension offers
are ignored; the server negotiates none. Frames with reserved bits,
including compressed frames, close with code 1002. Invalid UTF-8 closes with
1007; messages exceeding 8,701 bytes close with 1009.

The request line is limited to 2,048 bytes, each field line to 4,096 bytes,
and all fields to 64 entries and 16,384 bytes. Line limits exclude CRLF;
the combined field budget includes each field's CRLF and excludes the final
empty line. The
upgrade must finish within five seconds of TLS completion. The 30-second
registration budget starts at that same TLS completion, including upgrade
and owner-queue delay. Control writes and ordinary output retain the
30-second write-stall limit.

Admission reserves the normal 65,536-byte client allocation, writer queue,
262,144-byte TLS setup increment, and 65,536-byte WebSocket setup increment.
The setup permits are released after their temporary buffers are dropped.
Steady WebSocket buffers and control state require another 61,440 charged
bytes per connection. Allocation refusal, cancellation, protocol errors,
and connection shutdown release their permits. HTTP errors contain fixed
status text and do not reflect request values.

The implementation uses the existing bounded IRCv3 message decoder and a
bounded HTTP/frame codec. The optional crypto adapter uses the already
locked AWS-LC provider only for RFC 6455's public nonce accept digest.
Authentication and persisted protocol commitments keep their existing
cryptographic profiles.

The Stage 09 transport-equivalence fixture runs the same account and guest
scenario over TLS IRC, text WebSocket, and binary WebSocket. It compares the
ordered IRC replies and authenticated stored account and channel state.
The scenario includes creation and OPAQUE login, channel messages and policy,
secret-channel discovery, denied mutations, query-quota exhaustion, QUIT,
and malformed-input closure. Fresh identifiers, public cloaks, and times
are normalized. Membership lists in numerics 353 and 319 are compared as
sets of complete tokens because their traversal follows fresh identifiers.
The comparison preserves duplicates, role prefixes, visibility markers,
identity relationships, reply text, policies, revisions, and session
generations. Encrypted
account carriers are checked through their bounded framing and authenticated
decoded responses. This fixture covers the stated application scenario;
the resource tests separately exercise memory refusal and writer pressure.

## History service

Compile with `history` and set the following values on the coordinator and
on edges that will serve history queries:

```toml
[privacy]
history_enabled = true
history_default = "24h"
```

Both settings require a restart. `history_default` accepts `1h`, `24h`, or
`7d`; it supplies the retention for an explicit `ON` command. Enabling the
service does not enable retention on existing channels. A channel owner
registers a global plaintext channel and sets its policy:

```irc
CHANCTL REGISTER #channel
CHANCTL HISTORY #channel ON
CHANCTL HISTORY #channel 1H
CHANCTL HISTORY #channel OFF
```

`24H` and `7D` are also accepted. History admits ordinary channel-wide
`PRIVMSG` and `NOTICE` only while the channel is registered, listed,
plaintext, and not quarantined. Direct messages, local `&` channels,
secret or unlisted channels, status-targeted messages, `TAGMSG`, and E2EE
carriers are excluded. Stored messages retain their original sender,
message ID, receive timestamp, client tags, and expiry. Changing retention
applies to newly accepted messages. `OFF` stops capture and delivery; it
does not rewrite or extend older rows' expiry.

Clients negotiate `draft/chathistory` and its capability dependencies.
`CHATHISTORY` supports `LATEST`, `BEFORE`, `AFTER`, `BETWEEN`, and `AROUND`
with at most 100 selected messages. `TARGETS` is not supported. Results use
a `chathistory` batch and original message IDs and timestamps. Selection
uses exclusive anchors and renders messages in channel order. An unknown
initial message-ID anchor returns an empty batch. Each physical read and
federation page is bounded; authorization is checked again before delivery.
A part, kick, account suspension, session replacement, quarantine, policy
change, purge, or E2EE transition invalidates affected pending reads.

The coordinator stores message bodies in the sealed History table. Edges
retain only request metadata and deliver authenticated coordinator pages.
Saved result metadata identifies the original selected rows and the
original result-object digest. A retry either yields those same messages
under current authority or becomes terminally expired. No history body is
copied into federation replay records.

Federated cursors are single-use, expire after 60 seconds without progress,
and have a ten-minute absolute lifetime. A link reconnect may continue
delivery only to the same surviving client connection. Daemon restart never
assigns a saved page to a new connection. Replay metadata is retired after
the origin has been deleted or fenced for 24 hours; the retirement timer
starts conservatively when a maintenance sweep observes that state. Message
bodies retain their independent original expiry.

Retention is capped at 65,536 messages and 64 MiB per channel, 262,144
messages and 4,096 channel controls overall. Global logical history bytes
are capped at the smaller of 1 GiB and one quarter of the configured
database limit. The metadata index uses the existing shared memory pool
and is capped at the smaller of 256 MiB and one eighth of that pool;
memory availability can therefore impose a lower effective row limit.
Resource exhaustion refuses new work. It does not evict unexpired rows to
make room. A clock that cannot establish trusted wall time pauses capture,
delivery, and destructive expiry.

Use the isolated signed administration endpoint to delete retained rows:

```text
CHANNEL HISTORY PURGE <channel-instance-id> :reason
```

The operator needs the channels permission. Follow the endpoint's signed
confirmation flow; its token expires after 60 seconds and binds the exact
command and channel revision. The initial audited transaction freezes a
purge cutoff and immediately hides messages at or below it. Physical
removal commits in batches of at most 1,000 rows and resumes after a crash.
The success response is sent only after those deletion commits finish.
Messages accepted above the cutoff remain eligible when policy permits.

An E2EE bind requires history policy `OFF`, no retained message rows, and
no active purge. Turn history off and complete a purge before binding an
encrypted route. Empty control records alone do not block a bind.

A binary compiled without `history`, or configured with
`history_enabled = false`, still validates existing history records,
reconstructs their accounting, enforces E2EE exclusion, and completes
expiry and purge maintenance. It advertises no history capability and
serves no history query. Re-enabling the service can expose retained rows
that have not expired or been purged.
