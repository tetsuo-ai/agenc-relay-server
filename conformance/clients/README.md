# Conventional client qualification

The version-1 server requires ALPN `agenc-chat/1` before application bytes.
The pinned WeeChat and Irssi releases do not advertise this value. The local
qualification builds apply the recorded TLS patches and retain the clients'
IRC registration, capability negotiation, channel, and message code.

WeeChat advertises the exact ALPN with GnuTLS's mandatory-negotiation flag.
Irssi advertises the same value, requires TLS 1.3, and rejects a handshake
that does not select the required ALPN. Certificate verification remains
enabled in the test configuration. These builds are dedicated qualification
clients and are not general-purpose replacements for an installed client.

`versions.toml` pins the upstream commits, original source files, and patch
hashes. The build record must retain each compiler command, binary digest,
and upstream license. A passing test must identify the patched client build;
it must not claim that an unmodified release supports this server.

The patch failure paths use the upstream TLS initialization and connection
cleanup conventions. GitNexus does not index these external client sources;
the examined call sites are WeeChat's connection hook and Irssi's TLS channel
creation and handshake callbacks.

The client TLS APIs are documented by
[GnuTLS](https://gnutls.org/manual/html_node/Application-Layer-Protocol-Negotiation-_0028ALPN_0029.html)
and [OpenSSL](https://docs.openssl.org/3.0/man3/SSL_CTX_set_alpn_select_cb/).
The x86_64 development test has passed real sessions with both clients. An
authenticated native account creates listed public and secret channels.
Each conventional client registers as a guest, sends a public-channel message,
and tries to join and send to the secret channel. The native observer verifies
the public message and the absence of secret-channel access. Guest restrictions
remain those in architecture Section 11.8.

Build the tools and run the development test with these commands:

```sh
python3 scripts/build-qualification-tools.py --output /path/to/new-tools
qualification_image="$(cat /path/to/new-tools/image-id.txt)"
AGENC_STAGE10_TOOL_IMAGE="$qualification_image" cargo test -p agenc-relay-server \
  --all-features --locked --test stage_six_daemon \
  stage_ten::conventional_clients_exchange_public_messages_and_cannot_enter_secret_channels \
  -- --ignored --nocapture
```

The image also contains the pinned Chutney commit in `tor-tools.toml`, Tor,
and tcpdump. The Tor driver requires a container with networking disabled,
runs the daemon without root privileges, and captures packets only inside
that container. Tor control events must show distinct circuits for distinct
SOCKS authentication contexts. The capture must contain neither DNS packets
nor the plaintext test canary, and its kernel drop count must be zero.

Release qualification still requires the exact candidate binaries on both
native targets. Development sessions do not close that gate.
