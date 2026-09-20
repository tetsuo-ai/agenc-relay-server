# Project RFC: Agency Relay, ARC, and ARCD naming

Status: Product naming accepted by the project owner on 2026-09-20. Packaging
and deployment migration is in progress. Version-1 protocol identifiers are
unchanged.

Date: 2026-09-20

Scope: Server, chat application, SDK, documentation, packaging, and migration.
This proposal is informative. It does not amend the version-1 architecture or
IRC-MLS specifications, registries, released artifacts, or conformance claims.

## Summary

Use **Agency Relay** for the server, **ARCD** for its daemon executable,
**Agency Relay Chat (ARC)** for the client application, and **Agency Relay SDK**
for the shared client engine. The server is a federated chat relay with an
IRCv3-derived client interface and project-specific federation and MLS delivery
profiles. Version 1 remains a suite of explicitly versioned client,
federation, account, encrypted-conversation, and storage profiles, many of
which retain IRC or IRC-MLS syntax and identifiers.

These names are presentation and distribution changes. Existing version-1
clients, servers, databases, and signed objects must continue to use their exact
negotiated identifiers and bytes. A later wire protocol redesign would need a
separate normative proposal, new profile identities, migration rules, and
interoperability evidence.

## Motivation

`agenc-ircd` accurately describes the project's starting point, but `IRCD`
suggests a conventional IRC server. The daemon accepts an IRCv3-derived client
command model and preserves IRC concepts such as nicknames, channels, and
`/join`. Its federation is a distinct authenticated coordinator/edge protocol;
its account and encrypted-conversation features also have project-specific
semantics. The current name therefore undersells what operators deploy and can
create false expectations about compatibility with legacy IRC server links.

The distinction matters for the planned shared client SDK. SDK users should
understand which behavior is standard IRCv3, which is a version-1 Agency profile,
and which is local SDK behavior. The product name must not become a shortcut for
wire compatibility.

## Naming decision

| Surface | Chosen name or description | Reason |
| --- | --- | --- |
| Server product and repository | **Agency Relay**; `tetsuo-ai/agency-relay` | Names the standalone or federated server. |
| Daemon executable and new deployment | **ARCD**; `arcd` | Mirrors the familiar IRC/IRCD client-daemon distinction. |
| Chat application | **Agency Relay Chat (ARC)**; `tetsuo-ai/agency-relay-chat` | Names the human-facing client. |
| Client engine | **Agency Relay SDK**; `tetsuo-ai/agency-relay-sdk` | Serves CLI and GUI applications through one library. |
| Version-1 protocol documentation | **Agency Relay version-1 profiles**; name each client, federation, and IRC-MLS profile explicitly | Avoids suggesting one replaceable protocol identifier or broad compatibility promise. |
| IRC compatibility claim | **IRCv3-derived client interface with stated limits** | The daemon still speaks an IRC-shaped client grammar, but does not support legacy server links or every IRC extension. |

**Agency Relay Protocol** would require a separately specified and versioned
protocol family; a product rename alone does not create one. The previous
`AgenC` spelling remains in frozen wire labels, historical material, and
compatibility entry points where changing it would break version 1.

The already existing private `tetsuo-ai/agenc-relay` repository is a different
iOS/WebSocket bridge. It is not part of this rename.

## Compatibility boundary

The version-1 wire contract is controlled by
[`ircd-architecture-and-implementation-spec.md`](../ircd-architecture-and-implementation-spec.md),
[`irc-mls-e2ee-extension.md`](../irc-mls-e2ee-extension.md), and the
[`federation-v1-profile.registry`](../federation-v1-profile.registry).
In particular, a product rename must not rewrite:

- ALPN `agenc-chat/1`, `agenc-chat-fed/1`, or `agenc-chat-admin/1`, and WSS
  subprotocols `text.ircv3.net` and `binary.ircv3.net`;
- `agenc.ag/*` capabilities and tags, `AGENC-OPAQUE`, `FHELLO`, `ECAP IRCMLS`,
  IRC-shaped command and reply grammars, or the `irc-mls-v1` federation lane;
- `IRC-MLS/1` signature and hash domain labels, `agenc-chat` cryptographic
  contexts, or canonical serialized object names and discriminants;
- the base federation profile registry bytes or the frozen E2EE document bytes;
  the latter's exact bytes are included in its negotiated profile hash;
- network IDs, server IDs, recovery epochs, stored schema identities, or
  current release evidence and signed conformance artifacts.

Section 26 of the architecture specification already requires exact profile
matching and explicit versioning. Editing the frozen E2EE document even for a
new title changes its negotiated hash. Editing the architecture specification
or source ledger changes the specification manifest and requires the applicable
source and release checks. This proposal changes neither. An old-looking token
in a public identifier may therefore be correct and permanent for version 1.

The human-readable configured server name is a DNS-style name with separate
`ServerId` authority. An operator might choose a new hostname, but doing so is
an endpoint/certificate/configuration migration, not an automatic consequence
of renaming the product. The `network_id` and authenticated federation peer
pins must not be regenerated for branding.

## Rollout

1. Publish a terminology map: Agency Relay is the server, ARCD is its daemon,
   ARC is the chat client, and Agency Relay SDK is the shared engine. State the exact IRC
   compatibility limits in README and onboarding text.
2. Update unbound presentation surfaces first: repository description,
   marketing text, new docs, and release-note display name. Preserve historical
   evidence and published artifacts as historical records.
3. Inventory executable and operator surfaces before changing them: repository
   URL, Cargo package and crate names, Rust import paths, binary and CLI
   commands, service units, container/image tags, configuration keys and paths,
   logs/metrics, automation, downstream dependencies, and support links.
   Record an owner, compatibility strategy, and verification for each surface.
4. Introduce `arcd` and new deployment paths with a documented transition.
   Keep existing `agenc-ircd` invocations and data paths
   usable for deployed installations until an explicit retirement decision.
   Never silently move a database, key, backup, or rollback guard on startup.
5. Exercise the migration on an existing installation and on a fresh install.
   Verify old CLI/service entry points, config and data location, TLS/ALPN,
   federation profile matching, client negotiation, and restore behavior.
   Re-run the gates required by any actual code, packaging, or spec change.

No step above authorizes changing a frozen identifier, a protocol hash, or an
already signed release record. A future protocol-name change needs its own
normative change set and cannot be hidden inside this migration.

## Acceptance criteria

- Public server, daemon, chat, and SDK names match the chosen terminology.
- A migration inventory identifies every operator-visible executable, path,
  package, and deployment name before any of those identifiers changes.
- Version-1 wire identifiers and negotiated hashes are unchanged by the product
  rename; existing peers and clients continue to negotiate the same profiles.
- Existing data and deployment entry points have a tested compatibility path.
- The client SDK document uses the same terminology and cites the exact frozen
  v1 contract rather than deriving behavior from the new product name.

## Deferred internal rename

Version-1 Cargo crate names and Rust import paths still contain `agenc-ircd`.
They appear in the frozen specification, build policy, source paths, and signed
historical evidence. The public `arcd` executable and new deployment templates
can ship while those internals remain. A separate code migration may rename
internal crates after an inventory of downstream imports and all build gates;
it must preserve old executable and deployment compatibility and must not
rewrite version-1 wire labels or historical evidence.
