# RFC: AgenC Relay naming and ARC baseline

Status: Accepted by the project owner on 2026-09-20.

## Names and repositories

| Surface | Name |
| --- | --- |
| Server | AgenC Relay |
| Server repository and Cargo package | `tetsuo-ai/agenc-relay-server` |
| Daemon and executable | ARCD, `arcd` |
| Chat application | AgenC Relay Chat (ARC) |
| Chat repository | `tetsuo-ai/agenc-relay-chat` |
| Shared client engine | AgenC Relay SDK |
| SDK repository | `tetsuo-ai/agenc-relay-sdk` |
| Server libraries | `agenc-relay-*` |

All three repositories remain private. The SDK owns connections, accounts,
MLS state, persistence, recovery, and typed commands/events for CLI and GUI
consumers. Chat owns presentation. The server publishes the protocol contracts.

## Decision

This private development project has no deployed users. Release candidate
`1.0.0-rc.3` establishes the ARC version-1 baseline. There are no executable
aliases, old installation paths, or automatic database migrations.

Project-owned encrypted protocol labels use `ARC-MLS/1`, `ARCMLS`,
`arc-mls-v1`, `Arc*` canonical object names, and `arc_mls` extension names.
The project-owned WebSocket endpoint is `/arc`.
These labels participate in signatures, hashes, negotiated profiles, and MLS
extensions. Their fixtures and profile hashes must be regenerated from the
specifications. Cryptographic algorithms, field encodings, and ordering stay
as specified. Peers must match the exact ARC profile.

Existing AgenC labels (`agenc-chat/1`, `agenc-chat-fed/1`,
`agenc-chat-admin/1`, `AGENC-OPAQUE`, and `agenc.ag/*`) remain canonical.
IRCv3 standard names, including `text.ircv3.net` and `binary.ircv3.net`, retain
their standard spelling. The cited RFCs remain unmodified source documents.

## Operator layout and storage

`arcd` uses `/etc/arcd`, `/var/lib/arcd`, `/run/arcd`, and
`/var/lib/arcd-operator`. Service units and generated setup instructions use
`arcd.service`. Ordinary startup accepts storage schema generation 5. Earlier
development data is rejected; startup must never delete, rename, or migrate it.
Initialize a fresh data directory for the ARC baseline.

## Source and qualification

The normative ARC specifications, manifest, and frozen-source baseline are
committed separately from implementation closure evidence. Signed fixtures,
native storage reports, coverage anchors, fuzz seeds, release validation,
operator commands, and SDK source links must match this baseline.

Previous exact-revision evidence is preserved in Git history. It does not
qualify the renamed source and must not be relabeled as current evidence.
New closure records must come from actual passing gates at their recorded
source commit. Git history is not rewritten.
