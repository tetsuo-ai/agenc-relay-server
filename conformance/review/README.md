# Stage 08 external review package

This directory is the package handed to the external cryptographic and
protocol review that companion gate 13 (`S08-039`) requires. The task stays
open until a reviewer outside the implementing team has worked through it
and every finding has a disposition in `findings.md`. The Stage 08 gate
records this state in `conformance/stage-eight-e2ee-profile.toml` under
`[review]`; no release may advertise encrypted-v1 as reviewed before the
task closes.

## What is under review

Exact profile: `docs/irc-mls-e2ee-extension.md` at the document hash
recorded in `conformance/spec-baseline.toml`, negotiated as profile version
1 with token `lk0p96oG1QiE3t2W0fUBHPAVUls5iUpFNX-6k9Xou3M`, suites 0x0001 and
0x0003, context extension 0xF1C1, roster update proposal 0xF1C2, and join
authorization bundle extension 0xF1C3.

Implementation surfaces, in dependency order:

- `crates/agenc-ircd-e2ee`: public object codecs and validation (identity
  chains, rosters, capabilities, leaf authorizations, policies, bindings and
  root binding locks, contexts, application and Commit envelopes, sequencer
  credentials, candidate receipts, ACKs, finalization and abort, ReInit,
  Welcome wrappers), the MLS outer parser, client and federation wire
  carriers, reassembly, replies, and the ECAP tuple.
- `crates/agenc-ircd-domain/src/e2ee`: route table and semantic locks,
  sequencer log, lifecycle and recovery gate, directory, mailboxes, and the
  projection and barrier planning.
- `crates/agenc-ircd-storage/src/e2ee_records.rs`: the durable rows of
  tables 22 and 23.
- `crates/agenc-ircd-runtime/src/e2ee`: the coordinator executor and its
  forty handlers, peer synchronization, delivery streams, the edge router,
  and the startup reload; `crates/agenc-ircd-runtime/src/federation` for
  the cross-profile barrier on both roles.

Composition: the daemon is the untrusted MLS Delivery Service of the
companion document. It holds no MLS client, epoch secret, plaintext, root
private key, or device key; `scripts/check-workspace.py` and
`scripts/check-source.py` enforce that boundary mechanically.

## Threat boundaries the reviewer should test

- A malicious or compromised coordinator: it can withhold or reorder
  candidates and events but cannot forge a receipt without the sequencer
  key, cannot produce a finalization without the endpoints' votes, and
  cannot decrypt content.
- A malicious edge: it can only replay declared origins under the base
  origin the coordinator verified; requests are bound to the origin's
  operation sequence and replay table.
- A malicious client: every object it submits is validated against the
  published roots, rosters, capabilities, and policies before any
  signature, hash, or storage work beyond the admission limits.

## Evidence

- Vectors: `test-data/vectors/e2ee`, `test-data/interoperability/mls`,
  `test-data/fuzz-corpus/e2ee-*`.
- Transcripts: `conformance/stage-eight-transcripts.toml` binds every
  Section 21 gate except this one to named tests.
- Model: `conformance/stage-eight-model.toml` records the bounded
  exploration of the route, sequencer, and lifecycle state machines.
- Interoperability: `conformance/e2ee-interop-matrix.toml`.
- Wire budgets: `conformance/e2ee-wire-budget.toml`.
- Gate: `bash scripts/check-stage-eight.sh` and the exact-SHA checkpoint
  under `conformance/evidence/`.

## Interpretations recorded during implementation

See the Stage 08 completion notes in `TODO.md`. Each interpretation names
the section it reads and what the implementation does where the text left
a choice.
