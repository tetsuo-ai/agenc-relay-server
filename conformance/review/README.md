# Stage 08 external review package

This directory is the package handed to the external cryptographic and
protocol review that companion gate 13 (`S08-039`) requires. The task stays
open until a reviewer outside the implementing team has worked through it
and every finding has a disposition in `findings.md`. The Stage 08 gate
records this state in `conformance/stage-eight-e2ee-profile.toml` under
`[review]`; no release may advertise encrypted-v1 as reviewed before the
task closes.

The [2026-09-04 adversarial implementation review](adversarial-review-2026-09-04.md)
records reproduced defects, fixes, regression tests, and remaining limits in
the working tree. It is separate from the external review required above.

## What is under review

Exact profile: `docs/irc-mls-e2ee-extension.md` at the document hash
recorded in `conformance/spec-baseline.toml`, negotiated as profile version
1 with token `aZx0rf5wyMwzaIjlGR0eCRZsXeRAa5x8jppY7a3EgVk`, suites 0x0001 and
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
  forty-one handlers (policy publication and the finality quorum guard
  among them), peer synchronization, delivery streams, the edge router with
  its record-chain witness, and the startup reload;
  `crates/agenc-ircd-runtime/src/federation` for the cross-profile barrier
  on both roles.

Composition: the daemon is the untrusted MLS Delivery Service of the
companion document. It contains no MLS client and receives no MLS epoch
secrets, decrypted MLS content, root private keys, or device private keys;
`scripts/check-workspace.py` and
`scripts/check-source.py` enforce that boundary mechanically.

## Threat boundaries the reviewer should test

- A malicious or compromised coordinator: it can withhold or reorder
  candidates and events. The coordinator holds its sequencer signing key,
  so a compromise can produce signed conflicting or invalid records. MLS
  content remains encrypted to the endpoints. An honest coordinator certifies a
  finalization, abort, or ReInit terminal only after it has verified the
  published policy's quorum of council votes (companion 12.4), so a
  certificate carries the votes needed for the endpoints' independent
  quorum check. An honest edge checks the coordinator's record chain
  (companion 12.5), refuses a witness violation, records it durably, and
  closes the link. Edge record-chain checks do not replace endpoint
  signature and quorum validation.
- A malicious edge: it can only replay declared origins under the base
  origin the coordinator verified; requests are bound to the origin's
  operation sequence and replay table. A compromised edge can bypass its
  local witness or withhold deliveries. Clients must independently validate
  the certificates and record chains they receive; an edge's local checks
  provide no guarantee when that edge is malicious.
- The published policy: the server learns the controller roots and the
  finality council of every conversation it retains (companion Sections 4
  and 9.3); the reviewer should confirm that nothing beyond that is
  disclosed and that the retained copy cannot substitute for the
  Commit-bound copy the endpoints enforce.
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
- Interoperability: `conformance/e2ee-interop-matrix.toml`, including the
  lifecycle openmls and mls-rs drive through the daemon (gate 3).
- Wire budgets: `conformance/e2ee-wire-budget.toml`.
- Gate: `bash scripts/check-stage-eight.sh` and the exact-SHA checkpoint
  under `conformance/evidence/`.

## Interpretations recorded during implementation

See the Stage 08 completion notes in `TODO.md`. Each interpretation names
the section it reads and what the implementation does where the text left
a choice.

## Implementation review follow-up

The implementation review after checkpoint
`ae6457fb62fef8961d3caf904febed580e8b4a91` found that terminal certificates
could omit votes counted from earlier requests. The quorum ledger now retains
each accepted signature and inserts the complete matching vote set into
finalization, abort, and ReInit certificates. The
[sequencer tests](../../crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/sequence.rs)
check certificates assembled across requests and a coordinator reload. The
[quorum tests](../../crates/agenc-ircd-e2ee/src/tests/finality.rs) independently
verify the accumulated signatures and their terminal binding.

Startup also discarded accepted policies and counted votes after a council
device retired or its account rotated its root. Reload now re-verifies the
retained root chain and historical roster certificates for those previously
accepted records. New requests still use the active roster. The
[coordinator tests](../../crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/mod.rs)
cover device retirement, root rotation, and a forged historical roster;
`reload_preserves_counted_votes_after_the_signer_retires` in the sequencer tests
checks that committed votes survive retirement while fresh retired-device
requests fail.

ReInit reload also lost active attempts, the next attempt sequence after an
abort, and the migrated state after activation. Startup now restores those
states and the successor's log and lifecycle anchor. The ReInit sequencer test
restarts between votes, after abort, and after activation; the
[domain tests](../../crates/agenc-ircd-domain/src/e2ee/tests/sequencer_log.rs)
check restored attempt limits and reject slots that do not match the log head.
The subsequent adversarial pass also completed successor route binding; see
the [successor review](adversarial-review-2026-09-04.md#successor-routes-could-not-consume-their-activation-anchor).

The storage decoder also accepted unknown vote-slot values that its key
builder rejected. Vote rows now accept only finalization or abort slots;
approval and ACK rows require slot zero. The
[record tests](../../crates/agenc-ircd-storage/tests/e2ee_records.rs) cover
rejection before storage and round trips for both valid terminal slots.

Coordinator reload previously inferred an origin's next operation sequence
from expiring replay results, and generation-zero declarations skipped even
that inference. Each committed request now writes a durable sequence floor
in the same transaction as its result. The floor has no replay expiry and
occupies one table-23 row per home server, incarnation, and origin under
`origin-sequence/v1/irc-mls-v1/`. It uses the existing replay record kind 9
with a distinct version-2 body containing the latest origin generation and
its next unused sequence. The original version-1 replay codec is unchanged.
The [origin replay tests](../../crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/origin_replay.rs)
cover restart after replay deletion, generation-zero and later declarations,
atomic result/floor publication, generation rollback, incarnation isolation,
sequence exhaustion, and refusal of partial legacy history with a fresh
generation control. The record tests reject malformed floor bodies and keys
and distinguish them from ordinary replay rows.

An upgrade creates a floor when that origin next commits a request; startup
does not migrate older replay rows into durable floors. When retained replay
history proves a generation was used but no matching floor exists, restart
refuses its `EORIGIN ADD` or `UPDATE`. Earlier rows cannot prove the latest
sequence because security mutations and other requests expire at different
times. Operators must reconnect affected clients into fresh origins or
establish a new authenticated origin generation before continuing. If all
legacy replay history has expired, storage cannot distinguish that used
generation from one that never committed a request, which legitimately starts
at zero. Operators must replace such uncertain legacy origins during upgrade;
startup cannot reconstruct or detect their deleted history.

Local object retry matching also omitted recipient parameters. Reassembly
now retains the complete assembly tuple, and local commands use a digest of
their opcode and canonical parameters as its command scope. The actual
conversation still determines route quotas. The
[assembly tests](../../crates/agenc-ircd-e2ee/src/tests/assembly.rs) and
[local scope tests](../../crates/agenc-ircd-runtime/src/e2ee/edge/tests/scope.rs)
check that the same object can be delivered to another recipient while an
identical submission remains a retry.

The assembler's completed-object cache is capped at 4,096 tuples. Every
open submission reserves its eventual cache slot before payload allocation;
new submissions are refused at the limit while existing retries and responses
still work. Expiry releases those slots without evicting live retry entries.
The assembly tests cover a stream of small completed objects, reserved slots,
admission refusal, and recovery after expiry.

The edge reply review also found that a result arriving between event staging
and commit could remain unanswered. Completion now checks for that late result
after commit and releases its reply through the ordinary or barrier output
path. It does not mark completion or populate the retry cache when storage
refuses the event. The
[projection tests](../../crates/agenc-ircd-runtime/src/e2ee/edge/tests/projection.rs)
exercise both storage refusal and a result arriving during completion staging.
The [retry tests](../../crates/agenc-ircd-runtime/src/e2ee/edge/tests/retry.rs)
check requester, attachment session, command, label, retention, and reply
capacity boundaries. These checks are implementation review evidence; they
do not close the external review task.

The edge previously retained response objects without a count or aggregate
byte bound. It now admits at most 32 objects and 4,194,304 decoded bytes per
pending request, checks zero-based descriptor indexes, and binds each object
to its declared hash, kind, and size. Responses may arrive before their result;
the descriptor set is then checked against every buffered object before the
result is accepted. Exact duplicates are harmless; conflicting response bytes
or result envelopes close the companion link. The
[response tests](../../crates/agenc-ircd-runtime/src/e2ee/edge/tests/responses.rs)
cover both arrival orders, count and byte limits, malformed descriptor sets,
object mismatches, duplicate conflicts, and the link failure path.

The final working tree passed all 97 commands in the Stage 08 implementation
gate. The [adversarial review record](adversarial-review-2026-09-04.md#validation-record)
records its source inventory and results. A new checkpoint still requires a
committed source revision and its recorded gate artifact. The external review
task `S08-039` remains open.
