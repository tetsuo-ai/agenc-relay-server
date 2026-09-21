# Coordinator remediation

This record closes ENC-19 (issue #166), ENC-20 (issue #167), ENC-21 (issue
#168) and ENC-22 (issue #169): four defects of the hostile-coordinator,
historical-finality and object-proof-retention surface found on 2026-09-18 by
an examiner that had no context from the implementation and read the frozen
specification and the code cold. No wire object, opcode, reply code, limit,
registry, profile hash or normative text changed, and no storage key family
was added.

## ENC-19: the coordinator answers `EWITNESS REQUEST`

The edge half of companion 12.5.1 (ENC-04) sends one `EWITNESS REQUEST` per
unresolved `witness/v1` row after every `ERESUME OK`. The coordinator had no
handler: the frame fell through to a protocol violation, which closes the
link, so an edge holding one row lost its companion link on every reconnect
and every conversation it projected went down with it.

`crates/agenc-relay-runtime/src/e2ee/coordinator/sync/witness.rs` is the
publication side:

- A request is answered from the retained chain of the named conversation,
  starting at the edge's `expected_sequence`: one `witness_resolution` object
  on `EWITNESS BEGIN`, each retained `sequencer_record` on `EWITNESS ENTRY`
  in chain order, and `EWITNESS END`. The claimed head is the head record,
  the finalization a close followed, or the predecessor the next retained
  record names.
- A conversation the coordinator does not retain, an edge without a
  projection entitlement to it, and a position beyond the retained chain all
  get the empty set (`record_count` zero, the head unchanged), never a
  refusal; the edge keeps its row and repeats.
- The set holds at most `MAX_WITNESS_RESOLUTION_RECORDS` records and
  `MAX_WITNESS_RESOLUTION_BYTES`, and additionally at most 16 MiB of record
  bytes per answer because the lines are rendered in memory; a longer chain
  resolves through the requests that follow. It stops before a
  `reinit_attempt` record, which this carrier cannot prove.
- The set stops before the first chain event of that conversation the edge
  has not acknowledged. That event is retransmitted after the resolution and
  must still extend the installed head; delivering past it would turn the
  retransmission into a second violation.
- A first record whose predecessor is not the edge's head is a fork: only
  that record is delivered, the edge marks its row `conflict`, and no
  `RESOLVED` follows.
- One resolution is open per link. Later requests queue (at most 1,024) and
  are answered on the matching `EWITNESS RESOLVED`, after an empty answer, or
  when the edge's repeated request shows it settled a fork. A `RESOLVED` for
  the installed token is idempotent; one that names no open resolution is a
  violation.
- A blocked edge drops every delivery it receives. When its rows settle it
  replays its origins, and the coordinator then sends the unacknowledged
  rows again with its `EORIGIN` answer.

## ENC-20: terminal proofs reload from certified records

Startup rebuilt each conversation's terminal-proof map from every retained
`finalization_request` object. A request still below quorum is retained too,
so after a restart it satisfied the companion 13.7.3 rule that a `removed`
leaf proof names a retained finalization, and the Welcome delivery gate, for
an epoch that never finalized; the certified abort and ReInit terminal
identifiers the live coordinator records were dropped instead. The map is now
exactly the retained request of each terminal the conversation's sequencer
records certify, for all four terminal kinds.

## ENC-21: bootstrap-activation votes reload under their own council

The reload counted every durable vote under the current policy. The resulting
council's votes of a pending bootstrap activation (companion 9.5) were
refused there and silently dropped, so a restart made that council vote
again, against the companion 12.4 promise that a reloaded coordinator
rebuilds the count from its records. The replay now records a signer under
the old council when it sits on it and under the resulting council
otherwise, as the live handler does. A vote row that cannot be counted again
(no retained request, no vote of its signer, a signer on neither council, a
signature that no longer verifies) is counted per conversation and reported
by `CompanionCoordinator::unreplayed_votes`; a consistent store reports zero.

## ENC-22: retained below-quorum requests are charged

A `PENDING` finalization, abort or ReInit terminal request was retained as an
object, but only its counted votes had rows, so a request that added no vote
had no owner: it was charged to no conversation and bypassed
`MAX_STORED_BYTES_PER_CONVERSATION`. Every below-quorum request now writes a
retained-request row: a vote-accumulator row under the all-zero root (no root
fingerprint is all zero), keyed by the leading 16 bytes of the request
identifier, which the ENC-08 derivation charges to the conversation as
ordinary material. The vote replay skips these rows and startup restores the
retained set from them. A slot retains at most 128 requests below quorum
(`E2EE_RATE_LIMITED` beyond); a request that would cross the conversation
quota is refused with `E2EE_RATE_LIMITED` by the existing owner ledger and
nothing is written. The rows retire in the batch that certifies the slot's
terminal; a request no vote row names is then unowned and the ENC-09
collector deletes it at the ordinary retention boundary.

## Limitations

- The bridged tests drive the real coordinator publication code against the
  real edge over rendered lines, with the coordinator's retained chain
  installed directly; no two-daemon run exercises a witness resolution.
- The pending-event bound reads the delivery rows resident in memory; a
  cold outbox tail is not consulted.
- Requests queued behind a forked answer wait for the edge's repeated
  request (`MAX_WITNESS_RESOLUTION_SECONDS`), because the edge sends nothing
  when it settles a fork.
- The edge's own checks are unchanged, including the successor-credential
  overlap window of issue #162.
- `unreplayed_votes` is an accessor; no audit event or `STATS` field carries
  it yet.
- Two distinct requests whose identifiers share their leading 16 bytes share
  one retained-request row; the displaced request becomes unowned and ages
  out. Finding such a pair costs about 2^64 hashes.

## Evidence

- `crates/agenc-relay-runtime/src/e2ee/edge/tests/witness_bridged.rs`: a skip
  resolves through the coordinator, the edge installs the proven head,
  `RESOLVED` is accepted and idempotent, the origin replay is answered on the
  same link; a fork becomes a durable `conflict` confined to its
  conversation with the link up and a later request still answered; the
  answer stops before the unacknowledged event.
- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sync/review_witness.rs`:
  a request for an unretained conversation gets one empty set.
- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/review_reload.rs`:
  a pending finalization is not a retained one after reload; every certified
  terminal proof reloads; the resulting council's vote survives a reload and
  completes the activation; a lost request is reported; a vote-less pending
  request is charged, refused whole over the quota, and collected at the
  retention boundary once unowned.

Each regression failed on `46840bd` before its fix. Commands: `cargo test -p
agenc-relay-runtime --all-features --locked`, `cargo test -p agenc-relay-e2ee
--all-features --locked`, `cargo clippy --workspace --all-targets
--all-features --locked -- -D warnings`, `cargo fmt --all --check`, `python3
scripts/check-source.py check`.
