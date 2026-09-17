# Edge witness resolution

This record closes ENC-04 (issue #62): a durable `witness/v1` row now has a
way out. After an edge witnesses a skipped or forked sequencer record it
retains the row and blocks; from this change the coordinator must prove how
the retained chain continues before that conversation resumes. The proof
travels in the companion Section 12.5.1 `EWITNESS` family, which is the only
frame family a blocked edge reads. No limit, reply code, or normative text
changed; the companion already defined the frames, the object and the three
`MAX_WITNESS_RESOLUTION_*` limits under ENC-01.

## Wire

`witness_resolution(36)` joins the wire-kind table as a server-only federation
control object bounded by `MAX_FEDERATION_CONTROL_OBJECT`, carrying
`IrcFederationWitnessResolution` (`crates/agenc-ircd-e2ee/src/objects/federation.rs`):
the network, coordinator, target, conversation, token, the expected position
and head the row retained, the record count, the claimed new head, and exactly
`record_count` concatenated 32-byte object IDs in chain order. Five frames
join `CompanionFrame` (`crates/agenc-ircd-e2ee/src/federation/frames.rs`):
`EWITNESS REQUEST` and `EWITNESS RESOLVED` from the edge, and `EWITNESS
BEGIN`, `ENTRY` and `END` from the coordinator. BEGIN and ENTRY carry object
fragments; the other three are untagged. Three limits are published:
`MAX_WITNESS_RESOLUTION_RECORDS` (1,024, so the identifier vector fits its
32,768-byte bound), `MAX_WITNESS_RESOLUTION_BYTES` (268,435,456) and
`MAX_WITNESS_RESOLUTION_SECONDS` (300).

`WitnessRow` (kind 13) gains one field, `conflict`: the permanent mark an
authenticated fork leaves. Earlier development images without the field do
not decode.

## Blocked phase

A durable row no longer refuses the resume itself, because only the
coordinator can prove the chain and it can only do so over a live link. The
edge sends its ordinary ERESUME; `ERESUME OK` opens `Phase::Witness` instead
of replaying the origins, and one `EWITNESS REQUEST` goes out per unresolved
row in conversation order, naming that row's expected next position and head.
While any row is unresolved the edge reads only `ERESUME OK` and the three
coordinator `EWITNESS` frames and drops every other companion frame exactly
as before; `is_active` stays false, client lines keep failing `E2EE_SYNCING`,
and the delivery cursor, the projected heads and the row itself do not move.
An unanswered request repeats after `MAX_WITNESS_RESOLUTION_SECONDS` on a
reserved `CompanionWitnessResolution` wake.

## Validating one resolution

`crates/agenc-ircd-runtime/src/e2ee/edge/witness_resolution.rs` owns one open
resolution per link incarnation. BEGIN's object must name this network, this
coordinator, this edge, the conversation the line named, its own token, and
must repeat the row's exact `expected_sequence` and `expected_head_id`; its
record count must be within `MAX_WITNESS_RESOLUTION_RECORDS` and its
identifier vector must hold exactly that many IDs. Only the identifiers are
retained, charged against the edge's backing reservation port.

Each ENTRY must carry the next contiguous entry position and the object ID
the resolution declared there. A complete record is decoded, its own claimed
position read, and then:

1. it must name this network, this conversation and the route sequence the
   verified prefix reached (the row's expected position for the first record,
   one more than the previous record afterwards);
2. its credential must be one the negotiated sequencer key set holds — the
   active credential or its overlapping successor — and its signature must
   verify under exactly that credential at exactly that position, through the
   ENC-02 record authenticator;
3. its predecessor must be the head the verified prefix reached (the row's
   retained head for the first record, the previous record's recomputed
   semantic ID afterwards).

END must repeat the declared count, every entry must have arrived, and the
last record's recomputed semantic ID and sequence must equal the declared
`new_head_sequence` and `new_head_id`. Only then does one durable
transaction rewrite the conversation's `route/v1/` row with the proven head
and delete its `witness/v1/` row. `EWITNESS RESOLVED` is sent from that
receipt, never before it, and the origins replay in the same step once no row
is left unresolved. The in-memory head moves on the receipt too, so a refused
or lost batch leaves the old head and the row exactly as they were.

## The three other outcomes

- **Empty answer.** `record_count` zero means the coordinator holds nothing
  beyond the expected position. Nothing is staged, the row stands unchanged,
  and the request repeats on the reserved wake.
- **Unresolvable fork.** A record that authenticates at the expected position
  but names a predecessor other than the retained head is a fork. One durable
  transaction marks the row `conflict`; no head moves and no `RESOLVED` is
  sent. That conversation reads `E2EE_SYNCING` for good — the mark is never
  cleared and no command clears it — while every other conversation resumes,
  because a `conflict` row no longer blocks the link. The mark survives a
  sealed restart.
- **Anything else.** A wrong token, target, anchor, order, object identity,
  count, credential, signature, predecessor or declared head closes the
  companion link as a profile violation and retains the row untouched, so the
  next link asks again.

## Defects this exposed

Two owner rules in `witness_failure.rs` were written when a blocked edge read
no frames at all, and both were wrong once it reads `EWITNESS`:

- `record_witness` returned `true` for *every* frame failure while a witness
  record was held, so after the receipt stood an unrelated bad frame neither
  counted a violation nor closed the link. It now returns true only while the
  receipt is still pending or when a new violation was actually observed.
- `witness_batch_applied` claimed every later batch once its record was
  durable, which would have swallowed the resolution's own receipt. A durable
  record now yields the batch to its real owner.

## Limitations

- The edge side only. No coordinator answers an `EWITNESS REQUEST` yet; the
  publication side of the resolution set is not part of this change.
- The overlap window is not re-derived from a clock on the edge. The rule
  enforced is the operative one — a record under any credential outside the
  negotiated key set is a violation — and that set carries the active
  credential and at most its overlapping successor.
- A `reinit_attempt` record cannot be proven through this carrier: its
  semantic ID needs the referenced `reinit_attempt` object and `EWITNESS
  ENTRY` delivers only `sequencer_record` objects. Such a set closes the link.
- One resolution is open at a time per link. A BEGIN under another token or
  conversation while one is open is a profile violation; the coordinator
  answers the edge's requests one at a time.
- The witness still cannot detect a record the coordinator never delivers. A
  resolution proves the continuity of what was delivered, never completeness.
- `MAX_WITNESS_RESOLUTION_BYTES` is a cumulative guard a well-formed set
  cannot reach, not a branch outcome; one record object is far below it.
- The unit fixtures commit one batch per step through sealed storage; native
  ext4 physical-growth qualification remains REL-08.

## Evidence

- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/witness_resolution.rs`: a
  sealed durable row reaches the blocked phase over a replacement link and is
  answered by a real two-record continuation signed by the negotiated
  credential — nothing is published before the receipt, the receipt sends the
  exact `EWITNESS RESOLVED`, installs the proven head, deletes the row and
  replays the origins; an empty answer retains the row and repeats its exact
  request from the reserved wake; a real record at the expected position under
  another predecessor marks the row `conflict` durably, leaves the head,
  resumes the link, blocks only its own conversation through the router gate,
  and survives a sealed restart; a record under an unknown credential, a
  skipped first position, an undeclared object identity, a second record that
  does not name the first, a wrong END count, a wrong declared head, a wrong
  anchor and a wrong conversation each close the phase and retain the row —
  with the same record under the negotiated credential staging its
  transaction, so only the key made the difference.
- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/witness_gating.rs`: the
  blocked phase admits the resume and one request per durable row in
  conversation order, drops the `EORIGIN READY` that followed, and keeps the
  cursor, the head, the retention block and `is_active` exactly where they
  were — across two link incarnations and across a sealed reconstruction that
  preserves two unresolved rows.
- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/witness_persistence.rs`: the
  existing durable-receipt, refusal, replacement-link and timer controls are
  unchanged.
- `crates/agenc-ircd-e2ee/src/tests/federation_frames.rs`: all five `EWITNESS`
  frames render and parse back with their exact arity and direction, and a
  wrong verb, a noncanonical sequence, a trailing parameter, a missing
  fragment and a tag on an untagged frame are refused.
- `crates/agenc-ircd-e2ee/src/tests/objects.rs` and `tests/object.rs`: the
  `witness_resolution` body round-trips and kind 36 has its token, its
  federation-control limit and its server-only direction.
- `crates/agenc-ircd-storage/tests/stage_five_completion/witness_evidence.rs`:
  the conflict mark round-trips through the witness body and is the only
  difference from an unmarked row.

Seven release critical regions cover the request phase, the delivery
validation, the durable installation, the resume gate, the blocked-frame
admission, the frame parser and the witness row codec; each measures
branches.
