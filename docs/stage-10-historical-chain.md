# Historical public authority chain

This record closes ENC-02 (issue #51): the reusable verifier that turns the
independently pinned genesis binding plus a complete public historical chain
into a typed terminal or ancestry result. It changes no wire object, registry,
profile hash, storage format, or dependency pin. Declared recovery (companion
13.7.4) and witness resolution (companion 12.5.1) consume it; their
integration is ENC-03 and ENC-04.

## Composition

`agenc_ircd_e2ee::history::HistoricalChain` opens at the external genesis
anchor of an `InitialAuthority` (CAP-73 initial authority under the
independent binding pin) and adopts one complete `sequencer_record` at a
time through `advance`. Each record is authenticated at exactly the next
route sequence, naming the head as predecessor, under the credential the
validated history committed for that position; the caller can never choose a
position or credential. A caller-supplied `RecordReferences` carries the
public objects a transition needs and nothing else: an object without its
action bit, or a bit without its object, refuses the record.

- A candidate opens exactly one candidate of the accepted state at the
  expected candidate sequence and predecessor.
- A finalization must name the open candidate and its exact receipt, carry a
  canonical ACK set whose digest and fields agree with the certified core,
  carry the authorization the core commits, satisfy the old policy's
  controller threshold through `verify_commit_authorization`, and reach the
  old council's derived quorum from device signatures recounted through
  `QuorumLedger`. The committed credential must also cover the Commit's
  canonical validation time, as must every retained root and roster. A
  bootstrap activation additionally needs the resulting council's quorum
  over the same slot and can only install the binding's required operational
  policy; a bootstrap-pending group may finalize only plan Adds, join
  confirmations, and that activation. The finalization then installs, in
  order, root continuations and roster heads (a reaffirmed roster is accepted
  as the identical current roster), the policy under the old controller set,
  the sequencer successor under the previous credential's continuity
  signature, the binding successor whose ID the authorization committed, the
  close intent, or the ReInit target digest.
- An abort must name the open candidate and receipt, carry a nonzero reason,
  and reach the old council's abort quorum; the next candidate increments its
  sequence and names the abort.
- After the ReInit Commit finalizes, only attempts and their terminals follow.
  An attempt receipt needs its exact attempt object (hash, ID, target digest,
  old state, controller authorization under the old policy); an activation
  must repeat the retained attempt and receipt, carry a canonical ACK set
  that agrees with the attempt, and reach the old quorum over the attempt's
  sign-once slot; an attempt abort frees the next attempt sequence.
- A close authorization ends a closing lineage only when it names the current
  binding, the head finalization, and the committed close intent, and its
  approvals satisfy the last finalized policy's controller threshold.
- `examine_alternative` re-verifies a second record for the head position
  from the state before the head: a complete valid successor with a different
  semantic ID is a `Conflict`; the same semantic record under other proof
  bytes is `SameRecord`; malformed evidence, a wrong credential, or an
  unreached quorum is an error, never a fork.

Every accessor returns validated anchors only (head, accepted state, epoch,
policy, principals, binding, sequencer credential, lifecycle). The chain keeps
no evidence beyond those identities; `ChainLimits` bounds the records a chain
may adopt, every decode charges the caller's `DecodeBudget`, and a refused
record leaves the chain byte-for-byte unchanged, so cancellation or truncated
paged evidence preserves caller state. No clock, storage owner, signing
secret, or MLS private state enters the module.

Endpoint-only and therefore not claimed: the leaf membership behind an ACK
signature (ENC-05 supplies the server-visible mapping), copath coverage, the
staged result a voter compared, and the exact continuing set of a ReInit.

## Evidence

`crates/agenc-ircd-e2ee/tests/history.rs` builds real-signature chains from
the pinned genesis: two principals (three devices), the creator-only
bootstrap policy, the generation-one operational policy, and a sequencer key
that signs every record at its exact position. Inner MLS evidence stays
synthetic. The suite covers bootstrap activation under both councils; routine
finalizations; a policy transition under the old threshold with the exact
object; a roster reaffirmation and successor; a root continuation with a
fresh roster and a policy naming the new council; a sequencer rotation that
changes the committed credential for later positions; a binding migration;
an abort and the incremented candidate sequence; a closing transition and
the exact close; a ReInit attempt, attempt abort, second attempt, and
activation to the terminal; and conflict classification.

Refusals covered: an omitted, reordered, or replayed record; a record signed
by the successor key before rotation or the retired key after it; a
substituted policy object, a missing roster, a skipped roster generation, a
root continuation without its roster, a wrong binding target, an unapproved
policy change, a forged or wrong-binding close, a close before the closing
transition, a candidate after closing or after the ReInit Commit, an attempt
with a wrong target digest, a terminal after activation; votes below quorum
and an invented vote by a non-council device despite a valid sequencer
signature; a transition object smuggled beside a routine record; a chain
opened under another genesis pin; a record naming itself; the record limit,
truncated bytes, a wrong object kind, and an exhausted decode budget, each
leaving the chain unchanged.

Commands: `cargo test -p agenc-ircd-e2ee --locked` (all crate suites,
including the sixteen chain tests), `cargo clippy -p agenc-ircd-e2ee
--all-targets --all-features -- -D warnings`, `cargo fmt --all --check`, and
the stage-nine gate.
