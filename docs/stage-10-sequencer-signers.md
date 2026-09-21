# Sequencer signer roles across rotation

This record closes ENC-07 (issue #58): the coordinator holds companion 9.2.1's
three private signers, every conversation pins the credential of its current
accepted context, receipts and terminals are signed under the pinned and the
receipt's credential respectively, a finalized `SEQUENCER` transition moves
the pin, and startup reconstructs signer ownership from durable metadata,
refusing or blocking exactly as the overlap deadline requires. The
configuration contract is architecture Appendix C.7 (`e2ee.sequencer_*`
paths and the atomic refusal table) and C.8 (`print-onboarding` renders the
verified key set and omits the four E2EE lines as one unit when the profile is
disabled). No wire object, opcode, reply code, or normative text changed; the
nine `STATS E2EE` fields are unchanged.

## Signers and configuration

`e2ee.sequencer_private_key_file` serves the credential the credentials file
lists first, `e2ee.sequencer_successor_private_key_file` is required exactly
when the file lists a successor and must be that successor's key, and
`e2ee.sequencer_retired_private_key_file` names the one retired credential the
durable history and the live state still require. All three are protected
32-byte seeds loaded by the secret set, which refuses a seed shared between any
two purposes. Installation (`install_signers`) verifies every key against the
exact credential of its role and refuses the whole set otherwise: a successor
key that is not the other credential's key, a retired key whose credential the
advertised set still carries or whose key it is not, and two roles sharing one
public key. A refused installation changes nothing.

The credentials file may open above generation zero once the old credential is
gone: `SequencerKeySet::verify_opened` checks the opening credential's
structure (profile, network, interval order, a nonzero generation with a
predecessor identifier, a present continuity signature) and chains at most one
successor from it. The coordinator's startup then refuses a set whose opening
credential its durable history never accepted, so continuity is verified when
the credential first enters an accepted set and never trusted from the file
alone. Both roles derive the same digest, so the ECAP tuple and the onboarding
descriptor agree.

## Pins, receipts and terminals

A binding pins `sequencer_credential_id`, and bind refuses a credential no
active or successor signer issues. The pin lives in the conversation state and
in the `route/v1/` row (two appended optional fields: the pin and a blocked
marker), so a restart restores it exactly. A candidate receipt or ReInit
attempt receipt is signed only by the pinned credential's issuing owner and
only while that credential covers the Commit's canonical validation time (the
attempt's trusted time); otherwise the submission is `E2EE_SYNCING` and nothing
changes. A retired-retained signer never issues a receipt. Finalization,
abort, ReInit activation and ReInit abort use exactly the receipt's
`sequencer_key_id` through whichever role owns it, so an old-credential
receipt completes under the retired key after the set moved on and never
under a replacement.

A finalization whose authorization carries `action_bits::SEQUENCER` is the
conversation's transition: it is itself signed under the old credential, and
it moves the pin to the advertised credential whose `previous_key_id` is the
current pin, clearing the blocked marker, in the same batch as the route row.
Every later record signs under the successor. Without such a successor the
transition is `E2EE_BINDING_AUTH_INVALID`. The live request carries no
credential object, so the successor is the advertised one; the historical
chain verifies the supplied credential bytes as before.

## Startup reconciliation

Startup restores the accepted key set (`keyset/v1`, state kind 11, now
written) and the permanent credential history (`sequencer-history/v1/`, kind
19: key generation, public key, interval, predecessor, the set generations
that introduced and retired the credential, and the release fact), collects
the pin of every `normal` live route and the `sequencer_key_id` of every
unfinished candidate and attempt receipt, and decides at the trusted time:

- the configured set must equal the accepted set (same generation and digest)
  or advance it by one generation with its current credential already
  accepted; anything else refuses startup;
- a set that omits a credential a `normal` route still pins is refused before
  that credential's overlap deadline (its successor's `not_before` plus
  `MAX_SEQUENCER_KEY_OVERLAP`) and accepted at or after it, marking every such
  route blocked;
- every omitted credential is retired in the history; a retired credential no
  pin and no unfinished receipt requires is released, and its key is dropped;
- a configured retired key must be the key of exactly the required credential;
  a released or unrelated key refuses startup; a required key that is not
  configured starts the coordinator with the routes blocked, one
  `e2ee_retired_signer_missing` audit event, and `e2ee_routes_blocked` with
  the count.

The decision's rows are staged as the first startup batch through the same
loader as owner retirement, applied only once durable, and a reconciliation
with nothing to persist is applied without a batch. A closed or pending route
is never live for signer purposes. A blocked route refuses candidates, ReInit
attempts and policy changes with `E2EE_SYNCING`, keeps opaque application
delivery, and leaves the blocked state only through a finalized successor
transition of an already issued old-credential receipt (or close and rebind).

Findings: the first daemon startup that stages a signer batch exposed that
the federation loader resumed only from a maintenance tick (a minute apart in
the daemon, never in the in-process harness); the commit receipt now
continues the reload at once. The daemon test client had pinned a
placeholder credential in every binding, which the bind-time owner check now
refuses; the testkit binding builder takes the pin and the daemon tests pin
the coordinator's active credential.

## Onboarding

`print-onboarding` loads and verifies the credentials file exactly as startup
does and renders that set's generation and digest; with `e2ee.enabled = false`
the four E2EE lines are omitted as one unit and the descriptor parser returns
no key set, so an importer never enables E2EE. The unused duplicate file
layout in `agenc-relay-e2ee::federation::keyset_file` was removed.

## Limitations

- At most one retired-retained signer is held; a second required retired
  credential leaves its routes blocked and its receipts unfinished.
- The seven Appendix C.7 and C.8 clauses stay bound to `S10-008` (the
  restore, deletion and key-lifecycle drills), which also covers the
  descriptor's monotonicity check against a live database.
- The in-process harness binds one conversation per coordinator; the two
  conversation phases of the companion table are exercised as separate
  coordinators plus the restart sequence.

## Evidence

- `crates/agenc-relay-e2ee/src/tests/sequencer.rs`: a file opening above
  generation zero verifies structurally to the same set as with the
  predecessor at hand, chains a successor, and refuses a missing continuity
  signature, a zero predecessor, an inverted interval, generation zero,
  another profile or network, and a third credential.
- `crates/agenc-relay-config/tests/sequencer_secrets.rs`: the successor and
  retired seeds load by role; a seed shared with the active key, with another
  purpose, or between the two optional paths is refused with its field.
- `crates/agenc-relay-config/tests/template_onboarding.rs`: a disabled
  profile omits the four lines and parses back as no key set; a partial or
  foreign block is refused.
- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/sequencer_eligibility/rotation.rs`:
  bindings pin a credential and receipts follow it (old and successor,
  interval boundary, an unissued credential refused); a finalized `SEQUENCER`
  transition moves the pin durably and later receipts sign under the
  successor; a transition without an advertised successor is refused; a
  terminal completes under the retired-retained signer and never under the
  successor; a ReInit attempt signs only under the old pin; a blocked route
  refuses candidates, attempts and policies but delivers; installation
  refusals.
- `.../rotation/restart.rs`: the first startup records the set and history
  and the next has nothing to persist; refusal of a same-generation,
  below, skipped or unrelated set; refusal before the deadline and blocking
  at it with the missing-key report; the retired key completes an open
  receipt and the transition unblocks the route; release and refusal of the
  released or an unrelated key; early acceptance once every live route
  migrated.
- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/close_authority_cases.rs`:
  a closed route pins no signer at startup.
- `crates/agenc-relay-runtime/src/daemon.rs`: the active and successor keys
  install by credential, either alone is refused, and a retired set with the
  configured retired key installs the successor as active on the coordinator
  and the same tuple on an edge.
- `crates/agenc-relay-runtime/src/offline.rs`: the descriptor pins the
  verified set of an opened file, omits the block while disabled, and refuses
  a malformed file.
- `crates/agenc-relay-runtime/src/observe/adapter.rs`: the signer report
  emits the two audit events.

Seven release critical regions cover signer installation and selection, the
startup reconciliation, the transition pin, the startup proposal, the opened
credential and set, and the daemon's signer setup; each measures branches, and
a branch-instrumented run over the owning crates reaches every outcome.
