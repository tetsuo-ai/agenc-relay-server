# Recovery submission carrier

This record closes ENC-03 (issue #57): a route restored `pending` under a
new daemon recovery epoch consumes previously signed, completely
authenticated evidence through the companion 13.7.4 recovery submission
carrier and permanently becomes `closed` or `conflict` in one durable
transaction. The restored server verifies every element through the ENC-02
historical chain and never signs a missing link. The registered wire kind
`recovery_submission(35)`, the opcodes `submit_recovery(42)` and
`submit_recovery_element(43)`, the result kinds 24 through 27, the
`EGROUP SUBMIT RECOVERY` and `RECOVERY-ELEMENT` commands, the
`RECOVERY-ACCEPTED`, `RECOVERY-EXTENDED`, `RECOVERY-CLOSED` and
`RECOVERY-CONFLICT` replies, the `ARC-MLS/1 recovery submission` signature
label and the `recovery_submission_id` hash domain were all fixed by the
companion (ENC-01); no profile hash, registry or specification text changes.

## Ingress

`EGROUP SUBMIT RECOVERY <conversation-id>` carries an `ArcRecoverySubmission`
(at most `MAX_RECOVERY_SUBMISSION_OBJECT`). The coordinator accepts it only
when the durable gate is `pending` and the submission names exactly the
gate's recovery epoch, source rollback guard hash and the three restored
identifiers, this network and conversation (`E2EE_ROUTE_INVALID`
otherwise); the submitting device is the attached device (`E2EE_DEVICE_REQUIRED`),
its account is a principal of the restored binding and its certificate is
active in that account's retained roster, and the device signature verifies
(`E2EE_BINDING_AUTH_INVALID`). The position must be the next chain
position (head sequence plus one with the head as predecessor) or, for a
record, the head position itself, which admits the byte-identical re-upload
of the head record and a competing successor. At most
`MAX_OPEN_RECOVERY_SUBMISSIONS` open submissions and
`MAX_RECOVERY_CHAIN_BYTES` of accepted submissions and elements are held
per conversation (`E2EE_RATE_LIMITED`). An exact duplicate returns the prior
`RECOVERY-ACCEPTED` without a write; another object under the same
submission identifier is refused.

`EGROUP SUBMIT RECOVERY-ELEMENT <conversation-id> <submission-id>` delivers
the element: it must come from the submitting device of an open, unexpired
submission (`E2EE_OBJECT_NOT_FOUND` otherwise), carry the accepted wire kind
(`E2EE_INVALID_FRAGMENT`) and hash to `element_object_id`
(`E2EE_HASH_MISMATCH`).

- A `reference_element` (a policy, root identity, root chain, device roster,
  binding package or ReInit attempt) is retained for its position and
  answered `RECOVERY-EXTENDED` naming the unchanged head; a record at that
  position adopts exactly the references accepted for it.
- A `record_element` at the next position is adopted through
  `HistoricalChain::advance`; a valid record extends the recovery head
  (`RECOVERY-EXTENDED`), an invalid one is `E2EE_BINDING_AUTH_INVALID` and
  installs nothing. At the head position, the byte-identical head record
  repeats the prior reply; a different record is examined through
  `examine_alternative` against the chain before the head: a complete valid
  successor with another semantic identity installs `conflict` naming both
  records (`RECOVERY-CONFLICT`), the same record under other proof bytes is
  idempotent, and malformed or unreached evidence is refused.
- A `close_element` naming the head finalization is adopted through
  `HistoricalChain::close` and installs `closed` (`RECOVERY-CLOSED`).

An accepted submission whose element has not arrived after
`MAX_RECOVERY_SUBMISSION_SECONDS` is discarded: it no longer counts, its
element is `E2EE_OBJECT_NOT_FOUND`, and its row is deleted by the next
recovery batch of the conversation. A completed submission's exact element
re-upload repeats the prior reply.

## The resumed chain

The restored server derives the authorizing prior state from what it
already holds, never from uploaded objects: the retained binding package
re-verified against the current principal rosters, the last finalized
policy, the credential that signed the restored head (or, at the genesis
anchor, the credential the binding pins, falling back to the installed
current credential), the accepted epoch and state, the head and its open
candidate, the required operational policy and the bootstrap flag.
`HistoricalChain::resume` opens the chain at that position; the records the
recovery already installed are replayed from their rows with the references
accepted for each position, so a restart rebuilds exactly the lineage the
last committed batch left. The chain before the head is kept for alternative
examination; at the restored head it exists only when the head is an open
candidate. Recovery of a route whose restored head is a ReInit record, or
whose lineage needs a sequencer credential transition (no wire kind carries
a credential), is refused with `E2EE_ROUTE_INVALID` or
`E2EE_BINDING_AUTH_INVALID` and installs nothing.

## Durability

Two state rows persist the recovery under the gate:

- `recovery-submission/v1/<conversation><submission-id>` (record kind 17):
  the submitting account and device, the element kind, wire kind and object,
  the position, the trusted acceptance second, the submission object, whether
  the element is retained and the outcome (open, referenced, extended with
  the record identifier, closed with the close identifier, or conflict with
  both record identifiers). The row owns the submission object (ordinary)
  and, once retained, the element (a security proof for records and closes,
  ordinary for references), charged to the conversation (ENC-08).
- `recovery-record/v1/<conversation><route-sequence>` (record kind 18): one
  record the recovery installed beyond the restored head, with its
  identifier, object, predecessor, kind and submission; the row owns the
  record object as a security proof.

While the gate is `pending` the restored route row, its records and the
gate stay untouched, so a restart validates the same restored heads.
`closed` is installed in one batch with the close object, the tombstone
route row and object (the head moves to the close at the next sequence),
the completed submission and the `E2eeRecoveryGate` row; `conflict`
installs the gate row with the competing record retained. Both move the
route entry and lifecycle through `resolve_recovery`, never back to
`normal`, and the gate row is validated at startup exactly as before. A
refused or indeterminate batch installs nothing.

## Findings from the daemon evidence

The real-daemon test drives a coordinator restored to an older backup under
a new recovery epoch while both edges keep the state they projected after
that backup. Making that path work exposed five runtime defects, each fixed
here with its own unit test:

- After the restore the coordinator numbered its next snapshot generation
  for an edge from the backup's peer record, at or below the generation the
  edge already held; the edge refused the snapshot and the link flapped
  without end. `snapshot::resume` now counts on from the generation the
  edge reports when the scopes differ (FED-10), so no generation number is
  reissued and the edge's persisted rows of the old generation never collide
  with the new ones
  (`federation::coordinator::tests::a_generation_the_edge_holds_above_the_coordinator_is_never_reissued`).
- A companion `ESTATE` transfer interrupted by link loss could never resume:
  the coordinator kept the pending cut and refused the edge's next
  `ERESUME` as a protocol violation, while the edge had discarded its
  staged pages with the link. A resume on a new link now publishes the
  pending cut again from its first page, a second `ERESUME` on the link
  carrying the transfer is still a violation, and an expired or retired cut
  resets to the next delivery generation
  (`e2ee::coordinator::tests::sync::a_base_reset_opens_the_next_delivery_generation`).
- Between a device attachment and the acknowledgement of the origin
  declaration that carries it, the edge forwarded requests under the
  previous declaration, so the coordinator refused them as unattached. The
  origin now records the acknowledged generation the device predates, and
  requests answer `E2EE_SYNCING` until a later generation is acknowledged
  (`e2ee::edge::origins::tests::requests_wait_for_the_declaration_that_carries_a_new_attachment`).
- The live coordinator counted only the old council's votes on a bootstrap
  activation, while companion 9.5 and the ENC-02 chain require both the old
  and the resulting council. A vote from a member of the resulting council
  alone is now recorded against that council and both quorums are required,
  so a bootstrap activation the coordinator accepts is one the historical
  chain verifies
  (`e2ee::coordinator::tests::sequence::a_bootstrap_activation_needs_the_resulting_council_too`).
- The closed recovery reply completed through the closed route's own
  `RouteStateChanged` event, which the submitter's edge only receives when it
  hosts the route; the reply is now a generic completion like every other
  recovery reply, and the route event still goes to the hosting edges.

Two fixture facts also matter for anyone reproducing the evidence: the
roots and rosters must cover the records' canonical validation time, since
the chain re-verifies at that time (companion 9.2 and 9.3), and the bootstrap
activation must carry both councils' votes. Observed once in an early run
and not reproduced under instrumentation: an edge stopped right after its
client's `QUIT` refused to start with `StaleState` from its projection
install; the daemon test lets both sessions retire before it stops the
edges.

## Evidence

- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/recovery_submission.rs`
  (in-process coordinator): a route restored `pending` at the genesis
  anchor adopts a four-record lineage (candidate, bootstrap activation with
  its policy reference, closing candidate and closing finalization) and the
  finalized close, repeats the prior reply for the byte-identical head
  record, installs `closed`, keeps it through a reopen and refuses every
  later submission; a reload between chunks replays the installed records
  and completes; two valid candidates for position zero install a permanent
  `conflict` naming both, retaining both proofs through a reopen and
  refusing everything after; a forged second record installs nothing and
  keeps the submission open; a wrong epoch, guard, head, binding, position,
  predecessor, network, device or element kind, a non-principal account and
  a corrupted signature are refused with their codes and change nothing; an
  unknown submission, a wrong element and a wrong element kind are refused;
  an exact duplicate repeats the prior reply without a row; open submissions
  are bounded at `MAX_OPEN_RECOVERY_SUBMISSIONS`, expire after
  `MAX_RECOVERY_SUBMISSION_SECONDS` without touching the gate or head, and a
  new submission then fits; a route restored at the recorded bootstrap head
  or while closing resumes from that record and closes; a second device's
  byte-identical head record repeats the extension; a submission object of
  another kind and a head named with another predecessor are refused; and
  references come only from retained reference objects at the position.
- `crates/agenc-relay-server/tests/stage_eight_e2ee/recovery_submission.rs` (real
  daemons): a signed backup taken after the bind, the live lineage and close
  signed afterwards, `storage restore` under a new recovery epoch, the gate
  read `pending` from the restored state, the chain and close uploaded by
  the attached device through the edge, `RECOVERY-CLOSED` naming the
  original close, `closed` read from the durable gate after a stop, and
  `E2EE_ROUTE_INVALID` for a submission after the restart.
- `crates/agenc-relay-storage/tests/e2ee_records.rs`: both rows round trip,
  every inconsistent outcome is refused and neither body replays as the other.
- `crates/agenc-relay-e2ee`: the carrier object round trips with an
  identifier covering every field, the element kinds accept exactly their
  object kinds, and the command, carrier and reply tables cover the new
  productions.

Fifteen release critical regions cover the submission verifier and the
resumed chain in the e2ee crate, submission admission and element
installation, the lineage index, references and resume, the companion
transfer restart, the snapshot generation adoption, the edge origin
settlement and its gate, the dual-council count, the two storage rows and
the completion table; each measures branches, and a branch-instrumented
coverage run over the owning crates reaches every outcome in all fifteen.

The in-process fixtures use synthetic MLS bodies with real device, council
and sequencer signatures; the daemon test carries real objects end to end.
Real MLS endpoint evidence remains outside this record.
