# Stage 10 completion ledger

This working ledger tracks the implementation requested on 2026-09-10. It is
not a conformance manifest. A checked implementation item does not close a
production gate or qualify another source commit.

## Baseline

The earlier Stage 10 implementation and repairs merged through
[PR 27](https://github.com/tetsuo-ai/agenc-relay-server/pull/27). The credential and
runtime follow-up starts at merge commit
`fd7d39476302caae385e69bdea126d0a54164233`.

The invitation FINISH revalidation repair (audit subfinding ZDH-A1, issue
#38) is recorded in
[the invitation FINISH repair](stage-10-invitation-finish-repair.md).
The closed filesystem rejection causes (STO-09, issue #50) are recorded in
[the filesystem causes record](stage-10-filesystem-causes.md).
The silent post-TLS close follow-up (RUN-03, issue #45) is recorded in
[the admission diagnostics record](stage-10-admission-diagnostics.md).
The backup post-rename failure repair (STO-06, issue #48) is recorded in
[the backup publication repair](stage-10-backup-publication-repair.md).
The LIST selection and scan-charging repair (RUN-02, issue #54) is recorded
in [the LIST selection repair](stage-10-list-selection-repair.md).
The historical public authority chain verifier (ENC-02, issue #51) is
recorded in [the historical chain record](stage-10-historical-chain.md).
Durable object ownership, retention classes, trusted acceptance ages and the
conversation and global disk quotas (ENC-08, issue #53) are recorded in
[the object ownership record](stage-10-object-owners.md).
Bounded, race-safe physical deletion of expired unowned objects (ENC-09,
issue #67) is recorded in
[the object expiry record](stage-10-object-expiry.md).
The recovery submission carrier that lets a restored pending route become
permanently closed or conflict (ENC-03, issue #57) is recorded in
[the recovery submission record](stage-10-recovery-submission.md).
The three sequencer signer roles, per-conversation credential pins and the
startup reconciliation across a key rotation (ENC-07, issue #58) are recorded
in [the sequencer signer record](stage-10-sequencer-signers.md).
The edge's bounded durable snapshot generations with exact READY and ACTIVE
recovery (ENC-14, issue #59) are recorded in
[the edge snapshot generations record](stage-10-edge-snapshot-generations.md).
The configured secret-lookup response floor (RUN-06, issue #60) is recorded
in [the secret-lookup floor record](stage-10-secret-lookup-floor.md).
The re-verification and disposition of the four secondary 2026-09-01 audit
findings ZDH-C3, C4, C5 and A1 (issue #13) are recorded in
[the secondary audit findings record](stage-10-audit-secondary-findings.md).
The advertised capacity workload, the per-node occupancy measurement and the
advertised-limit profiling matrix (CAP-01, issue #56) are recorded in
[the capacity workload record](stage-10-capacity-workload.md).
The authenticated `EWITNESS` resolution that lets a durable edge witness
install a proven head, or block its conversation for good (ENC-04, issue #62),
is recorded in
[the edge witness resolution record](stage-10-edge-witness-resolution.md).
The bounded four-phase stop of a coordinator and an edge while federation
recovery is live and acknowledgement work is still outstanding (RUN-05, issue
#64) is recorded in
[the shutdown-during-recovery record](stage-10-shutdown-during-recovery.md).
The database/guard publication window a kill can interrupt, and the withdrawal
of CAP-01's reading that a killed edge's restart was refused by
`verify_guard_pair` (STO-10, issue #124), are recorded in
[the storage guard reopen record](stage-10-storage-guard-reopen.md).
Real openmls and mls-rs endpoints driving the repaired encrypted recovery,
sequencer rotation and ReInit paths through the daemon's client surface
(ENC-10, issue #71) are recorded in
[the encrypted client proof record](stage-10-encrypted-client-proof.md).
The funded default memory budget that holds the advertised 50,000-client
population in the normal overload class, and the eviction projection that
returns each closed connection's whole charge (issue #113), are recorded in
[the overload threshold record](stage-10-overload-threshold-defaults.md).
The project-owned redb fork that replaces the withdrawn upstream submission
(STO-02, issue #55) is recorded in [the redb fork record](stage-10-redb-fork.md).
The coordinator's `EWITNESS` publication side, terminal proofs and
bootstrap-activation votes that reload as the live coordinator admitted them,
and conversation-charged retained terminal requests (ENC-19 to ENC-22, issues
#166 to #169) are recorded in
[the coordinator remediation record](stage-10-coordinator-remediation.md).
The one physical growth allowance that now spans the nonce reservation, both
guard replacements, the main or checkpoint transaction, the deferred cleanup
and the close of every durable operation on the core write path, its
determinate refusal, and the bounded region size a live database is created
with (STO-03, issue #61) are recorded in
[the bounded durable operation record](stage-10-bounded-durable-operation.md).
The writer queue that is full only at its byte or item ceiling, so pipelined
one-line replies and deliveries no longer close a connection as a slow
consumer, and the `ERROR` line a slow-consumer close now sends from the
reserved control slot (RUN-10, issue #174) are recorded in
[the pipelined commands record](stage-10-pipelined-commands.md).
The owners of all three Section-19.3 overload classes — the refused guest and
expensive query at 80 percent, the refused channel creation at 90 percent, and
whole-connection eviction down to the 85-percent recovery mark at 95 percent
(RUN-07, issue #131) — are recorded in
[the overload class owners record](stage-10-overload-class-owners.md).
The base runtime, domain and wire critical-branch regressions, the
forty-one regions they bring to 100 percent and the region-metric corrections
they required (COV-01, issue #66) are recorded in
[the base coverage record](stage-10-base-coverage.md).

The durable-prefix sweep of an edge restarted after a kill under load, the
unreproduced CAP-01 startup refusal it narrows, and the reconstruction surface
and record family the daemon now names in that refusal (RUN-08, issue #134) are
recorded in
[the edge startup reconstruction record](stage-10-edge-startup-reconstruction.md).
The disproof of that record's remaining hypothesis, the per-generation
reconstruction ceilings that let an edge restore rebuild every projection its
admission side can admit, and the classified cause the daemon now prints beside
the record family (RUN-08, issue #134) are recorded in
[the edge restore refusal cause record](stage-10-reconstruction-cause.md).
The reproduction of that refusal at the published `server.memory_budget_bytes`,
three times in 209 SIGKILLs of an edge under load, the channel a running edge
legitimately holds between the two projected events that bracket it, the
restore install that now rebuilds it while the snapshot install stays closed,
and the recovered session reconciliation that now names itself in every refusal
it raises (RUN-08, issue #134) are recorded in
[the peer-loss reproduction record](stage-10-peer-loss-reproduction.md).
The encrypted lifecycle, authentication and crypto critical-branch
regressions, the eighteen regions they bring to 100 percent, the five
region-metric corrections they required and the three rows that cannot reach
100 percent under their declared metric (COV-02, issue #72) are recorded in
[the encrypted coverage record](stage-10-encrypted-coverage.md).
The per-row decisions for the release-critical regions that reach 100 percent
under neither metric, the audit that found nine more rows with the same
declaration defect, and the refusal that now names an unscoreable declaration
apart from an untested span (COV-05, issue #135) are recorded in
[the region metric decisions record](stage-10-region-metric-decisions.md).
The thirty-five reviewed spans re-anchored onto the item their row names, the
drift that moved them, the audit that found sixty-seven more and the refusal
that now names a mis-anchored span apart from an unexercised file (COV-06,
issue #142) are recorded in
[the region anchors record](stage-10-region-anchors.md).
The sequencer rotation drill rewritten to the overlap, the finalized
`SEQUENCER` transition and the retained predecessor ENC-07 requires, the
receipts and refusals it now asserts at every step, the ordinary test that
guards its key sets outside the native campaign, and the audit of every other
ignored Stage 10 drill (QA-02, issue #137) are recorded in
[the rotation drill repair record](stage-10-rotation-drill-repair.md).
The fifty-nine reviewed spans that had drifted onto executable code and scored
against items they never declared, the nine the audit had miscounted, and the
`item` and `span_sha256` fields that now bind every row to its item instead of
to a line range an insertion above can silently invalidate (COV-07, issue #145)
are recorded in [the region drift record](stage-10-region-drift.md).
The account-deletion drill given the account-controls capability its `ACCT`
surface requires and the readiness wait its restarts lacked, the refusal it
now proves writes nothing, the rows it reads for what a deletion removes and
retains, and the ordinary test that guards both preconditions outside the
native campaign (QA-03, issue #147) are recorded in
[the deletion drill repair record](stage-10-deletion-drill-repair.md).
The six release-critical regions that measured zero once COV-07 anchored them
to their own items — the companion coordinator's mailbox and ESTATE expiry
timers, its fetch continuation and three quarters of the startup
owner-retirement protocol — the regressions that drive each one through its
owning boundary rather than by calling the function, and the one entry that no
input can reach (COV-08, issue #150) are recorded in
[the companion coverage record](stage-10-companion-coverage.md).
The SASL carrier given the `UNAVAILABLE` report its two sibling carriers
already carry, the emission point that keeps a transient authority apart from a
refused credential where the cause is still known, the unchanged transcript a
client without `standard-replies` reads, and the drill retry and capacity
predicate that now read the line instead of guessing (RUN-09, issue #152) are
recorded in
[the SASL unavailable authority record](stage-10-sasl-unavailable.md).
The flake causes a dynamic-analysis sweep traced under adverse scheduling, the
fixture port allocator that removes the probe-and-release window, the fixture
commit awaited without a wall-clock deadline, the bind refusal and the
shutdown phase a daemon now names, and the two shutdown behaviours left open
with their `rr` evidence (QA-04, issue #175) are recorded in
[the flake causes record](stage-10-flake-causes.md).
The edge that drains with a base snapshot install outstanding, the decision
for each install stage between abandoning a wait only the coordinator can end
and finishing a local durable commit, the four-phase regressions that reopen
to a state which negotiates the snapshot again, and the audit retention scan
that `flush` waits on, reported and not patched (RUN-11, issue #178), are
recorded in
[the edge drain record](stage-10-edge-drain-pending-install.md).
The shutdown flush that no longer runs an audit retention sweep, the state
owner's flush that no longer queues behind the administrative one, the
maintenance sweep bounded by its checkpoint ceiling and resumed from the
checkpoint chain, the verification that still precedes every trust, deletion
and export, and the `rr` replay showing no signature verification inside
flush (RUN-12, issue #180) are recorded in
[the bounded shutdown flush record](stage-10-bounded-shutdown-flush.md).
Leaf-membership proofs verified against the retained roster snapshot they
name instead of the account's current heads, so live admission decides as
startup reconstruction does after a roster or root rotation, the explicit
`removed`-proof reading, and the finding it remediates
(ENC-18, issue #164) are recorded in
[the named-roster membership record](stage-10-membership-named-roster.md).
The remediation of the three edge
findings — the base entitlement an ESTATE snapshot entry now needs, the
fragment-zero charge with the dedicated decoded-byte ingress bucket, and the
successor credential's overlap window in witness resolution (ENC-15, ENC-16
and ENC-17, issues #160, #161 and #162) — is recorded in
[the edge remediation record](stage-10-edge-remediation.md).
The live release of a direct route projection when its edge stops hosting
both accounts, the cut and edge check that now enforce one hosting rule, and
the interrupted cut that is retired instead of republished (ENC-23, issue
#173) are recorded in
[the direct route release record](stage-10-direct-route-release.md).
The recovery and reference scratch admitted against the exact filesystem and
bounded by the fork's allowance before every one of its transactions, the
checkpoint that reads its cut back before it publishes and allocates no
scratch afterwards, the refusal mapping that never reports a refused scratch
as stale state or as an uncertain commit, and the metered scratch startup and
checkpoints now report (STO-04, issue #65) are recorded in
[the bounded recovery scratch record](stage-10-bounded-recovery-scratch.md).
The online backup that yields between bounded slices of every phase while
reading one authenticated snapshot cut, the exact final length fixed before
its temporary exists, and the bounded scratch written through the
project-owned fork (STO-05, issue #68) are recorded in
[the incremental backup record](stage-10-incremental-backup.md).
The descriptor-bound `R(F) + G` admission of every restore and rekey
scratch-plan and target-construction transaction, the scratch plan rebuilt as
bounded two-phase slices with bounded reclamation and close, the region rule
that lets a bounded database grow, the resume of a construction stopped before
its target existed, and the exact resume at a refused target batch (STO-07,
issue #69) are recorded in
[the restore and rekey admission record](stage-10-restore-rekey-admission.md).
The recovery epoch NOTE the welcome burst now sends to a client that
negotiated `agenc.ag/recovery`, whether or not it negotiated
`standard-replies`, the `900` that now ends an authenticated registration's
burst, read from the domain on a coordinator and from the session projection
on an edge, the `900` and `ACCOUNT` lines that now follow a registered
session's login on a coordinator, a standalone node or an edge, with the
login projected to the edges, the federation codec rule that lets a
recomputed channel membership keep the revision it joined at, with the edge
check that a recompute changes only a member's role, and the origin
generation an edge now declares after a registered connection's login
(SC-007, SDK program, outside master #35), are recorded in
[the login state record](stage-10-login-state.md).
The one formatter that now frames the public cloak in every user mask and in
every separate user and host field as Architecture Section 7.4 specifies, the
local JOIN token bound grown for the framed mask, and the revert of each
rendering site (AUD-18, SDK program item B-12, outside master #35) are
recorded in [the framed cloak record](stage-10-framed-cloak.md). An explicit
NAMES reply larger than one response batch, which closed the requester's
connection on a node answering its own clients and which the framed tokens
made more common, is delivered in pages as a JOIN's NAMES is (AUD-18 review,
outside master #35); see [the explicit NAMES pages record](stage-10-explicit-names-pages.md).
The local JOIN that a node's own router, core-only or a federated
coordinator, applies in the step that admits it, whose NAMES snapshot now
opens at once instead of never, so a lone `&` JOIN is answered and no longer
holds the commands behind it (AUD-16, SDK program, outside master #35), is
recorded in [the in-step local JOIN record](stage-10-in-step-local-join.md).
The edge's own answers to `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN` and
`INFO`, which closed the requester's connection on an edge, from the
single-node renderers with `LUSERS` in one fixed form without counts, also
while partitioned and always after the connection's earlier requests, and
`LINKS` forwarded to the coordinator (BLJ-R1, SDK program decisions D-28 and
D-35, outside master #35), are recorded in
[the edge local queries record](stage-10-edge-local-queries.md).
The one labeled response an edge gives its client's labeled `PRIVMSG`,
`NOTICE` or `TAGMSG`, the held echoes under `echo-message` and otherwise a
labeled `ACK`, as the coordinator gives its own client, and every welcome's
`RPL_LUSER*` counters, now the figures of the node's own `LUSERS` reply (SDK
program decision D-36, outside master #35), are recorded in
[the edge echo record](stage-10-edge-echo.md).
The edge initialized by `arcd init` that starts, links and advertises the
encrypted profile, its database complete without the fake OPAQUE record only a
coordinator must hold, and the kill-and-restart comparison showing that this
refusal does not explain RUN-08 (AUD-01, SDK program, outside master #35) are
recorded in [the CLI edge initialization record](stage-10-cli-edge-initialization.md).
The edge descriptor that pins the coordinator epoch the edge advertises,
through the daemon's own selection, the refusal of an edge with no enabled
coordinator record, and the node's own epoch printed by `arcd init` for its
peers' records (AUD-03, SDK program, outside master #35) are recorded in
[the edge descriptor epoch record](stage-10-edge-descriptor-epoch.md).
The offline `arcd sequencer-credentials create` command that writes a new
network's generation-zero sequencer credentials document from the shared
encoders, byte-equal to the testkit's, the operator-guide procedure that
enables the encrypted profile with it, and the three-node network provisioned
through `arcd` (AUD-02, SDK program, outside master #35) are recorded in
[the sequencer credentials record](stage-10-sequencer-credentials-command.md).
The edge's labeled `REINIT-STAGED`, `REINIT-ACKED`, `REINIT-ACTIVATED` and
`REINIT-ABORTED` replies, rendered by the result kind instead of as `ACKED`
or `ABORTED`, and the untagged ACK notice or terminal broadcast the edge no
longer sends to the connection whose request it completes (SC-013, SDK
program, outside master #35), are recorded in
[the requester replies record](stage-10-e2ee-requester-replies.md).
`EKEY CLAIM STATUS` answered with the claim's stored target device instead of
the asking device, and the disposition that leaves an empty claim result
re-evaluated after a coordinator restart (SC-001 and SC-002, SDK program,
outside master #35), are recorded in
[the claim status record](stage-10-claim-status-target.md).
The shared public verifiers corrected where they admitted correctly signed
objects the companion refuses, a sequencer successor that reuses its
predecessor's key, capability and leaf statements signed for another
network, roster certificates whose enrollment issuance is not shown and a
roster listing one certificate both active and revoked, together with the
first-contact roster admission that takes that issuance as explicit
evidence and the first-contact capability admission (X-10, SDK program,
outside master #35), are recorded in
[the shared verifier predicates record](stage-10-shared-verifier-predicates.md).
The thirteen endpoint scalars of companion Section 16 that had no constant,
and the table test that compares every Section 16 row with the `limits`
module (X-11, SDK program, outside master #35), are recorded in
[the companion client scalars record](stage-10-companion-client-scalars.md).
The public OPAQUE profile and client modules of the auth crate, which give
a client the coordinator's exact suite, key-stretching function, context and
identities and the client half of registration and login (X-08, SDK program,
outside master #35), are recorded in
[the OPAQUE client profile record](stage-10-opaque-client-profile.md).
The fuzz workspace's own selection of the reviewed local OPAQUE source,
which it resolved from the unpatched release before, and the explicit root
path edge that was measured but not applied because it fails the Section
28.8 formatting gate (X-09, SDK program, outside master #35), are recorded in
[the OPAQUE fuzz source record](stage-10-opaque-fuzz-source.md).
The program's normative revision, which removes the finalization ID from the
ReInit target, carries the target in every ReInit attempt with the
sequencer's checks and the coordinator's atomic successor installation, and
states the edge recovery-epoch, welcome `900`, pre-authentication default,
crate-graph and formatting rules, moving the E2EE profile hash under profile
version 1 (PC-001 with decisions D-13 to D-16 and D-30, SDK program item P-01,
outside master #35), is recorded in
[the ReInit target revision record](stage-10-reinit-target-revision.md).
The `preauth_command` default burst of 24 that the configuration, the
runtime's admission table and the golden configuration now use, as Section
19.1 and Appendix C.6 specify, so that a client paced to the bucket finishes
account creation or a login before registration within the registration
limit, and the operator guide's section on the budget (AUD-07, SDK program
item B-05, outside master #35), are recorded in
[the pre-authentication default record](stage-10-preauth-default.md).
The client wire crate's object-kind list completed with the four kinds it
lacked and held equal, with its copied tag, fragment and object limits, to
the crates that own them (X-12), the Appendix A.1 argument bounds made
public for client encoders (X-07), the server-to-client base decoder, its
framer, raw tag parser, registries and validators, with its fuzz target and
hand-written vectors (X-05), and the reader of the E2EE replies with the
charge of an object batch to its class and batch bounds (X-06, SDK program,
outside master #35), are recorded in
[the shared client wire record](stage-10-shared-client-wire.md).
The shared ReInit target helper that rebuilds a target from its Proposal,
checks the target every attempt carries for the sequencer, an endpoint and a
later joiner, and binds them to the old ReInit finalization and the successor
initial Commit, with the historical chain's carried-target checks, the
independent ReInit vectors and the one-target Stage 08 fixture (P-02, SDK
program, outside master #35), is recorded in
[the ReInit target helper record](stage-10-reinit-target-helper.md).
The ReInit successor verified under the rosters its own roster heads name,
with root continuity from the old heads and its binding's principals, the
root-rotation and suite-change vectors, and the channel-authority root that a
ReInit cannot rotate (P-03, SDK program, outside master #35), are recorded in
[the ReInit successor rosters record](stage-10-reinit-successor-rosters.md).
The refusal of the previous encrypted profile, the profile-mismatch answer
to an `ECAP` line of another profile, the mixed-version link through the
daemons and the operator guide's upgrade note (P-05, SDK program, outside
master #35) are recorded in
[the previous-profile refusal record](stage-10-previous-profile-refusal.md).
The ReInit phase the coordinator enters when a ReInit Commit finalizes, with
the sequencer's attempt checks against that finalization's authorized target
in the order decision D-11a fixes, the phase and its authority restored after
a restart, the successor the activation installs in its own transaction with
no reservation or binding and that a restart restores from its own rows, the
restore of ReInit state stored under the previous profile, which keeps such
groups closed, and the Stage 08 model's ReInit finalization (P-04 with G-07
and G-08, SDK program, outside master #35), are recorded in
[the ReInit enforcement record](stage-10-reinit-enforcement.md).
The route row's holding of its encrypted conversation's binding package for
as long as the route exists, with startup deriving the same holding, a
restart's validation-time floor from the Commits its candidate slots name,
a route row's holding of the rosters its conversation's statements name,
and the restore of stores written before these rules (D-39 with G-08, SDK
program, outside master #35), are recorded in
[the binding retention record](stage-10-binding-retention.md).
An edge's companion origin deletion naming the generation of the last
declaration its link carried and its next unused sequence, where the
coordinator fences the origin, a request a new link carries again being
classified against the coordinator's replay rows, the resending of an
origin's unanswered requests once its replayed declaration is acknowledged
after READY, under its acknowledged generation, and its base origin deletion
naming a pending update only once a link carried it (D-37, SDK program,
outside master #35), are recorded in [the origin deletion
record](stage-10-origin-deletion.md).
The leaf credential that `old_credential_hash` and
`resulting_leaf_credential_hash` read, the canonical TLS encoding of the
leaf's RFC 9420 `Credential` whose `credential_type` is basic, with the shared
helper over it and its check against two MLS libraries (D-42, SDK program,
outside master #35), is recorded in [the credential hash
record](stage-10-credential-hash.md).
What one peer asks of the coordinator being refused for that request alone
and never failing the federation link, beginning with the coordinator's
recent-object cache bounded per peer, expired at the companion idempotency
retention and answering a request past its peer's ceiling with its failed
result (D-41, SDK program, outside master #35), is recorded in [the link
faults record](stage-10-link-faults.md).
A federation link resuming after a lost acknowledgement, beginning with the
coordinator taking an `ERESUME` cursor that names a retained delivered row
past its committed acknowledgement as that row's cumulative `EACK`, committed
before `ERESUME OK` (D-44, SDK program, outside master #35), is recorded in
[the link resume record](stage-10-link-resume.md).
Display-name preparation preparing or refusing every input without
panicking, with spaces collapsed after normalization: the adapter applies
the RFC 8266 enforcement passes itself and uses the PRECIS dependency only
for the FreeformClass check and NFKC (D-45, SDK program, outside master
#35), is recorded in [the name preparation
record](stage-10-name-preparation.md).
A deleted origin's journal row naming the generation and next sequence its
deletion named, so an edge restarted before the deletion's acknowledgement
is durable replays the deletion its live link sent, the restore of origin
rows written before that rule, the held generation declared with its
acknowledged principal and daemon tests of such a restart (D-41 with G-08,
SDK program, outside master #35), are recorded in [the origin journal
record](stage-10-origin-journal.md).
The historical chain's check of the roots and rosters a finalization uses,
and of those it installs, against the Commit's canonical validation time,
with the narrow roster recovery from an expired roster (B-15, SDK program,
outside master #35), is recorded in [the E2EE lineage
record](stage-10-e2ee-lineage.md).
Further task isolation, generated administrator identity and federated MODE
repairs are recorded in [the runtime follow-up](stage-10-runtime-followup.md).
Independent connection scheduling and borrowed storage ciphertext are recorded
in [the client input repair](stage-10-client-input-repair.md) and
[the storage copy repair](stage-10-storage-copy-repair.md). On-demand input
and output queue backing and the default idle admission model (RUN-04, issue
#46) are recorded in [the idle connection backing record](stage-10-idle-backing.md).
The preceding operational changes are recorded in
[the operational repair report](stage-10-operational-repair.md). Earlier credential
and runtime repairs are recorded in
[the credential and runtime repair report](stage-10-credential-runtime-repair.md).
Earlier test and coverage measurements apply to their recorded sources. The
ignored qualification jobs remain
separate from the default workspace tests.

The accepted constraints are current-format storage only, published upstream
redb dependencies only, unchanged physical growth limits, and all five v1
claims on both native Linux targets. Earlier development formats remain
unsupported. The current-format backup and restore contract remains required.

## Implementation work

| Item | Required result | Status |
| --- | --- | --- |
| Repository history | Push the existing committed branch and open its review | Repair branches pushed in PRs #29–#34; PRs #29–#33 merged, with the final queue repair and completed gate results in #34 |
| Conformance maintenance | Bind the accepted current-format specification and preserve historical evidence | Baseline and requirement bindings repaired |
| Storage initialization | Preserve every existing rollback guard and reject reused initialization directories | Implemented; 316 storage tests pass |
| STO-1 | Upstream bounded preparation, allocation-free publication, bounded cleanup and close; integrate a published release | Mechanism implemented and tested in the isolated checkout (STO-01); upstream publication withdrawn for the project-owned fork (STO-02); core write path integrated under one allowance (STO-03), with the scratch, backup and construction paths and the native growth qualification still open |
| CAP-73 authority | Authenticate public state and its complete historical transitions without exposing private MLS context | Open |
| CAP-73 recovery | Ingest signed terminal evidence and atomically install Closed or Conflict | Open |
| CAP-74 | Resolve retained edge witnesses with authenticated ancestry | Open |
| CAP-86 | Bind ReInit admission and ACK signatures to the required old and continuing leaves | Open |
| CAP-101 | Select per-conversation credentials and retain exact old signers for unfinished records | Open |
| CAP-79 | Persist complete accepted-owner references, trusted ages and race-safe physical object cleanup | Owner accounts implemented (ENC-08); bounded race-safe collection of expired unowned objects implemented (ENC-09), with native ext4 growth and reuse qualification still owned by STO-03 and REL-08 |
| Edge credentials | Forward registered credential replacement with durable coordinator authority and replay | Implemented; real daemon replacement, registered reauthentication, session revocation, restart and receipt-order tests pass |
| Runtime follow-ups | Revalidate and close the Stage 06 command, privacy, revision, queue, reload and shutdown findings | Deferred channel-key authorization, account administration revisions, reload admission, durable refusal audit, idle session-close retry and startup audit indexing repaired. Capability refusals, channel privacy, per-connection accounting, maintenance isolation and independent round-robin input scheduling repaired; other items open |
| Storage follow-ups | Revalidate and close backup slicing, publication, temporary cleanup, canonical decoding and accounting findings | Canonical decoding, temporary cleanup, borrowed ciphertext decoding/opening and reverse-manifest arithmetic repaired; checkpoint/backup capacity and publication remain open |
| Configuration follow-ups | Reconcile OCSP, disabled listeners, key sharing, service-user checks and generated admin access | Disabled material, same-class key sharing, generated administrator UID and OCSP schema/WSS admission repaired, preserving edge outbound TLS; service-user checks remain open |
| Capacity evidence | Distinguish development load from production capacity and exercise the advertised limits | Workload matrix, per-node occupancy accounting, generator and default node budget implemented, and one node's 50,000 idle connections measured (CAP-01); the production campaign and the seven-day soak remain unrun, blocked on the Section 19.3 conflict in #113 |

Earlier findings remain in `TODO.md` and `stage-10-qualification.md`. A finding
is closed here only with a current regression or a recorded current-source
check showing the earlier repair. Historical checkpoint counts do not replace
fresh results.

### Storage initialization evidence

Three integration regressions fail on the baseline because initialization
reports success after overwriting a retained guard. The repair rejects a
retained valid guard, malformed or empty guard, symlink or directory before
creating `database.redb`. First-guard publication uses an exclusive rename;
a late entry is preserved and a failure after the database commit remains
Indeterminate. Later normal guard replacements retain their existing behavior.

`cargo test -p agenc-relay-storage --locked` passes 210 unit tests and 106
integration tests, including the new five regression and control tests and
the existing crash, restore and fault-injection cases. The production changes
add no wire or storage format and change no dependency pin or limit. The
release critical inventory now includes the initialization and guard checks.

### Capacity report evidence

The report verifier now requires at least 50,000 configured and observed
connections for the production capacity job. The separate soak job requires
at least 256. A 64-client development campaign cannot close production
capacity. The driver records its actual configured and peak populations and
rejects dropped resource samples, invalid sample times, unordered latency
percentiles and non-boolean shutdown results.

The regression tests fail on the earlier verifier and pass with the repair.
`python3 scripts/test-release-qualification.py` passes all 50 tests, and
`python3 scripts/qualify-release.py check` validates the 31-job inventory.
The existing capacity driver still runs 64 clients and therefore cannot
produce passing production evidence. Implementing and running the full
workload remains open.

### Canonical storage evidence

Channel body encoding and decoding now use the domain topic parser and
require canonical typed masks in every list. Persisted reference decoding
requires strictly increasing table/key pairs. Three regression tests reproduce
the earlier acceptance failures. A fourth test preserves valid topic tabs,
Unicode, each mask subject and quiet masks. The release inventory now includes
the changed envelope and channel validation gates.

Workspace Clippy passes with warnings denied. The all-feature workspace tests
pass, including live TLS, administration, restart, WSS and both MLS clients.
The first separate storage run refused its physical reserve probe because
filesystem free space changed between samples on all five attempts. The same
probe passes in the completed workspace run. Its exact boundary requirement
and retry count are unchanged.

### Temporary cleanup evidence

Storage startup and backup creation now enumerate temporary files through
the same open directory used for deletion. The new regression replaces the
original directory path, checks that the replacement's files remain intact,
and repeats cleanup through the retained descriptor. It fails with the earlier
path-based enumeration and passes with the repair. All 10 platform tests,
the complete storage suite and workspace Clippy pass.

### Specification and evidence bindings

The specification baseline now names exact normative source commit
`15acb53621e04b1aed87fa53033eb4b1f4628bd5`. Its six artifact bytes match that
commit, including current-format admission, the audit export union and the
client numeric corrections. The base and E2EE profile hashes are unchanged.
No normative document or archived result was edited for this repair.

Three current storage requirement bindings are added to the reviewed catalog.
The replaced migration atomicity sentence remains an archive-only binding and
is rejected for new closure. The catalog validates 382 bindings and all 1,000
archived entries. Its 79 negative cases and explicit retired-closure checks
pass. These catalog records identify required evidence; they do not provide
new passing qualification artifacts.

The inherited gates exposed three additional stale catalogs. Stage 01 now
pins the same architecture and decision-ledger bytes as the baseline. Stage 04
records the review of two changed crypto files: unkeyed artifact/snapshot
hash adapters and a public database-ID accessor. The reviewed login HMAC,
OPAQUE paths and secret comparisons are unchanged. Stage 05 no longer
requires the five legacy migration modules removed by the current-format
decision. Each stage's catalog check and negative self-tests pass.

At `8daac95`, the fresh all-feature workspace run passes 2,807 tests with
zero failures and 21 ignored tests. The separate documentation run passes
41 tests. Workspace Clippy, both target compile checks, dependency policy and
the advisory check pass. Coverage is 75.0714% branches and 91.4550% lines,
with all eight interim critical regions at 100%. That inherited run exposed
stale catalogs; the final validation below includes the resumed checks.

### Reader and command-line boundaries

The reader checks the pending parsed-byte and request counts before parsing
each completed line. Refusal stops further accumulation. Forwarding now
drains each complete line before feeding another, so a maximum-sized line
retained from an earlier read can complete within the minimum arena. Two
accumulator regressions fail with the earlier behavior. All 27 connection
tests pass, including fragmented input, message ordering and the exact
30-second inbox stall under a paused clock.

Account invitation expiry now rejects noncanonical unsigned decimals before
descriptor or signing-key access. The subprocess regression reproduces the
earlier acceptance of `+1` and passes for eight invalid spellings after the
repair. Workspace Clippy and source policy pass. The source-bound release
inventory includes both reader gates and the CLI parser; its thresholds are
unchanged.

JOIN key duplication was rechecked against Appendix A.1. Its `csv(key,20)`
grammar forbids duplicate canonical values, so the existing rejection is
retained. The broader queue-ownership and command-authorization findings
remain open.

### Final local validation

At `b2aa74760330b7a1c74fa0a1638402a5a20eba2d`,
`cargo test --workspace --all-features --locked` passes 2,813 tests, including
documentation tests, with zero failures and 21 ignored tests. The ignored
set contains 19 qualification scenarios and two fixture generators. Live TLS,
administration, federation, restart, WSS and both MLS client tests pass.

Workspace Clippy with all targets and features and warnings denied, formatting,
source policy and its 31 rejection cases, workspace policy, the requirement
ledger and baseline checks pass. The 50 release-runner tests and the 31-job
qualification inventory pass. Both x86_64 and AArch64 all-target compilation
checks pass; native AArch64 execution remains outstanding.

The 103 inherited Stage 00 through 09 commands were checked through the initial
and resumed runs after the catalog and test repairs. The final Stage 07 through
09 run passes its transcripts, bounded models, encrypted load and fuzz smoke
checks. The optional-profile matrix passes four builds, nine admitted
configurations, seven refusals before storage writes and retained-history
restarts with history disabled. These are implementation checks. Full native
release campaigns remain required.

Fresh coverage is 75.09% branches and 91.46% lines. All eight interim critical
regions and the three added reader/CLI regions reach 100%. The release check
still fails its 90% branch floor and 672 of 1,061 critical regions, including
regions without executable branch data. Both inventories bind all 765 current
Rust source files; the thresholds remain unchanged.

All three workflow files pass actionlint 1.7.12 syntax and expression checks,
with its optional shellcheck and Pyflakes integrations disabled, and parse
with PyYAML. The pinned checkout and upload action commits resolve.

### Hosted CI startup incident

Every push and pull-request event since 2026-09-10 17:42 UTC produces one
run that GitHub records as `startup_failure` with zero jobs, an empty
workflow name, the display title `(Unknown event)`, and the synthetic
workflow path `BuildFailed` (workflow ID 355138507, state `deleted`), for
example run 34782832427 on `daec140e`, run 34990440748 on `567cd6de`, and
run 34992419054 on `3786108f`. Their check suites carry no check runs and no
retained log, so the provider supplies no diagnostic text. The three real
workflows (`ci.yml` ID 341694647, `stage-10-aarch64.yml` ID 355219474,
`storage-qualification.yml` ID 345200086) are `active`, repository Actions
permissions are enabled with every action allowed, the default token
permission is read, no self-hosted runner is registered, and the last
workflow-file change (`d01f638`, 2026-09-05) precedes runs that started jobs
on 2026-09-05 and 2026-09-07. Probe PR #98, which removed
`stage-10-aarch64.yml`, still ended in `startup_failure`, so workflow content
is not the cause. The same signature appears across the organization's other
private repositories from 2026-09-11 (`agenc-backend` Dependabot runs,
`agenc-os` on 2026-09-14), and the organization's billing usage shows Actions
charges beyond the included quota in August and September 2026. The cause is
therefore an organization-level Actions block that starts every run before a
workflow is selected; confirming and clearing it requires an organization
owner to review the tetsuo-ai billing settings (payment method, Actions
spending limit, and any hold) and the organization Actions policy, which the
repository token cannot read (`admin:org` scope required). No repository
change can resolve it. The `Record the source identity` step now prints the
exact revision in every job log once runs start again. Hosted CI is not
green.

The isolated [upstream bounded transaction](upstream/redb-bounded-transaction/README.md)
gives redb 4.2.0 a typed physical allocation allowance with explicit phases:
charged mutation, abortable preparation that journals and restores every
allocator change on refusal, allocation-free publication, bounded resumable
reclamation, and bounded allocator-state persistence at close. It passes the
433 upstream host tests, clippy, the `panic=abort` no-std check, a fifteen-test
phase, boundary and crash matrix, and an API-aware fuzz state machine. Its
required upstream container gates still stop because Podman is unavailable.
Upstream submission is withdrawn for the project-owned fork (STO-02), and the
core write path is integrated under one nonce, guard, main-commit, cleanup and
close allowance (STO-03); the scratch, backup and construction paths follow
under STO-04, #68 and STO-07.
The x86_64 qualification host, its immutable release and client-tools
images, the ext4 tuple, the campaign isolation runbook and the AArch64
external blocker (REL-01, issue #43) are recorded in
[the qualification hosts record](stage-10-qualification-hosts.md).

The isolated [upstream allocation probe](https://github.com/tetsuo-ai/agenc-relay-server/blob/66ef11a03d18571ba745c9c19540feb0f5abe0be/docs/upstream/redb-allocation-probe/README.md)
passes 424 host tests but cannot publish a transaction. Its required upstream
container gates stop because Podman is unavailable. The normal-API fuzz smoke
does not exercise the new probe API. Full bounded commit support, upstream
acceptance and a published dependency remain open under STO-1.

## Required production evidence

- [ ] Mandatory build and analysis checks on native x86_64 and AArch64.
- [ ] Default, WSS, history and combined feature checks, including retained-data restarts.
- [ ] At least 90% branch coverage, 90% line coverage and 100% of the complete critical inventory.
- [ ] Supported native ext4 storage tests at the unchanged 128 MiB qualified growth ceiling and 256 MiB operational reserve.
- [ ] Independent IRC clients, OpenMLS and mls-rs lifecycles, federation failures and Tor privacy tests.
- [ ] Default 50,000-connection capacity within 4 GiB, advertised active workloads and recorded hardware.
- [ ] Each of the 21 fuzz targets for 24 CPU-hours per native target.
- [ ] Seven-day sustained operation and all recovery, deletion, key-lifecycle and hardening drills.
- [ ] Reproducible binaries, SBOM and complete requirement evidence for the frozen candidate.
- [ ] Signed release decision and independent verification of the exact artifact hashes.

Source, lockfile, configuration, binary or qualification-policy changes create
a new candidate. Full release qualification follows the reviewed merge and
source freeze. Production deployment is a separate release-owner action.
