# Adversarial implementation review on 2026-09-04

The second implementation review found defects in TLS policy enforcement,
OPAQUE identity reporting, host file reads, terminal proof binding, coordinator
restart, and edge delivery and projection. The changes described here are in
the working tree. The final Stage 08 implementation gate passed all 97 commands.
No new exact-source checkpoint has been recorded for these uncommitted changes.

This was an internal code review with adversarial regression tests. The
reviewers participated in implementation and shared the working tree. No
external cryptographic or protocol certification was performed. `S08-039`
remains open, and this record does not qualify encrypted-v1 as externally
reviewed.

The earlier fixes for incomplete certificate vote sets, historical roster and
policy restoration, ReInit log restoration, and invalid durable vote slots
are described in the [implementation review follow-up](README.md#implementation-review-follow-up).
This record covers the subsequent pass.

## Confirmed defects and changes

### Outbound federation ignored required hybrid key exchange

The daemon built its federation client with the default hybrid-preferred
provider even when `tls.group_policy` required hybrid exchange. An edge could
complete mutual TLS with a coordinator offering only X25519 under that
configuration. The federation builder now accepts the configured group policy,
and the daemon passes the policy into its outbound connection plan.

The regression
`federation_client_enforces_required_hybrid_and_allows_preferred_fallback`
performs mutual TLS with both classical-only and hybrid-only peers. Required
hybrid mode rejects the classical peer. Preferred mode permits the configured
fallback, and both modes connect to the hybrid peer. The required/classical
case failed before the fix.

Files include `crates/agenc-ircd-runtime/src/tls/config.rs`, `tls/mod.rs`,
`daemon.rs`, and `tests/tls_federation_policy.rs` in that crate.

### OPAQUE reported the dummy identity as the server identity

`opaque_server_public_key` extracted a fixed slice from the serialized setup.
That slice contained the fake record's dummy public key, rather than the
server's AKE public key. Public-identity reuse checks therefore compared the
wrong identity. The helper now deserializes the setup and asks opaque-ke for
the public key of its server key pair. The vendored library was not changed.

`reported_opaque_server_identity_matches_registration_response` compares the
reported identity with the public key returned in a real registration
response. The test failed before the fix. The daemon test
`stopped_runtime_check_rejects_cross_purpose_public_identity_reuse` now derives
the expected identity independently through opaque-ke, so the check no longer
uses the same helper to construct its expected result.

Files include `crates/agenc-ircd-auth/src/opaque.rs`, its
`tests/stage_four.rs`, and `crates/agenc-ircd/tests/stage_six_daemon.rs`.

The source change invalidated the previous constant-time review hash. A
follow-up read checked the helper, its daemon caller, and the pinned library's
public-key accessors and serialization. Login start and finish work, worker
callers, and secret comparisons were unchanged. The
[constant-time review record](../stage-four-constant-time-review.toml) now
binds that review to the corrected source hash and retains its evidence-only
status and timing-analysis limits.

### A FIFO could block configuration or secret loading

The host readers opened a path before confirming that the opened descriptor
referred to a regular file. A named pipe could block the open indefinitely,
including when a checked secret path was replaced between metadata inspection
and open. A production `check-config` invocation with a FIFO was observed to
hang until the test process terminated it.

The protected-file reader and both secret-file open paths now include
`O_NONBLOCK`. Existing descriptor checks still reject non-regular files.
`protected_read_and_secret_replacement_reject_fifos_without_a_writer` covers
both a direct protected FIFO and replacement of a regular secret with a FIFO.
The test bounds its wait and releases a regressed blocking reader before
joining the worker.

Files include `crates/agenc-ircd-config/src/paths.rs`, `src/secrets.rs`, and
`tests/fifo_rejection.rs`.

### A finalization could substitute authorization fields outside the voted core

The finalization handler counted votes over the core's finalization ID while
using the accompanying authorization's fields to change the current policy
and bootstrap lifecycle. It did not recompute the authorization ID and compare
it with the core. A request could retain the valid votes and substitute those
state-changing authorization fields.

The handler now recomputes the authorization TBS ID and canonical ACK-TBS set
digest. Both must match the voted core. Candidate finalization and abort also
require the exact retained receipt and the expected profile, network, and
epoch. ReInit terminals require the retained attempt receipt and the exact
attempt wire object. ReInit activation checks the ACK-TBS digest and repeated
attempt and result fields before counting votes or changing state.

`finalization_rejects_authorization_substitution_without_new_votes` submits a
changed authorization with unchanged votes, checks rejection, and then submits
the valid request successfully. The existing
`a_reinit_attempt_is_staged_acknowledged_aborted_and_finally_activated` test
exercises the positive ReInit terminal path through restarts.

These checks bind public fields to the vote and receipt. The semantic hashes
exclude controller approval signatures and MLS ACK signatures. The coordinator
does not thereby validate controller authority, MLS processing, ACK signature
validity, copath coverage, or a common staged MLS result. Those checks remain
endpoint obligations under Sections 9.3, 12.4, and 13.8 of the companion
specification.

Files include
`crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/terminal_proof.rs`,
`ops/sequence.rs`, and `tests/sequence.rs`.

### Restart reset the Commit validation-time floor

The live coordinator remembered the most recently accepted candidate's
validation time. Restart initialized that field to zero, allowing an older
timestamp to pass the same guard after reload. Startup now visits retained
candidate receipts in route-sequence order, loads each referenced Commit, and
verifies its route, prior state, epoch, and timestamp ordering. Missing or
inconsistent Commit evidence prevents that route from being reconstructed.
The existing persistent format contains the required evidence.

The new restart tests are

- `reload_preserves_validation_time_of_an_open_candidate`
- `reload_preserves_validation_time_after_an_aborted_candidate`
- `reload_preserves_validation_time_after_a_finalized_candidate`
- `reload_refuses_a_route_whose_candidate_commit_is_missing`

The timestamp tests reject time 19 after accepting time 20 and preserve the
existing behavior for time 20. They cover open, aborted, and finalized
candidates. Files include
`crates/agenc-ircd-runtime/src/e2ee/coordinator/startup.rs` and
`tests/restart.rs`, declared as a child of `tests/sequence.rs`.

### Successor routes could not consume their activation anchor

ReInit activation created the successor log at epoch one, but route reservation
and BIND rejected the occupied predecessor route. Ordinary BIND also created a
genesis log. A valid activation therefore could not complete the specified
successor route transition.

The repair follows companion Sections 9.4, 11.5, and 13.8.

The coordinator now allows a current principal to reserve the occupied route
for a successor. BIND consumes that reservation only after checking the retained
activation and attempt against the exact target binding hash, supplied context
digest, group parameters, and initial member plan. The replacement must preserve
the concrete route, semantic lock, and incarnation, name the previous binding,
and increment its generation once. Direct routes preserve the verified
predecessor nonce. Channel transitions still require the current base owner and
the exact account roster. The successor keeps the activation ID as its epoch-one
anchor and starts without a pending bootstrap commit.

Reload rechecks the retained activation before selecting the successor's route
indexes and restoring its context digest. It discards successor bindings whose
predecessor or activation evidence is missing. A separate route-table defect
allowed a predecessor loaded later to replace a newer route's indexes. The
restore guard now preserves the higher generation for the same concrete route,
lock, and incarnation. The regression for reverse read-back order failed before
that change.

The coordinator sends the predecessor's hidden-route event, retires its current
entitlements, and excludes historical routes from later projections and state
cuts. The edge route-state wire object does not carry a binding generation;
edge correctness relies on that ordered projection lifecycle.

The added tests are

- `successor_bind_requires_activation_and_preserves_epoch_one_after_restart`
- `successor_bind_rejects_changed_target_and_keeps_the_reservation`
- `successor_bind_rejects_a_different_reservation_owner`
- `successor_reservation_can_be_renewed_after_activation_and_restart`
- `successor_reload_rejects_missing_activation_evidence`
- `successor_channel_plan_requires_current_owner_and_exact_account_roster`
- `direct_successor_reservations_require_the_owner_nonce_and_exact_lineage`
- `expired_successor_reservations_cannot_replace_the_route`
- `restoring_predecessor_after_successor_keeps_the_latest_projection`

The coordinator tests execute channel successor reservation, activation, BIND,
and candidate admission, with in-memory durable row replay for restart. The
channel-authority test uses the real base domain planner. Direct-route coverage
checks domain reservation and replacement rules. This focused pass did not run
a multi-process successor BIND or an endpoint MLS successor exchange.

Files include domain `e2ee/route_table.rs`, `route_table/successor.rs`, and
`projection.rs`; runtime coordinator `ops/route.rs`, `ops/route_successor.rs`,
`execute.rs`, `sync.rs`, and `startup.rs`; and their successor tests.

### Barrier delivery skipped the edge record-chain witness

Ordinary companion events passed through the edge's sequencer witness, but
barrier parts bypassed that check. A skipped or conflicting semantic record
could therefore reach barrier application. Barrier preparation now invokes
the same witness check, and a witness failure records evidence through the
companion failure path before the link closes.

`a_barrier_rejects_a_skipped_sequencer_record` failed before the fix and now
checks rejection. The change affects companion edge event handling and
`registration::apply_ready_barrier`.

### Delivery cursors did not follow durable application

Barrier writes omitted the final companion delivery cursor. Ordinary
companion events and snapshots had a different defect: they advanced the live
resume cursor or generation before durable admission. A refused batch could
leave a reconnect advertising state that storage had never accepted.

The edge now prepares cursor rows from local copies. Barrier application
includes the final companion cursor, and live cursor or generation changes
occur after the durable batch is applied. The regressions are

- `a_barrier_persists_the_final_companion_cursor_without_exposing_it_early`
- `refused_event_storage_keeps_the_previous_resume_cursor`
- `refused_snapshot_storage_keeps_the_previous_delivery_generation`

Each test failed before its corresponding fix. Files include
`crates/agenc-ircd-runtime/src/e2ee/edge/events.rs` and `sync.rs`.

### Removed routes remained in the edge projection

A hidden-route event removed the route's stored row and conversation view but
left its channel or direct-route indexes behind. Snapshot completion also
inserted the received routes without removing routes omitted by the new
snapshot. Both paths could retain a route after the edge's projected
entitlement had ended.

The route table now removes a projection and releases only indexes that still
belong to that projection. Snapshot completion removes omitted route entries
and rows. `a_hidden_route_is_removed_from_every_projection_index` and
`an_empty_snapshot_removes_every_prior_route` failed before the fixes.
`removing_a_projection_releases_only_its_own_target_and_lock_indexes` checks
that removing an old projection preserves indexes already assigned to its
successor.

Files include `crates/agenc-ircd-domain/src/e2ee/route_table.rs` and runtime
`e2ee/edge/events.rs` and `sync.rs`.

### Client output could precede durable event admission

Base federation event rendering sent client output immediately, including
output associated with a cross-profile barrier. Storage rejection or
cancellation could leave a client observing a mutation the edge had not
committed. Rendering now prepares bounded fanout entries. StateCore reserves
and applies ordinary output, and the combined base and companion barrier
output, with their durable batch.

`an_event_waits_for_storage_and_cancellation_discards_its_output` and
`rejected_durable_admission_does_not_deliver_event_output` failed before the
fix. Files include runtime `federation/edge/render.rs`, `events.rs`,
`barrier.rs`, `mod.rs`, and `registration.rs`.

Base completion events also published their completion marker before storage,
allowing a later result to finish a client request during a pending or refused
batch. Completion correlations are now checked without publishing the marker;
the commit callback matches the result or retains a marker bound to that pending
request. Disconnect removes the marker. A `RequestCompleted` barrier part was
previously ignored at commit, so a durable receipt could leave its request
pending indefinitely; the barrier now runs the same completion callback after
its receipt commits.

Matching IDs also failed to enforce the repeated state generation. Completion
header and arm generations now agree with the result generation in every
arrival order; the pending request retains that generation after event commit.
Negative tests cover changed replay keys, request-object IDs, and generations.
Raw malformed result-kind/completion-ID pairs are rejected by the existing
federation wire decoder before pending state changes.

`completion_results_before_during_and_after_storage_wait_for_commit` and
`refused_completion_storage_cannot_release_a_later_result` reproduced premature
completion markers before the fix. The real-storage regression
`a_result_first_barrier_retires_its_request_only_after_the_durable_receipt`
reproduced the missing barrier completion. All now pass, and
`completion_markers_live_only_as_long_as_their_pending_request` checks cleanup
when a client leaves before or after commit.
`completion_generations_must_match_in_every_result_arrival_order` and
`completion_header_and_arm_generations_must_agree_before_staging` cover the
generation checks.

The edge regressions are in
`crates/agenc-ircd-runtime/src/e2ee/edge/tests/projection.rs` and
`src/federation/edge/tests/durability.rs`. The projection-index regression is
in `crates/agenc-ircd-domain/src/e2ee/tests/route_table.rs`.

### Replay expiry erased the coordinator's operation-sequence floor

Coordinator startup inferred the next operation sequence from expiring replay
rows. Generation-zero declarations could skip that inference altogether.
Each completed request now commits a durable sequence floor atomically with
its result. One row per home server, incarnation, and origin records the latest
generation and next sequence without a replay expiry. Reload rejects generation
rollback; admission rejects fresh requests after sequence exhaustion. Tests
remove replay rows before reload and verify that the committed floor still
controls admission.

The existing table-23 replay kind uses a distinct key prefix and version-2 body
for floors; version-1 replay rows retain their existing encoding. This is an
upgrade boundary. Startup refuses a generation's `EORIGIN ADD` or `UPDATE` when
retained legacy replay history exists without a matching floor. The regression
retains an earlier security mutation after a later ordinary result expires,
checks refusal, and accepts a fresh authenticated generation. Without this
guard, that partial history understated the sequence and admitted an old
operation again.

If all legacy history has expired, storage cannot distinguish a previously used
generation from one that never committed a request. Startup cannot reconstruct
or detect that deleted history. Affected clients must reconnect into fresh
origins or establish a new authenticated origin generation during upgrade, as
described in the [operator guide](../../docs/operator-guide.md#upgrade-encrypted-federation-state).

### Local retries lost replies or collided across commands

An already completed object could receive no reply because the assembler
recognized its object ID and silently stopped processing it. Its retry scope
also omitted some command and recipient parameters. The assembler now retains
the full assembly tuple. Local commands include their opcode and canonical
parameters in that scope, while conversation identity still controls route
quotas.

The edge caches completed replies for 30 minutes under the connection, attached
session, object ID, and full command scope. It preserves fragment and batch
tags and replaces the request label when replaying a reply. Admission reserves
reply capacity before accepting a submission. The limits are 1,024 replies,
16 MiB per encoded reply, and 128 MiB in total. The assembler separately caps
recent submissions at 4,096 tuples and reserves a slot for each open submission.
Expiry releases capacity without evicting live retry entries.

Completion coverage, request retirement, and retry-cache publication now occur
after the durable event commits. A result arriving while that write is pending
is released at commit. Storage refusal leaves the request pending. Unit tests
cover both arrival orders, refused storage, scope isolation, expiry, and
capacity. The daemon lifecycle test repeats a finalization and an application
submission under new labels and checks their earlier results.

### Federation responses accumulated without a request-level bound

Individual response objects were bounded, but the edge retained arbitrary
response indexes and aggregate bytes for a pending request. It now accepts at
most 32 response objects and 4 MiB of decoded object bytes per request. Result
descriptors must be contiguous and match each response's index, kind, size, and
object hash. Responses received before their result remain bounded and are
reconciled when the result arrives. Exact duplicates consume no additional
quota; conflicting responses or result objects close the link. Six regression
tests cover size, count, ordering, descriptor mismatch, and conflict handling,
including the live frame-handler failure path.

### Durable barrier parts could not survive daemon restart

Barrier application deleted immutable part rows immediately, and daemon edge
startup did not reconstruct pending barriers. Startup now loads authenticated
sealed peer and projection state, both delivery cursors, barrier heads, parts,
receipts, and referenced payload objects before starting the storage bridge.
It validates their identity, sequence, and part metadata before resuming work.
A restored complete barrier waits for both profiles to become active.

Applied parts remain available through receipt retention. Cleanup requires
both delivery cursors to cover the receipt, a trusted wall clock, and no pending
local requests. Each cleanup batch is bounded to 1,000 rows including its peer
row and 16 MiB. The durable head survives partial cleanup so restart can finish
it. A changed coordinator incarnation is durably fenced before old pending
parts can be discarded. An interrupted snapshot remains snapshot-required
across restart.

Crash-image regressions commit production storage transactions and reload their
sealed state. They cover collecting and applied barriers, retained payloads,
receipt replay, partial cleanup, incarnation fencing, and invalid restore
evidence. These tests do not inject a physical disk or fsync failure.

Ordinary semantic events also advanced the live record-chain witness without
updating its stored route row. Resume could therefore advertise a delivery
cursor newer than the reconstructed witness and reject the next valid record.
Each event now writes the latest witness head with its cursor; a barrier writes
one final head per affected conversation. The exact coordinator route-state
object remains unchanged. Startup checks that authenticated head metadata is
neither older than nor forked from that cut. A sealed-reload regression accepts
the next terminal after restoring a committed candidate beyond the original cut.

The new `DeliveryRow::WitnessedCursor` arm uses tag 4 under the existing
`delivery/v1/` key. Legacy cursor arm 1 keeps its original encoding. The new arm
distinguishes checkpoints that include witness updates. Older or missing
checkpoints force fresh snapshots in both profiles. A legacy collecting barrier
stops startup with its state intact because no durable identity fence permits
discarding it. Applied legacy receipts must still contain their required
retention evidence. The [operator guide](../../docs/operator-guide.md#upgrade-encrypted-federation-state)
records stopped recovery and backward-compatibility limits.

### Rejected writes left speculative projections in memory

Event and snapshot preparation changed route indexes, record-chain witness
heads, and cached route objects before storage admission. Rejecting the batch
kept those speculative changes in memory. A repeated valid event could then
look like a skipped or forked record. The base profile could likewise retain
uncommitted replica and nickname changes while resuming from its old cursor.

Both profiles now retain the previous projection until their transaction
commits. Preparation errors, refused admission, and rejected batches restore
it. Companion rollback also restores pending echo lines and drops prepared
completion output while preserving evidence of a real witness violation.
Successful commits keep the new projection. A snapshot's committed delivery
generation survives a link loss while its READY write is pending.

Regressions exercise ordinary events, multi-part barrier preparation, the
registration barrier-admission path, empty snapshot replacement, batch
rejection, and retry. Four companion projection regressions and the pending
READY link-loss regression failed before their repairs. The base projection
regressions were added after the repair and check both rejection and commit.

The companion rollback and READY tests are

- `refused_event_admission_restores_the_witness_head`
- `rejected_event_batch_restores_the_witness_head`
- `refused_snapshot_admission_restores_the_removed_route`
- `failed_barrier_preparation_restores_prior_parts_and_keeps_violation_evidence`
- `snapshot_commit_after_link_loss_keeps_the_committed_delivery_generation`
- `refused_barrier_apply_restores_projection_and_retries_the_retained_parts`

The registration-path test refuses storage admission for a complete retained
barrier, reuses the same companion instance for the retry, and commits the
successful retry through storage before loading fresh edge instances. These
tests use admission refusal and explicit batch callbacks; they do not inject
power loss or an fsync failure.

## Reviewed scope and limits

The auth and host review traced account creation and login START/FINISH
lineage, expiry and grant binding, selected registered account operations,
OPAQUE setup identity, HPKE boundaries, operator admission, admin signatures
and counters, TLS builders and peer verifiers, protected file reads, secret
identity checks, and selected reload fingerprints. The review inspected the
relevant handlers in `agenc-ircd-auth`, `agenc-ircd-config`, and runtime
registration, account service, administration, TLS, and daemon composition.
It did not prove every branch of those crates or audit the cryptographic
libraries' implementations.

The coordinator review traced candidate admission, finalization and abort,
ReInit attempts and terminals, startup reconstruction, route reservation and
binding, and successor log and lifecycle anchors. A separate reviewer read
the new terminal proof helpers and their callers against companion Sections
2.2, 12.4, and 13.8. That read found no further defect in the added hash and
receipt checks that changed server state without the corresponding council
votes. The review does not establish endpoint MLS correctness.

The federation review inspected runtime
`federation/edge/{events,barrier,sync,mod,render}.rs`,
`e2ee/edge/{events,sync,mod,result}.rs`, `e2ee/barrier.rs`, registration's
barrier application and drive hooks, StateCore durable staging and fanout,
federation inbox hold and commit paths, and daemon edge-role attachment. The
review compared these paths with base Section 20.8 and companion Section
12.5. Follow-up review included barrier startup, receipt retention, incarnation
fencing, and companion origin replay floors. It did not exhaustively review
all persistence code. StateCore's inbox hold during a pending or
in-flight batch resolved an initial concern about base event sequencing; that
concern is not recorded as a runtime defect.

Durability regressions used quiescing to refuse admission, cancellation before
submission, and sealed storage crash images. They did not inject disk or fsync
failures. The aggregate gate results below record broader validation separately.

GitNexus query and context results supported call tracing. Impact analysis
preceded symbol changes, and high or critical call-graph results were reported
before edits. New files were absent from the index and therefore had unknown
graph risk; their callers were reviewed in source. A missing graph result was
not treated as proof of safety. Existing uncommitted changes were preserved.

After rebuilding the index, `detect_changes` for both the working tree and
comparison with `main` reported 325 changed symbols in 62 tracked files and
36 affected execution flows, with critical aggregate risk. The reported flows
covered protected file reads, origin replay, route reservation and binding,
terminal submissions, link establishment, and commit callbacks. These are
the intended changed paths. The diff-based count excludes untracked files;
the added modules and tests were reviewed separately and included in the
workspace checks.

The refreshed index included the PDG layers. It skipped control-dependence
extraction for three existing functions in `fuzz/fuzz_targets/parse_render.rs`;
their control-flow and variable-definition graphs remained available. The
taint query returned no persisted findings. That analysis does not model
closure, property, or implicit flows, so the result does not establish their
safety. Source review and regression tests supplied the evidence for the
state and commit-order defects described here.

## Known implementation gaps

- An edge forwards account creation and login, but registered credential
  replacement returns `UNAVAILABLE`. The registered account-service forwarding
  path and its authentication lifecycle remain incomplete. Adding a fresh-auth
  deadline alone would not implement that path.
- Startup does not reconstruct the context digest supplied by a genesis BIND.
  The coordinator does not use that stored field in an acceptance check, and
  this review did not demonstrate a genesis context-digest restart bypass.
  Successor BIND validates its context digest against the retained activation
  attempt and reconstructs it from that attempt on reload.

## Validation record

`bash scripts/check-stage-eight.sh` completed successfully on 2026-09-04 after
the combined source changes and review manifests were finalized. All 97
commands passed, including every inherited Stage 00 through 07 command.
The results below come from that final aggregate run.

| Command | Observed result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo check --workspace --all-targets --all-features --locked` | Passed; separate checks also passed for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | Passed |
| `cargo test --workspace --all-features --locked` | 1,770 passed, 0 failed, 2 ignored across 112 result groups |
| `cargo test --workspace --doc --all-features --locked` | Passed |
| `cargo deny check` and `cargo audit --deny warnings` | Passed |
| `cargo llvm-cov --workspace --all-features --branch --locked --json --output-path target/stage-zero-coverage.json` followed by `python3 scripts/check-coverage.py check target/stage-zero-coverage.json conformance/critical-coverage.toml` | 76.05% branch coverage, 90.70% line coverage; all six declared critical regions at 100% |
| `bash scripts/run-stage-eight-transcripts.sh` | Passed, including the two-library MLS check and both three-process encrypted daemon tests |
| `bash scripts/run-stage-eight-fuzz.sh` | Five targets passed 10,000 runs each |
| `bash scripts/run-stage-eight-load.sh` | Release-mode maximum-object reassembly, bounded flood, and padding checks passed |

The two ignored tests generate reviewed golden vectors manually; no ordinary
workspace test was skipped by a filter. Coverage satisfies the current 75%
branch and 90% line floors. The six declared regions do not represent every
security-critical branch. Stage 10's broader release-coverage qualification
remains outstanding.

The reviewed working tree is based on commit
`a2b27a30f3b3908e757c45163cbacc68ea5da4c6`. The production Rust inventory used
by the coverage checker contains 392 files with SHA-256
`ad32f4bf9e85e1d7c531aa04bebc5c9dc130da963d90d0f33f3cc72132b9ca80`.
The final aggregate log is retained locally at
`/tmp/agenc-ircd-adversarial-stage-eight-final.log`; coverage and load reports
are under `target/`. These are working-tree validation outputs, not a recorded
exact-source gate artifact. Documentation was finalized after the run without
further Rust changes.

The six pinned normative artifacts and all twelve RFC files remain
byte-identical. Local documentation links and fragments passed a separate
check, and `git diff --check` passed. A new checkpoint requires a committed
source revision and its recorded gate artifact. This review does not close
`S08-039`.
