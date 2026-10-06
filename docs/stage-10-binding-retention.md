# Retention of what a live encrypted conversation reads (D-39)

This record covers the server topic `sdk/b-binding-retention` of the SDK
server program (decision D-39, 2026-10-06, outside master #35): the
coordinator retains every object a live encrypted conversation's restart
reads for as long as the conversation's route exists. The work
lands in small commits: the first makes a route row hold its
conversation's binding package, the second takes a restart's
validation-time floor from the Commits the candidate slots name, the third
makes a route row hold the rosters its conversation's statements name, and
the fourth restores stores written before these rules (G-08). No
specification, profile hash, registry entry, named limit, reply code, wire
object, table, key, row kind, field or storage generation changed.

## A route row holds its binding package (first commit)

The companion text this rule implements:

- Section 11.5: "Successful BIND is the atomic activation barrier: the server
  durably stores the binding", and "A binding survives server restart until
  authorized close or destruction of that exact channel instance." A restart
  restores each route from its route row and the binding package that
  row's binding names.
- Section 11.7: "Successful `EGROUP QUERY CHANNEL` or `QUERY DIRECT` instead
  uses one object batch with the `BOUND` metadata child and the exact current
  `BINDING` object". A live route answers with its package.
- Section 13.8 installs a ReInit successor "whose current `BINDING` object
  (Section 11.7) is the `ArcConversationBindingPackage` of that binding",
  which takes traffic "also after a coordinator restart, which restores the
  installed successor from durable state".
- Section 15: "the root, roster, binding, and policy ancestry needed to verify
  a live semantic lineage are security proofs, not ordinary message history.
  The responsible servers retain those exact objects for
  `SECURITY_PROOF_RETENTION`", and "generation-zero binding and root-lock
  objects are marked on acceptance as well". `SECURITY_PROOF_RETENTION` is
  "live semantic lineage plus `WELCOME_RETENTION` after final close"
  (Section 16).

The rule, in `crates/agenc-relay-runtime/src/e2ee/coordinator/owners.rs`:

- A route row (`route/v1/<conversation>`) owns its route state object, as
  before, and also holds the binding package of the binding it names, as a
  security proof charged to the conversation. The batch that binds a route
  (`EGROUP BIND`) and the batch that installs a ReInit successor at its
  activation stage that package; the row acquires the staged package whose
  binding identifier, recomputed from the package, is the row's
  `binding_id` (`owned_by_in_batch`, `route_owned`, `staged_binding_id`). A
  staged object that does not decode as a package, or the package of
  another binding, is acquired by no row.
- A route's binding never changes in place (a ReInit successor is a new
  route with its own row), so every later rewrite of the row keeps the
  package it holds while releasing the route state it replaces
  (`kept_on_rewrite`). Only the deletion of the row releases the package to
  object expiry, which collects it once the security-proof window has
  passed since that deletion.
- Startup derives the same holding: each route row read is recorded, and
  once the routes are restored its row holds the package the route was
  restored from (`Rebuild::derive_held`), so the restart rebuilds the
  ownership live batches derived (`owner_reconstruction` is clean for a
  store this coordinator wrote, apart from roster objects that other rows
  made resident).
- A migrated ReInit predecessor keeps its route row, so it keeps its
  generation-zero package beside the successor's package: the binding
  ancestry of the live lineage stays retained.
- A package that other rows also name, such as the bound package delivered
  to a device's mailbox with `EKEY DELIVER BINDING`, stays a security proof
  of the conversation after those rows retire.

This extends the owner matrix of
[the object ownership record](stage-10-object-owners.md), which is left as
written: the route row owns its route state object and the binding package
of its binding.

## A restart needs no Commit that no slot names (second commit)

A restart restores each route's validation-time floor from its accepted
candidates (`restore_validation_time` in
`crates/agenc-relay-runtime/src/e2ee/coordinator/startup.rs`), re-verifying
each candidate's Commit in route order. A candidate's Commit is named by its
epoch's candidate slot row (`candidate/v1/<conversation><prior epoch>`),
which a later candidate of the same epoch, after an abort, takes over; the
replaced Commit is then ordinary material that no durable row names, which
companion Sections 15 and 16 let object expiry collect ("the ordinary
`SEQUENCER_RECORD_RETENTION` applies only to records not referenced by a live
proof chain"). Every accepted candidate's validation time is at least the
previous one's, so the replacing candidate's Commit carries a floor at least
as late as the replaced one's.

- A candidate whose Commit the store no longer holds adds nothing to the
  floor when its epoch's slot row names another Commit.
- A Commit its slot row still names is retained by that row, so its absence
  is a storage fault and still refuses the route, as does a candidate
  without a slot row.
- The restore still reads every candidate's receipt, which its record row
  retains, and checks its network, conversation and route sequence.

## A route row holds the rosters its conversation's statements name (third commit)

A roster stops being its account's current one at the next publication,
but statements of live conversations keep naming it or depending on it:

- Section 9.4: a binding names each principal's roster head
  (`ArcBindingPrincipal`), which a ReInit successor's binding names too, and
  Section 9.5's join roster chain "begins at each binding-named head, and has
  no unexplained gap", covering "every signed roster needed to validate
  binding and policy approvers and tree credentials".
- Section 13.7.3: a leaf-membership proof names the roster its credential
  was authorized under, and "the proof's device must be active in the
  retained roster named by `roster_id`".
- Section 9.3: "every approval verifies against the retained roster
  certificate it names"; a restart re-verifies each retained policy, leaf
  proof and counted vote against the retained rosters of its principals.
- Section 15 makes "the root, roster, binding, and policy ancestry needed to
  verify a live semantic lineage" security proofs that "the responsible
  servers retain", and "A server never frees space by deleting a proof still
  needed to validate a live lineage." It charges them too: "The proof set
  counts against `MAX_STORED_BYTES_PER_CONVERSATION`."

So a replaced roster stays retained while a live conversation's statement
names it, charged to that conversation. Section 9.5's roster chain travels
in the Welcome that members build from their own state; the server retains
the rosters that the statements it stores name, which are the rosters a
restart reads. A device's first leaf proof that names a replaced roster no
statement names is checked against that roster only while it is still
resident (see the limitations). The rule, in `owners.rs` and
`roster_holds.rs`:

- A route row holds, as security proofs charged to its conversation, the
  roster each principal entry of its binding names as that principal's
  head, the roster each stored leaf-membership proof of the conversation
  names, and, for each root a retained policy names in its finality
  principals or approvals, the earliest retained roster of that root, by
  roster generation, that verifies under the root and holds every
  certificate the policy names for it (`roster_holds::of_binding`,
  `of_policy`). A counted vote carries the certificate its council's policy
  names for the voting device, so the roster held for that policy verifies
  the vote too.
- The batch that stores the statement acquires the holding: the batch that
  binds a route or installs a ReInit successor for its roster heads, a
  membership row's batch for its proof, and a policy row's batch for its
  policy (`owners::hold_named_rosters`, `roster_holds::of_batch`). A
  statement of a conversation that has no route row once its batch commits
  holds nothing. Every later rewrite of the route row keeps the rosters
  (`kept_on_rewrite`), also a roster that a leaf proof named once a later
  proof of the same leaf and device replaces that proof; only the row's
  deletion releases them.
- Startup derives the same holdings: from the binding package, the stored
  proofs and the retained policies of each restored route
  (`Rebuild::derive_held`, `roster_holds::of_conversation`), and from each
  roster's stored account, whose route-row holders it keeps when the route
  was read and restored and the account's kind and size are those of the
  resident roster object (`Rebuild::recorded_route_holders`). A roster that
  only a replaced proof named therefore stays held, and charged to the
  conversation, across a restart, and a store whose owner rows record no
  such holder, such as one written before this rule, gets each holding
  derived from the statement that names the roster.
- The earliest roster that verifies a policy does not change once it is
  held: a certificate first appears at the roster generation its enrollment
  targeted, no roster below that generation verifies with it
  (`identity::check_issuance`), and a held roster is not collected. So the
  batch that stores a policy and every restart choose the same roster. A
  second roster index, by root and generation
  (`roster_snapshots::Generations`), serves that choice, and object expiry
  removes a collected roster from both indexes.
- An account's roster row owns only its current roster. A replaced roster
  that no route row holds retires when the account replaces it, and object
  expiry collects it once the security-proof window has passed.
- One owner row references at most `MAX_RECORD_REFERENCES` (4,096) rows. A
  roster that many rows already hold takes no further holder: the batch
  that names it is admitted, the roster stays retained by those rows, and
  the further conversations are not charged for it. A restart keeps the
  same ceiling and takes the holders the stored account records first
  (`Rebuild::hold_roster`).

The `roster_snapshots` and `roster_holds` module documentation states the
rule.

## Tests

`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/retention.rs`
runs object expiry past every retention window, applies each pass's batch
to the harness store as the coordinator commits it, and restarts from that
store:

| Test | What it pins |
| --- | --- |
| `a_bound_channel_keeps_its_binding_package_and_restarts_after_expiry` | A bound channel after its bootstrap activation: the route row alone holds the package as a security proof; expiry collects superseded route states but not the package; `EGROUP QUERY CHANNEL` answers with it before and after a restart; the restart's ownership reconstruction is clean. |
| `a_bound_channel_restores_from_sealed_storage_after_expiry` | The same store sealed into a storage fixture and read back through the storage reads a restart uses restores, with a clean reconstruction. |
| `a_deleted_route_row_releases_its_binding_package_to_expiry` | While the row exists no window releases the package or the route state; the batch that deletes the row retires both at its trusted second, and expiry collects them one second before the security-proof window has passed since then not, and at the window yes. |
| `a_bound_package_delivered_to_a_mailbox_stays_held_by_its_route` | Delivering and acknowledging the bound package through a device mailbox leaves it a security proof of the conversation, held by the route row, which expiry does not collect. |
| `a_route_row_acquires_only_the_package_of_its_binding_that_its_batch_stages` | The ledger rule on synthetic rows: a row naming another binding, or a staged binding object that does not decode, acquires nothing; a binding batch's row acquires its package and its route state; a rewrite keeps the package and releases only the replaced route state; the row's deletion retires the package. |

`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/reinit/successor/retention.rs`:

| Test | What it pins |
| --- | --- |
| `an_installed_successor_restarts_after_expiry_collects_every_unowned_object` | After a ReInit activation the successor's and the predecessor's route rows hold their packages; after expiry the restart restores the successor open, the predecessor migrated and the channel route on the successor, with a clean reconstruction. |
| `an_installed_successor_restores_from_sealed_storage_after_expiry` | The same through sealed storage. |

`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/retention/replaced_candidates.rs`:

| Test | What it pins |
| --- | --- |
| `a_route_restarts_after_the_commit_of_a_replaced_candidate_expires` | An aborted candidate replaced by a later candidate of the same epoch: expiry collects the replaced Commit and keeps the current one; the restart restores the route with the floor of the current Commit and its open candidate. |
| `a_restart_still_refuses_a_route_whose_named_commit_is_missing` | A store without the Commit its slot row names refuses startup. |

`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/retention/rosters.rs`,
its `rosters/ceiling.rs` and `rosters/restart.rs`, and
`.../tests/sequence/leaf_membership/expiry.rs`:

| Test | What it pins |
| --- | --- |
| `the_roster_a_binding_names_stays_held_after_the_account_replaces_it` | The roster a binding names is held by the route row, charged to the conversation, also across the row's rewrite at the bootstrap activation; after a newer roster and expiry past every window the route row alone holds it, also after a restart with a clean reconstruction. |
| `a_policy_restores_after_the_roster_its_council_was_verified_under_expires` | A published policy whose council device the account's next roster drops restores after expiry and a restart, the replaced roster held by the route row. |
| `a_replaced_roster_no_live_conversation_names_is_collected` | Rosters the account replaced that no statement names are collected, the resident object bytes fall and the roster index forgets them, while the roster the binding names and the current roster stay; a restart reconstructs clean without them. |
| `an_account_without_a_conversation_keeps_only_its_current_roster` | An account that publishes five rosters and names none in a conversation keeps only the current one after expiry, also after a restart. |
| `a_policy_holds_the_earliest_roster_that_verifies_it` | A policy seating a device the second roster enrolled holds that roster, not a newer one with the same devices; after a later roster revokes the device, expiry keeps the held roster and collects the newer one, and a restart restores all three policies with a clean reconstruction. |
| `a_policy_stored_after_expiry_holds_the_earliest_resident_roster` | Once expiry has collected the roster that enrolled a device, a policy seating it holds the earliest roster still retained that verifies it, which the restart chooses too. |
| `a_proof_holds_the_roster_it_names` | A proof naming the roster that enrolled its device is held by the route row after a newer roster and expiry, and both proofs restore after a restart. |
| `a_first_proof_naming_a_collected_roster_is_refused` | A device enrolled by a roster that the account replaced before any statement named it: once object expiry has collected that roster, the device's first proof naming it is refused with `E2EE_BINDING_AUTH_INVALID`; without expiry the same proof is admitted. |
| `a_deleted_route_row_releases_its_rosters_to_expiry` | The batch that deletes a route row retires the replaced roster it alone held at its trusted second; expiry collects it at the window and not a second before. |
| `a_policy_holds_no_roster_that_does_not_verify` | In a store whose head roster is replaced by a copy that does not verify, the restart holds the current roster for the policies, the earliest that verifies them, and both policies restore. |
| `a_statement_of_a_conversation_without_a_route_holds_nothing` | A proof stored for a conversation without a route, and one for a conversation whose route row the same batch deletes, give the roster no holder. |
| `a_batch_naming_a_roster_at_the_reference_ceiling_adds_no_holder` | A batch binding a route whose binding names a roster that 4,096 rows already hold is admitted; the roster takes no further holder, and the route row still acquires its package. |
| `a_restart_holds_a_roster_for_at_most_the_reference_ceiling_of_rows` | 4,097 restored routes name one roster: the restart keeps 4,096 holders, those the stored account records first, then the others in key order. |
| `a_roster_a_replaced_proof_named_stays_held_across_restarts` | Leaf 0's device replaces its proof twice, each time naming the account's newer roster: the route row keeps holding the roster that only the replaced proof named, charged to the conversation, through expiry, a restart with a clean reconstruction and the same conversation charge, expiry again and a second restart. |
| `a_restart_keeps_only_restored_route_holders_of_a_resident_roster` | The restart keeps a roster's recorded route-row holder only for a route that was read and restored, charged to its conversation, and keeps none for an account whose size is not the resident roster's or whose object is not a roster. |
| `a_restart_without_owner_rows_derives_each_holding_from_its_statement` | A store without owner rows: the restart derives the route row's holding of the binding's roster head, of the roster a stored proof names and of the only roster that verifies a policy, each charged to the conversation. |
| `a_proof_naming_a_replaced_roster_is_admitted_and_restored_after_expiry` | After a newer roster and expiry, a device's first proof naming the replaced roster, which the binding names too, is admitted, and both stored proofs restore after a restart. |

`an_installed_successor_restarts_without_the_roster_its_predecessor_named`
(one of the ReInit enforcement record's expiry tests, renamed from
`an_installed_successor_restarts_after_the_roster_its_predecessor_named_expires`)
removes that roster's object and owner rows from the store before the
restart, since the roster stays retained, and shows that the restart does
not need it.

`every_owner_class_seals_and_reopens_with_the_same_accounts` (ownership
suite) delivers the binding package of an unbound conversation to the
mailbox, so a mailbox-class account still appears in its store now that the
bound package is a security proof of its route.

## Coverage

Release policy (`conformance/release-critical-coverage.toml`):

- `e2ee-owner-derivation`, `e2ee-owner-batch-derivation`,
  `e2ee-owner-quotas` and `e2ee-owner-reconstruction` are re-spanned from
  their reviewed first and last lines over the lines this change inserts,
  with their reasons extended by the holding; `e2ee-owner-ledger-index` and
  `e2ee-owner-stage-rows` only moved.
- New: `retention-owner-staged-packages` (the staged packages a batch
  knows by binding identifier) and `retention-owner-held-packages`
  (`Rebuild::derive_held`), and, in the second commit,
  `retention-startup-validation-floor` (the replaced-candidate rule; the
  startup regions below it only moved).
- A branch report of the runtime library at the second commit scores the
  derivation 14 of 14, quotas 12 of 12, reconstruction 24 of 24, the
  staged packages 4 of 4 and the floor rule 4 of 4; the held-packages
  region has no branch. The batch-derivation and stage-rows regions score
  20 of 24 and 10 of 14 on lines this change does not touch (`Sizes::of`
  for an already accounted object and the undated acceptance floor), as
  before it.
- Third commit: the startup holding region is renamed
  `retention-owner-startup-holdings` and re-reviewed over the new
  `derive_held`, and eleven regions are new: `retention-owner-named-rosters`
  (`hold_named_rosters`), `retention-owner-startup-roster-ceiling`
  (`Rebuild::hold_roster`) and `retention-owner-startup-recorded-holders`
  (`Rebuild::recorded_route_holders`) in `owners.rs`, and, in
  `roster_holds.rs`, `retention-roster-holds-batch` (`of_batch`),
  `retention-roster-holds-routed` (`Batch::routed`),
  `retention-roster-holds-binding` (`of_binding`),
  `retention-roster-holds-policy` (`of_policy`),
  `retention-roster-holds-earliest` (`earliest`),
  `retention-roster-holds-root` (`root_of`),
  `retention-roster-holds-certificates` (`holds_all`) and
  `retention-roster-holds-conversation` (`of_conversation`).
  `e2ee-owner-derivation`, `e2ee-owner-batch-derivation`,
  `e2ee-owner-reconstruction` and `cap76-startup-rebuild` are re-spanned;
  the other regions of the changed files only moved. A branch report of the
  runtime library at the third commit scores every new region in full
  (branches 4 of 4, 6 of 6, 4 of 4, 2 of 2, 2 of 2 and 2 of 2; regions 40 of
  40, 80 of 80, 12 of 12, 29 of 29 and 51 of 51), the derivation 16 of 16,
  quotas 12 of 12, reconstruction 28 of 28, the roster snapshot resolution
  4 of 4, the startup rebuild 91 of 91 regions and the startup
  holdings 0 of 0 branches; batch derivation and stage rows keep their 20
  of 24 and 10 of 14. The batch reader's own decode refusals (`Batch::row`,
  `Batch::stage`) are in no region: the ownership derivation refuses those
  rows before the reader sees them.

Both policies' source inventories are refreshed.

## Stores written before these rules (G-08, fourth commit)

The decision is additive within storage generation 5 (decision D-06). No
table, key, row kind, field or object layout changes, and startup writes
nothing: the owner rows a batch writes already reference table-23 rows; a
binding package's owner row also names its route row, and a held roster's
owner row the route rows that hold it.

`test-data/stage-ten/binding-retention/` holds three stores written by the
test harness of two earlier coordinators, with the generator and commands
in its README: a bound channel after its bootstrap activation and a bound
channel whose account replaced its roster, both from release candidate 3
(`70c832c`), and an installed ReInit successor from `main` after the merge
of the P-04 topic (`c262ce1`). In
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/retention/earlier_stores.rs`:

| Test | What it pins |
| --- | --- |
| `every_store_that_holds_its_packages_restores_from_sealed_storage` | The three stores restore through the storage reads a restart uses. |
| `an_earlier_bound_channel_restores_and_its_route_holds_its_package_from_then_on` | The restart derives the route row's holding of the package and rebuilds its account; object expiry past every window then keeps it, and `EGROUP QUERY CHANNEL` answers with it before and after another restart. |
| `an_earlier_store_keeps_the_roster_its_policies_were_verified_under` | The restart holds the replaced roster under the route row, as the roster its binding names and the earliest that verifies both policies; after expiry and another restart it is still held, and both published policies and the current one restore. |
| `an_earlier_installed_successor_restores_and_keeps_both_packages` | The successor restores open on the channel route, the successor's and the predecessor's route rows hold their packages, expiry keeps both, and another restart restores the successor. |
| `a_store_without_a_routes_binding_package_refuses_startup` | A bound-channel or installed-successor store whose binding package rows are removed refuses startup, through the harness reload and through sealed storage. |

A store that holds its routes' binding packages restores, and from that
restart on its route rows hold their packages and the rosters their
statements name. Each restart derives these holdings until a batch next
writes the object's owner row, and the reconstruction counts such an
account as rebuilt.

A store that does not hold a route's binding package lacks the facts a
restart restores that route from (group, suite, context core, principals,
initial policies and the ReInit facts of the binding), and startup refuses
it, as it refuses a route whose rows name any other object the store does
not hold. A restart that instead restored such a route, held its semantic
route lock and refused every operation on it would leave the route without
any way back: companion 13.7.1 and 13.7.2 adopt a lost lineage's objects
only through the server recovery gate, under the binding identifier it
pins, and this coordinator's recovery resumes from the retained package.
The decision is recorded for the owner.

Downgrade: release candidate 3 reads a store this topic wrote, since no
format changed, but does not derive these holdings; the operator guide
already says not to start it on a database a later release has run on.

## Limitations

- A live conversation's rosters count toward
  `MAX_STORED_BYTES_PER_CONVERSATION` with the rest of its proof set
  (Section 15). A route row keeps the rosters it acquired until its
  deletion, as it keeps its package, and a restart keeps them too, so a
  roster that a replaced proof named stays held while the route exists. A
  replacement keeps its proof's credential, so a conforming device names
  the same roster again; a replacement that names another roster adds one
  held roster, charged to the conversation, and the per-conversation proof
  quota (`MAX_RETAINED_LEAF_MEMBERSHIPS`) does not count replacements. The
  coordinator holds every retained encrypted object other than message
  payloads in memory, up to `MAX_RETAINED_OBJECT_BYTES` (256 MiB) in all;
  the operator guide states it.
- A replaced roster that no statement of a live conversation names is
  collected once the security-proof window has passed, and a device's first
  leaf proof that names it is then refused with `E2EE_BINDING_AUTH_INVALID`.
  An example is the roster that enrolled a device after the binding, when
  the account replaces it before the device's first proof. The device
  recovers by proving its leaf under a credential that a retained roster
  authorized. Holding each principal's roster chain from the head its
  binding names while the route exists, or the roster that each retained
  KeyPackage's leaf authorization names, would admit such a proof; the
  choice is recorded for the owner.
- One owner row references at most 4,096 rows. A conversation beyond the
  4,096th that names a roster is not a holder of it and is not charged for
  it, so the roster's retention rests on the route rows that hold it. If
  all of those rows were deleted, the roster would retire while that
  conversation still names it, until the next restart derives the holder;
  no coordinator path deletes a route row today.
- A row of another kind that would become a roster's 4,097th owner, such as
  a recovery submission whose reference element is that roster, is refused
  with `E2EE_RATE_LIMITED`, as is any batch that would leave an object with
  more owners than one owner row can reference.
- A roster object that only another row made resident, such as a recovery
  submission's reference element, enters the roster indexes only at a
  restart, so a restart can hold it where live batches did not, and the
  reconstruction then counts that account as mismatched. This can only
  over-retain.
- The rosters a pending ReInit target names are held once the activation
  installs the successor, as the roster heads its binding names; until then
  only the statements above hold them. The activation's verification of the
  successor policy that the ReInit enforcement record describes is
  unchanged by this topic.

- No coordinator path deletes a route row today: a closed conversation's
  tombstone row stays, and so do the package and the rosters it holds,
  which is more than the security-proof window after the final close that
  Section 15 requires.
- Collecting a route's objects once its row is deleted is shown by deleting
  the row in a test batch.

## Revert proofs

- First commit: with `owners.rs` set back to its parent, the seven new
  tests fail and the ownership suite passes.
- Second commit: with `startup.rs` set back to its parent, the new restart
  test fails and the missing-Commit refusal passes; with the rule widened to
  skip every missing Commit, the missing-Commit refusal fails.
- Third commit: with every production file it changes set back to its parent
  and `roster_holds.rs` removed, 14 of its 18 new tests fail. The other four
  pass there, since the parent holds no replaced roster, and each fails when
  only the rule it pins is broken: keeping every roster an account published
  fails the test of an account without a conversation and the first-proof
  refusal, and dropping the reference ceiling or the route condition fails
  its own test. With only the restart's recorded route-row holders removed
  (`Rebuild::recorded_route_holders`), the replaced-proof restart test and
  the recorded-holder test fail. 24 of 26 single-edit mutations of the rule
  fail tests; the two that pass cannot change what is held: one moves only
  where the earliest-roster scan starts, and the other drops the
  trusted-time dating that every such batch's own statement rows already
  require.
- Fourth commit: with every production file of this topic set back to
  `c262ce1` and `roster_holds.rs` removed, the three earlier-store tests
  that check the holding fail, and the sealed-storage restore and the
  refusal of a store without its packages pass.

## Validation

First commit, Rust 1.98.0, from the worktree root:

- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: exit 0.
- `python3 scripts/check-source.py check`: exit 0.
- `cargo nextest run -p agenc-relay-runtime --lib --all-features --locked --no-fail-fast -E 'not test(/offline::tests::/)'`:
  2,712 run, 2,711 passed; the one failure,
  `state_core::tests::a_guest_session_registers_and_commands_flow_through_the_router`,
  is a timing failure that also fails at the parent `c262ce1` in two of
  three runs of the same command and passes alone.
- The fast static gate (59 commands): exit 0.

Second commit: the same commands; the runtime library run passes 2,714 of
2,714; the fast static gate exits 0.

Third commit: the same commands; the runtime library run passes
2,732 of 2,732; the fast static gate exits 0.

Fourth commit: the same commands; the runtime library run passes
2,737 of 2,737, the workspace run with the host filter
(`-E 'not (test(/offline::tests::/) | test(/cli_provisioning/))'`) passes
4,823 of 4,823 with 62 skipped, and the fast static gate exits 0.
