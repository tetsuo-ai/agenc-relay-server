# Retention of what a live encrypted conversation reads (D-39)

This record covers the server topic `sdk/b-binding-retention` of the SDK
server program (decision D-39, 2026-10-06, outside master #35): the
coordinator retains every object a live encrypted conversation's restart
reads for as long as the conversation's route exists. The work
lands in small commits; this one, the first, makes a route row hold its
conversation's binding package. No specification, profile hash, registry
entry, named limit, reply code, wire object, table, key, row kind, field or
storage generation changed.

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
  restored from (`Rebuild::derive_held`), so the restart rebuilds exactly
  the ownership live batches derived (`owner_reconstruction` is clean for a
  store this coordinator wrote).
- A migrated ReInit predecessor keeps its route row, so it keeps its
  generation-zero package beside the successor's package: the binding
  ancestry of the live lineage stays retained.
- A package that other rows also name, such as the bound package delivered
  to a device's mailbox with `EKEY DELIVER BINDING`, stays a security proof
  of the conversation after those rows retire.

The owner matrix of [the object ownership record](stage-10-object-owners.md)
gains this holding: the route row owns its route state object and the
binding package of its binding.

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
  (`Rebuild::derive_held`).
- A branch report of the runtime library scores the derivation 14 of 14,
  quotas 12 of 12, reconstruction 24 of 24 and the staged packages 4 of 4;
  the held-packages region has no branch. The batch-derivation and
  stage-rows regions score 20 of 24 and 10 of 14 on lines this change does
  not touch (`Sizes::of` for an already accounted object and the undated
  acceptance floor), as before it.

Both policies' source inventories are refreshed.

## Persistence (G-08)

Additive within storage generation 5. No table, key, row kind, field or
object layout changes, and startup writes nothing: the owner rows a batch
writes already reference table-23 rows, and a package's owner row also
references its route row. A store written before this change restores, and
its routes' rows hold their packages from that restart on; each restart
derives the holding until a batch next writes the package's owner row.

## Limitations

- No coordinator path deletes a route row today: a closed conversation's
  tombstone row stays, and so does the package it holds, which is more than
  the security-proof window after the final close that Section 15 requires.
- Collecting a route's objects once its row is deleted is shown by deleting
  the row in a test batch.

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
