# Stable KeyPackage claim results (SC-001 and SC-002)

The coordinator retains a successful claim and an accepted no-stock claim under
the claimant account and operation ID. A client can recover either result after
restarting the coordinator or refilling the target device's stock. SC-001
corrected the target device returned by `CLAIM STATUS`. SC-002 implements the
stable mapping required by companion §11.6.

## SC-001: CLAIM STATUS returns the stored result

Companion Section 11.6 has the coordinator transactionally map
`(claiming_account_id, operation_id)` to the exact claim parameters and result
before it consumes a package, and has `CLAIM STATUS` return that stored
result; an identical retry is idempotent and the mapping survives reconnect.
Section 11.7 gives the claimed line as
`EKEY CLAIMED <device-id> NORMAL <key-package-ref> <object-id>`, and the
Section 12.5 `claimed` tuple names the device, the package kind, the
KeyPackageRef and the object.

`EKEY CLAIM PACKAGE` answered with the target device the package was claimed
from, but `claim_status`
(`crates/agenc-relay-runtime/src/e2ee/coordinator/ops/directory.rs`) rendered
the device the asking connection had attached. Every `CLAIM STATUS` answer for
a claim of another account's or a sibling device's package, which is every
claim a client makes in practice, therefore named the wrong device; the
reference, the object and its bytes were right.

`Directory::stored_claim` (`crates/agenc-relay-domain/src/e2ee/directory.rs`)
returns the parameters stored beside a claim's outcome, which the startup
restore already fills from the durable claim row, and `claim_status` names the
stored target device. An operation the claimant never made still answers
`EKEY EMPTY PACKAGE`. The lookup stays keyed by the requesting account's
digest, so who may read a claim is unchanged. The grammar gives only the
position of `<device-id>`; the change reads it as the claim's target, as
`CLAIM PACKAGE` already does and as "returns that stored result" implies.

This adopts the SDK rehearsal's patch 0003 (rehearsal commit `b481397c`)
unchanged; only the coverage source inventories were recomputed for this
tree.

### Regressions

- `e2ee::coordinator::tests::claims::claim_status_names_the_claim_target_from_another_device_and_after_a_restart`
  (runtime): a sibling device of the same account claims the other device's
  package; `CLAIM STATUS`, the identical retry, `CLAIM STATUS` after a restart
  rebuilt from the staged rows through the production restore path, and
  `CLAIM STATUS` from the target device itself all return the original result
  and package bytes, and an operation never made answers `EMPTY PACKAGE`.
- `a_stored_claim_keeps_the_parameters_it_was_made_with` (domain): the
  accessor returns the parameters of a claimed and of an unavailable
  operation, nothing for an unknown operation or another claimant, and the
  parameters of a restored claim.
- Stage 08: the shared `real_clients::claim_package_with` helper, which every
  real-client scenario uses to claim across accounts, now also sends
  `EKEY CLAIM STATUS` for the same operation and requires the same
  `EKEY CLAIMED` words and object; and
  `claim_restart::a_claim_keeps_its_target_and_result_across_a_coordinator_restart`
  runs the production coordinator and two edges: bob publishes a real mls-rs
  KeyPackage, alice claims it from the other edge, the coordinator is
  restarted, and `CLAIM STATUS` and the identical retry return the same
  `EKEY CLAIMED` line, naming bob's device, and the same object.

With `claim_status` alone reverted to its previous commit, the coordinator
test fails (`Claimed([8; 16], …)` where `Claimed([7; 16], …)` is required), and
both daemon tests fail: `CLAIM STATUS` names alice's device
`Pj4-Pj4-Pj4-Pj4-Pj4-Pg` where bob's `SEhISEhISEhISEhISEhISA` is required, in
`real_clients::real_mls_clients_run_the_encrypted_lifecycle_through_the_daemon`
through the shared helper and in the restart test. The domain test covers the
accessor only and passes either way. With the fix restored, all pass.

### Wire effect

`EKEY CLAIM STATUS` for a claimed operation now answers with the claim's
target device in the `EKEY CLAIMED` line, the same line `EKEY CLAIM PACKAGE`
returned. Nothing else changes.

## SC-002 durable results and admission

For an attached claimant and an active target device, the coordinator first
looks up the operation under the authenticated claimant's account digest.
Identical parameters replay the stored result. Changing the target account,
target device or suite returns `E2EE_OPERATION_CONFLICT`. A new claim selects
eligible stock under the normal minimum remaining lifetime rule. When the
device has no eligible stock, an accepted operation writes a typed
`KeyUnavailable` claim and returns `EKEY EMPTY PACKAGE`. The authenticated
`claim/v1/<claimant-digest><operation-id>` row stores the target account digest,
device, suite and seven-day cutoff with an empty KeyPackageRef and no object.
A server upgraded from a version that kept empty results only in memory can
recover every operation with a durable row. It starts retaining new empty
results from upgrade onward. The actor publishes the new mapping and
response after the storage receipt. An unknown operation also returns
`EKEY EMPTY PACKAGE` to `CLAIM STATUS`. A retry against replenished stock and a
changed-parameter conflict distinguish a retained result from an unknown one.

The coordinator admits up to **64 retained no-stock operations per claimant**
and **4,096 across the coordinator**. Each takes an 8 KiB reservation from
the shared process memory budget, including during reload. A fresh empty
claim at either limit, or with insufficient process backing, returns
`RATE_LIMITED` and leaves the claim operation available for retry. Existing
mappings still replay or conflict and a fresh stocked claim can still
succeed. Expired rows keep their slots until their deletes commit. A reload
that cannot admit all retained rows fails before serving the directory. The loader
checks the full claim or stock key and its typed row together. The v1 codec
can represent `RateLimited`, but this server records overload as an admission
refusal. It rejects such a stored row at startup.

The request-maintenance worker examines up to 128 claim rows and deletes at
most one claim mapping per pass. It uses trusted time and permits deletion at
the cutoff. An empty mapping releases its slot after that commit. For a
successful claim, the row and the object's claim-owner reference change in
the same transaction. Its retention floor is the later of the seven-day
timeout and the signed package lifetime. Older successful rows may record
only the seven-day cutoff, so the worker also checks the retained signed
package. Missing lifetime evidence leaves the mapping in place. The object
collector continues to own physical deletion.

Expired route reservations, replay results and the selected KeyPackage claim
share one storage receipt. The worker reserves at most half of the 128
primary deletion slots for route grants, one for a due KeyPackage claim and
the remainder for completed request replays. The replay and KeyPackage scans
keep independent cursors. A restart test captures an expired route lease
and one of two due no-stock claims, confirms their exact durable deletions
and reopening, and selects the remaining claim on the next pass.

### Linux verification

The coordinator tests exercise the production handler, its typed staged row,
real package refill, same-account queries from a sibling device and production
startup decoding. They check the precise cutoff with a controlled clock,
dropped maintenance, committed deletion, old successful rows, unchanged
object ownership, the per-account and aggregate ceilings, insufficient memory
and the first new grant after a slot is released.

The registered test starts one coordinator and two edges. Alice and Bob register, authenticate and
attach their enrolled devices on separate edges. Alice gets a no-stock
result, Bob publishes a signed mls-rs KeyPackage, and Alice can still replay
her empty claim while a fresh claim receives those exact bytes. After
restarting the coordinator, Bob publishes another signed package. Alice's
status and identical retry still return empty, a changed suite conflicts, and
a fresh operation takes the second package. The same run checks Alice's
original successful status and bytes after restart. The daemon case keeps
the edge processes running and uses real TLS and persistent storage. The
seven-day cutoff and the two capacity limits are exercised in the coordinator
tests.

```sh
cargo test --locked --offline --all-features -p agenc-relay-domain --lib
cargo test --locked --offline --all-features -p agenc-relay-runtime --lib -- --test-threads=4
cargo test --locked --offline --all-features -p agenc-relay-server --test stage_eight_e2ee claim_restart::a_claim_keeps_its_target_and_result_across_a_coordinator_restart -- --exact
```

On Linux with Rust 1.98.0, all ten focused coordinator claim tests and all
268 domain tests passed. The registered restart case passed in 16.02 seconds with the
exact labeled empty and conflict completions checked. The SDK's independent client qualification can repeat this
exchange against the merged, pinned daemon.
