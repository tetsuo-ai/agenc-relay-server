# CLAIM STATUS names the stored claim's target (SC-001, SC-002)

This record covers SC-001 and SC-002 of the SDK server program (2026-10-01,
outside master #35). SC-001 changes how `EKEY CLAIM STATUS` names a claim's
device; SC-002 is recorded as a disposition without a code change. No wire
object, registry, profile hash, limit, persistent format or normative text
changed.

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
the two daemon tests run with it reverted fail: `CLAIM STATUS` names alice's
device `Pj4-Pj4-Pj4-Pj4-Pj4-Pg` where bob's `SEhISEhISEhISEhISEhISA` is
required, in
`real_clients::real_mls_clients_run_the_encrypted_lifecycle_through_the_daemon`
through the shared helper and in the restart test. The domain test covers the
accessor only and passes either way. With the fix restored, all pass.

### Wire effect

`EKEY CLAIM STATUS` for a claimed operation now answers with the claim's
target device in the `EKEY CLAIMED` line, the same line `EKEY CLAIM PACKAGE`
returned. Nothing else changes.

## SC-002: disposition only

SC-002 asked whether an `EKEY EMPTY PACKAGE` claim result must survive a
coordinator restart. The Section 11.6 paragraph that defines the claim mapping
maps every claim result, but it uses no BCP 14 keyword and phrases its
retention for a claimed package, and Section 12.5 gives an empty claim no
completion event; the SDK's readiness audit rated SC-002 a hardening gap, not
an interoperability defect.

The disposition is no change. An empty result stays recorded in memory under
its operation, so an identical retry before a restart still answers
`EMPTY PACKAGE`, and after a coordinator restart the same operation is
evaluated again. The SDK rehearsal's patch 0004, which made empty results
durable, is not adopted; the retention of claim records is the owner's
decision.

## Limitations

- The daemon evidence restarts the coordinator only, with the client
  sessions kept on their edges; a restart of the claimant's edge, and a
  claim between two devices of one account over the real wire, are covered at
  the coordinator level only.
- No critical-coverage region was added for `claim_status` or
  `Directory::stored_claim`; whether the release inventory should gain one is
  the owner's decision.
