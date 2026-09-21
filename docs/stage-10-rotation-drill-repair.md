# The sequencer rotation drill, repaired and given an ordinary signal

This record closes QA-02 (issue #137): the Stage 10 sequencer rotation drill
configured a sequencer key set ENC-07 (#58) made the daemon refuse, so it
could not start its nodes, and it is `#[ignore]`d for the qualification
driver, so nothing outside the native drill campaign noticed. The drill now
walks the workflow ENC-07 specifies and the operator guide documents, checks
what a client observes at every step, and is guarded by an ordinary
non-ignored test in the same module. No production source changed and no
production defect was demonstrated: the daemon's refusal was correct and the
drill encoded a procedure the daemon does not accept.

## What was wrong

`run_sequencer_rotation` installed a two-credential rotation document on every
node and then pointed the coordinator's `e2ee.sequencer_private_key_file` at
the **new** key, configuring no `e2ee.sequencer_successor_private_key_file` at
all. `daemon.rs::e2ee_setup_with_hook` takes the active key to be the key of
the credential the file lists first and requires a successor key exactly when
the file lists a successor, so that set is refused twice over with
`DaemonError::E2eeCredentials`. The coordinator exits before opening a
listener, printing

```
agenc-relay-server: E2EE sequencer credentials file is invalid or does not match the sequencer key
```

and `DrillNodes::check_alive` then fails the drill. Because startup
reconciles signer ownership from durable metadata and admits only continuous
succession, the active key can never move ahead of the advertised set: the
incoming key is the configured successor until a finalized `SEQUENCER`
transition moves each conversation's pin, and only then may it become the
active key.

The drill's assertions were as weak as its configuration. It counted
`e2ee_profile_acknowledged` lines in the two edge logs and logged one account
in. Neither names a sequencer credential, so even a drill that started would
not have shown that a rotation happened.

The drill's last recorded pass, in
[the qualification record](stage-10-qualification.md), describes "a
generation-1 set chaining from the previous credential" and predates ENC-07.

## The corrected workflow

The drill runs one coordinator and two edges of the production binary over
real mutual TLS, with two accounts created, authenticated and
device-attached, and every companion object signed by keys no server holds.
MLS bodies are synthetic; the controller signatures, council votes,
sequencer credentials, receipts and transport are real.

1. **Steady state, set generation 0.** The coordinator's
   `sequencer_private_key_file` is the generation-zero signer, with neither
   optional signer configured, and every node advertises the one-credential
   document the fixture wrote. `#room` is bound and its bootstrap activation
   is certified; `#held` is bound next and deliberately left pinned to the
   generation-zero credential, so a route that never transitions survives
   into the retirement.
2. **Overlap, set generation 1.** The two-credential rotation document — the
   active credential first, the successor chained from it second — is written
   on every node. The coordinator keeps `sequencer_private_key_file` on the
   generation-zero key and adds `sequencer_successor_private_key_file` for the
   incoming key. Every node is stopped and started again, because a changed
   credentials file is restart-only and never reloads in place.
3. **Transition.** A Commit on `#room` whose authorization carries
   `action_bits::SEQUENCER` is certified and finalized.
4. **Retirement, set generation 2.** The successor-only document is written
   on every node. The coordinator's active signer becomes the incoming key,
   the successor line is commented out again, and the predecessor moves to
   `sequencer_retired_private_key_file`, where `#held` still requires it.
   Every node is stopped and started again.
5. **New binding.** `#rotated` is reserved once and bound twice.

This is steps 2, 3, 5 and 6 of the operator guide's "Rotate the sequencer
credential", with the overlap and the retirement each proved by a restart of
the real binary.

## What each step asserts

| Step | Assertion |
| --- | --- |
| bind | The bootstrap activation's candidate receipt names the generation-zero credential, and its sequencer signature verifies under exactly that credential's public key. `#held` binds under the same pin. |
| overlap | Every node starts and serves on the two-credential set; both edges re-acknowledge the companion profile, whose ECAP tuple carries the new set generation and digest. |
| transition | The `SEQUENCER` transition's own receipt is signed under the **predecessor**, and the next finalized record's receipt is signed under the **successor**: the pin moved. |
| retire | Every node starts with the predecessor at `sequencer_retired_private_key_file`. That is itself the check that the retained key is the key of exactly the credential the live state still requires, because startup refuses a released or unrelated retired key. `e2ee_routes_blocked` is logged for `#held`, which still pins the predecessor, and `e2ee_retired_signer_missing` is not. |
| pin | A binding package pinning the retired credential is refused with `FAIL EGROUP E2EE_BINDING_AUTH_INVALID` and no `EGROUP BOUND`, and the same reservation binds once the package pins the credential the advertised set now issues. |

The drill record carries each of these as a fact:
`activation_receipt_credential`, `transition_receipt_credential`,
`post_transition_receipt_credential`, `profile_reacknowledged`,
`blocked_route_reported`, `retired_signer_missing`, `retired_pin_refused`,
`successor_pin_bound` and `daemons_stopped_cleanly`.

One repair was needed beyond the key set. A client session never survives an
edge restart, and a submission on a channel conversation needs its members
present, so the drill re-joins `#room` and `#held` from both clients after
every restart, exactly as the ENC-10 rotation scenario does. Without that the
first submission after a restart receives no reply at all.

## The signal outside the native campaign

The ordinary Stage 08 suite now carries
`sequencer_rotation_key_sets_are_the_ones_the_daemon_accepts`, a non-ignored
test in the same module that shares the drill's `KeyPlan` values and its
`install_keys`. It binds one route pinned to the generation-zero credential,
then stops every node and, in order:

- installs the set ENC-07 refuses — the active key pointed at the incoming
  generation with no successor — and requires the coordinator to exit
  non-zero;
- installs the overlap set the drill builds and requires every node to come
  up and link;
- installs the retirement set with the predecessor retained and requires
  every node to come up, the blocked-route event to be reported, and the
  retired signer not to be reported missing.

This was chosen over a check in the qualification driver's own self-test.
That self-test (`scripts/test-release-qualification.py`) imports
`scripts/qualify-stage-ten-drills.py` and feeds `validate_record` synthetic
record dictionaries; it has no fixture, no configuration and no daemon, so it
can only check the closed record schema. A drill's configuration is built in
Rust from the Stage 08 fixture, and the only thing that can decide whether
the daemon accepts it is the daemon. Putting the check beside the drill, over
the same helper, is the only place it can actually run, and it costs 24
seconds against the drill's 42 and needs no drill directory.

## Audit of the other ignored Stage 10 drills

Every `#[ignore]`d drill in `stage_ten_drills.rs` was run to completion on
this host, serially, against this branch. "Configuration accepted" means the
daemon started and served on every configuration the drill writes.

| Drill | Configuration it writes | Accepted? |
| --- | --- | --- |
| `restore` | `state_dir`, `rollback_guard_key_file` after `storage restore`; the new recovery epoch re-pinned on both edges | yes — passed |
| `disaster_restore` | the same, with the current state directory removed first | yes — passed |
| `deletion` | none beyond the restore rewrite (`state_dir`, `rollback_guard_key_file`, `master_key_file`) | configuration accepted; **the drill still fails**, see below |
| `rekey` | restore rewrite plus a new `master_key_file`, epoch re-pinned on the coordinator | yes — passed |
| `index_transition` | the login-index key mapping installed through the signed maintenance command | yes — passed |
| `tls_rotation` | `tls/server.crt` and `tls/server.key` replaced in place, once for a re-issued certificate and once for a new leaf key | yes — passed |
| `federation_rotation` | the edge's `signing_private_key_file` swapped and its `signing_public_key` re-pinned on the coordinator | yes — passed |
| `sequencer_rotation` | the sequencer key sets of this repair | yes — passed, repaired here |
| `backup_rotation` | a two-key backup trust manifest and a swapped `backup_signing_private_key_file` | yes — passed |
| `audit_rotation` | a two-key audit trust manifest and a swapped `audit_signing_private_key_file` | yes — passed |
| `compromise` | `max_connections` lowered to 1 and reloaded, then a restore under a new master key | yes — passed |
| `rollback` | none; an older `database.redb` under the current guard, whose refusal is the drill | yes — passed (refusal observed) |
| `resynchronization` | restore rewrite without a new master key, epoch re-pinned | yes — passed |
| `host_hardening` | none; it inspects listeners, file modes, the core limit, canaries, crash handling and locked secrets | yes — passed |
| `observability` | none; it reads the STATS vocabulary and the log registry | yes — passed |

Nothing else in the file installs a sequencer key set, a credentials
document or a trust manifest whose accepted shape ENC-07 or any other
normative change moved. The two rotations that do rewrite a trust manifest —
backup and audit — append the new key beside the old one and swap the active
signing key, which is the shape those manifests still require, and both were
proved by running them.

### `deletion` needs its own issue

`deletion` is the one drill that does not pass on this host at this branch,
and its failure is not a key set the daemon refuses. Two runs failed in two
different places:

- the first, in the serial sweep, at `authenticated_client` immediately after
  `nodes.restart(&network, 0)`, with
  `FAIL ACCTCREATE UNAVAILABLE :Account creation unavailable`. `DrillNodes::restart`
  waits for both edges' federation links but not for their account authority,
  which `DrillNodes::restart_all` does wait for, so the account is created in
  the window before the edge can serve one;
- the second, run on its own, past that point and inside `delete_account`,
  where an `ACCT` command of the deletion sequence is answered
  `:edge-a.test 481 delete-me :Permission denied` and the drill's read then
  times out.

The first is a readiness race in the drill. The second is an authority
refusal that only the account-deletion path can explain, and repairing it
means deciding whether the daemon or the drill is wrong about who may start a
deletion — a separate question from this issue, and one that cannot be
answered by editing the drill until it passes. Both are reported here for
their own issue rather than patched speculatively, so the reproduction stays
clean. Nothing in this change touches `run_deletion` or any path it uses.

## Limitations

- The drill's MLS bodies remain synthetic. Real openmls and mls-rs endpoints
  drive the same rotation in the ENC-10 scenario recorded in
  [the encrypted client proof record](stage-10-encrypted-client-proof.md);
  this drill is the operator-facing one and proves the configuration, the
  restarts and the durable pin, not MLS processing.
- The drill proves the retirement at or after the overlap deadline. The
  fixture's credentials carry `not_before = 0`, so the deadline
  (`not_before` plus `MAX_SEQUENCER_KEY_OVERLAP`, seven days) is long past at
  any real trusted time. A retirement refused *before* the deadline while a
  normal route still pins the predecessor stays with the ENC-07 in-process
  suites.
- Only one retired-retained signer is held, which is the ENC-07 limitation,
  so the drill retires exactly one credential.
- These are development-host runs of the Stage 08 fixture. Native release
  qualification of the whole drill campaign remains with REL-10 (#84).

## Evidence

Sources:

- `crates/agenc-relay-server/tests/stage_eight_e2ee/stage_ten_drills/sequencer_rotation.rs`
  (the drill, the key sets, and the ordinary smoke test)
- `crates/agenc-relay-server/tests/stage_eight_e2ee/stage_ten_drills.rs`
- `crates/agenc-relay-server/tests/stage_eight_e2ee.rs` (the fixture, the binding and
  certification helpers)
- `crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/rotation.rs`
  (the ENC-10 scenario this repair follows)
- `crates/agenc-relay-runtime/src/daemon.rs` (`e2ee_setup_with_hook`)
- `crates/agenc-relay-runtime/src/e2ee/coordinator/signer_startup.rs`
  (the reconciliation that requires or releases a retired signer)

Commands and results at this branch (Rust 1.98.0, from the repository root):

```sh
# the repaired drill, explicitly including ignored tests
AGENC_STAGE10_DRILL_DIR=<dir> cargo test -p agenc-relay-server --test stage_eight_e2ee \
  --all-features drill_sequencer_rotation -- --ignored --nocapture
# 1 passed; 0 failed; 50 filtered out; 42.47s
# record: passed=true, five steps, eleven facts

# every ignored Stage 10 drill, serially, for the audit above
AGENC_STAGE10_DRILL_DIR=<dir> cargo test -p agenc-relay-server --test stage_eight_e2ee \
  --all-features stage_ten_drills::drill_ -- --ignored --test-threads=1
# 14 passed; 1 failed (deletion); 294.28s
# run through the already-built test binary so the sweep held no cargo lock

# the ordinary suite, which now carries the non-ignored guard
cargo test -p agenc-relay-server --test stage_eight_e2ee --all-features
# 35 passed; 0 failed; 16 ignored; 42.80s

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean
cargo fmt --all
python3 scripts/check-source.py check
# source policy: ok (1004 Rust files)
bash /mnt/data/agenc-dev/tools/static-checks.sh .
# STATIC CHECKS OK
```

No production source changed, so no critical region moved and the coverage
source inventory is unchanged.
