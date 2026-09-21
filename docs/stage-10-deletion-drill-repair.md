# The deletion drill, repaired and given an ordinary signal

This record closes QA-03 (issue #147): the Stage 10 account-deletion drill
failed in two different places depending on how it was run, and neither
failure was visible outside the native drill campaign because every Stage 10
drill carries `#[ignore = "Stage 10 drill; run through the qualification
driver"]`. The first was a readiness gap in the drill harness. The second was
a capability refusal, and **the refusal was correct**: the drill sent `ACCT`
over a session that had never negotiated `agenc.ag/account-controls`, and the
daemon is required to refuse exactly that. No production source changed and no
production defect was demonstrated by either failure. The drill now walks the
deletion sequence with the capabilities Section 14.6 requires, asserts what
the deletion removes, what it retains, what a later lookup returns and that a
refused deletion writes nothing, and is guarded by an ordinary non-ignored
test in the same module.

## The two failures

### Run in the sweep: `FAIL ACCTCREATE UNAVAILABLE`

`DrillNodes::restart` waited for the federation links the restart interrupts
and returned. `DrillNodes::restart_all` waits for those links **and** for
`wait_for_account_authority` on both edges. A link is established before an
edge can serve an account, so `run_deletion`'s
`authenticated_client(&network.edge_a, …)` immediately after
`nodes.restart(&network, 0)` could reach a node whose account service had not
finished coming up and be answered

```
FAIL ACCTCREATE UNAVAILABLE :Account creation unavailable
```

This is a harness gap, not a product defect: the refusal is the documented
Section 9.3 answer for a listener whose account authority is not available,
and the drill simply asked too early. `restart` now performs the same
readiness wait `restart_all` performs, for each edge whose link it waits on.

### Run alone: `481 :Permission denied` on `delete_account`

Reproduced at `14a594f` before any change, with the drill's own record:

```
$ AGENC_STAGE10_DRILL_DIR=<dir> cargo test -p agenc-relay-server --test stage_eight_e2ee \
    --all-features drill_deletion -- --ignored --nocapture
[drill deletion] delete (25040 ms): edge account deletion failed
test result: FAILED. 0 passed; 1 failed; 50 filtered out; finished in 49.53s

deletion_at_edge: read failed (Resource temporarily unavailable (os error 11))
  before the expected reply; received [":edge-a.test 481 delete-me :Permission denied"]
```

The refused line is the **first** `ACCT` of the sequence,
`ACCT LABEL deletion-check`, not a deletion command: every `ACCT` line that
session sent would have been refused the same way. The drill then waited out
`REPLY_DEADLINE` for a `NOTE ACCT UPDATED` that was never coming.

## The decision: the refusal is correct and the drill was wrong

`delete_account` opened its connection with `ArcClient::negotiate_sasl`, which
requests `agenc.ag/account-create agenc.ag/account-credentials sasl`, and then
added exactly one capability:

```rust
client.send_until("CAP REQ :standard-replies", " CAP * ACK ")?;
```

Architecture Section 14.6 opens the `ACCT` and `CHANCTL` surface with the
words "the vendor capabilities in Section 9 enable this closed command
surface", and Section 9.3 names `agenc.ag/account-controls=v1` as the one for
"authenticated account control". `RegistrationState::require_command_capabilities`
in `crates/agenc-relay-client-wire/src/registration.rs` implements exactly
that: a `PostRegistrationCommandKind::Account` command requires **both**
`agenc.ag/account-controls` and `standard-replies`, and returns
`RegistrationGrammarError::NoPrivileges` otherwise, which
`crates/agenc-relay-runtime/src/registration.rs` renders as
`481 :Permission denied`. The session had one of the two, so the daemon
refused, correctly, before the command reached the account service.

The dates settle it. The drill was written in `ac0d73f` ("Add the Stage 10
operational drills and the generation-1 fixture feature", 2026-09-05) with
that one-capability request. `require_command_capabilities` was added eight
days later in `0c0128a` ("Repair capability replies, federated masks, TLS
loading and queue accounting", 2026-09-13), which brought the daemon to what
Section 14.6 already required. Nothing updated the drill, so it kept
negotiating a session the `ACCT` surface is not open on.

**The drill is wrong and the daemon is right.** The repair is in the drill:
every deletion session now requests
`standard-replies agenc.ag/account-controls` and asserts the server
acknowledged both before it sends an `ACCT` line. No runtime or domain source
changed.

## What the drill now asserts

The drill runs one coordinator and two edges of the production binary over
real mutual TLS. It seeds an account that owns `#drill`, creates a second
account, refuses a deletion, deletes the second account, and restores the
coordinator under a new master key and rollback guard. Every durable claim is
read from the stopped coordinator's own storage through `StorageOwner`, not
inferred from a reply.

| Step | Assertion |
| --- | --- |
| baseline | The seeded account and channel exist and a backup of that state is taken. |
| create | The target account's rows are live: an `Account` row whose body decodes and whose generation and revision match it, an `OpaqueRecord` referencing exactly that account and carrying a decodable OPAQUE registration record, and a `Live` login-index row naming it. |
| refuse | `ACCT DELETE CONFIRM` of a canonical token no `DELETE START` issued is answered `FAIL ACCT BAD_STATE :Command is not valid in the current state`, and the coordinator's rows for **both** accounts are then byte-identical to the creation's, modulo the session generation and revision an authentication of its own advances. |
| delete | The deletion sequence completes over the capabilities Section 14.6 requires; the connection's last line is `NOTE ACCT UPDATED :Account setting updated` and the server then closes it cleanly; a later OPAQUE authentication of the deleted login is refused with `InvalidLoginError`, which only a completed OPAQUE exchange can produce; the seeded account still authenticates on the other edge. |
| rekey | Restored under a new master key and a new rollback guard, the deleted account's rows are byte-identical to what the deletion left, and the seeded account's account body, OPAQUE credential and login-index row are unchanged. |
| verify | The deleted login is still refused after the rekey, on the other edge. |

What deletion **removes** is read row by row: after the deletion the target's
`Account` row is a tombstone with generation 0, no expiry, no references and
an empty body, and its `OpaqueRecord` row is gone. What it **retains** is read
the same way: the login-index row is a `DeletionTombstone` naming the deleted
account with a non-zero expiry, which is the 30-day login-hash reservation,
and the unrelated account keeps its credential and policy. What a **later
lookup returns** is the refusal an OPAQUE authentication of that login gets,
before and after the rekey, on both edges. That a **refusal changes nothing**
is the `refuse` step above, which is new here.

The drill's verdict is now the conjunction of the refusal, the unchanged
state after it, the final note and clean close, the two deleted-login
refusals, the full durable comparison in `deletion_state_is_complete`, and
every daemon stopping cleanly.

## The signal outside the native campaign

The ordinary Stage 08 suite now carries
`deletion_drill_preconditions_are_the_ones_the_daemon_requires`, a non-ignored
test in the same module, over the same helpers the drill uses. It starts the
drill network and, in order:

- creates one account, then opens a session carrying `standard-replies`
  alone — the set the drill used to negotiate — and requires `ACCT LABEL` to
  be answered `481 :Permission denied`;
- opens a session carrying `DELETION_CAPS`, the set the drill now negotiates,
  and requires the same line to be answered `NOTE ACCT UPDATED`;
- stops and restarts the coordinator through `DrillNodes::stop` and the
  repaired `DrillNodes::restart`, then reads both edges' `active_peers` with
  no wait of its own and requires each to be 1, which is what
  `wait_for_account_authority` waits for and therefore what `restart` must
  already have established, and serves one more `ACCT` line on the far edge.

This is the same shape `sequencer_rotation_key_sets_are_the_ones_the_daemon_accepts`
took for QA-02 (#137), and for the same reason: the qualification driver's own
self-test (`scripts/test-release-qualification.py`) feeds `validate_record`
synthetic record dictionaries and has no fixture, no configuration and no
daemon, so it can only check the closed record schema. Only the daemon can
decide whether a capability set opens a command surface. The test costs about
20 seconds against the drill's 47 and needs no drill directory.

## A separate observation: an unavailable account authority is a `904`

While reproducing the second failure, a third and unrelated behaviour showed
up and is **reported here for its own issue rather than repaired**. An OPAQUE
authentication that reaches an edge in the moments after the creating session
leaves is sometimes refused immediately with

```
:edge-a.test 904 * :SASL authentication failed
```

and in one capture the coordinator logged `event=federation_link_closed
severity=warning` in the same second. `SaslNumeric` has `Failed`, `TooLong`,
`Aborted`, `AlreadyAuthenticated` and `Mechanisms` and no unavailable arm, so
a client cannot tell an authority it cannot reach from a wrong password —
which is precisely why `stage_ten_capacity::transient_transport` refuses to
treat a `904` as a transient transport failure, and why
`an_authentication_refusal_is_not_a_transient_transport_failure` pins that.
Section 9.3 gives `FAIL ACCTCREATE UNAVAILABLE` and `FAIL ACCTCRED
UNAVAILABLE` for exactly this state on the other two carriers.

Nothing here depends on resolving it. `deletion_session` retries its own
attempt inside the ordinary `NETWORK_WAIT` after re-waiting for account
authority, and no refusal this module proves is read from that carrier: the
capability refusal is read from the `ACCT` reply and the deleted-login refusal
from `deleted_account_login_refused`, which keeps using the strict helper that
treats a `904` as a hard failure.

## Limitations

- The drill deletes an account that owns no channel and holds no E2EE route,
  so the Section 14.6 conditions that refuse a `DELETE CONFIRM` from a session
  occupying a channel, from an account that would leave a channel ownerless,
  or from one that has not left every E2EE route, are not exercised here and
  stay with the in-process suites.
- The refusal the drill proves is the `BAD_STATE` one a token outside the
  daemon's challenge epoch gets. The token-mismatch refusal consumes the
  challenge on every outcome and would need a second OPAQUE authentication to
  continue, so it is not driven from the drill.
- The 30-day login-hash reservation is proved as the durable tombstone row
  with its expiry, not by attempting to create a second account on the same
  login.
- These are development-host runs of the Stage 08 fixture. Native release
  qualification of the whole drill campaign remains with REL-10 (#84).

## Evidence

Sources:

- `crates/agenc-relay-server/tests/stage_eight_e2ee/stage_ten_drills.rs`
  (`DrillNodes::restart`, `deletion_session`, `refuse_unissued_deletion`,
  `delete_account`, `run_deletion`, and the ordinary signal)
- `crates/agenc-relay-client-wire/src/registration.rs`
  (`require_command_capabilities`)
- `crates/agenc-relay-runtime/src/registration.rs`
  (`render_registration_error`, the `481` this raises)
- `crates/agenc-relay-domain/src/decision.rs`
  (`plan_account_deletion_start`, `plan_account_deletion_confirm`)
- `crates/agenc-relay-runtime/src/account_service.rs`
  (`account_deletion_writes`, the tombstone and the deleted credential)
- `docs/arc-architecture-and-implementation-spec.md` Sections 9.3 and 14.6

Commands and results at this branch (Rust 1.98.0, from the repository root):

```sh
# the repaired drill, explicitly including ignored tests
AGENC_STAGE10_DRILL_DIR=<dir> cargo test -p agenc-relay-server --test stage_eight_e2ee \
  --all-features drill_deletion -- --ignored --nocapture
# 1 passed; 0 failed; 51 filtered out; 46.97s
# record: passed=true, six steps, twenty-one facts; refuse step reports
#   "unissued DELETE CONFIRM refused=true, state unchanged=true"

# every ignored Stage 10 drill, serially: the first failure only appears here
AGENC_STAGE10_DRILL_DIR=<dir> cargo test -p agenc-relay-server --test stage_eight_e2ee \
  --all-features stage_ten_drills::drill_ -- --ignored --test-threads=1
# 15 passed; 0 failed; 37 filtered out; 327.45s
# run through the already-built test binary so the sweep held no cargo lock

# the ordinary suite, which now carries the non-ignored guard
cargo test -p agenc-relay-server --test stage_eight_e2ee --all-features
# 36 passed; 0 failed; 16 ignored; 45.87s

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean
cargo fmt --all
python3 scripts/check-source.py check
# source policy: ok (1006 Rust files)
python3 /mnt/data/agenc-dev/tools/verify-regions.py .
# stale regions: 0
bash /mnt/data/agenc-dev/tools/static-checks.sh .
# STATIC CHECKS OK
```

No production source changed, so no critical region moved and the coverage
source inventory is unchanged.
