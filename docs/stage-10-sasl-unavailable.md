# An unavailable account authority, told apart from a wrong password

This record closes RUN-09 (issue #152). An OPAQUE authentication that reached
an edge whose account authority was momentarily unavailable was answered
`:edge-a.test 904 * :SASL authentication failed`, the same numeric a wrong
password gets, so no client and no harness could tell the two apart. The
normative answer needed no invention and no new numeric: the Section 9.5 reply
registry already gives `UNAVAILABLE` to the two sibling carriers of this
surface, and the SASL carrier now joins that row. On the wire the refusal is
`FAIL AUTHENTICATE UNAVAILABLE :Account authority unavailable` followed by the
existing `904`; a client that did not negotiate `standard-replies` reads
exactly what it reads today.

## The decision, and why no numeric was added

`SaslNumeric` carries exactly the IRCv3 set, 903 through 908. There is no
assigned numeric for a temporarily unavailable authenticator, and numerics are
a shared registry, so a vendor one is not available to this daemon. Section 9.5
already lists `FAIL AUTHENTICATE` with `BAD_STATE`, and already gives
`UNAVAILABLE` to `FAIL ACCTCREATE` and `FAIL ACCTCRED` for exactly this state
on the other two carriers of the account surface. The whole normative change is
one row:

```diff
-| `FAIL ACCTCREATE`, `FAIL ACCTCRED` | `UNAVAILABLE` | none |
+| `FAIL ACCTCREATE`, `FAIL ACCTCRED`, `FAIL AUTHENTICATE` | `UNAVAILABLE` | none |
```

The public context stays **none**, exactly as the other two carriers keep
theirs, so the line says only that the authority is unavailable. It never
names an account, a login or a credential, and it is sent whether or not the
account exists, so it cannot be used to probe for one. Section 11.4 gained one
lowercase paragraph stating the outcome, the ordering and the unnegotiated
client's unchanged view; it adds no BCP-14 requirement record, and the
regenerated ledger is the same 251 records with only the document hash and the
line numbers below the insertion changed.

## Where the refusal is emitted

The cause is known in exactly one place and is reported from there rather than
re-derived downstream. `SaslTransport` has two terminal doors out of an
in-flight exchange, and they already separate the two outcomes:

- `complete(accepted, now)` is the door an **answered** exchange leaves by. A
  rejected completion is `complete(false, now)`, which is the wrong-password
  and unknown-account path, and it still yields the `904` alone.
- `unavailable(now)` is the door an exchange leaves by when the account service
  **produced no completion at all** — the edge could not forward the envelope,
  the coordinator answered with no usable completion, or the request was
  abandoned on its deadline.

`unavailable` now returns two actions, the new
`SaslAction::AuthorityUnavailable` followed by the same
`SaslAction::Numeric(SaslNumeric::Failed)`. Nothing else in the carrier ever
produces the first action, so no other refusal can acquire the line and no
success can: `903` is reached only through `complete(true, now)`.

The three call sites are the three ways an authority becomes unreachable:

| Call site | The state it reports |
| --- | --- |
| `registration.rs` `edge_sasl_line` | `EdgeFederation::send_account_carrier` refused the envelope, so it never left the edge. |
| `registration.rs` `edge_sasl_answer` | The coordinator's answer was neither a challenge, an authenticated completion, nor a rejected completion with chunks. |
| `account_service.rs` `fail_route` | The coordinator's own account service could not carry the request to a completion. |

Rendering is `render_sasl_action` in `account_service.rs`, which takes the
connection's negotiated `standard-replies` state and drops the action when it
is absent, so an unnegotiated client's transcript is byte-identical to today's.
That state is read where it is held and carried to where the refusal is
rendered: the edge paths read `state.registration.capability_state()` on the
connection, and `route_sasl` records it on the coordinator's own
`AccountConnection` so a refusal answered from a later storage or crypto
continuation still renders what that client accepted. The coordinator's
*virtual* connection for a federated carrier passes `false` — it negotiates no
capability, and the edge that holds the real client renders the line itself.

The frame is built exactly as `account_failure` builds the sibling carriers'
line, and `standard_reply`'s applicability table in
`crates/agenc-ircd-client-wire/src/render.rs` gained the same row the document
did, so the public renderer recognizes the shape with an empty context and
refuses it with any context at all.

## The failure stays closed

- The line precedes the numeric and never replaces it. Every refusal still
  ends in `904`, so a client that ignores standard replies cannot read a
  refusal as anything but a refusal.
- `sasl_action_result` classes the new action `Rejected`, so it can never
  contribute an `Ok` result to an observation.
- The action is unreachable from `complete(true, _)`, from `reject_logout`,
  from `tick`, and from the abort and too-long paths, each of which keeps the
  numeric it has today.
- A malformed envelope, an expired transaction and a storage refusal all reach
  `fail_route` and are reported as the same `UNAVAILABLE`, which is the
  indistinguishability Section 11.3 already requires of the sibling carriers:
  "No failure distinguishes conflict, rate limit, token, policy, malformed
  record, expired transaction, or storage outcome."

## The regressions

| Test | What it pins |
| --- | --- |
| `sasl_authority_unavailable::an_unavailable_authority_reports_itself_before_the_shared_numeric` | Each of the three waiting phases leaves `unavailable` as the pair, in that order. |
| `sasl_authority_unavailable::a_refused_credential_carries_the_numeric_alone` | `complete(false, _)` is the `904` alone and `complete(true, _)` is the `903` alone. |
| `sasl_authority_unavailable::every_other_refusal_keeps_the_numeric_it_has_today` | Abort, deadline expiry and a refused logout are unchanged. |
| `sasl_authority_unavailable::the_failure_line_is_a_recognized_shape_that_carries_no_account_context` | The exact bytes; any context is `InapplicableReply`; no capability is `CapabilityRequired`. |
| `account_service::tests::sasl_unavailable::an_unavailable_authority_names_itself_before_the_numeric` | The coordinator's own route emits both lines, in order, with the real prefix. |
| `account_service::tests::sasl_unavailable::a_client_without_standard_replies_reads_exactly_the_numeric` | The same route emits the `904` alone, which is today's transcript. |
| `account_service::tests::sasl_unavailable::a_refused_credential_never_names_the_authority` | A rejected completion renders the `904` alone **even with the capability negotiated**. |
| `account_service::tests::sasl_unavailable::an_accepted_authentication_never_names_the_authority` | An accepted completion renders the `903` alone. |
| `stage_ten_drills::deletion_drill_preconditions_are_the_ones_the_daemon_requires` | The live proof: with the coordinator stopped, a real client on a real edge reads the line, and `transient_transport` calls it transient. |

The live step is the one that settles it, and it is deterministic rather than
opportunistic. The ordinary non-ignored Stage 08 test already stops the
coordinator and restarts it; between those two calls an authentication now
reaches `edge-a` with nothing behind it, and the drill requires the refusal to
carry `FAIL AUTHENTICATE UNAVAILABLE`. Before this change that same step read
`904` and could not distinguish it from the deleted-login refusal the module
proves elsewhere.

## The drill workaround, removed

`deletion_session` carried a bounded retry that repeated **any** failure inside
`NETWORK_WAIT` and discarded the error unread:

```rust
Err(error) if Instant::now() < deadline => {
    let _retried = error;
    thread::sleep(Duration::from_secs(1));
}
```

That was a workaround for the carrier's silence and it is gone. The retry now
reads the carrier's own report, through the same predicate the capacity
campaign uses:

```rust
Err(error)
    if Instant::now() < deadline
        && super::stage_ten_capacity::transient_transport(&error) =>
```

Every caller of `deletion_session` negotiates `standard-replies`, so the line
arrives; a refused credential and a protocol failure are now returned on the
first attempt instead of being retried for the full network wait. The readiness
wait before each attempt is kept: it is an ordinary wait for `active_peers`,
not a workaround for an unreadable refusal.

## The capacity harness: yes, the pair is transient

`stage_ten_capacity::transient_transport` excluded `904` outright, with the
reason stated in its own test name —
`an_authentication_refusal_is_not_a_transient_transport_failure` — because a
transient authority and a wrong password arrived as the same line.

**It can now treat the pair as transient, and does.** The predicate checks the
failure line first and returns `true`; the bare-`904` exclusion is kept below
it, so a refused credential is still never transient:

```rust
if text.contains(AUTHORITY_UNAVAILABLE) {
    return true;
}
if text.contains(" 904 ") {
    return false;
}
```

Three facts make this safe rather than a relaxation. The line is emitted only
from `unavailable`, which a rejected completion cannot reach. It arrives
**before** the `904`, and the harness surfaces the first unexpected line it
reads, so the two cases cannot both appear in one error string. And every
session this module authenticates negotiates `standard-replies` through
`E2EE_CAPS`, so the line is actually sent to it — a harness that negotiated
nothing would see only the `904` and would correctly keep treating it as a hard
failure. The existing test keeps all five of its negative cases, including the
two `904` strings, and gains the positive one.

This is also the behaviour the issue asked for on the client side: a wrong
password must not be retried automatically, an unavailable authority should be
retried after a delay, and the campaign now does exactly that instead of
failing a node that would have served it a second later.

## Limitations

- The transient state is proved live by stopping the coordinator, which is the
  cleanest instance of an unreachable authority. The narrower races — a link
  closing mid-exchange, or a coordinator answering without a usable completion
  — reach the same `unavailable` door and are proved at the carrier and
  coordinator seams rather than live.
- The line does not distinguish *why* the authority is unavailable, and
  deliberately so: a malformed envelope, an expired transaction and a storage
  refusal are the same refusal, as they already are on the two sibling
  carriers.
- Nothing here changes the attempt budget. An unavailable authority still
  consumes the connection-wide attempt the carrier had already counted, so a
  client retrying on the same connection has at most one more.
- These are development-host runs of the Stage 08 fixture. Native release
  qualification of the whole drill campaign remains with REL-10 (#84).

## Evidence

Sources:

- `docs/ircd-architecture-and-implementation-spec.md` Sections 9.5 and 11.4
- `crates/agenc-ircd-client-wire/src/auth_transport.rs`
  (`SaslAction::AuthorityUnavailable`, `SaslTransport::unavailable`,
  `unavailable_actions`)
- `crates/agenc-ircd-client-wire/src/render.rs`
  (`failed_standard_reply_is_applicable`)
- `crates/agenc-ircd-runtime/src/account_service.rs`
  (`render_sasl_action`, `render_sasl_actions`, `sasl_action_result`,
  `route_sasl`, `fail_route`, `AccountConnection::standard_replies`)
- `crates/agenc-ircd-runtime/src/registration.rs`
  (`edge_sasl_line`, `edge_sasl_answer`, `route_edge_carrier`,
  `edge_carrier_answered`)
- `crates/agenc-ircd-runtime/src/remote_accounts.rs` (the virtual connection)
- `crates/agenc-ircd/tests/stage_eight_e2ee/stage_ten_drills.rs`
  (`deletion_session`, the live precondition test)
- `crates/agenc-ircd/tests/stage_eight_e2ee/stage_ten_capacity.rs`
  (`AUTHORITY_UNAVAILABLE`, `transient_transport`)

Commands and results at this branch (Rust 1.98.0, from the repository root):

```sh
cargo test -p agenc-ircd-runtime --all-features
# 1564 passed; 0 failed; 1 ignored (lib) and every integration target green
cargo test -p agenc-ircd-client-wire --all-features
# every target green, including the new sasl_authority_unavailable (4 passed)
cargo test -p agenc-ircd --test stage_eight_e2ee --all-features
# 36 passed; 0 failed; 16 ignored; 47.20s

# the deletion drill, whose workaround this removes
AGENC_STAGE10_DRILL_DIR=<dir> ./target/debug/deps/stage_eight_e2ee-<hash> \
  drill_deletion --ignored --nocapture
# 1 passed; 0 failed; 51 filtered out; 50.78s
# record: passed=true, six steps; refuse step reports
#   "unissued DELETE CONFIRM refused=true, state unchanged=true"

# every ignored Stage 10 drill, serially, through the already-built binary so
# the sweep holds no cargo lock
AGENC_STAGE10_DRILL_DIR=<dir> ./target/debug/deps/stage_eight_e2ee-<hash> \
  stage_ten_drills::drill_ --ignored --test-threads=1
# 15 passed; 0 failed; 37 filtered out

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean
cargo fmt --all
python3 scripts/requirements.py generate && python3 scripts/requirements.py check
# requirement ledger: ok (251 records)
python3 scripts/generate-stage-one.py
python3 scripts/check-stage-one.py check
# Stage-01 artifacts: ok (62 constants, 132 schemas, 132 vectors)
python3 scripts/check-source.py check
# source policy: ok (1008 Rust files)
python3 scripts/check-baseline.py
# specification baseline: ok
python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
# coverage self-test: ok (28 rejection cases)
python3 scripts/check-coverage.py audit conformance/critical-coverage.toml
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
# region anchors: ok
python3 /mnt/data/agenc-dev/tools/verify-regions.py .
# stale regions: 0
bash /mnt/data/agenc-dev/tools/static-checks.sh .
# STATIC CHECKS OK
```

The specification edit took the full refreeze: the requirement ledger and the
Stage-01 artifacts were regenerated, `RAW_HASHES` in `scripts/check-stage-one.py`
and the architecture entry in `docs/specification-manifest.txt` were repinned
by hand, and `conformance/spec-baseline.toml` was refrozen at the resulting
commit in a second commit, because `check-baseline.py` compares the working
files against `frozen_at_commit`.

## One reviewed region re-anchored by hand

Nine reviewed release-critical regions were displaced by the production edits
and re-anchored by `reanchor.py`, which may move a span only by finding the
exact reviewed text again and verifies each relocated span against its reviewed
span hash and its named item. A tenth could not be, and it is the one COV-07
(#145) predicted: `edge-account-response-phase` names the item
`edge_account_answer`, but its span began fifteen lines above that function,
inside the tail of `edge_sasl_answer` — one of the eighty-eight rows COV-07
recorded as offset from their item while still covering its declaration, and
deliberately left alone as "not this issue's class".

Those fifteen lines are exactly where this change rewrote `edge_sasl_answer`'s
render call, so the reviewed text no longer exists and the tool refused rather
than absorbing the drift, which is the behaviour COV-07 built it for. The row
is re-anchored onto `edge_account_answer` itself, the item it names and the only
code its claim describes, and the span it now covers was re-reviewed: the
outcome is accepted only through `edge_account_payload(outcome, kind, finish)`,
which matches the outcome arm against the carrier's kind and phase, and every
non-matching answer rejects the transfer and sends
`FAIL <command> UNAVAILABLE`, so "account creation and credential replacement
accept only matching operation and phase responses" holds over the new span.
The move and the re-review are recorded in the row's own `reason`.

The coverage source inventory was refreshed for the two new test files.
