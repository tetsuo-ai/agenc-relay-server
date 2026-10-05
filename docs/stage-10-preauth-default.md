# The pre-authentication command burst an account client can finish within

This record covers AUD-07 of the SDK's 2026-09-28 readiness audit, plan item
B-05 of the SDK program (2026-10-04, outside master #35). The program's
normative revision (P-01, commits `1a2419d` and `7075ea0`, recorded in
[the ReInit target revision record](stage-10-reinit-target-revision.md))
already states the corrected default: Architecture Section 19.1 and Appendix
C.6 give `preauth_command` one token per second with a burst of 24, inside
the unchanged hard row of ten tokens per second with a burst of 50, and C.6
explains the value. This branch makes the configuration and the runtime use
it. It changes no wire format, numeric, reply code, registry, hard limit,
persistent format, profile hash or specification text.

## What was observed

Every line a connection sends before its registration completes is charged
to that connection's `preauth_command` bucket, and a line beyond the credit
is answered with `263 * <command> :Please wait a while and try again.` and
not processed. The configuration's `RATE_ROWS` and the runtime's own default
table gave the bucket a burst of 10, the value the specification carried
before P-01.

An `ACCTCREATE` request (Section 11.3) sends its 16 `DATA` lines and its
`END` with no reply between them, so its client cannot know when they reach
the server, and network delay can deliver them at once. With a burst of 10
the end of such a run could be refused however the client paced it. The
SDK's account pacing model therefore refused account creation and the login
before registration (Section 11.4) at the template default outright, and the
daemon's own account tests ran only with the bucket raised to its hard row.
The value 24 and its derivation are decision D-14a of the program and the
ledger's Section 9: it is the smallest burst at which the SDK's pacing model
admits the 41-line creation and the 38-line login, each followed by
registration, within the 30-second registration limit of Section 8.3 at
round trips of up to 3 seconds.

## Change

- `RATE_ROWS` in `crates/agenc-relay-config/src/limits.rs` and
  `BucketKind::default_rate` in
  `crates/agenc-relay-runtime/src/admission/buckets.rs` give
  `preauth_command` the default 1/1, burst 24. The hard row stays 10/1,
  burst 50, and the existing equality test of the two tables
  (`config_and_runtime_rate_defaults_match`) keeps them together.
- The golden `public` configuration document
  (`crates/agenc-relay-config/tests/golden/public.toml`), which states every
  rate table at its default, states burst 24.
- `arcd init` writes no `[limits.rate]` table, so every node it initializes
  runs the C.6 defaults and takes the new value with no change to the
  template's text; a test now holds that for all three profiles.
- The operator guide gains a section on the budget: what the bucket
  charges, the default and the hard row, the `263` refusal, why the burst
  must cover an account request's 17-line run, and what lowering or raising
  it does.

The abuse budget changes within the hard row: at most 24 unauthenticated
lines of a connection are admitted at once instead of 10, and at most 54
instead of 40 before its 30-second registration limit closes it; a line
beyond the available credit is answered with `263` and is not processed.
Every line keeps its existing size and parse bounds, and account-service work
still starts only after the bucket admits the line that needs it.

`agenc.ag/privacy` stays `v1`: Section 26.2 changes that profile when
client-visible base semantics or mandatory limits change, and a default
inside an unchanged hard row is neither.

## Requirement IDs

None. The default appears in Section 19.1's table, Appendix C.6's table and
C.6's explanation, none of which carries a BCP 14 keyword, so
`scripts/requirements.py` extracts no clause for it and P-01 added none to
the architecture. The one requirement of Section 19.1
(`ARCH-REQ-AC500B2D79C7A16B554A`, the Tor clause, `S06-011`) is unrelated and
unchanged. `S06-011`'s admission evidence now agrees with the specified
default again, which the P-01 note listed as differing until this item.

## Regressions

| Test | What it pins |
| --- | --- |
| `agenc-relay-config` `boundaries::the_preauth_command_row_defaults_to_burst_24_within_the_hard_row` | The row is `preauth_command` with default 1/1, burst 24 and hard row 10/1, burst 50; the default table, the golden document and a document without the table all resolve to it; bursts 1, 24 and 50 are accepted and 51 is refused. |
| `agenc-relay-config` `template_onboarding::every_profile_runs_the_appendix_c6_rate_defaults` | A configuration written by `render_template` (`arcd init`) for the `public`, `onion` and `dual` profiles resolves every rate to its C.6 default, and `preauth_command` to 1/1, burst 24. |
| `agenc-relay-config` `boundaries::every_rate_row_is_checked_against_its_hard_ceiling` | (existing) Each row's hard row is accepted and a faster or burstier one refused; it edits the golden document's default block, so it needs the golden to state the default. |
| `agenc-relay-runtime` `registration::tests::preauth_lines_stop_at_the_exact_connection_burst` | A connection's bucket at the runtime default admits 24 lines at one instant and refuses the 25th, then admits one line after one second and refuses the next. |
| `agenc-relay-runtime` `state_core::lifecycle_tests::a_preauth_rate_refusal_keeps_the_transport_open` | (existing, now consuming the default burst rather than ten tokens) A line beyond the bucket is answered with `263 * PING` and the transport stays open. |
| `agenc-relay-runtime` `daemon::tests::config_and_runtime_rate_defaults_match` | (existing) The runtime default table equals the configuration's. |
| `stage_six_daemon` `preauth_budget::paced_account_creation_and_login_register_within_the_limit_at_the_template_rate` | The production binary with the template's rate table (the fixture's raised rows removed): a client paced to the bucket, one line per token, with a simulated 3-second round trip before it acts on each reply and every reply-less run delivered at once, creates an account and registers, then logs in before registration and registers with its `900`, each within 30 seconds of connecting. |
| `stage_six_daemon` `preauth_budget::a_client_beyond_its_preauth_burst_is_told_to_wait_and_stays_connected` | The same daemon: 25 `PING` lines in one write before registration get 24 `PONG`s and one `263 * PING`, and after one second a further `PING` gets its `PONG` on the same connection. |

The paced client in the daemon test applies the daemon's own refill rule,
whole refill periods from the first charge capped at the burst, on its own
clock, with 250 milliseconds of slack on each refill it waits for. Lines no
reply has shown read are held and written at once when the last of them
leaves, which is the delivery a burst must survive, and the first line after
each reply leaves three seconds after the reply was read, so the daemon sees
every exchange take a 3-second round trip. The flows are the daemon test
suite's own (`negotiate_sasl`, `create_live_account`,
`authenticate_live_account`, `complete_registration`): `CAP LS`, one
`CAP REQ`, then 39 or 36 account and registration lines. Measured at this
branch on the development host, the creation registered after 24.6 to 24.8
seconds and the login after 20.3 seconds in three runs. Scratch runs with
100 milliseconds of slack measured 18.4 and 14.1 seconds at a 1-second round
trip, 21.4 and 17.1 seconds at 2 seconds, and 24.5 and 20.1 seconds at 3
seconds, the last also under the gate's `cargo llvm-cov` instrumentation.
The time is set by the bucket and the round trips, not by the client's key
stretching, which overlaps the refill. The SDK's
model, with its own inputs (250 ms of server work per request, 1.5 s for the
client's finish and its pacing allowances), predicts 29.5 and 26.5 seconds at
3 seconds; this test shows that the daemon admits a client paced to the
bucket at that round trip, not the SDK's own margin.

## The fix, reverted

With the three values (`RATE_ROWS`, the runtime default and the golden
document) restored to burst 10 and every test kept, five tests fail:

| Test | Failure |
| --- | --- |
| `the_preauth_command_row_defaults_to_burst_24_within_the_hard_row` | the row's default is 1/1, burst 10 |
| `every_profile_runs_the_appendix_c6_rate_defaults` | the `public` template resolves to burst 10 |
| `preauth_lines_stop_at_the_exact_connection_burst` | the 11th charge at one instant is refused |
| `a_client_beyond_its_preauth_burst_is_told_to_wait_and_stays_connected` | 10 `PONG`s, then the `263` |
| `paced_account_creation_and_login_register_within_the_limit_at_the_template_rate` | the daemon answers the first `ACCTCREATE` run with `263 * ACCTCREATE :Please wait a while and try again.` |

`every_rate_row_is_checked_against_its_hard_ceiling`,
`config_and_runtime_rate_defaults_match`,
`validated_config_builds_exact_runtime_rates_limits_and_budget`,
`preauth_lines_beyond_the_burst_are_told_to_wait` and
`a_preauth_rate_refusal_keeps_the_transport_open` pass either way: they
guard the refusal path and the agreement of the tables, which the fix leaves
unchanged. With only the runtime default restored to 10,
`config_and_runtime_rate_defaults_match` and
`preauth_lines_stop_at_the_exact_connection_burst` fail.

## Coverage

Both production source inventories are refreshed. No reviewed region names
`RATE_ROWS` or `BucketKind::default_rate`. Four release regions in
`registration.rs` and `state_core/mod.rs`, above the changed tests, keep
their spans and take the new file hashes.

## Compatibility

- Operators: a node whose configuration names no `preauth_command` table
  runs burst 24 after an upgrade; an explicit table keeps its value. The
  hard row, and so every accepted configuration, is unchanged.
- Clients: a client paced to the old default is admitted as before, with
  more credit; a client that outruns the bucket is refused with the same
  `263`.
- Wire, registries, federation, storage and privacy: unchanged. No
  persistent state holds the default, so no restore test applies.
- SDK: its `PreAuthRate::DEFAULT` still says burst 10 and its pacing model
  refuses both flows at it; following the server's default to 24 is the
  SDK's item S-08.

## Limitations

- The round trip is simulated on loopback: the client waits before acting
  on each reply and holds each reply-less run, which reproduces the timing
  the daemon sees but not jitter or loss.
- The daemon test runs on the development host, not the release
  qualification hosts.

## Validation

At `5191617`, from the repository root:

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | clean |
| `cargo nextest run -p agenc-relay-config -p agenc-relay-runtime -p agenc-relay-server --all-features --locked` | 3,004 passed (1 slow), 21 skipped |
| the two `preauth_budget` daemon tests, three further runs | passed each time; account creation registers after 24.6 to 24.8 s and the login after 20.3 s |
| the SDK program's fast gate (agenc-relay-sdk `evidence/2026-09-29-server-rehearsal-pc001/tools/fast-gates.sh`, 59 commands), on the staged tree and at the commit | every command passes |
| `taskset -c 0-31 bash scripts/check-stage-nine.sh` | exit 1: 104 of 105 commands pass; the one failure is the storage disk profile (`cargo nextest run -p agenc-relay-storage --all-features --locked --profile disk`), whose qualification workload does not complete its free-space boundary cases on this host's XFS volume (`QualificationFailure { error: StaleState }`), the known failure of the base, unrelated to this change |

This section was added in a later commit that changes this record only; the
full gate was run again at that commit.

In the program's review fix round, a later record-only commit corrected the
abuse-budget sentence above and in the TODO note (lines are admitted, not
sent) and the description of the storage disk profile's failure. Its
validation: the check-release-claims.py document lint on the record and
TODO.md and `git diff --check` pass, and the SDK program's fast gate passes
on the staged tree.
