# Silent post-TLS close diagnostics

This record closes the Stage 06 review follow-up that one recorded gate run
closed a fresh guest connection after the TLS handshake and before its first
reply (`production_daemon_credential_and_lookup_edges_fail_closed`). It is a
diagnostic and evidence closure (RUN-03, issue #45), not a newly proven
production failure: the incident did not reproduce in the thirteen suite runs
recorded at the time, and it did not reproduce in the strict campaign below.
It changes no protocol registry, storage format, cryptographic primitive,
configuration key, or dependency pin.

## What the listener can do to a fresh connection

After the TLS handshake the supervisor sends StateCore one open notice and
waits for the acknowledgement. Before this record every way that wait could
end without an accepted open produced an unattributable `connection_closed`
event with no error field, and two different causes shared one label:

| Wait outcome | Close label before | Close label now |
| --- | --- | --- |
| StateCore answered `Refused` (input slot, session table, or prefix bucket refused) | `Overload` | `Overload` |
| StateCore dropped the acknowledgement without answering | `Shutdown` | `Shutdown` |
| the connection token was cancelled while the answer was pending | `Shutdown` | `Shutdown` |
| no answer inside the 30 s inbox notice budget | `Shutdown` | `Deadline` |

The last row is the repair to classification: a StateCore that took the
notice but never answered it is a stalled owner, not a cancelled tree, and it
now carries the same `Deadline` label the registration, handshake, and
keepalive deadlines use. `CloseReason` stays a closed set; no label was added.

`connection_closed` now carries the typed public error field that Architecture
25.2 already allows, mapped from the closed `CloseReason` set:
`transport_loss`, `protocol_error`, `slow_consumer`, `read_stall`,
`write_stall`, `deadline`, `memory_exhausted` (overload), and `cancelled`
(shutdown). An orderly client `QUIT` carries no error field. Closes the daemon
chose for a misbehaving or stalled peer are logged at warning severity. The
event carries nothing else new, so the log still contains no address, login,
nickname, channel, or body by construction.

## Deterministic tests for every outcome

`crates/agenc-ircd-runtime/tests/listener_accept/admission_outcomes.rs` drives
the real listener, TLS, and supervisor with a scripted StateCore inbox and
forces each outcome once: accepted open followed by a routed `QUIT`, refused
open followed by a fresh admission on the same slot, a dropped acknowledgement,
cancellation while the answer is pending, a graceful `stop_accepting` and
`cancel_connections` shutdown, and a critical root-token cancellation. Each
test asserts the closed label the observer recorded, that the client saw no
reply, that the connection child was joined, that the whole memory budget
(base, queue backing, TLS setup) and the global client slot are back while the
listener still accepts, and, through the harness finish, that every handshake
slot and count slot returned exactly once. The 30 s deadline row runs under
paused time in `connection::supervisor::tests` against a duplex transport, so
it takes no wall-clock time and proves the transport closes without a reply
and the admission is released once.

`observe::events` and `observe::adapter` tests pin the close-label mapping,
its distinctness, the severity per reason, and the rendered field.

## Fixture evidence

The standalone daemon fixture (`crates/agenc-ircd/tests/stage_six_daemon.rs`)
now records phase markers, every fresh-connection attempt with its reason, the
daemon child's exit (joined status, killed after the stop budget, or killed at
drop without a join), and the first failure. Two test-only environment
variables control the evidence:

- `AGENC_IRCD_STAGE_SIX_RETAIN_DIR=<directory>`: a fixture that ends in a
  panic or a returned error copies its daemon logs (at most 4 MiB) and a
  `diagnostics.txt` record into `<directory>/<fixture-root-name>/` with mode
  `0700` on the directory and `0600` on every file. Only the daemon's own
  structured logs are copied; keys, the database, the configuration, and raw
  source addresses never are. A fixture that succeeds still removes its root.
- `AGENC_IRCD_STAGE_SIX_STRICT_ADMISSION=1`: every fresh-connection helper
  makes exactly one attempt, so a silent close after TLS fails the test.

Without the strict variable `connect_registered_guest` still retries a silent
close up to four times, only in the two recovery scenarios that call it (a
refused logout and a refused deletion, each of which may legitimately close the
connection), and every attempt and its reason is recorded and reported in the
final error. No timeout or retry count was raised.

`idle_healthy_admission_never_silently_closes_a_fresh_connection` is the
correctness test for idle healthy admission: eight sequential fresh TLS
connections must each register on their only attempt, and after shutdown the
daemon log must contain no `connection_closed` event labelled `deadline` or
`memory_exhausted`. `a_failed_fixture_retains_only_bounded_logs_and_diagnostics`
exercises the retention path directly.

## Strict repetition campaign

The affected test ran with strict first-attempt admission and retention
enabled, from the built test binary, on the x86_64 development host while an
unrelated repository gate was running on the same host.

| Mode | Runs | Result | Wall time per run |
| --- | --- | --- | --- |
| serial, strict, retention on | 10 | 10 passed, 0 retained | 24.0 s to 24.5 s |
| parallel, 4 processes per round, strict, retention on | 3 rounds (12 runs) | 12 passed, 0 retained | 24.1 s to 24.6 s per round |
| `idle_healthy_admission_never_silently_closes_a_fresh_connection`, strict | 5 | 5 passed | about 2.6 s |

Commands (from the built `stage_six_daemon` test binary, x86_64 host, 2026-09-15 17:29 to 17:34 UTC, while an unrelated repository gate ran on the same host):

```sh
export AGENC_IRCD_STAGE_SIX_STRICT_ADMISSION=1
export AGENC_IRCD_STAGE_SIX_RETAIN_DIR=<private scratch directory>
for i in $(seq 1 10); do $EXE production_daemon_credential_and_lookup_edges_fail_closed --exact; done
for round in 1 2 3; do for j in 1 2 3 4; do $EXE production_daemon_credential_and_lookup_edges_fail_closed --exact & done; wait; done
for i in 1 2 3 4 5; do $EXE idle_healthy_admission_never_silently_closes_a_fresh_connection --exact; done
```

No run failed, so no fixture was retained and the historical incident did not
reproduce. The root cause of the one recorded close therefore remains
unknown; what is now established is that the only listener paths that close a
fresh connection before its first reply are the four rows above, that each is
distinguishable in the daemon log, and that a recurrence will leave the
attributable log line plus the fixture's phase, attempt, and exit record. No
silently retried failure can pass the strict idle-admission test.
