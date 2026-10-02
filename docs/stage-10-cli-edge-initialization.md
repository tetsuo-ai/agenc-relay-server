# Stage 10 edge initialized by `arcd init` serves

This record covers AUD-01 of the SDK readiness audit (2026-10-01, SDK
program, outside master #35). An edge created the way the operator guide
creates a node, `arcd init --coordinator-descriptor <file>
--coordinator-server-id <id>`, could never start. Its first `arcd serve`
printed

```text
arcd: runtime startup failed: durable state reconstruction refused the
recovered state: storage owner failed: storage state is stale or inconsistent
```

and exited 1. Only edges offer the encrypted profile
(`RegistrationRouter::with_e2ee_edge`), so no node an operator initialized
with `arcd` could serve an E2EE client.

## The defect

Initialization and reconstruction disagreed about the fake OPAQUE record.

- `initialize_database` (`crates/agenc-relay-runtime/src/offline.rs`) writes
  the fake record only from the coordinator's generated OPAQUE profile. An
  edge has no OPAQUE server setup, no fake-credential key and no
  account-service private key (Section 22.3: the fake-credential-ID key is
  coordinator-only, and edge initialization "never creates or requests the
  recipient private key"). The owner's tests pin that intent:
  `edge_init_imports_public_pins_without_creating_coordinator_secrets`
  requires `table_record_count(OpaqueRecord) == 0`, and
  `edge_onboarding_uses_read_only_reconstruction_without_fake_opaque_state`
  names it.
- `AccountServiceScan::finish`
  (`crates/agenc-relay-runtime/src/state_core/reconstruct.rs`) required the
  record for every role and refused its absence with `StaleState`.

Nothing on an edge reads the record. The only reader is
`account_service_config` in `crates/agenc-relay-runtime/src/daemon.rs`,
which builds the hosted account service and runs only for the
`Coordinator` role; an edge advertises the coordinator's account service
(`AccountServiceRole::Advertised`) and forwards every account request to it.

The daemon suites never saw this because they write every node's database
through `initialize_storage` with a fake record, edges included
(`initialize_database_with_header` in
`crates/agenc-relay-server/tests/stage_eight_e2ee.rs`); no test started
`serve` on a database `arcd init` wrote for an edge.

## What changed

- `reconstruct` takes the configured `NodeRole`, and `AccountServiceScan::finish`
  applies it: a coordinator database without the fake record is still refused
  with the same `StaleState`, at the same point and with the same printed
  line; an edge database without it is complete. A record an edge database
  was seeded with (every library-initialized fixture edge, and any
  workaround an operator applied) is still admitted under the unchanged row
  checks of `admit_fake_opaque_record` and is never read.
- `AccountServiceReconstruction::fake_opaque_record` returns an `Option`.
  The coordinator's account-service construction takes it through
  `hosted_fake_opaque_record`, which refuses an absent record as the same
  durable-state reconstruction refusal; reconstruction has already refused
  that database, so the arm is defensive.
- The runtime test fixtures (`test_support.rs` and the login-index fixture)
  pass the role their databases are seeded for.

No row, record kind, table or storage generation changes. A database that
`arcd init` wrote for an edge at `70c832c` starts unchanged; a coordinator
database is admitted exactly as before.

## Regressions

- `state_core::reconstruct::tests::only_a_coordinator_database_requires_the_fake_opaque_record`:
  the scan without a fake record finishes for an edge and refuses for a
  coordinator; a seeded record survives on either role.
- `offline::tests::initialized_databases_reconstruct_under_their_own_role`:
  the databases `initialize_node` writes for a coordinator and for an edge
  reconstruct under their own roles, through the real storage owner and the
  `reconstruct` that `serve` runs; the edge database is still refused under
  the coordinator role.
- `stage_eight_e2ee::cli_provisioning::a_cli_initialized_edge_serves_links_and_advertises_e2ee`
  (new module `crates/agenc-relay-server/tests/stage_eight_e2ee/cli_provisioning.rs`):
  a coordinator and an edge created by `arcd init`, the edge from the
  coordinator's `arcd print-onboarding` descriptor, with the operator's TLS,
  federation and E2EE edits. The edge starts, establishes its coordinator
  link, advertises `agenc.ag/e2ee-mls` and the coordinator's
  `agenc.ag/recovery` epoch, registers a client, and after a SIGKILL restarts,
  links again and registers again.

With the role rule reverted (an edge without the record refused again), all
three fail; the daemon test fails at once with the daemon's own line:

```text
edge-a.test.client exited with exit status: 1 before linking: arcd: runtime
startup failed: durable state reconstruction refused the recovered state:
storage owner failed: storage state is stale or inconsistent
```

With the five runtime files restored to their `70c832c` bytes and the new
test module kept, the daemon test fails with the same line.

## A CAP-01-style kill and restart, before and after

RUN-08 (issue #134) began as CAP-01's killed edge refusing its restart with
`runtime startup failed: storage owner failed: storage state is stale or
inconsistent`, the same text AUD-01 printed before #138 named the surface.
The question was whether this mechanism explains it, or anything in QA-04
(issue #175).

Four runs on this host, each killing an edge with SIGKILL and restarting it.
The library-edge runs are RUN-08's own `stage_ten_capacity::peer_loss_kill_drill`
(64 clients, the published budget, kill phases stepped across 0 to 34.5
seconds, every second restart killed again during its own startup); the CLI
run is a scratch variant of the new daemon test that kills a CLI-initialized
edge 24 times, with the phase stepped across 0 to 11.5 seconds after each
link, while eight clients join, message and leave channels on it.

| build | edge | kills restarted | refused |
| --- | --- | ---: | ---: |
| `70c832c` runtime | initialized by `arcd init` | never started | 1 of 1 first starts |
| `70c832c` runtime | library fixture (RUN-08 drill) | 21 of 21 | 0 |
| fixed | library fixture (RUN-08 drill, two runs) | 32 of 33 | 1 (see below) |
| fixed | initialized by `arcd init` | 24 of 24 | 0 |

No run ended on a refusal of this mechanism. The first base run and the first
fixed run ran side by side and were both stopped at the same minute by a
host-wide disturbance (all three base daemons stopped with `state core durable
outcome indeterminate: storage reported an indeterminate commit`, and the
fixed run's coordinator and edge A failed `phase=flush` at their final stop);
the fixed rerun, alone, stopped after 23 clean rounds when the controller's
`STATS RUNTIME` read was answered `FAIL STATS UNAVAILABLE RUNTIME`. The one
refused restart, in the disturbed fixed run, printed `E2EE sequencer
credentials file is invalid or does not match the sequencer key`: the
credentials read, which this change does not touch, on an edge whose database
held its fake record. It coincided with the disturbance, did not recur in the
23 kills of the rerun, and is recorded for the owner, not explained.

**The mechanism does not explain RUN-08 #134 or any QA-04 #175 item.**

- The mechanism refuses deterministically, on the first start of an edge
  whose database never held the fake record. Every CAP-01, RUN-08 and QA-04
  edge was written by the library fixtures, which seed the record, and no
  runtime path writes or deletes an `OpaqueRecord` row on an edge: the
  account service, the only writer, is hosted by the coordinator alone. A
  record present at initialization is present at every later restart, so
  this refusal cannot appear intermittently after a kill.
- RUN-08's own reproduction (three refusals in 209 kills at `99956df`) was
  labelled `edge federation restore at edge-projection-install`, a different
  surface, and was repaired there ([the peer-loss reproduction
  record](stage-10-peer-loss-reproduction.md)).
- QA-04's residue (the unexplained `FAIL ACCTCREATE UNAVAILABLE` on a
  single-node daemon, the drain safe point behind a pending snapshot install,
  and `flush` under extreme load) concerns a coordinator, which always holds
  its record, or shutdown phases, which reconstruction does not run.

Nothing here claims #134 or #175 fixed.

## Limitations

- The daemon test enrolls TLS certificates from the testkit CA and writes
  the federation peer records by hand, as an operator does; the federation
  signing public keys it pins are derived from the seeds `arcd init` wrote.
- At this commit the test's public sequencer credentials document still comes
  from the testkit builder, and the edge's own recovery epoch for the
  coordinator's peer record comes from the edge's `print-onboarding`.
- The kill experiments ran a debug build on a shared, heavily loaded host and
  are evidence about this mechanism, not a capacity or soak result; their
  logs are not part of this repository.
