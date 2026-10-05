# The information queries an edge answers itself

This record covers BLJ-R1, a finding of the review of the SDK program's AUD-16
work, placed by the program's decision D-28 (2026-10-04, outside master #35).
It changes no wire format, numeric, reply code, registry, configured limit,
persistent format or specification text.

## What was observed

On an edge, `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN`, `INFO` and `LINKS`,
plain or labeled, got no reply: the edge closed the requester's connection
and logged `connection_closed ... error=protocol_error`. A core-only node and
a coordinator answered them. The SDK's liveness rule probes a connection
whose requests go unanswered with a labeled `TIME`, so its first probe on an
edge would have ended the session.

## Cause

The edge's registration router sent every information query to the node's
own command executor, the path a core-only node uses. That executor
authorizes a command against the node's own domain, and an edge's sessions
are not there: the edge holds them in its projection of the coordinator's
state. Authorization failed, and the router treated the failure as a
protocol error and closed the connection.

## Fix

The router now sends an edge's information queries down the edge's own
command path, like every other registered command
(`crates/agenc-relay-runtime/src/registration.rs`, `route_edge_command`).
There, in `crates/agenc-relay-runtime/src/federation/edge/request.rs`:

- `MOTD`, `LUSERS`, `VERSION`, `TIME`, `ADMIN` and `INFO`
  (`is_local_information_query`) are answered by the edge itself
  (`local_information`). Architecture Section 14 lists them with
  privacy-safe static or aggregate output, and the closed federation
  operation table of Section 20.5.2 carries no operation for them. The
  answer uses the single-node renderers (`query_render::information_frames`,
  which the core path now also uses): the edge's configured MOTD and public
  information, its build and its clock. `LUSERS` has one fixed form on an
  edge (`LusersForm::Static`, the program's decision D-35, which replaced the
  counted form D-28 first set): `251` and `255` with fixed text and no count,
  the same on every edge in every state apart from the server prefix, the
  nickname and the label. A coordinator and a core-only node keep their
  counted reply. The command is charged as a registered command, as on a
  single node, needs the requester's session in the projection and a
  registered connection, and its reply carries the request's label and batch
  (`client_render::logical_frames`).
- `LINKS` is the coordinator's directory query (`directory.links`), which the
  edge forwards as it forwards `WHO` or `NAMES`.
- While the edge is active, a query it answers itself still waits behind the
  connection's earlier work: while a request of the connection is in flight,
  or its origin update or a JOIN's NAMES continuation is pending, the query
  joins the connection's deferred commands, as any command does. When it is released,
  its reply is handed to the router as one more completion
  (`EdgeCompletion::LocalReply`), after the completion that released it, so
  the router renders the earlier request's reply first. The edge's other local
  read, the requester's own `MODE <nick>`, takes the same path; before, a
  released user-mode read was sent at once, ahead of the reply of the request
  it had waited for.
- While the coordinator link is down or recovering, the six queries are
  served, as Section 20.10 requires of strictly local account-independent
  queries, together with the user-mode read (`served_while_unavailable`).
  `LINKS` fails closed with `NETWORK_UNAVAILABLE`, as other global work does.

## The regressions

| Test | What it pins |
| --- | --- |
| `federation::edge::tests::local_information::an_active_edge_answers_its_information_queries_itself` | Through the edge's actor loop with a scripted coordinator: each of the six, plain, ends with its numeric to the requester and no `FAIL`; `LUSERS`, in its fixed form, and `VERSION` are pinned line by line; each of the six, labeled, is one labeled line or one labeled batch; the first request the edge sends afterwards is the directory query of a `LINKS`, so none of the six left the edge. |
| `...::a_partitioned_edge_still_answers_its_information_queries` | After the coordinator link closes and a `PRIVMSG` gets `NETWORK_UNAVAILABLE`: the six, plain and labeled, are answered, `LUSERS` in the same fixed form; `LINKS` gets `FAIL LINKS NETWORK_UNAVAILABLE`. |
| `...::a_local_answer_waits_behind_the_connections_pending_request` | Behind an unanswered `WHO`: a `TIME`, a `MOTD`, the user-mode read and a labeled `LUSERS` each wait (a `PING` sent after them is answered first), and each reply follows the `WHO`'s reply once the coordinator answers it. |
| `...::a_local_query_needs_the_session_in_the_projection` | Without the requester's session in the projection each query is refused with `RegistrationRequired` and nothing is forwarded. |
| `...::a_local_query_needs_a_registered_connection` | With the session projected but no registered connection to answer under, `TIME` is refused with `RegistrationRequired`. |
| `...::a_local_query_is_charged_as_a_registered_command` | With the requester's registered-command bucket exhausted, each query is refused with `ServerBusy`. |
| `stage_seven_federation::an_edge_answers_its_information_queries_and_keeps_the_connection` | The production binary, a coordinator and one edge: a guest on the edge sends the six and a `PING`, plain and then labeled, and reads every reply from the edge and the `PONG`; `LINKS` is answered through the coordinator; after the coordinator is killed and the edge reports the partition, the six are answered again, plain and labeled, `LINKS` fails closed and the connection stays open. |
| `stage_seven_federation::edges_answer_lusers_in_one_fixed_form` | The production binary, a coordinator and two edges: edge A serves one client and no channel, edge B two clients and a channel. Both answer `LUSERS` with the same fixed reply apart from the server prefix and the nickname, and edge A's reply stays the same after a `JOIN`, after a `PART` and after the coordinator is killed. |

## The fix, reverted

With the five production files restored to `6986ace` and every test kept,
all seven tests above fail. The three refusal tests, which call the edge's
command path directly, get `BadState`: that path had no answer for these
queries either, since its directory mapping refuses every information query
but `LINKS`. The other three edge tests receive nothing after the welcome,
and the daemon test reads `transport closed before the expected reply` after
the first query, because the router closed the connection. Two further runs
revert one part each:

- The completion that delivers a released answer, replaced by sending the
  answer at once inside the edge: only the waiting test fails (`TIME
  overtook the WHO`, the `391` before the `315`), which is how a released
  user-mode read behaved before.
- The partition rule, with the six no longer served while the link is down:
  the partitioned edge test fails (`FAIL MOTD NETWORK_UNAVAILABLE` instead of
  the MOTD), and so does the daemon test.

A scratch probe (not committed) sent `LINKS` alone first in the daemon test:
at `6986ace` it closes the connection; with the fix the coordinator answers
it.

With the counted `LUSERS` form restored (`query_render.rs`,
`federation/edge/request.rs` and `federation/replica.rs` at `4e12970`) and
every test kept, the active and the partitioned edge tests fail, because the
reply no longer ends with the fixed form's `255`, and
`edges_answer_lusers_in_one_fixed_form` fails because the two edges' replies
differ.

## Coverage

Both production source inventories are refreshed (1,011 files: the new test
module sits under `src/`). The release region
`runtime-edge-local-user-mode-authority` is respanned, since `local_user_modes`
now returns its reply instead of sending it; its reason is unchanged. Two
release regions are new: `runtime-edge-local-information-queries` binds
`is_local_information_query` and `runtime-edge-local-information-answer`
binds `local_information`. Other regions in the changed files moved with
their spans unchanged. With the fixed `LUSERS` form, the release region
`runtime-edge-static-lusers` binds `render_static_lusers`, and
`runtime-edge-local-information-answer` is respanned with its reason
restated; the inventories keep 1,011 files. Over the runtime library tests at this branch
(`RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime --lib
--all-features --branch --locked`, 2,683 passed), scored with
`check-coverage.py`'s counting:

| Item | Measure |
| --- | --- |
| `is_local_information_query` (new region) | regions 4/4 |
| `local_information` (new region) | regions 47/48; the unreached region is the renderer failure exit |
| `local_user_modes` (respanned region) | branches 4/4 |
| `local_answer` | regions 21/21, branches 2/2 |
| `served_while_unavailable` | regions 6/6, branches 2/2 |
| `route_command` | regions 78/88, branches 16/16 |
| `dispatch_one` | regions 17/17 |

## Compatibility

- Clients of an edge: the seven queries are answered instead of closing the
  connection. The six carry the single-node reply text, except `LUSERS`,
  which an edge answers in its fixed form, without counts. A released local
  reply now always follows the reply of the request it waited behind.
- Coordinators and core-only nodes: unchanged; they answer from their own
  domain as before.
- Federation, storage, registries and the specification: unchanged. No
  persistent state changes, so no restore test applies.
- Mixed builds: an edge built before this change still closes the
  connection on these queries, whatever the coordinator runs.

## Limitations

- An edge still refuses `JOIN` of a local `&` channel (BLJ-R2); that is a
  missing edge feature, placed on the owner's list by decision D-29.
- `LINKS` needs the coordinator, so it is unavailable on a partitioned edge.
- While the coordinator link is down or recovering, the edge defers no
  command (`must_defer_command` holds commands back only in the active
  phase), so a query answered then is not held behind a request of the
  connection that is still pending from before the link was lost; that
  request is resent once the link is back. The user-mode read behaved the
  same way before this change.
- The daemon test runs on the development host, not the release
  qualification hosts.

## Validation

At `415f7c6`, from the repository root:

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | clean |
| `cargo nextest run -p agenc-relay-domain -p agenc-relay-runtime -p agenc-relay-server --all-features --locked` | 3,158 passed (1 slow), 21 skipped |
| `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime --lib --all-features --branch --locked` | 2,683 passed, 1 skipped |
| `python3 scripts/check-source.py check` | ok |
| the SDK program's fast gate (agenc-relay-sdk `evidence/2026-09-29-server-rehearsal-pc001/tools/fast-gates.sh`, 59 commands), on the staged tree and at the commit | every command passes |
| `taskset -c 0-31 bash scripts/check-stage-nine.sh` | exit 1: 104 of 105 commands pass; the one failure is the storage disk profile (`cargo nextest run -p agenc-relay-storage --all-features --locked --profile disk`), whose qualification workload does not complete its free-space boundary cases on this host's XFS volume (`QualificationFailure { error: StaleState }`), the known failure of the base, unrelated to this change |

This section, and the two sentences on the partition, were added in a later
commit that changes this record only; the full gate was run again at that
commit.

## Review fix round

The program's review of this topic led to changes made in commits of their
own after the commits above:

- `LUSERS` on an edge takes one fixed form (decision D-35, which replaced the
  counted form of D-28), described under Fix, with its tests under The
  regressions and its revert under The fix, reverted.

Validation of the fixed `LUSERS` form, from the repository root before its
commit:

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | clean |
| `cargo nextest run -p agenc-relay-domain -p agenc-relay-runtime -p agenc-relay-server --all-features --locked` | 3,159 passed (1 slow), 21 skipped |
| `python3 scripts/check-source.py check` | ok |
| coverage policy refresh: both inventories, re-anchoring, both audits and self-tests | ok |
| the SDK program's fast gate (59 commands) on the staged tree | every command passes |
