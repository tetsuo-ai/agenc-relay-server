# Stage 02 Evidence

Status: provisional local development record on 2026-08-26. No Stage 02 JSON
evidence manifest binds these results to a committed source revision.

This record covers the bounded client-wire implementation. The architecture
document remains authoritative. These tests show what the current working tree
and fixtures enforce. The [closure audit](stage-two-audit.md) lists the frozen
specification and evidence blockers that keep the stage open.

## S02-001

`EVID-S02-001-FRAMING` is the `stream_framer_*` test set in
`crates/agenc-ircd-client-wire/tests/stage_two_wire.rs` and
`framing_incremental_budgets.rs`. It checks fragmented and coalesced reads at
every split point, exact and over-limit lines, CRLF, bare CR/LF, NUL, invalid
UTF-8, timeout, EOF, and empty-line accounting. Fragmented input is rejected on
client-tag byte 4,095 or tagged-command byte 511, before a delimiter arrives.
The exact composite maximum of 4,094 tag bytes and 510 command bytes is
admitted without a larger stream allocation.

## S02-002

`EVID-S02-002-WEBSOCKET` is the `websocket_*` test. It checks masked text
fragment reassembly, protocol violations, invalid UTF-8, and oversize close
codes. The optional HTTP/WSS listener remains Stage 09 work.

## S02-003

`EVID-S02-003-TAGS` is the `tags_*` test and the checked client-wire vector
file. It covers one-pass escapes, empty values, exact-case duplicate handling,
opaque keys, client-only counts, decoded-value limits, and canonical output.

## S02-004

`EVID-S02-004-PARSER` is the `syntax_parser_*` test and
`crates/agenc-ircd-client-wire/tests/registration_command.rs`. They cover
uppercase canonicalization, forbidden client prefixes, 15 parameters, middle
and trailing parameters, and every closed Appendix-A public command shape and
bound before Stage 03 applies target resolution or authorization. Millisecond
timestamps validate the Gregorian date and table-free RFC 3339 leap-second
shape. A `:60` second is admitted only at UTC month-end `23:59:60`.

## S02-005

`EVID-S02-005-CAP` is the `capability_requests_*` test,
`capability_dependencies.rs`, and `capability_reply_budget.rs`. They check
exact-case names, CAP 302, implicit `cap-notify`, atomic ACK/NAK, every Appendix
A.3 dependency edge, LIST/END, and LS-only continuation lines. The reply-budget
tests derive the conservative 212-byte token-list limit from the frozen maximum
server name and nickname, exercise its exact and plus-one boundaries, and check
that an oversized ACK/NAK echo or projected LIST cannot mutate capability
state. `scripts/generate-stage-one.py --check` also guards the complete
bare-name capability registry.

## S02-006

`EVID-S02-006-REGISTRATION` is the `registration_*` test set. It checks
generation-bound nickname reservation, replacement, release, and commit
results; USER handling; the 30-second deadline; pending-input bounds;
idempotent closure; and fixed welcome-group order. Ownership tests reject stale
acceptance, retain an old lease after replacement failure, and release an
accepted stale reservation. Transcript branch tests cover pre-registration
rejection, constant-time exact PASS comparison in the test driver, matching and
wrong PONG values, authenticated and unauthenticated commit results, timeout
closure, and typed auth handoffs. Every complete incoming message refreshes the
keepalive activity time after deadline precedence, including a message that
later fails command grammar. The state machine requests external actions and
owns no socket or domain state.

## S02-007

`EVID-S02-007-AUTH` is the `sasl_transport_*` and `account_transfer_*` test
set. SASL uses padded Base64 with the exact 4,726/4,342-byte envelope shapes.
Account creation and credential carriers use unpadded Base64url, fixed chunk
counts, tag prohibition, and 15/60-second deadlines. Outbound response chunks
use move-only, redacted text values that wipe their full allocation on drop;
partial construction unwinds through the same owner. Stage 04 owns OPAQUE,
HPKE, credential processing, and account policy.

## S02-008

`EVID-S02-008-RENDER` is the renderer test and
`test-data/vectors/client-wire-budgets.toml`. Measurement performs no output
allocation. Encoding consumes a covering permit, produces the measured byte
count, applies exact line budgets, and orders server tags before client-only
tags. The public numeric constructor rejects unvalidated numeric messages, and
standard replies use an explicit operation, code, and context map.

This task remains blocked. The frozen 510-byte command limit cannot carry the
required 1,024-byte topic or the 512-byte federation message body. See the
[closure audit](stage-two-audit.md#frozen-wire-size-conflicts).

## S02-009

`EVID-S02-009-REPLIES` is the labeled-response portion of the renderer test.
An empty semantic response emits one labeled `ACK` when labeled-response is
negotiated. Single replies carry one direct label. Multi-message replies use
two BATCH wrappers with the label rendered once. The move-only batch stack caps
nesting at 32 and semantic replies at 512. Undefined or conflicting reply
shapes fail closed as listed in the
[closure audit](stage-two-audit.md#reply-shape-gaps).

## S02-010

`EVID-S02-010-TRANSCRIPT` is
`test-data/transcripts/client-registration-v1.transcript` and the testkit
client transcript tests. The fixture uses evidence-bound pipe records with
literal ASCII or lowercase hex payloads and deterministic time steps. The
test driver accepts an explicit listener policy and capability profile, splits
long CAP LS replies, and records secret-free auth and registered-command
handoffs instead of discarding them. Branch tests observe the complete welcome
step order, exact recovery notice, pending frame byte count, account result,
and batch state.

## S02-011

`EVID-S02-011-FUZZ` is the independent `fuzz/` workspace and the local
`conformance/stage-two-fuzz-smoke.toml` record. On 2026-08-26, all four targets
passed 10,000 deterministic runs with seed 20260824, `max_len=32768`, a
two-second input timeout, and a 512 MiB RSS limit. Client-state fuzzing has one
structured seed for each of the 29 public Appendix-A command families. The
record lacks the revision and artifact fields required for closure. The 24
CPU-hour campaign remains release task S10-004.

## S02-900

`EVID-S02-900-STAGE-GATE` is `bash scripts/check-stage-two.sh`. It includes the
complete Stage 01 gate, validates generated artifacts and malformed fixtures,
builds the isolated fuzz workspace, checks dependency policy, and runs all
four fuzz smoke targets. The 2026-08-26 working-tree run passed. Its merged
coverage report recorded 1,833 of 2,036 branches (90.03%) and 11,106 of 11,820
lines (93.96%), and each fuzz target completed 10,000 deterministic runs. This
local result cannot close Stage 02 until the specification blockers, Stage 02
requirement facets, and a revision-bound evidence manifest are resolved.
