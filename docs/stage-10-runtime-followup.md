# Runtime and administration follow-up

This follow-up closes the connection-task isolation and generated admin UID
findings and repairs additional federated MODE argument conversion. It changes
no protocol registry, storage format, cryptographic primitive or dependency pin.

## Connection task ownership

The supervisor retains each child's name, failure policy and cancellation token
by Tokio task ID until join. Aborts and unwinds therefore keep their original
classification. A completed connection cancels its child token; critical failures
cancel the root. Missing registrations are internal critical failures. Listener
connection failures remain observable diagnostics while other clients continue
and new connections are accepted. The production panic hook still terminates
the process as required by Architecture 21.2.

## Generated administration

Initialization uses its effective UID for both local socket admission and the
generated operator identity. It does not infer authority from environment
variables. Root initialization still selects UID 0. Administrative signing-key
proof and the existing filesystem controls remain required. Root checks of
service-owned files remain a separate open finding.

## Federated mode arguments

Two new edge regressions reproduced SERVERBUSY for valid channel key and role
changes before the repair. The codec now adds/removes the existing uint16 key
length prefix and converts decimal limits to/from the required uint32 bytes.
Role requests resolve known nicknames to User IDs at the edge. The coordinator
resolves that exact ID to its current nickname, refusing unknown or malformed
IDs. Requests therefore cannot follow a nickname reassignment in transit.
Key bytes reach channel-key construction without their wire length prefix.
The live test exposed a second encoding defect: projected key presence used
one byte where the existing schema requires two, causing mutation staging to
refuse `+k`. Both directions now use the exact two-byte Presence encoding.
Replacing an existing verifier also emits its redacted key-state event, so the
origin receives confirmation even when key presence remains true.

## Validation

Focused supervisor, live TLS listener, generated-template, initialization,
edge request, wire codec and coordinator conversion tests cover positive and
negative paths. Exact binary key/limit vectors, all role codes and directions,
trailing IRC arguments and missing role targets are included. The live
three-daemon transcript passes key creation/replacement, keyed rejoining,
limit and voice changes, removals, coordinator restart and partition behavior.

`RUST_TEST_THREADS=1 CARGO_INCREMENTAL=0 bash scripts/check-stage-nine.sh`
completed with exit 0 for implementation commit
`99cfa80bbb71c7a7ccbd1e417d18e944d776c1ca` on 2026-09-13. The all-feature
workspace reported 2,867 passed and 21 ignored tests; documentation tests
passed. Coverage measured 75.2415% branches and 91.6499% lines, with all 19
reviewed interim critical regions at 100%. Thresholds are unchanged.
The inventory covers 778 production sources with digest
`67722e0d35bec037ed20350580ee6781c46f3b20bb9d0548743cad20ae50a4ab`.
The full local log is `/tmp/agenc-runtime-followup-stage-nine.log`.

GitHub Actions failed before starting jobs. The independent Bugbot rerun
found no issues, and the security review passed. This local implementation
gate includes x86_64/AArch64 compilation; it does not establish native
qualification on both targets or an exact-SHA stage closure.

Encrypted historical recovery, retained witnesses, old MLS leaf authority,
conversation signing-key ownership, encrypted-object cleanup, STO-1, remaining
configuration findings and per-connection scheduling remain open.
