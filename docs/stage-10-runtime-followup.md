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
trailing IRC arguments and missing role targets are included. The full gate,
coverage and live federation results will be recorded after their final run.

Encrypted historical recovery, retained witnesses, old MLS leaf authority,
conversation signing-key ownership, encrypted-object cleanup, STO-1, remaining
configuration findings and per-connection scheduling remain open.
