# Stage 02 Closure Audit

Status: open on 2026-08-26. The Stage 02 implementation and complete local gate
pass, but the stage cannot receive revision-bound closure evidence yet.

This audit records blockers found while reviewing Stages 00 through 02. The
architecture specification remains authoritative. This file does not change a
wire rule.

## Frozen wire-size conflicts

Section 9.1 limits every command portion to 510 bytes. Section 9.4 requires
`TOPICLEN=1024` and forbids advertising a value larger than the implementation
enforces. Section 14.3 and the federation topic schema also admit a 1,024-byte
topic.

The smallest topic-setting command, `TOPIC #a :`, leaves 500 bytes for the
topic. A server `332` reply with a 253-byte server name, 32-byte nickname, and
64-byte channel name leaves 152 bytes. The specification excludes multiline
from the base profile and forbids using client `BATCH` as a transport. No Stage
02 renderer can satisfy all of these rules at once.

The federation `message` schema admits a 512-byte body. The smallest client
form, `PRIVMSG a :`, leaves 499 bytes under the same command limit. A delivered
message also needs a prefix and target. The base profile defines no carrier for
the remaining bytes.

The frozen specification needs one explicit policy for each case. Options
include lowering the semantic limit, defining a negotiated multiline carrier,
or changing the command-size rule. Implementation code must not choose one of
those policies on its own.

## Reply-shape gaps

The renderer rejects one conflicting reply shape and two mappings that the
typed Stage 02 API does not represent:

- Section 14.6 gives `NOTE CHANCTL UPDATED` without context, while Appendix E
  includes the channel.
- Section 14.6 defines `NOTE ACCT DELETE_CHALLENGE <22-character token>`
  exactly, but the Stage 02 typed reply context has no token variant.
- Registry entries without a public command, operation, and context mapping
  cannot be constructed through the public renderer.

Failing closed prevents an invented wire shape. `CHANCTL UPDATED` needs a
normative decision. `DELETE_CHALLENGE` needs a typed implementation in its
owner stage. Registry-only replies need explicit command and context mappings.

## Evidence gaps

`conformance/evidence/` contains no real JSON evidence manifest. The example is
deliberately non-claiming, and the evidence checker correctly accepts an empty
set of claims. The local Stage 02 fuzz record does not bind a commit, source
tree, lockfile, target, timestamps, or artifact hash. It is a development
record, not release evidence.

`conformance/requirement-bindings.toml` has no `S02-*` task binding. The three
client-wire invariants, `TRN-04` through `TRN-06`, are assigned only to
`S06-900`. Calling the current requirements checker with a Stage 02 task filter
would therefore test an empty set. Stage 02 needs reviewed requirement facets
before its gate can claim requirement coverage.

No evidence manifest should be created for an uncommitted tree. After the
normative conflicts and requirement facets are resolved, run the full gate on
one committed revision and record the exact source, lockfile, target, tool,
time, result, artifact, and limitation fields.

## Current review corrections

The 2026-08-26 Rust review corrected seven implementation defects in the local
working tree:

- fragmented client input now fails at its tag-side or command-side limit;
- RFC 3339 `:60` seconds require a structurally possible UTC month-end time;
- malformed complete commands refresh keepalive activity after deadline checks;
- outbound authentication chunks use move-only zeroizing text;
- federation events bind embedded home projections to the target server;
- authenticated federation origins require a session and user identity; and
- repeated singleton channel-mode changes are rejected even when their values
  differ.

Focused tests cover each correction. These results remain local development
evidence until a manifest binds the full gate to one committed revision.

The complete `bash scripts/check-stage-two.sh` run passed on 2026-08-26. Its
workspace coverage report recorded 1,833 of 2,036 branches (90.03%) and 11,106
of 11,820 lines (93.96%). The gate also ran both declared Linux target checks,
Clippy with warnings denied, workspace tests and documentation tests,
dependency policy and advisory checks, generated-artifact validation, and
10,000 deterministic fuzz runs for each of the four Stage 02 targets.

## Closure decision

Stage 03 must not begin under the current roadmap dependency. Local test
success is recorded as development evidence, but `S02-008`, `S02-009`,
`S02-011`, and `S02-900` remain blocked. The other Stage 02 checkboxes remain
open because the roadmap requires evidence tied to the relevant source
revision.
