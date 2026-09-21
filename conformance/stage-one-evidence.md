# Stage 01 Evidence

Status: implementation complete; checkpoint closed for exact source commit
`1e5b738468f88b238061cc6e84b732176f5cae65`. The current schema version 2
[manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-01-1e5b738468f88b238061cc6e84b732176f5cae65.json)
binds 14 passed records to one clean Stage 01 gate run and its checked-in
[artifact](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/artifacts/stage-one-implementation-1e5b738468f88b238061cc6e84b732176f5cae65.json).
The [schema version 1
manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-01-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json)
for commit `8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` remains archive-only.
The 2026-08-24 pass for commit
`7ae6439b472521d3c23fb99261deaf8964a70c5a` remains historical evidence.

## Verification summary

`bash scripts/check-stage-one.sh` passed under Rust 1.98.0 for both declared
Linux targets. The recorded Stage 00 and Stage 01 checks covered frozen
sources, generated artifacts, formatting, compilation, Clippy, all tests,
documentation tests, dependency policy, advisories, and branch coverage.
Measured workspace coverage is 90.01% branches and 95.59% lines. All five
critical regions reached 100%.

The independent artifact checker accounts for 53 closed registry constants,
all 128 Appendix B schemas, and one reviewed golden vector per schema. This
stage implements bounded representations and codecs only; client connection
state, domain behavior, persistence, cryptographic operations, and networking
remain assigned to later stages.

## S01-001

`EVID-S01-001-REGISTRIES`: generated typed registries match the frozen
Appendix A and Appendix B sources exhaustively. Independent checks reject
missing, duplicate, reordered, renumbered, and stale entries.

## S01-002

`EVID-S01-002-QUANTITIES`: ten private-field quantity families retain units and
inclusive bounds. Tests exercise minimum, one, maximum, maximum-plus-one,
overflow, and underflow behavior.

## S01-003

`EVID-S01-003-IDENTITIES`: domain-separated identifier types provide explicit
binary construction, canonical unpadded Base64url parsing, redacted debug
output, injected entropy, and account-specific grammar. Cross-domain and
alternate-encoding tests pass.

## S01-004

`EVID-S01-004-BOUNDED-VALUES`: bounded byte and UTF-8 types validate length,
encoding, NUL, and control policy before allocation. Boundary and hostile-input
tests cover owned and borrowed construction.

## S01-005

`EVID-S01-005-NAMES-MASKS`: nickname, login, account-label, display-name,
channel, server, cloak, and typed-mask values implement their exact canonical
profiles. Tests cover presentation/comparison separation, collisions, invalid
PRECIS input, prefixes, globs, and fixed cloak grammar.

## S01-006

`EVID-S01-006-PROTOCOL-ERRORS`: closed validation and public protocol errors
map exhaustively to fixed codes and safe descriptions. Error values retain no
raw input, internal chain, or implicit user-controlled rendering.

## S01-007

`EVID-S01-007-BINARY-CODEC`: the safe-Rust federation codec implements every
integer width, minimal length prefix, enum, structure, vector, and fixed union
without Serde. It requires full consumption, checked allocation and arithmetic,
an explicit value budget, and a bounded iterative parser stack.

## S01-008

`EVID-S01-008-APPENDIX-B`: all 128 common, projection, event, request, result,
origin, and snapshot schemas decode through exact registered arms. Semantic
negatives cover canonical IDs/names, revision and presence tuples, ordering,
envelope and union substitution, projected values, identity cross-references,
padding, and malformed embedded objects.

Request correlation uses the four ID fields as its presence discriminator.
An empty tuple requires both integer fields to be zero. A present tuple accepts
generation and operation-sequence zero because Section 20.5 assigns those
values to the pre-registration principal and the first request in a generation.

## S01-009

`EVID-S01-009-TEXT-CARRIERS`: client and federation carrier primitives enforce
uppercase tokens, exact arity, canonical decimal, canonical padded or unpadded
Base64 as selected, fragment arithmetic, and re-encode equality. Alternate
alphabets, padding, signs, zero forms, case variants, and overflow are rejected.

## S01-010

`EVID-S01-010-PROFILE-HASHES`: generated constants bind the raw architecture,
E2EE companion, registry, source ledger, and both derived profile hashes.
Independent single-byte mutations change the expected digest and fail checks.

## S01-011

`EVID-S01-011-REFERENCE-VECTORS`: the Python generator/checker and the testkit
reference encoder do not import production codec types. Production decode and
canonical re-encode agree byte-for-byte with all 128 checked-in vectors and
their SHA-256 provenance records.

## S01-012

`EVID-S01-012-TOTALITY`: every vector rejects every truncation and trailing
byte. Every schema is tested with a deterministic generated corpus at short,
length-prefix, and object-size boundaries. Successful decodes are re-encoded,
decoded, and re-encoded again under explicit budgets, with byte-for-byte
canonical agreement. Every parser error discriminant has a negative path.
Source checks require explicit nonrecursive stacks and reject recursive parser
mutations.

## S01-900

`EVID-S01-900-STAGE-GATE`: the recorded Stage 01 run passed with the pinned
lockfile and tools on both targets. Generated-source freshness, six artifact
checker mutations, all workspace tests, Clippy with warnings denied,
`cargo-deny`, `cargo-audit`, and the greater-than-90% branch threshold passed.
The current schema version 2 manifest records the required gate on exact source
commit `1e5b738468f88b238061cc6e84b732176f5cae65` with a verified artifact path
and closes `S01-900`. The schema version 1 record for commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` is retained as archive evidence.
