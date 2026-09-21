# Stage 02 Evidence

Status: implementation complete; checkpoint closed for exact source commit
`1e5b738468f88b238061cc6e84b732176f5cae65`. The current schema version 2
[manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json)
binds 12 passed records to one clean Stage 02 gate run and its checked-in
[artifact](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/artifacts/stage-two-implementation-1e5b738468f88b238061cc6e84b732176f5cae65.json).
The [schema version 1
manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-02-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json)
for commit `8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` and the 2026-08-26 manifest
remain archive-only.

## S02-001

`EVID-S02-001-FRAMING` covers fragmented and coalesced reads at every split
point, exact and over-limit lines, terminators, NUL, UTF-8, timeout, EOF, and
empty-line accounting. Input is rejected as soon as the tag, command, or total
physical limit is exceeded, before a larger stream allocation.

## S02-002

`EVID-S02-002-WEBSOCKET` covers masked text fragmentation, control frames,
close payloads, invalid UTF-8, and shared IRC message limits. This checkpoint
covers framing. The HTTP/WSS listener is implemented in
[Stage 09](../docs/stage-09-operations.md).

## S02-003

`EVID-S02-003-TAGS` covers one-pass escapes, empty values, exact-case duplicate
handling, opaque keys, client-only counts, decoded-value limits, and canonical
output.

## S02-004

`EVID-S02-004-PARSER` covers uppercase canonicalization, client prefixes,
parameter forms, semantic text ceilings, numeric and time carriers, and every
Appendix-A public command shape before Stage 03 target resolution.

## S02-005

`EVID-S02-005-CAP` covers CAP 302, implicit `cap-notify`, atomic ACK/NAK,
dependency edges, LIST/END, continuation lines, and exact traditional reply
budgets inside the extended envelope.

## S02-006

`EVID-S02-006-REGISTRATION` covers generation-bound nickname ownership, USER,
CAP, authentication handoffs, deadlines, pending input, keepalive, closure,
and fixed welcome ordering. The state machine requests actions and owns no
socket or domain state.

## S02-007

`EVID-S02-007-AUTH` covers SASL and account-service carrier chunking, markers,
deadlines, tag prohibition, canonical Base64 forms, and move-only zeroizing
outbound text. OPAQUE, HPKE, and account policy remain Stage 04 work.

## S02-008

`EVID-S02-008-RENDER` covers allocation-free measurement, permit-bound
encoding, exact byte equality, tag ordering, the complete command envelope,
traditional CAP output, and typed standard replies.

## S02-009

`EVID-S02-009-REPLIES` covers empty, single, and multi-message labeled
responses, bounded parent-tagged batch nesting, and the ratified ASCII letter,
digit, and hyphen grammar for batch references. It also covers exact
standard-reply contexts and fail-closed mapping of every public reply shape.

## S02-010

`EVID-S02-010-TRANSCRIPT` covers the deterministic registration transcript and
its malformed forms. It records time, listener policy, capability state,
welcome ordering, exact rendered bytes, and secret-free handoffs.

## S02-011

`EVID-S02-011-FUZZ` covers the independent fuzz workspace. All four targets
passed 10,000 deterministic runs with seed 20260824, a 32,768-byte input
ceiling, a two-second input timeout, and a 512 MiB RSS limit. The 24 CPU-hour
campaign remains release task S10-004.

## S02-900

`EVID-S02-900-STAGE-GATE` records `bash scripts/check-stage-two.sh`. The current
run passed the inherited checks, both declared Linux targets, Clippy, tests,
documentation tests, dependency checks, generated-artifact validation, 90.01%
branch coverage, 95.59% line coverage, and four fuzz targets at 10,000 runs
each. All five critical regions reached 100%. The schema version 2 manifest has
a verified artifact path and closes `S02-900` for exact source commit
`1e5b738468f88b238061cc6e84b732176f5cae65`. Earlier records remain
archive-only.
