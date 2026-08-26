# Stage 02 Evidence

Status: complete on 2026-08-26. The machine-readable manifest in
`conformance/evidence/` binds these claims to the tested source revision.

## S02-001

`EVID-S02-001-FRAMING` covers fragmented and coalesced reads at every split
point, exact and over-limit lines, terminators, NUL, UTF-8, timeout, EOF, and
empty-line accounting. Input is rejected as soon as the tag, command, or total
physical limit is exceeded, before a larger stream allocation.

## S02-002

`EVID-S02-002-WEBSOCKET` covers masked text fragmentation, control frames,
close payloads, invalid UTF-8, and shared IRC message limits. The HTTP/WSS
listener remains Stage 09 work.

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
responses, bounded batch nesting, exact standard-reply contexts, and
fail-closed mapping of every public reply shape.

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

`EVID-S02-900-STAGE-GATE` is `bash scripts/check-stage-two.sh`. The 2026-08-26
run passed the inherited gates, both declared Linux targets, Clippy, tests,
documentation tests, dependency checks, generated-artifact validation, 90.03%
branch coverage, 93.97% line coverage, and four 10,000-run fuzz smokes.
