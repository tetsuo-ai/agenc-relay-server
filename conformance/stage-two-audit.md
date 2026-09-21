# Stage 02 Closure Audit

Status: implementation findings resolved on 2026-08-26. Exact-source closure
was recorded on 2026-08-27 after the evidence and requirement-ownership
policies were tightened.

This audit records the issues found during the Stage 02 review and how each
one was closed. The architecture specification remains authoritative.

## Wire-size resolution

The former command limit conflicted with the required topic and message body
limits. Architecture section 9.1 now defines one complete base-profile
envelope: at most 4,096 tag-section bytes, 8,701 command bytes, and 8,703
physical bytes including CRLF. CAP replies retain the traditional 512-byte
compatibility target. The stream, WebSocket, parser, renderer, tests, vectors,
and fuzz target enforce the same limits.

## Reply-shape resolution

The standard-reply table now assigns an exact public command, operation, code,
and context shape to every exposed reply. `CHANCTL UPDATED` carries its channel
context. `ACCT DELETE_CHALLENGE` uses a typed, move-only deletion token and the
renderer produces the exact registered shape. The token comparison is
constant-time and the token has no public text or debug representation.

## Traceability resolution

`TRN-04`, `TRN-05`, and `TRN-06` cover more than the Stage 02 client parser.
Their complete closure now belongs to `S08-900`, after every external E2EE
parser and state boundary exists. `python3 scripts/requirements.py
check-stage-two` still checks the full ledger for stale source bytes, mappings,
ownership, and generated output before it reports the Stage 02-owned subset.
CI also checks the fuzz workspace with the pinned nightly formatter.

## Verification

`bash scripts/check-stage-two.sh` passed on 2026-08-27 for exact source commit
`1e5b738468f88b238061cc6e84b732176f5cae65`. The run checked both Linux
targets, formatting, Clippy with warnings denied, tests, documentation tests,
dependency policy, advisories, generated artifacts, and four fuzz targets at
10,000 runs each. Coverage reached 90.01% of branches and 95.59% of lines, with
all five critical regions at 100%. The current schema version 2
[manifest](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/stage-02-1e5b738468f88b238061cc6e84b732176f5cae65.json)
and checked-in
[artifact](https://github.com/tetsuo-ai/agenc-relay-server/blob/1578b639b0aa6a42fececdc9752ab3f258a9ac61/conformance/evidence/artifacts/stage-two-implementation-1e5b738468f88b238061cc6e84b732176f5cae65.json)
close Stage 02. The schema version 1 manifest for commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` and the 2026-08-26 manifest remain
archive-only.
