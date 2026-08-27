# Stage 02 Closure Audit

Status: implementation findings resolved on 2026-08-26. Stage closure was
reopened after the evidence and requirement-ownership policies were tightened.

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

`bash scripts/check-stage-two.sh` passed on 2026-08-26. The run checked both Linux
targets, formatting, Clippy with warnings denied, tests, documentation tests,
dependency policy, advisories, generated artifacts, and all four deterministic
10,000-run fuzz smokes. Coverage was 90.03% of branches and 93.97% of lines.
The source revision and artifact digest are recorded in the Stage 02 evidence
manifest, but that manifest has no checked-in artifact path. It is archive
evidence and does not close `S02-900` under the current policy.
