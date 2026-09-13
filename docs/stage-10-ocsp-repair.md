# Stage 10 OCSP configuration repair

The separate Appendix C.3 revision in PR #31 declares the previously accepted
`tls_ocsp_staple_file` key. It specifies the public TLS/WSS purpose union,
protected-file and size bounds, presence requirements, and atomic reload.
It also makes the existing opaque-response behavior explicit: the daemon
does not establish certificate status or response freshness.

The configuration parser previously accepted a staple only for `client_tls`,
although the global required-staple policy also covered `client_wss`. Thus
an enabled WSS listener could neither omit nor provide its required staple.
The parser now accepts both public purposes. Onion, federation, local admin
and TLS admin purposes remain forbidden.

## Verification

The new WSS regression failed before the repair with `Scalars/InvalidValue`
for `tls_ocsp_staple_file`. It now checks the exact retained path for optional
and required staples, and checks the missing-staple refusal. A separate matrix
checks the precise field error for every forbidden purpose. The complete
configuration crate suite passes. Existing host-file protection and live TLS
staple-delivery tests remain part of the full implementation gate.

The specification validator passes with unchanged base-federation and E2EE
profile hashes. Coverage inventories bind the revised parser without changing
coverage thresholds. The complete `RUST_TEST_THREADS=1 CARGO_INCREMENTAL=0
bash scripts/check-stage-nine.sh` passed for combined implementation
`3a0efdf64c7beb3040ef6cf7549f71737ed9629d`, which includes this parser repair.
It ran in a temporary memory-backed checkout: 2,872 workspace tests passed,
21 existing tests were ignored, and coverage reached 75.2373% branches and
91.6569% lines, with all 20 interim critical regions at 100%. This includes
the feature matrix, concurrency models and fuzz smoke checks. The later
prerequisite merges changed only the earlier runtime validation report.

The specification and implementation merged in PRs #31 and #32. These are
functional checks; they do not qualify native ext4 production operation or
close a stage for a new exact source revision.

This repair does not close service-user checks, encrypted recovery, STO-1,
or native release qualification. The connection scheduling follow-up is
recorded in [the client input repair](stage-10-client-input-repair.md).
