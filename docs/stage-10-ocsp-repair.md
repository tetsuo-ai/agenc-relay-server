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
coverage thresholds. Full-gate results will be recorded after completion.

This repair does not close service-user checks, encrypted recovery, STO-1,
per-connection scheduling, or native release qualification.
