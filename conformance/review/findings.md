# Stage 08 review findings

No external review has been performed yet. The implementing team's
[adversarial review](adversarial-review-2026-09-04.md) records the defects and
fixes found during the internal follow-up. External findings belong in the
table below; the internal report does not close this gate.

Each external finding gets one entry:

| Id | Reported | Severity | Surface | Summary | Disposition | Re-review evidence |
| --- | --- | --- | --- | --- | --- | --- |

A finding is closed only when the disposition names the commit that
remediated it and the gate run that re-verified the surface.

## Internal independent review, 2026-09-18

This section is appended separately from the external table above. The
2026-09-18 review was **internal**: it was performed by a reviewer that had no
context from the implementation and no stake in it, and it is not a
third-party audit. It does not close `S08-039`, and the statement at the top
of this file still holds.

| Id | Reported | Severity | Surface | Summary | Disposition | Re-review evidence |
| --- | --- | --- | --- | --- | --- | --- |
| ENC11-1 | 2026-09-18 | medium | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/membership.rs` (`verify`), against `membership_restore::restore` | Live `EGROUP SUBMIT MEMBERSHIP` verified a leaf-membership proof against the account's current root and roster, while companion 13.7.3 and startup reconstruction use the retained roster the proof names; after a routine roster or root rotation a conforming proof was refused live with `E2EE_BINDING_AUTH_INVALID` yet accepted on a reload. Stricter, never more permissive: a divergence with an availability edge, not an authority break. | Remediated by ENC-18 (issue #164, branch `enc-18-membership-named-roster`): `roster_snapshots::resolve` resolves the named root and retained roster snapshot, `verify` checks the proof against it, current roster activity stays the separate `attached_device` check, and a `removed` proof follows the same two rules (a revoked device states nothing). Record: `docs/stage-10-membership-named-roster.md`. Open until the merge commit and its gate run are named here. | Eight regressions in `tests/sequence/leaf_membership/named_roster.rs`, four of which fail on the unremediated `verify`; focused and full `agenc-ircd-runtime` and `agenc-ircd-e2ee` suites, strict clippy and the static checks on the branch. Gate: pending. |
