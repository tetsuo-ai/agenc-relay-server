# Stage 08 review findings

The [adversarial review](adversarial-review-2026-09-04.md) records the defects
and fixes found during implementation. The completed internal review findings
and their dispositions follow.

## Internal review findings

The rows below come from the internal review of the encrypted profile (issue
#76). The reviewers took no part in the implementation and worked without its
context, from the specification, this package and the source. The re-review
column names the focused regressions; the gate run that re-verifies each surface is
recorded with the pull request that merges the remediation.

| Id | Reported | Severity | Surface | Summary | Disposition | Re-review evidence |
| --- | --- | --- | --- | --- | --- | --- |
| ENC-EDGE-01 (ENC-15, #160) | 2026-09-18 | Medium | Edge ESTATE receiver, `e2ee/edge/snapshot.rs` | The edge staged every route a coordinator cut named without the base channel and account entitlement check companion 12.5 requires before READY, so a compromised or buggy coordinator could install direct-conversation state for account pairs the edge hosts nothing for. Not client-reachable. | Remediated: an unentitled entry refuses the whole snapshot with `E2EE_SYNCING` before READY with nothing retained; the witness resolution installer requires the hosted channel; the coordinator re-derives direct standing from hosting at every full cut. See [the edge review remediation record](../../docs/stage-10-review-remediation-edge.md). | `e2ee::edge::tests::snapshot` entitlement cases, `federation::edge::sync::pending_generation`, `e2ee::coordinator::tests::sync::a_full_cut_drops_direct_standing_the_edge_no_longer_hosts`, and the Stage 08 daemon suite |
| ENC-EDGE-02 (ENC-16, #161) | 2026-09-18 | Medium | Client E2EE admission, `registration.rs` `route_e2ee_line` | Every fragment line was charged a command token and a signature token, and the dedicated decoded-byte bucket of companion 16 did not exist: a maximum control object moved at about 18 percent of `MIN_ADMITTED_E2EE_INGRESS_RATE` and cost 1,427 verifications. Throttling, not a hard denial. | Remediated: command and signature tokens are charged on a command line or a fragment zero only; continuation fragments behind an accepted fragment zero pay decoded bytes to the fixed `E2eeIngress` bucket keyed by account and device; a fragment behind no accepted fragment zero pays for a command line and is refused. Same record. | `e2ee::edge::tests::ingress`, and the Stage 08 daemon suite under the relaxed pacer |
| ENC-EDGE-03 (ENC-17, #162) | 2026-09-18 | Low | Edge witness resolution, `e2ee/edge/witness_resolution.rs` | A resolution record verified under either credential of the negotiated key set at any time, although companion 12.5.1 admits the successor only during `MAX_SEQUENCER_KEY_OVERLAP`. Hardening; the signer is the coordinator. | Remediated: `SequencerKeySet::credential_at` admits the successor only from its `not_before` through the overlap at the second the record signed; outside it the link closes and the row is retained. Same record. | `e2ee::edge::tests` successor window cases, `agenc-ircd-e2ee` `a_successor_credential_is_admitted_only_inside_its_overlap_window` and `every_record_arm_states_the_sequencing_second_it_signed` |

A finding is closed only when the disposition names the commit that
remediated it and the gate run that re-verified the surface.

## Internal independent review, 2026-09-18

The 2026-09-18 review was performed by reviewers who had no context from the
implementation and no stake in it. Their findings and regressions are recorded
here.

| Id | Reported | Severity | Surface | Summary | Disposition | Re-review evidence |
| --- | --- | --- | --- | --- | --- | --- |
| ENC11-1 | 2026-09-18 | medium | `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/membership.rs` (`verify`), against `membership_restore::restore` | Live `EGROUP SUBMIT MEMBERSHIP` verified a leaf-membership proof against the account's current root and roster, while companion 13.7.3 and startup reconstruction use the retained roster the proof names; after a routine roster or root rotation a conforming proof was refused live with `E2EE_BINDING_AUTH_INVALID` yet accepted on a reload. Stricter, never more permissive: a divergence with an availability edge, not an authority break. | Remediated by ENC-18 (issue #164, branch `enc-18-membership-named-roster`): `roster_snapshots::resolve` resolves the named root and retained roster snapshot, `verify` checks the proof against it, current roster activity stays the separate `attached_device` check, and a `removed` proof follows the same two rules (a revoked device states nothing). Record: `docs/stage-10-membership-named-roster.md`. Open until the merge commit and its gate run are named here. | Eight regressions in `tests/sequence/leaf_membership/named_roster.rs`, four of which fail on the unremediated `verify`; focused and full `agenc-ircd-runtime` and `agenc-ircd-e2ee` suites, strict clippy and the static checks on the branch. Gate: pending. |

These findings come from an internal review, performed by reviewers with no
context from the implementation.

| Id | Reported | Severity | Surface | Summary | Disposition | Re-review evidence |
| --- | --- | --- | --- | --- | --- | --- |
| ENC-19 (#166) | 2026-09-18 | High | coordinator companion sync, companion 12.5.1 | The coordinator had no `EWITNESS` publication side and refused `EWITNESS REQUEST` as a protocol violation, so a blocked edge lost its link on every reconnect and a witnessed skip could never resolve. | Remediated by `d01ff62` "Answer EWITNESS REQUEST from the coordinator's retained chain" on `enc-review-remediation-coordinator`. | `edge/tests/witness_bridged.rs`, `coordinator/tests/sync/review_witness.rs`; gate pending. |
| ENC-20 (#167) | 2026-09-18 | Medium | coordinator startup, companion 12.4 and 13.7.3 | Reload treated every retained finalization request, including one below quorum, as a retained finalization and dropped certified abort and ReInit terminal identifiers. | Remediated by `7457a04` "Rebuild terminal proofs on reload from certified records only". | `coordinator/tests/sequence/review_reload.rs`; gate pending. |
| ENC-21 (#168) | 2026-09-18 | Medium | coordinator startup, companion 9.5 and 12.4 | Reload dropped the resulting council's counted votes of a pending bootstrap activation and swallowed every vote it could not replay. | Remediated by `33a9a22` "Replay bootstrap-activation votes under the council their signer sits on". | `coordinator/tests/sequence/review_reload.rs`; gate pending. |
| ENC-22 (#169) | 2026-09-18 | Medium | sequencing handlers and object ownership, companion 15 and 16 | A retained terminal request below quorum that added no counted vote had no owning row and bypassed `MAX_STORED_BYTES_PER_CONVERSATION`. | Remediated by `944a7c1` "Charge retained below-quorum terminal requests to their conversation". | `coordinator/tests/sequence/review_reload.rs`; gate pending. |
| ENC-23 (#173) | 2026-09-18 | Medium | coordinator route entitlements, companion 12.5 | The runtime never released a direct route reference on the live path, so a coordinator kept and restated every direct route it had ever projected to a Server ID; found by the internal reviewer while remediating ENC-15 and fenced there at cut time only. Not client-reachable. | Remediated: a departure marks the edge's direct standings, the next event-bearing plan hides an unhosted one with `route_state_hidden` and drops its references with the commit, fenced and unreplayed origins no longer count as hosting, and an interrupted cut naming an unhosted pair is retired instead of republished. The cut still names every bound pair of a hosted account, kept for the edge-side downgrade refusal. See [the direct route release record](../../docs/stage-10-direct-route-release.md). | `e2ee::coordinator::tests::direct_release`, `e2ee::edge::tests` `direct_release` bridged regressions, the domain `direct_entitlement` ledger test, and a `rust-gdb` trace of the count before and after |
