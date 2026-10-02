# The recovery NOTE and the logged-in state in the welcome (SC-007)

This record covers SC-007, a server prerequisite the AgenC Relay SDK's server
cross-check lists as blocking its account flows. It is worked in the SDK
program the owner authorized on 2026-10-01, outside master #35, so no issue
exists for it. SC-007 has three parts, worked in this order:

| Part | Specification | State at this revision |
| --- | --- | --- |
| The recovery epoch NOTE in the welcome burst | Architecture Section 10.2 step 5 | Implemented (this record) |
| The authenticated account state (`900`) in the welcome burst | Section 10.2 step 6, Appendix E.2 | Not implemented |
| `900` after a post-registration login, and `ACCOUNT` to `account-notify` peers | Section 11.4 | Not implemented |

No specification text, wire registry, profile hash, persistent format or
dependency changes. No Stage 10 task box changes.

## The recovery NOTE

Section 10.2 orders the successful welcome burst. Its step 5 reads: "when
`agenc.ag/recovery` is negotiated,
`NOTE * RECOVERY_EPOCH <22-char-epoch> :Current server recovery identity`",
after the MOTD numerics or `ERR_NOMOTD` (step 4) and before the
authenticated account state (step 6). Section 9.5 registers `NOTE *`
`RECOVERY_EPOCH` with a 22-character epoch.

The client-wire state machine already planned `WelcomeStep::RecoveryEpoch`
exactly when the capability was enabled, and the testkit transcript model
rendered it, but `RegistrationRouter::welcome_frames` left the step empty, so
no daemon sent the NOTE. The router now keeps the recovery epoch it
advertises, which is the hosted account service's epoch on a coordinator or
standalone node and the advertised epoch on an edge, and renders the NOTE for
that step from the same field. The NOTE and the `CAP LS` value therefore
cannot disagree.

### Not gated on `standard-replies`

The NOTE is sent whenever `agenc.ag/recovery` is negotiated, whether or not
`standard-replies` is:

- Section 10.2 conditions it on `agenc.ag/recovery` alone.
- Appendix A.3 lists `agenc.ag/recovery` as standalone, with no required
  companion capability.
- The pinned IRCv3 standard-replies capability lets a server send standard
  replies that no other specification enables; Section 10.2 is such a
  specification.

Most of the daemon's own NOTEs are gated: `NOTE CHANCTL UPDATED` and the
`NOTE ACCT` replies are dropped without `standard-replies`, on the local and
the edge path. Only `NOTE ACCTCREATE CREATED` and `NOTE ACCTCRED CHANGED` were
ungated, and the recovery NOTE is built the same way, with
`WireMessage::new`. Its doc comment says which NOTEs are gated and which are
not.

### What a client sees

A client that requested `agenc.ag/recovery` receives one more line, the NOTE,
right after `376` or `422`. A client that did not request it sees no
difference. A client that treats `376` or `422` as the end of the welcome and
then reads its next reply may read the NOTE first.

### Commits

The three commits are adopted, with `git am`, from the SDK's server rehearsal
of 2026-09-29 (`evidence/2026-09-29-server-rehearsal-sc` in the SDK
repository), with the rehearsal trailer replaced by an adoption note and a
validation list:

| Commit | Rehearsal commit | Subject |
| --- | --- | --- |
| `ba66d283` | `b24be015` | Send the recovery epoch NOTE in the welcome burst |
| `1a400eeb` | `f2fb28e1` | Test the recovery epoch NOTE after pre-registration SASL and on an edge |
| `f03bfe9f` | `a32b2bff` | Correct the recovery NOTE comment on standard-replies gating |

The rehearsal's commits for SC-013, SC-001 and SC-002, which sat between the
first and the second of these, are not on this branch. The first two patches
apply unchanged, and their trees equal the rehearsal commits' trees
(`037a0a53` and `4ce350e4`). The third patch's inventory digests had been
computed over a tree that held those other commits, so its two inventory
hunks did not apply. The coverage source inventory was recomputed with the
checker's own `production_source_inventory` (999 files, `0c26cf3d…`). Its two
region hunks apply as rehearsed: `registration.rs` hashes to the rehearsal
tip's `b8f8c326…`, and both registration regions keep their spans.

## The regressions

| Test | What it pins |
| --- | --- |
| `registration::welcome_tests::a_recovery_client_gets_the_advertised_epoch_right_after_the_motd_group` | The local burst `001 002 003 004 005 005 005 251 422 NOTE`, with the NOTE equal to the fixture epoch and to the `CAP LS` value. |
| `registration::welcome_tests::the_epoch_note_follows_a_published_motd` | The NOTE follows `375 372 372 376`. |
| `registration::welcome_tests::the_epoch_note_needs_only_the_recovery_capability` | The same NOTE with `standard-replies` also negotiated; no NOTE with `standard-replies` alone or with no CAP at all. |
| `registration::welcome_tests::an_edge_registration_sends_the_epoch_note_after_the_motd_group` | The edge completion path, with and without the capability. |
| `welcome_burst::production_daemon_sends_the_recovery_note_only_to_a_recovery_client` | The production `arcd` binary, byte-exact against the fixture's epoch, with a `PING`/`PONG` barrier ending the burst. |
| `welcome_burst::production_daemon_sends_the_recovery_note_after_preregistration_sasl` | A client that authenticated with SASL before `CAP END` gets the same burst and NOTE. |
| `welcome_recovery::an_edge_sends_the_recovery_note_after_preregistration_sasl` | A production edge linked to a production coordinator: the recovery burst is the burst without the capability plus exactly the NOTE, byte for byte against the epoch the edge advertised. |

With the `RecoveryEpoch` arm building the NOTE but not sending it, all seven
fail at the burst comparison, which lacks the final `NOTE`; with the arm
restored, all seven pass.

The Stage 08 edge test keeps every registered connection open until its
scenario ends.

## Limitations

- A daemon test covers the edge only after pre-registration SASL; edge guest
  registrations are covered by the unit test of the edge completion path.
- Step 6 of the welcome and the post-registration login are not implemented at
  this revision, so an authenticated registration's burst still ends at the
  NOTE, or at the MOTD group without the capability.
- These are development-host runs. The full Stage 09 gate runs at the
  integration tip, not on this branch.

## Evidence

Sources:

- `docs/arc-architecture-and-implementation-spec.md` Sections 9.5 and 10.2,
  and Appendix A.3
- `crates/agenc-relay-runtime/src/registration.rs`
  (`RegistrationRuntimeConfig::recovery_epoch`, `welcome_frames`,
  `recovery_epoch_note`)
- `crates/agenc-relay-runtime/src/registration/tests/welcome.rs`
- `crates/agenc-relay-server/tests/stage_six_daemon/welcome_burst.rs`
- `crates/agenc-relay-server/tests/stage_eight_e2ee/welcome_recovery.rs`

Commands and results on this branch (Rust 1.98.0, from the repository root,
with `TMPDIR` on a short mode-0700 directory under the home cache):

```sh
# at each of the three commits: the rehearsal's fast static gate
bash fast-gates.sh <tree> <log directory>
# 59 of 59 exit 0 at ba66d283, 1a400eeb and f03bfe9f
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean at ba66d283 and f03bfe9f
cargo nextest run -p agenc-relay-runtime -p agenc-relay-server --all-features --locked
# ba66d283: 2815 tests run: 2815 passed, 21 skipped
cargo nextest run -p agenc-relay-server --all-features --locked
# 1a400eeb: 95 tests run: 95 passed, 19 skipped
cargo nextest run -p agenc-relay-runtime -p agenc-relay-server --all-features --locked \
  -E 'test(/welcome_tests::/) | test(/welcome_burst::/) | test(/welcome_recovery::/)'
# f03bfe9f: 7 passed; with the NOTE arm reverted: 7 failed
```
