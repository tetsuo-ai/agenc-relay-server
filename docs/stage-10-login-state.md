# The recovery NOTE and the logged-in state (SC-007)

This record covers SC-007, a server prerequisite the AgenC Relay SDK's server
cross-check lists as blocking its account flows. It is worked in the SDK
program the owner authorized on 2026-10-01, outside master #35, so no issue
exists for it. SC-007 has three parts, worked in this order:

| Part | Specification | State at this revision |
| --- | --- | --- |
| The recovery epoch NOTE in the welcome burst | Architecture Section 10.2 step 5 | Implemented |
| The authenticated account state (`900`) in the welcome burst | Section 10.2 step 6, Appendix E.2 | Implemented |
| `900` after a post-registration login, and `ACCOUNT` to `account-notify` peers, on a coordinator or standalone node | Section 11.4 | Implemented |
| The same for a session an edge homes, and `ACCOUNT` to the peers other edges home | Section 11.4 | Not implemented |

The login of a session an edge homes also needed two corrections on the path
it takes through the coordinator. Each has its own commit and regression:

| Correction | Specification | State at this revision |
| --- | --- | --- |
| A recomputed channel membership keeps the revision it joined at on the federation wire | Section 20.6 | Implemented |
| An edge declares the account of a registered connection's login in its next origin generation | Section 20.7 | Implemented |

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

## The welcome `900`

Section 10.2 step 6 follows the NOTE with "the authenticated account
numeric/tag state, when present", and Appendix E.2 shows the line:

```text
:<server> 900 <nick> <nick>!<user>@<host> <public-account-label-or-*> :You are now logged in
```

The client-wire state machine already planned `WelcomeStep::AccountState`
exactly for a registration that bound an account, after the recovery NOTE
when there is one and after the MOTD group otherwise, and the router left the
step empty. The router now renders it:

- On a coordinator or standalone node it reads the session from the domain
  (`mutation_render::logged_in`). On an edge it reads the session projection
  the coordinator installed on the home edge (`EdgeFederation::logged_in`).
  That projection is in the replica before the edge completes the
  registration: the coordinator appends a request's completion event after
  the events of its plan (`append_completion`), and the edge completes a
  session open only once it has applied that event.
- The mask is the session's public prefix from the same function that renders
  every other prefix of that session (`session_prefix` locally,
  `render::prefix` on an edge), so a change to the cloak spelling changes both
  together.
- The label is the account's public label, or `*` when the account has none.
- A bound session the router cannot find, one without an account, or an
  account the domain does not hold fails the whole burst closed: nothing of
  the welcome is sent and the connection closes. A welcome without its
  account state is never sent.
- A guest's burst is unchanged: the state machine plans no account state for
  it.

`client_render::LoggedIn` holds the mask and label and builds the numeric, so
the local and edge paths, and the post-registration login, share one
rendering. The testkit transcript model renders the same step for its
authenticated scenario, with the model's deterministic cloak and `*`.

Appendix E.2 shows `001` directly followed by `900`, which conflicts with
Section 10.2's order; Section 10.2 governs. Correcting E.2 is a normative
change and is not part of this branch.

### What a client sees

An authenticated registration's burst gains one line, the `900`, after the
NOTE when `agenc.ag/recovery` was negotiated and after `376` or `422`
otherwise. A client that reads the welcome only up to `376` or `422` then
reads the `900` first. The daemon tests' own registration helpers did exactly
that. They now remember a SASL success and read the `900` after the MOTD
group: `ArcClient::complete_registration` in the Stage 06 and Stage 08
binaries, the Stage 10 drills' `account_login_named` and the capacity
campaign's `opaque_login_once`, each through `read_account_state`, which
requires the line's shape.

## The post-registration login

Section 11.4 ends a successful SASL exchange with the fixed sealed response and
`903`, and requires the client to check the committed completion against "the
later 900/session state". A login before registration is named by the
welcome's `900`. A registered session that logs in, or authenticates again to
the account it holds, read only the `903`: the account service rendered the
carrier's frames and nothing else.

The account service now renders a registered session's successful finish with
`mutation_render::render_account_login` (decision D-13 of the SDK program):

- The connection that logged in receives the carrier's frames, which end with
  `903`, and then `900 <nick> <nick>!<user>@<host> <label-or-*> :You are now
  logged in`, built by the same `client_render::LoggedIn` as the welcome's.
  The `903` stays first, so a client that reads exactly one line after the
  completion still reads it.
- A guest that logged in changes its public account state. Every local
  recipient of the account switch that negotiated `account-notify`, the
  session itself included, receives `:<mask> ACCOUNT <label-or-*>`, after the
  `900` on the requester's own connection. That is the set and the form a
  logout already uses for `ACCOUNT *`.
- A same-account reauthentication changes no public state: its plan is the
  account-service checkpoint, so only the `900` repeats.
- A coordinator serving the login of a session an edge homes does so through
  an internal carrier, which is not that session's connection on the
  coordinator. It gets no `900`, because the captured carrier frames become
  the federated result the edge renders. The coordinator's own clients that
  share a channel with that session still receive the `ACCOUNT` line.
- The frames are part of the same fanout that commits with the login's
  durable batch, so nothing is sent for a refused login.

No `901` is sent on logout, and a logout is unchanged.

## Account switches of channel members on a federated network

An account switch rewrites the session's membership in every channel it
joined and advances each of those channels, so the coordinator projects one
`channel_memberships_recomputed` event per joined channel to every edge with
a member in it. The domain keeps each membership at the accepted revision it
joined at: that revision is immutable, fences history reads, and is what the
coordinator's history authorization tuple and the edges' copies carry. The
federation codec's semantic check `validate_membership_recompute` required
every membership in the event to carry the event's resulting revision
instead. The projector therefore could not encode the event, the coordinator
refused to stage the switch, and a session that shared a channel with any
member an edge homes could neither log in after registration (its node
answered `904`) nor log out, whichever node homed it.

Section 20.6 does not ask for the equality: the recompute arm, like PART,
KICK, mode and topic, "carries the resulting revision explicitly", while
`member_joined` is the event that uses its membership revision as the
resulting one. The check now binds each recomputed membership to the event's
channel and requires its revision to be nonzero and not above the resulting
revision. Both the coordinator's encoder and an edge's decoder apply it. The
account-grant recompute of a registered channel (a prefix mode on an
authenticated target) is encoded under the same rule. No producer, schema,
registry, vector or profile hash changes.

Compatibility: an edge built from 70c832c or earlier still requires the
equality when it decodes such an event, so it refuses the event a corrected
coordinator sends; the coordinator and its edges are upgraded together.

## An edge's origin after a post-registration login

An edge declares every client connection to the coordinator as an origin
whose principal (the session and the account) the coordinator checks before
it serves an account-service request under it. Section 20.7 requires "a
session registration, login, logout, account switch, or companion device
attach/detach" to be "represented by the next generation before requests
under it are accepted". The edge did this for a session registration, but
not for a login after registration: the origin kept declaring a guest. The
coordinator commits such a login and switches the session's account, so the
connection's next account-service request named a principal that no longer
matched the session, and the coordinator refused it. A same-account
reauthentication therefore failed with `904` after the first login. The edge
also builds a credential change only for an origin that declares an account,
so it refused one for such a connection without sending it (read from the
code; not exercised by a test here).

When a registered connection's SASL finish comes back authenticated, the edge
now records the account in the origin and declares the next generation, as it
does for a registration. Every later request of the connection already waits
for an outstanding declaration's acknowledgement and then travels under it.
A login before registration is declared by the session open, as before, and a
reauthentication to the account the origin already names declares nothing.
The companion origin mirrors each acknowledged base generation and follows
the same way. No wire, registry or persistent format change: the origin
record and its journal row already carry the account.

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

The welcome `900`:

| Test | What it pins |
| --- | --- |
| `registration::account_state_tests::an_authenticated_local_burst_ends_with_the_logged_in_state_after_the_note` | The local burst `001 002 003 004 005 005 005 251 422 NOTE 900`, the `900` byte-exact against a mask built from the session's cloak, with `*` for an account without a label. |
| `registration::account_state_tests::the_logged_in_state_names_the_public_label_right_after_the_motd_group` | Without the recovery NOTE the `900` directly follows `422`, and names the account's public label. |
| `registration::account_state_tests::a_local_burst_whose_session_has_no_account_state_fails_closed` | A bound session the domain does not hold, and one without an account, close the connection with nothing sent. |
| `registration::account_state_tests::an_authenticated_edge_burst_reads_the_logged_in_state_from_the_replica` | The edge completion path: the `900` reads the coordinator's session projection, label included. |
| `registration::account_state_tests::an_authenticated_edge_burst_without_its_projection_fails_closed` | An edge without the projection sends nothing of the burst and closes the connection. |
| `welcome_burst::production_daemon_sends_the_recovery_note_after_preregistration_sasl` | The production binary: `… 422 NOTE 900`, and `… 422 900` without the capability, each `900` byte-exact, its mask equal to the prefix of the session's own `JOIN` echo. |
| `welcome_recovery::an_edge_sends_the_recovery_note_after_preregistration_sasl` | The same through a production edge linked to a production coordinator. |
| `client_transcript_branches::harness_observes_and_renders_the_complete_welcome_order` | The testkit model ends its authenticated burst with the NOTE and then its `900`. |
| `client_transcript_branches::harness_renders_no_account_state_for_a_guest` | The model's guest burst plans and renders no account state. |

With the `AccountState` arm computing the logged-in state but neither sending
it nor failing closed, the five unit tests and both daemon tests fail, and the
five NOTE tests still pass; restored, all twelve pass. With the testkit
model's arm rendering nothing again, its welcome-order test fails; restored,
all eleven transcript branch tests pass. Every authenticated registration of
the Stage 06 and Stage 08 suites now also checks its `900` through
`read_account_state`.

The post-registration login:

| Test | What it pins |
| --- | --- |
| `mutation_render::account_login_render::a_guest_login_answers_903_then_900_and_names_its_account_to_notify_peers` | The requester reads its carrier frames, `903`, the `900` with the account's label and then its own `ACCOUNT` line; an `account-notify` peer reads only the `ACCOUNT` line, a peer without the capability nothing. |
| `mutation_render::account_login_render::a_reauthentication_repeats_900_alone` | A same-account reauthentication's checkpoint plan: `903` and the `900` naming `*`, and nothing to a peer. |
| `mutation_render::account_login_render::an_internal_carrier_gets_no_900_while_local_peers_learn_the_account` | The coordinator's internal carrier for an edge client reads only the carrier frames; the coordinator's own `account-notify` peer reads the `ACCOUNT` line. |
| `mutation_render::account_login_render::a_login_rendering_refuses_a_stale_plan_or_an_absent_account` | A plan for another revision, or an account the domain does not hold, renders nothing. |
| `login_after_registration::a_login_after_registration_follows_903_with_900_and_names_the_account` | The production binary: a registered guest's login reads `903` and then the `900`, byte-exact against its own `JOIN` echo and the account's public label; an `account-notify` peer reads `ACCOUNT <label>`, a peer without it and the guest itself (no `account-notify`) nothing more; a reauthentication repeats the `900` alone; a logout still names `ACCOUNT *` to the peer and answers the client with nothing. |

With the account service rendering a registered login's frames as before (no
`render_account_login`), the daemon test above and the account edge exercise
`production_daemon_account_edges_cover_replay_mismatch_logout_and_deletion`
fail waiting for a `900`, and the four unit tests pass; with the `900` left
out of `render_account_login`, the guest-login and reauthentication unit
tests and both daemon tests fail; with the `ACCOUNT` line left out, the
guest-login and internal-carrier unit tests and the login daemon test fail.
Restored, all six pass. The Stage 06 registration helpers remember the
nickname a connection registered under, and `authenticate_live_account`
reads the `900` after the `903` of such a connection, so the account edge
exercise's reauthentication after a wrong deletion token checks its `900`
too.

The recomputed membership revision:

| Test | What it pins |
| --- | --- |
| `semantics::tests::a_recomputed_membership_keeps_the_revision_it_joined_at` | Membership revisions 1, 8 and 9 under resulting revision 9 are accepted; 0 and 10 are refused. |
| `semantics::tests::recomputed_memberships_bind_the_outer_channel_and_revision` | Unchanged: a membership of another channel, a zero resulting revision and a membership above it are refused. |
| `federation::codec::tests::recompute::a_recomputed_membership_round_trips_at_the_revision_it_joined_at` | The runtime codec encodes a membership joined at 3 under resulting revision 7 and decodes it back unchanged; one joined at 8 is refused. |
| `federation::codec::tests::recompute::a_member_edge_receives_the_recompute_of_its_member_login` | The coordinator's projector encodes the login of a guest an edge homes, alone in a channel, for that edge. |

With the equality restored, the three new tests fail and the unchanged one
passes; restored, all four pass. A temporary, uncommitted daemon scenario (a
guest on one edge and a peer on the other in the same channel, then the
guest's login) read `904` with the equality and `903` with the correction.

The edge origin after a login:

| Test | What it pins |
| --- | --- |
| `federation::edge::tests::accounts::a_login_after_registration_declares_its_account_before_the_next_carrier` | Through the edge router and a scripted coordinator: a registered guest's authenticated SASL finish is followed by `FORIGIN UPDATE` generation 2 naming the session and the account, and the connection's next SASL start waits for that acknowledgement and leaves under generation 2. |
| `federation::edge::tests::accounts::sasl_crosses_the_federation_and_its_grant_opens_the_session` | Unchanged: a login before registration is declared by the session open. |

With the declaration left out, the new test fails because the next carrier
leaves under the guest generation, and the unchanged one passes; restored,
both pass. A temporary, uncommitted Stage 08 scenario (a registered guest on
edge A logs in and then authenticates again) read `904` for the
reauthentication, with the coordinator logging `principal_mismatch`, without
the declaration, and `903` with it.

The Stage 08 edge test keeps every registered connection open until its
scenario ends.

## Limitations

- A daemon test covers the edge only after pre-registration SASL; edge guest
  registrations are covered by the unit test of the edge completion path.
- The daemon tests use accounts without a public label, so the labeled `900`
  is covered by the unit tests only.
- The capacity campaign's login, which now reads the `900`, is an ignored
  qualification scenario; it was compiled, not run. The drills' login helper
  is run by the ordinary Stage 08 recovery submission test.
- The post-registration login of a session an edge homes is not implemented
  at this revision: its edge sends no `900`, and peers that other edges home
  read no `ACCOUNT` line.
- The local `ACCOUNT` line follows a login and a logout only; an account
  label change still reaches only the peers that edges home, as before.
- These are development-host runs. The full Stage 09 gate runs at the
  integration tip, not on this branch.

## Evidence

Sources:

- `docs/arc-architecture-and-implementation-spec.md` Sections 9.5 and 10.2,
  and Appendix A.3
- `crates/agenc-relay-runtime/src/registration.rs`
  (`RegistrationRuntimeConfig::recovery_epoch`, `welcome_frames`,
  `recovery_epoch_note`, `account_state_numeric`)
- `crates/agenc-relay-runtime/src/client_render.rs` (`LoggedIn`)
- `docs/arc-architecture-and-implementation-spec.md` Section 11.4, and
  Appendix A.3 (`account-notify`)
- `crates/agenc-relay-runtime/src/mutation_render.rs` (`logged_in`,
  `render_account_login`)
- `crates/agenc-relay-runtime/src/account_service.rs` (`stage_finish`)
- `docs/arc-architecture-and-implementation-spec.md` Section 20.6
- `crates/agenc-relay-federation-wire/src/semantics.rs`
  (`validate_membership_recompute`) and `src/tests/semantics.rs`
- `crates/agenc-relay-domain/src/federation/projection.rs`
  (`project_member_authority`, `project_recompute`)
- `crates/agenc-relay-runtime/src/federation/codec/tests/recompute.rs`
- `docs/arc-architecture-and-implementation-spec.md` Section 20.7
- `crates/agenc-relay-runtime/src/federation/edge/request.rs`
  (`completed_request`, `declare_logged_in_account`)
- `crates/agenc-relay-runtime/src/federation/coordinator/accounts.rs`
  (`validate_remote_principal`)
- `crates/agenc-relay-runtime/src/federation/edge/tests/harness.rs`
  (`accounts::a_login_after_registration_declares_its_account_before_the_next_carrier`)
- `crates/agenc-relay-runtime/src/tests/account_login_render.rs`
- `crates/agenc-relay-server/tests/stage_six_daemon/login_after_registration.rs`
- `crates/agenc-relay-runtime/src/federation/edge/mod.rs`
  (`EdgeFederation::logged_in`)
- `crates/agenc-relay-testkit/src/client_transcript.rs` (`transcript_mask`)
- `crates/agenc-relay-runtime/src/registration/tests/welcome.rs` and
  `account_state.rs`
- `crates/agenc-relay-server/tests/stage_six_daemon/welcome_burst.rs`
- `crates/agenc-relay-server/tests/stage_eight_e2ee/welcome_recovery.rs`
- `crates/agenc-relay-server/tests/stage_six_daemon.rs` and
  `stage_eight_e2ee.rs` (`complete_registration`, `read_account_state`)

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

# the welcome 900, on the tree of its commit
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean
cargo nextest run -p agenc-relay-runtime -p agenc-relay-server -p agenc-relay-testkit \
  -p agenc-relay-e2ee --all-features --locked
# 3206 tests run: 3206 passed, 21 skipped
cargo nextest run -p agenc-relay-runtime -p agenc-relay-server --all-features --locked \
  -E 'test(/account_state_tests::/) | test(/welcome_burst::/) | test(/welcome_recovery::/) | test(/welcome_tests::/)'
# 12 passed; with the AccountState arm computing but not sending: 7 failed, 5 passed
cargo nextest run -p agenc-relay-testkit --all-features --locked --test client_transcript_branches
# 11 passed; with the model's AccountState arm reverted: 1 failed, 10 passed
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
# region anchors: ok (1145 reviewed spans hold the item they name); ten regions in
# client_render.rs, federation/edge/mod.rs and registration.rs moved, spans unchanged

# the post-registration login on its own node, on the tree of its commit
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean
cargo nextest run -p agenc-relay-runtime -p agenc-relay-server --all-features --locked
# 2827 tests run: 2827 passed, 21 skipped
cargo nextest run -p agenc-relay-runtime -p agenc-relay-server --all-features --locked \
  -E 'test(account_login_render) | test(login_after_registration) | test(production_daemon_account_edges_cover_replay_mismatch_logout_and_deletion)'
# 6 passed; the account service rendering as before: 2 failed, 4 passed;
# no 900: 4 failed, 2 passed; no ACCOUNT line: 3 failed, 3 passed

# the recomputed membership revision, on the tree of its commit
cargo nextest run --workspace --all-features --locked
# 4535 tests run: 4535 passed, 24 skipped
cargo nextest run -p agenc-relay-runtime -p agenc-relay-federation-wire --all-features --locked \
  -E 'test(recompute) | test(recomputed)'
# 4 passed; with the equality restored: 3 failed, 1 passed

# the edge origin after a login, on the tree of its commit
cargo nextest run -p agenc-relay-runtime -p agenc-relay-server --all-features --locked
# 2830 tests run: 2830 passed, 21 skipped
cargo nextest run -p agenc-relay-runtime --all-features --locked --lib \
  -E 'test(a_login_after_registration_declares_its_account_before_the_next_carrier) | test(sasl_crosses_the_federation)'
# 2 passed (ten of ten repeated runs); without the declaration: 1 failed, 1 passed
```
