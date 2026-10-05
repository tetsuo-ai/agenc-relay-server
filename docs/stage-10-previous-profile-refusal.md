# Refusing the previous encrypted profile and the coordinated upgrade (PC-001, P-05)

This record covers plan item P-05 of the SDK server program (2026-10-04,
outside master #35). The program's normative revision
([the ReInit target revision record](stage-10-reinit-target-revision.md),
P-01) moved the E2EE profile hash under profile version 1, from the token
`wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U` of release candidate 3 to
`CzmFweGfd-Vhc0E51lEx-xwfxct6Y6ERnKA7WmFYNSU`, and described the coordinated
upgrade. CAP, ECAP and the onboarding descriptor accept only the exact
`(version, profile-hash)` pair, so each of them already refused the previous
hash. This change pins those refusals with tests, makes a federation link
that receives an `ECAP` line of another profile send the line companion
Section 12.5 names before it closes, links an edge of the previous profile to
a coordinator of this one through the production daemons, and adds the
operator guide's upgrade note. No specification, hash, registry, wire object,
reply code or storage generation changed.

## The refusals

- `crates/agenc-relay-e2ee/src/tests/profile.rs`,
  `the_previous_profile_and_its_drafts_are_refused`: the release candidate 3
  capability value, byte for byte, is refused by `check_capability_value`. The
  release candidate 3 token and the tokens of three drafts of the revision
  that were never adopted (the program's superseded first round,
  `wdFNKl0-6lCHsd81UTpS74BG2BGg0yZUURoRCzwEkO8`, and the two revisions of its
  earlier rehearsal, `7IkMThzSxSXro80LOF4RPUlMHJzf1GcDPZDiHxk9U-0` and
  `fApHHjGXpxyWRFMLG00LDDpXjORF6u13LPffgT2ALY0`) are each placed in the
  current capability value and the current ECAP tuple. Each fails
  `check_capability_value`, `EcapTuple::parse` and `parse_companion_frame`
  for `ECAP ARCMLS OFFER` with `ProfileMismatch`, and the current tuple still
  parses on the same path.
- `crates/agenc-relay-config/tests/template_onboarding.rs`,
  `a_descriptor_of_the_previous_profile_is_refused`: a descriptor whose
  `e2ee-profile-sha256` names one of those four tokens is refused with
  `InvalidValue`. A node with the encrypted profile disabled prints no E2EE
  line, so its descriptor is the same under either revision.

Both tests also pass against the parent commit's code. They pin the refusal
the exact-match rules already gave.

## The link's answer

Companion Section 12.5: "A duplicate OFFER or ACK, ACK-before-OFFER, unknown
subcommand, wrong arity, tag, prefix mismatch, field mismatch, timeout at or
after the deadline, or any E2EE frame before `profile_active` sends at most
`ERROR :ARC-MLS profile mismatch` and closes the link."

A tuple that parses but differs was already answered this way by the
negotiation (`CompanionLinks::on_frame`). An OFFER or ACK that names another
profile hash, though, fails before the negotiation sees it, because
`EcapTuple::parse` refuses every profile token but the build's. The link
then closed as on any line that does not parse, without a line.

Now `federation::link::parse_line` reports an `ECAP` line that does not parse
as `ReadFailure::Profile`; every other companion line that does not parse is
still `Framing`. The link loop answers a profile failure with
`ERROR :ARC-MLS profile mismatch`, rendered by
`agenc_relay_e2ee::federation::ecap::violation_line` as the negotiation's
violations are, and then closes with reason `Framing`, as before. The
write waits at most the link's keepalive timeout (`LinkTiming::keepalive_timeout`,
10 seconds), so a peer that stops reading cannot hold the close open; a write
that fails or times out changes nothing. During the hello, a profile failure
becomes `HelloFailure::Framing`, like every other line failure.

`crates/agenc-relay-runtime/src/federation/link/tests/profile_mismatch.rs`:

- `an_offer_of_another_profile_is_a_profile_line_failure`: a current OFFER
  parses; the release candidate 3 OFFER, a short OFFER and an unknown `ECAP`
  subcommand are profile failures.
- `a_previous_profile_offer_is_answered_with_the_mismatch_line_and_closes`: a
  link run as `core.example` answers the release candidate 3 OFFER with
  exactly `:core.example ERROR :ARC-MLS profile mismatch\r\n` and closes with
  `Framing`.
- `a_peer_that_stops_reading_cannot_hold_the_close_open`: over a one-byte
  transport whose peer never reads, the link closes with `Framing` once the
  write's bound passes.
- `a_malformed_base_line_still_closes_without_a_profile_line`: a base line
  that does not parse still closes the link without any line.

## The mixed-version link through the daemons

`crates/agenc-relay-server/tests/stage_eight_e2ee/mixed_profile.rs`,
`an_edge_of_the_previous_profile_is_refused_while_base_chat_continues`, runs a
Stage 08 coordinator and edge B as `arcd` processes. The test process plays
edge A as an edge of release candidate 3: it runs the runtime's own dial
owner under edge A's configured identity, keys and certificates. On the
coordinator's OFFER, its companion layer renders and sends the OFFER of the
previous profile, which is the coordinator's tuple with the release candidate
3 token. Every daemon is built from this tree, so only the old edge is played
by test code, and only its companion profile differs. The test shows:

- a client of the coordinator and a client of edge B chat in both directions
  before and after the old edge's attempt;
- the old edge's hello completes, and the coordinator's OFFER is exactly this
  build's tuple (`EcapTuple::local` of its network, coordinator and key set);
- the old edge's link closes with `Framing`, on the coordinator's answer, a
  line no base grammar admits. It does not close on the end of the transport
  (`PeerClosed`). The coordinator logs a failed `federation_link_closed`;
- edge B's link neither closes nor reconnects meanwhile.

The runtime test checks the bytes of the answer. The daemon test does not read
the line itself, because its old edge is the runtime's dial owner, which
reports only the close reason.

## The upgrade note

`docs/operator-guide.md` gains "Upgrade to a new encrypted profile", which
says:

- why this release is a coordinated upgrade, and to stop, install and restart
  every node that has the encrypted profile enabled together;
- what a link between different hashes does: it closes, an upgraded end
  sends the profile-mismatch line first, and an edge whose coordinator link
  is closed behaves as architecture Section 20.10 states;
- that an upgraded node advertises the new value, and that a client of the
  previous hash finds it unequal and keeps its encrypted conversations
  blocked, never falling back to plaintext (companion 11.1);
- that this release does not migrate ReInit state stored under the previous
  profile: a conversation whose latest sequencer record is a ReInit
  activation or abort of that profile is not restored, and a ReInit attempt
  left open under it can neither complete nor be aborted (P-02's record
  explains why; how such state migrates is part of P-04, plan item G-08);
- to print and distribute new descriptors and invitations;
- what does not change.

## Review

An independent review of this topic led to a follow-up commit: the mismatch
write is bounded by the keepalive timeout, with the test above, which fails
without the bound; and the upgrade note now says what a client of the
previous hash sees and what happens to ReInit state stored under the previous
profile. Validation of the follow-up:
`cargo nextest run -p agenc-relay-runtime -p agenc-relay-config -p agenc-relay-e2ee --all-features --locked`
and the Stage 08 suite passed, and the fast gate passed.

## Requirements

No requirement record or binding changes. Every one of the revision's 21
clauses is in Section 13.8. The tests exercise two existing clauses:

- `E2EE-REQ-675C5F4ED330BC9F24B5`: companion 12.5, exact link-profile
  negotiation; `S08-031`, `implemented`.
- `ARCH-REQ-71BBCEF88CC9E11D5672`: architecture C.8, a descriptor's E2EE
  block equals the build constant; `S10-008`, `unimplemented`.

The fourteen `S10-005` clauses that P-02 and P-03 implement stay
`unimplemented` until `S10-005` closes. The seven `S10-004` clauses remain
P-04's.

## Coverage

Both coverage policies take the new production source inventory (1,012
files, `a3397412dfebf2c0591c82ba8cd39e0784223aa28005c438687d585272dcc77e`).
The edit displaced two regions of the release policy,
`companion-link-linkloop-on-outbound` and `cap13-link-linkqueue-drop`. They
are re-anchored, and their span hashes are unchanged. One `branches` region,
`pc001-link-parse-line`, is added for `parse_line`, so the policy holds 1,173
reviewed spans.

A branch report of the runtime crate's tests scores `parse_line` at 12 of 12
branches. The same run scores the two re-anchored regions at 20 of 21 and 7
of 8 regions, as it does at the parent commit. The release check scores the
workspace run.

## Revert proof

- With the answer disabled, by wrapping the call in a false condition,
  `a_previous_profile_offer_is_answered_with_the_mismatch_line_and_closes`
  fails because it reads an empty answer.
- With the same edit, the old edge's link in the daemon test closes with
  `PeerClosed` instead of `Framing`, and the test fails.

## Limitations

- This build's runtime plays the old edge with the previous profile's
  companion tuple; no release candidate 3 binary runs. A release candidate 3
  node that reads this revision's OFFER closes the link without the line,
  because its parser refuses the token, as this build's did before this
  change. The link closes either way.
- The daemon test observes the answer only through the old edge's close
  reason. The runtime test checks the exact bytes.
- An `ECAP` line under another peer's prefix, or with a tag other than the
  companion tag, still closes the link without the line, which the "at most"
  of Section 12.5 permits.

## Validation

On the tree of this commit, before it was committed, with Rust 1.98.0:

- `cargo fmt --all --check`;
  `cargo clippy -p agenc-relay-runtime -p agenc-relay-config -p agenc-relay-e2ee -p agenc-relay-server --all-targets --all-features --locked -- -D warnings`;
  `python3 scripts/check-source.py check`: clean.
- `cargo nextest run -p agenc-relay-runtime -p agenc-relay-config -p agenc-relay-e2ee --all-features --locked`:
  3,224 tests passed, 3,219 at the parent commit and the five new ones.
- `cargo nextest run -p agenc-relay-server --test stage_eight_e2ee --locked`:
  47 tests passed (46 at the parent commit) and the 17 Stage 10 drills were
  skipped; the new daemon test also passed alone three times.
- The revert proofs above.
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime --all-features --branch --locked --json`:
  the scores above.
- `python3 scripts/check-coverage.py audit` and `self-test` on both policies:
  passed (21 and 1,173 reviewed spans).
- The program's fast static gate (59 commands): all passed.
