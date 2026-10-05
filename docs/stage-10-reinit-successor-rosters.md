# The successor rosters of a ReInit and the channel-authority limitation (PC-001, P-03)

This record covers plan item P-03 of the SDK server program (2026-10-04,
outside master #35). The program's normative revision added one endpoint rule
to companion Section 13.8 (decision D-12): a ReInit successor's policy, with
its controllers and finality council, is verified under the rosters that the
successor context's own `roster_heads` name, and each of those heads, for an
account the old context's heads also name, carries the old head's root or a
continuous successor of it, so a ReInit never carries a root discontinuity.
This change implements that rule in the shared target helper
([the ReInit target helper record](stage-10-reinit-target-helper.md)), adds
root-rotation and `0x0001`-to-`0x0003` suite-change vectors and tests, and
establishes that a ReInit cannot rotate a channel's authority root. No
specification, hash, wire object, registry, reply code or storage generation
changed; only the helper's reconstruction API did.

## The rule

`reconstruct_reinit_target` now takes the old conversation as an endpoint
holds it, `OldConversation` (its current binding and the roster heads its
current context commits), and the successor's rosters, `SuccessorRosters`:

- `rosters`, the verified root and roster of every account the successor
  context's `roster_heads` name, and of no other account;
- `root_chains`, for each account whose successor head names another root
  than its old head, the consecutive root identities from the old head's root
  to the successor's, oldest first, both included.

After the structural rules of the carried target, the reconstruction checks:

- the rosters are exactly the ones the successor's heads name: as many
  rosters as heads, and for each supplied account a head with its account
  digest naming that account's root generation and fingerprint and its roster
  generation and ID, so no head lacks a roster and none names an account twice
  (companion 9.5: the last roster of every account equals the committed head;
  extra or missing heads are invalid);
- root continuity: for each successor head of an account the old heads also
  name (at most once), either the same root fingerprint, or a supplied chain
  whose first root is the old head's root, whose every later root verifies
  under its predecessor's continuity signature (`verify_root_chain`), and
  whose last root is the successor's (companion 8.2); an account the old
  context does not name needs no chain;
- the successor binding's principals, under those rosters, with the rule
  every binding package meets (`route::check_principals`, now `pub(crate)`),
  against the semantic route the structural check already verified
  (`context::check_binding_agreement` now returns it): each principal names
  its roster's root, roster generation and roster ID, a direct binding names
  its route's two accounts, and a channel's authority root is among the
  supplied roots (companion 9.4);
- the successor policy verifies under those rosters, as before.

Before this change the reconstruction verified the successor policy under
whatever rosters its caller supplied, and its documentation and tests
supplied the old conversation's: it neither tied the rosters to the
successor's roster heads nor required root continuity, nor checked the
successor binding's principals, and under the documented rosters a successor
naming a rotated root could not be rebuilt. The sequencer's checks
(`check_carried_target`, `AuthorizedReinit::check_attempt`) and a later
joiner's are unchanged: the rule is an endpoint's, and a later joiner relies on
the activation certificate's old-policy quorum for the old context's heads.

## Root rotation and the suite change

`scripts/generate-e2ee-vectors.py` adds 23 files to
`test-data/vectors/e2ee/reinit` (79 in all), all earlier files byte-identical:

- `root-d-1.bin` and `roster-d-1.bin`: account `d`'s generation-one root,
  whose continuity signature is by `d`'s old root, with a new certificate for
  the same device and a generation-zero roster under the new root;
- the `rotation` successor at suite `0x0001`, whose roster heads, binding
  principals, policy and plan name `d`'s new root: its extension list and
  target, a later joiner's ReInit binding-chain and policy-chain entries, and
  a log from the ReInit candidate through the finalization, the attempt
  receipt (with the attempt, which carries the target, and its initial
  Commit) and the activation, certified by the old council under the old
  roots;
- `rotation-0003`, the same rotation with a suite change from `0x0001` to
  `0x0003`, reconstructed only;
- the rejection files: `reject-root-d-1-forged-continuity.bin` (the same
  generation-one root, so the same fingerprint, with a continuity signature by
  another key); `root-d-1-sibling.bin` (another valid generation-one root of
  `d`, from which the rotation does not descend); `root-d-fresh.bin`,
  `roster-d-fresh.bin` and
  `reject-rotation-fresh-root-extensions.bin` (a generation-zero root of `d`
  that does not continue the old one); `reject-rotation-stale-principal-extensions.bin`
  (heads, policy and plan on `d`'s new root, the binding on the old one); and
  `root-c-1.bin`, `roster-c-1.bin` and
  `reject-rotation-channel-authority-extensions.bin` (a continuous rotation of
  `c`, the channel-authority root).

`crates/agenc-relay-e2ee/tests/reinit/rosters.rs`:

- `a_root_rotation_reinit_rebuilds_under_the_successor_rosters_and_activates`:
  the rotation rebuilds byte for byte under the successor rosters and `d`'s
  chain; the sequencer's check rebuilds the same target from the carried
  bytes; the shared history adopts the candidate, finalization, attempt and
  activation; and a later joiner accepts its entries;
- `a_suite_change_reinit_moves_from_0x0001_to_0x0003`: the suite change alone
  and with the rotation, each refused under the other's rosters;
- `the_successor_rosters_must_be_the_ones_its_roster_heads_name`: the old
  conversation's rosters, an extra roster, a missing one, the old roster under
  the new root, another roster generation and another root of the account; and,
  with the binding's principals and the policy still naming the supplied
  rosters, a successor head no roster covers, `d`'s head naming another root
  generation, root fingerprint, roster generation or roster ID, and two heads
  for one account;
- `a_successor_root_must_continue_the_old_head_root`: no chain, an empty
  chain, the new or the old root alone, a chain from another account's root, a
  chain to another root of the account, the forged continuity signature, the
  fresh root with and without chains, a rollback, a fork (the old context names
  the sibling root, and neither a chain from the common ancestor nor one from
  the sibling reaches the rotation's root from it), and two old heads for one
  account are refused; an account the old context does not name and an
  unchanged root need no chain;
- `the_successor_binding_principals_must_name_the_successor_rosters`;
- `a_reinit_cannot_rotate_the_channel_authority_root` (below).

The other ReInit tests pass the old conversation's roster heads and, for the
suites that keep their roots, the old conversation's rosters as the successor
rosters.

## A ReInit cannot rotate a channel's authority root

A channel's semantic route names its authority root's fingerprint, and the
semantic route lock is the hash of that route (companion 9.4). A ReInit
successor keeps the old binding's semantic route lock and concrete route,
which the activation remaps (companion 13.8), and a later incarnation keeps
the route's key, the channel name and authority root, too. When the authority
account rotates its root continuously, the successor's roster head for that
account names the new root, and the binding's principals must name the
rosters those heads name, so no supplied root carries the fingerprint the
kept route names, and the binding fails the channel rule every binding package
meets. `a_reinit_cannot_rotate_the_channel_authority_root` shows that the
reconstruction refuses such a successor although its root chain verifies and
the structural rules accept it (`check_carried_target` admits its carried
target). Rotating the root of another member or controller works through
ReInit (the vectors rotate `d`, a controller and council member). A direct
conversation's route names its two Account IDs rather than roots, so the same
rules admit a rotation of either party's root; the vectors do not exercise a
direct conversation.

This is the limitation decision D-12 (1) anticipated. No mechanism is added
for it: version 1 defines no transition that moves a channel to another
authority root, so a channel whose authority root must change is closed and
created again under a new semantic route, which is a new channel identity.

## Requirements

`E2EE-REQ-FB9D986123B9141AF6AB` ("the context's policy does not verify under
the rosters its `roster_heads` name, or one of those heads, for an account
that the old context's `roster_heads` also name, carries a root that is
neither the old head's root nor a continuous successor of it") is now
implemented by `reconstruct_reinit_target` (`check_rosters_named`,
`check_root_continuity`, the principals and policy checks). With the thirteen
clauses of P-02, the shared code (the helper, with `HistoricalChain` where the
P-02 record's table says so) implements all fourteen `S10-005` clauses of the
revision; they stay bound to `S10-005`, `unimplemented` until that task
closes, as the server's process derives status from the task. The seven
`S10-004` clauses remain P-04's.

## Coverage

Both coverage policies take the new production source inventory (1,011
files, as before). In the release policy the reconstruction's region is
respanned with a new reason, the other `pc001-reinit-*` regions of
`reinit_target.rs` and the regions of `route.rs` and `context.rs` that the
edits displaced or changed are re-anchored or respanned, and two `branches`
regions are added for `check_rosters_named` and `check_root_continuity`; the
policy holds 1,172 reviewed spans.

## Revert proof

The new tests do not compile against the parent commit's reconstruction API.
The parent's reconstruction, run in a scratch copy of the parent tree on the
new vectors, refused the rotation under the old conversation's rosters, its
documented input, and accepted the rotation under the rotated rosters without
any continuity evidence, the fresh-root successor, the stale-principal
successor and the channel-authority rotation. With this change the rotation is
accepted only with `d`'s verified chain, and the other three are refused.

## Limitations

- The successor's roster heads, binding principals and plan are checked
  against the rosters the endpoint supplies; that they are the ones the
  controllers approved stays an endpoint obligation outside the helper.
- A later joiner does not apply this rule; it relies on the activation
  certificate's old-policy quorum for the old context's roster heads.
- The vectors' MLS inputs are synthetic, as in P-02.

## Validation

On the tree of this commit, before it was committed, with Rust 1.98.0:

- `cargo fmt --all --check`; `cargo clippy -p agenc-relay-e2ee --all-targets --all-features --locked -- -D warnings`;
  `python3 scripts/check-source.py check`: clean.
- `python3 scripts/generate-e2ee-vectors.py --check`: 9 identity, 20 recovery
  and 79 ReInit files; the 56 earlier ReInit files are unchanged.
- `cargo nextest run -p agenc-relay-e2ee --all-features --locked`: 328 tests
  passed (322 at the parent commit).
- Mutation testing: the 130 single-check mutations of the parent commit's
  campaign and 15 new ones for the successor rosters (the reconstruction's
  three new steps, the head count and each compared head field, and root
  continuity's duplicate old head, same-root shortcut both ways, chain start,
  chain end, new-account rule and continuity verification): 144 of 145
  killed, the survivor being the parent's equivalent stored-target mutation.
  An earlier pass showed the head comparisons and the chain start masked by
  the principals and chain checks, which the head-field, unrostered-head and
  fork cases now separate, and one head-uniqueness comparison that the head
  count already implies (removed).
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-e2ee --all-features --branch --locked --json`:
  every `pc001-*` region at 100 percent (the two new regions 6 of 6 and 8 of 8
  branches, the reconstruction all of its regions) and the crate at 91.17
  percent of branches; the three history `regions` rows score as at the
  parent commit.
- `python3 scripts/check-coverage.py audit` and `self-test` on both policies:
  passed (21 and 1,172 reviewed spans).
- The revert proof above, in a scratch copy of the parent tree.
- The program's fast static gate (59 commands): all passed.
