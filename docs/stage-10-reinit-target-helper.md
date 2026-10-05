# The shared ReInit target helper and the carried target (PC-001, P-02)

This record covers plan item P-02 of the SDK server program (2026-10-04,
outside master #35): the shared implementation, in `agenc-relay-e2ee`, of the
companion Section 13.8 rules that the program's normative revision specified
([the ReInit target revision record](stage-10-reinit-target-revision.md)),
the independent ReInit vectors, and the Stage 08 fixture that builds one
target. It re-authors the SDK's PC-001 rehearsal on the merged text, which
differs from the rehearsal in four ways: every attempt carries its target,
the sequencer's attempt checks are a list of five, a member that joins after
activation checks its entries against the carried target, and the successor
initial Commit's authenticated data names the target's profile version and
network. No specification, profile hash, registry entry, named limit, reply
code or storage generation changed: the object layouts below are the ones the
revision froze.

## The two object layouts

`ArcReInitTargetTbs` (`crates/agenc-relay-e2ee/src/objects/reinit.rs`) no
longer has `old_reinit_state_id`, and `ArcReInitAttempt` has one more field,
`target`, right after its TBS: the exact target whose digest is the attempt's
`target_context_digest`. The activation and abort requests embed the attempt,
so they carry the target too. These are the companion 13.8 structures at the
current profile hash; an attempt of the previous layout does not decode.

## The helper: `agenc_relay_e2ee::reinit_target`

A client-usable module over public bytes only: no key material, bounded
decoding, and the server's source rules.

- `reconstruct_reinit_target` is an endpoint's reconstruction from the ReInit
  Proposal (or from a continuing member's epoch-1 GroupContext): it derives
  the whole target from the Proposal's group ID, version, suite and exact
  extension list, applies the structural rules below, and verifies the
  successor policy under the rosters the caller supplies. It returns a
  `ReinitTarget`.
- `check_carried_target` applies the structural rules to a target a verifier
  holds without the Proposal, such as the one an attempt carries, and
  requires every field of the target to be the value its own extension list
  yields: the first two endpoint rules "with that target in place of the
  Proposal". It returns a `CarriedTarget`, which a `ReinitTarget` also
  exposes (`ReinitTarget::carried`).
- The structural rules are the extension list's shape (one exact MLS vector,
  no repeated type, exactly one context and one `required_capabilities`
  extension, the context within `MAX_ARC_MLS_CONTEXT_EXTENSION`), the context
  core recomputed from the Proposal and the binding, and the successor the
  context and its binding describe: this profile and network, active with no
  close intent, no bootstrap and no pending join; an unapproved binding of
  the successor's group, conversation, version and suite that replaces the
  old conversation's current binding (the next generation, that binding's ID,
  its semantic route lock, concrete route, channel instance or nonce); the
  binding agreement, private-topic and roster-head-order rules of every
  context; the generation-zero policy the binding names as its initial and
  required operational policy, for its network, conversation, kind and suite;
  and the sequencer credential the binding names.
- `AuthorizedReinit::from_proof` recomputes the hash links of the old ReInit
  finalization proof (the ReInit bit alone as a controlled transition with a
  nonzero target digest; one position and candidate in the authorization,
  core and receipt; the core commits the authorization's ID) and yields the
  finalization ID, the authorized digest and the old Commit's validation
  time. `check_target` requires a target to hash to the authorized digest.
- `AuthorizedReinit::check_attempt` is the sequencer's attempt check for
  P-04 to call before it signs a receipt, given the old conversation's
  current binding: the attempt names this finalization ID; the carried
  target hashes to the attempt's digest, which is the authorized one; the
  attempt's group, version, suite, successor conversation, binding and plan
  are the carried target's; the device tuples and capability IDs of its
  `ArcKeyPackagePlan`, in the plan's order, form the semantic plan the target
  names; and the carried target meets `check_carried_target`. Whether the
  old conversation's accepted state is the ReInit finalization is the
  sequencer's own state and stays the caller's.
- `AuthorizedReinit::check_attempt_target` is an endpoint's check of an
  attempt against its own reconstruction: the carried target must be the
  reconstruction byte for byte, with the same links and plan check.
- `AuthorizedReinit::check_staged` checks a verified `ArcStagedReInit`
  against the old conversation and the finalization ID.
- `AuthorizedReinit::check_join_entries` is a later joiner's check: the
  activation's attempt carries the authorized target, which meets the
  structural rules with the binding-chain entry that precedes the ReInit
  entry as the old conversation's current binding; the activation core names
  this finalization and that attempt; the binding-chain entry is a
  `reinit_target_transition` whose binding is the one in the carried target's
  context, with that binding's semantic plan and no root binding lock; and the
  policy-chain entry is a `policy_reinit_target_transition` whose policy is
  the one in that context. That the activation certificate verifies under the
  old policy (sequencer signature, ACK set and quorum) is checked by
  `HistoricalChain` or the caller.
- `AuthorizedReinit::check_initial_commit` checks the successor initial
  Commit's public frame (a `PrivateMessage` of the target group at epoch zero
  with `commit` content) and its `ArcCommitAad`: the target's profile version
  and network, the successor conversation, the target context's route, a
  validation time no earlier than the old ReInit Commit's, and the old
  finalization ID as prior state.

`check_binding_agreement` in `context.rs` became `pub(crate)` for this module.

## The historical chain

`HistoricalChain` checks the target every adopted attempt carries: the
carried target must hash to the digest the attempt names, which the chain
already compares with the finalized authorization's, and the attempt must
repeat its group, version, suite, successor conversation, binding and plan.
This applies to every chain, a server's included (companion 13.7.2, "attempt
carries the authorized target"). `HistoricalChain::bind_reinit_target` binds a
verifier's reconstruction: the target must name its own successor
conversation and hash to the finalized digest, and binding is refused while
an attempt is open. A bound chain compares each later attempt's carried
target with the bound bytes instead of hashing it. The chain does not apply
the carried extension list's structural rules or the initial-Commit rule;
the method's documentation names the helper checks that do.

## The vectors

`scripts/generate-e2ee-vectors.py` (the independent Python TLS encoder and
Ed25519 signer of the identity and recovery sets) writes
`test-data/vectors/e2ee/reinit`, 56 files. For suites `0x0001` and `0x0003`
it writes the successor extension list, the target that list reconstructs and
its digest, and a sequencer log of the old conversation from its pinned
genesis binding through bootstrap, the ReInit candidate, its finalization,
the attempt receipt and the activation, with the attempt object, which
carries the target, and a successor initial Commit whose `ArcCommitAad`
names the old finalization; and the ReInit binding-chain and policy-chain
entries a later joiner checks, after the old genesis entry. A suite-`0x0001`
log advances the accepted state through a self-update and a candidate abort,
authorizes the same target there, aborts its first attempt and activates the
second. The rejection files duplicate the context extension, omit
`required_capabilities`, carry a later joiner's context with its own pending
join, change the context core, keep the previous target layout that named the
finalization ID, name the activation in the initial Commit, name another
target's digest while carrying that target, and name the authorized digest
while carrying another target. `--check` fails on any drift, including a
stale or missing file. Their MLS inputs are synthetic; their signatures are
real.

## Tests

- `crates/agenc-relay-e2ee/tests/reinit_vectors.rs` reads the vectors byte for
  byte: both suites rebuild one target from the extension list and activate
  it through the shared history, the sequencer's check rebuilds the same
  target from the attempt's carried bytes, one target survives the advanced
  log's state advance, candidate abort and attempt retry, and every rejection
  vector is refused.
- `tests/reinit/rules.rs` gives every rule a failing case beside its accepted
  control: the Proposal and extension list, the successor context and its
  core, the old authorization and finalization, the attempt's names and
  digest, the fields of the carried target, the carried bytes themselves, the
  KeyPackage plan's semantic plan, the carried list's derived fields (each
  edited under an authorization re-committed to its digest), the initial
  Commit, and the chain's carried-target checks, binding and late-binding
  refusal.
- `tests/reinit/successor.rs` edits the successor context one rule at a time
  and refuses each structural edit twice, through an endpoint's
  reconstruction and through the sequencer's check of the target a sender
  carrying the edited list would build; an invalid policy approval is refused
  only by the endpoint, which verifies the policy under rosters.
- `tests/reinit/join.rs` covers a later joiner: the activation's attempt and
  its carried target, the target against the preceding binding-chain entry
  (derived fields under a re-committed authorization), the activation core,
  the binding-chain entry and the policy-chain entry, and the staged wrapper.
- `tests/history/reinit_faults.rs` and the shared history support now build
  attempts that carry a target; new cases refuse an attempt carrying another
  target or naming other fields than the one it carries, and a bound chain
  refuses a carried target other than its own.
- Every test that builds an attempt (the object round trips, the record
  shapes, the coordinator's in-process harness) builds one with a target.

## The Stage 08 fixture

`crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/reinit.rs`
builds the target once, before the ReInit Commit, in both ReInit scenarios
(the activation and the attempt abort that SC-013 added), and every attempt
carries it. After the activation the scenario fetches the daemon's records and
replays them through `HistoricalChain`, resumed before the ReInit candidate:
the finalization commits the target's digest, `AuthorizedReinit` recomputes the
finalization ID and accepts the carried target, a target with one field
replaced neither matches the authorization nor binds, the bound target admits
the attempt receipt, no target binds while the attempt is open, and the
activation ends the old lineage. The target's extension list is a one-byte
placeholder (mls-rs 0.56 returns neither the successor initial Commit nor a way
to set its authenticated data, and these endpoints advertise no ARC extension),
so the structural rules and the initial-Commit rule are proven by the vectors,
not by this scenario. Run on this tree, which includes SC-013's requester
checks, both ReInit scenarios pass with their single labeled completions and
untagged broadcasts.

## Requirements

No binding changes. The fourteen `S10-005` clauses of the revision describe
what an endpoint or a later joiner checks; the helper implements thirteen of
them, and P-03 the remaining one (the successor policy under the rosters its
roster heads name, with root continuity). Under the server's process a
clause's status follows its closure task, so they stay `unimplemented` until
`S10-005` closes, as the ENC-06 clauses stayed bound to `S10-008` when ENC-07
implemented them:

| Requirement | Clause | Implemented by |
| --- | --- | --- |
| `E2EE-REQ-CD50092C1042C824D3AE` | extension list and context core | `extension_parts`, `successor_target` |
| `E2EE-REQ-5CE2946BC4C5748CBAD9` | context and binding describe the successor | `binding_of`, `check_lineage`, `check_context`, `check_policy_named` |
| `E2EE-REQ-978953B8799A08B41F25` | presented, replaced or carried target equals the reconstruction | `check_target`, `check_attempt_target`, `bind_reinit_target` |
| `E2EE-REQ-9C570091CD7134A351DB` | old candidate authorization | `from_proof`, `check_target` |
| `E2EE-REQ-6D390E4D9F1DEA0EEF68` | finalization core commits the authorization | `from_proof` |
| `E2EE-REQ-B7019C9600DEEE9F73B2` | later objects name the finalization ID | `check_attempt`, `check_attempt_target`, `check_staged`, `check_join_entries`; the chain for receipts, ACKs, votes and terminals |
| `E2EE-REQ-6A3059C08EDF34B7BA92` | attempt digest and fields against the carried target | `check_carried_links`; `HistoricalChain` |
| `E2EE-REQ-78EA2878D8AF97B72939` | joiner: finalization rules with the carried digest | `from_proof`, `check_join_entries`; the old-policy verification of the activation by `HistoricalChain` or the caller |
| `E2EE-REQ-C32EDD6C33F900C062E9` | joiner: attempt names the finalization and digest | `check_join_entries` |
| `E2EE-REQ-06A132AFEEEA39A18944` | joiner: carried target's structure, derived IDs and attempt fields | `check_join_entries` |
| `E2EE-REQ-3E01466276139F12C048` | joiner: binding entry | `check_binding_entry` |
| `E2EE-REQ-110D92BDA8FFA62CB76B` | joiner: policy entry | `check_join_entries` |
| `E2EE-REQ-0178BBD7E7A2A76F4D6D` | successor initial Commit `ArcCommitAad` | `check_initial_commit` |

The seven `S10-004` clauses are the sequencer's and the coordinator's, and
P-04 implements them in the coordinator: `E2EE-REQ-91603206702A296AE34F`
(`E2EE_FINALITY_REQUIRED`), `E2EE-REQ-667141DBC7473B7A0F9D`,
`E2EE-REQ-CCA2E69085E483C5155F`, `E2EE-REQ-39DFA440E75F7F7495F2`,
`E2EE-REQ-B4977D179E4C66AAD737`, `E2EE-REQ-4A3F05D133A72461A8DC` (the five
`E2EE_BINDING_AUTH_INVALID` checks, which `AuthorizedReinit::check_attempt`
provides) and `E2EE-REQ-65D600D44A7F4FDA9EE6` (the atomic successor
installation).

## Coverage

Both coverage policies take the new production source inventory (1,011
files). The release policy gains twenty-four regions for the new decisions,
twenty-two in `reinit_target.rs` and two in `history/reinit.rs`: twenty-three
under the `branches` metric and `pc001-reinit-target-reconstruction`, which
only delegates and so has no branch records, under `regions`. The edits of
`history.rs` and `history/reinit.rs` moved three reviewed spans
(`history-chain-record-adoption`, `history-reinit-activation`,
`history-reinit-ack-agreement`), which were re-anchored, and changed the span
of `e2ee-history-resume` by one field initializer (a resumed chain starts with
no bound target), which was re-reviewed and respanned; the policy holds 1,170
reviewed spans.

## Wire and persistence effect

The `reinit_attempt` object and the two ReInit terminal requests that embed it
carry the target, as the revision's companion text requires. No other object,
token, reply or registry changes, and the storage generation is unchanged. A
coordinator that holds a ReInit attempt object of the previous profile and
reads it again (an ACK for that attempt) no longer decodes it; how a database
holding such attempts restores is part of P-04 (plan item G-08).

## Limitations

- The vectors' MLS inputs (Commits, GroupContext, tree and GroupInfo
  encodings, exporter values, the initial Commit's sender data and ciphertext)
  are synthetic, and mls-rs 0.56 cannot emit a successor initial Commit, so
  the initial-Commit and extension-list rules are proven against the
  independent vectors, not against an MLS library's bytes. OpenMLS 0.9 has no
  ReInit.
- The helper checks structure, hash links and the successor policy's
  approvals; the old Commit's approvals, finality votes, ACK sets, sequencer
  signatures and record positions stay with `HistoricalChain` or the caller.
  The successor's MLS state (Add set, KeyPackageRefs, PSK use, tree) stays an
  endpoint obligation.
- A later joiner relies on the activation certificate's old-policy quorum for
  the checks that need the old group's state, such as the old context's
  roster heads.
- The successor rosters are tied to the successor context's roster heads only
  by P-03; here the caller supplies the rosters the successor policy verifies
  under.
- The Stage 08 fixture proves one target through the daemon and the shared
  history, not a real ARC successor context or initial Commit.

## Validation

On the tree of this commit, before it was committed, with Rust 1.98.0:

- `cargo fmt --all --check` and `cargo clippy -p agenc-relay-e2ee -p agenc-relay-runtime -p agenc-relay-server --all-targets --all-features --locked -- -D warnings`: clean.
  `python3 scripts/check-source.py check`: passed.
- `python3 scripts/generate-e2ee-vectors.py --check`: 9 identity, 20 recovery
  and 56 ReInit files; the identity and recovery sets are unchanged.
- `cargo nextest run -p agenc-relay-e2ee --all-features --locked`: 322 tests
  passed (281 at the parent commit).
- `cargo nextest run -p agenc-relay-runtime -p agenc-relay-e2ee -p agenc-relay-testkit -p agenc-relay-domain --all-features --locked`:
  3,487 of 3,488 passed; the one failure,
  `state_core::tests::a_guest_session_registers_and_commands_flow_through_the_router`,
  is a load-dependent test that ReInit does not reach, and it passed alone
  three times.
- `cargo nextest run -p agenc-relay-server --test stage_eight_e2ee --all-features --locked`:
  46 passed, 17 Stage 10 drills skipped, among them both ReInit scenarios.
- Mutation testing: 130 single-check mutations of `reinit_target.rs` and the
  chain's ReInit checks, one per condition and per compared field, each
  rebuilt and run against the `reinit_vectors` and `history` test binaries:
  129 killed. The survivor removes the stored bound target: a bound chain then
  compares the carried target's digest instead of its bytes, which refuses
  exactly the same attempts. An earlier pass found five structural policy
  comparisons and two binding comparisons that only an endpoint-path check
  masked (now tested through the sequencer's path as well) and two
  conversation comparisons that could not refuse anything on their own
  (removed).
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-e2ee --all-features --branch --locked --json`:
  every new region at 100 percent (the twenty-three `branches` regions of all
  their branches, the reconstruction's 17 of 17 regions), the respanned
  `e2ee-history-resume` at 12 of 12 branches, and the crate at 91.09 percent
  of branches (90.20 at the parent commit). The three moved `regions` rows of
  the history score 67 of 69, 60 of 62 and 84 of 86 in this e2ee-only
  report, against 67, 59 and 84 at the parent commit.
- `python3 scripts/check-coverage.py audit` and `self-test` on both policies:
  passed (21 and 1,170 reviewed spans).
- The program's fast static gate (59 commands of the Stage 09 static lane plus
  the coverage audits): all passed.

The workspace test run and the full `bash scripts/check-stage-nine.sh` run at
the tip of the branch; their results are in the program's lane report.
