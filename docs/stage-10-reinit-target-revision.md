# The ReInit target revision and successor installation (PC-001)

This record covers the SDK server program's single normative revision, plan
item P-01 (2026-10-04, outside master #35). It changes both specifications and
the source ledger, moves the E2EE profile hash under the unchanged profile
version 1, and changes no production behaviour: the only production sources
that change are the three that pin the moved values. The series is two
commits, as for every earlier hash move: this normative commit, then a commit
that edits only `conformance/spec-baseline.toml` to refreeze the baseline at
it.

| Part | Specification | Decision | State at this revision |
| --- | --- | --- | --- |
| ReInit target without the finalization ID | companion 13.8 | D-08, D-09 | Specified; unimplemented |
| Target carried in every attempt; sequencer checks; atomic successor installation | companion 13.8 | D-11 (B), D-11a | Specified; unimplemented |
| Successor context, rosters and later joiners | companion 9.5, 13.8 | D-11, D-12 | Specified; unimplemented |
| `CLAIM STATUS` names the stored target | companion 11.6 | SC-001 | Specified; implemented by SC-001 |
| Edge recovery epoch in CAP and descriptor | architecture 9.3, A.3, C.8 | D-15 | Specified; implemented by AUD-03 |
| Recovery `NOTE` gating and the welcome `900` | architecture 9.5, E.2 | D-13 | Specified; implemented by SC-007 |
| `preauth_command` default burst 24 | architecture 19.1, C.6 | D-14, D-14a | Specified; the configuration keeps 10 until B-05 |
| Two shared client crates | architecture 24.1 | D-16 | Specified; the crates arrive with X-01 |
| `cargo fmt --check` | architecture 28.8 | D-30 | Specified; the gate pins move with X-09 |

## Why

At the previous profile hash, companion Section 13.8 put
`old_reinit_state_id`, the finalization ID of the old ReInit Commit, inside
`ArcReInitTargetTBS`. The authorization of that same Commit commits
`transition_target_digest`, the digest of the target, and the finalization
commits the authorization. The target digest, the authorization ID and the
finalization ID therefore formed a content-address cycle: no target could be
built before the finalization that must commit it, and no conforming ReInit
could complete.

The other parts are the program's decisions D-11 to D-16 and D-30, with D-11a
and D-14a, which the program fixed before this revision so that the hash
moves once.

## The companion

### The target (Section 13.8)

- `old_reinit_state_id` leaves `ArcReInitTargetTBS`. Every remaining field is
  fixed by the old conversation and the ReInit Proposal: the Proposal's group
  ID, version, suite and exact extension list, the Section 2.2 conversation ID
  of that group, and the binding, plan and context core of the list's single
  context extension, the context core recomputed from the
  `required_capabilities` extension and the context.
- The text states the successor that context describes: active, not
  bootstrapping, with no pending join, a generation-zero policy and a
  sequencer credential that its binding names, and a binding that is the
  Section 9.4 replacement of the old conversation's current binding on the
  same semantic route lock and concrete route. Section 9.4 now says that such
  a binding takes its channel instance or conversation nonce from the binding
  it replaces, since a successor has no reservation.
- The successor's policy, controllers and finality council are verified under
  the rosters that the successor context's roster heads name, and each of
  those heads for an account the old context also names carries the old
  head's root or a continuous successor of it (decision D-12). A ReInit
  therefore never carries a root discontinuity; whether it can rotate a
  channel's authority root, which the kept semantic route lock names, is
  P-03's to establish (decision D-12 (1)).
- Because no target field depends on the accepted state, one target stays
  byte-identical across an accepted-state advance, a candidate abort and an
  attempt retry; a later candidate needs only its own authorization.
- The successor initial Commit's `ArcCommitAad` names the target's profile
  version and network, the new conversation, the route, and
  `old_reinit_state_id` as `prior_state_id`. The successor has no accepted
  state before activation, and naming its activation ID would recreate a
  cycle through the attempt's `initial_commit_digest`. The Commit is a
  `PrivateMessage` that only its creator parses; Welcome recipients check the
  same facts from their Welcome.
- Every post-finalization `old_reinit_state_id` (attempt, attempt
  authorization, receipt, `ArcStagedReInit`, ACK, vote, activation, abort)
  keeps its meaning.

### The carried target and the successor installation (decisions D-11 (B) and D-11a)

`ArcReInitAttempt` gains one field, `ArcReInitTargetTBS target`, after its
TBS: the exact target whose digest is the attempt's `target_context_digest`.
The activation and abort requests embed the attempt, so the target reaches
every verifier, including a member that joins after activation.

- The sequencer refuses an attempt with `E2EE_FINALITY_REQUIRED`, retaining
  nothing, while the old conversation's accepted state is not the
  finalization of a ReInit Commit. Only for an attempt on a conversation
  whose accepted state is that finalization does it check, before it signs an
  attempt receipt, and refuse with `E2EE_BINDING_AUTH_INVALID`, retaining
  nothing, an attempt whose `old_reinit_state_id` is not that finalization;
  whose carried target does not hash to the attempt's digest or whose digest
  is not the authorized `transition_target_digest`; whose group, version,
  suite, conversation, binding or plan differs from the target; whose
  `ArcKeyPackagePlan` does not form the target's semantic initial member
  plan; or whose target's extension list fails the structural endpoint rules
  against the old conversation's current binding, or does not yield the
  target's own conversation, context core, binding and plan IDs. No reply code
  or registry entry is added.
- At activation the coordinator installs the successor from the carried
  target in the transaction that stores the activation certificate, before
  any reply or event: the route remap, the successor conversation with its
  binding, its current binding object (the binding package the attempt's plan
  forms), its policy and its sequencer credential, the accepted state and
  record-head anchor, and the delivery mappings. The successor's context
  digest is the Section 2.2 `context_digest` of its `ArcMlsContext`, kept
  apart from the target digest. A ReInit successor is never bound with
  `EGROUP RESERVE` and `EGROUP BIND`, and a restart restores the installed
  successor.
- A member that joins after activation checks its join bundle's ReInit
  binding-chain and policy-chain entries against the target the activation
  certificate's attempt carries, including the target's derived IDs and the
  old authorization against the carried target's digest, and relies on that
  certificate's old-policy quorum for the checks that need the old group's
  state.
- Section 16's headroom rule counts the carried target in the attempt and in
  the terminal requests that embed it.

### The other companion sections

- Sections 2.3 and 22 record the revision: profile version 1 stays and the
  hash moves although, unlike the revision before it, this one changes two
  object layouts, which the first rule of Section 22 would give a new
  version; under the previous hash no target could be constructed, so no
  conforming ReInit exists to keep interoperable, and exact-match CAP and
  ECAP negotiation refuses every peer that presents that hash. A ReInit object
  stored under the previous hash is never parsed under this one.
- Section 9.3 says no transition target digest covers an accepted-state or
  record ID, and Section 9.5 says which verifier checks a ReInit policy entry
  against which target.
- Section 11.6 states that `CLAIM STATUS` names the claim's stored target
  device, as `CLAIM PACKAGE` did, never the device that asks (SC-001).
- Section 13.7.2 gains the coordinator's attempt rows and the two endpoint
  rows, and Section 21 items 2, 13 and 16 gain the vectors and tests the new
  rules need.

## The architecture

- Section 9.3, Appendix A.3 and Appendix C.8: a coordinator or standalone
  node advertises its own database epoch in `agenc.ag/recovery`, and an edge
  its coordinator's, as its enabled coordinator peer record pins it; the
  welcome `NOTE` and the `print-onboarding` descriptor carry the same epoch,
  `serve` refuses an edge without an enabled coordinator peer record, and
  `print-onboarding` prints no descriptor for it (decision D-15). The AUD-03
  change already made the daemon do this.
- Section 9.5 says the welcome `NOTE * RECOVERY_EPOCH` does not depend on
  `standard-replies`, and Appendix E.2 shows the account-state `900` after
  the MOTD group and that `NOTE`, the order Section 10.2 fixes (decision
  D-13). The SC-007 changes already send them so.
- Section 19.1 and Appendix C.6 raise the `preauth_command` default burst
  from 10 to 24; the default rate stays one token per second and the hard row
  stays 10/1 with burst 50 (decisions D-14 and D-14a). A paragraph in C.6
  says why: the burst covers the longest run of lines a client sends before
  registration with no reply between them, and the credit beyond it lets
  account creation or a pre-registration login, each followed by
  registration, finish within the 30-second registration limit at round
  trips of up to 3 seconds, as `tor-exit` and `onion` connections can have.
- Section 24.1 adds `agenc-relay-client-support` (onboarding descriptor and
  endpoint grammar, SOCKS5 codec; no socket, TLS or Tokio API; workspace
  edges to `types` and `federation-wire`) and `agenc-relay-transport` (the
  client side of TLS and SOCKS, and the TLS policy, provider, trust store and
  SPKI digest both sides share; edges to `types` and `client-support`), and
  gives `config` an edge to `client-support` (decision D-16).
- Section 28.8 runs `cargo fmt --check`, which formats every workspace member
  and no path dependency outside it, so a reviewed vendored source keeps the
  bytes its tree digest names (decision D-30).
- Section 30.3 and Appendix C.8 carry the new companion hash and token.

### Deriving the pre-authentication default

Decisions D-14 and D-14a ask for the smallest burst at which the SDK's
account pacing model admits both the account creation followed by
registration and the pre-registration login within the 30-second
registration deadline, at one token per second and round trips of up to
3 seconds, because the SDK supports the `tor-exit` and `onion` profiles. The
model is `crates/agenc-relay-sdk/src/session/machine/account_phase.rs` in
agenc-relay-sdk at `f1c2509`. That file is byte-identical at `a6844c1`, the
commit whose documentation of the model D-14 cites, and at `0332a28`; the
session pacer it drives changed between `a6844c1` and `f1c2509` and not
since. The model admits a flow only if the burst covers the flow's longest
run of lines that no reply shows read, because the pacer credits nothing to
such lines: 16 `AUTHENTICATE` chunks for a login, and an `ACCTCREATE`
request's 16 `DATA` lines and `END` for a creation. Beyond that run, the
deadline decides.

Run with its default inputs otherwise (250 ms of server work per request and
1.5 s for the client's finish), the smallest burst admitting both flows is:

| Round trip | 0 to 1 s | 1.5 s | 2 s | 2.5 s | 3 s |
| --- | ---: | ---: | ---: | ---: | ---: |
| Smallest burst, one or two `CAP REQ` lines | 17 | 18 | 19 | 21 | 24 |

At 3-second round trips, burst 23 admits the login (27.519 s) and refuses the
creation with registration on the deadline (30.525 s predicted); burst 24
admits the login (26.517 s) and the creation (29.523 s); no burst below 24
admits both. The default is therefore 24. The values come from tests added
only to a scratch copy of the SDK; the SDK's own test
`a_burst_covering_the_run_leaves_the_deadline_to_decide` pins the 16 and 17
boundaries at zero round trip.

## The source ledger

`docs/protocol-sources-and-decisions.md` gains Section 9, dated 2026-10-04:
what changed in each specification, the coordinated upgrade, the descriptors
issued again, the unchanged persistent format, and the four version axes of
architecture Section 26.2. `scripts/check-spec.sh` now expects nine ledger
sections, and `ledger_sha256` in `conformance/release-source-decisions.toml`
names the new ledger; the source decisions themselves and their date are
unchanged.

## Values

| Value | Previous | This revision |
| --- | --- | --- |
| companion raw SHA-256 | `57d6d98df53ce8f738da463304fb47726c9133ef0bec5b268a8cadbc117405bc` | `4fa947bf4edfe146de8f6a72932b93625828b0fd6eea46976e699ab06719658c` |
| E2EE profile hash | `c1b5313f8a7f196cda30eea797fb1ab65b004a55d71cf9a81071927046e5d395` | `0b3985c1e19f77e561734139d65131fb1c1fc5cb7a63a1119ca03b5a61583525` |
| E2EE profile token | `wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U` | `CzmFweGfd-Vhc0E51lEx-xwfxct6Y6ERnKA7WmFYNSU` |
| architecture raw SHA-256 | `46f2924279daa9d68347112748ab08b4850a74508fa05841c3fd45f5dbf66e81` | `7317477b0058ec2bc3cba3f14921154e849358e5016ae36bbe18a08fb2fa6528` |
| source ledger raw SHA-256 | `23a20cb38c7918d8488403fc780fc1eba14c647d187548f921cee4cdad4635ac` | `430af31197f917c143c7a4f61aabe5c602854a9322674263c0ad59858207fc62` |
| `scripts/check-spec.sh` raw SHA-256 | `9f52553174e8f190020a76ffa002d30c55cdd4b21ea0f24ab314386798efd29a` | `69575580be5ef3fabcca507ebcb240ed12e5d3949ed61c2b928a76318556d3b7` |
| specification manifest raw SHA-256 | `fd79b41f0a42aa38b23e2383225eaf9189d4f0b06dab00ee3d99e88a7df1d1f4` | `a0aaed6845250fea877e08b9c2afa4792d6e1af392e39700f20d88f914bf2b45` |
| base federation profile hash | `7b00e0d0844270626411d398f15f7520224ea906117738e3da9741a611dc67b3` | unchanged |
| `agenc.ag/e2ee-mls` value | `v1,profile=wbUxP4p_GWzaMO6nl_satlsASlXXHPmoEHGScEbl05U,seg=2940,obj=262144,parts=90,welcome=4194304` | `v1,profile=CzmFweGfd-Vhc0E51lEx-xwfxct6Y6ERnKA7WmFYNSU,seg=2940,obj=262144,parts=90,welcome=4194304` |

The profile hash and token were computed independently of the server's
scripts (Python `hashlib` over the companion bytes and the Section 2.3 label)
and agree with `check-spec.sh`, `check-stage-one.py`, `generated_hashes.rs`,
the E2EE `CAPABILITY_VALUE`, the configuration's onboarding token and the
Stage 08 profile record.

Pins moved: the architecture's companion hash, profile hash and descriptor
token; `scripts/check-spec.sh`, `scripts/check-stage-one.py` and
`scripts/check-stage-eight.py`; `conformance/stage-eight-e2ee-profile.toml`;
`docs/specification-manifest.txt`; the regenerated
`crates/agenc-relay-federation-wire/src/generated_hashes.rs`;
`crates/agenc-relay-e2ee/src/limits.rs` (`CAPABILITY_VALUE`);
`crates/agenc-relay-config/src/onboarding.rs` and its template test; and
`conformance/release-source-decisions.toml`. The baseline itself moves in the
refreeze commit. No binary file holds a pinned hash.

## Requirements and coverage

Twenty-one new BCP 14 clauses, all in companion Section 13.8, take
`conformance/requirements.toml` from 251 to 272 records. No existing clause
changed its text, so no binding went stale. Following decision D-12, each new
clause is bound as `unimplemented`, and no task box changes:

| Clauses | Count | Task |
| --- | ---: | --- |
| endpoint reconstruction and rejection rules | 8 | `S10-005` |
| later-joiner rules | 5 | `S10-005` |
| successor initial-Commit authenticated data | 1 | `S10-005` |
| sequencer refusal without a ReInit finalization (`E2EE_FINALITY_REQUIRED`) | 1 | `S10-004` |
| sequencer attempt checks (`E2EE_BINDING_AUTH_INVALID`) | 5 | `S10-004` |
| coordinator successor installation | 1 | `S10-004` |

The architecture text adds no BCP 14 clause. Both coverage policies take the
new production source inventory (1,010 files, `4d95f382…`); no reviewed region
covers a changed source.

## The coordinated upgrade

Every node that has the encrypted profile enabled moves to this revision
together. CAP and ECAP accept only the exact `(version, profile-hash)` pair,
so a client of the previous revision is not offered the encrypted profile,
and a federation link whose ends present different hashes fails ECAP with
`ERROR :ARC-MLS profile mismatch` and closes (companion Section 12.5); an edge
whose coordinator link is closed behaves as architecture Section 20.10
states. Every onboarding descriptor that carries the E2EE lines, and every
account invitation that embeds one, is issued again after the upgrade,
because an importer refuses a descriptor whose `e2ee-profile-sha256` differs
from its build constant; a descriptor of a node with the encrypted profile
disabled is unaffected. Clients import the new descriptor through the
explicit confirmation architecture Sections 6.3 and 9.3 require for a changed
pin. Recovery epochs, keys and the base federation profile are unchanged, and
so is the storage format (generation 5).

## Review

An independent review of an earlier draft of this series, before anything
was merged or pushed, led to: the sequencer's refusal order
(`E2EE_FINALITY_REQUIRED` first, as its own clause); the derived-ID checks of
the carried target by the sequencer and a later joiner; the joiner's
old-authorization check against the carried target's digest; the
successor initial Commit's profile version and network; the narrower
root-rotation statement; the reservation sentence of Section 9.4; the shared
TLS pieces in Section 24.1; the descriptor and stored-object statements of the
ledger; and the wording of Sections 2.3, A.3, C.8 and E.2. The program then
set the pre-authentication default to cover 3-second round trips (D-14a).
The series was rebuilt as one normative commit and one refreeze.

## What stays open

- P-02: the shared target helper and its vectors, and the Stage 08 fixture
  that builds one target and carries it in the attempt.
- P-03: verifying the successor policy under the successor's own roster
  heads, with root-rotation and suite-change vectors, and whether a ReInit
  can rotate a channel's authority root, which the kept semantic route lock
  names.
- P-04: the sequencer's attempt checks and reply codes, the atomic successor
  installation, its restart and crash behaviour, and the Stage 08 model
  update, which implement the seven `S10-004` clauses.
- P-05: refusal of the previous profile's token and capability value, the
  mixed-version link test and the operator guide's upgrade note.
- X-01 to X-04: the two crates of Section 24.1.
- X-09: `conformance/gates.toml`, `scripts/check-ci.py` and
  `scripts/run-stage-ten-workspace.py` still pin `cargo fmt --all --check`,
  which formats the same files until the vendored opaque-ke source becomes a
  path dependency.
- B-05: the `preauth_command` default in `crates/agenc-relay-config`, its
  golden file and the `arcd init` template, which keep burst 10 at this
  commit.
- For the owner: under TODO.md's rule that a changed normative source or
  profile hash reopens every affected task, every S08 task that
  `conformance/stage-eight-e2ee-profile.toml` binds was evidenced under the
  previous profile hash, among them `S08-001` and `S08-031`, which test the
  exact hash, `S08-017` and `S08-900`; `S08-019` and `S08-033` rest on
  companion Section 21 items 2 and 16 (TODO gates 2 and 17), which gain
  ReInit vector and cycle obligations, as `S08-030` rests on item 13 (TODO
  gate 14) and `S08-012` on the target layout, the ReInit fixture and the
  activation contract; `S01-010`'s pins were regenerated here; `S00-004`'s
  graph names crates the workspace gains only with X-01; `S06-011`'s
  pre-authentication default differs from the configuration until B-05; and
  the Stage 09 checkpoint names an earlier exact commit. Whether to reopen
  them, and whether to record Stage 09 again, is the owner's decision.

## Validation

On the tree of this commit, before it was committed, with Rust 1.98.0:

- `bash scripts/check-spec.sh`: passed, E2EE profile
  `0b3985c1e19f77e561734139d65131fb1c1fc5cb7a63a1119ca03b5a61583525`.
- `python3 scripts/check-stage-one.py check`, `self-test` and
  `scripts/generate-stage-one.py --check`: passed.
- `python3 scripts/check-stage-eight.py check` and `self-test`: passed.
- `python3 scripts/requirements.py check`: 272 records; `self-test` (13
  rejection cases) and `check-stage-zero` to `check-stage-nine`: passed.
- `python3 scripts/check-coverage.py audit` and `self-test` on both policies:
  passed (21 and 1,146 reviewed spans).
- `generate-e2ee-vectors.py --check`, `generate-e2ee-wire-budget.py --check`
  and `generate-e2ee-fuzz-seeds.py --check`: passed, unchanged by the
  revision.
- `python3 scripts/test-release-qualification.py`: passed. It runs the
  document lint of `scripts/check-release-claims.py` over `TODO.md` and the
  other ledgers; the claims driver itself needs a release candidate and was
  not run.
- `python3 scripts/check-baseline.py`: fails, as at every normative commit,
  because the frozen commit must contain the new artifacts; the refreeze
  commit makes it pass.
- The program's fast static gate, 59 commands from the Stage 09 manifest's
  static lane plus the coverage audits: 58 passed, and the 59th is
  `check-baseline.py` above.
- A content-address dependency analysis of the companion's TLS structures
  (119 structures): one cycle at the previous revision, none at this one,
  and none with the successor initial Commit naming the old finalization.
- `cargo nextest run -p agenc-relay-federation-wire -p agenc-relay-config -p agenc-relay-e2ee -p agenc-relay-runtime --all-features --locked`:
  3,267 tests passed, 2 skipped.

The fast static gate, the same crate suites and the full
`bash scripts/check-stage-nine.sh` run again at the refreeze commit; their
results are recorded with the program's push report.

## Limitations

- The new rules are text. The requirement ledger shows every new clause as
  unimplemented until P-02 to P-04 implement it.
- The target's MLS-level facts (the Add set, KeyPackageRefs, the PSK use and
  the successor tree) stay endpoint obligations; the server checks only the
  public bytes the target and attempt carry.
- A later joiner still relies on the old-policy quorum for the checks that
  need the old group's state, such as the old context's roster heads.
- The pre-authentication default covers the model's flows at round trips of
  up to 3 seconds. A client whose round trips exceed that needs an operator
  to raise the burst, within the hard maximum of 50.
