# Direct route release

This record closes ENC-23 (issue #173), the coordinator-side gap found while
remediating ENC-15 (#160): the runtime never released a direct route
reference on the live path, so a long-running coordinator kept, and restated
in every full cut, every direct route it had ever projected to a Server ID.
PR #171 worked around it at cut time only. No wire object, registry, limit or
normative text changed; the `route_state_hidden` event the companion already
defines carries the removal.

## What was observed first

The owner's rule is to observe, not guess, so the live path was stepped
under `rust-gdb` before and after the change, in the coordinator scenario
`a_departed_standing_is_hidden_by_the_next_plan_and_released_with_it`
(a real `EORIGIN DEL`, then a real channel application by another origin):

- **Before** (the scenario with the new `mark_departure` call removed, which
  is `main`'s live path): stopped in `origin_del`, `entitlements.direct` held
  one entry and `departing` none; no breakpoint in `mark_departure`,
  `release_departed` or `release_direct` was ever reached, the entry was
  still there when the next plan committed, and the scenario failed at its
  first departure assertion. The reference count never moves on `main`.
- **After**: `origin_del` reaches `mark_departure` with `direct = 1`,
  `departing = 0` and leaves `departing = 1`; nothing is released there. The
  next committed plan's effect, `plan_releases::{closure}` called from the
  request's commit, reaches `release_departed` with `direct = 1`,
  `departing = 1`, and two lines later both read `0`. That is where the
  count was expected to reach zero: with the plan that carries the removal,
  not before it.

Two further facts were observed rather than assumed. `hosts_direct_account`
counted a fenced companion origin as hosting, and an origin still suspended
after the edge replayed its origin set, so hosting could never end by that
clause; both are now excluded (`direct_release::attached_at`). And the edge
refuses a second ordinary event that arrives while the first one's batch is
in flight (`admit_event` checks the next sequence before it queues); the
state core holds link input during a batch, so the bridged regression feeds
one frame at a time with its batch settled in between, as the daemon does.

## Live release

The coordinator has no mutation of its own: every event leaves in the plan
of a client request. So the release is in two steps
(`crates/agenc-relay-runtime/src/e2ee/coordinator/direct_release.rs`,
`RouteEntitlements` in `crates/agenc-relay-domain/src/e2ee/projection.rs`):

1. When hosting may have ended — `EORIGIN DEL`, an `EORIGIN UPDATE` (logout,
   account switch, detach), and `EORIGIN READY` after a replay, where an
   origin not declared again is gone — the edge's direct standings are marked
   departing (`mark_departure`), at most `MAX_DEPARTING_DIRECT` (4,096).
2. The next committed mutation plan that already delivers events looks at up
   to sixteen departing standings. One whose edge hosts neither account — no
   live attached companion origin and no base account projection standing at
   that edge — gets a `route_state_hidden` copy in that plan, naming the
   prior route object, and `release_departed` drops every reference with the
   commit, so a later event projects the route again first. One still hosted
   keeps its reference and leaves the queue after
   `DEPARTING_DIRECT_LOOKS` (8) looks, which covers a base session removed
   after its companion origin. A standing the same plan delivers an event
   for is left alone.

## The cut and the edge check enforce one rule

A full cut names a direct route exactly when the edge hosts one of its
accounts at the cut: `refresh_entitlements` fences the edge's direct
references and re-derives them from `hosts_direct_account`, which now shares
`attached_at` with the live release. That is the rule the edge verifies
(ENC-15). The cut was not narrowed below hosting, deliberately: the edge's
projected direct routes are the only place the plaintext downgrade refusal
for a bound direct pair is enforced (`E2eeEdge::direct_pair_bound`; the
coordinator's base message path has no such check), so a cut that omitted a
hosted account's bound pairs would let that account send plaintext to a
bound peer.

## The republished cut

An interrupted cut was republished unchanged, so a cut that named a pair the
edge stopped hosting was refused by the edge until its 15-minute token
expired. `resume` now republishes a pending cut only while
`pending_cut_current` holds: every direct route standing for the edge is
still hosted. Otherwise the cut is dropped exactly as an expired one is and
the scope takes a fresh cut in its next delivery generation. The limit that
remains is narrower: hosting that ends during one link's transfer is covered
on the edge by the hosted-at-open rule, and a change the coordinator has not
learned by the next `ERESUME` still republishes the old cut.

## Evidence

- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/direct_release.rs`
  (real coordinator): a hosted standing is left alone; the real
  `EORIGIN DEL` marks it; the next plan carries `route_state_hidden` to that
  edge and drops the references; a later plan hides nothing more; a standing
  still hosted keeps its reference and leaves the queue after eight looks; a
  pending cut is republished byte for byte while the pair is hosted and
  retired for a fresh, entry-free cut once it is not.
- `crates/agenc-relay-runtime/src/e2ee/edge/tests/direct_release_bridged.rs`
  (the coordinator's rendered lines into the real edge): hosting ends and
  the route leaves the edge's conversations, route objects and route table
  with the link up and both copies acknowledged; a reinstalled edge whose
  Server ID still holds a direct reference is sent a cut with no entry and
  records READY; an honest cut naming a hosted pair is accepted when the
  counted session closes between BEGIN and the entry, and the same cut is
  refused by an edge that never hosted the pair.
- `crates/agenc-relay-domain/src/e2ee/tests/projection.rs`: the departing
  queue, its looks, the release, and the fences that clear it.

## Limitations

- The release rides the next mutation plan that delivers events. A
  coordinator that commits no such plan after a departure keeps the standing
  until the edge's next full cut. A coordinator-originated mutation would
  remove the wait and is not part of this change.
- Channel routes still leave an edge only through a successor or a full cut;
  the live `route_state_hidden` for a channel whose last local entitlement
  ended is not produced.
- An account that logs in after a cut gains its bound direct pairs at that
  edge only with the next event or cut, so the edge-side downgrade refusal
  does not cover it until then; the coordinator's base path has no check.
- Departures beyond `MAX_DEPARTING_DIRECT` are corrected by the next cut.
