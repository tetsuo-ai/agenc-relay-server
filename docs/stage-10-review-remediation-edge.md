# Edge review remediation

This record closes ENC-15 (issue #160), ENC-16 (issue #161) and ENC-17 (issue
#162): the three findings the internal review of the encrypted profile (#76)
reported against the hostile edge and client surface and the recovery and
witness gates. The review was internal: one reviewer who took no part in the
implementation and worked from the specification, the review package and the
source alone. It was not a third-party audit and does not close `S08-039`.
The findings and their dispositions are in
[the review findings ledger](../conformance/review/findings.md). No wire
object, registry, limit, reply code or normative text changed, so the
specification baseline is untouched.

## ENC-15: base entitlement of an ESTATE snapshot entry

Companion 12.5 has the edge verify "base channel/account entitlement" before
READY and says a direct route "is never projected merely because the edge
hosts a session for either Account ID". The receiver staged whatever route a
cut named. `retain_entry` now refuses the whole snapshot with `E2EE_SYNCING`
before anything of the entry is charged or retained, unless
`cut_route_entitled` (`crates/agenc-ircd-runtime/src/e2ee/edge/entitlement.rs`)
accepts the route:

- a channel route needs `EdgeFederation::holds_channel`: the hosted channel
  detail in the active base projection, or in the base snapshot generation
  still being installed, because a paired base FSNAPSHOT and the companion
  ESTATE are cut from the same standing and arrive interleaved;
- a direct route needs one of its two accounts hosted here:
  `EdgeFederation::hosts_account` (the account projection in either base
  generation, or a base origin this edge declared, live or still awaiting its
  deletion) or a local companion origin with an attached device. This mirrors
  the coordinator's `hosts_direct_account`;
- hosting is read when the entry arrives and as it stood when page zero
  opened the transfer. A paired base resynchronization closes every session
  the cut counted while later pages are still being fetched, and an honest
  cut must not be refused for that. The accounts retained for it are charged
  against the snapshot backing port and released with the generation; an
  empty cut retains none;
- a cut may restate a direct route this edge already projects for the same
  pair: that discloses nothing, and refusing it would refuse an honest cut
  taken before the edge's user left.

The refusal is a frame failure: the link closes, the staging generation is
abandoned and its rows cleaned up, and no READY is sent. The witness
resolution installer (`stage_witness_resolved`) now rewrites a head only on a
channel route whose channel the base projection still hosts, and otherwise
closes the link with the row retained; it never creates a projection, so a
direct route it touches is one the edge already holds.

One coordinator change was needed to keep an honest cut verifiable. The
runtime never released a direct reference (`RouteEntitlements::release_direct`
has no caller), so a long-running coordinator restated every direct route it
had ever projected to a Server ID, including to a reinstalled edge that hosts
none of those accounts; the new check would have refused that cut for good.
`refresh_entitlements` now calls the new `RouteEntitlements::fence_direct`
before every full cut and re-derives direct standing from
`hosts_direct_account`, which is what the reset that precedes a full cut
already means for the origins and events those references stood for. A later
direct event re-projects its route first, exactly as for a first entitlement.
The missing release on the live path is unchanged and is reported separately.

Known limit: the coordinator republishes an interrupted cut unchanged. A cut
that named an account this edge hosted at the time, republished after a link
loss to an edge that no longer hosts it and never projected the route, is
refused until the cut's 15-minute token retires it and the next cut is taken.

## ENC-16: fragment-zero charging and the decoded-byte ingress bucket

Companion 16 charges E2EE ingress by decoded bytes "through a dedicated
authenticated token bucket that provides at least
`MIN_ADMITTED_E2EE_INGRESS_RATE`" after "cheap fragment-zero checks and atomic
quota reservation", and counts signature verifications per verification.
`route_e2ee_line` charged every fragment line one `E2eeCommand` and one
`E2eeSignature` token: a 4 MiB control object moved at about 11,760 bytes per
second and cost 1,427 verifications.

`E2eeEdge::ingress_charge` (`crates/agenc-ircd-runtime/src/e2ee/edge/ingress.rs`)
now classifies each line before admission from its one bounded fragment tag:

- a command line, a fragment zero, a malformed tag and a fragment behind no
  accepted fragment zero are command lines: one `E2eeCommand` token for the
  session and, when the line carries object bytes, one `E2eeSignature` token
  for the account. One object is one verification;
- a continuation is a fragment of index above zero whose object is the one
  this connection's in-progress assembly holds (fragment zero was admitted
  and its quota reserved), or the one whose fragment zero was just answered
  from the retry cache, whose duplicate fragments the assembler ignores
  without work. It is charged its decoded bytes against the new
  `BucketKind::E2eeIngress`, keyed `BucketKey::AccountDevice(account, device)`
  with an all-zero device while none is attached.

The bucket refills exactly `MIN_ADMITTED_E2EE_INGRESS_RATE` (65,536) bytes a
second with a burst of one `MAX_LIVE_OBJECT` (262,144 bytes), so a live object
is never paced by its own size and the largest control object completes in 60
seconds against the 64 the floor allows and the 351 the line bucket needed.
It is fixed like the other two companion rows: no configuration name, and its
hard rate is its default. A fragment behind no accepted fragment zero is
still refused by the router with `E2EE_INVALID_FRAGMENT`, now having paid for
a command line rather than riding the byte bucket.

The Stage 08 daemon harness pacer that ENC-10 (#71) added follows the same
model: a command line or a fragment zero waits for a line token, a
continuation fragment waits for its decoded bytes, and the line burst the
suites allow themselves is unchanged.

## ENC-17: the successor credential's overlap window

Companion 12.5.1 admits a witness-resolution record under the overlapping
successor only "during `MAX_SEQUENCER_KEY_OVERLAP`". `verify_record` accepted
either credential of the negotiated set at any time.
`SequencerKeySet::credential_at` now admits the active credential at any
second and the successor only from its own `not_before` through
`MAX_SEQUENCER_KEY_OVERLAP` afterwards, so a successor record before the
window opens is refused as well as one past its close. The second is the one
the record signed, read by `record_authentication::declared_sequenced_at`: a
receipt's own `sequenced_at`, and for a terminal certificate the
`sequenced_at` of the receipt it embeds, the only signed time a terminal
carries and a lower bound on its own. The edge consults no clock. A successor
record outside the window closes the link as a profile violation and retains
the row, like any other record under a key the link did not negotiate.

## Evidence

- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/snapshot.rs`: an unentitled
  channel entry and an unentitled direct entry each refuse the snapshot with
  nothing of the entry retained and nothing staged, and the frame failure
  abandons the generation before any READY; the same channel cut installs once
  hosted; a direct entry installs for an attached device of either account, is
  refused for an unattached origin or a third account, is accepted when its
  host closed after the transfer opened and refused when it closed before;
  a cut may restate a projected pair and may not change it. The receiver's
  existing tests now host every channel they feed.
- `crates/agenc-ircd-runtime/src/federation/edge/tests/pending_generation.rs`:
  the channel detail, account projection and session accounts of the active
  and of the installing base generation.
- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/witness_resolution.rs`: an
  authentic continuation for a channel the base no longer hosts closes the
  link and retains the row; a successor record at the opening, inside and at
  the close of its window stages its installation, the active credential has
  no window, and a successor record before, past and far past the window, or
  on a link that never negotiated it, is refused with the row retained.
- `crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/sync.rs` and
  `crates/agenc-ircd-domain/src/e2ee/tests/projection.rs`: a full cut drops a
  direct reference the edge no longer hosts and keeps its channel standing;
  `fence_direct` touches one edge's direct references only.
- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/ingress.rs`: one
  three-fragment object costs one command token, one signature token and its
  continuation bytes; a fragment behind no accepted fragment zero is a
  command line and is refused `E2EE_INVALID_FRAGMENT`, and another
  connection's admitted object entitles it to nothing; the duplicate
  fragments of a retried object ride the byte bucket until the next fragment
  zero; a `MAX_LIVE_OBJECT` is admitted at once and a
  `MAX_SEQUENCER_RECORD_OBJECT` inside the floor's time without touching the
  line bucket.
- `crates/agenc-ircd-e2ee/src/tests/sequencer.rs` and
  `crates/agenc-ircd-e2ee/tests/record_authentication.rs`: `credential_at`
  before, at the opening, inside, at the close and past the window, and the
  signed second of every record arm.
- `crates/agenc-ircd/tests/stage_eight_e2ee.rs`: the daemon suite passes
  under the relaxed pacer.

## Limitations

- The live `route_state_changed` path is not entitlement-checked; companion
  12.5 assigns that verification to the snapshot, and a live change arrives
  in the same ordered plan as the base delta that entitles it.
- The coordinator still never releases a direct reference between full cuts,
  and its cut names every direct route of a hosted account; both are
  coordinator-side divergences from the companion's least-information rules
  that this change neither introduced nor repaired.
- A terminal certificate's time is the receipt it embeds, so a terminal
  certified after the window under a successor whose receipt was sequenced
  inside it is admitted. No record arm carries a later signed time.
- The ingress bucket's burst is a deployment default inside the companion's
  floor, not a companion limit.
- Native release qualification remains with the root release issues.
