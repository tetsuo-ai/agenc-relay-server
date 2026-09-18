# Edge snapshot generations

This record closes ENC-14 (issue #59): the edge's complete ESTATE receiver is
a bounded, durable pending-generation owner. Every page is verified and staged
in its own storage batch under the pending generation's keys, READY is
recorded durably before it is sent and resent identically after a reconnect,
ACTIVE alone swaps the generation into use, and the generation's rows then
migrate into the active keys in bounded batches; an abandoned generation is
cleaned up the same way. No wire line, limit, or normative text changed; the
coordinator's publication side (CAP-82 hashing, pending-cut publication and
reconstruction) is untouched.

## Rows

Two table-23 rows carry the generation (`crates/agenc-ircd-storage/src/e2ee_records.rs`):

- `pending-route/v1/<delivery-generation><conversation-id>` (kind 20,
  `PendingRouteRow`): exactly a `route/v1/` body under the generation's key,
  so one generation is one contiguous key range.
- `edge-snapshot/v1/<coordinator-server-id>` (kind 21, `SnapshotMarkerRow`):
  the token, state and delivery generation, declared entry count and digest,
  the entries and bytes staged so far, the phase (`Staging`, `Ready`,
  `Active`), the monotonic millisecond page zero opened at, and the
  migration cursor. The staged count never exceeds the total, `Ready` and
  `Active` need every entry, and only `Active` carries a cursor.

Earlier development images without these rows restore no generation.

## Receiving

`crates/agenc-ircd-runtime/src/e2ee/edge/snapshot.rs` replaces the in-memory
`SnapshotInstall`. Page zero opens a generation only in `Resuming`, refuses a
declared count above `MAX_FEDERATION_STATE_ENTRIES_PER_EDGE` before anything
is allocated, and fixes the exact partition (every nonfinal page holds
`MAX_BATCH_OBJECTS` entries, the final page the remainder). Every later BEGIN
must repeat the cut and continue the partition. A route state object is far
below one fragment (`MAX_FRAGMENT_RAW`), so each object is complete with its
first fragment and the assembler checks its declared ID; a complete object
must decode as a route state of this network, name the conversation the
ENTRY line names, follow the previous conversation in order, and not precede the live
witnessed head of its conversation (which is the existing witness path). Its
bytes are charged against the edge's backing reservation port before they are
retained (a refused reservation is `E2EE_RATE_LIMITED` and retains nothing),
its ID is pushed into the streaming `FederationSnapshotDigest`, and it is
added to a pending projection kept beside the live one. Per-page and
cumulative byte ceilings are guards a well-formed route state cannot reach.
The token lifetime is `FEDERATION_STATE_SNAPSHOT_TIMEOUT_SECONDS` from page
zero on the monotonic clock, checked on every frame and never extended.

END with a cursor stages the page's pending rows and the `Staging` marker as
one batch; the next page is fetched only after that batch commits. The final
END verifies the count and the digest, then stages the last page with the
`Ready` marker. When that batch commits READY goes out; after a link loss the
next `link_active` announces the identical READY instead of ERESUME, and the
coordinator answers with the identical ACTIVE. The delivery position does not
move at READY.

## Base entitlement (ENC-15)

The internal review of the encrypted profile found that the receiver staged
whatever route a cut named (issue #160), although companion 12.5 has the edge
verify base channel and account entitlement before READY. `retain_entry` now
asks `cut_route_entitled` (`crates/agenc-ircd-runtime/src/e2ee/edge/entitlement.rs`)
before anything of an entry is charged or retained:

- a channel route needs the base channel-detail entitlement,
  `EdgeFederation::holds_channel`: the hosted channel detail in the active
  projection, or in the base snapshot generation still being installed, whose
  cut pairs with the transfer;
- a direct route needs one of its two accounts hosted here: the base account
  projection in either generation or a declared base origin
  (`EdgeFederation::hosts_account`), or a local companion origin with an
  attached device. Hosting is read when the entry arrives and as it stood when
  page zero opened the transfer, because a paired base resynchronization
  closes the sessions the cut counted while later pages are still being
  fetched; the accounts retained for that are charged against the backing
  port and released with the generation;
- a cut may restate a direct route this edge already projects for the same
  pair, which discloses nothing.

An unentitled entry answers `E2EE_SYNCING`: the frame failure closes the link,
the staging generation is abandoned, and no READY is sent. The witness
resolution installer rewrites a head only on a channel route whose channel the
base projection still hosts; it never creates a projection, so a direct route
it touches is one the edge already holds. The coordinator side was made exact
to match: `refresh_entitlements` drops an edge's direct references before every
full cut and re-derives them from what the edge hosts, so an honest cut never
restates a pair the edge cannot verify. A cut the edge hosted at the time but
no longer does, republished after a link loss, is refused until its 15-minute
token retires it and the next cut is taken. The remediation record is
[the edge review remediation](stage-10-review-remediation-edge.md).

## Activation and migration

ACTIVE must name the exact cut of the durable READY generation. It stages the
`Active` marker and the new delivery cursor (generation, no position) as one
batch; on commit the pending projection becomes the live one, the base edge
learns the new cursor, and the origins replay. From then on the migration
moves at most `STEP_ROWS` (256) conversations per batch from their pending
keys into `route/v1/` and deletes the stale rows of the previous generation up
to the same cursor, advancing the marker's cursor; the marker is deleted with
the last batch. A live `route_state_changed` during the migration also
refreshes the conversation's pending row (or removes it when hidden), so the
migration never copies a superseded object. Migration and cleanup batches are
staged only when no other batch is pending, from the commit receipt and from
the maintenance tick, so traffic is never blocked by them.

A link loss abandons a `Staging` generation: its committed rows are deleted in
bounded batches, then its marker. `Ready` and `Active` generations survive
link loss and restart.

## Restart

The E2EE state scan reads the marker before the pending rows and those before
the active rows. A `Staging` marker is abandoned outright. A `Ready` marker
rebuilds the pending projection from its rows and must find every entry. An
`Active` marker owns every conversation beyond its cursor through its pending
rows (they are the live routes and remain to migrate); an active row beyond
the cursor without a pending row is a stale row of the previous generation,
ignored and queued for deletion. Pending rows of a generation no marker names
are strays and are deleted first. The cursor row is written only at ACTIVE,
so a restart never infers activation from it.

## Limitations

- The per-page and cumulative byte ceilings are structural guards, not
  branch outcomes: a route state object is far below a page's share.
- The unit fixtures commit one batch through sealed storage per test; the
  later phases (ACTIVE, mid-migration, staging abandoned at restart) are
  restored from rows written exactly as the receiver writes them.
- Native ext4 physical-growth qualification remains REL-08 after STO-03.

## Evidence

- `crates/agenc-ircd-storage/tests/e2ee_records.rs`: the pending route and
  marker rows round-trip under their keys and kinds, the marker rules refuse
  an over-staged, incomplete READY, or cursor-bearing READY row, and a
  forged phase does not decode.
- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/snapshot.rs`: a two-page
  snapshot stages one bounded batch per page with the exact marker
  progress, keeps the prior projection live through READY, swaps at ACTIVE
  with the new cursor, and migrates with the stale row deleted and the marker
  last; an over-ceiling declaration, wrong partition, out-of-order entry,
  wrong object ID, too many entries, an incomplete page, a wrong digest and a
  changed cut are refused retaining nothing; the token expires on the
  fixture clock; a lost link abandons the staged rows through bounded
  deletes; memory admission refuses an entry before it is retained; a cut
  behind the witnessed head is a witness violation; a READY generation
  survives a sealed restart, announces READY on reconnect and accepts only
  the exact cut; an ACTIVE generation restarts live with its migration
  resumed and its stale row deleted; a restart in mid-migration restores the
  exact route set; a staging marker is abandoned at restart and its rows and
  a stray generation deleted.
- `crates/agenc-ircd-runtime/src/e2ee/edge/tests/projection.rs` and
  `projection/rollback.rs`: an empty snapshot removes the prior routes only
  at ACTIVE, refused storage keeps the previous delivery generation, and a
  READY committed after link loss keeps the generation pending and is
  announced by the next link.
- `crates/agenc-ircd-runtime/src/federation/edge/tests`: the real state core
  drives the empty-snapshot READY and ACTIVE sequence through the receiver.

Six release critical regions cover the page partition, the receiver, the
migration and cleanup steps, the restore rules, the route projection writes,
and the marker row; each measures branches.
