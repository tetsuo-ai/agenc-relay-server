# Explicit NAMES replies larger than one response batch arrive in pages

This record covers review finding B12-R0-1 of AUD-18, SDK program item B-12
(2026-10-02, outside master #35). It changes no wire format, numeric, reply
code, registry, configured limit, persistent format or specification text. A
NAMES reply that fits one response batch is sent exactly as before.

## What was observed

On a node that answers its own clients, a core-only node or a federated
coordinator, an explicit `NAMES` was rendered as one logical reply and sent
through the fanout, which refuses any reply larger than
`response_batch_bytes` (Appendix C: 65,536 bytes by default, 262,144 at
most). The refusal failed the command, and the router closed the client's
connection with a protocol error instead of answering. A JOIN's own NAMES
reply and the NAMES an edge relays from its coordinator were already paged;
this one was not, although Section 14.3 has NAMES "visibility-filtered and
paged", at most 512 users to a page.

The defect predates B-12: at the default `members_per_channel` of 4,096, the
NAMES of a full channel exceeds one response batch with long nicknames even
without `userhost-in-names`, and a bare `NAMES` lists every joined channel in
one reply. The framed cloak of B-12 lengthens every `userhost-in-names` token
by 12 bytes, which lowered the largest NAMES the node still answered by about
a fifth. The review measured, with `userhost-in-names` (bare cloak against
framed cloak): 1,400 members with 8-byte nicknames render 52,349 against
69,259 bytes, and 900 and 1,000 members with 32-byte nicknames 55,425 and
61,580 against 66,335 and 73,690 bytes. The framed sizes exceed 65,536 bytes;
before this change each closed the connection.

No test showed it because the state-core fixture runs at the hard maximum
response batch of 262,144 bytes, not the 65,536 a configured node uses by
default.

## The change

`query_render::render_names_reply` now answers an explicit NAMES:

- It renders the reply and wraps it for the request's label as before. If the
  logical reply fits one response batch and 512 semantic replies, it is sent
  whole, unchanged: the same frames, and for a labeled request the same batch
  named by the label.
- Otherwise it admits a query snapshot for the reply's rows and backing
  (`prepare_query_snapshot`: the per-session snapshot slot, the row ceiling
  and the global row and byte totals), renders the reply again from the same
  revision, which no command in the routing step has changed, and retains it
  with `StateCoreContext::retain_local_names` as a committed local NAMES seed
  beside the JOIN seeds. The second rendering must match the first in frames
  and rows, or the command fails as before.
- The router opens the seed after the routing step, exactly as it opens a
  local JOIN's NAMES seed, and delivers it through the same continuation
  (`JoinNamesContinuation`), the output state machine Section 14.2 gives a
  coordinator-local client: pages of at most 512 users, 512 replies and
  65,536 bytes; the next page only once the client's queue is below half;
  one `labeled-response` batch from the first page to the last for a labeled
  request; every 366 on the last page; the connection's later registered
  commands held behind the reply, while `PING` is still answered; and the
  idle and absolute deadlines and failure handling of a JOIN continuation,
  which close the connection.
- A seed carries the channels an explicit NAMES ends (`explicit`), read from
  its closing 366 replies, so the continuation checks the last page against
  them; a JOIN's seed still takes its channels from its topic replies.
- Pages are cut with the batch tag counted: `measure_names` counts each frame
  with the tag it gains on a labeled page, `@batch=fq<n> ` for the
  continuation's 64-bit batch counter, at most 30 bytes, and `page_count`'s
  512-byte page allowance covers the closing BATCH line, so a tagged page fits
  the smallest response batch. A local JOIN's pages are cut by the same
  function; with at most 20 channels and 512 users to a page they stay far
  below the bound, so they are unchanged in practice.
- The response floor's timer, which resumes the commands a floored refusal
  held, now opens any snapshot those commands leave
  (`resume_deferred_commands`), as every other point that runs commands
  outside a routed line already did. sdk/b-local-join adds the same line for
  AUD-16's local JOINs; the two changes are byte-identical, so they merge
  without a conflict.

An edge sends every NAMES to its coordinator as a directory query, which the
coordinator already pages; an edge renders no NAMES reply itself, so the edge
path is unchanged.

## Resources

The retained reply is charged as a query snapshot, by the same
`backing_bytes` bound a local JOIN's NAMES snapshot uses: the retained frames,
the membership projection that renders them, and a fixed allowance that
covers the request and the channel list (at most `channels_per_session`, 256,
names). It is admitted before the reply it retains is rendered, and released
when the last page is queued or the connection closes. Only a reply too large
for one response batch, which was refused before, reaches this admission, and
a refusal there closes the connection as before. The first rendering, which
decides whether the reply fits, is transient and uncharged, as the single
rendering before this change was.

## The regressions

Every router test runs at the Appendix C default response batch, read from
the configuration's default table, rather than the fixture's hard maximum.

| Test | What it pins |
| --- | --- |
| `registration::explicit_names_tests::an_explicit_names_beyond_one_response_batch_arrives_in_pages` | Through the state core with its clock frozen: a guest with `userhost-in-names` in a channel of 1,400 members with 8-byte nicknames sends `NAMES #paged` and then `TIME`. The connection stays open; the reply, more than 65,536 bytes, lists every member once, framed, no line more than 512 of them, then one 366, then the `391`. |
| `registration::explicit_names_tests::a_labeled_names_in_pages_keeps_one_batch_and_a_small_one_is_sent_whole` | `@label=whole NAMES #small` is one batch named `whole` with the 353 and the 366, as before; `@label=paged NAMES #paged` opens one `fq` batch with the label, tags every 353 and the 366 with it, closes it, and only then answers `TIME`. |
| `registration::explicit_names_tests::a_bare_names_across_joined_channels_arrives_in_pages` | A bare `NAMES` from a member of twenty channels of 72 members: every channel's tokens, then the twenty 366 replies, then the `391`. |
| `registration::explicit_names_tests::a_paged_names_released_by_a_response_floor_opens_in_that_step` | `TOPIC #missing`, then `NAMES #paged` and `TIME`; firing the floor's timer publishes the `403` and the NAMES's first page in that one step, and no seed is left pending. |
| `state_core::local_join::tests::a_names_page_fits_one_response_batch_once_its_frames_are_tagged` | Nine 353 lines and a 366 that fit 65,536 bytes untagged are cut into pages of 8 and 2 frames, each of which fits 65,536 bytes once tagged with the longest generated batch ID and closed. |

The local JOIN tests, the live-router JOIN continuation tests and every other
runtime test pass unchanged.

## Each part, reverted

Each part was restored alone in a scratch copy of the branch, with lints
capped to warnings, and the 81 runtime tests whose names contain
`explicit_names_tests`, `once_its_frames_are_tagged`, `local_join` or `names`
were run; the control passes all of them.

| Part reverted | Tests that then fail |
| --- | --- |
| None (control) | none: all 81 pass |
| `render_names_reply` restored to one logical reply whatever its size, as at `70c832c` | the four router tests: the connection closes at the NAMES ("a NAMES beyond one response batch keeps its connection"), and nothing answers the `TIME` behind it |
| The response floor's timer resumes the commands without opening their snapshot | the response-floor test: the floor's step publishes the `403` and nothing after it |
| Pages cut without the batch tag (`encoded: 0`, as before) | the page-size test: "a page of 10 frames is 65872 bytes" |
| The continuation takes a NAMES's channels from topic replies, as a JOIN's | the four router tests: the continuation refuses to open and the connection closes |
| Every explicit NAMES paged, also one that fits one response batch | the labeled test: the small NAMES is no longer one batch named by its label |

## Limitations

- `WHO #channel` keeps its single logical reply: a WHO of a channel with more
  than 512 visible members, or whose 352 replies exceed one response batch,
  still closes the connection on a node that answers its own clients. With a
  short display name the 512-reply bound binds first; B-12 lengthens each 352
  by 12 bytes, so with long display names the byte bound now binds a few
  percent earlier. This is listed for the owner and not changed here.
- The 366 replies of one NAMES stay together on its last page. A bare `NAMES`
  whose 366 replies alone exceed one page, possible only near the hard
  maximum of 256 joined channels with long channel and server names, cannot
  be paged and still fails closed, as every NAMES larger than one response
  batch did before.
- The continuation is local to the node that answers the client; an edge's
  explicit NAMES is paged by its coordinator as before.
- The conventional-client qualification was not rerun; it sends no NAMES
  larger than one response batch.

## Validation

On this branch, with `CARGO_TARGET_DIR` on `/mnt/data` and a short private
`TMPDIR`:

- `cargo fmt --all --check`: ok.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  ok.
- `cargo nextest run -p agenc-relay-runtime --all-features --locked`: 2,731
  passed, 2 skipped, the five new tests among them.
- The revert campaign above: the control passes all 81 tests and each revert
  fails at least one.
- The SDK program's fast static gate (`fast-gates.sh`, 59 commands): all pass.
- `check-coverage.py` self-test on both policies and audit on both: ok (21 and
  1,145 reviewed spans). Both production source inventories are refreshed.
  The release region `runtime-local-join-snapshot-identity` (`open`) was
  re-reviewed and respanned, since `open` now takes an explicit NAMES's
  rendered frames; its identity check still precedes both paths, and its
  reason names both snapshots. The regions in `query_render.rs`,
  `runtime_config.rs`, `registration.rs` and `state_core/mod.rs` moved with
  their span text unchanged.
- The document lint of `check-release-claims.py` on its policy documents and
  this record: no completion phrase.
- Not run here: the workspace suite and the branch measurement of the
  respanned region, which the framed cloak record's validation reports at
  the topic tip; the Stage 09 implementation gate.
