# Every user mask spells the public cloak as Section 7.4 frames it

This record covers AUD-18, item B-12 of the SDK program (2026-10-01, outside
master #35). Architecture Section 7.4 specifies the visible source form

```text
<nickname>!u-<10 base32 chars>@h-<16 base32 chars>.invalid
```

and every transcript of Appendix E uses it. The daemon rendered the bare
`PublicCloak` components instead, `<nickname>!<10 base32>@<16 base32>`, in
every source prefix, and the separate user and host fields of `WHO`, `WHOIS`,
`WHOWAS` and `USERHOST` carried the bare components too. A client decoder that
enforces Section 7.4 therefore refused every user prefix the daemon sent. The
SDK's wire codec found it against a daemon built from b477e1b: all 42
user-prefixed lines of its captured transcript used the bare spelling.

The change is rendering only. `PublicCloak`, the storage records that hold it
(`domain_records`, `history_records`) and the federation objects that carry it
(`SourceView`, `SessionRecord`) keep the bare components, exactly as Section
7.4 generates them. No wire registry, profile hash, persistent format,
storage generation or federation object changes, and the specification is not
edited: it already says what the daemon now does.

## One formatter

`agenc-relay-client-wire` owns the client-visible wire forms, so the
formatter lives there, in `render.rs`, beside the other renderers:

- `VisibleCloak::new(&PublicCloak)` frames both components: `user()` is
  `u-<10 base32>` and `host()` is `h-<16 base32>.invalid`.
- `VisibleCloak::mask(nickname)` and `user_mask(nickname, &PublicCloak)` render
  `<nickname>!<user field>@<host field>`. The nickname must match the Section
  7.2 grammar (the crate's own `validate_nickname`), so the mask is refused
  rather than rendered for anything else.
- `VISIBLE_CLOAK_USER_BYTES` (12), `VISIBLE_CLOAK_HOST_BYTES` (26) and
  `MAX_USER_MASK_BYTES` (72) state the sizes. Because the mask refuses a
  nickname longer than 32 bytes, 72 is a bound on what the formatter can
  produce, not an assumption about its callers.

Every renderer of a user now takes its text from that one place:

| Renderer | What it renders |
| --- | --- |
| `mutation_render::session_prefix` | The source of every line a local user originates: `JOIN`, `PART`, `QUIT`, `NICK`, `PRIVMSG`, `NOTICE`, `TAGMSG`, `TOPIC`, `MODE`, `KICK`, `INVITE`, `AWAY`, `SETNAME` and `ACCOUNT`. SC-007's welcome `900` (SDK program B-02) renders its mask from the same function. |
| `mutation_render::names_token` | The `userhost-in-names` token of a JOIN's own NAMES reply. |
| `query_render::names_entry` | The `userhost-in-names` tokens of NAMES and of the local JOIN snapshot. |
| `query_render::render_who_session`, `render_whois`, `render_whowas_row` | The user and host fields of 352, 311 and 314. |
| `query_render::render_userhost` | The `nick=+user@host` entries of 302. |
| `federation::edge::render::prefix` | The source of every event an edge renders from a projection, remote users included, and of the encrypted edge's event lines. |
| `history_render` | The original sender of a history replay, on the coordinator and on edges. |

The domain's cloak-mask matcher already compared a `$c:` glob against the
framed host `h-<16>.invalid` (`decision.rs`, `mask_strength`). The host field a
client reads in `WHO` or `WHOIS` is now the text such a mask matches; before,
a host copied from those replies into a `$c:` mask did not match the user it
came from. The domain crate depends on `agenc-relay-types` alone, so the
matcher keeps its own spelling of the host field, and a runtime test that
bans the host a `WHO` row shows holds the two together.

## The page arithmetic

A NAMES chunk holds at most 8,000 bytes and is flushed only when the next
token and its separator would overflow it, so every chunk but the last holds
at least `8000 / (T + 1)` tokens of at most `T` bytes. The local JOIN snapshot
uses that count to bound its frames before admission
(`rows / MIN_FULL_CHUNK_ROWS + 2` per channel) and refuses to open with
`LimitExceeded` when the rendered reply has more.

`T` was `1 + 32 + 2 + 10 + 16 = 61`, a role byte and the bare mask. A framed
token is a role byte and up to 72 mask bytes, so `MAX_NAMES_TOKEN_BYTES` is now
`1 + MAX_USER_MASK_BYTES = 73` and `MIN_FULL_CHUNK_ROWS` falls from 129 to 108.
Without that change, a channel of 219 members with 32-byte nicknames, joined
with `userhost-in-names`, renders three 353 chunks (109, 109 and 1 tokens) and
the 366 against a bound of three frames, and its JOIN's NAMES fails. The
8,000-byte chunk, the 512-user and 512-reply page limits and the 64 KiB page
are unchanged; a large channel's snapshot reserves one frame of backing per
108 members instead of per 129.

The bound is tight only when every token carries a role byte. A channel whose
founder and 215 voiced members have 32-byte nicknames renders, with the
requester, 217 tokens as chunks of exactly 108, 108 and 1 and the 366: four
frames, which `217 / 108 + 2` admits. Counting 109 tokens to a full chunk, by
dropping either the role byte or the separator from the divisor, bounds the
same snapshot at three frames and refuses the JOIN's NAMES. In the 219-member
channel only the founder holds a role, so its full chunks hold 109 tokens and
it cannot tell 108 from 109; the role-prefixed channel can, and both the local
JOIN bound and the coordinator's bound are tested against it.

The coordinator's directory query shape (`federation/coordinator/query/shape.rs`)
bounds NAMES the same way, and its `MIN_FULL_NAMES_ROWS` now derives from the
same constant. The coordinator renders federated NAMES without user masks
(`federated_query_frames(.., false, ..)`), so its old figure was never exceeded,
but it is again an honest bound on the renderer it describes.

One more NAMES path had a bound, and the framed tokens moved it. A node that
answers its own clients sent an explicit `NAMES` as one logical reply, which
the fanout refuses above `response_batch_bytes` (65,536 bytes by default),
closing the connection. With `userhost-in-names` the framed tokens make that
reply about a fifth larger, so the largest NAMES still answered fell by as
much (review finding B12-R0-1). Such a reply is now delivered in pages
instead, as a JOIN's NAMES is; the change and its measurements are recorded
in [the explicit NAMES pages record](stage-10-explicit-names-pages.md).

## Compatibility

- Clients: every user mask is 12 bytes longer, and so is every user and host
  field pair of 311, 314, 352 and 302: `u-` goes before the user component,
  and `h-` before and `.invalid` after the host component. Conventional
  clients treat the user and host as opaque text, and the conventional-client
  qualification asserts no mask. A decoder that enforces Section 7.4 now
  accepts every user prefix the daemon sends.
- Federation, storage and registries: unchanged. `PublicCloak`,
  `SourceView`, `SessionRecord` and the stored session and history records
  keep the bare components, and each node frames them when it renders. While
  one network runs nodes built before and after this change, each client
  reads the spelling of the node it is connected to, so one user can read
  bare on one edge and framed on another; no node refuses the other's
  objects. Storage generation 5 is unchanged and nothing persisted is
  rewritten, so no restore test applies.
- Cloak masks: a `$c:` mask was already matched against the framed host
  before this change, so a ban written in the framed form behaves the same
  across such a mixed network.
- Privacy: none. The frame is fixed text around the same two random
  components.
- Limits: the two NAMES frame bounds above change, and an explicit NAMES
  reply larger than one response batch, which the framed tokens made about a
  fifth more common with `userhost-in-names`, is now paged rather than closing
  the connection ([the explicit NAMES pages record](stage-10-explicit-names-pages.md)).
  `WHO #channel` keeps its single logical reply, which closes the connection
  above 512 visible members or one response batch, as it did before; each
  352 is 12 bytes longer, so with long display names the byte bound binds a
  few percent earlier. That is listed for the owner. A server line holds 8,701
  command bytes and the longest mask is 72, and a history page is already
  sized for seven maximum-sized lines.

## Regressions

| Test | What it pins |
| --- | --- |
| `client-wire` `visible_cloak` (five tests) | The exact fields and mask for a known cloak, the 311 parameters, a 32-byte nickname filling exactly `MAX_USER_MASK_BYTES`, and a nickname outside Section 7.2 refused. |
| `mutation_render::tests::user_sources_and_names_tokens_render_the_framed_public_cloak` | Through `render_mutation` and the fanout: the requester's JOIN echo, its 353 token for a 32-byte nickname (73 bytes), the member's view of both JOINs and its 353, and the delivered `PRIVMSG` source. |
| `query_render::tests::names_who_and_whois_render_the_framed_public_cloak` | NAMES `userhost-in-names` tokens, every 352 row and the 311 fields, and no bare component anywhere in the encoded replies. |
| `query_render::tests::a_cloak_ban_on_the_who_host_field_matches_the_user_it_names` | A `$c:` ban on the host field of a user's own `WHO` row refuses that user's JOIN with `Forbidden`, and a ban on the bare host component, the text `WHO` showed before, admits it. |
| `query_render::tests::userhost_uses_public_cloaks_away_flags_and_presence_privacy` | The 302 entries, now framed. |
| `state_core::whowas::tests::whowas_count_and_rows_contain_only_retired_public_facts` | The 314 fields, now framed. |
| `federation::edge::render::tests::a_projected_source_renders_the_framed_public_cloak` | The edge's `prefix` and `actor_prefix` for a projected source. |
| `federation::edge::history::tests::rendering_callback_rechecks_link_state_and_preserves_original_tags` | A history page replayed on an edge names the original sender with the framed mask. |
| `federation::edge::tests::edge_and_coordinator_interoperate_over_a_bridged_link` | Over a live in-process link: JOIN, channel and private message sources rendered by the edge, and every cloak in the WHO, WHOIS, USERHOST and WHOWAS replies the coordinator renders. |
| `state_core::local_join::tests::a_local_join_of_the_longest_framed_tokens_fits_its_frame_bound` | 219 members with 32-byte nicknames, only the founder holding a role: the snapshot's bound is four frames, it opens, and its chunks hold 109, 109 and 1 framed tokens of at most 73 bytes. |
| `state_core::local_join::tests::a_local_join_of_role_prefixed_framed_tokens_fits_its_frame_bound` | The worst case: the founder, 215 voiced members and the requester, every member token 73 bytes. The bound is `(217, 4)`, the snapshot opens, and its chunks hold exactly 108, 108 and 1 tokens; it also pins `MIN_FULL_CHUNK_ROWS` at 108. |
| `federation::coordinator::query::shape::tests::the_names_frame_bound_covers_the_longest_framed_tokens` | The 219-member channel against the coordinator's NAMES bound. |
| `federation::coordinator::query::shape::tests::the_names_frame_bound_covers_role_prefixed_framed_tokens` | The role-prefixed channel against the coordinator's NAMES bound: four frames rendered with `userhost-in-names`, a bound of four, and `MIN_FULL_NAMES_ROWS` pinned at 108. |
| `stage_six_daemon` `cloak_spelling::every_user_mask_in_a_two_guest_transcript_uses_the_framed_cloak` | A real daemon and two guests: JOIN, an echoed message, NAMES with `userhost-in-names`, WHO, WHOIS, USERHOST, a rename with WHOWAS, and MONITOR. The transcript names exactly 18 masks and field pairs, a count the test pins; every one is framed, each user is spelled identically on every line, and no bare component appears. |
| `stage_seven_federation` `clients_on_two_edges_share_channels_through_the_coordinator` | Three daemons: edge A renders bob, homed on edge B, with a framed source, and the WHOIS reply the coordinator renders for edge A frames bob's fields. |
| `stage_six_daemon` `wss::equivalence` | The S09-002 transcript normalizer validates every cloak it learns as framed, and refuses the bare spelling (`cloak_normalization_accepts_only_the_framed_spelling`). |

Each check parses the framing itself or builds the expected text from the
stored components; none takes its expectation from the formatter.

## Each part, reverted

The revert proof restores one part of the change at a time in the worktree,
with lints capped to warnings so that a binding a partial revert leaves unused
does not stop the build, runs the seventeen tests above, and restores the
file. It first ran at 29e61c8 with the sixteen tests of that commit; the
table is its second run, at 026611d, which adds the `$c:` ban test, and its
last row a third, which also reverts the formatter's own nickname check. The
scripts (`mutate-b12.py`, `mutate-b12-v2.py` and `mutate-b12-v3.py`) and their
logs are kept with the SDK program's records.

| Part reverted | Tests that then fail |
| --- | --- |
| None (control) | none: all seventeen pass |
| The formatter's framing, which returns every renderer and both bounds to the 70c832c output | all 17: four `visible_cloak` tests, all ten runtime tests above, the two-guest transcript, the three-daemon federation test and the WSS equivalence test |
| `session_prefix` | the `mutation_render` test, the two-guest transcript, WSS equivalence |
| `names_token` | the `mutation_render` test |
| `names_entry` | the `query_render` test, the local JOIN page test, the coordinator bound test, the two-guest transcript |
| 314 fields | the `whowas` test, the bridged-link test, the two-guest transcript |
| 352 fields | the `query_render` test, the `$c:` ban test ("a ban on $c:bbbbbbbbbbbbbbf5 decided #render-cloak-who wrongly"), the bridged-link test, the two-guest transcript |
| 311 fields | the `query_render` test, the bridged-link test, the two-guest transcript, the three-daemon federation test, WSS equivalence |
| 302 entries | the `userhost` test, the bridged-link test, the two-guest transcript |
| The edge's `prefix` | the edge render test, the bridged-link test, the three-daemon federation test |
| The history replay sender | the edge history test |
| The local JOIN token bound, 73 back to 61 | the local JOIN page test (`LimitExceeded`) |
| The coordinator's NAMES bound | the coordinator bound test |
| The local JOIN full-chunk count without the separator, 109 (review finding B12-R1-01: it passed all eighteen tests of the earlier runs) | the role-prefixed local JOIN test (`open refused with bounds (217, 3): LimitExceeded`) |
| The coordinator's full-chunk count without the role byte, 109 (B12-R1-01, likewise) | the role-prefixed coordinator test (`4 frames exceed the bound 3`) |
| The formatter's nickname check (`mutate-b12-v3.py`, which adds the refusal test to the set; its control passes all eighteen) | the `visible_cloak` refusal test |

The two rows marked B12-R1-01 come from a later run over the four NAMES bound
tests, each count changed in turn; its control passes all four, and each
change fails the role-prefixed test of its bound with the message shown.

`names_token` is reached only when a JOIN's own NAMES is rendered with the
fanout rather than as a local JOIN snapshot, which no production JOIN with a
reply does today, so only the unit test sees it.

## Limitations

- Federated NAMES replies still carry no `userhost-in-names` tokens: the
  coordinator renders every directory query with the capability off, whatever
  the edge client negotiated. That predates this change and is unchanged.
- `730` names nicknames only, as it did; no mask is rendered there.
- Section 14.5 has `WHOWAS` keep the "ephemeral user/host mask", and Appendix
  A.2 has 314 carry the "ephemeral public user and host components". This
  change renders those components in the same visible fields `WHOIS` and
  `WHO` use, so one session reads the same in all three.
- The welcome `900` of SC-007 and the later `900` and `ACCOUNT` of a
  post-registration login (SDK program B-02 and B-03) are not on this branch.
  They take their masks from `session_prefix` and from the edge's `prefix`,
  so they are framed wherever both changes are merged, and any test of them
  that spells the mask bare has to take the framed spelling then.
- The conventional-client qualification
  (`stage_ten::conventional_clients_exchange_public_messages_and_cannot_enter_secret_channels`)
  was not rerun; it needs the pinned container and asserts no mask.
- The SDK's opt-in for the bare spelling (its wire mismatch WD-1) can be
  retired once the SDK pins a commit that carries this change.

## Release regions measured

The gate's coverage command
(`RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest --workspace --all-features --branch --locked`)
ran at 026611d and on an export of 70c832c under the same procedure, and each
region below was scored with `check-coverage.py`'s own counting on the span
its policy reviews at that commit. These are the release regions in every
production file this branch changes; covered over total, in the region's
metric.

| Region | Metric | 70c832c | 026611d |
| --- | --- | --- | --- |
| `client-registration-grammar-error-arms` | regions | 13/13 | 13/13 |
| `client-render-error-arms` | regions | 18/18 | 18/18 |
| `runtime-whowas-current-cloak-authority` | branches | 4/4 | 4/4 |
| `runtime-local-join-snapshot-identity` | branches | 4/6 | 4/6 |
| `runtime-userhost-disclosure` | branches | 6/6 | 6/6 |
| `runtime-monitor-status-disclosure` | branches | 2/2 | 2/2 |
| `cap81-shape-bounds` | regions | 47/56 | 47/56 |
| `cap81-shape-names` | regions | 45/72 | 45/72 |
| `cap81-shape-user-query` | regions | 43/48 | 43/48 |
| `cap81-shape-whois` | regions | 35/40 | 35/40 |
| `cap81-shape-mode` | regions | 33/39 | 33/39 |
| `cap81-shape-presence` | regions | 37/45 | 37/45 |
| `cap81-shape-information` | regions | 0/31 | 0/31 |
| `cap13-render-render-event-strict` | regions | 43/46 | 43/46 |

Each region reads the same in its metric at both commits. The respanned
`runtime-userhost-disclosure` keeps all six branches covered; its regions went
from 36 of 38 to 36 of 37, because the two `?` exits of the component
conversions, which no input reaches, became the one exit of the formatter
call. The regions below 100 percent are below it at 70c832c as well; the
release policy is read by the Stage 10 runner, not by the Stage 09 gate. The
interim policy, which the gate checks, passes at both commits: branches 84.53
percent, lines 93.94 percent, all 21 critical regions at 100 percent.

## Validation

On this branch at 026611d, with `CARGO_TARGET_DIR` on `/mnt/data` and a short
private `TMPDIR`; the commit that follows it changes only this record:

- `cargo fmt --all --check`: ok.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  ok.
- `cargo nextest run --workspace --all-features --locked`: 4,527 passed, 24
  skipped. The 70c832c base under the same procedure: 4,514 passed, 24
  skipped.
- The SDK program's fast static gate (`fast-gates.sh`, 59 commands):
  `check-spec.sh`, `check-baseline.py`, `requirements.py` with every stage
  and its self-test, `check-workspace.py`, `check-source.py`,
  `check-evidence.py`, `check-ci.py` and their self-tests, rustfmt,
  `cargo tree`, `cargo deny`, `cargo audit`, both coverage policies'
  self-test and audit, every `generate-*` `--check`, the Stage 01 to 09
  checkers, `qualify-stage-six.sh` and `test-release-qualification.py`: all
  pass.
- `check-coverage.py audit` on the release policy: all 1,145 reviewed spans
  hold their items. The drifted regions moved with their span text unchanged;
  `runtime-userhost-disclosure` was re-reviewed and respanned, since
  `render_userhost` now takes its fields from the formatter.
- The document lint of `check-release-claims.py` on its policy documents and
  this record: no completion phrase. The whole script runs only under
  `qualify-release.py`, with a candidate binary.
- The revert campaign above: the control passes and every revert fails at
  least one test.
- The coverage measurement above: under `cargo llvm-cov`, 4,527 tests
  passed (70c832c: 4,514), and the gate's interim policy check passes at
  both commits.
- Not run: the Stage 09 implementation gate (`check-stage-nine.sh`), the
  storage disk profile (no storage change) and the conventional-client
  qualification.
