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

The coordinator's directory query shape (`federation/coordinator/query/shape.rs`)
bounds NAMES the same way, and its `MIN_FULL_NAMES_ROWS` now derives from the
same constant. The coordinator renders federated NAMES without user masks
(`federated_query_frames(.., false, ..)`), so its old figure was never exceeded,
but it is again an honest bound on the renderer it describes.

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
| `state_core::local_join::tests::a_local_join_of_the_longest_framed_tokens_fits_its_frame_bound` | 219 members with 32-byte nicknames: the snapshot's bound is four frames, it opens, and its chunks hold 109, 109 and 1 framed tokens of at most 73 bytes. |
| `federation::coordinator::query::shape::tests::the_names_frame_bound_covers_the_longest_framed_tokens` | The same channel against the coordinator's NAMES bound. |
| `stage_six_daemon` `cloak_spelling::every_user_mask_in_a_two_guest_transcript_uses_the_framed_cloak` | A real daemon and two guests: JOIN, an echoed message, NAMES with `userhost-in-names`, WHO, WHOIS, USERHOST, a rename with WHOWAS, and MONITOR. The transcript names exactly 18 masks and field pairs, a count the test pins; every one is framed, each user is spelled identically on every line, and no bare component appears. |
| `stage_seven_federation` `clients_on_two_edges_share_channels_through_the_coordinator` | Three daemons: edge A renders bob, homed on edge B, with a framed source, and the WHOIS reply the coordinator renders for edge A frames bob's fields. |
| `stage_six_daemon` `wss::equivalence` | The S09-002 transcript normalizer validates every cloak it learns as framed, and refuses the bare spelling (`cloak_normalization_accepts_only_the_framed_spelling`). |

Each check parses the framing itself or builds the expected text from the
stored components; none takes its expectation from the formatter.

## Each part, reverted

The revert proof restored one part of the change at a time in the worktree,
with lints capped to warnings so that a binding a partial revert leaves unused
does not stop the build, ran the sixteen tests above, and restored the file.
The script (`mutate-b12.py`) and its logs are kept with the SDK program's
records.

| Part reverted | Tests that then fail |
| --- | --- |
| None (control) | none: all sixteen pass |
| The formatter's framing, which returns every renderer and both bounds to the 70c832c output | 16: four `visible_cloak` tests, all nine runtime tests above, the two-guest transcript, the three-daemon federation test and the WSS equivalence test |
| `session_prefix` | the `mutation_render` test, the two-guest transcript, WSS equivalence |
| `names_token` | the `mutation_render` test |
| `names_entry` | the `query_render` test, the local JOIN page test, the coordinator bound test, the two-guest transcript |
| 314 fields | the `whowas` test, the bridged-link test, the two-guest transcript |
| 352 fields | the `query_render` test, the bridged-link test, the two-guest transcript |
| 311 fields | the `query_render` test, the bridged-link test, the two-guest transcript, the three-daemon federation test, WSS equivalence |
| 302 entries | the `userhost` test, the bridged-link test, the two-guest transcript |
| The edge's `prefix` | the edge render test, the bridged-link test, the three-daemon federation test |
| The history replay sender | the edge history test |
| The local JOIN token bound, 73 back to 61 | the local JOIN page test (`LimitExceeded`) |
| The coordinator's NAMES bound | the coordinator bound test |

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
- The welcome `900` of SC-007 (SDK program B-02) is not on this branch. It
  takes its mask from `session_prefix` and from the edge's `prefix`, so it is
  framed wherever both changes are merged, and any test of it that spells the
  mask bare has to take the framed spelling then.
- The conventional-client qualification
  (`stage_ten::conventional_clients_exchange_public_messages_and_cannot_enter_secret_channels`)
  was not rerun; it needs the pinned container and asserts no mask.
- The SDK's opt-in for the bare spelling (its wire mismatch WD-1) can be
  retired once the SDK pins a commit that carries this change.

## Validation

On this branch, with `CARGO_TARGET_DIR` on `/mnt/data` and a short private
`TMPDIR`:

- `cargo fmt --all --check`: ok.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  ok.
- `cargo nextest run --workspace --all-features --locked`: 4,526 passed, 24
  skipped. The 70c832c base under the same procedure: 4,514 passed, 24
  skipped.
- The SDK program's fast static gate, 59 commands: `check-spec.sh`,
  `check-baseline.py`, `requirements.py` with every stage and its self-test,
  `check-workspace.py`, `check-source.py`, `check-evidence.py`, `check-ci.py`
  and their self-tests, rustfmt, `cargo tree`, `cargo deny`, `cargo audit`,
  both coverage policies' self-test and audit, every `generate-*` `--check`,
  the Stage 01 to 09 checkers, `qualify-stage-six.sh` and
  `test-release-qualification.py`: all pass.
- `check-coverage.py audit` on the release policy: all 1,145 reviewed spans
  hold their items. The drifted regions moved with their span text unchanged;
  `runtime-userhost-disclosure` was re-reviewed and respanned, since
  `render_userhost` now takes its fields from the formatter.
- The revert campaign above: the control passes and every revert fails at
  least one test.
- Not run: the Stage 09 implementation gate (`check-stage-nine.sh`), a branch
  measurement of the touched release regions, the storage disk profile (no
  storage change) and the conventional-client qualification.
