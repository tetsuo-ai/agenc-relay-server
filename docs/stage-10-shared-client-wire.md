# The shared client wire surface

This record covers the SDK program's server items X-12, X-07, X-05 and X-06
(2026-10-04, outside master #35), which make the client wire crate's limits,
registries and grammar usable by a client: the copies of limits and of the
object-kind registry that other crates own, the Appendix A.1 argument
bounds, and, in later sections, the server-to-client base decoder and the
inverse of the E2EE response renderers. No specification, profile hash, wire
format, registry, configured limit, storage generation or daemon behaviour
changes. No Stage 10 task is closed by this record.

## X-12: the object-kind list, and the copied limits held equal

### Finding

`E2EE_OBJECT_KINDS` in `crates/agenc-relay-client-wire/src/text.rs`, the
list behind `E2eeObjectKind::parse`, held 33 of companion Section 11.7's 37
`object-kind` tokens: `POLICY`, `RECOVERY-SUBMISSION`, `WITNESS-RESOLUTION`
and `LEAF-MEMBERSHIP-PROOF`, ordinals 34 to 37 of `ArcWireObjectKind`, were
missing (audit finding AUD-05), so a client using the list refused an
`EOBJECT` of those kinds. The daemon does not use the list; it reads object
kinds with `ArcWireObjectKind`. Nothing compared the client wire crate's
copies of the tag, fragment and object limits with the crates that own
them either.

### Change

- `E2EE_OBJECT_KINDS` gains the four tokens, in ordinal order.
- `crates/agenc-relay-testkit/tests/shared_wire_limits.rs` holds every copy
  equal to its owner (the testkit already depends on both crates, so no
  workspace edge changes):
  - `object_kind_registries_agree`: the list has exactly the 37 tokens of
    `ArcWireObjectKind::ALL`, each at its ordinal position, and
    `E2eeObjectKind::parse` and `ArcWireObjectKind::from_token` accept each
    other's tokens;
  - `tag_and_line_limits_agree`: the client, server and combined tag budgets
    of the client wire crate, the E2EE `limits` module and the base profile
    registry (`CLIENT_TAG_BYTES`, `SERVER_TAG_BYTES`,
    `COMBINED_TAG_SECTION_BYTES`), and the 8,703-byte physical line;
  - `fragment_limits_agree`: `MAX_E2EE_FRAGMENT_BYTES` and
    `MAX_FRAGMENT_RAW` (2,940), and `MAX_E2EE_FRAGMENT_COUNT` with the
    mailbox fragment ceiling and `MAX_BATCH_FRAGMENTS` (1,427), which is the
    number of fragments the largest object needs;
  - `object_limits_agree`: `MAX_E2EE_OBJECT_BYTES` is the largest kind's
    maximum, the envelope plus the largest body, and `MAX_BATCH_DECODED_BYTES`
    (4,194,304).
- `text_carrier::closed_e2ee_tokens_match_the_documented_registry` checks the
  list's length and its last four tokens.

### Evidence

With `text.rs` restored to `6986ace` and the tests kept,
`object_kind_registries_agree` and
`closed_e2ee_tokens_match_the_documented_registry` fail (`left: 33, right:
37`); with the four tokens both pass, as do the three limit tests.

## X-07: the Appendix A.1 argument bounds

### Finding

The client-input grammar enforced the Appendix A.1 argument bounds from
private constants in `registration_command.rs`, so a client encoder (which
stays in the SDK, decision D-18) had to restate every one of them.

### Change

- `crates/agenc-relay-client-wire/src/limits.rs` defines them publicly, with
  their Appendix A.1 meaning: `MAX_COMPATIBILITY_PASS_BYTES` (256),
  `CONFIGURED_PASS_CHARACTERS` (43), `MAX_QUIT_REASON_BYTES` (256),
  `MAX_PING_PONG_BYTES` (64), `MAX_REALNAME_BYTES` (64),
  `MAX_SASL_MECHANISM_BYTES` (20), `MAX_CHANNEL_BYTES` (64),
  `MAX_NICKNAME_BYTES` (32), `MAX_SERVER_NAME_BYTES` (253),
  `MAX_CHANNEL_TARGETS` (20), `MAX_MESSAGE_TARGETS` (4), `MAX_KICK_TARGETS`
  (4), `MAX_MODE_CHANGES` (6), `MIN_CHANNEL_KEY_BYTES` (8),
  `MAX_CHANNEL_KEY_BYTES` (256), `MAX_PART_KICK_AWAY_BYTES` (256),
  `MAX_TOPIC_BYTES` (1,024), `MAX_MESSAGE_BODY_BYTES` (512),
  `MAX_WHOWAS_COUNT` (10), `MAX_ISON_NICKNAMES` (20),
  `MAX_USERHOST_NICKNAMES` (5), `MAX_MONITOR_NICKNAMES` (20) and
  `MAX_HISTORY_LIMIT` (100).
- `registration_command.rs` and `render.rs` use them. `MONITOR +` and
  `MONITOR -` now name `MAX_MONITOR_NICKNAMES` instead of sharing
  `MAX_CHANNEL_TARGETS`; both are 20, so nothing the parser accepts changes.
  The derived `PASS` byte length and authentication chunk bound stay
  private.

### Evidence

`crates/agenc-relay-client-wire/tests/argument_bounds.rs` drives the public
parsers (`parse_registration_command` under both access-token policies, and
`validate_post_registration_command`) with each bound at its exact value and
one over: every bound above is accepted at its value and refused one over,
the shortest channel key also one under, and the `JOIN` key list with
distinct keys. `ISON`'s 20 nicknames cannot be reached: the global
15-parameter budget refuses a sixteenth parameter first, so the test pins
that 15 are accepted and the line parser refuses 16.

## X-05: the server-to-client base decoder

### Finding

The client wire crate frames and parses what a client sends; a client reading
what a server sends had no shared decoder. The client-input framer applies
the client's 4,094-byte tag budget, so it refuses a legal server line whose
tag section carries both server-added and relayed client-only tags, and the
client-input parser discards the raw tag text, accepts any case and expects
no prefix. A client therefore needed its own server-direction framer, tag
parser and message decoder, with the registries and bounds restated.

### Change

Three modules of `crates/agenc-relay-client-wire/src` decode the server
direction. The client entry points (`StreamFramer`, `FramedLine`,
`parse_client_tags`, `parse_message`) keep their meaning and code; the daemon
never runs the new modules.

- `server_framing.rs`: `WireDirection` names each direction's bounds
  (`ClientToServer`: 4,094 bytes of client tag data, empty lines skipped;
  `ServerToClient`: a tag section of 8,191 bytes with its `@` and space,
  empty lines refused; 8,701 content bytes either way). `ServerFramedLine`
  is the borrowed proof that a line passed them, and `ServerStreamFramer`
  frames a stream with the client framer's design: one buffer reserved at
  construction, CR, LF and NUL checked byte by byte, each bound enforced as
  the byte that exceeds it arrives, buffers wiped when discarded. Its first
  failure is final (`ServerFramingError`, ten closed variants).
- `server_tags.rs`: `parse_server_tags` checks one tag section and keeps it
  verbatim, each `ServerTag` borrowing its key and raw value: the section
  length, then per field the IRCv3 key grammar of Section 9.2, the closed
  escapes (`\:` `\s` `\\` `\r` `\n`; any other escape or a dangling
  backslash is refused, where the client-input parser is lenient), the
  `label` bound (one to 64 decoded bytes with no escaped delimiter, which is
  what the renderer can emit) and the `batch` reference grammar, each side's
  4,094 bytes counted apart in either order, the client-only limits (16
  tags, 256 decoded bytes per value, 1,024 in all, `+agenc.ag/e2ee` exempt
  from the two byte limits), and duplicate keys, found in linear time.
  `unescape_server_tag_value` is the strict unescape. `validate_safe_label`
  is the companion's `safe-label` grammar on raw bytes and
  `validate_batch_reference` the batch reference grammar; the renderer's own
  batch check now calls the same predicate.
- `server_message.rs`: `parse_server_message` decodes the canonical line the
  renderer writes: single spaces, an optional prefix that is a server name
  or a cloaked user mask in the framed spelling of Section 7.4 (the bare
  cloak spelling is refused), a command of the base `SERVER_COMMANDS`
  registry in upper case or a three-digit numeric of `SERVER_NUMERICS`, at
  most 15 parameters, the Section 9.5 frame and closed base registry of
  `FAIL`, `WARN` and `NOTE` with the administrative codes refused and
  `SLOW_CONSUMER` only as `WARN *`, and client-only tags only on `PRIVMSG`,
  `NOTICE` and `TAGMSG`. `FORBIDDEN_NUMERICS` (317, 325, 338, 378, 379) get
  their own error and `ADMIN_ONLY_REPLY_CODES` restates the administrative
  subset. The prefix names use the crate's own name grammars, which a test
  holds equal to the shared types' `ServerName` and `Nickname`. The decoded
  `ServerMessage` borrows the line; the only allocation in decoding is the
  duplicate tracker of a tag section, reserved once from its field count.
  The companion commands `EGROUP`, `EKEY`, `EDIRECT` and `EOBJECT` and the
  companion reply codes are outside the base registries, so this decoder
  refuses them; X-06 reads those lines in `agenc_relay_e2ee::wire`.
- The SDK's preparatory codec was the reference for the rules and tests;
  its opt-in for the audit pin's bare cloak spelling stays in the SDK.
- `crates/agenc-relay-testkit/src/client_transcript.rs`: every server frame a
  transcript asserts must also be one line `ServerStreamFramer` and
  `parse_server_message` accept (`decode_server_frame`); the registration
  transcript's twelve frames do.
- `fuzz/fuzz_targets/server_framing.rs` (seeds in
  `test-data/fuzz-corpus/server-framing/`) frames arbitrary bytes under
  three chunk schedules, requires the same lines, decodes and errors from
  each, decodes the input as one delimited line and as a bare tag section,
  and requires every value of an accepted section to unescape.
  `scripts/check-stage-two.py` lists the target and the three modules, and
  validates the new vector file's evidence IDs.

### Evidence

| Test | What it pins |
| --- | --- |
| `server_direction::each_direction_names_the_bounds_its_framer_applies` | `WireDirection`'s numbers are the ones each framer applies: the client framer refuses 4,095 bytes of tag data and skips an empty line, the server framer takes a full two-sided section and refuses an empty line. |
| `...::the_combined_tag_section_holds_8191_bytes_and_refuses_8192` | A section of 4,094 server bytes, a separator and 4,094 client bytes (8,191 with `@` and space) frames and decodes; one byte more is refused by the framer as the byte arrives, by `ServerFramedLine` and by `parse_server_tags`. |
| `...::each_tag_side_holds_4094_bytes_and_refuses_4095` | Each side at 4,094 and 4,095 bytes, and a side's separators counted when the other side's tags sit between its own. |
| `...::a_full_tag_section_leaves_510_command_bytes` | With a full section, 510 command bytes (8,701 in all) decode and 511 are `LineTooLong`; untagged, 8,701 and 8,702. |
| `...::framing_is_the_same_for_every_split_of_the_stream`, `...::stream_failures_are_typed_and_final` | Identical lines for every split point and byte by byte, multi-byte characters across splits; bare LF, bare CR, NUL, invalid UTF-8, empty line, partial line and timeout, each final. |
| `...::tag_keys_follow_the_ircv3_grammar`, `...::tag_values_stay_raw_and_unescape_strictly`, `...::duplicate_keys_are_found_in_small_and_large_sections`, `...::client_only_tags_keep_their_count_value_and_total_limits`, `...::correlation_tags_keep_their_bounds` | The key grammar with vendor host and label bounds (253 and 63 bytes), raw values and the strict unescape, duplicates in a 3-field and a 300-field section, 16 and 17 client-only tags, 256 and 257 value bytes, 1,024 and 1,025 total bytes, the E2EE exemption, the `label` and `batch` bounds and both validators. |
| `...::prefixes_are_a_server_name_or_a_framed_cloaked_user`, `...::prefix_names_follow_the_shared_name_grammars` | The framed mask and its fields and cloak, no prefix, and thirteen refused spellings (bare and mixed cloaks, a real host among them); the decoder's server-name and nickname verdicts equal `ServerName::parse` and `Nickname::parse` on 26 names. |
| `...::commands_come_from_the_closed_registries`, `...::spacing_is_single_and_parameters_are_at_most_fifteen`, `...::standard_replies_keep_their_frame_and_closed_codes`, `...::client_only_tags_ride_only_the_relaying_commands` | Every registered numeric, the five forbidden ones, case, companion and unknown commands; spacing; 15 and 16 parameters; the reply frame, code grammar, registry, administrative codes and the queue warning; client-only tag placement. |
| `server_round_trip` (7 tests) | `decode(render(x))` over every numeric the renderer builds (each registered numeric but 901 and 902, which it refuses), the three mandatory `005` groups, every row of the Section 9.5 reply table (19 replies) and the queue warning, labeled responses of zero, one and three replies, nested history and labeled batches with their parent references, server and relayed client-only tags with escapes and a 3,000-byte E2EE fragment, and the longest user mask; each line rebuilds byte for byte from its decoded parts. The companion lines `WireMessage::extension_line` renders are refused here, except the relayed `TAGMSG`. |
| `server_vectors::every_vector_decodes_or_fails_as_recorded` | 57 hand-written vectors in `test-data/vectors/server-wire-v1.vectors` (23 accepted, 34 refused at a named stage with a named error), bound to the Stage 02 framing, tags, parser, rendering and reply evidence IDs. |
| `client_transcript_branches::every_asserted_server_frame_decodes_as_one_server_line` | The transcript check refuses two lines, a partial line, an undecodable line and an empty frame, and the registration transcript passes it. |

Each decoder rule was weakened in turn in the working tree, and at least one
of the tests above failed every time: the combined section and the server
side one byte larger, client-only tags allowed anywhere, any escape
accepted, the forbidden numerics treated as unregistered, an unbounded
`label`, empty lines accepted, duplicates accepted and lower-case commands
accepted. The fuzz target ran 10,000 inputs with the Stage 02 smoke
parameters (seed 20260824, 32,768-byte inputs, 2-second timeout, 512 MiB)
without a failure.

### Coverage

Both source inventories are refreshed (1,013 files). Five release regions
are new: the three error enums' `fmt` (`server-framing-error-arms`,
`server-tag-error-arms`, `server-message-error-arms`, regions) and the two
parsers (`server-tag-section-errors` on `parse_server_tags` and
`server-message-parser-errors` on `parse_server_message`, branches). Over
the client wire and testkit suites (`RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest
-p agenc-relay-client-wire -p agenc-relay-testkit --all-features --branch
--locked`, 359 tests), scored with `check-coverage.py`'s counting, each new
region is complete for its metric, and the production functions of the
three modules and `decode_server_frame` reach 642 of 645 regions and 146 of
146 branches; the three unreached regions are allocation-failure exits.
`client-render-error-arms` and `client-registration-grammar-error-arms`
moved with their spans unchanged.

## Compatibility

Additive public items only, and four tokens a client may now accept. The
daemon's parsing, rendering and stored state are unchanged; the renderer's
batch check calls the shared predicate with the same grammar.

## Limitations

- The SDK keeps its own wire modules until the owner accepts this extraction
  (decision D-27); nothing here changes the SDK.
- The decoder checks each line on its own. Batch bookkeeping (that a `batch`
  tag names an open batch), label correlation, numeric parameter shapes,
  `005` token grammar and which reply code may follow which command are the
  reader's, as Appendix A.2 and Section 9.5 leave them.
- The decoder applies the IRCv3 key grammar of Section 9.2 to every key; the
  client-input tag parser's key rule is unchanged by this extraction
  (decision D-20).
- No gate script runs the `server_framing` fuzz target; the Stage 09 gate
  builds it with the other targets, and its smoke run is recorded here.
