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

## Compatibility

Additive public items only, and four tokens a client may now accept. The
daemon's parsing, rendering and stored state are unchanged.

## Limitations

- The SDK keeps its own wire modules until the owner accepts this extraction
  (decision D-27); nothing here changes the SDK.
