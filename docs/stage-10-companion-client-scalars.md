# Companion Section 16 client scalars

This record covers X-11 of the SDK program's server work (2026-10-01, outside
master #35). No specification, profile hash, wire format, storage generation
or dependency changes, and no daemon behaviour changes. No Stage 10 task is
closed by this record.

## Finding

Companion Section 16 is the normative table of profile limits and defaults,
and `agenc-relay-e2ee`'s `limits` module is their shared code owner. Of the
table's 125 rows, 13 had no constant: the endpoint-only scalars of the MLS
ratchet and application replay windows (Section 14) and the update and idle
defaults (Section 13.6). The server holds no ratchet or replay state and
enforces none of them, so nothing in the daemon needed them, but every
client had to copy the values. Nothing compared the table with the module
either: the SDK readiness audit of 2026-09-28 found no value mismatch with a
one-off script, and nothing kept it so.

## Change

- `crates/agenc-relay-e2ee/src/limits.rs` defines the 13 scalars in table
  order, durations in seconds as the module's other durations are:
  `MAX_RATCHET_FORWARD_JUMP` (MLS sender generations, `u32`),
  `MAX_SKIPPED_KEYS_PER_SENDER`, `MAX_SKIPPED_KEY_BYTES_PER_CONVERSATION`,
  `SKIPPED_KEY_RETENTION_SECONDS`, `MAX_RETAINED_PAST_EPOCHS`,
  `PAST_EPOCH_RECEIVE_RETENTION_SECONDS` (zero for a removed leaf, as the
  table qualifies it), `MAX_APPLICATION_SEQUENCE_FORWARD_JUMP` (a
  `sender_sequence` distance, `u64`), `MAX_APPLICATION_SEQUENCE_GAPS`,
  `MAX_RECENT_MESSAGE_IDS_PER_LEAF`,
  `MAX_REPLAY_GAP_STATE_BYTES_PER_CONVERSATION`,
  `DEFAULT_ACTIVE_UPDATE_PERIOD_SECONDS`, `DEFAULT_ACTIVE_UPDATE_MESSAGES`
  and `DEFAULT_IDLE_DEVICE_EVICTION_SECONDS`. The module documentation says
  they are endpoint limits the server does not enforce.
- `crates/agenc-relay-e2ee/tests/companion_limits_table.rs` reads the
  companion at build time, parses every Section 16 row and compares its
  default, converted once to canonical units (seconds for durations), with
  the constant that names it. The two reassembly timeouts map to their
  absolute and idle constants, and `SECURITY_PROOF_RETENTION`, a rule rather
  than a scalar, is compared as exact text. The test lists the rows in table
  order, so a changed value, a new row without a constant, or a constant left
  behind by a removed row fails; an unknown unit in a default cell fails too.

## Tests

| Test | What it pins |
| --- | --- |
| `every_section_16_row_equals_its_limits_constant` | All 125 rows, in order, equal their constants. |
| `the_endpoint_scalars_are_named_by_the_table` | Each of the 13 endpoint scalars is exactly one table row. |
| `the_default_grammar_is_read_in_canonical_units` | The cell grammar: thousands separators, a two-quantity cell, a `;` qualifier, hours and days; an unknown unit, a rule cell and an overflowing value are errors. |

At the parent commit the test does not compile: the 13 constants are
undefined, and the compiler names exactly those 13. With the constants it
passes; with `MAX_RATCHET_FORWARD_JUMP` changed to 1,023 the table test fails
on that row.

## Compatibility

Additive public constants only. The daemon does not read them, so wire,
persistence, privacy and dependency effects are none.

## Limitations

- The constants carry the table's values; whether an endpoint enforces them
  is the endpoint's evidence, not this test's.
- The test reads the companion file in the tree, which `scripts/check-spec.sh`
  and `scripts/check-baseline.py` pin; it does not check the profile hash
  itself.
- The implementation gate (`scripts/check-stage-nine.sh`) was not run on this
  branch.

## Evidence

Commands at this branch, from the repository root:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run -p agenc-relay-e2ee --all-features --locked
python3 scripts/check-source.py check
```
