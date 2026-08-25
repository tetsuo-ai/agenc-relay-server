---
name: tests
description: "Skill for the Tests area of agenc-ircd. 103 symbols across 17 files."
---

# Tests

103 symbols | 17 files | Cohesion: 93%

## When to Use

- Working with code in `crates/`
- Understanding how new, parse, parse work
- Modifying tests-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `crates/agenc-ircd-federation-wire/src/tests/semantics.rs` | schema, fields, validate, opaque, unsigned (+25) |
| `crates/agenc-ircd-testkit/src/reference_codec.rs` | admit, write_u8, write_u16, write_u24, write_u32 (+10) |
| `crates/agenc-ircd-client-wire/src/text.rs` | from_bytes, validate_decoded_length, new, from_parts, validate_fragment_relationships (+4) |
| `crates/agenc-ircd-testkit/tests/codec_boundaries.rs` | every_vector_rejects_every_truncation_and_trailing_byte, decode, finite_hostile_corpus_is_total_for_every_schema, constructors_reject_shape_type_bounds_enum_schema_and_order, join_target (+3) |
| `crates/agenc-ircd-testkit/src/lib.rs` | new, push_expected, observe, finish, at_revision (+2) |
| `crates/agenc-ircd-testkit/tests/deterministic_capabilities.rs` | transcript_mismatch_does_not_consume_expectation, transcript_limits_and_terminal_states_are_explicit, rejected_reference_transition_preserves_state, exhausted_reference_revision_rejects_before_transition, clock_overflow_is_atomic (+1) |
| `crates/agenc-ircd-federation-wire/src/text.rs` | validate_federation_command, validate_command_token, select_command_form, validate_tag_policy, to_text |
| `crates/agenc-ircd-federation-wire/src/tests/codec.rs` | schema, enum_nested_projection_and_optional_fixed_guards_fail_closed, iterative_machines_reject_impossible_or_overdeep_states |
| `crates/agenc-ircd-types/src/masks.rs` | compile, parse, parse_subject |
| `crates/agenc-ircd-testkit/tests/federation_vectors.rs` | independent_primitive_encoder_covers_every_length_width, independent_encoder_rejects_every_width_and_bound_failure, every_schema_decodes_and_reencodes_its_independent_vector |

## Entry Points

Start here when exploring this area:

- **`new`** (Function) — `crates/agenc-ircd-testkit/src/lib.rs:128`
- **`parse`** (Function) — `crates/agenc-ircd-types/src/masks.rs:127`
- **`parse`** (Function) — `crates/agenc-ircd-types/src/names.rs:38`
- **`write_u8`** (Function) — `crates/agenc-ircd-testkit/src/reference_codec.rs:82`
- **`write_u16`** (Function) — `crates/agenc-ircd-testkit/src/reference_codec.rs:90`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `new` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 128 |
| `parse` | Function | `crates/agenc-ircd-types/src/masks.rs` | 127 |
| `parse` | Function | `crates/agenc-ircd-types/src/names.rs` | 38 |
| `write_u8` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 82 |
| `write_u16` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 90 |
| `write_u24` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 98 |
| `write_u32` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 114 |
| `write_u64` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 122 |
| `write_fixed` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 129 |
| `write_opaque` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 136 |
| `write_length` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 150 |
| `from_bytes` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 94 |
| `new` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 246 |
| `new` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 60 |
| `parse_reference_vectors` | Function | `crates/agenc-ircd-testkit/src/reference_codec.rs` | 220 |
| `decode_exact` | Function | `crates/agenc-ircd-federation-wire/src/codec.rs` | 171 |
| `validate_federation_command` | Function | `crates/agenc-ircd-federation-wire/src/text.rs` | 443 |
| `push_expected` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 478 |
| `observe` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 488 |
| `finish` | Function | `crates/agenc-ircd-testkit/src/lib.rs` | 510 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Validate_mode_change → New` | cross_community | 6 |
| `From_bytes → Expected_fragment_count` | intra_community | 5 |
| `From_bytes → Expected_segment_length` | intra_community | 5 |
| `Validate_session_hidden → New` | cross_community | 5 |
| `Validate_topic_change → New` | cross_community | 5 |
| `Validate_away_fields → New` | cross_community | 5 |
| `Write_opaque → Admit` | intra_community | 4 |
| `Parse_reference_vectors → New` | cross_community | 4 |
| `Validate_reply → New` | cross_community | 4 |
| `New → Validate_decoded_length` | intra_community | 3 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Cluster_3 | 4 calls |
| Cluster_7 | 3 calls |
| Cluster_11 | 3 calls |
| Cluster_10 | 1 calls |
| Cluster_14 | 1 calls |

## How to Explore

1. `context({name: "new"})` — see callers and callees
2. `query({search_query: "tests"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
