---
name: fuzz-targets
description: "Skill for the Fuzz_targets area of agenc-ircd. 84 symbols across 14 files."
---

# Fuzz_targets

84 symbols | 14 files | Cohesion: 67%

## When to Use

- Working with code in `fuzz/`
- Understanding how measure, parse_message, requested_backing_capacities work
- Modifying fuzz_targets-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `fuzz/fuzz_targets/client_state.rs` | exercise_post_registration_grammar, exercise_post_registration_line, exercise_capability_changes, assert_capability_changes, assert_enabled_in_profile (+19) |
| `fuzz/fuzz_targets/parse_render.rs` | new, exercise_boundary_render_plan, exercise_exact_render_boundaries, render_prefix, render_command (+9) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | contains, apply_profile, diff_advertisements, apply_requested_tokens, insert_unique (+7) |
| `fuzz/fuzz_targets/websocket.rs` | exercise_fragmented_sequence, assert_control_event, exercise_arbitrary_frame, exercise_oversized_message, safe_message (+3) |
| `crates/agenc-ircd-client-wire/src/message.rs` | parse_message, parse_parameters, validate_parameters, copy_string, calculate_requested_backing_bytes (+1) |
| `crates/agenc-ircd-client-wire/src/text.rs` | parse_u16_decimal, parse_u32_decimal, parse_u64_decimal, parse_decimal, parse_fragment_decimal (+1) |
| `crates/agenc-ircd-client-wire/src/render.rs` | measure, command_bytes, combined_tag_section |
| `crates/agenc-ircd-storage/src/sealed.rs` | new, seal, open |
| `fuzz/fuzz_targets/tcp_framing.rs` | run, checksum |
| `crates/agenc-ircd-crypto/src/storage.rs` | from_reserved_bytes, derive_storage_record_key |

## Entry Points

Start here when exploring this area:

- **`measure`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:284`
- **`parse_message`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:150`
- **`requested_backing_capacities`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:208`
- **`apply_profile`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:369`
- **`parse_u16_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:230`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `measure` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 284 |
| `parse_message` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 150 |
| `requested_backing_capacities` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 208 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 369 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 230 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 236 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 242 |
| `from_reserved_bytes` | Function | `crates/agenc-ircd-crypto/src/storage.rs` | 171 |
| `derive_storage_record_key` | Function | `crates/agenc-ircd-crypto/src/storage.rs` | 252 |
| `new` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 27 |
| `seal` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 43 |
| `open` | Function | `crates/agenc-ircd-storage/src/sealed.rs` | 120 |
| `request` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 269 |
| `split_capability_lines` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 473 |
| `command_bytes` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 311 |
| `combined_tag_section` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1220 |
| `new` | Function | `fuzz/fuzz_targets/parse_render.rs` | 23 |
| `exercise_boundary_render_plan` | Function | `fuzz/fuzz_targets/parse_render.rs` | 109 |
| `exercise_exact_render_boundaries` | Function | `fuzz/fuzz_targets/parse_render.rs` | 152 |
| `render_prefix` | Function | `fuzz/fuzz_targets/parse_render.rs` | 191 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Seal → Put_fixed` | cross_community | 5 |
| `Open → Put_fixed` | cross_community | 5 |
| `Seal → Value` | cross_community | 4 |
| `Seal → As_mut_bytes` | cross_community | 4 |
| `Seal → New` | cross_community | 4 |
| `Open → Value` | cross_community | 4 |
| `Open → As_mut_bytes` | cross_community | 4 |
| `Open → New` | cross_community | 4 |
| `Exercise_boundary_render_plan → New` | intra_community | 4 |
| `Capability_state_covers_atomic_negotiation_and_profile_changes → Capabilities` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 16 calls |
| Cluster_64 | 9 calls |
| Cluster_63 | 7 calls |
| Cluster_69 | 3 calls |
| Cluster_173 | 3 calls |
| Connection | 2 calls |
| Cluster_106 | 1 calls |
| Cluster_170 | 1 calls |

## How to Explore

1. `context({name: "measure"})` — see callers and callees
2. `query({search_query: "fuzz_targets"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
