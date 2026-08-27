---
name: fuzz-targets
description: "Skill for the Fuzz_targets area of agenc-ircd. 79 symbols across 13 files."
---

# Fuzz_targets

79 symbols | 13 files | Cohesion: 70%

## When to Use

- Working with code in `fuzz/`
- Understanding how measure, as_str, parse_message work
- Modifying fuzz_targets-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `fuzz/fuzz_targets/client_state.rs` | exercise_post_registration_grammar, exercise_post_registration_line, exercise_capability_state, exercise_capability_request, exercise_capability_end (+19) |
| `fuzz/fuzz_targets/parse_render.rs` | new, exercise_boundary_render_plan, exercise_exact_render_boundaries, render_prefix, render_command (+9) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | contains, apply_profile, diff_advertisements, reconnects_on_value_change, request (+6) |
| `fuzz/fuzz_targets/websocket.rs` | exercise_fragmented_sequence, assert_control_event, exercise_arbitrary_frame, exercise_oversized_message, safe_message (+3) |
| `crates/agenc-ircd-client-wire/src/message.rs` | parse_message, parse_parameters, validate_parameters, copy_string, calculate_requested_backing_bytes (+1) |
| `crates/agenc-ircd-client-wire/src/text.rs` | parse_u16_decimal, parse_u32_decimal, parse_u64_decimal, parse_decimal, parse_fragment_decimal (+1) |
| `crates/agenc-ircd-client-wire/src/render.rs` | measure, command_bytes, combined_tag_section |
| `fuzz/fuzz_targets/tcp_framing.rs` | run, checksum |
| `crates/agenc-ircd-client-wire/src/framing.rs` | as_str |
| `crates/agenc-ircd-client-wire/src/registration.rs` | grammar_rejection_refreshes_complete_message_activity |

## Entry Points

Start here when exploring this area:

- **`measure`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:284`
- **`as_str`** (Function) — `crates/agenc-ircd-client-wire/src/framing.rs:86`
- **`parse_message`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:150`
- **`requested_backing_capacities`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:208`
- **`parse_u16_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:230`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `measure` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 284 |
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |
| `parse_message` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 150 |
| `requested_backing_capacities` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 208 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 230 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 236 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 242 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 369 |
| `request` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 269 |
| `split_capability_lines` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 473 |
| `command_bytes` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 311 |
| `combined_tag_section` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 1220 |
| `new` | Function | `fuzz/fuzz_targets/parse_render.rs` | 23 |
| `exercise_boundary_render_plan` | Function | `fuzz/fuzz_targets/parse_render.rs` | 109 |
| `exercise_exact_render_boundaries` | Function | `fuzz/fuzz_targets/parse_render.rs` | 152 |
| `render_prefix` | Function | `fuzz/fuzz_targets/parse_render.rs` | 191 |
| `render_command` | Function | `fuzz/fuzz_targets/parse_render.rs` | 204 |
| `render_middle` | Function | `fuzz/fuzz_targets/parse_render.rs` | 212 |
| `render_parameter` | Function | `fuzz/fuzz_targets/parse_render.rs` | 227 |
| `render_trailing` | Function | `fuzz/fuzz_targets/parse_render.rs` | 241 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Labeled_response → Command_bytes` | cross_community | 8 |
| `Add_client_only_tag → Command_bytes` | cross_community | 6 |
| `Run → Admit_len` | cross_community | 6 |
| `Drive → Split_field` | cross_community | 5 |
| `Run → Split_field` | cross_community | 5 |
| `Run → Validate_key` | cross_community | 5 |
| `Run → Validate_correlation_value_len` | cross_community | 5 |
| `Run → Validate_decoded_value` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Admit_len` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Split_field` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 10 calls |
| Cluster_36 | 9 calls |
| Cluster_35 | 7 calls |
| Cluster_41 | 3 calls |
| Cluster_78 | 1 calls |
| Cluster_44 | 1 calls |
| Cluster_48 | 1 calls |
| Cluster_51 | 1 calls |

## How to Explore

1. `context({name: "measure"})` — see callers and callees
2. `query({search_query: "fuzz_targets"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
