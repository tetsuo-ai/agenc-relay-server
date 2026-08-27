---
name: fuzz-targets
description: "Skill for the Fuzz_targets area of agenc-ircd. 77 symbols across 12 files."
---

# Fuzz_targets

77 symbols | 12 files | Cohesion: 71%

## When to Use

- Working with code in `fuzz/`
- Understanding how as_str, parse_message, requested_backing_capacities work
- Modifying fuzz_targets-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `fuzz/fuzz_targets/client_state.rs` | exercise_post_registration_grammar, exercise_post_registration_line, exercise_capability_state, exercise_capability_request, exercise_capability_end (+21) |
| `fuzz/fuzz_targets/parse_render.rs` | new, exercise_boundary_render_plan, exercise_exact_render_boundaries, render_prefix, render_command (+8) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | list, ensure_token_list_renderable, contains, apply_profile, diff_advertisements (+3) |
| `fuzz/fuzz_targets/websocket.rs` | exercise_fragmented_sequence, assert_control_event, exercise_arbitrary_frame, exercise_oversized_message, safe_message (+3) |
| `crates/agenc-ircd-client-wire/src/message.rs` | parse_message, parse_parameters, validate_parameters, copy_string, calculate_requested_backing_bytes (+1) |
| `crates/agenc-ircd-client-wire/src/text.rs` | parse_u16_decimal, parse_u32_decimal, parse_u64_decimal, parse_decimal, parse_fragment_decimal (+1) |
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | parsed, classify, validate_account_length |
| `fuzz/fuzz_targets/tcp_framing.rs` | run, checksum |
| `crates/agenc-ircd-client-wire/src/render.rs` | measure, combined_tag_section |
| `crates/agenc-ircd-client-wire/src/framing.rs` | as_str |

## Entry Points

Start here when exploring this area:

- **`as_str`** (Function) — `crates/agenc-ircd-client-wire/src/framing.rs:86`
- **`parse_message`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:153`
- **`requested_backing_capacities`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:208`
- **`measure`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:284`
- **`list`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:317`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |
| `parse_message` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 153 |
| `requested_backing_capacities` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 208 |
| `measure` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 284 |
| `list` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 317 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 230 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 236 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 242 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 364 |
| `split_capability_lines` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 468 |
| `parse_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 210 |
| `validate_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 232 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 261 |
| `calculate_requested_backing_bytes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 270 |
| `parser_covers_empty_prefix_command_and_parameter_shapes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 354 |
| `grammar_rejection_refreshes_complete_message_activity` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 1436 |
| `parsed` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 1945 |
| `classify` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 1953 |
| `exercise_post_registration_grammar` | Function | `fuzz/fuzz_targets/client_state.rs` | 97 |
| `exercise_post_registration_line` | Function | `fuzz/fuzz_targets/client_state.rs` | 113 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Drive → Admit_len` | cross_community | 6 |
| `Drive → Split_field` | cross_community | 5 |
| `Run → Admit_len` | cross_community | 5 |
| `Run → Split_field` | cross_community | 5 |
| `Run → Validate_key` | cross_community | 5 |
| `Run → Validate_correlation_value_len` | cross_community | 5 |
| `Run → Validate_decoded_value` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Admit_len` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Split_field` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Validate_key` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 8 calls |
| Cluster_6 | 7 calls |
| Cluster_2 | 5 calls |
| Cluster_8 | 3 calls |
| Cluster_46 | 1 calls |
| Cluster_27 | 1 calls |
| Cluster_11 | 1 calls |
| Cluster_15 | 1 calls |

## How to Explore

1. `context({name: "as_str"})` — see callers and callees
2. `query({search_query: "fuzz_targets"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
