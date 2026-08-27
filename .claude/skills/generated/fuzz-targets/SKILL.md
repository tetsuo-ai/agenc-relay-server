---
name: fuzz-targets
description: "Skill for the Fuzz_targets area of agenc-ircd. 82 symbols across 13 files."
---

# Fuzz_targets

82 symbols | 13 files | Cohesion: 70%

## When to Use

- Working with code in `fuzz/`
- Understanding how as_str, parse_message, requested_backing_capacities work
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
| `crates/agenc-ircd-client-wire/src/registration_command.rs` | parsed, classify, validate_account_length |
| `crates/agenc-ircd-client-wire/src/render.rs` | measure, command_bytes, combined_tag_section |
| `fuzz/fuzz_targets/tcp_framing.rs` | run, checksum |
| `crates/agenc-ircd-client-wire/src/framing.rs` | as_str |

## Entry Points

Start here when exploring this area:

- **`as_str`** (Function) — `crates/agenc-ircd-client-wire/src/framing.rs:86`
- **`parse_message`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:150`
- **`requested_backing_capacities`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:208`
- **`measure`** (Function) — `crates/agenc-ircd-client-wire/src/render.rs:284`
- **`apply_profile`** (Function) — `crates/agenc-ircd-client-wire/src/capability.rs:369`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `as_str` | Function | `crates/agenc-ircd-client-wire/src/framing.rs` | 86 |
| `parse_message` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 150 |
| `requested_backing_capacities` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 208 |
| `measure` | Function | `crates/agenc-ircd-client-wire/src/render.rs` | 284 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 369 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 230 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 236 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 242 |
| `request` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 269 |
| `split_capability_lines` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 473 |
| `parse_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 195 |
| `validate_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 214 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 232 |
| `calculate_requested_backing_bytes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 241 |
| `parser_covers_empty_prefix_command_and_parameter_shapes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 325 |
| `grammar_rejection_refreshes_complete_message_activity` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 1446 |
| `parsed` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 1945 |
| `classify` | Function | `crates/agenc-ircd-client-wire/src/registration_command.rs` | 1953 |
| `client_wire_and_domain_agree_on_ctcp_message_semantics` | Function | `crates/agenc-ircd-testkit/tests/domain_commands.rs` | 24 |
| `exercise_post_registration_grammar` | Function | `fuzz/fuzz_targets/client_state.rs` | 97 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Labeled_response → Command_bytes` | cross_community | 8 |
| `Add_client_only_tag → Command_bytes` | cross_community | 6 |
| `Run → Admit_len` | cross_community | 6 |
| `Capability_state_covers_atomic_negotiation_and_profile_changes → CapabilitySpec` | cross_community | 5 |
| `Drive → Split_field` | cross_community | 5 |
| `Run → Split_field` | cross_community | 5 |
| `Run → Validate_key` | cross_community | 5 |
| `Run → Validate_correlation_value_len` | cross_community | 5 |
| `Run → Validate_decoded_value` | cross_community | 5 |
| `Maximal_message_stays_below_the_hard_parsed_arena → Admit_len` | cross_community | 5 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 11 calls |
| Cluster_36 | 9 calls |
| Cluster_35 | 7 calls |
| Cluster_41 | 3 calls |
| Cluster_78 | 1 calls |
| Cluster_44 | 1 calls |
| Cluster_48 | 1 calls |
| Cluster_51 | 1 calls |

## How to Explore

1. `context({name: "as_str"})` — see callers and callees
2. `query({search_query: "fuzz_targets"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
