---
name: fuzz-targets
description: "Skill for the Fuzz_targets area of agenc-ircd. 74 symbols across 13 files."
---

# Fuzz_targets

74 symbols | 13 files | Cohesion: 71%

## When to Use

- Working with code in `fuzz/`
- Understanding how parse_message, requested_backing_capacities, parse_u16_decimal work
- Modifying fuzz_targets-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `fuzz/fuzz_targets/client_state.rs` | exercise_post_registration_grammar, exercise_post_registration_line, exercise_capability_state, exercise_capability_request, exercise_capability_end (+21) |
| `fuzz/fuzz_targets/parse_render.rs` | new, exercise_boundary_render_plan, exercise_exact_render_boundaries, render_prefix, render_command (+8) |
| `fuzz/fuzz_targets/websocket.rs` | exercise_fragmented_sequence, assert_control_event, exercise_arbitrary_frame, exercise_oversized_message, safe_message (+3) |
| `crates/agenc-ircd-client-wire/src/message.rs` | parse_message, parse_parameters, validate_parameters, copy_string, calculate_requested_backing_bytes (+2) |
| `crates/agenc-ircd-client-wire/src/text.rs` | parse_u16_decimal, parse_u32_decimal, parse_u64_decimal, parse_decimal, parse_fragment_decimal (+1) |
| `crates/agenc-ircd-client-wire/src/capability.rs` | contains, apply_profile, diff_advertisements, reconnects_on_value_change, split_capability_lines (+1) |
| `fuzz/fuzz_targets/tcp_framing.rs` | run, checksum |
| `crates/agenc-ircd-client-wire/src/registration.rs` | grammar_rejection_refreshes_complete_message_activity |
| `crates/agenc-ircd-client-wire/src/tags.rs` | requested_backing_capacities |
| `crates/agenc-ircd-runtime/src/account_service.rs` | parsed |

## Entry Points

Start here when exploring this area:

- **`parse_message`** (Function) — `crates/agenc-ircd-client-wire/src/message.rs:164`
- **`requested_backing_capacities`** (Function) — `crates/agenc-ircd-client-wire/src/tags.rs:208`
- **`parse_u16_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:230`
- **`parse_u32_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:236`
- **`parse_u64_decimal`** (Function) — `crates/agenc-ircd-client-wire/src/text.rs:242`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `parse_message` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 164 |
| `requested_backing_capacities` | Function | `crates/agenc-ircd-client-wire/src/tags.rs` | 208 |
| `parse_u16_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 230 |
| `parse_u32_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 236 |
| `parse_u64_decimal` | Function | `crates/agenc-ircd-client-wire/src/text.rs` | 242 |
| `apply_profile` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 369 |
| `split_capability_lines` | Function | `crates/agenc-ircd-client-wire/src/capability.rs` | 473 |
| `parse_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 209 |
| `validate_parameters` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 228 |
| `copy_string` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 246 |
| `calculate_requested_backing_bytes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 255 |
| `parser_covers_empty_prefix_command_and_parameter_shapes` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 339 |
| `taking_parameters_moves_middle_and_trailing_secrets_without_losing_context` | Function | `crates/agenc-ircd-client-wire/src/message.rs` | 373 |
| `grammar_rejection_refreshes_complete_message_activity` | Function | `crates/agenc-ircd-client-wire/src/registration.rs` | 1461 |
| `parsed` | Function | `crates/agenc-ircd-runtime/src/account_service.rs` | 6930 |
| `parsed` | Function | `crates/agenc-ircd-runtime/src/registration.rs` | 1792 |
| `client_wire_and_domain_agree_on_ctcp_message_semantics` | Function | `crates/agenc-ircd-testkit/tests/domain_commands.rs` | 24 |
| `exercise_post_registration_grammar` | Function | `fuzz/fuzz_targets/client_state.rs` | 97 |
| `exercise_post_registration_line` | Function | `fuzz/fuzz_targets/client_state.rs` | 113 |
| `run` | Function | `fuzz/fuzz_targets/tcp_framing.rs` | 41 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Apply_action → CapLine` | cross_community | 4 |

## Connected Areas

| Area | Connections |
|------|-------------|
| Tests | 14 calls |
| Cluster_70 | 5 calls |
| Cluster_69 | 5 calls |
| Cluster_93 | 3 calls |
| Cluster_73 | 3 calls |
| Connection | 2 calls |
| State_core | 2 calls |
| Cluster_110 | 1 calls |

## How to Explore

1. `context({name: "parse_message"})` — see callers and callees
2. `query({search_query: "fuzz_targets"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
